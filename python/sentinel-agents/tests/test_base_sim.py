"""Tests for the SimulationAgent base class with stub implementation."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.simulate.base_sim import SimulationAgent
from sentinel_agents.simulate.mitre import MitreTechnique, get_techniques_for_tactic
from sentinel_agents.simulate.models import (
    GraphProtocol,
    SimConfig,
    SimulationFinding,
    TacticType,
)
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentPlan, AgentStatus

# ── Mock Graph ──────────────────────────────────────────────────


class MockGraph:
    """Mock graph provider satisfying GraphProtocol."""

    def __init__(
        self,
        nodes_by_label: dict[str, list[dict[str, Any]]] | None = None,
        neighbors_by_node: dict[str, list[dict[str, Any]]] | None = None,
        attack_paths_response: dict[str, Any] | None = None,
        blast_radius_response: dict[str, Any] | None = None,
        edges: list[dict[str, Any]] | None = None,
    ) -> None:
        self._nodes = nodes_by_label or {}
        self._neighbors = neighbors_by_node or {}
        self._attack_paths = attack_paths_response or {"attack_paths": []}
        self._blast_radius = blast_radius_response or {
            "blast_score": 0.0,
            "total_reachable": 0,
        }
        self._edges = edges or []
        self.queries_executed: list[dict[str, Any]] = []

    async def query_nodes(
        self,
        label: str,
        tenant_id: str,
        *,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self.queries_executed.append({"method": "query_nodes", "label": label})
        return self._nodes.get(label, [])[:limit]

    async def query_neighbors(
        self,
        node_id: str,
        tenant_id: str,
        *,
        edge_types: list[str] | None = None,
        target_labels: list[str] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self.queries_executed.append(
            {
                "method": "query_neighbors",
                "node_id": node_id,
            }
        )
        return self._neighbors.get(node_id, [])[:limit]

    async def find_attack_paths(
        self,
        tenant_id: str,
        *,
        sources: list[str] | None = None,
        targets: list[str] | None = None,
        max_depth: int = 10,
        max_paths: int = 100,
        include_lateral: bool = False,
        include_blast: bool = False,
    ) -> dict[str, Any]:
        self.queries_executed.append(
            {
                "method": "find_attack_paths",
                "sources": sources,
            }
        )
        return self._attack_paths

    async def compute_blast_radius(
        self,
        tenant_id: str,
        compromised_node_id: str,
        *,
        max_hops: int = 5,
        min_exploitability: float = 0.3,
    ) -> dict[str, Any]:
        self.queries_executed.append({"method": "compute_blast_radius"})
        return self._blast_radius

    async def query_edges(
        self,
        tenant_id: str,
        *,
        edge_type: str | None = None,
        source_label: str | None = None,
        target_label: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        self.queries_executed.append(
            {
                "method": "query_edges",
                "edge_type": edge_type,
            }
        )
        return self._edges[:limit]


# Verify protocol compliance
assert isinstance(MockGraph(), GraphProtocol)


# ── Stub SimulationAgent ────────────────────────────────────────


class StubSimAgent(SimulationAgent):
    """Minimal SimulationAgent for testing base class behavior."""

    async def select_techniques(
        self,
        plan: AgentPlan,
    ) -> list[MitreTechnique]:
        return get_techniques_for_tactic(self.sim_config.tactic)[:1]

    async def simulate_technique(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        hosts = context.get("hosts", [])
        if hosts:
            return [
                SimulationFinding(
                    tactic=self.sim_config.tactic,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="medium",
                    title="Stub finding",
                    description=f"Found {len(hosts)} hosts",
                    risk_score=5.0,
                    affected_nodes=[h.get("id", "") for h in hosts],
                    mitre_url=technique.mitre_url,
                ),
            ]
        return []


# ── Helpers ─────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Test simulation plan",
            "rationale": "Test adversarial assessment",
            "confidence": 0.85,
            "steps": ["Select techniques", "Simulate"],
            "alternatives": [],
        }
    )
    summary = "Simulation complete. No critical findings."
    return [plan, summary]


def _make_agent(
    graph: MockGraph | None = None,
    config: SimConfig | None = None,
) -> StubSimAgent:
    agent_config = AgentConfig(
        agent_id="sim-test-1",
        agent_type="simulate",
        tenant_id=uuid4(),
    )
    return StubSimAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        graph=graph or MockGraph(),
        sim_config=config or SimConfig(tactic=TacticType.INITIAL_ACCESS),
    )


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sim_agent_run_lifecycle() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [{"id": "h1", "hostname": "web-01"}],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test initial access simulation")

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_type == "simulate"
    assert result.engram_id is not None
    assert len(result.findings) == 1
    assert result.findings[0].title == "Stub finding"


@pytest.mark.asyncio
async def test_sim_agent_no_findings() -> None:
    agent = _make_agent()
    result = await agent.run("Simulation with empty graph")

    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_sim_agent_queries_graph() -> None:
    graph = MockGraph()
    agent = _make_agent(graph=graph)
    await agent.run("Verify graph queries")

    # Should query hosts, users, services, vulnerabilities
    query_labels = [q["label"] for q in graph.queries_executed if q["method"] == "query_nodes"]
    assert "Host" in query_labels
    assert "User" in query_labels
    assert "Service" in query_labels
    assert "Vulnerability" in query_labels


@pytest.mark.asyncio
async def test_sim_agent_cancellation() -> None:
    graph = MockGraph()
    agent = _make_agent(graph=graph)
    agent.request_cancel()

    await agent.run("Cancelled simulation")
    # After cancellation, no technique simulations should run
    technique_queries = [q for q in graph.queries_executed if q["method"] == "find_attack_paths"]
    assert len(technique_queries) == 0


@pytest.mark.asyncio
async def test_sim_agent_finding_has_mitre_context() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [{"id": "h1"}],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("MITRE context test")

    assert len(result.findings) == 1
    evidence = result.findings[0].evidence
    assert "technique_id" in evidence
    assert "technique_name" in evidence
    assert "mitre_url" in evidence
    assert evidence["mitre_url"].startswith("https://attack.mitre.org/")


@pytest.mark.asyncio
async def test_sim_agent_risk_score_in_evidence() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [{"id": "h1"}],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Risk score test")

    assert len(result.findings) == 1
    evidence = result.findings[0].evidence
    assert "risk_score" in evidence
    assert evidence["risk_score"] == 5.0

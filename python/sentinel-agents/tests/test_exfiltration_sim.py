"""Tests for the Exfiltration simulation playbook."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.simulate.exfiltration import ExfiltrationSimAgent
from sentinel_agents.simulate.models import ExfiltrationConfig
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_base_sim import MockGraph

# ── Helpers ─────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Simulate exfiltration",
            "rationale": "Test data egress paths",
            "confidence": 0.85,
            "steps": ["Check C2 paths", "Check DNS tunneling"],
            "alternatives": [],
        }
    )
    summary = "Exfiltration simulation complete."
    return [plan, summary]


def _make_agent(
    graph: MockGraph | None = None,
    config: ExfiltrationConfig | None = None,
) -> ExfiltrationSimAgent:
    agent_config = AgentConfig(
        agent_id="sim-exfil-1",
        agent_type="simulate",
        tenant_id=uuid4(),
    )
    return ExfiltrationSimAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        graph=graph or MockGraph(),
        sim_config=config or ExfiltrationConfig(),
    )


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_empty_graph() -> None:
    agent = _make_agent()
    result = await agent.run("Exfiltration on empty graph")
    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_t1041_egress_paths() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [
                {"id": "crown-1", "criticality": "critical", "is_internet_facing": False},
                {"id": "exit-1", "criticality": "low", "is_internet_facing": True},
            ],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        attack_paths_response={
            "attack_paths": [
                {"risk_score": 0.9, "steps": [{"node_id": "crown-1"}, {"node_id": "exit-1"}]},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test C2 exfiltration")

    c2_findings = [f for f in result.findings if "T1041" in f.evidence.get("technique_id", "")]
    assert len(c2_findings) == 1
    assert c2_findings[0].severity == "critical"
    assert c2_findings[0].evidence.get("paths_count") == 1


@pytest.mark.asyncio
async def test_t1048_dns_exfiltration() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [
                {"id": "sensitive-1", "criticality": "critical"},
            ],
            "User": [],
            "Service": [
                {"id": "dns-svc", "port": 53},
            ],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "sensitive-1": [
                {"id": "dns-svc", "port": 53},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test DNS exfiltration")

    dns_findings = [f for f in result.findings if "T1048" in f.evidence.get("technique_id", "")]
    assert len(dns_findings) == 1
    assert dns_findings[0].severity == "high"
    assert "DNS" in dns_findings[0].title


@pytest.mark.asyncio
async def test_t1041_no_crown_jewels_no_finding() -> None:
    """No findings when there are no critical assets."""
    graph = MockGraph(
        nodes_by_label={
            "Host": [
                {"id": "h1", "criticality": "low", "is_internet_facing": True},
            ],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("No crown jewels")

    c2_findings = [f for f in result.findings if "T1041" in f.evidence.get("technique_id", "")]
    assert len(c2_findings) == 0


@pytest.mark.asyncio
async def test_t1048_no_dns_services_no_finding() -> None:
    """No DNS exfil findings when no DNS services exist."""
    graph = MockGraph(
        nodes_by_label={
            "Host": [{"id": "h1", "criticality": "critical"}],
            "User": [],
            "Service": [{"id": "svc-web", "port": 443}],
            "Vulnerability": [],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("No DNS services")

    dns_findings = [f for f in result.findings if "T1048" in f.evidence.get("technique_id", "")]
    assert len(dns_findings) == 0


@pytest.mark.asyncio
async def test_t1537_cloud_storage_access() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [],
            "Vulnerability": [],
            "Application": [
                {"id": "app-s3", "app_type": "database"},
            ],
        },
        neighbors_by_node={
            "app-s3": [
                {"id": "svc-1"},
                {"id": "svc-2"},
            ],
        },
    )
    # Override query_nodes to also return Application
    original_query = graph.query_nodes

    async def patched_query(label, tenant_id, *, filters=None, limit=100):
        if label == "Application":
            return graph._nodes.get("Application", [])[:limit]
        return await original_query(label, tenant_id, filters=filters, limit=limit)

    graph.query_nodes = patched_query

    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1537")

    cloud_findings = [f for f in result.findings if "T1537" in f.evidence.get("technique_id", "")]
    assert len(cloud_findings) == 1
    assert cloud_findings[0].evidence.get("accessor_count") == 2

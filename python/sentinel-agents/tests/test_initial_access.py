"""Tests for the Initial Access simulation playbook."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.simulate.initial_access import InitialAccessSimAgent
from sentinel_agents.simulate.models import InitialAccessConfig
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_base_sim import MockGraph

# ── Helpers ─────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Simulate initial access",
            "rationale": "Test exposed attack surface",
            "confidence": 0.85,
            "steps": ["Scan exposed services", "Test phishing vectors"],
            "alternatives": [],
        }
    )
    summary = "Initial access simulation complete."
    return [plan, summary]


def _make_agent(
    graph: MockGraph | None = None,
    config: InitialAccessConfig | None = None,
) -> InitialAccessSimAgent:
    agent_config = AgentConfig(
        agent_id="sim-ia-1",
        agent_type="simulate",
        tenant_id=uuid4(),
    )
    return InitialAccessSimAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        graph=graph or MockGraph(),
        sim_config=config or InitialAccessConfig(),
    )


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_empty_graph() -> None:
    agent = _make_agent()
    result = await agent.run("Initial access on empty graph")
    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_t1190_exploitable_cve() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [
                {"id": "web-01", "hostname": "web-01", "is_internet_facing": True},
            ],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "web-01": [
                {
                    "label": "Vulnerability",
                    "id": "vuln-1",
                    "cve_id": "CVE-2024-1234",
                    "exploitable": True,
                },
            ],
        },
        attack_paths_response={
            "attack_paths": [
                {"risk_score": 0.8, "steps": [{"node_id": "web-01"}]},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1190")

    t1190_findings = [f for f in result.findings if "T1190" in f.evidence.get("technique_id", "")]
    assert len(t1190_findings) == 1
    assert t1190_findings[0].severity == "critical"
    assert "CVE-2024-1234" in t1190_findings[0].evidence.get("cve_ids", [])


@pytest.mark.asyncio
async def test_t1133_exposed_remote_services() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [
                {"id": "rdp-host", "hostname": "rdp-host", "is_internet_facing": True},
            ],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "rdp-host": [
                {"label": "Service", "id": "svc-rdp", "port": 3389},
                {"label": "User", "id": "u1", "mfa_enabled": False},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1133")

    t1133_findings = [f for f in result.findings if "T1133" in f.evidence.get("technique_id", "")]
    assert len(t1133_findings) == 1
    assert t1133_findings[0].severity == "high"
    assert 3389 in t1133_findings[0].evidence.get("exposed_ports", [])


@pytest.mark.asyncio
async def test_t1566_phishing_no_mfa() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [
                {"id": "u1", "username": "alice", "user_type": "human", "mfa_enabled": False},
            ],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "u1": [
                {"label": "Host", "id": "h1", "criticality": "critical"},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1566")

    t1566_findings = [f for f in result.findings if "T1566" in f.evidence.get("technique_id", "")]
    assert len(t1566_findings) == 1
    assert "phishing" in t1566_findings[0].title.lower()


@pytest.mark.asyncio
async def test_t1078_overprivileged_service_account() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [
                {"id": "svc-1", "username": "svc-deploy", "user_type": "service_account"},
            ],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "svc-1": [
                {"id": f"res-{i}"}
                for i in range(6)  # 6 > threshold of 5
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1078")

    t1078_findings = [f for f in result.findings if "T1078" in f.evidence.get("technique_id", "")]
    assert len(t1078_findings) == 1
    assert "svc-deploy" in t1078_findings[0].evidence.get("username", "")


@pytest.mark.asyncio
async def test_t1199_trust_relationships() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        edges=[
            {"source_id": "vpc-1", "target_id": "vpc-2", "edge_type": "TRUSTS"},
            {"source_id": "vpc-2", "target_id": "vpc-3", "edge_type": "TRUSTS"},
        ],
        attack_paths_response={"attack_paths": [{"risk_score": 0.5}]},
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1199")

    t1199_findings = [f for f in result.findings if "T1199" in f.evidence.get("technique_id", "")]
    assert len(t1199_findings) == 1
    assert "trust" in t1199_findings[0].title.lower()


@pytest.mark.asyncio
async def test_technique_filter_limits_scope() -> None:
    """Only simulate specified techniques when config.techniques is set."""
    graph = MockGraph(
        nodes_by_label={
            "Host": [
                {"id": "web-01", "hostname": "web-01", "is_internet_facing": True},
            ],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "web-01": [
                {"label": "Vulnerability", "id": "v1", "cve_id": "CVE-1", "exploitable": True},
            ],
        },
        attack_paths_response={"attack_paths": [{"risk_score": 0.5}]},
    )
    # Only simulate T1190, not all 5 techniques
    cfg = InitialAccessConfig(techniques=["T1190"])
    agent = _make_agent(graph=graph, config=cfg)
    result = await agent.run("Filtered simulation")

    # Should only find T1190-related findings
    technique_ids = {f.evidence.get("technique_id") for f in result.findings}
    assert technique_ids <= {"T1190"}

"""Tests for the Lateral Movement simulation playbook."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.simulate.lateral_movement import LateralMovementSimAgent
from sentinel_agents.simulate.models import LateralMovementSimConfig
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_base_sim import MockGraph

# ── Helpers ─────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Simulate lateral movement",
            "rationale": "Test internal movement paths",
            "confidence": 0.85,
            "steps": ["Check RDP chains", "Check credential reuse"],
            "alternatives": [],
        }
    )
    summary = "Lateral movement simulation complete."
    return [plan, summary]


def _make_agent(
    graph: MockGraph | None = None,
    config: LateralMovementSimConfig | None = None,
) -> LateralMovementSimAgent:
    agent_config = AgentConfig(
        agent_id="sim-lm-1",
        agent_type="simulate",
        tenant_id=uuid4(),
    )
    return LateralMovementSimAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        graph=graph or MockGraph(),
        sim_config=config or LateralMovementSimConfig(),
    )


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_empty_graph() -> None:
    agent = _make_agent()
    result = await agent.run("Lateral movement on empty graph")
    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_t1021_001_rdp_chains() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [
                {"id": "svc-rdp", "port": 3389, "host_id": "h1"},
            ],
            "Vulnerability": [],
        },
        attack_paths_response={
            "attack_paths": [],
            "lateral_chains": [
                {
                    "techniques": ["rdp-hop", "rdp-hop"],
                    "risk_score": 0.7,
                    "steps": [],
                },
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test RDP lateral chains")

    rdp_findings = [f for f in result.findings if "T1021.001" in f.evidence.get("technique_id", "")]
    assert len(rdp_findings) == 1
    assert rdp_findings[0].severity == "high"
    assert "RDP" in rdp_findings[0].title


@pytest.mark.asyncio
async def test_t1021_004_ssh_chains() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [
                {"id": "svc-ssh", "port": 22, "host_id": "h1"},
            ],
            "Vulnerability": [],
        },
        attack_paths_response={
            "attack_paths": [],
            "lateral_chains": [
                {
                    "techniques": ["ssh-pivot"],
                    "risk_score": 0.6,
                    "steps": [],
                },
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test SSH lateral chains")

    ssh_findings = [f for f in result.findings if "T1021.004" in f.evidence.get("technique_id", "")]
    assert len(ssh_findings) == 1
    assert "SSH" in ssh_findings[0].title


@pytest.mark.asyncio
async def test_t1550_002_pass_the_hash() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [
                {"id": "admin-1", "username": "admin-user"},
            ],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "admin-1": [
                {"id": "h1", "permissions": ["local-admin"]},
                {"id": "h2", "permissions": ["local-admin"]},
                {"id": "h3", "permissions": ["domain-admin"]},
            ],
        },
        blast_radius_response={"blast_score": 0.8, "total_reachable": 10},
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test pass-the-hash")

    pth_findings = [f for f in result.findings if "T1550.002" in f.evidence.get("technique_id", "")]
    assert len(pth_findings) == 1
    assert pth_findings[0].severity == "critical"
    assert pth_findings[0].evidence.get("blast_score") == 0.8


@pytest.mark.asyncio
async def test_t1482_domain_trust() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        edges=[
            {"source_id": "d1", "target_id": "d2", "edge_type": "TRUSTS"},
            {"source_id": "d2", "target_id": "d3", "edge_type": "TRUSTS"},
            {"source_id": "d3", "target_id": "d4", "edge_type": "TRUSTS"},
        ],
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test domain trust discovery")

    trust_findings = [f for f in result.findings if "T1482" in f.evidence.get("technique_id", "")]
    assert len(trust_findings) == 1
    assert "trust" in trust_findings[0].title.lower()
    assert trust_findings[0].evidence.get("transitive_hops", 0) > 0

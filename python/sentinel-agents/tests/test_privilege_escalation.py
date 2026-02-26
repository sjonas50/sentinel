"""Tests for the Privilege Escalation simulation playbook."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.simulate.models import PrivilegeEscalationConfig
from sentinel_agents.simulate.privilege_escalation import (
    PrivilegeEscalationSimAgent,
)
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_base_sim import MockGraph

# ── Helpers ─────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Simulate privilege escalation",
            "rationale": "Test misconfigurations and vulnerabilities",
            "confidence": 0.85,
            "steps": ["Check CVEs", "Check default accounts"],
            "alternatives": [],
        }
    )
    summary = "Privilege escalation simulation complete."
    return [plan, summary]


def _make_agent(
    graph: MockGraph | None = None,
    config: PrivilegeEscalationConfig | None = None,
) -> PrivilegeEscalationSimAgent:
    agent_config = AgentConfig(
        agent_id="sim-pe-1",
        agent_type="simulate",
        tenant_id=uuid4(),
    )
    return PrivilegeEscalationSimAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        graph=graph or MockGraph(),
        sim_config=config or PrivilegeEscalationConfig(),
    )


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_empty_graph() -> None:
    agent = _make_agent()
    result = await agent.run("Priv esc on empty graph")
    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_t1068_exploitable_vulns() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [],
            "Vulnerability": [
                {
                    "id": "vuln-1",
                    "cve_id": "CVE-2024-5678",
                    "cvss_score": 9.1,
                    "exploitable": True,
                },
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1068")

    t1068_findings = [f for f in result.findings if "T1068" in f.evidence.get("technique_id", "")]
    assert len(t1068_findings) == 1
    assert t1068_findings[0].severity == "critical"
    assert "CVE-2024-5678" in t1068_findings[0].evidence.get("cve_ids", [])


@pytest.mark.asyncio
async def test_t1078_001_default_accounts() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [
                {"id": "u-admin", "username": "admin", "enabled": True},
                {"id": "u-root", "username": "root", "enabled": True},
            ],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "u-admin": [{"id": "h1", "label": "Host"}],
            "u-root": [{"id": "h2", "label": "Host"}],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1078.001")

    default_findings = [
        f for f in result.findings if "T1078.001" in f.evidence.get("technique_id", "")
    ]
    assert len(default_findings) == 2
    usernames = {f.evidence.get("username") for f in default_findings}
    assert "admin" in usernames
    assert "root" in usernames


@pytest.mark.asyncio
async def test_t1548_wildcard_permissions() -> None:
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [],
            "Service": [],
            "Vulnerability": [],
        },
        edges=[
            {"source_id": "u1", "target_id": "role-1", "edge_type": "MEMBER_OF"},
        ],
        neighbors_by_node={
            "role-1": [
                {"id": "role-1", "permissions": ["s3:*", "ec2:*", "iam:*"]},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1548")

    wildcard_findings = [
        f for f in result.findings if "T1548" in f.evidence.get("technique_id", "")
    ]
    assert len(wildcard_findings) == 1
    assert "wildcard" in wildcard_findings[0].title.lower()


@pytest.mark.asyncio
async def test_t1134_token_manipulation() -> None:
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
                {"id": "h1", "criticality": "critical"},
                {"id": "h2", "criticality": "critical"},
                {"id": "h3", "criticality": "high"},
            ],
        },
        blast_radius_response={"blast_score": 0.7, "total_reachable": 8},
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test T1134")

    token_findings = [f for f in result.findings if "T1134" in f.evidence.get("technique_id", "")]
    assert len(token_findings) == 1
    assert token_findings[0].evidence.get("blast_score") == 0.7


@pytest.mark.asyncio
async def test_below_threshold_no_finding() -> None:
    """Service account with < 3 critical hosts should not trigger T1134."""
    graph = MockGraph(
        nodes_by_label={
            "Host": [],
            "User": [
                {"id": "svc-1", "username": "svc-small", "user_type": "service_account"},
            ],
            "Service": [],
            "Vulnerability": [],
        },
        neighbors_by_node={
            "svc-1": [
                {"id": "h1", "criticality": "critical"},
                {"id": "h2", "criticality": "low"},
            ],
        },
    )
    agent = _make_agent(graph=graph)
    result = await agent.run("Test below threshold")

    token_findings = [f for f in result.findings if "T1134" in f.evidence.get("technique_id", "")]
    assert len(token_findings) == 0

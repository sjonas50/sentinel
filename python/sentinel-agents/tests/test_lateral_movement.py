"""Tests for the Lateral Movement hunt playbook."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sentinel_agents.hunt.lateral_movement import LateralMovementHuntAgent
from sentinel_agents.hunt.models import LateralMovementConfig
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_hunt_agent import MockQueryResult, MockSiem, MockSiemEvent

# ── Helpers ──────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Hunt for lateral movement",
            "rationale": "Detect unusual internal traffic patterns",
            "confidence": 0.8,
            "steps": ["Query RDP", "Query SMB", "Analyze service accounts"],
            "alternatives": [],
        }
    )
    summary = "Detected lateral movement patterns."
    return [plan, summary]


def _make_agent(
    siem: MockSiem | None = None,
    config: LateralMovementConfig | None = None,
) -> LateralMovementHuntAgent:
    agent_config = AgentConfig(
        agent_id="hunt-lateral-1",
        agent_type="hunt",
        tenant_id=uuid4(),
    )
    return LateralMovementHuntAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        siem=siem or MockSiem(),
        hunt_config=config or LateralMovementConfig(),
    )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_clean_data() -> None:
    agent = _make_agent()
    result = await agent.run("Hunt for lateral movement")

    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_service_account_hopping() -> None:
    events = [
        MockSiemEvent(
            id="svc-1",
            user="svc-deploy",
            hostname="web-01",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.10",
        ),
        MockSiemEvent(
            id="svc-2",
            user="svc-deploy",
            hostname="db-01",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.20",
        ),
        MockSiemEvent(
            id="svc-3",
            user="svc-deploy",
            hostname="app-01",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.30",
        ),
    ]
    siem = MockSiem(
        query_responses={
            "svc-*": MockQueryResult(events=events, total_hits=3),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for service account hopping")

    svc_findings = [f for f in result.findings if "svc-deploy" in f.title]
    assert len(svc_findings) == 1
    assert svc_findings[0].severity == "high"
    assert "T1021" in svc_findings[0].evidence.get("mitre_technique_ids", [])


@pytest.mark.asyncio
async def test_rdp_fan_out_detection() -> None:
    events = [
        MockSiemEvent(
            id="rdp-1",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.10",
            dest_port=3389,
        ),
        MockSiemEvent(
            id="rdp-2",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.20",
            dest_port=3389,
        ),
    ]
    siem = MockSiem(
        query_responses={
            "3389": MockQueryResult(events=events, total_hits=2),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for RDP lateral movement")

    rdp_findings = [f for f in result.findings if "RDP" in f.title]
    assert len(rdp_findings) == 1
    assert rdp_findings[0].severity == "medium"
    assert "T1021.001" in rdp_findings[0].evidence.get("mitre_technique_ids", [])
    assert "10.0.0.5" in rdp_findings[0].evidence.get("affected_hosts", [])


@pytest.mark.asyncio
async def test_smb_fan_out_detection() -> None:
    events = [
        MockSiemEvent(
            id="smb-1",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.11",
            dest_port=445,
        ),
        MockSiemEvent(
            id="smb-2",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.12",
            dest_port=445,
        ),
    ]
    siem = MockSiem(
        query_responses={
            "445": MockQueryResult(events=events, total_hits=2),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for SMB lateral movement")

    smb_findings = [f for f in result.findings if "SMB" in f.title]
    assert len(smb_findings) == 1
    assert smb_findings[0].severity == "medium"
    assert "T1021.002" in smb_findings[0].evidence.get("mitre_technique_ids", [])


@pytest.mark.asyncio
async def test_service_account_below_threshold() -> None:
    # Only 1 host — below threshold of 2
    events = [
        MockSiemEvent(id="svc-1", user="svc-deploy", hostname="web-01"),
    ]
    siem = MockSiem(
        query_responses={
            "svc-*": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt with single host svc account")

    svc_findings = [f for f in result.findings if "svc-deploy" in f.title]
    assert len(svc_findings) == 0


@pytest.mark.asyncio
async def test_queries_executed() -> None:
    siem = MockSiem()
    agent = _make_agent(siem=siem)
    await agent.run("Verify query count")

    # 4 queries: internal_rdp, service_account_hops, smb_winrm, unusual_ports
    assert len(siem.queries_executed) == 4


@pytest.mark.asyncio
async def test_sigma_rule_for_lateral_finding() -> None:
    events = [
        MockSiemEvent(
            id="rdp-1",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.10",
            dest_port=3389,
        ),
        MockSiemEvent(
            id="rdp-2",
            source_ip="10.0.0.5",
            dest_ip="10.0.0.20",
            dest_port=3389,
        ),
    ]
    siem = MockSiem(
        query_responses={
            "3389": MockQueryResult(events=events, total_hits=2),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt with sigma")

    rdp_findings = [f for f in result.findings if "RDP" in f.title]
    assert len(rdp_findings) == 1
    sigma = rdp_findings[0].evidence.get("sigma_yaml", "")
    assert "lateral_movement" in sigma

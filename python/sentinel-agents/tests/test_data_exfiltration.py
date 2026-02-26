"""Tests for the Data Exfiltration hunt playbook."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sentinel_agents.hunt.data_exfiltration import DataExfiltrationHuntAgent
from sentinel_agents.hunt.models import DataExfiltrationConfig
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_hunt_agent import MockQueryResult, MockSiem, MockSiemEvent

# ── Helpers ──────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Hunt for data exfiltration",
            "rationale": "Detect large transfers and DNS tunneling",
            "confidence": 0.8,
            "steps": ["Query large transfers", "Check DNS", "Analyze patterns"],
            "alternatives": [],
        }
    )
    summary = "Exfiltration analysis complete."
    return [plan, summary]


def _make_agent(
    siem: MockSiem | None = None,
    config: DataExfiltrationConfig | None = None,
) -> DataExfiltrationHuntAgent:
    agent_config = AgentConfig(
        agent_id="hunt-exfil-1",
        agent_type="hunt",
        tenant_id=uuid4(),
    )
    return DataExfiltrationHuntAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=_make_llm_responses()),
        tool_registry=ToolRegistry(),
        siem=siem or MockSiem(),
        hunt_config=config or DataExfiltrationConfig(),
    )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_clean_data() -> None:
    agent = _make_agent()
    result = await agent.run("Hunt for data exfiltration")

    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_large_outbound_transfer() -> None:
    events = [
        MockSiemEvent(
            id="net-1",
            source_ip="10.0.0.50",
            dest_ip="203.0.113.10",
            raw={"network": {"bytes": 150_000_000}},
        ),
    ]
    siem = MockSiem(
        query_responses={
            "network.bytes": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for large transfers")

    large_findings = [f for f in result.findings if "Large data transfer" in f.title]
    assert len(large_findings) == 1
    assert large_findings[0].severity == "high"
    assert "T1567" in large_findings[0].evidence.get("mitre_technique_ids", [])
    assert "203.0.113.10" in large_findings[0].evidence.get("dest_ips", [])


@pytest.mark.asyncio
async def test_dns_tunneling_detection() -> None:
    long_domain = "a" * 60 + ".evil.com"
    events = [
        MockSiemEvent(
            id="dns-1",
            source_ip="10.0.0.30",
            raw={"dns": {"question": {"name": long_domain}}},
        ),
    ]
    siem = MockSiem(
        query_responses={
            "event.category": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for DNS tunneling")

    dns_findings = [f for f in result.findings if "DNS tunneling" in f.title]
    assert len(dns_findings) == 1
    assert dns_findings[0].severity == "high"
    assert "T1071.004" in dns_findings[0].evidence.get("mitre_technique_ids", [])


@pytest.mark.asyncio
async def test_dns_short_queries_no_finding() -> None:
    short_domain = "google.com"
    events = [
        MockSiemEvent(
            id="dns-1",
            source_ip="10.0.0.30",
            raw={"dns": {"question": {"name": short_domain}}},
        ),
    ]
    siem = MockSiem(
        query_responses={
            "event.category": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt with normal DNS")

    dns_findings = [f for f in result.findings if "DNS tunneling" in f.title]
    assert len(dns_findings) == 0


@pytest.mark.asyncio
async def test_after_hours_detection() -> None:
    # 11 PM — within after-hours window (22-6)
    late_time = datetime(2024, 6, 15, 23, 30, tzinfo=UTC)
    events = [
        MockSiemEvent(
            id="late-1",
            source_ip="10.0.0.40",
            timestamp=late_time,
            raw={"network": {"bytes": 50_000_000}},
        ),
    ]
    siem = MockSiem(
        query_responses={
            "event.category": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for after-hours activity")

    after_findings = [f for f in result.findings if "After-hours" in f.title]
    assert len(after_findings) == 1
    assert after_findings[0].severity == "medium"
    assert "T1048" in after_findings[0].evidence.get("mitre_technique_ids", [])


@pytest.mark.asyncio
async def test_business_hours_no_after_hours_finding() -> None:
    # 2 PM — within business hours
    daytime = datetime(2024, 6, 15, 14, 0, tzinfo=UTC)
    events = [
        MockSiemEvent(
            id="day-1",
            source_ip="10.0.0.40",
            timestamp=daytime,
            raw={"network": {"bytes": 50_000_000}},
        ),
    ]
    siem = MockSiem(
        query_responses={
            "event.category": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt during business hours")

    after_findings = [f for f in result.findings if "After-hours" in f.title]
    assert len(after_findings) == 0


@pytest.mark.asyncio
async def test_queries_executed() -> None:
    siem = MockSiem()
    agent = _make_agent(siem=siem)
    await agent.run("Verify query count")

    # 4 queries: large_outbound, dns_tunneling, unusual_destinations, after_hours
    assert len(siem.queries_executed) == 4


@pytest.mark.asyncio
async def test_sigma_rule_for_exfil_finding() -> None:
    events = [
        MockSiemEvent(
            id="net-1",
            source_ip="10.0.0.50",
            dest_ip="203.0.113.10",
            raw={"network": {"bytes": 150_000_000}},
        ),
    ]
    siem = MockSiem(
        query_responses={
            "network.bytes": MockQueryResult(events=events, total_hits=1),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt with sigma")

    large_findings = [f for f in result.findings if "Large data transfer" in f.title]
    assert len(large_findings) == 1
    sigma = large_findings[0].evidence.get("sigma_yaml", "")
    assert "exfiltration" in sigma

"""Tests for the Credential Abuse hunt playbook."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sentinel_agents.hunt.credential_abuse import CredentialAbuseHuntAgent
from sentinel_agents.hunt.models import CredentialAbuseConfig
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentStatus

from tests.test_hunt_agent import MockQueryResult, MockSiem, MockSiemEvent

# ── Helpers ──────────────────────────────────────────────────────


def _make_llm_responses() -> list[str]:
    plan = json.dumps(
        {
            "description": "Hunt for credential abuse",
            "rationale": "Detect brute force and credential stuffing",
            "confidence": 0.85,
            "steps": ["Query failed logins", "Analyze patterns"],
            "alternatives": [],
        }
    )
    # LLM summary response
    summary = "Detected 2 suspicious IPs with brute force patterns."
    # LLM supplementary analysis (returns no extra findings)
    llm_analysis = json.dumps({"findings": []})
    return [plan, llm_analysis, summary]


def _make_agent(
    siem: MockSiem | None = None,
    config: CredentialAbuseConfig | None = None,
    llm_responses: list[str] | None = None,
) -> CredentialAbuseHuntAgent:
    agent_config = AgentConfig(
        agent_id="hunt-cred-1",
        agent_type="hunt",
        tenant_id=uuid4(),
    )
    return CredentialAbuseHuntAgent(
        config=agent_config,
        llm=MockLLMProvider(responses=llm_responses or _make_llm_responses()),
        tool_registry=ToolRegistry(),
        siem=siem or MockSiem(),
        hunt_config=config or CredentialAbuseConfig(),
    )


def _make_failed_login_events(
    ip: str, users: list[str], count_per_user: int = 1
) -> list[MockSiemEvent]:
    events = []
    for user in users:
        for i in range(count_per_user):
            events.append(
                MockSiemEvent(
                    id=f"evt-{ip}-{user}-{i}",
                    source_ip=ip,
                    user=user,
                    event_type="authentication",
                )
            )
    return events


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_on_clean_data() -> None:
    agent = _make_agent()
    result = await agent.run("Hunt for credential abuse")

    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_brute_force_detection() -> None:
    events = _make_failed_login_events("10.0.0.99", ["admin"], count_per_user=15)
    siem = MockSiem(
        query_responses={
            "event.outcome": MockQueryResult(events=events, total_hits=15),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for brute force")

    # Should find brute force (15 >= threshold of 10)
    brute_force = [f for f in result.findings if "Excessive failed logins" in f.title]
    assert len(brute_force) >= 1
    assert brute_force[0].severity in ("medium", "high")
    assert "T1110.001" in brute_force[0].evidence.get("mitre_technique_ids", [])


@pytest.mark.asyncio
async def test_brute_force_high_severity() -> None:
    # 35 failures (> 10 * 3 = 30 → high severity)
    events = _make_failed_login_events("10.0.0.99", ["admin"], count_per_user=35)
    siem = MockSiem(
        query_responses={
            "event.outcome": MockQueryResult(events=events, total_hits=35),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for heavy brute force")

    brute_force = [f for f in result.findings if "Excessive failed logins" in f.title]
    assert len(brute_force) >= 1
    assert brute_force[0].severity == "high"


@pytest.mark.asyncio
async def test_credential_stuffing_detection() -> None:
    # 5 unique users from same IP (meets default threshold of 5)
    users = ["user1", "user2", "user3", "user4", "user5"]
    events = _make_failed_login_events("192.168.1.50", users)
    siem = MockSiem(
        query_responses={
            "event.outcome": MockQueryResult(events=events, total_hits=5),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for credential stuffing")

    stuffing = [f for f in result.findings if "credential stuffing" in f.title.lower()]
    assert len(stuffing) >= 1
    assert stuffing[0].severity == "high"
    assert "T1110.004" in stuffing[0].evidence.get("mitre_technique_ids", [])


@pytest.mark.asyncio
async def test_service_account_failures() -> None:
    events = [
        MockSiemEvent(id="svc-1", source_ip="10.0.0.1", user="svc-deploy"),
        MockSiemEvent(id="svc-2", source_ip="10.0.0.2", user="svc-backup"),
    ]
    siem = MockSiem(
        query_responses={
            # Use "wildcard" key — only the service account query has it
            "wildcard": MockQueryResult(events=events, total_hits=2),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt for service account abuse")

    svc_findings = [f for f in result.findings if "Service account" in f.title]
    assert len(svc_findings) == 1
    assert svc_findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_threshold_configuration() -> None:
    # 8 failures, threshold set to 5
    events = _make_failed_login_events("10.0.0.99", ["admin"], count_per_user=8)
    siem = MockSiem(
        query_responses={
            "event.outcome": MockQueryResult(events=events, total_hits=8),
        }
    )
    config = CredentialAbuseConfig(failed_login_threshold=5)
    agent = _make_agent(siem=siem, config=config)
    result = await agent.run("Hunt with low threshold")

    brute_force = [f for f in result.findings if "Excessive failed logins" in f.title]
    assert len(brute_force) >= 1


@pytest.mark.asyncio
async def test_below_threshold_no_finding() -> None:
    # 3 failures, below default threshold of 10
    events = _make_failed_login_events("10.0.0.99", ["admin"], count_per_user=3)
    siem = MockSiem(
        query_responses={
            "event.outcome": MockQueryResult(events=events, total_hits=3),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt below threshold")

    brute_force = [f for f in result.findings if "Excessive failed logins" in f.title]
    assert len(brute_force) == 0


@pytest.mark.asyncio
async def test_sigma_rule_generated_for_finding() -> None:
    events = _make_failed_login_events("10.0.0.99", ["admin"], count_per_user=15)
    siem = MockSiem(
        query_responses={
            "event.outcome": MockQueryResult(events=events, total_hits=15),
        }
    )
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt with sigma")

    findings_with_sigma = [f for f in result.findings if f.evidence.get("sigma_yaml")]
    assert len(findings_with_sigma) >= 1
    sigma_yaml = findings_with_sigma[0].evidence["sigma_yaml"]
    assert "credential_access" in sigma_yaml


@pytest.mark.asyncio
async def test_lockout_query_disabled() -> None:
    config = CredentialAbuseConfig(lockout_correlation=False)
    siem = MockSiem()
    agent = _make_agent(siem=siem, config=config)
    await agent.run("Hunt without lockout correlation")

    # Should not have executed account_lockouts query
    query_dsls = [json.dumps(q["query_dsl"]) for q in siem.queries_executed]
    assert not any("4740" in q for q in query_dsls)

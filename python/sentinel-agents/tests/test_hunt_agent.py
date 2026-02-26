"""Tests for the HuntAgent base class with a stub playbook."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from sentinel_agents.hunt.base_hunt import HuntAgent
from sentinel_agents.hunt.models import (
    HuntConfig,
    HuntFinding,
    PlaybookType,
    SiemProtocol,
)
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import AgentConfig, AgentPlan, AgentStatus

# ── Mock SIEM fixtures ───────────────────────────────────────────


class MockSiemEvent:
    """Minimal SiemEvent-like object for testing."""

    def __init__(self, **kwargs: Any) -> None:
        self.id = kwargs.get("id", "evt-1")
        self.index = kwargs.get("index", "test-index")
        self.timestamp = kwargs.get("timestamp")
        self.source_ip = kwargs.get("source_ip")
        self.dest_ip = kwargs.get("dest_ip")
        self.source_port = kwargs.get("source_port")
        self.dest_port = kwargs.get("dest_port")
        self.event_type = kwargs.get("event_type")
        self.severity = kwargs.get("severity")
        self.message = kwargs.get("message")
        self.user = kwargs.get("user")
        self.hostname = kwargs.get("hostname")
        self.raw = kwargs.get("raw", {})


class MockQueryResult:
    """Minimal QueryResult-like object for testing."""

    def __init__(
        self,
        events: list[MockSiemEvent] | None = None,
        total_hits: int = 0,
    ) -> None:
        self.events = events or []
        self.total_hits = total_hits
        self.took_ms = 5
        self.timed_out = False
        self.query_dsl: dict[str, Any] = {}
        self.aggregations: dict[str, Any] = {}


class MockSiem:
    """Mock SIEM connector satisfying SiemProtocol."""

    def __init__(self, query_responses: dict[str, MockQueryResult] | None = None) -> None:
        self._responses = query_responses or {}
        self._default_response = MockQueryResult()
        self.queries_executed: list[dict[str, Any]] = []

    async def execute_query(
        self,
        query_dsl: dict[str, Any],
        index: str,
        *,
        size: int = 100,
        sort: list[dict[str, Any]] | None = None,
        aggs: dict[str, Any] | None = None,
    ) -> MockQueryResult:
        self.queries_executed.append({"query_dsl": query_dsl, "index": index, "size": size})
        # Match by looking for query key substrings in DSL
        for key, response in self._responses.items():
            if key in json.dumps(query_dsl):
                return response
        return self._default_response

    async def discover_indices(self, pattern: str = "*") -> Any:
        return None


# Verify MockSiem satisfies protocol
assert isinstance(MockSiem(), SiemProtocol)


# ── Stub HuntAgent for testing ───────────────────────────────────


class StubHuntAgent(HuntAgent):
    """Minimal HuntAgent implementation for testing base class behavior."""

    async def build_queries(self, plan: AgentPlan) -> list[tuple[str, dict[str, Any], str]]:
        return [
            ("test_query", {"match_all": {}}, self.hunt_config.index_pattern),
        ]

    async def analyze_results(self, query_results: dict[str, Any]) -> list[HuntFinding]:
        result = query_results.get("test_query")
        if result and result.total_hits > 0:
            return [
                HuntFinding(
                    playbook=self.hunt_config.playbook,
                    severity="medium",
                    title="Test finding",
                    description=f"Found {result.total_hits} events",
                    evidence={"total_hits": result.total_hits},
                    mitre_technique_ids=["T1234"],
                    mitre_tactic="Test",
                )
            ]
        return []


# ── Helpers ──────────────────────────────────────────────────────


def _make_llm_plan_response() -> str:
    return json.dumps(
        {
            "description": "Run test queries against SIEM",
            "rationale": "Test hunt plan",
            "confidence": 0.9,
            "steps": ["Execute test query", "Analyze results"],
            "alternatives": [],
        }
    )


def _make_agent(
    siem: MockSiem | None = None,
    hunt_config: HuntConfig | None = None,
    llm_responses: list[str] | None = None,
) -> StubHuntAgent:
    config = AgentConfig(
        agent_id="hunt-test-1",
        agent_type="hunt",
        tenant_id=uuid4(),
    )
    llm = MockLLMProvider(responses=llm_responses or [_make_llm_plan_response(), "Hunt summary"])
    return StubHuntAgent(
        config=config,
        llm=llm,
        tool_registry=ToolRegistry(),
        siem=siem or MockSiem(),
        hunt_config=hunt_config or HuntConfig(playbook=PlaybookType.CREDENTIAL_ABUSE),
    )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hunt_agent_run_lifecycle() -> None:
    events = [MockSiemEvent(id="e1", source_ip="10.0.0.1")]
    siem = MockSiem(query_responses={"match_all": MockQueryResult(events=events, total_hits=1)})
    agent = _make_agent(siem=siem)
    result = await agent.run("Test credential abuse hunt")

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_type == "hunt"
    assert result.engram_id is not None
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test finding"


@pytest.mark.asyncio
async def test_hunt_agent_no_findings() -> None:
    agent = _make_agent()  # MockSiem returns empty by default
    result = await agent.run("Hunt with no results")

    assert result.status == AgentStatus.COMPLETED
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_hunt_agent_queries_siem() -> None:
    siem = MockSiem()
    agent = _make_agent(siem=siem)
    await agent.run("Test hunt")

    assert len(siem.queries_executed) == 1
    assert siem.queries_executed[0]["index"] == "filebeat-*,winlogbeat-*,logs-*"


@pytest.mark.asyncio
async def test_hunt_agent_sigma_generation() -> None:
    events = [MockSiemEvent(id="e1", source_ip="10.0.0.1")]
    siem = MockSiem(query_responses={"match_all": MockQueryResult(events=events, total_hits=1)})
    agent = _make_agent(siem=siem)
    result = await agent.run("Hunt with sigma rules")

    assert len(result.findings) == 1
    evidence = result.findings[0].evidence
    assert evidence.get("sigma_yaml") is not None
    assert "attack.credential_access" in evidence["sigma_yaml"]


@pytest.mark.asyncio
async def test_hunt_agent_sigma_disabled() -> None:
    events = [MockSiemEvent(id="e1", source_ip="10.0.0.1")]
    siem = MockSiem(query_responses={"match_all": MockQueryResult(events=events, total_hits=1)})
    cfg = HuntConfig(playbook=PlaybookType.CREDENTIAL_ABUSE, generate_sigma_rules=False)
    agent = _make_agent(siem=siem, hunt_config=cfg)
    result = await agent.run("Hunt without sigma rules")

    assert len(result.findings) == 1
    evidence = result.findings[0].evidence
    assert evidence.get("sigma_yaml") is None


@pytest.mark.asyncio
async def test_hunt_agent_cancellation() -> None:
    siem = MockSiem()
    agent = _make_agent(siem=siem)
    agent.request_cancel()

    await agent.run("Cancelled hunt")
    # Agent should complete quickly with no queries executed
    assert len(siem.queries_executed) == 0


@pytest.mark.asyncio
async def test_hunt_agent_finding_has_mitre_context() -> None:
    events = [MockSiemEvent(id="e1")]
    siem = MockSiem(query_responses={"match_all": MockQueryResult(events=events, total_hits=1)})
    agent = _make_agent(siem=siem)
    result = await agent.run("MITRE test")

    finding = result.findings[0]
    assert "mitre_technique_ids" in finding.evidence
    assert finding.evidence["mitre_technique_ids"] == ["T1234"]
    assert finding.evidence["mitre_tactic"] == "Test"

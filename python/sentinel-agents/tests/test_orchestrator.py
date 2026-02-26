"""Tests for the agent orchestrator."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.orchestrator import AgentOrchestrator
from sentinel_agents.tools import ToolRegistry
from sentinel_agents.types import (
    AgentConfig,
    AgentStatus,
)

from .test_base_agent import StubAgent

# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def orchestrator() -> AgentOrchestrator:
    return AgentOrchestrator()


@pytest.fixture
def tenant_id():
    return uuid4()


def make_agent(
    tenant_id,
    agent_id: str = "test-agent",
    *,
    fail: bool = False,
) -> StubAgent:
    config = AgentConfig(
        agent_id=agent_id,
        agent_type="hunt",
        tenant_id=tenant_id,
    )
    return StubAgent(
        config,
        MockLLMProvider(),
        ToolRegistry(),
        fail_during_execute=fail,
    )


# ── Tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_session(orchestrator: AgentOrchestrator, tenant_id) -> None:
    agent = make_agent(tenant_id)
    session_id = await orchestrator.start(agent, "Hunt for threats")

    assert session_id is not None
    session = orchestrator.get_status(session_id)
    assert session.session_id == session_id

    # Wait for the background task to complete
    await asyncio.sleep(0.1)

    session = orchestrator.get_status(session_id)
    assert session.status == AgentStatus.COMPLETED
    assert session.result is not None
    assert session.result.status == AgentStatus.COMPLETED


@pytest.mark.asyncio
async def test_cancel_session(orchestrator: AgentOrchestrator, tenant_id) -> None:
    agent = make_agent(tenant_id)
    session_id = await orchestrator.start(agent, "Hunt for threats")
    await orchestrator.cancel(session_id)

    session = orchestrator.get_status(session_id)
    assert session.status == AgentStatus.CANCELLED
    assert agent.is_cancelled


@pytest.mark.asyncio
async def test_get_status(orchestrator: AgentOrchestrator, tenant_id) -> None:
    agent = make_agent(tenant_id)
    session_id = await orchestrator.start(agent, "intent")

    session = orchestrator.get_status(session_id)
    assert session.agent is agent
    assert session.created_at is not None


@pytest.mark.asyncio
async def test_list_sessions(orchestrator: AgentOrchestrator) -> None:
    tid1 = uuid4()
    tid2 = uuid4()

    await orchestrator.start(make_agent(tid1, "agent-1"), "intent-1")
    await orchestrator.start(make_agent(tid1, "agent-2"), "intent-2")
    await orchestrator.start(make_agent(tid2, "agent-3"), "intent-3")

    all_sessions = orchestrator.list_sessions()
    assert len(all_sessions) == 3

    tid1_sessions = orchestrator.list_sessions(tenant_id=tid1)
    assert len(tid1_sessions) == 2

    tid2_sessions = orchestrator.list_sessions(tenant_id=tid2)
    assert len(tid2_sessions) == 1


@pytest.mark.asyncio
async def test_failed_session(orchestrator: AgentOrchestrator, tenant_id) -> None:
    agent = make_agent(tenant_id, fail=True)
    session_id = await orchestrator.start(agent, "will fail")

    await asyncio.sleep(0.1)

    session = orchestrator.get_status(session_id)
    assert session.status == AgentStatus.FAILED
    assert session.result is not None
    assert session.result.error == "Simulated failure"

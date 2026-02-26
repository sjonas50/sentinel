"""Tests for BaseAgent lifecycle and Engram integration."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from sentinel_agents.base import BaseAgent
from sentinel_agents.llm import MockLLMProvider
from sentinel_agents.tools import Tool, ToolRegistry, ToolResult
from sentinel_agents.types import (
    AgentConfig,
    AgentPlan,
    AgentResult,
    AgentStatus,
    Finding,
    PlanAlternative,
)

# ── Concrete test agent ──────────────────────────────────────────


class StubAgent(BaseAgent):
    """Minimal agent for testing the base lifecycle."""

    def __init__(
        self,
        config: AgentConfig,
        llm: MockLLMProvider,
        tool_registry: ToolRegistry,
        *,
        fail_during_execute: bool = False,
    ) -> None:
        super().__init__(config, llm, tool_registry)
        self.fail_during_execute = fail_during_execute

    async def plan(self, intent: str, context: dict[str, Any]) -> AgentPlan:
        return AgentPlan(
            description="Test plan",
            rationale="For testing",
            confidence=0.9,
            steps=["step-1", "step-2"],
            alternatives=[PlanAlternative(option="alt-plan", reason="not needed")],
        )

    async def execute(self, plan: AgentPlan) -> AgentResult:
        if self.fail_during_execute:
            msg = "Simulated failure"
            raise RuntimeError(msg)
        return AgentResult(
            agent_id=self.config.agent_id,
            agent_type=self.config.agent_type,
            tenant_id=self.config.tenant_id,
            status=AgentStatus.RUNNING,
            findings=[
                Finding(
                    severity="high",
                    title="Test finding",
                    description="Found something",
                ),
            ],
            actions_taken=2,
        )


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def config() -> AgentConfig:
    return AgentConfig(
        agent_id="test-agent-1",
        agent_type="hunt",
        tenant_id=uuid4(),
    )


@pytest.fixture
def tool_registry() -> ToolRegistry:
    return ToolRegistry()


@pytest.fixture
def llm() -> MockLLMProvider:
    return MockLLMProvider()


# ── Tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_lifecycle(
    config: AgentConfig, llm: MockLLMProvider, tool_registry: ToolRegistry
) -> None:
    agent = StubAgent(config, llm, tool_registry)
    assert agent.status == AgentStatus.PENDING

    result = await agent.run("Hunt for threats")

    assert result.status == AgentStatus.COMPLETED
    assert agent.status == AgentStatus.COMPLETED
    assert result.agent_id == config.agent_id
    assert result.tenant_id == config.tenant_id
    assert len(result.findings) == 1
    assert result.actions_taken == 2
    assert result.error is None


@pytest.mark.asyncio
async def test_run_records_engram(
    config: AgentConfig, llm: MockLLMProvider, tool_registry: ToolRegistry
) -> None:
    agent = StubAgent(config, llm, tool_registry)
    result = await agent.run("Hunt for threats", {"scope": "network"})

    # Engram should have been finalized
    assert result.engram_id is not None
    assert result.completed_at is not None

    # Verify the session recorded decisions and actions
    engram = agent._session._engram  # type: ignore[union-attr]
    assert len(engram.decisions) == 1
    assert engram.decisions[0].choice == "Test plan"
    assert len(engram.alternatives) == 1
    assert engram.alternatives[0].option == "alt-plan"
    assert len(engram.actions) >= 1  # at least execution_complete


@pytest.mark.asyncio
async def test_run_handles_failure(
    config: AgentConfig, llm: MockLLMProvider, tool_registry: ToolRegistry
) -> None:
    agent = StubAgent(config, llm, tool_registry, fail_during_execute=True)
    result = await agent.run("Hunt for threats")

    assert result.status == AgentStatus.FAILED
    assert agent.status == AgentStatus.FAILED
    assert result.error == "Simulated failure"
    assert result.engram_id is not None


@pytest.mark.asyncio
async def test_cancel_request(
    config: AgentConfig, llm: MockLLMProvider, tool_registry: ToolRegistry
) -> None:
    agent = StubAgent(config, llm, tool_registry)
    assert not agent.is_cancelled

    agent.request_cancel()
    assert agent.is_cancelled


@pytest.mark.asyncio
async def test_execute_tool_records_action(
    config: AgentConfig, llm: MockLLMProvider, tool_registry: ToolRegistry
) -> None:
    async def mock_handler(**kwargs: Any) -> ToolResult:
        return ToolResult(success=True, data={"found": 3})

    tool = Tool(name="search_graph", description="Search the graph", agent_types=["hunt"])
    tool_registry.register(tool, mock_handler)

    agent = StubAgent(config, llm, tool_registry)
    # Manually set up session so execute_tool works
    from sentinel_api.engram.session import EngramSession

    agent._session = EngramSession(
        tenant_id=config.tenant_id,
        agent_id=config.agent_id,
        intent="test",
    )

    result = await agent.execute_tool("search_graph", {"query": "test"})

    assert result.success
    assert result.data == {"found": 3}
    # Verify action was recorded in engram
    assert len(agent._session._engram.actions) == 1
    assert agent._session._engram.actions[0].action_type == "tool_search_graph"

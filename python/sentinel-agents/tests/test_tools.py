"""Tests for tool registry and policy enforcement."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sentinel_agents.tools import (
    PolicyViolationError,
    Tool,
    ToolParam,
    ToolRegistry,
    ToolResult,
)

# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry()


@pytest.fixture
def sample_tool() -> Tool:
    return Tool(
        name="search_graph",
        description="Search the asset graph",
        agent_types=["hunt", "discover"],
        params=[
            ToolParam(name="query", type="string", description="Search query"),
            ToolParam(name="limit", type="integer", description="Max results", required=False),
        ],
    )


async def mock_handler(**kwargs: Any) -> ToolResult:
    return ToolResult(success=True, data={"results": [1, 2, 3]})


# ── Registration and lookup ───────────────────────────────────────


def test_register_and_get(registry: ToolRegistry, sample_tool: Tool) -> None:
    registry.register(sample_tool, mock_handler)
    tool, handler = registry.get("search_graph")
    assert tool.name == "search_graph"
    assert handler is mock_handler


def test_get_unknown_raises(registry: ToolRegistry) -> None:
    with pytest.raises(KeyError):
        registry.get("nonexistent")


def test_list_for_agent_type(registry: ToolRegistry) -> None:
    hunt_tool = Tool(name="query_logs", description="Query logs", agent_types=["hunt"])
    discover_tool = Tool(name="scan_network", description="Scan", agent_types=["discover"])
    shared_tool = Tool(
        name="read_graph", description="Read graph", agent_types=["hunt", "discover"]
    )

    registry.register(hunt_tool, mock_handler)
    registry.register(discover_tool, mock_handler)
    registry.register(shared_tool, mock_handler)

    hunt_tools = registry.list_for_agent_type("hunt")
    assert len(hunt_tools) == 2
    names = {t.name for t in hunt_tools}
    assert names == {"query_logs", "read_graph"}

    discover_tools = registry.list_for_agent_type("discover")
    assert len(discover_tools) == 2

    simulate_tools = registry.list_for_agent_type("simulate")
    assert len(simulate_tools) == 0


# ── Execution ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_execute_allowed(registry: ToolRegistry, sample_tool: Tool) -> None:
    registry.register(sample_tool, mock_handler)
    result = await registry.execute(
        "search_graph",
        agent_type="hunt",
        params={"query": "test"},
    )
    assert result.success
    assert result.data == {"results": [1, 2, 3]}


@pytest.mark.asyncio
async def test_execute_wrong_agent_type(registry: ToolRegistry, sample_tool: Tool) -> None:
    registry.register(sample_tool, mock_handler)
    with pytest.raises(PolicyViolationError, match="not allowed"):
        await registry.execute(
            "search_graph",
            agent_type="simulate",
            params={"query": "test"},
        )


@pytest.mark.asyncio
async def test_execute_denied_by_policy(registry: ToolRegistry, sample_tool: Tool) -> None:
    from sentinel_policy.models import Decision, Tier

    registry.register(sample_tool, mock_handler)

    mock_engine = AsyncMock()
    mock_engine.evaluate_agent_action.return_value = Decision(
        allowed=False,
        tier=Tier.DENY,
        reasons=["Action blocked by policy"],
    )

    with pytest.raises(PolicyViolationError, match="blocked by policy"):
        await registry.execute(
            "search_graph",
            agent_type="hunt",
            params={"query": "test"},
            policy_engine=mock_engine,
            agent_id="agent-1",
            tenant_id=str(uuid4()),
        )


@pytest.mark.asyncio
async def test_execute_with_policy_allowed(registry: ToolRegistry, sample_tool: Tool) -> None:
    from sentinel_policy.models import Decision, Tier

    registry.register(sample_tool, mock_handler)

    mock_engine = AsyncMock()
    mock_engine.evaluate_agent_action.return_value = Decision(
        allowed=True,
        tier=Tier.AUTO,
        reasons=[],
    )

    result = await registry.execute(
        "search_graph",
        agent_type="hunt",
        params={"query": "test"},
        policy_engine=mock_engine,
        agent_id="agent-1",
        tenant_id=str(uuid4()),
    )
    assert result.success


@pytest.mark.asyncio
async def test_execute_records_engram(registry: ToolRegistry, sample_tool: Tool) -> None:
    from sentinel_api.engram.session import EngramSession

    registry.register(sample_tool, mock_handler)
    session = EngramSession(tenant_id=uuid4(), agent_id="test", intent="test")

    await registry.execute(
        "search_graph",
        agent_type="hunt",
        params={"query": "test"},
        session=session,
    )

    assert len(session._engram.actions) == 1
    assert session._engram.actions[0].action_type == "tool_search_graph"
    assert session._engram.actions[0].success


@pytest.mark.asyncio
async def test_execute_records_policy_violation_in_engram(
    registry: ToolRegistry, sample_tool: Tool
) -> None:
    from sentinel_api.engram.session import EngramSession
    from sentinel_policy.models import Decision, Tier

    registry.register(sample_tool, mock_handler)
    session = EngramSession(tenant_id=uuid4(), agent_id="test", intent="test")

    mock_engine = AsyncMock()
    mock_engine.evaluate_agent_action.return_value = Decision(
        allowed=False,
        tier=Tier.DENY,
        reasons=["Blocked"],
    )

    with pytest.raises(PolicyViolationError):
        await registry.execute(
            "search_graph",
            agent_type="hunt",
            params={"query": "test"},
            policy_engine=mock_engine,
            agent_id="agent-1",
            tenant_id="t-1",
            session=session,
        )

    assert len(session._engram.actions) == 1
    assert session._engram.actions[0].action_type == "policy_violation"
    assert not session._engram.actions[0].success

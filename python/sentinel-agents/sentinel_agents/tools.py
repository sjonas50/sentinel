"""Tool registry with policy enforcement and Engram recording."""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

if TYPE_CHECKING:
    from sentinel_api.engram.session import EngramSession
    from sentinel_policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class PolicyViolationError(Exception):
    """Raised when a tool call is denied by the policy engine."""

    def __init__(self, tool_name: str, reasons: list[str]) -> None:
        self.tool_name = tool_name
        self.reasons = reasons
        super().__init__(f"Policy denied tool '{tool_name}': {', '.join(reasons)}")


class ToolParam(BaseModel):
    """Schema for a single tool parameter."""

    name: str
    type: str  # "string", "integer", "boolean", "object"
    description: str
    required: bool = True


class ToolResult(BaseModel):
    """Result returned from a tool execution."""

    success: bool
    data: Any = None
    error: str | None = None


class Tool(BaseModel):
    """A tool that agents can invoke."""

    name: str
    description: str
    agent_types: list[str]  # which agent types may use this tool
    params: list[ToolParam] = []


# Type alias for async tool handlers
ToolHandler = Callable[..., Coroutine[Any, Any, ToolResult]]


class ToolRegistry:
    """Registry of available tools with policy-checked execution."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, tool: Tool, handler: ToolHandler) -> None:
        """Register a tool and its handler."""
        self._tools[tool.name] = tool
        self._handlers[tool.name] = handler

    def get(self, name: str) -> tuple[Tool, ToolHandler]:
        """Look up a tool and its handler by name.

        Raises:
            KeyError: If the tool is not registered.
        """
        return self._tools[name], self._handlers[name]

    def list_for_agent_type(self, agent_type: str) -> list[Tool]:
        """Return tools available to the given agent type."""
        return [t for t in self._tools.values() if agent_type in t.agent_types]

    async def execute(
        self,
        name: str,
        agent_type: str,
        params: dict[str, Any],
        *,
        policy_engine: PolicyEngine | None = None,
        agent_id: str = "",
        tenant_id: str = "",
        session: EngramSession | None = None,
    ) -> ToolResult:
        """Execute a tool with policy validation and Engram recording.

        1. Look up the tool
        2. Validate the agent type is allowed
        3. Check policy engine (if present)
        4. Execute the handler
        5. Record the action in the Engram session (if present)
        """
        tool, handler = self.get(name)

        if agent_type not in tool.agent_types:
            raise PolicyViolationError(
                name,
                [f"Agent type '{agent_type}' is not allowed to use tool '{name}'"],
            )

        # Policy check
        if policy_engine is not None:
            from sentinel_policy.models import PolicyInput

            policy_input = PolicyInput(
                agent_id=agent_id,
                agent_type=agent_type,
                action=name,
                target=params.get("target", ""),
                tenant_id=tenant_id,
                context=params,
            )
            decision = await policy_engine.evaluate_agent_action(policy_input)

            if not decision.allowed:
                if session is not None:
                    session.add_action(
                        action_type="policy_violation",
                        description=f"Tool '{name}' denied by policy",
                        details={"reasons": decision.reasons, "violations": decision.violations},
                        success=False,
                    )
                raise PolicyViolationError(name, decision.reasons)

        # Execute
        try:
            result = await handler(**params)
        except Exception as exc:
            if session is not None:
                session.add_action(
                    action_type=f"tool_{name}",
                    description=f"Tool '{name}' failed: {exc}",
                    details=params,
                    success=False,
                )
            raise

        # Record success
        if session is not None:
            session.add_action(
                action_type=f"tool_{name}",
                description=f"Executed tool '{name}'",
                details={"params": params, "success": result.success},
                success=result.success,
            )

        return result

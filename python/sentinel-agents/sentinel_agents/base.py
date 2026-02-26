"""BaseAgent ABC with lifecycle management and Engram integration."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from sentinel_api.engram.session import EngramSession

from sentinel_agents.types import AgentPlan, AgentResult, AgentStatus

if TYPE_CHECKING:
    from sentinel_policy.engine import PolicyEngine

    from sentinel_agents.llm import LLMProvider
    from sentinel_agents.tools import ToolRegistry, ToolResult

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base for all Sentinel agents.

    Provides the lifecycle: init -> plan -> execute -> report, with
    automatic Engram session capture. Subclasses implement ``plan``
    and ``execute``.
    """

    def __init__(
        self,
        config: Any,  # AgentConfig
        llm: LLMProvider,
        tool_registry: ToolRegistry,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        from sentinel_agents.types import AgentConfig

        if not isinstance(config, AgentConfig):
            msg = f"Expected AgentConfig, got {type(config).__name__}"
            raise TypeError(msg)

        self.config: AgentConfig = config
        self.llm = llm
        self.tools = tool_registry
        self.policy = policy_engine
        self.status = AgentStatus.PENDING
        self._session: EngramSession | None = None
        self._cancel_requested = False

    @abstractmethod
    async def plan(self, intent: str, context: dict[str, Any]) -> AgentPlan:
        """Produce an execution plan given the intent and context."""

    @abstractmethod
    async def execute(self, plan: AgentPlan) -> AgentResult:
        """Execute the plan and return structured results."""

    async def run(self, intent: str, context: dict[str, Any] | None = None) -> AgentResult:
        """Full lifecycle: init -> plan -> execute -> report.

        Creates an Engram session, runs plan and execute phases,
        records decisions/actions, and finalizes the session.
        """
        context = context or {}
        self.status = AgentStatus.RUNNING
        self._session = EngramSession(
            tenant_id=self.config.tenant_id,
            agent_id=self.config.agent_id,
            intent=intent,
        )
        self._session.set_context(context)

        result: AgentResult | None = None
        try:
            # Plan phase
            agent_plan = await self.plan(intent, context)
            self._session.add_decision(
                agent_plan.description,
                agent_plan.rationale,
                agent_plan.confidence,
            )
            for alt in agent_plan.alternatives:
                self._session.add_alternative(alt.option, alt.reason)

            # Execute phase
            result = await self.execute(agent_plan)
            self._session.add_action(
                "execution_complete",
                f"Completed with {len(result.findings)} findings",
                {"findings": len(result.findings), "actions": result.actions_taken},
                success=True,
            )
            self.status = AgentStatus.COMPLETED
            result.status = AgentStatus.COMPLETED

        except Exception as exc:
            self._session.add_action(
                "execution_failed",
                str(exc),
                success=False,
            )
            self.status = AgentStatus.FAILED
            result = AgentResult(
                agent_id=self.config.agent_id,
                agent_type=self.config.agent_type,
                tenant_id=self.config.tenant_id,
                status=AgentStatus.FAILED,
                started_at=self._session._engram.started_at,
                error=str(exc),
            )

        finally:
            engram = self._session.finalize()
            if result is not None:
                result.engram_id = engram.id.value
                result.completed_at = engram.completed_at

        return result  # type: ignore[return-value]

    async def execute_tool(self, tool_name: str, params: dict[str, Any]) -> ToolResult:
        """Execute a tool with policy check and Engram recording."""
        return await self.tools.execute(
            name=tool_name,
            agent_type=self.config.agent_type,
            params=params,
            policy_engine=self.policy,
            agent_id=self.config.agent_id,
            tenant_id=str(self.config.tenant_id),
            session=self._session,
        )

    def request_cancel(self) -> None:
        """Signal cancellation. Subclasses should check ``is_cancelled``."""
        self._cancel_requested = True

    @property
    def is_cancelled(self) -> bool:
        """True if cancellation has been requested."""
        return self._cancel_requested

"""Agent session orchestrator — start, pause, resume, cancel."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from sentinel_agents.base import BaseAgent  # noqa: TC001 (Pydantic needs runtime access)
from sentinel_agents.types import AgentResult, AgentStatus

logger = logging.getLogger(__name__)


class AgentSession(BaseModel):
    """In-memory representation of a running or completed agent session."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: UUID
    agent: BaseAgent
    status: AgentStatus
    created_at: datetime
    result: AgentResult | None = None


class AgentOrchestrator:
    """Manages agent sessions: start, pause, resume, cancel."""

    def __init__(self) -> None:
        self._sessions: dict[UUID, AgentSession] = {}
        self._tasks: dict[UUID, asyncio.Task[None]] = {}

    async def start(
        self,
        agent: BaseAgent,
        intent: str,
        context: dict[str, Any] | None = None,
    ) -> UUID:
        """Start an agent session in the background. Returns session_id."""
        session_id = uuid4()
        session = AgentSession(
            session_id=session_id,
            agent=agent,
            status=AgentStatus.RUNNING,
            created_at=datetime.now(UTC),
        )
        self._sessions[session_id] = session

        task = asyncio.create_task(self._run_agent(session_id, intent, context))
        self._tasks[session_id] = task
        return session_id

    async def cancel(self, session_id: UUID) -> None:
        """Request cancellation of an agent session."""
        session = self._sessions[session_id]
        session.agent.request_cancel()
        session.status = AgentStatus.CANCELLED

    def get_status(self, session_id: UUID) -> AgentSession:
        """Get the current session state."""
        return self._sessions[session_id]

    def list_sessions(self, tenant_id: UUID | None = None) -> list[AgentSession]:
        """List all sessions, optionally filtered by tenant."""
        sessions = list(self._sessions.values())
        if tenant_id is not None:
            sessions = [s for s in sessions if s.agent.config.tenant_id == tenant_id]
        return sessions

    async def _run_agent(
        self,
        session_id: UUID,
        intent: str,
        context: dict[str, Any] | None,
    ) -> None:
        """Run agent and update session state on completion."""
        session = self._sessions[session_id]
        try:
            result = await session.agent.run(intent, context)
            session.result = result
            session.status = result.status
        except Exception as exc:
            logger.exception("Agent session %s failed", session_id)
            session.status = AgentStatus.FAILED
            session.result = AgentResult(
                agent_id=session.agent.config.agent_id,
                agent_type=session.agent.config.agent_type,
                tenant_id=session.agent.config.tenant_id,
                status=AgentStatus.FAILED,
                error=str(exc),
            )

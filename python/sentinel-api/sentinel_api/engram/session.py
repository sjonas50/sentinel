"""Builder-pattern session recorder for engram capture."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sentinel_api.engram.models import (
    Action,
    Alternative,
    Decision,
    Engram,
    EngramId,
)

if TYPE_CHECKING:
    from uuid import UUID


class EngramSession:
    """Incrementally records agent reasoning during execution.

    Usage::

        session = EngramSession(tenant_id, "scanner", "Scan subnet")
        session.set_context({"subnet": "10.0.1.0/24"})
        session.add_decision("ICMP scan", "fastest", 0.9)
        session.add_action("scan", "ping sweep", {"hosts": 254}, True)
        engram = session.finalize()
    """

    def __init__(self, tenant_id: UUID, agent_id: str, intent: str) -> None:
        self._engram = Engram(
            tenant_id=tenant_id,
            agent_id=agent_id,
            intent=intent,
        )

    @property
    def id(self) -> EngramId:
        return self._engram.id

    def set_context(self, context: Any) -> None:
        self._engram.context = context

    def add_decision(
        self, choice: str, rationale: str, confidence: float
    ) -> None:
        self._engram.decisions.append(
            Decision(choice=choice, rationale=rationale, confidence=confidence)
        )

    def add_alternative(self, option: str, rejection_reason: str) -> None:
        self._engram.alternatives.append(
            Alternative(option=option, rejection_reason=rejection_reason)
        )

    def add_action(
        self,
        action_type: str,
        description: str,
        details: Any = None,
        success: bool = True,
    ) -> None:
        self._engram.actions.append(
            Action(
                action_type=action_type,
                description=description,
                details=details,
                success=success,
            )
        )

    def finalize(self) -> Engram:
        """Finalize the session: set completed_at and compute content hash."""
        self._engram.completed_at = datetime.now(UTC)
        self._engram.content_hash = self._engram.compute_hash()
        return self._engram

"""Core types for the agent framework."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AgentStatus(StrEnum):
    """Lifecycle states for an agent session."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentConfig(BaseModel):
    """Configuration for an agent session."""

    agent_id: str
    agent_type: str  # "hunt", "simulate", "discover", "govern"
    tenant_id: UUID
    llm_model: str = "claude-sonnet-4-20250514"
    max_steps: int = 20
    timeout_seconds: int = 300


class Finding(BaseModel):
    """A security finding produced by an agent."""

    id: UUID = Field(default_factory=uuid4)
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    evidence: dict[str, Any] = {}
    recommendations: list[str] = []


class Recommendation(BaseModel):
    """An actionable recommendation from an agent."""

    title: str
    description: str
    priority: str  # "critical", "high", "medium", "low"
    automated: bool = False


class PlanAlternative(BaseModel):
    """An alternative considered during planning."""

    option: str
    reason: str


class AgentPlan(BaseModel):
    """Structured plan produced by the plan phase."""

    description: str
    rationale: str
    confidence: float
    steps: list[str]
    alternatives: list[PlanAlternative] = []


class AgentResult(BaseModel):
    """Structured output from an agent execution."""

    agent_id: str
    agent_type: str
    tenant_id: UUID
    status: AgentStatus
    findings: list[Finding] = []
    recommendations: list[Recommendation] = []
    actions_taken: int = 0
    engram_id: UUID | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str | None = None

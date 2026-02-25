"""Policy evaluation data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class Tier(StrEnum):
    """Response action approval tiers."""

    AUTO = "auto"
    FAST_TRACK = "fast_track"
    REVIEW = "review"
    DENY = "deny"


class Decision(BaseModel):
    """Result of a policy evaluation."""

    allowed: bool
    tier: Tier = Tier.DENY
    reasons: list[str] = []
    violations: list[str] = []
    metadata: dict[str, Any] = {}


class PolicyInput(BaseModel):
    """Input data sent to OPA for evaluation."""

    agent_id: str
    agent_type: str
    action: str
    target: str = ""
    tenant_id: str = ""
    context: dict[str, Any] = {}

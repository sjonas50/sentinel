"""Core engram data models mirroring the Rust sentinel-engram crate."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EngramId(BaseModel):
    """Wrapper for engram session identifiers."""

    value: UUID = Field(default_factory=uuid4)

    def __str__(self) -> str:
        return str(self.value)

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EngramId):
            return self.value == other.value
        return NotImplemented


class Decision(BaseModel):
    """A decision made during agent execution."""

    choice: str
    rationale: str
    confidence: float
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )


class Alternative(BaseModel):
    """An alternative considered but not chosen."""

    option: str
    rejection_reason: str


class Action(BaseModel):
    """An action taken by the agent."""

    action_type: str
    description: str
    details: Any = None
    success: bool = True
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )


class Engram(BaseModel):
    """Complete reasoning chain of an AI agent session."""

    id: EngramId = Field(default_factory=EngramId)
    tenant_id: UUID
    agent_id: str
    intent: str
    context: Any = None
    decisions: list[Decision] = Field(default_factory=list)
    alternatives: list[Alternative] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    completed_at: datetime | None = None
    content_hash: str | None = None

    def compute_hash(self) -> str:
        """Compute BLAKE3-equivalent hash using hashlib (SHA-256 fallback).

        Uses the same field set as the Rust implementation (all fields
        except content_hash).
        """
        hashable = self.model_dump(
            exclude={"content_hash"}, mode="json"
        )
        data = _canonical_json(hashable)
        return hashlib.blake2b(data, digest_size=32).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify the stored content_hash matches a freshly computed hash."""
        if self.content_hash is None:
            return False
        return self.content_hash == self.compute_hash()


class EngramQuery(BaseModel):
    """Query parameters for listing engrams."""

    tenant_id: UUID | None = None
    agent_id: str | None = None
    session_id: EngramId | None = None
    from_time: datetime | None = None
    to_time: datetime | None = None


def _canonical_json(obj: Any) -> bytes:
    """Produce deterministic JSON bytes for hashing."""
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

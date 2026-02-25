"""Event types for inter-service communication.

These Pydantic models mirror the Rust types in sentinel-core/src/events.rs.
Keep them in sync when modifying either side.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventSource(StrEnum):
    DISCOVER = "discover"
    DEFEND = "defend"
    GOVERN = "govern"
    OBSERVE = "observe"
    API = "api"


class SentinelEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: EventSource
    payload: EventPayload


# ── Event payloads ─────────────────────────────────────────────────


class NodeDiscovered(BaseModel):
    event_type: str = "NodeDiscovered"
    node_id: UUID
    node_type: str
    label: str


class NodeUpdated(BaseModel):
    event_type: str = "NodeUpdated"
    node_id: UUID
    changed_fields: list[str]


class NodeStale(BaseModel):
    event_type: str = "NodeStale"
    node_id: UUID
    last_seen: datetime


class EdgeDiscovered(BaseModel):
    event_type: str = "EdgeDiscovered"
    source_id: UUID
    target_id: UUID
    edge_type: str


class VulnerabilityFound(BaseModel):
    event_type: str = "VulnerabilityFound"
    node_id: UUID
    cve_id: str
    cvss_score: float | None = None
    exploitable: bool = False


class ScanStarted(BaseModel):
    event_type: str = "ScanStarted"
    scan_id: UUID
    scan_type: str
    target: str


class ScanCompleted(BaseModel):
    event_type: str = "ScanCompleted"
    scan_id: UUID
    nodes_found: int
    nodes_updated: int
    nodes_stale: int
    duration_ms: int


class AttackPathComputed(BaseModel):
    event_type: str = "AttackPathComputed"
    path_id: UUID
    source_node: UUID
    target_node: UUID
    risk_score: float
    step_count: int


class HuntFinding(BaseModel):
    event_type: str = "HuntFinding"
    finding_id: UUID
    severity: str
    title: str
    description: str


class ShadowAiDiscovered(BaseModel):
    event_type: str = "ShadowAiDiscovered"
    service_name: str
    domain: str
    risk_score: float


class PolicyViolation(BaseModel):
    event_type: str = "PolicyViolation"
    agent_id: str
    policy_name: str
    action: str
    details: str


class EngramRecorded(BaseModel):
    event_type: str = "EngramRecorded"
    session_id: UUID
    agent_type: str
    intent: str
    action_count: int


class ConfigAuditCompleted(BaseModel):
    event_type: str = "ConfigAuditCompleted"
    audit_id: UUID
    findings_count: int
    critical_count: int
    high_count: int
    drift_count: int


class ConfigDriftDetected(BaseModel):
    event_type: str = "ConfigDriftDetected"
    resource_id: str
    resource_type: str
    old_hash: str
    new_hash: str


# Union of all event payloads
EventPayload = (
    NodeDiscovered
    | NodeUpdated
    | NodeStale
    | EdgeDiscovered
    | VulnerabilityFound
    | ScanStarted
    | ScanCompleted
    | AttackPathComputed
    | HuntFinding
    | ShadowAiDiscovered
    | PolicyViolation
    | EngramRecorded
    | ConfigAuditCompleted
    | ConfigDriftDetected
)

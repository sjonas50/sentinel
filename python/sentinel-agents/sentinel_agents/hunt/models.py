"""Hunt-specific data models, SIEM protocol, and configuration types."""

from __future__ import annotations

# Re-export datetime only under TYPE_CHECKING for annotations;
# keep runtime import for default factories.
from datetime import datetime  # noqa: TC003 — used in Field defaults
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid4

import yaml
from pydantic import BaseModel, Field

# ── SIEM Protocol ────────────────────────────────────────────────


@runtime_checkable
class SiemProtocol(Protocol):
    """Interface for SIEM query operations.

    The concrete ``ElasticConnector`` from sentinel-connectors satisfies
    this protocol via duck typing. Hunt agents depend on the protocol,
    not the concrete class, keeping the dependency graph clean.
    """

    async def execute_query(
        self,
        query_dsl: dict[str, Any],
        index: str,
        *,
        size: int = 100,
        sort: list[dict[str, Any]] | None = None,
        aggs: dict[str, Any] | None = None,
    ) -> Any: ...

    async def discover_indices(self, pattern: str = "*") -> Any: ...


# ── Playbook Types ───────────────────────────────────────────────


class PlaybookType(StrEnum):
    """Built-in hunt playbook identifiers."""

    CREDENTIAL_ABUSE = "credential_abuse"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"


# ── Hunt Configuration ───────────────────────────────────────────


class HuntConfig(BaseModel):
    """Base configuration shared by all hunt playbooks."""

    playbook: PlaybookType
    time_window_hours: int = 24
    index_pattern: str = "filebeat-*,winlogbeat-*,logs-*"
    max_results_per_query: int = 1000
    severity_threshold: str = "medium"
    target_hosts: list[str] = []
    target_users: list[str] = []
    generate_sigma_rules: bool = True


class CredentialAbuseConfig(HuntConfig):
    """Configuration for the Credential Abuse playbook."""

    playbook: PlaybookType = PlaybookType.CREDENTIAL_ABUSE
    failed_login_threshold: int = 10
    brute_force_window_minutes: int = 5
    lockout_correlation: bool = True
    credential_stuffing_unique_users: int = 5
    service_account_monitoring: bool = True


class LateralMovementConfig(HuntConfig):
    """Configuration for the Lateral Movement playbook."""

    playbook: PlaybookType = PlaybookType.LATERAL_MOVEMENT
    internal_subnet_prefixes: list[str] = Field(
        default_factory=lambda: ["10.", "172.16.", "192.168."]
    )
    rdp_chain_max_hops: int = 3
    service_account_hop_threshold: int = 2
    unusual_port_threshold: int = 5


class DataExfiltrationConfig(HuntConfig):
    """Configuration for the Data Exfiltration playbook."""

    playbook: PlaybookType = PlaybookType.DATA_EXFILTRATION
    large_transfer_bytes: int = 100_000_000  # 100 MB
    dns_query_length_threshold: int = 50
    dns_txt_record_threshold: int = 10
    unusual_destination_check: bool = True
    after_hours_start: int = 22  # 10 PM
    after_hours_end: int = 6  # 6 AM


# ── Sigma Rule Models ────────────────────────────────────────────


class SigmaDetection(BaseModel):
    """Detection logic for a Sigma rule."""

    selection: dict[str, Any]
    filter: dict[str, Any] = {}
    condition: str = "selection"


class SigmaRule(BaseModel):
    """Pydantic model that serializes to valid Sigma YAML format.

    Conforms to the SigmaHQ specification.
    """

    title: str
    id: UUID = Field(default_factory=uuid4)
    status: str = "experimental"
    description: str
    author: str = "Sentinel Hunt Agent"
    date: str = Field(default_factory=lambda: datetime.now().strftime("%Y/%m/%d"))
    references: list[str] = []
    tags: list[str] = []
    logsource: dict[str, str] = {}
    detection: SigmaDetection
    falsepositives: list[str] = []
    level: str = "medium"

    def to_yaml(self) -> str:
        """Serialize to valid Sigma YAML."""
        data: dict[str, Any] = {
            "title": self.title,
            "id": str(self.id),
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "references": self.references,
            "tags": self.tags,
            "logsource": self.logsource,
            "detection": {
                "selection": self.detection.selection,
                **({"filter": self.detection.filter} if self.detection.filter else {}),
                "condition": self.detection.condition,
            },
            "falsepositives": self.falsepositives,
            "level": self.level,
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


# ── Hunt Finding ─────────────────────────────────────────────────


class HuntFinding(BaseModel):
    """A finding produced by a hunt playbook with MITRE ATT&CK context."""

    id: UUID = Field(default_factory=uuid4)
    playbook: PlaybookType
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = {}
    recommendations: list[str] = []
    affected_hosts: list[str] = []
    affected_users: list[str] = []
    mitre_technique_ids: list[str] = []
    mitre_tactic: str = ""
    sigma_rule: SigmaRule | None = None
    timestamp: datetime | None = None


# ── Playbook Result ──────────────────────────────────────────────


class PlaybookResult(BaseModel):
    """Complete result from a hunt playbook execution."""

    playbook: PlaybookType
    config: HuntConfig
    findings: list[HuntFinding] = []
    sigma_rules: list[SigmaRule] = []
    queries_executed: int = 0
    events_analyzed: int = 0
    duration_seconds: float = 0.0
    summary: str = ""

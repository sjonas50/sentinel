"""Models for adversarial simulation agents.

Defines the GraphProtocol for read-only graph access, simulation
configuration hierarchy, and finding/result types.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

# ── Graph Protocol ──────────────────────────────────────────────


@runtime_checkable
class GraphProtocol(Protocol):
    """Read-only interface for graph and pathfinding operations.

    Concrete implementations (sentinel-api graph service + pathfind wrapper)
    satisfy this protocol at runtime. Simulation agents depend on the
    protocol only — no import dependency on sentinel-api.
    """

    async def query_nodes(
        self,
        label: str,
        tenant_id: str,
        *,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query nodes by label with optional property filters."""
        ...

    async def query_neighbors(
        self,
        node_id: str,
        tenant_id: str,
        *,
        edge_types: list[str] | None = None,
        target_labels: list[str] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get neighbors of a node filtered by edge type or target label."""
        ...

    async def find_attack_paths(
        self,
        tenant_id: str,
        *,
        sources: list[str] | None = None,
        targets: list[str] | None = None,
        max_depth: int = 10,
        max_paths: int = 100,
        include_lateral: bool = False,
        include_blast: bool = False,
    ) -> dict[str, Any]:
        """Compute attack paths (wraps sentinel-pathfind)."""
        ...

    async def compute_blast_radius(
        self,
        tenant_id: str,
        compromised_node_id: str,
        *,
        max_hops: int = 5,
        min_exploitability: float = 0.3,
    ) -> dict[str, Any]:
        """Compute blast radius from a compromised node."""
        ...

    async def query_edges(
        self,
        tenant_id: str,
        *,
        edge_type: str | None = None,
        source_label: str | None = None,
        target_label: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Query edges with optional type and endpoint label filters."""
        ...


# ── Enums ───────────────────────────────────────────────────────


class TacticType(StrEnum):
    """MITRE ATT&CK tactic categories covered by simulation."""

    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXFILTRATION = "exfiltration"


# ── Configuration Hierarchy ─────────────────────────────────────


class SimConfig(BaseModel):
    """Base configuration for all adversarial simulations."""

    tactic: TacticType
    techniques: list[str] = []  # filter to specific MITRE IDs; empty = all
    max_paths: int = 50
    max_depth: int = 10
    min_exploitability: float = 0.3
    include_blast_radius: bool = True
    target_node_ids: list[str] = []  # empty = auto-detect crown jewels
    source_node_ids: list[str] = []  # empty = auto-detect internet-facing


class InitialAccessConfig(SimConfig):
    """Configuration for initial access simulations."""

    tactic: TacticType = TacticType.INITIAL_ACCESS
    check_exposed_services: bool = True
    check_phishing_vectors: bool = True
    check_valid_accounts: bool = True
    exposed_service_ports: list[int] = [
        80,
        443,
        8080,
        8443,
        3389,
        22,
        21,
        25,
        445,
    ]


class LateralMovementSimConfig(SimConfig):
    """Configuration for lateral movement simulations."""

    tactic: TacticType = TacticType.LATERAL_MOVEMENT
    max_chain_length: int = 8
    check_credential_reuse: bool = True
    check_trust_exploitation: bool = True
    check_remote_services: bool = True


class PrivilegeEscalationConfig(SimConfig):
    """Configuration for privilege escalation simulations."""

    tactic: TacticType = TacticType.PRIVILEGE_ESCALATION
    check_misconfigs: bool = True
    check_vulnerable_services: bool = True
    check_excessive_permissions: bool = True
    admin_role_patterns: list[str] = [
        "admin",
        "root",
        "superuser",
        "owner",
        "contributor",
    ]


class ExfiltrationConfig(SimConfig):
    """Configuration for exfiltration simulations."""

    tactic: TacticType = TacticType.EXFILTRATION
    check_data_paths: bool = True
    check_dns_exfil: bool = True
    check_cloud_storage: bool = True
    sensitive_data_labels: list[str] = [
        "pii",
        "phi",
        "financial",
        "credentials",
        "source-code",
    ]


# ── Finding & Result Types ──────────────────────────────────────


class RemediationStep(BaseModel):
    """A structured remediation recommendation."""

    title: str
    description: str
    priority: str  # critical, high, medium, low
    effort: str  # low, medium, high
    automated: bool = False


class SimulationFinding(BaseModel):
    """A finding from adversarial simulation with attack path context."""

    id: UUID = Field(default_factory=uuid4)
    tactic: TacticType
    technique_id: str
    technique_name: str
    severity: str  # critical, high, medium, low
    title: str
    description: str
    attack_paths: list[dict[str, Any]] = []
    blast_radius: dict[str, Any] | None = None
    risk_score: float = 0.0  # 0.0 to 10.0
    affected_nodes: list[str] = []
    evidence: dict[str, Any] = {}
    remediation: list[RemediationStep] = []
    mitre_url: str = ""


class SimulationResult(BaseModel):
    """Complete result from a tactic simulation run."""

    tactic: TacticType
    config: SimConfig
    findings: list[SimulationFinding] = []
    techniques_tested: int = 0
    techniques_with_findings: int = 0
    highest_risk_score: float = 0.0
    duration_seconds: float = 0.0
    summary: str = ""

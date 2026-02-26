"""Data models for Shadow AI discovery."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from sentinel_connectors.governance.domains import AiServiceCategory, RiskTier  # noqa: TC001


class DnsQueryMatch(BaseModel):
    """A single DNS query that matched an AI service domain."""

    query_domain: str
    source_ip: str
    source_host: str | None = None
    timestamp: datetime | None = None
    query_count: int = 1


class NetworkFlowMatch(BaseModel):
    """A network flow that matched an AI service endpoint."""

    dest_domain: str
    source_ip: str
    source_host: str | None = None
    dest_ip: str | None = None
    dest_port: int = 443
    bytes_sent: int = 0
    bytes_received: int = 0
    timestamp: datetime | None = None
    request_path: str | None = None


class ShadowAiServiceRecord(BaseModel):
    """Aggregated shadow AI service discovered from DNS/network analysis."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    service_name: str
    domain: str
    category: AiServiceCategory
    risk_tier: RiskTier
    risk_score: float = 0.0
    sanctioned: bool = False
    # Aggregated stats
    total_dns_queries: int = 0
    total_network_flows: int = 0
    unique_source_ips: int = 0
    unique_source_hosts: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Source details
    source_hosts: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)


class ShadowAiScanResult(BaseModel):
    """Result of a shadow AI discovery scan."""

    services: list[ShadowAiServiceRecord]
    total_dns_matches: int = 0
    total_flow_matches: int = 0
    scan_duration_ms: int = 0
    errors: list[str] = Field(default_factory=list)

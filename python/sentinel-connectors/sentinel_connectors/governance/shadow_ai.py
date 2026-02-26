"""Shadow AI Discovery connector.

Discovers unauthorized AI service usage by analyzing DNS logs and
network flow data. Integrates with SIEM connectors to pull log data,
or accepts pre-fetched logs directly via the ``scan()`` method.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.governance.dns_analyzer import DnsLogAnalyzer
from sentinel_connectors.governance.domains import (
    build_domain_lookup,
    match_domain,
)
from sentinel_connectors.governance.flow_analyzer import NetworkFlowAnalyzer
from sentinel_connectors.governance.models import (
    DnsQueryMatch,
    NetworkFlowMatch,
    ShadowAiScanResult,
    ShadowAiServiceRecord,
)
from sentinel_connectors.governance.risk_scorer import compute_risk_score
from sentinel_connectors.registry import register

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class ShadowAiConnector(BaseConnector):
    """Shadow AI discovery connector.

    Operates in two modes:

    1. **Pull mode** (via ``sync()`` / ``discover()``): Reads DNS and
       network flow logs from ``self.config["dns_logs"]`` and
       ``self.config["network_flows"]``.

    2. **Push mode** (via ``scan()``): Accepts pre-fetched DNS logs and
       network flows as arguments, returning a ``ShadowAiScanResult``.
    """

    NAME = "shadow_ai"

    def __init__(
        self,
        tenant_id: UUID,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(tenant_id, config)
        self._dns_analyzer = DnsLogAnalyzer()
        self._flow_analyzer = NetworkFlowAnalyzer()
        self._domain_lookup = build_domain_lookup()
        self._sanctioned_domains: set[str] = set(self.config.get("sanctioned_domains", []))

    @property
    def name(self) -> str:
        return "shadow_ai"

    async def health_check(self) -> bool:
        """Shadow AI connector is always healthy (no external deps)."""
        return True

    async def discover(self, session: EngramSession) -> SyncResult:
        """Run shadow AI discovery scan via the connector lifecycle."""
        result = SyncResult(connector_name=self.name)

        dns_logs: list[dict[str, Any]] = self.config.get("dns_logs", [])
        network_flows: list[dict[str, Any]] = self.config.get("network_flows", [])

        session.add_action(
            action_type="shadow_ai_scan_start",
            description=(
                f"Analyzing {len(dns_logs)} DNS logs and {len(network_flows)} network flows"
            ),
            success=True,
        )

        # Analyze
        dns_matches = self._dns_analyzer.analyze_logs(dns_logs)
        flow_matches = self._flow_analyzer.analyze_flows(network_flows)

        session.add_decision(
            choice=(f"Found {len(dns_matches)} DNS matches and {len(flow_matches)} flow matches"),
            rationale="Matched against known AI service domain registry",
            confidence=0.95,
        )

        # Aggregate and score
        services = self._aggregate_matches(dns_matches, flow_matches)
        for svc in services:
            svc.risk_score = compute_risk_score(svc)

        session.add_action(
            action_type="shadow_ai_scan_complete",
            description=f"Discovered {len(services)} shadow AI services",
            details={
                "services_found": len(services),
                "dns_matches": len(dns_matches),
                "flow_matches": len(flow_matches),
            },
            success=True,
        )

        return result

    async def scan(
        self,
        dns_logs: list[dict[str, Any]],
        network_flows: list[dict[str, Any]],
    ) -> ShadowAiScanResult:
        """Push-mode scanning without the full connector lifecycle."""
        start = time.monotonic()

        dns_matches = self._dns_analyzer.analyze_logs(dns_logs)
        flow_matches = self._flow_analyzer.analyze_flows(network_flows)
        services = self._aggregate_matches(dns_matches, flow_matches)

        for svc in services:
            svc.risk_score = compute_risk_score(svc)

        duration_ms = int((time.monotonic() - start) * 1000)

        return ShadowAiScanResult(
            services=services,
            total_dns_matches=len(dns_matches),
            total_flow_matches=len(flow_matches),
            scan_duration_ms=duration_ms,
        )

    def _aggregate_matches(
        self,
        dns_matches: list[DnsQueryMatch],
        flow_matches: list[NetworkFlowMatch],
    ) -> list[ShadowAiServiceRecord]:
        """Aggregate DNS and flow matches into per-service records."""
        service_map: dict[str, ShadowAiServiceRecord] = {}

        for m in dns_matches:
            svc_info = match_domain(
                m.query_domain.lower().rstrip("."),
                self._domain_lookup,
            )
            if svc_info is None:
                continue
            key = svc_info.service_name
            record = service_map.get(key)
            if record is None:
                record = ShadowAiServiceRecord(
                    tenant_id=self.tenant_id,
                    service_name=svc_info.service_name,
                    domain=svc_info.domain,
                    category=svc_info.category,
                    risk_tier=svc_info.risk_tier,
                    sanctioned=svc_info.domain in self._sanctioned_domains,
                )
                service_map[key] = record
            record.total_dns_queries += m.query_count
            if m.source_ip not in record.source_ips:
                record.source_ips.append(m.source_ip)
            if m.source_host and m.source_host not in record.source_hosts:
                record.source_hosts.append(m.source_host)
            if m.timestamp:
                record.last_seen = max(record.last_seen, m.timestamp)
                record.first_seen = min(record.first_seen, m.timestamp)

        for m in flow_matches:
            svc_info = match_domain(
                m.dest_domain.lower().rstrip("."),
                self._domain_lookup,
            )
            if svc_info is None:
                continue
            key = svc_info.service_name
            record = service_map.get(key)
            if record is None:
                record = ShadowAiServiceRecord(
                    tenant_id=self.tenant_id,
                    service_name=svc_info.service_name,
                    domain=svc_info.domain,
                    category=svc_info.category,
                    risk_tier=svc_info.risk_tier,
                    sanctioned=svc_info.domain in self._sanctioned_domains,
                )
                service_map[key] = record
            record.total_network_flows += 1
            record.total_bytes_sent += m.bytes_sent
            record.total_bytes_received += m.bytes_received
            if m.source_ip not in record.source_ips:
                record.source_ips.append(m.source_ip)
            if m.source_host and m.source_host not in record.source_hosts:
                record.source_hosts.append(m.source_host)

        # Finalize unique counts
        for record in service_map.values():
            record.unique_source_ips = len(record.source_ips)
            record.unique_source_hosts = len(record.source_hosts)

        return sorted(
            service_map.values(),
            key=lambda s: s.risk_score,
            reverse=True,
        )

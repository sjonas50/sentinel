"""Network flow analysis for AI API call detection."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sentinel_connectors.governance.domains import (
    build_domain_lookup,
    match_domain,
)
from sentinel_connectors.governance.models import NetworkFlowMatch

logger = logging.getLogger(__name__)

# Ports that indicate API traffic
_API_PORTS = frozenset({443, 80, 8080, 8443})


class NetworkFlowAnalyzer:
    """Analyzes network flow records to identify API calls to AI endpoints.

    Accepts flow records in multiple formats:
    - Generic dicts with ``dest_domain``, ``source_ip``, ``dest_port``, etc.
    - ECS format (``destination.domain``, ``source.ip``, ``destination.port``)
    - Zeek/Bro format (``id.resp_h``, ``id.orig_h``, ``id.resp_p``)
    """

    def __init__(self) -> None:
        self._lookup = build_domain_lookup()

    def analyze_flows(self, flows: list[dict[str, Any]]) -> list[NetworkFlowMatch]:
        """Analyze a batch of network flow records, returning AI matches."""
        matches: list[NetworkFlowMatch] = []
        for flow in flows:
            m = self._analyze_single(flow)
            if m is not None:
                matches.append(m)
        return matches

    def _analyze_single(self, flow: dict[str, Any]) -> NetworkFlowMatch | None:
        """Check a single flow record against known AI endpoints."""
        dest_domain = self._extract_field(
            flow,
            "dest_domain",
            "destination.domain",
        )
        if dest_domain is None:
            return None

        dest_domain = dest_domain.lower().rstrip(".")

        service = match_domain(dest_domain, self._lookup)
        if service is None:
            return None

        dest_port = self._extract_int(flow, "dest_port", "destination.port", "id.resp_p") or 443
        if dest_port not in _API_PORTS:
            return None

        return NetworkFlowMatch(
            dest_domain=dest_domain,
            source_ip=(
                self._extract_field(flow, "source_ip", "source.ip", "id.orig_h") or "unknown"
            ),
            source_host=self._extract_field(
                flow,
                "source_host",
                "host.name",
                "hostname",
            ),
            dest_ip=self._extract_field(
                flow,
                "dest_ip",
                "destination.ip",
                "id.resp_h",
            ),
            dest_port=dest_port,
            bytes_sent=(self._extract_int(flow, "bytes_sent", "source.bytes", "orig_bytes") or 0),
            bytes_received=(
                self._extract_int(
                    flow,
                    "bytes_received",
                    "destination.bytes",
                    "resp_bytes",
                )
                or 0
            ),
            timestamp=self._extract_timestamp(flow),
            request_path=self._extract_field(
                flow,
                "request_path",
                "url.path",
                "http.request.path",
            ),
        )

    # ── Field extraction helpers ──────────────────────────────

    @staticmethod
    def _extract_field(data: dict[str, Any], *keys: str) -> str | None:
        """Try multiple field names, return first match."""
        for key in keys:
            if "." in key:
                parts = key.split(".", 1)
                nested = data.get(parts[0])
                if isinstance(nested, dict) and parts[1] in nested:
                    return str(nested[parts[1]])
            elif key in data:
                return str(data[key])
        return None

    @staticmethod
    def _extract_int(data: dict[str, Any], *keys: str) -> int | None:
        """Try multiple field names, return first integer match."""
        for key in keys:
            if "." in key:
                parts = key.split(".", 1)
                nested = data.get(parts[0])
                if isinstance(nested, dict) and parts[1] in nested:
                    try:
                        return int(nested[parts[1]])
                    except (ValueError, TypeError):
                        continue
            elif key in data:
                try:
                    return int(data[key])
                except (ValueError, TypeError):
                    continue
        return None

    @staticmethod
    def _extract_timestamp(flow: dict[str, Any]) -> datetime | None:
        """Extract timestamp from flow record."""
        for key in ("timestamp", "@timestamp", "ts"):
            if key in flow:
                val = flow[key]
                if isinstance(val, datetime):
                    return val
                try:
                    return datetime.fromisoformat(str(val))
                except (ValueError, TypeError):
                    continue
        return None

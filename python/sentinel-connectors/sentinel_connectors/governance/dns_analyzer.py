"""DNS log analysis for AI service domain detection."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sentinel_connectors.governance.domains import (
    build_domain_lookup,
    match_domain,
)
from sentinel_connectors.governance.models import DnsQueryMatch

logger = logging.getLogger(__name__)


class DnsLogAnalyzer:
    """Analyzes DNS query logs to detect queries to known AI service domains.

    Accepts DNS logs in multiple formats:
    - Generic dicts with ``query_domain``, ``source_ip``, ``timestamp`` keys
    - Elasticsearch ECS format (``dns.question.name``, ``source.ip``)
    - Zeek/Bro format (``query``, ``id.orig_h``)
    """

    def __init__(self) -> None:
        self._lookup = build_domain_lookup()

    def analyze_logs(self, dns_logs: list[dict[str, Any]]) -> list[DnsQueryMatch]:
        """Analyze a batch of DNS log entries, returning matches."""
        matches: list[DnsQueryMatch] = []
        for log in dns_logs:
            m = self._analyze_single(log)
            if m is not None:
                matches.append(m)
        return matches

    def _analyze_single(self, log: dict[str, Any]) -> DnsQueryMatch | None:
        """Check a single DNS log entry against the AI domain list."""
        domain = self._extract_domain(log)
        if domain is None:
            return None

        service = match_domain(domain, self._lookup)
        if service is None:
            return None

        return DnsQueryMatch(
            query_domain=domain,
            source_ip=self._extract_source_ip(log) or "unknown",
            source_host=self._extract_source_host(log),
            timestamp=self._extract_timestamp(log),
        )

    # ── Field extraction helpers ──────────────────────────────

    @staticmethod
    def _extract_domain(log: dict[str, Any]) -> str | None:
        """Extract queried domain from DNS log (generic, ECS, Zeek)."""
        # Generic
        if "query_domain" in log:
            return str(log["query_domain"]).lower().rstrip(".")
        # ECS: dns.question.name
        dns = log.get("dns")
        if isinstance(dns, dict):
            question = dns.get("question")
            if isinstance(question, dict) and "name" in question:
                return str(question["name"]).lower().rstrip(".")
        # Zeek
        if "query" in log:
            return str(log["query"]).lower().rstrip(".")
        return None

    @staticmethod
    def _extract_source_ip(log: dict[str, Any]) -> str | None:
        """Extract source IP from DNS log."""
        if "source_ip" in log:
            return str(log["source_ip"])
        source = log.get("source")
        if isinstance(source, dict) and "ip" in source:
            return str(source["ip"])
        # Zeek
        id_field = log.get("id.orig_h")
        if id_field is not None:
            return str(id_field)
        return None

    @staticmethod
    def _extract_source_host(log: dict[str, Any]) -> str | None:
        """Extract source hostname from DNS log."""
        if "source_host" in log:
            return str(log["source_host"])
        host = log.get("host")
        if isinstance(host, dict) and "name" in host:
            return str(host["name"])
        if "hostname" in log:
            return str(log["hostname"])
        return None

    @staticmethod
    def _extract_timestamp(log: dict[str, Any]) -> datetime | None:
        """Extract timestamp from DNS log."""
        if "timestamp" in log:
            val = log["timestamp"]
            if isinstance(val, datetime):
                return val
            try:
                return datetime.fromisoformat(str(val))
            except (ValueError, TypeError):
                return None
        if "@timestamp" in log:
            try:
                return datetime.fromisoformat(str(log["@timestamp"]))
            except (ValueError, TypeError):
                return None
        return None

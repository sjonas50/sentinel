"""Data Exfiltration threat hunt playbook.

Detects: large outbound transfers, DNS tunneling indicators,
unusual external destinations, and after-hours data movement.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel_agents.hunt.base_hunt import HuntAgent
from sentinel_agents.hunt.models import (
    DataExfiltrationConfig,
    HuntFinding,
    PlaybookType,
)

if TYPE_CHECKING:
    from sentinel_agents.types import AgentPlan

logger = logging.getLogger(__name__)


class DataExfiltrationHuntAgent(HuntAgent):
    """Hunts for data exfiltration patterns in network logs."""

    async def build_queries(self, plan: AgentPlan) -> list[tuple[str, dict[str, Any], str]]:
        start, end = self.time_range
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": start.isoformat(),
                    "lte": end.isoformat(),
                }
            }
        }
        cfg = self.hunt_config
        assert isinstance(cfg, DataExfiltrationConfig)
        index = cfg.index_pattern

        queries: list[tuple[str, dict[str, Any], str]] = []

        # Q1: Large outbound transfers
        queries.append(
            (
                "large_outbound",
                {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "network.bytes": {
                                        "gte": cfg.large_transfer_bytes,
                                    }
                                }
                            },
                            time_filter,
                        ],
                        "must_not": [
                            {"terms": {"destination.ip": ["10.0.0.0/8"]}},
                        ],
                    }
                },
                index,
            )
        )

        # Q2: DNS tunneling indicators (long query names)
        queries.append(
            (
                "dns_tunneling",
                {
                    "bool": {
                        "must": [
                            {"match": {"event.category": "dns"}},
                            time_filter,
                        ],
                    }
                },
                index,
            )
        )

        # Q3: Unusual external destinations
        if cfg.unusual_destination_check:
            queries.append(
                (
                    "unusual_destinations",
                    {
                        "bool": {
                            "must": [
                                {"match": {"event.category": "network"}},
                                time_filter,
                            ],
                            "must_not": [
                                {
                                    "terms": {
                                        "destination.ip": [
                                            "10.0.0.0/8",
                                            "172.16.0.0/12",
                                            "192.168.0.0/16",
                                        ]
                                    }
                                },
                            ],
                        }
                    },
                    index,
                )
            )

        # Q4: After-hours network activity
        queries.append(
            (
                "after_hours_transfers",
                {
                    "bool": {
                        "must": [
                            {"match": {"event.category": "network"}},
                            {
                                "range": {
                                    "network.bytes": {
                                        "gte": cfg.large_transfer_bytes // 10,
                                    }
                                }
                            },
                            time_filter,
                        ],
                    }
                },
                index,
            )
        )

        return queries

    async def analyze_results(self, query_results: dict[str, Any]) -> list[HuntFinding]:
        findings: list[HuntFinding] = []
        cfg = self.hunt_config
        assert isinstance(cfg, DataExfiltrationConfig)

        # ── Large outbound transfers ─────────────────────────────
        large_out = query_results.get("large_outbound")
        if large_out and large_out.total_hits > 0:
            dest_bytes: dict[str, int] = {}
            dest_sources: dict[str, set[str]] = {}
            for event in large_out.events:
                dst = event.dest_ip or "unknown"
                src = event.source_ip or "unknown"
                raw_bytes = event.raw.get("network", {}).get("bytes", 0)
                dest_bytes[dst] = dest_bytes.get(dst, 0) + int(raw_bytes)
                dest_sources.setdefault(dst, set()).add(src)

            for dst_ip, total_bytes in dest_bytes.items():
                if total_bytes >= cfg.large_transfer_bytes:
                    sources = dest_sources.get(dst_ip, set())
                    mb = total_bytes / (1024 * 1024)
                    findings.append(
                        HuntFinding(
                            playbook=PlaybookType.DATA_EXFILTRATION,
                            severity="high",
                            title=(f"Large data transfer to {dst_ip} ({mb:.0f} MB)"),
                            description=(
                                f"Total of {mb:.1f} MB transferred to external "
                                f"destination {dst_ip} from "
                                f"{len(sources)} internal host(s)."
                            ),
                            evidence={
                                "dest_ips": [dst_ip],
                                "total_bytes": total_bytes,
                                "source_hosts": sorted(sources),
                            },
                            recommendations=[
                                f"Investigate traffic to {dst_ip}",
                                "Check if destination is an authorized service",
                                "Review DLP policies for sensitive data",
                            ],
                            affected_hosts=sorted(sources),
                            mitre_technique_ids=["T1567"],
                            mitre_tactic="Exfiltration",
                        )
                    )

        # ── DNS tunneling ────────────────────────────────────────
        dns_results = query_results.get("dns_tunneling")
        if dns_results and dns_results.total_hits > 0:
            long_queries: list[str] = []
            suspect_hosts: set[str] = set()
            for event in dns_results.events:
                dns_name = event.raw.get("dns", {}).get("question", {}).get("name", "")
                if len(dns_name) >= cfg.dns_query_length_threshold:
                    long_queries.append(dns_name)
                    if event.source_ip:
                        suspect_hosts.add(event.source_ip)

            if long_queries:
                findings.append(
                    HuntFinding(
                        playbook=PlaybookType.DATA_EXFILTRATION,
                        severity="high",
                        title=(f"Possible DNS tunneling ({len(long_queries)} suspicious queries)"),
                        description=(
                            f"Detected {len(long_queries)} DNS queries with "
                            f"names exceeding {cfg.dns_query_length_threshold} "
                            f"characters, a common indicator of DNS tunneling."
                        ),
                        evidence={
                            "dns_queries": long_queries[:10],
                            "source_hosts": sorted(suspect_hosts),
                            "query_count": len(long_queries),
                        },
                        recommendations=[
                            "Block suspicious DNS domains at resolver",
                            "Investigate source hosts for malware",
                            "Deploy DNS monitoring and filtering",
                        ],
                        affected_hosts=sorted(suspect_hosts),
                        mitre_technique_ids=["T1071.004"],
                        mitre_tactic="Exfiltration",
                    )
                )

        # ── After-hours transfers ────────────────────────────────
        after_hours = query_results.get("after_hours_transfers")
        if after_hours and after_hours.total_hits > 0:
            after_hours_hosts: set[str] = set()
            after_hours_count = 0
            for event in after_hours.events:
                if event.timestamp:
                    hour = event.timestamp.hour
                    is_after = hour >= cfg.after_hours_start or hour < cfg.after_hours_end
                    if is_after:
                        after_hours_count += 1
                        if event.source_ip:
                            after_hours_hosts.add(event.source_ip)

            if after_hours_count > 0:
                findings.append(
                    HuntFinding(
                        playbook=PlaybookType.DATA_EXFILTRATION,
                        severity="medium",
                        title=(f"After-hours data transfers from {len(after_hours_hosts)} host(s)"),
                        description=(
                            f"Detected {after_hours_count} network transfer "
                            f"events outside business hours "
                            f"({cfg.after_hours_start}:00-"
                            f"{cfg.after_hours_end}:00)."
                        ),
                        evidence={
                            "source_hosts": sorted(after_hours_hosts),
                            "event_count": after_hours_count,
                        },
                        recommendations=[
                            "Review after-hours transfer policies",
                            "Investigate source hosts for scheduled tasks",
                            "Consider network segmentation for after-hours",
                        ],
                        affected_hosts=sorted(after_hours_hosts),
                        mitre_technique_ids=["T1048"],
                        mitre_tactic="Exfiltration",
                    )
                )

        return findings

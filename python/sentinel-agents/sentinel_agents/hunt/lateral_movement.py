"""Lateral Movement threat hunt playbook.

Detects: unusual internal traffic, service account hopping,
RDP chains, and SMB/WinRM lateral activity.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel_agents.hunt.base_hunt import HuntAgent
from sentinel_agents.hunt.models import (
    HuntFinding,
    LateralMovementConfig,
    PlaybookType,
)

if TYPE_CHECKING:
    from sentinel_agents.types import AgentPlan

logger = logging.getLogger(__name__)


class LateralMovementHuntAgent(HuntAgent):
    """Hunts for lateral movement patterns in network and auth logs."""

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
        assert isinstance(cfg, LateralMovementConfig)
        index = cfg.index_pattern

        queries: list[tuple[str, dict[str, Any], str]] = []

        # Q1: Internal RDP connections (port 3389)
        queries.append(
            (
                "internal_rdp",
                {
                    "bool": {
                        "must": [
                            {"term": {"destination.port": 3389}},
                            time_filter,
                        ],
                    }
                },
                index,
            )
        )

        # Q2: Service account authentication across hosts
        queries.append(
            (
                "service_account_hops",
                {
                    "bool": {
                        "must": [
                            {"wildcard": {"user.name": "svc-*"}},
                            {"match": {"event.category": "authentication"}},
                            {"match": {"event.outcome": "success"}},
                            time_filter,
                        ],
                    }
                },
                index,
            )
        )

        # Q3: SMB/WinRM lateral connections
        queries.append(
            (
                "smb_winrm",
                {
                    "bool": {
                        "must": [
                            {"terms": {"destination.port": [445, 5985, 5986]}},
                            time_filter,
                        ],
                    }
                },
                index,
            )
        )

        # Q4: Unusual internal port connections
        queries.append(
            (
                "unusual_internal_ports",
                {
                    "bool": {
                        "must": [
                            time_filter,
                        ],
                        "must_not": [
                            {
                                "terms": {
                                    "destination.port": [
                                        22,
                                        53,
                                        80,
                                        88,
                                        135,
                                        389,
                                        443,
                                        445,
                                        636,
                                        3389,
                                        5985,
                                        5986,
                                        8080,
                                        8443,
                                    ]
                                }
                            },
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
        assert isinstance(cfg, LateralMovementConfig)

        # ── Analyze service account hopping ──────────────────────
        svc_hops = query_results.get("service_account_hops")
        if svc_hops and svc_hops.total_hits > 0:
            # Map service accounts to unique destination hosts
            svc_host_map: dict[str, set[str]] = {}
            for event in svc_hops.events:
                user = event.user or "unknown"
                host = event.hostname or event.dest_ip or "unknown"
                svc_host_map.setdefault(user, set()).add(host)

            for svc_account, hosts in svc_host_map.items():
                if len(hosts) >= cfg.service_account_hop_threshold:
                    findings.append(
                        HuntFinding(
                            playbook=PlaybookType.LATERAL_MOVEMENT,
                            severity="high",
                            title=(f"Service account {svc_account} active on {len(hosts)} hosts"),
                            description=(
                                f"Service account '{svc_account}' authenticated "
                                f"to {len(hosts)} distinct hosts: "
                                f"{', '.join(sorted(hosts))}. This may indicate "
                                f"lateral movement using compromised credentials."
                            ),
                            evidence={
                                "source_hosts": sorted(hosts),
                                "dest_hosts": sorted(hosts),
                                "service_account": svc_account,
                                "host_count": len(hosts),
                            },
                            recommendations=[
                                f"Audit all activity by {svc_account}",
                                "Restrict service account to expected hosts",
                                "Rotate service account credentials",
                            ],
                            affected_hosts=sorted(hosts),
                            affected_users=[svc_account],
                            mitre_technique_ids=["T1021"],
                            mitre_tactic="Lateral Movement",
                        )
                    )

        # ── Analyze internal RDP ─────────────────────────────────
        rdp_results = query_results.get("internal_rdp")
        if rdp_results and rdp_results.total_hits > 0:
            rdp_sources: dict[str, set[str]] = {}
            for event in rdp_results.events:
                src = event.source_ip or "unknown"
                dst = event.dest_ip or "unknown"
                rdp_sources.setdefault(src, set()).add(dst)

            for src_ip, destinations in rdp_sources.items():
                if (
                    self._is_internal(src_ip, cfg.internal_subnet_prefixes)
                    and len(destinations) >= 2  # noqa: PLR2004
                ):
                    findings.append(
                        HuntFinding(
                            playbook=PlaybookType.LATERAL_MOVEMENT,
                            severity="medium",
                            title=f"Internal RDP fan-out from {src_ip}",
                            description=(
                                f"Host {src_ip} made RDP connections to "
                                f"{len(destinations)} internal hosts: "
                                f"{', '.join(sorted(destinations))}."
                            ),
                            evidence={
                                "source_hosts": [src_ip],
                                "dest_hosts": sorted(destinations),
                                "dest_ports": [3389],
                            },
                            recommendations=[
                                f"Investigate host {src_ip} for compromise",
                                "Review RDP access policies",
                                "Enable NLA for all RDP endpoints",
                            ],
                            affected_hosts=[src_ip, *sorted(destinations)],
                            mitre_technique_ids=["T1021.001"],
                            mitre_tactic="Lateral Movement",
                        )
                    )

        # ── Analyze SMB/WinRM ────────────────────────────────────
        smb_results = query_results.get("smb_winrm")
        if smb_results and smb_results.total_hits > 0:
            smb_sources: dict[str, set[str]] = {}
            for event in smb_results.events:
                src = event.source_ip or "unknown"
                dst = event.dest_ip or "unknown"
                smb_sources.setdefault(src, set()).add(dst)

            for src_ip, destinations in smb_sources.items():
                if len(destinations) >= cfg.service_account_hop_threshold:
                    findings.append(
                        HuntFinding(
                            playbook=PlaybookType.LATERAL_MOVEMENT,
                            severity="medium",
                            title=f"SMB/WinRM fan-out from {src_ip}",
                            description=(
                                f"Host {src_ip} made SMB/WinRM connections to "
                                f"{len(destinations)} hosts: "
                                f"{', '.join(sorted(destinations))}."
                            ),
                            evidence={
                                "source_hosts": [src_ip],
                                "dest_hosts": sorted(destinations),
                                "dest_ports": [445, 5985],
                            },
                            recommendations=[
                                f"Investigate host {src_ip} for compromise",
                                "Review SMB/WinRM access controls",
                            ],
                            affected_hosts=[src_ip, *sorted(destinations)],
                            mitre_technique_ids=["T1021.002"],
                            mitre_tactic="Lateral Movement",
                        )
                    )

        return findings

    @staticmethod
    def _is_internal(ip: str, prefixes: list[str]) -> bool:
        """Check if an IP matches internal subnet prefixes."""
        return any(ip.startswith(p) for p in prefixes)

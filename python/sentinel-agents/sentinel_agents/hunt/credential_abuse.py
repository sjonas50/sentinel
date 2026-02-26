"""Credential Abuse threat hunt playbook.

Detects: brute-force login attempts, credential stuffing, password spraying,
service account misuse, and account lockout patterns.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from sentinel_agents.hunt.base_hunt import HuntAgent
from sentinel_agents.hunt.models import (
    CredentialAbuseConfig,
    HuntFinding,
    PlaybookType,
)

if TYPE_CHECKING:
    from sentinel_agents.types import AgentPlan

logger = logging.getLogger(__name__)


class CredentialAbuseHuntAgent(HuntAgent):
    """Hunts for credential abuse patterns in authentication logs."""

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
        assert isinstance(cfg, CredentialAbuseConfig)
        index = cfg.index_pattern

        queries: list[tuple[str, dict[str, Any], str]] = []

        # Q1: All failed authentication events
        queries.append(
            (
                "failed_logins_by_ip",
                {
                    "bool": {
                        "must": [
                            {"match": {"event.outcome": "failure"}},
                            {"match": {"event.category": "authentication"}},
                            time_filter,
                        ],
                    }
                },
                index,
            )
        )

        # Q2: Account lockout events (Windows 4740 / 4625)
        if cfg.lockout_correlation:
            queries.append(
                (
                    "account_lockouts",
                    {
                        "bool": {
                            "must": [
                                {"terms": {"event.code": ["4740", "4625"]}},
                                time_filter,
                            ],
                        }
                    },
                    index,
                )
            )

        # Q3: Service account authentication failures
        if cfg.service_account_monitoring:
            queries.append(
                (
                    "service_account_failures",
                    {
                        "bool": {
                            "must": [
                                {"match": {"event.outcome": "failure"}},
                                {"match": {"event.category": "authentication"}},
                                {"wildcard": {"user.name": "svc-*"}},
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
        assert isinstance(cfg, CredentialAbuseConfig)

        # ── Analyze failed logins ────────────────────────────────
        failed_logins = query_results.get("failed_logins_by_ip")
        if failed_logins and failed_logins.total_hits > 0:
            ip_counts: dict[str, int] = {}
            ip_users: dict[str, set[str]] = {}
            for event in failed_logins.events:
                ip = event.source_ip or "unknown"
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
                user = event.user or "unknown"
                ip_users.setdefault(ip, set()).add(user)

            # Brute force: IPs exceeding threshold
            for ip, count in ip_counts.items():
                if count >= cfg.failed_login_threshold:
                    unique_users = ip_users.get(ip, set())
                    severity = "high" if count > cfg.failed_login_threshold * 3 else "medium"
                    findings.append(
                        HuntFinding(
                            playbook=PlaybookType.CREDENTIAL_ABUSE,
                            severity=severity,
                            title=f"Excessive failed logins from {ip}",
                            description=(
                                f"Source IP {ip} had {count} failed login "
                                f"attempts targeting "
                                f"{len(unique_users)} unique user(s) in the "
                                f"last {cfg.time_window_hours} hours."
                            ),
                            evidence={
                                "source_ips": [ip],
                                "failed_count": count,
                                "target_users": sorted(unique_users),
                                "event_ids": ["4625"],
                            },
                            recommendations=[
                                f"Block IP {ip} at the perimeter firewall",
                                "Enable account lockout policies if not set",
                                "Review affected accounts for compromise",
                            ],
                            affected_users=sorted(unique_users),
                            mitre_technique_ids=["T1110.001"],
                            mitre_tactic="Credential Access",
                        )
                    )

            # Credential stuffing: same IP targeting many unique users
            for ip, users in ip_users.items():
                if len(users) >= cfg.credential_stuffing_unique_users:
                    findings.append(
                        HuntFinding(
                            playbook=PlaybookType.CREDENTIAL_ABUSE,
                            severity="high",
                            title=f"Potential credential stuffing from {ip}",
                            description=(
                                f"Source IP {ip} attempted logins against "
                                f"{len(users)} unique accounts, indicating "
                                f"possible credential stuffing attack."
                            ),
                            evidence={
                                "source_ips": [ip],
                                "target_users": sorted(users),
                                "unique_user_count": len(users),
                            },
                            recommendations=[
                                f"Block IP {ip} immediately",
                                "Force password reset for targeted accounts",
                                "Enable MFA for all affected accounts",
                                "Check credentials against breach databases",
                            ],
                            affected_users=sorted(users),
                            mitre_technique_ids=["T1110.004"],
                            mitre_tactic="Credential Access",
                        )
                    )

        # ── Analyze service account failures ─────────────────────
        svc_results = query_results.get("service_account_failures")
        if svc_results and svc_results.total_hits > 0:
            svc_accounts: set[str] = set()
            for event in svc_results.events:
                if event.user:
                    svc_accounts.add(event.user)

            if svc_accounts:
                findings.append(
                    HuntFinding(
                        playbook=PlaybookType.CREDENTIAL_ABUSE,
                        severity="critical",
                        title="Service account authentication failures",
                        description=(
                            f"Service accounts {', '.join(sorted(svc_accounts))} "
                            f"experienced authentication failures. Service "
                            f"accounts should never fail in normal operations."
                        ),
                        evidence={
                            "target_users": sorted(svc_accounts),
                            "total_failures": svc_results.total_hits,
                        },
                        recommendations=[
                            "Immediately rotate affected service account credentials",
                            "Audit recent activity of these service accounts",
                            "Review service account permissions for least-privilege",
                        ],
                        affected_users=sorted(svc_accounts),
                        mitre_technique_ids=["T1110"],
                        mitre_tactic="Credential Access",
                    )
                )

        # ── LLM supplementary analysis ───────────────────────────
        if failed_logins and failed_logins.total_hits > 0:
            llm_findings = await self._llm_analyze(query_results)
            findings.extend(llm_findings)

        return findings

    async def _llm_analyze(self, query_results: dict[str, Any]) -> list[HuntFinding]:
        """Use LLM to identify subtler credential abuse patterns."""
        from sentinel_agents.llm import LLMMessage

        summary_data: dict[str, Any] = {}
        for name, result in query_results.items():
            if result and hasattr(result, "total_hits"):
                events = result.events[:20] if hasattr(result, "events") else []
                summary_data[name] = {
                    "total_hits": result.total_hits,
                    "sample_events": [
                        {
                            "timestamp": str(e.timestamp),
                            "source_ip": e.source_ip,
                            "user": e.user,
                            "hostname": e.hostname,
                        }
                        for e in events
                    ],
                }

        prompt = (
            "Analyze these SIEM query results for credential abuse patterns.\n"
            "Look for: time-based patterns, password spraying (low-and-slow), "
            "unusual user agents.\n\n"
            f"Data: {json.dumps(summary_data, default=str)}\n\n"
            "Return a JSON object with 'findings' array. Each finding: "
            "severity, title, description, mitre_technique_ids, "
            "affected_users (arrays of strings)."
        )

        response = await self.llm.complete(
            messages=[LLMMessage(role="user", content=prompt)],
            system="You are a SOC analyst specializing in credential abuse.",
            max_tokens=1024,
        )

        try:
            data = json.loads(response.content)
            return [
                HuntFinding(
                    playbook=PlaybookType.CREDENTIAL_ABUSE,
                    severity=f.get("severity", "medium"),
                    title=f.get("title", "LLM-identified pattern"),
                    description=f.get("description", ""),
                    mitre_technique_ids=f.get("mitre_technique_ids", []),
                    affected_users=f.get("affected_users", []),
                    mitre_tactic="Credential Access",
                )
                for f in data.get("findings", [])
            ]
        except (json.JSONDecodeError, KeyError, TypeError):
            return []

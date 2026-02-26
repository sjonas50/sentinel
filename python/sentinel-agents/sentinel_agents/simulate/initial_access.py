"""Initial Access adversarial simulation playbook.

Simulates: exploit public-facing apps (T1190), external remote services
(T1133), phishing vectors (T1566), valid accounts (T1078), and trusted
relationships (T1199).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel_agents.simulate.base_sim import SimulationAgent
from sentinel_agents.simulate.mitre import get_techniques_for_tactic
from sentinel_agents.simulate.models import (
    RemediationStep,
    SimulationFinding,
    TacticType,
)

if TYPE_CHECKING:
    from sentinel_agents.simulate.mitre import MitreTechnique
    from sentinel_agents.types import AgentPlan

logger = logging.getLogger(__name__)

_REMOTE_SERVICE_PORTS = {22, 3389, 5900, 5985}


class InitialAccessSimAgent(SimulationAgent):
    """Simulates initial access techniques against the digital twin."""

    async def select_techniques(
        self,
        plan: AgentPlan,
    ) -> list[MitreTechnique]:
        all_techniques = get_techniques_for_tactic(TacticType.INITIAL_ACCESS)
        if self.sim_config.techniques:
            return [t for t in all_techniques if t.technique_id in self.sim_config.techniques]
        return all_techniques

    async def simulate_technique(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        handlers = {
            "T1190": self._sim_t1190,
            "T1133": self._sim_t1133,
            "T1566": self._sim_t1566,
            "T1078": self._sim_t1078,
            "T1199": self._sim_t1199,
        }
        handler = handlers.get(technique.technique_id)
        if handler is None:
            return []
        return await handler(technique, context)

    # ── T1190: Exploit Public-Facing Application ────────────────

    async def _sim_t1190(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        internet_hosts = [h for h in context.get("hosts", []) if h.get("is_internet_facing")]

        for host in internet_hosts:
            host_id = host.get("id", "")
            neighbors = await self.graph.query_neighbors(
                host_id,
                tenant_id,
                edge_types=["EXPOSES", "HAS_CVE"],
            )
            exploitable_vulns = [
                n for n in neighbors if n.get("label") == "Vulnerability" and n.get("exploitable")
            ]
            if not exploitable_vulns:
                continue

            paths_result = await self.graph.find_attack_paths(
                tenant_id,
                sources=[host_id],
                max_depth=self.sim_config.max_depth,
                max_paths=self.sim_config.max_paths,
            )
            attack_paths = paths_result.get("attack_paths", [])
            path_risk = max(
                (p.get("risk_score", 0) for p in attack_paths),
                default=0.0,
            )

            cve_ids = [v.get("cve_id", "unknown") for v in exploitable_vulns]
            risk = self._compute_risk_score(path_risk, "critical")
            findings.append(
                SimulationFinding(
                    tactic=TacticType.INITIAL_ACCESS,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="critical",
                    title=(f"Exploitable public-facing service on {host.get('hostname', host_id)}"),
                    description=(
                        f"Internet-facing host {host.get('hostname', host_id)}"
                        f" has {len(exploitable_vulns)} exploitable "
                        f"vulnerabilities ({', '.join(cve_ids)}). "
                        f"{len(attack_paths)} attack path(s) found."
                    ),
                    attack_paths=attack_paths,
                    risk_score=risk,
                    affected_nodes=[host_id],
                    evidence={
                        "cve_ids": cve_ids,
                        "host_id": host_id,
                        "paths_count": len(attack_paths),
                    },
                    remediation=[
                        RemediationStep(
                            title=f"Patch {', '.join(cve_ids[:3])}",
                            description="Apply security patches for exploitable CVEs",
                            priority="critical",
                            effort="medium",
                        ),
                        RemediationStep(
                            title="Deploy WAF",
                            description="Add web application firewall in front of exposed services",
                            priority="high",
                            effort="medium",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1133: External Remote Services ─────────────────────────

    async def _sim_t1133(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        internet_hosts = [h for h in context.get("hosts", []) if h.get("is_internet_facing")]

        for host in internet_hosts:
            host_id = host.get("id", "")
            neighbors = await self.graph.query_neighbors(
                host_id,
                tenant_id,
                edge_types=["HAS_ACCESS", "EXPOSES"],
            )
            remote_svcs = [n for n in neighbors if n.get("port") in _REMOTE_SERVICE_PORTS]
            no_mfa_users = [
                n for n in neighbors if n.get("label") == "User" and not n.get("mfa_enabled")
            ]
            if not remote_svcs:
                continue

            svc_names = [str(s.get("port", "unknown")) for s in remote_svcs]
            risk = self._compute_risk_score(0.5, "high")
            findings.append(
                SimulationFinding(
                    tactic=TacticType.INITIAL_ACCESS,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="high",
                    title=(f"Exposed remote services on {host.get('hostname', host_id)}"),
                    description=(
                        f"Internet-facing host exposes remote services on "
                        f"ports {', '.join(svc_names)}. "
                        f"{len(no_mfa_users)} user(s) without MFA."
                    ),
                    risk_score=risk,
                    affected_nodes=[host_id],
                    evidence={
                        "exposed_ports": [s.get("port") for s in remote_svcs],
                        "no_mfa_user_count": len(no_mfa_users),
                    },
                    remediation=[
                        RemediationStep(
                            title="Enable MFA for all remote access",
                            description="Require multi-factor authentication for RDP/SSH/VNC",
                            priority="critical",
                            effort="low",
                        ),
                        RemediationStep(
                            title="Restrict source IPs",
                            description="Limit remote service access to known IP ranges",
                            priority="high",
                            effort="low",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1566: Phishing ─────────────────────────────────────────

    async def _sim_t1566(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        no_mfa_users = [
            u
            for u in context.get("users", [])
            if u.get("user_type") == "human" and not u.get("mfa_enabled")
        ]
        if not no_mfa_users:
            return []

        critical_access_users: list[dict[str, Any]] = []
        for user in no_mfa_users:
            user_id = user.get("id", "")
            neighbors = await self.graph.query_neighbors(
                user_id,
                tenant_id,
                edge_types=["HAS_ACCESS"],
            )
            critical_hosts = [n for n in neighbors if n.get("criticality") in ("critical", "high")]
            if critical_hosts:
                critical_access_users.append(
                    {
                        "user_id": user_id,
                        "username": user.get("username", "unknown"),
                        "critical_host_count": len(critical_hosts),
                    }
                )

        if not critical_access_users:
            return []

        affected = [u["user_id"] for u in critical_access_users]
        risk = self._compute_risk_score(
            0.6,
            "high" if len(critical_access_users) > 3 else "medium",  # noqa: PLR2004
        )
        findings.append(
            SimulationFinding(
                tactic=TacticType.INITIAL_ACCESS,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="high" if len(critical_access_users) > 3 else "medium",  # noqa: PLR2004
                title=(
                    f"{len(critical_access_users)} phishing-vulnerable user(s) with critical access"
                ),
                description=(
                    f"{len(critical_access_users)} user(s) without MFA "
                    f"have access to critical systems, making them viable "
                    f"phishing targets."
                ),
                risk_score=risk,
                affected_nodes=affected,
                evidence={
                    "users": critical_access_users,
                    "total_no_mfa": len(no_mfa_users),
                },
                remediation=[
                    RemediationStep(
                        title="Enable MFA",
                        description="Require MFA for all users with critical system access",
                        priority="critical",
                        effort="low",
                    ),
                    RemediationStep(
                        title="Security awareness training",
                        description="Conduct phishing awareness training for affected users",
                        priority="high",
                        effort="medium",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1078: Valid Accounts ───────────────────────────────────

    async def _sim_t1078(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        # Check service accounts with excessive access
        svc_accounts = [
            u for u in context.get("users", []) if u.get("user_type") == "service_account"
        ]

        for svc in svc_accounts:
            svc_id = svc.get("id", "")
            neighbors = await self.graph.query_neighbors(
                svc_id,
                tenant_id,
                edge_types=["HAS_ACCESS"],
            )
            if len(neighbors) >= 5:  # noqa: PLR2004
                risk = self._compute_risk_score(0.5, "high")
                findings.append(
                    SimulationFinding(
                        tactic=TacticType.INITIAL_ACCESS,
                        technique_id=technique.technique_id,
                        technique_name=technique.technique_name,
                        severity="high",
                        title=(f"Overprivileged service account {svc.get('username', svc_id)}"),
                        description=(
                            f"Service account '{svc.get('username', svc_id)}' "
                            f"has access to {len(neighbors)} resources. "
                            f"Compromising it grants broad lateral access."
                        ),
                        risk_score=risk,
                        affected_nodes=[svc_id],
                        evidence={
                            "username": svc.get("username"),
                            "access_count": len(neighbors),
                        },
                        remediation=[
                            RemediationStep(
                                title="Apply least privilege",
                                description="Restrict service account to minimum required access",
                                priority="high",
                                effort="medium",
                            ),
                            RemediationStep(
                                title="Rotate credentials",
                                description="Rotate service account credentials regularly",
                                priority="medium",
                                effort="low",
                            ),
                        ],
                        mitre_url=technique.mitre_url,
                    ),
                )
        return findings

    # ── T1199: Trusted Relationship ─────────────────────────────

    async def _sim_t1199(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        trust_edges = await self.graph.query_edges(
            tenant_id,
            edge_type="TRUSTS",
        )
        if not trust_edges:
            return []

        affected = list(
            {e.get("source_id", "") for e in trust_edges}
            | {e.get("target_id", "") for e in trust_edges}
        )

        paths_result = await self.graph.find_attack_paths(
            tenant_id,
            sources=[e.get("source_id", "") for e in trust_edges],
            max_depth=self.sim_config.max_depth,
            max_paths=self.sim_config.max_paths,
        )
        attack_paths = paths_result.get("attack_paths", [])
        path_risk = max(
            (p.get("risk_score", 0) for p in attack_paths),
            default=0.0,
        )

        risk = self._compute_risk_score(path_risk, "medium")
        findings.append(
            SimulationFinding(
                tactic=TacticType.INITIAL_ACCESS,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="medium",
                title=(f"{len(trust_edges)} trust relationship(s) detected across boundaries"),
                description=(
                    f"Found {len(trust_edges)} TRUSTS edge(s) that may "
                    f"enable lateral movement across security boundaries. "
                    f"{len(attack_paths)} attack path(s) found."
                ),
                attack_paths=attack_paths,
                risk_score=risk,
                affected_nodes=affected,
                evidence={
                    "trust_count": len(trust_edges),
                    "paths_count": len(attack_paths),
                },
                remediation=[
                    RemediationStep(
                        title="Review trust boundaries",
                        description="Audit all trust relationships for necessity",
                        priority="medium",
                        effort="medium",
                    ),
                    RemediationStep(
                        title="Implement zero-trust segmentation",
                        description="Replace implicit trust with explicit verification",
                        priority="high",
                        effort="high",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

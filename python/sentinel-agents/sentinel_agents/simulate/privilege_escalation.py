"""Privilege Escalation adversarial simulation playbook.

Simulates: exploitation for priv esc (T1068), default accounts (T1078.001),
abuse elevation control (T1548), access token manipulation (T1134), and
account manipulation (T1098).
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

_DEFAULT_ACCOUNT_NAMES = {
    "admin",
    "administrator",
    "root",
    "guest",
    "sa",
    "postgres",
    "oracle",
    "test",
}


class PrivilegeEscalationSimAgent(SimulationAgent):
    """Simulates privilege escalation techniques against the digital twin."""

    async def select_techniques(
        self,
        plan: AgentPlan,
    ) -> list[MitreTechnique]:
        all_techniques = get_techniques_for_tactic(
            TacticType.PRIVILEGE_ESCALATION,
        )
        if self.sim_config.techniques:
            return [t for t in all_techniques if t.technique_id in self.sim_config.techniques]
        return all_techniques

    async def simulate_technique(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        handlers = {
            "T1068": self._sim_t1068,
            "T1078.001": self._sim_t1078_001,
            "T1548": self._sim_t1548,
            "T1134": self._sim_t1134,
            "T1098": self._sim_t1098,
        }
        handler = handlers.get(technique.technique_id)
        if handler is None:
            return []
        return await handler(technique, context)

    # ── T1068: Exploitation for Privilege Escalation ────────────

    async def _sim_t1068(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []

        high_cvss_vulns = [
            v
            for v in context.get("vulnerabilities", [])
            if v.get("cvss_score", 0) >= 7.0  # noqa: PLR2004
            and v.get("exploitable")
        ]
        if not high_cvss_vulns:
            return []

        affected = [v.get("id", "") for v in high_cvss_vulns]
        max_cvss = max(v.get("cvss_score", 0) for v in high_cvss_vulns)
        cve_ids = [v.get("cve_id", "unknown") for v in high_cvss_vulns]
        risk = self._compute_risk_score(max_cvss / 10.0, "critical")

        findings.append(
            SimulationFinding(
                tactic=TacticType.PRIVILEGE_ESCALATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="critical",
                title=(f"{len(high_cvss_vulns)} exploitable privilege escalation vulnerabilities"),
                description=(
                    f"Found {len(high_cvss_vulns)} vulnerabilities with "
                    f"CVSS >= 7.0 and exploitable=true: "
                    f"{', '.join(cve_ids[:5])}. Max CVSS: {max_cvss}."
                ),
                risk_score=risk,
                affected_nodes=affected,
                evidence={
                    "cve_ids": cve_ids,
                    "max_cvss": max_cvss,
                    "vuln_count": len(high_cvss_vulns),
                },
                remediation=[
                    RemediationStep(
                        title="Patch critical vulnerabilities",
                        description=f"Apply patches for {', '.join(cve_ids[:3])}",
                        priority="critical",
                        effort="medium",
                    ),
                    RemediationStep(
                        title="Application sandboxing",
                        description="Implement privilege separation for affected services",
                        priority="high",
                        effort="high",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1078.001: Default Accounts ─────────────────────────────

    async def _sim_t1078_001(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        default_users = [
            u
            for u in context.get("users", [])
            if u.get("username", "").lower() in _DEFAULT_ACCOUNT_NAMES and u.get("enabled", True)
        ]
        if not default_users:
            return []

        for user in default_users:
            user_id = user.get("id", "")
            neighbors = await self.graph.query_neighbors(
                user_id,
                tenant_id,
                edge_types=["HAS_ACCESS"],
            )
            if not neighbors:
                continue

            risk = self._compute_risk_score(0.6, "high")
            findings.append(
                SimulationFinding(
                    tactic=TacticType.PRIVILEGE_ESCALATION,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="high",
                    title=(f"Active default account: {user.get('username', user_id)}"),
                    description=(
                        f"Default account '{user.get('username')}' is "
                        f"enabled and has access to {len(neighbors)} "
                        f"resource(s)."
                    ),
                    risk_score=risk,
                    affected_nodes=[user_id],
                    evidence={
                        "username": user.get("username"),
                        "access_count": len(neighbors),
                    },
                    remediation=[
                        RemediationStep(
                            title="Disable default account",
                            description=f"Disable the '{user.get('username')}' default account",
                            priority="high",
                            effort="low",
                            automated=True,
                        ),
                        RemediationStep(
                            title="Enforce unique credentials",
                            description="Replace default accounts with named service accounts",
                            priority="medium",
                            effort="medium",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1548: Abuse Elevation Control Mechanism ────────────────

    async def _sim_t1548(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        edges = await self.graph.query_edges(
            tenant_id,
            edge_type="MEMBER_OF",
            source_label="User",
            target_label="Role",
        )

        # Collect unique role IDs to check
        role_ids = list({e.get("target_id", "") for e in edges})

        overprivileged_roles: list[dict[str, Any]] = []
        for role_id in role_ids:
            neighbors = await self.graph.query_neighbors(
                role_id,
                tenant_id,
            )
            # Look for role details in the neighbor data or raw
            role_data = next(
                (n for n in neighbors if n.get("id") == role_id),
                None,
            )
            permissions = role_data.get("permissions", []) if role_data else []
            has_wildcard = any("*" in str(p) for p in permissions)
            if has_wildcard:
                overprivileged_roles.append(
                    {
                        "role_id": role_id,
                        "permissions": permissions,
                    }
                )

        if not overprivileged_roles:
            return []

        affected = [r["role_id"] for r in overprivileged_roles]
        risk = self._compute_risk_score(0.6, "high")
        findings.append(
            SimulationFinding(
                tactic=TacticType.PRIVILEGE_ESCALATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="high",
                title=(f"{len(overprivileged_roles)} role(s) with wildcard permissions"),
                description=(
                    f"Found {len(overprivileged_roles)} role(s) with "
                    f"wildcard (*) permissions that enable privilege "
                    f"escalation."
                ),
                risk_score=risk,
                affected_nodes=affected,
                evidence={
                    "role_count": len(overprivileged_roles),
                    "roles": overprivileged_roles,
                },
                remediation=[
                    RemediationStep(
                        title="Replace wildcards with specific permissions",
                        description=(
                            "Audit roles and replace wildcard permissions with least-privilege"
                        ),
                        priority="high",
                        effort="medium",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1134: Access Token Manipulation ────────────────────────

    async def _sim_t1134(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

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
            critical_hosts = [n for n in neighbors if n.get("criticality") in ("critical", "high")]
            if len(critical_hosts) < 3:  # noqa: PLR2004
                continue

            blast = await self.graph.compute_blast_radius(
                tenant_id,
                svc_id,
            )
            blast_score = blast.get("blast_score", 0.0)
            risk = self._compute_risk_score(0.7, "high", blast_score)
            findings.append(
                SimulationFinding(
                    tactic=TacticType.PRIVILEGE_ESCALATION,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="high",
                    title=(f"Token manipulation risk: {svc.get('username', svc_id)}"),
                    description=(
                        f"Service account '{svc.get('username', svc_id)}' "
                        f"accesses {len(critical_hosts)} critical hosts. "
                        f"Token compromise enables wide privilege escalation."
                    ),
                    blast_radius=blast,
                    risk_score=risk,
                    affected_nodes=[
                        svc_id,
                        *(h.get("id", "") for h in critical_hosts),
                    ],
                    evidence={
                        "username": svc.get("username"),
                        "critical_host_count": len(critical_hosts),
                        "blast_score": blast_score,
                    },
                    remediation=[
                        RemediationStep(
                            title="Implement token lifetime limits",
                            description="Set short token expiration for service accounts",
                            priority="high",
                            effort="low",
                        ),
                        RemediationStep(
                            title="Restrict service account scope",
                            description="Limit service account to minimum required hosts",
                            priority="high",
                            effort="medium",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1098: Account Manipulation ─────────────────────────────

    async def _sim_t1098(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        edges = await self.graph.query_edges(
            tenant_id,
            edge_type="MEMBER_OF",
            source_label="User",
            target_label="Role",
        )
        role_ids = list({e.get("target_id", "") for e in edges})

        for role_id in role_ids:
            neighbors = await self.graph.query_neighbors(
                role_id,
                tenant_id,
            )
            role_data = next(
                (n for n in neighbors if n.get("id") == role_id),
                None,
            )
            if not role_data:
                continue
            permissions = role_data.get("permissions", [])
            has_iam = any(
                kw in str(p).lower()
                for p in permissions
                for kw in ("iam", "identity", "user", "role")
            )
            if has_iam and len(permissions) > 10:  # noqa: PLR2004
                # Users in this role can self-elevate
                role_users = [
                    e.get("source_id", "") for e in edges if e.get("target_id") == role_id
                ]
                risk = self._compute_risk_score(0.6, "high")
                findings.append(
                    SimulationFinding(
                        tactic=TacticType.PRIVILEGE_ESCALATION,
                        technique_id=technique.technique_id,
                        technique_name=technique.technique_name,
                        severity="high",
                        title=(f"Self-elevation risk via role {role_id}"),
                        description=(
                            f"Role '{role_id}' has {len(permissions)} "
                            f"permissions including identity management. "
                            f"{len(role_users)} user(s) can self-elevate."
                        ),
                        risk_score=risk,
                        affected_nodes=[role_id, *role_users],
                        evidence={
                            "role_id": role_id,
                            "permission_count": len(permissions),
                            "user_count": len(role_users),
                        },
                        remediation=[
                            RemediationStep(
                                title="Separation of duties",
                                description="Remove identity management from broad roles",
                                priority="high",
                                effort="medium",
                            ),
                            RemediationStep(
                                title="Privileged access reviews",
                                description="Enable periodic review of privileged role assignments",
                                priority="medium",
                                effort="low",
                            ),
                        ],
                        mitre_url=technique.mitre_url,
                    ),
                )
        return findings

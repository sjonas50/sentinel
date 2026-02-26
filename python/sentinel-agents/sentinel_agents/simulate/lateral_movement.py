"""Lateral Movement adversarial simulation playbook.

Simulates: RDP chains (T1021.001), SSH chains (T1021.004), pass the
hash (T1550.002), Kerberos ticket theft (T1558), and domain trust
discovery (T1482).
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


class LateralMovementSimAgent(SimulationAgent):
    """Simulates lateral movement techniques against the digital twin."""

    async def select_techniques(
        self,
        plan: AgentPlan,
    ) -> list[MitreTechnique]:
        all_techniques = get_techniques_for_tactic(
            TacticType.LATERAL_MOVEMENT,
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
            "T1021.001": self._sim_rdp,
            "T1021.004": self._sim_ssh,
            "T1550.002": self._sim_pass_the_hash,
            "T1558": self._sim_kerberos,
            "T1482": self._sim_domain_trust,
        }
        handler = handlers.get(technique.technique_id)
        if handler is None:
            return []
        return await handler(technique, context)

    # ── T1021.001: RDP ──────────────────────────────────────────

    async def _sim_rdp(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        rdp_services = [
            s
            for s in context.get("services", [])
            if s.get("port") == 3389  # noqa: PLR2004
        ]
        if not rdp_services:
            return []

        paths_result = await self.graph.find_attack_paths(
            tenant_id,
            max_depth=self.sim_config.max_depth,
            max_paths=self.sim_config.max_paths,
            include_lateral=True,
        )
        lateral_chains = paths_result.get("lateral_chains", [])
        rdp_chains = [
            c for c in lateral_chains if any("rdp" in t.lower() for t in c.get("techniques", []))
        ]

        if rdp_chains:
            max_risk = max(
                (c.get("risk_score", 0) for c in rdp_chains),
                default=0.0,
            )
            risk = self._compute_risk_score(max_risk, "high")
            affected = list({s.get("host_id", s.get("id", "")) for s in rdp_services})
            findings.append(
                SimulationFinding(
                    tactic=TacticType.LATERAL_MOVEMENT,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="high",
                    title=f"{len(rdp_chains)} RDP lateral chain(s) found",
                    description=(
                        f"Detected {len(rdp_chains)} RDP lateral movement "
                        f"chain(s) across {len(rdp_services)} host(s) with "
                        f"RDP enabled."
                    ),
                    attack_paths=rdp_chains,
                    risk_score=risk,
                    affected_nodes=affected,
                    evidence={
                        "chain_count": len(rdp_chains),
                        "rdp_host_count": len(rdp_services),
                    },
                    remediation=[
                        RemediationStep(
                            title="Implement jump servers",
                            description="Require all RDP access through hardened jump servers",
                            priority="high",
                            effort="medium",
                        ),
                        RemediationStep(
                            title="Enable NLA",
                            description="Enable Network Level Authentication for all RDP endpoints",
                            priority="medium",
                            effort="low",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1021.004: SSH ──────────────────────────────────────────

    async def _sim_ssh(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        ssh_services = [
            s
            for s in context.get("services", [])
            if s.get("port") == 22  # noqa: PLR2004
        ]
        if not ssh_services:
            return []

        paths_result = await self.graph.find_attack_paths(
            tenant_id,
            max_depth=self.sim_config.max_depth,
            max_paths=self.sim_config.max_paths,
            include_lateral=True,
        )
        lateral_chains = paths_result.get("lateral_chains", [])
        ssh_chains = [
            c for c in lateral_chains if any("ssh" in t.lower() for t in c.get("techniques", []))
        ]

        if ssh_chains:
            max_risk = max(
                (c.get("risk_score", 0) for c in ssh_chains),
                default=0.0,
            )
            risk = self._compute_risk_score(max_risk, "high")
            affected = list({s.get("host_id", s.get("id", "")) for s in ssh_services})
            findings.append(
                SimulationFinding(
                    tactic=TacticType.LATERAL_MOVEMENT,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="high",
                    title=f"{len(ssh_chains)} SSH lateral chain(s) found",
                    description=(
                        f"Detected {len(ssh_chains)} SSH lateral movement "
                        f"chain(s) across {len(ssh_services)} host(s) with "
                        f"SSH enabled."
                    ),
                    attack_paths=ssh_chains,
                    risk_score=risk,
                    affected_nodes=affected,
                    evidence={
                        "chain_count": len(ssh_chains),
                        "ssh_host_count": len(ssh_services),
                    },
                    remediation=[
                        RemediationStep(
                            title="Use SSH certificate auth",
                            description="Replace password auth with certificate-based SSH",
                            priority="high",
                            effort="medium",
                        ),
                        RemediationStep(
                            title="Implement bastion hosts",
                            description="Route all SSH through hardened bastion hosts",
                            priority="high",
                            effort="medium",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1550.002: Pass the Hash ────────────────────────────────

    async def _sim_pass_the_hash(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        for user in context.get("users", []):
            user_id = user.get("id", "")
            neighbors = await self.graph.query_neighbors(
                user_id,
                tenant_id,
                edge_types=["HAS_ACCESS"],
            )
            admin_hosts = [
                n for n in neighbors if any("admin" in p.lower() for p in n.get("permissions", []))
            ]
            if len(admin_hosts) < 2:  # noqa: PLR2004
                continue

            blast = await self.graph.compute_blast_radius(
                tenant_id,
                user_id,
            )
            blast_score = blast.get("blast_score", 0.0)
            risk = self._compute_risk_score(0.7, "critical", blast_score)
            findings.append(
                SimulationFinding(
                    tactic=TacticType.LATERAL_MOVEMENT,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="critical",
                    title=(
                        f"Pass-the-hash risk: "
                        f"{user.get('username', user_id)} "
                        f"admin on {len(admin_hosts)} hosts"
                    ),
                    description=(
                        f"User '{user.get('username', user_id)}' has admin "
                        f"access to {len(admin_hosts)} hosts. Credential "
                        f"compromise enables wide lateral movement."
                    ),
                    blast_radius=blast,
                    risk_score=risk,
                    affected_nodes=[user_id, *(h.get("id", "") for h in admin_hosts)],
                    evidence={
                        "username": user.get("username"),
                        "admin_host_count": len(admin_hosts),
                        "blast_score": blast_score,
                    },
                    remediation=[
                        RemediationStep(
                            title="Implement LAPS",
                            description="Deploy Local Administrator Password Solution",
                            priority="critical",
                            effort="medium",
                        ),
                        RemediationStep(
                            title="Enable Credential Guard",
                            description="Enable Windows Credential Guard to protect hashes",
                            priority="high",
                            effort="medium",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

    # ── T1558: Kerberos Tickets ─────────────────────────────────

    async def _sim_kerberos(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        for user in context.get("users", []):
            user_id = user.get("id", "")
            neighbors = await self.graph.query_neighbors(
                user_id,
                tenant_id,
                edge_types=["MEMBER_OF", "HAS_ACCESS"],
            )
            privileged_groups = [
                n
                for n in neighbors
                if n.get("label") == "Group"
                and any(kw in n.get("name", "").lower() for kw in ("admin", "domain", "enterprise"))
            ]
            dc_access = [
                n
                for n in neighbors
                if n.get("label") == "Host" and "dc" in (n.get("hostname", "") or "").lower()
            ]
            if privileged_groups and dc_access:
                risk = self._compute_risk_score(0.8, "critical")
                findings.append(
                    SimulationFinding(
                        tactic=TacticType.LATERAL_MOVEMENT,
                        technique_id=technique.technique_id,
                        technique_name=technique.technique_name,
                        severity="critical",
                        title=(f"Kerberos ticket risk: {user.get('username', user_id)}"),
                        description=(
                            f"User '{user.get('username', user_id)}' is in "
                            f"privileged group(s) and has access to domain "
                            f"controller(s). Kerberoasting or golden ticket "
                            f"attacks are viable."
                        ),
                        risk_score=risk,
                        affected_nodes=[
                            user_id,
                            *(h.get("id", "") for h in dc_access),
                        ],
                        evidence={
                            "username": user.get("username"),
                            "privileged_groups": [g.get("name") for g in privileged_groups],
                            "dc_count": len(dc_access),
                        },
                        remediation=[
                            RemediationStep(
                                title="Rotate KRBTGT",
                                description="Rotate the KRBTGT account password twice",
                                priority="critical",
                                effort="low",
                            ),
                            RemediationStep(
                                title="Monitor Kerberos anomalies",
                                description="Enable detection for unusual ticket requests",
                                priority="high",
                                effort="medium",
                            ),
                        ],
                        mitre_url=technique.mitre_url,
                    ),
                )
        return findings

    # ── T1482: Domain Trust Discovery ───────────────────────────

    async def _sim_domain_trust(
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
        if len(trust_edges) < 2:  # noqa: PLR2004
            return []

        # Build transitive chain: A trusts B trusts C
        trust_targets: dict[str, list[str]] = {}
        for edge in trust_edges:
            src = edge.get("source_id", "")
            tgt = edge.get("target_id", "")
            trust_targets.setdefault(src, []).append(tgt)

        transitive_count = sum(
            1 for targets in trust_targets.values() for t in targets if t in trust_targets
        )

        if transitive_count > 0:
            affected = list(
                {e.get("source_id", "") for e in trust_edges}
                | {e.get("target_id", "") for e in trust_edges}
            )
            risk = self._compute_risk_score(0.5, "medium")
            findings.append(
                SimulationFinding(
                    tactic=TacticType.LATERAL_MOVEMENT,
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    severity="medium",
                    title=(f"Transitive trust chains: {transitive_count} hop(s) detected"),
                    description=(
                        f"Found {len(trust_edges)} trust relationship(s) "
                        f"with {transitive_count} transitive hop(s). "
                        f"Attackers can traverse trust boundaries."
                    ),
                    risk_score=risk,
                    affected_nodes=affected,
                    evidence={
                        "trust_count": len(trust_edges),
                        "transitive_hops": transitive_count,
                    },
                    remediation=[
                        RemediationStep(
                            title="Enable SID filtering",
                            description="Enable SID filtering on all domain trusts",
                            priority="high",
                            effort="low",
                        ),
                        RemediationStep(
                            title="Audit trust relationships",
                            description="Review and remove unnecessary trust relationships",
                            priority="medium",
                            effort="medium",
                        ),
                    ],
                    mitre_url=technique.mitre_url,
                ),
            )
        return findings

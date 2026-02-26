"""Exfiltration adversarial simulation playbook.

Simulates: exfil over C2 (T1041), alternative protocol (T1048), web
service (T1567), cloud account transfer (T1537), and scheduled
transfer (T1029).
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


class ExfiltrationSimAgent(SimulationAgent):
    """Simulates data exfiltration techniques against the digital twin."""

    async def select_techniques(
        self,
        plan: AgentPlan,
    ) -> list[MitreTechnique]:
        all_techniques = get_techniques_for_tactic(TacticType.EXFILTRATION)
        if self.sim_config.techniques:
            return [t for t in all_techniques if t.technique_id in self.sim_config.techniques]
        return all_techniques

    async def simulate_technique(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        handlers = {
            "T1041": self._sim_t1041,
            "T1048": self._sim_t1048,
            "T1567": self._sim_t1567,
            "T1537": self._sim_t1537,
            "T1029": self._sim_t1029,
        }
        handler = handlers.get(technique.technique_id)
        if handler is None:
            return []
        return await handler(technique, context)

    # ── T1041: Exfiltration Over C2 Channel ─────────────────────

    async def _sim_t1041(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        # Find crown jewels and internet-facing nodes
        crown_jewels = [h for h in context.get("hosts", []) if h.get("criticality") == "critical"]
        internet_facing = [h for h in context.get("hosts", []) if h.get("is_internet_facing")]
        if not crown_jewels or not internet_facing:
            return []

        # Paths from crown jewels to internet exits
        paths_result = await self.graph.find_attack_paths(
            tenant_id,
            sources=[h.get("id", "") for h in crown_jewels],
            targets=[h.get("id", "") for h in internet_facing],
            max_depth=self.sim_config.max_depth,
            max_paths=self.sim_config.max_paths,
        )
        attack_paths = paths_result.get("attack_paths", [])
        if not attack_paths:
            return []

        max_risk = max(
            (p.get("risk_score", 0) for p in attack_paths),
            default=0.0,
        )
        risk = self._compute_risk_score(max_risk, "critical")
        affected = list({h.get("id", "") for h in crown_jewels})
        findings.append(
            SimulationFinding(
                tactic=TacticType.EXFILTRATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="critical",
                title=(f"{len(attack_paths)} egress path(s) from critical assets"),
                description=(
                    f"Found {len(attack_paths)} attack path(s) from "
                    f"{len(crown_jewels)} critical asset(s) to "
                    f"{len(internet_facing)} internet-facing node(s)."
                ),
                attack_paths=attack_paths,
                risk_score=risk,
                affected_nodes=affected,
                evidence={
                    "paths_count": len(attack_paths),
                    "crown_jewel_count": len(crown_jewels),
                    "exit_count": len(internet_facing),
                },
                remediation=[
                    RemediationStep(
                        title="Network segmentation",
                        description="Isolate critical assets from internet-facing segments",
                        priority="critical",
                        effort="high",
                    ),
                    RemediationStep(
                        title="Deploy DLP",
                        description="Implement data loss prevention on egress points",
                        priority="high",
                        effort="medium",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1048: Exfiltration Over Alternative Protocol ───────────

    async def _sim_t1048(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        dns_services = [
            s
            for s in context.get("services", [])
            if s.get("port") == 53  # noqa: PLR2004
        ]
        if not dns_services:
            return []

        # Check if sensitive hosts can reach DNS services
        sensitive_hosts = [
            h for h in context.get("hosts", []) if h.get("criticality") in ("critical", "high")
        ]

        reachable_from: list[str] = []
        for host in sensitive_hosts:
            host_id = host.get("id", "")
            neighbors = await self.graph.query_neighbors(
                host_id,
                tenant_id,
                edge_types=["CAN_REACH", "CONNECTS_TO"],
            )
            dns_reachable = [
                n
                for n in neighbors
                if n.get("port") == 53  # noqa: PLR2004
            ]
            if dns_reachable:
                reachable_from.append(host_id)

        if not reachable_from:
            return []

        risk = self._compute_risk_score(0.5, "high")
        findings.append(
            SimulationFinding(
                tactic=TacticType.EXFILTRATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="high",
                title=(f"DNS exfiltration path from {len(reachable_from)} sensitive host(s)"),
                description=(
                    f"{len(reachable_from)} sensitive host(s) can reach "
                    f"DNS services, enabling potential DNS tunneling "
                    f"exfiltration."
                ),
                risk_score=risk,
                affected_nodes=reachable_from,
                evidence={
                    "dns_service_count": len(dns_services),
                    "reachable_host_count": len(reachable_from),
                },
                remediation=[
                    RemediationStep(
                        title="Restrict DNS resolvers",
                        description="Limit outbound DNS to approved internal resolvers only",
                        priority="high",
                        effort="low",
                    ),
                    RemediationStep(
                        title="DNS monitoring",
                        description="Deploy DNS query monitoring for anomalous patterns",
                        priority="medium",
                        effort="medium",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1567: Exfiltration Over Web Service ────────────────────

    async def _sim_t1567(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        # Find cloud storage / web service applications
        apps = await self.graph.query_nodes(
            "Application",
            tenant_id,
            limit=200,
        )
        cloud_apps = [a for a in apps if a.get("app_type") in ("database", "web_app")]
        if not cloud_apps:
            return []

        sensitive_hosts = [
            h for h in context.get("hosts", []) if h.get("criticality") in ("critical", "high")
        ]
        reachable_apps: list[str] = []
        for host in sensitive_hosts:
            host_id = host.get("id", "")
            neighbors = await self.graph.query_neighbors(
                host_id,
                tenant_id,
                edge_types=["CAN_REACH", "DEPENDS_ON"],
            )
            for n in neighbors:
                if n.get("id") in {a.get("id") for a in cloud_apps}:
                    reachable_apps.append(n.get("id", ""))

        if not reachable_apps:
            return []

        unique_apps = list(set(reachable_apps))
        risk = self._compute_risk_score(0.5, "high")
        findings.append(
            SimulationFinding(
                tactic=TacticType.EXFILTRATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="high",
                title=(f"{len(unique_apps)} cloud service(s) reachable from sensitive hosts"),
                description=(
                    f"Sensitive hosts can reach {len(unique_apps)} cloud "
                    f"application(s), enabling data exfiltration to web "
                    f"services."
                ),
                risk_score=risk,
                affected_nodes=unique_apps,
                evidence={
                    "cloud_app_count": len(unique_apps),
                    "sensitive_host_count": len(sensitive_hosts),
                },
                remediation=[
                    RemediationStep(
                        title="Implement CASB",
                        description=(
                            "Deploy cloud access security broker to control cloud service access"
                        ),
                        priority="high",
                        effort="high",
                    ),
                    RemediationStep(
                        title="Block unauthorized cloud storage",
                        description="Restrict access to unapproved cloud storage services",
                        priority="high",
                        effort="medium",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1537: Transfer Data to Cloud Account ───────────────────

    async def _sim_t1537(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        apps = await self.graph.query_nodes(
            "Application",
            tenant_id,
            limit=200,
        )
        storage_apps = [a for a in apps if a.get("app_type") == "database"]
        if not storage_apps:
            return []

        # Check who has access to cloud storage
        accessible_by: list[str] = []
        for app in storage_apps:
            app_id = app.get("id", "")
            neighbors = await self.graph.query_neighbors(
                app_id,
                tenant_id,
                edge_types=["HAS_ACCESS"],
            )
            accessible_by.extend(n.get("id", "") for n in neighbors)

        if not accessible_by:
            return []

        unique_accessors = list(set(accessible_by))
        risk = self._compute_risk_score(0.5, "high")
        findings.append(
            SimulationFinding(
                tactic=TacticType.EXFILTRATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="high",
                title=(f"{len(unique_accessors)} entity(ies) can access cloud storage"),
                description=(
                    f"{len(unique_accessors)} user(s)/service(s) have "
                    f"direct access to {len(storage_apps)} cloud storage "
                    f"application(s)."
                ),
                risk_score=risk,
                affected_nodes=[a.get("id", "") for a in storage_apps],
                evidence={
                    "storage_app_count": len(storage_apps),
                    "accessor_count": len(unique_accessors),
                },
                remediation=[
                    RemediationStep(
                        title="Enforce cloud storage policies",
                        description="Implement access policies on all cloud storage resources",
                        priority="high",
                        effort="medium",
                    ),
                    RemediationStep(
                        title="Enable access logging",
                        description="Enable detailed logging on all cloud storage access",
                        priority="medium",
                        effort="low",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

    # ── T1029: Scheduled Transfer ───────────────────────────────

    async def _sim_t1029(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        findings: list[SimulationFinding] = []
        tenant_id = context["tenant_id"]

        # Find scheduler/daemon services
        scheduler_services = [
            s
            for s in context.get("services", [])
            if any(
                kw in (s.get("name", "") or "").lower()
                for kw in ("cron", "scheduler", "task", "daemon")
            )
        ]
        if not scheduler_services:
            return []

        # Check if schedulers can reach external hosts
        schedulers_with_egress: list[dict[str, Any]] = []
        for svc in scheduler_services:
            host_id = svc.get("host_id", svc.get("id", ""))
            neighbors = await self.graph.query_neighbors(
                host_id,
                tenant_id,
                edge_types=["CAN_REACH", "CONNECTS_TO"],
            )
            external = [n for n in neighbors if n.get("is_internet_facing")]
            if external:
                schedulers_with_egress.append(
                    {
                        "service": svc.get("name", "unknown"),
                        "host_id": host_id,
                        "external_count": len(external),
                    }
                )

        if not schedulers_with_egress:
            return []

        affected = [s["host_id"] for s in schedulers_with_egress]
        risk = self._compute_risk_score(0.4, "medium")
        findings.append(
            SimulationFinding(
                tactic=TacticType.EXFILTRATION,
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                severity="medium",
                title=(f"{len(schedulers_with_egress)} scheduler(s) with external reach"),
                description=(
                    f"Found {len(schedulers_with_egress)} scheduler "
                    f"service(s) that can reach external hosts, enabling "
                    f"automated data exfiltration."
                ),
                risk_score=risk,
                affected_nodes=affected,
                evidence={
                    "schedulers": schedulers_with_egress,
                },
                remediation=[
                    RemediationStep(
                        title="Audit scheduled tasks",
                        description="Review all scheduled tasks for unauthorized data transfers",
                        priority="medium",
                        effort="medium",
                    ),
                    RemediationStep(
                        title="Restrict outbound connectivity",
                        description="Block outbound connections from scheduler hosts",
                        priority="medium",
                        effort="low",
                    ),
                ],
                mitre_url=technique.mitre_url,
            ),
        )
        return findings

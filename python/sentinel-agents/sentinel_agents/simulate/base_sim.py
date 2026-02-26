"""SimulationAgent base class for adversarial simulation.

Extends BaseAgent with read-only graph access and MITRE ATT&CK
technique-driven simulation. Subclasses implement ``select_techniques``
and ``simulate_technique``.
"""

from __future__ import annotations

import logging
import time
from abc import abstractmethod
from typing import TYPE_CHECKING, Any

from sentinel_agents.base import BaseAgent
from sentinel_agents.hunt.base_hunt import HuntAgent  # noqa: F401 — sibling pattern
from sentinel_agents.simulate.models import (
    GraphProtocol,
    SimConfig,
    SimulationFinding,
    SimulationResult,
)
from sentinel_agents.types import AgentPlan, AgentResult, AgentStatus, Finding

if TYPE_CHECKING:
    from sentinel_policy.engine import PolicyEngine

    from sentinel_agents.llm import LLMProvider
    from sentinel_agents.simulate.mitre import MitreTechnique
    from sentinel_agents.tools import ToolRegistry

logger = logging.getLogger(__name__)


class SimulationAgent(BaseAgent):
    """Base class for adversarial simulation agents.

    All simulations are read-only — they query the graph/pathfind engine
    and never modify the digital twin.
    """

    def __init__(
        self,
        config: Any,
        llm: LLMProvider,
        tool_registry: ToolRegistry,
        graph: GraphProtocol,
        sim_config: SimConfig,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        super().__init__(config, llm, tool_registry, policy_engine)
        self.graph = graph
        self.sim_config = sim_config

    # ── Abstract methods ────────────────────────────────────────

    @abstractmethod
    async def select_techniques(
        self,
        plan: AgentPlan,
    ) -> list[MitreTechnique]:
        """Select which MITRE techniques to simulate."""

    @abstractmethod
    async def simulate_technique(
        self,
        technique: MitreTechnique,
        context: dict[str, Any],
    ) -> list[SimulationFinding]:
        """Simulate a single technique against the graph (read-only)."""

    # ── Lifecycle ───────────────────────────────────────────────

    async def plan(
        self,
        intent: str,
        context: dict[str, Any],
    ) -> AgentPlan:
        from sentinel_agents.llm import LLMMessage

        prompt = (
            f"Simulation intent: {intent}\n"
            f"Tactic: {self.sim_config.tactic.value}\n"
            f"Techniques filter: {self.sim_config.techniques or 'all'}\n"
            f"Context: {context}\n\n"
            "Produce a structured simulation plan."
        )
        return await self.llm.complete_structured(
            messages=[LLMMessage(role="user", content=prompt)],
            response_model=AgentPlan,
            system=(
                "You are a red team simulation planner. Produce a plan for "
                "testing MITRE ATT&CK techniques against a network knowledge "
                "graph. This is read-only — no live attacks."
            ),
        )

    async def execute(self, plan: AgentPlan) -> AgentResult:
        start_time = time.monotonic()

        techniques = await self.select_techniques(plan)
        graph_context = await self._build_graph_context()

        all_findings: list[SimulationFinding] = []
        techniques_with_findings = 0

        for technique in techniques:
            if self.is_cancelled:
                break

            findings = await self.simulate_technique(technique, graph_context)
            if findings:
                techniques_with_findings += 1
                all_findings.extend(findings)

            if self._session is not None:
                self._session.add_action(
                    action_type=f"simulate_{technique.technique_id}",
                    description=(
                        f"Simulated {technique.technique_id} "
                        f"({technique.technique_name}): "
                        f"{len(findings)} findings"
                    ),
                    details={
                        "technique_id": technique.technique_id,
                        "findings_count": len(findings),
                    },
                    success=True,
                )

        summary = await self._generate_summary(all_findings, techniques)
        elapsed = time.monotonic() - start_time
        highest_risk = max(
            (f.risk_score for f in all_findings),
            default=0.0,
        )

        # Store full simulation result in first finding's evidence
        _sim_result = SimulationResult(
            tactic=self.sim_config.tactic,
            config=self.sim_config,
            findings=all_findings,
            techniques_tested=len(techniques),
            techniques_with_findings=techniques_with_findings,
            highest_risk_score=highest_risk,
            duration_seconds=round(elapsed, 2),
            summary=summary,
        )

        agent_findings = self._to_agent_findings(all_findings)

        return AgentResult(
            agent_id=self.config.agent_id,
            agent_type=self.config.agent_type,
            tenant_id=self.config.tenant_id,
            status=AgentStatus.RUNNING,
            findings=agent_findings,
            actions_taken=len(techniques),
            started_at=self._session._engram.started_at
            if self._session
            else __import__("datetime").datetime.now(
                tz=__import__("datetime").timezone.utc,
            ),
        )

    # ── Helpers ─────────────────────────────────────────────────

    async def _build_graph_context(self) -> dict[str, Any]:
        """Gather high-level graph topology for simulations."""
        tenant_id = str(self.config.tenant_id)
        hosts = await self.graph.query_nodes("Host", tenant_id, limit=500)
        users = await self.graph.query_nodes("User", tenant_id, limit=500)
        services = await self.graph.query_nodes(
            "Service",
            tenant_id,
            limit=500,
        )
        vulnerabilities = await self.graph.query_nodes(
            "Vulnerability",
            tenant_id,
            limit=500,
        )
        return {
            "hosts": hosts,
            "users": users,
            "services": services,
            "vulnerabilities": vulnerabilities,
            "tenant_id": tenant_id,
        }

    async def _generate_summary(
        self,
        findings: list[SimulationFinding],
        techniques: list[MitreTechnique],
    ) -> str:
        from sentinel_agents.llm import LLMMessage

        if not findings:
            return (
                f"No findings from {len(techniques)} "
                f"{self.sim_config.tactic.value} technique(s) tested."
            )

        finding_lines = "\n".join(
            f"- [{f.severity.upper()}] {f.technique_id} {f.title}" for f in findings
        )
        prompt = (
            f"Summarize adversarial simulation results for "
            f"{self.sim_config.tactic.value}.\n"
            f"Techniques tested: {len(techniques)}\n"
            f"Findings ({len(findings)}):\n{finding_lines}\n\n"
            "Provide a concise red-team assessment for a CISO briefing."
        )
        response = await self.llm.complete(
            messages=[LLMMessage(role="user", content=prompt)],
            system="You are a senior red team operator.",
            max_tokens=512,
        )
        return response.content

    @staticmethod
    def _to_agent_findings(
        sim_findings: list[SimulationFinding],
    ) -> list[Finding]:
        return [
            Finding(
                id=sf.id,
                severity=sf.severity,
                title=sf.title,
                description=sf.description,
                evidence={
                    "tactic": sf.tactic.value,
                    "technique_id": sf.technique_id,
                    "technique_name": sf.technique_name,
                    "risk_score": sf.risk_score,
                    "attack_paths_count": len(sf.attack_paths),
                    "affected_nodes": sf.affected_nodes,
                    "mitre_url": sf.mitre_url,
                    "remediation": [r.model_dump() for r in sf.remediation],
                    **sf.evidence,
                },
                recommendations=[r.title for r in sf.remediation],
            )
            for sf in sim_findings
        ]

    @staticmethod
    def _compute_risk_score(
        path_risk: float,
        severity: str,
        blast_score: float = 0.0,
    ) -> float:
        """Compute a 0-10 risk score from components."""
        severity_multipliers = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
        }
        sev_mult = severity_multipliers.get(severity, 0.5)
        score = (path_risk * 5.0) + (sev_mult * 2.5) + (blast_score * 2.5)
        return min(score, 10.0)

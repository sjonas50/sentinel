"""Base class for all threat hunt agents."""

from __future__ import annotations

import logging
import time
from abc import abstractmethod
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sentinel_agents.base import BaseAgent
from sentinel_agents.hunt.models import (
    HuntConfig,
    HuntFinding,
    PlaybookResult,
    SiemProtocol,
)
from sentinel_agents.hunt.sigma import SigmaGenerator
from sentinel_agents.types import AgentPlan, AgentResult, AgentStatus, Finding

if TYPE_CHECKING:
    from sentinel_policy.engine import PolicyEngine

    from sentinel_agents.llm import LLMProvider
    from sentinel_agents.tools import ToolRegistry

logger = logging.getLogger(__name__)


class HuntAgent(BaseAgent):
    """Base class for threat hunt playbook agents.

    Extends ``BaseAgent`` with SIEM integration, hunt configuration,
    and Sigma rule generation. Subclasses implement ``build_queries``
    and ``analyze_results`` for their specific hunting logic.
    """

    def __init__(
        self,
        config: Any,  # AgentConfig
        llm: LLMProvider,
        tool_registry: ToolRegistry,
        siem: SiemProtocol,
        hunt_config: HuntConfig,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        super().__init__(config, llm, tool_registry, policy_engine)
        self.siem = siem
        self.hunt_config = hunt_config
        self._sigma_gen = SigmaGenerator()

    @property
    def time_range(self) -> tuple[datetime, datetime]:
        """Compute the time window for this hunt based on config."""
        end = datetime.now(UTC)
        start = end - timedelta(hours=self.hunt_config.time_window_hours)
        return (start, end)

    # ── Abstract methods for subclasses ──────────────────────────

    @abstractmethod
    async def build_queries(self, plan: AgentPlan) -> list[tuple[str, dict[str, Any], str]]:
        """Build the SIEM queries for this playbook.

        Returns:
            List of ``(query_name, query_dsl, index_pattern)`` tuples.
        """

    @abstractmethod
    async def analyze_results(self, query_results: dict[str, Any]) -> list[HuntFinding]:
        """Analyze query results and produce findings.

        Args:
            query_results: Map of query_name -> query result object.
        """

    # ── BaseAgent lifecycle implementation ───────────────────────

    async def plan(self, intent: str, context: dict[str, Any]) -> AgentPlan:
        """Use LLM to produce a hunt plan based on the intent and config."""
        from sentinel_agents.llm import LLMMessage

        system_prompt = (
            "You are a threat hunting expert. Given a hunting intent and "
            "configuration, produce a structured plan. Include which data "
            "sources to query, what patterns to look for, and in what order."
        )
        user_prompt = (
            f"Hunt intent: {intent}\n"
            f"Playbook: {self.hunt_config.playbook.value}\n"
            f"Time window: {self.hunt_config.time_window_hours} hours\n"
            f"Index pattern: {self.hunt_config.index_pattern}\n"
            f"Config: {self.hunt_config.model_dump_json()}\n"
            f"Context: {context}"
        )

        return await self.llm.complete_structured(
            messages=[LLMMessage(role="user", content=user_prompt)],
            response_model=AgentPlan,
            system=system_prompt,
        )

    async def execute(self, plan: AgentPlan) -> AgentResult:
        """Execute the hunt: run queries, analyze, generate Sigma rules."""
        start_time = time.monotonic()

        # Build programmatic queries (subclass-specific)
        queries = await self.build_queries(plan)

        # Execute all queries against SIEM
        query_results: dict[str, Any] = {}
        total_events = 0
        for query_name, query_dsl, index_pattern in queries:
            if self.is_cancelled:
                break
            result = await self.siem.execute_query(
                query_dsl=query_dsl,
                index=index_pattern or self.hunt_config.index_pattern,
                size=self.hunt_config.max_results_per_query,
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            query_results[query_name] = result
            total_events += result.total_hits

            if self._session is not None:
                self._session.add_action(
                    action_type=f"siem_query_{query_name}",
                    description=(f"Executed query '{query_name}': {result.total_hits} hits"),
                    details={
                        "query_dsl": query_dsl,
                        "total_hits": result.total_hits,
                    },
                    success=True,
                )

        # Analyze results (subclass-specific, may use LLM)
        hunt_findings = await self.analyze_results(query_results)

        # Generate Sigma rules for findings
        sigma_rules = []
        if self.hunt_config.generate_sigma_rules:
            for finding in hunt_findings:
                rule = self._sigma_gen.from_finding(finding)
                if rule is not None:
                    sigma_rules.append(rule)
                    finding.sigma_rule = rule

        # LLM summary
        summary = await self._generate_summary(hunt_findings, total_events)

        elapsed = time.monotonic() - start_time

        # Build PlaybookResult (stored in evidence of the AgentResult)
        _playbook_result = PlaybookResult(
            playbook=self.hunt_config.playbook,
            config=self.hunt_config,
            findings=hunt_findings,
            sigma_rules=sigma_rules,
            queries_executed=len(queries),
            events_analyzed=total_events,
            duration_seconds=round(elapsed, 2),
            summary=summary,
        )

        # Convert HuntFindings to agent-level Findings
        agent_findings = [
            Finding(
                id=hf.id,
                severity=hf.severity,
                title=hf.title,
                description=hf.description,
                evidence={
                    **hf.evidence,
                    "playbook": hf.playbook.value,
                    "affected_hosts": hf.affected_hosts,
                    "affected_users": hf.affected_users,
                    "mitre_technique_ids": hf.mitre_technique_ids,
                    "mitre_tactic": hf.mitre_tactic,
                    "sigma_yaml": (hf.sigma_rule.to_yaml() if hf.sigma_rule else None),
                },
                recommendations=hf.recommendations,
            )
            for hf in hunt_findings
        ]

        return AgentResult(
            agent_id=self.config.agent_id,
            agent_type=self.config.agent_type,
            tenant_id=self.config.tenant_id,
            status=AgentStatus.RUNNING,
            findings=agent_findings,
            actions_taken=len(queries),
        )

    # ── Private helpers ──────────────────────────────────────────

    async def _generate_summary(self, findings: list[HuntFinding], total_events: int) -> str:
        """Use LLM to generate a human-readable summary of hunt results."""
        from sentinel_agents.llm import LLMMessage

        finding_descriptions = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description}" for f in findings
        )
        prompt = (
            f"Summarize the results of a {self.hunt_config.playbook.value} "
            f"threat hunt.\nEvents analyzed: {total_events}\n"
            f"Findings ({len(findings)}):\n{finding_descriptions}\n\n"
            "Provide a concise 2-3 sentence summary suitable for a SOC analyst."
        )
        response = await self.llm.complete(
            messages=[LLMMessage(role="user", content=prompt)],
            max_tokens=256,
        )
        return response.content

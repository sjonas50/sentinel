"""Sigma detection rule generator from hunt findings."""

from __future__ import annotations

from typing import Any

from sentinel_agents.hunt.models import (
    HuntFinding,
    PlaybookType,
    SigmaDetection,
    SigmaRule,
)


class SigmaGenerator:
    """Converts hunt findings into Sigma detection rules.

    Dispatches to playbook-specific rule builders based on the
    finding's playbook type. Each builder extracts evidence fields
    and constructs detection logic appropriate to the threat category.
    """

    def from_finding(self, finding: HuntFinding) -> SigmaRule | None:
        """Generate a Sigma rule from a hunt finding.

        Returns ``None`` if the finding's playbook type has no handler
        or if evidence is insufficient.
        """
        handler = self._PLAYBOOK_HANDLERS.get(finding.playbook)
        if handler is None:
            return None
        return handler(self, finding)

    # ── Playbook-specific builders ───────────────────────────────

    def _credential_abuse_rule(self, finding: HuntFinding) -> SigmaRule:
        evidence = finding.evidence
        selection: dict[str, Any] = {
            "event.outcome": "failure",
            "event.category": "authentication",
        }
        if "source_ips" in evidence:
            selection["source.ip"] = evidence["source_ips"]
        if "target_users" in evidence:
            selection["user.name"] = evidence["target_users"]
        if "event_ids" in evidence:
            selection["event.code"] = evidence["event_ids"]

        tags = ["attack.credential_access"]
        for tid in finding.mitre_technique_ids:
            tags.append(f"attack.{tid.lower()}")

        return SigmaRule(
            title=finding.title,
            description=finding.description,
            tags=tags,
            logsource={"category": "authentication", "product": "windows"},
            detection=SigmaDetection(selection=selection, condition="selection"),
            level=self._severity_to_level(finding.severity),
            falsepositives=["Legitimate account lockout due to password change"],
        )

    def _lateral_movement_rule(self, finding: HuntFinding) -> SigmaRule:
        evidence = finding.evidence
        selection: dict[str, Any] = {}
        if "source_hosts" in evidence:
            selection["source.ip"] = evidence["source_hosts"]
        if "dest_hosts" in evidence:
            selection["destination.ip"] = evidence["dest_hosts"]
        if "dest_ports" in evidence:
            selection["destination.port"] = evidence["dest_ports"]
        else:
            selection["destination.port"] = [3389, 445, 5985]

        tags = ["attack.lateral_movement"]
        for tid in finding.mitre_technique_ids:
            tags.append(f"attack.{tid.lower()}")

        return SigmaRule(
            title=finding.title,
            description=finding.description,
            tags=tags,
            logsource={"category": "network_connection", "product": "any"},
            detection=SigmaDetection(selection=selection, condition="selection"),
            level=self._severity_to_level(finding.severity),
            falsepositives=["Legitimate system administration via RDP or WinRM"],
        )

    def _data_exfiltration_rule(self, finding: HuntFinding) -> SigmaRule:
        evidence = finding.evidence
        selection: dict[str, Any] = {}
        if "dest_ips" in evidence:
            selection["destination.ip"] = evidence["dest_ips"]
        if "dest_ports" in evidence:
            selection["destination.port"] = evidence["dest_ports"]
        if "dns_queries" in evidence:
            selection["dns.question.name|contains"] = evidence["dns_queries"]

        tags = ["attack.exfiltration"]
        for tid in finding.mitre_technique_ids:
            tags.append(f"attack.{tid.lower()}")

        return SigmaRule(
            title=finding.title,
            description=finding.description,
            tags=tags,
            logsource={"category": "network_connection", "product": "any"},
            detection=SigmaDetection(selection=selection, condition="selection"),
            level=self._severity_to_level(finding.severity),
            falsepositives=["Large legitimate file transfers", "Backup operations"],
        )

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _severity_to_level(severity: str) -> str:
        """Map finding severity to Sigma level."""
        return {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "informational",
        }.get(severity, "medium")

    _PLAYBOOK_HANDLERS = {
        PlaybookType.CREDENTIAL_ABUSE: _credential_abuse_rule,
        PlaybookType.LATERAL_MOVEMENT: _lateral_movement_rule,
        PlaybookType.DATA_EXFILTRATION: _data_exfiltration_rule,
    }

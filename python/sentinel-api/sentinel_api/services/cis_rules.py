"""CIS Benchmark rules engine — Python rule definitions for configuration audit.

Each rule is a callable class implementing the CisRule protocol. Rules are
registered in a global registry keyed by rule_id and can be filtered by
cloud provider, section, and severity.
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class CloudTarget(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ANY = "any"


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata describing a single CIS benchmark rule."""

    rule_id: str
    title: str
    section: str
    severity: str
    cloud: CloudTarget
    resource_types: list[str]
    remediation: str
    benchmark: str = "CIS AWS Foundations Benchmark v2.0"


@dataclass
class RuleFinding:
    """A single finding produced by a rule evaluation."""

    rule_id: str
    severity: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)


class CisRule(ABC):
    """Abstract base for a CIS benchmark rule."""

    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata: ...

    @abstractmethod
    def evaluate(self, resource: dict[str, Any]) -> list[RuleFinding]:
        """Evaluate a resource dict (from Neo4j node properties).

        Returns an empty list if the resource is compliant,
        or one or more RuleFinding objects if violations are detected.
        """
        ...


# ── Rule Registry ─────────────────────────────────────────────

_RULE_REGISTRY: dict[str, CisRule] = {}


def register_rule(cls: type[CisRule]) -> type[CisRule]:
    """Class decorator: instantiate and register a rule."""
    instance = cls()
    _RULE_REGISTRY[instance.metadata.rule_id] = instance
    return cls


def get_rules(
    cloud: CloudTarget | None = None,
    resource_type: str | None = None,
) -> list[CisRule]:
    """Get all registered rules, optionally filtered."""
    rules = list(_RULE_REGISTRY.values())
    if cloud is not None:
        rules = [
            r
            for r in rules
            if r.metadata.cloud in (cloud, CloudTarget.ANY)
        ]
    if resource_type is not None:
        rules = [
            r
            for r in rules
            if resource_type in r.metadata.resource_types
        ]
    return rules


def get_rule(rule_id: str) -> CisRule | None:
    return _RULE_REGISTRY.get(rule_id)


# ── Helpers ───────────────────────────────────────────────────


def _parse_rules_json(raw: str | None) -> Any:
    """Safely parse the rules_json field from a Policy node."""
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        import ast

        try:
            return ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            return []


def config_hash(data: Any) -> str:
    """Compute a SHA-256 content hash for configuration data."""
    canonical = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── AWS CIS v2.0 Rules ──────────────────────────────────────

# -- Section 2.1: S3 ------------------------------------------------


@register_rule
class CisAwsS3PublicAccess(CisRule):
    """CIS AWS 2.1.4 — Ensure S3 bucket public access is blocked."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-2.1.4",
            title="S3 bucket should block public access",
            section="2.1 Simple Storage Service (S3)",
            severity="critical",
            cloud=CloudTarget.AWS,
            resource_types=["Application"],
            remediation=(
                "Enable S3 Block Public Access at the account"
                " and/or bucket level."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        name = resource.get("name", "")
        if not name:
            return []
        public_block = resource.get("public_access_block")
        if public_block is None:
            return [
                RuleFinding(
                    rule_id=self.metadata.rule_id,
                    severity=self.metadata.severity,
                    title=self.metadata.title,
                    description=(
                        f"S3 bucket '{name}' does not have public"
                        " access block configured."
                    ),
                    resource_id=resource.get("id", ""),
                    resource_type="Application",
                    remediation=self.metadata.remediation,
                    details={"bucket_name": name},
                )
            ]
        return []


# -- Section 5: Networking ------------------------------------------


@register_rule
class CisAwsSgOpenSsh(CisRule):
    """CIS AWS 5.2 — No SG allows ingress from 0.0.0.0/0 to port 22."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-5.2",
            title="Security group should not allow unrestricted SSH",
            section="5. Networking",
            severity="high",
            cloud=CloudTarget.AWS,
            resource_types=["Policy"],
            remediation=(
                "Restrict SSH (port 22) access to specific"
                " trusted IP ranges."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        if resource.get("policy_type") != "security_group":
            return []
        rules = _parse_rules_json(resource.get("rules_json"))
        findings: list[RuleFinding] = []
        for rule in rules:
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 0)
            if from_port <= 22 <= to_port:
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        findings.append(
                            RuleFinding(
                                rule_id=self.metadata.rule_id,
                                severity=self.metadata.severity,
                                title=self.metadata.title,
                                description=(
                                    f"Security group"
                                    f" '{resource.get('name', '')}'"
                                    " allows SSH (port 22)"
                                    " from 0.0.0.0/0."
                                ),
                                resource_id=resource.get("id", ""),
                                resource_type="Policy",
                                remediation=self.metadata.remediation,
                                details={
                                    "cidr": cidr,
                                    "port": 22,
                                    "sg_name": resource.get(
                                        "name", ""
                                    ),
                                },
                            )
                        )
        return findings


@register_rule
class CisAwsSgOpenRdp(CisRule):
    """CIS AWS 5.3 — No SG allows ingress from 0.0.0.0/0 to port 3389."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-5.3",
            title="Security group should not allow unrestricted RDP",
            section="5. Networking",
            severity="high",
            cloud=CloudTarget.AWS,
            resource_types=["Policy"],
            remediation=(
                "Restrict RDP (port 3389) access to specific"
                " trusted IP ranges."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        if resource.get("policy_type") != "security_group":
            return []
        rules = _parse_rules_json(resource.get("rules_json"))
        findings: list[RuleFinding] = []
        for rule in rules:
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 0)
            if from_port <= 3389 <= to_port:
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        findings.append(
                            RuleFinding(
                                rule_id=self.metadata.rule_id,
                                severity=self.metadata.severity,
                                title=self.metadata.title,
                                description=(
                                    f"Security group"
                                    f" '{resource.get('name', '')}'"
                                    " allows RDP (port 3389)"
                                    " from 0.0.0.0/0."
                                ),
                                resource_id=resource.get("id", ""),
                                resource_type="Policy",
                                remediation=self.metadata.remediation,
                                details={
                                    "cidr": cidr,
                                    "port": 3389,
                                },
                            )
                        )
        return findings


@register_rule
class CisAwsSgUnrestrictedIngress(CisRule):
    """CIS AWS 5.4 — No SG allows all-port ingress from 0.0.0.0/0."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-5.4",
            title=(
                "Security group should not allow unrestricted"
                " all-traffic ingress"
            ),
            section="5. Networking",
            severity="critical",
            cloud=CloudTarget.AWS,
            resource_types=["Policy"],
            remediation=(
                "Remove rules allowing 0.0.0.0/0 on all ports."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        if resource.get("policy_type") != "security_group":
            return []
        rules = _parse_rules_json(resource.get("rules_json"))
        findings: list[RuleFinding] = []
        for rule in rules:
            ip_protocol = rule.get("IpProtocol", "")
            if ip_protocol == "-1":  # All traffic
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        findings.append(
                            RuleFinding(
                                rule_id=self.metadata.rule_id,
                                severity=self.metadata.severity,
                                title=self.metadata.title,
                                description=(
                                    f"Security group"
                                    f" '{resource.get('name', '')}'"
                                    " allows all traffic"
                                    " from 0.0.0.0/0."
                                ),
                                resource_id=resource.get("id", ""),
                                resource_type="Policy",
                                remediation=self.metadata.remediation,
                                details={
                                    "sg_name": resource.get(
                                        "name", ""
                                    ),
                                },
                            )
                        )
        return findings


# -- Section 1: IAM ------------------------------------------------


@register_rule
class CisAwsIamWildcardPolicy(CisRule):
    """CIS AWS 1.16 — IAM policies should not use wildcard (*)."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-1.16",
            title="IAM policy should not have wildcard permissions",
            section="1. Identity and Access Management",
            severity="high",
            cloud=CloudTarget.AWS,
            resource_types=["Policy"],
            remediation=(
                "Replace wildcard (*) actions and resources"
                " with specific least-privilege permissions."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        if resource.get("policy_type") != "iam_policy":
            return []
        rules = _parse_rules_json(resource.get("rules_json"))
        findings: list[RuleFinding] = []
        statements = (
            rules
            if isinstance(rules, list)
            else rules.get("Statement", [])
            if isinstance(rules, dict)
            else []
        )
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if effect == "Allow" and (
                "*" in actions or "*" in resources
            ):
                findings.append(
                    RuleFinding(
                        rule_id=self.metadata.rule_id,
                        severity=self.metadata.severity,
                        title=self.metadata.title,
                        description=(
                            f"IAM policy '{resource.get('name', '')}'"
                            " contains a statement with wildcard"
                            f" permissions (Action: {actions},"
                            f" Resource: {resources})."
                        ),
                        resource_id=resource.get("id", ""),
                        resource_type="Policy",
                        remediation=self.metadata.remediation,
                        details={
                            "actions": actions,
                            "resources": resources,
                            "effect": effect,
                        },
                    )
                )
        return findings


@register_rule
class CisAwsIamMfaEnabled(CisRule):
    """CIS AWS 1.4 — MFA should be enabled for IAM users."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-1.4",
            title="MFA should be enabled for all IAM users",
            section="1. Identity and Access Management",
            severity="critical",
            cloud=CloudTarget.AWS,
            resource_types=["User"],
            remediation=(
                "Enable MFA for all IAM users, especially those"
                " with console access."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        source = resource.get("source", "")
        if source != "aws_iam":
            return []
        mfa_enabled = resource.get("mfa_enabled")
        if mfa_enabled is False or mfa_enabled is None:
            return [
                RuleFinding(
                    rule_id=self.metadata.rule_id,
                    severity=self.metadata.severity,
                    title=self.metadata.title,
                    description=(
                        f"IAM user '{resource.get('username', '')}'"
                        " does not have MFA enabled."
                    ),
                    resource_id=resource.get("id", ""),
                    resource_type="User",
                    remediation=self.metadata.remediation,
                    details={
                        "username": resource.get("username", ""),
                        "mfa_enabled": mfa_enabled,
                    },
                )
            ]
        return []


# -- Section 2.3: RDS -----------------------------------------------


@register_rule
class CisAwsEncryptionAtRest(CisRule):
    """CIS AWS 2.3.1 — RDS instances should have encryption at rest."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="cis-aws-2.0-2.3.1",
            title=(
                "RDS instances should have encryption"
                " at rest enabled"
            ),
            section="2.3 Relational Database Service (RDS)",
            severity="high",
            cloud=CloudTarget.AWS,
            resource_types=["Service"],
            remediation=(
                "Enable encryption at rest for all RDS instances."
            ),
        )

    def evaluate(
        self, resource: dict[str, Any]
    ) -> list[RuleFinding]:
        name = resource.get("name", "")
        encrypted = resource.get("storage_encrypted")
        if encrypted is False:
            return [
                RuleFinding(
                    rule_id=self.metadata.rule_id,
                    severity=self.metadata.severity,
                    title=self.metadata.title,
                    description=(
                        f"RDS instance '{name}' does not have"
                        " encryption at rest enabled."
                    ),
                    resource_id=resource.get("id", ""),
                    resource_type="Service",
                    remediation=self.metadata.remediation,
                    details={"rds_name": name},
                )
            ]
        return []

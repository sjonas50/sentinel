"""Configuration Auditor service.

Orchestrates CIS benchmark rule evaluation against discovered assets
in the Neo4j knowledge graph. Writes Finding nodes with HAS_FINDING
edges to the affected resources.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

from sentinel_api.engram.session import EngramSession
from sentinel_api.models.core import FindingStatus
from sentinel_api.services.cis_rules import (
    CloudTarget,
    RuleFinding,
    config_hash,
    get_rules,
)

if TYPE_CHECKING:
    from uuid import UUID

    import neo4j

logger = logging.getLogger(__name__)

AUDITABLE_LABELS = [
    "Policy",
    "User",
    "Host",
    "Service",
    "Application",
]


class AuditResult(BaseModel):
    """Summary of a configuration audit run."""

    resources_scanned: int = 0
    rules_evaluated: int = 0
    findings_created: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    config_drifts: int = 0
    errors: list[str] = Field(default_factory=list)


class ConfigAuditor:
    """Runs CIS benchmark checks against assets in the graph."""

    def __init__(self, neo4j_driver: neo4j.AsyncDriver) -> None:
        self._driver = neo4j_driver

    async def audit_tenant(
        self,
        tenant_id: UUID,
        cloud: CloudTarget | None = None,
    ) -> AuditResult:
        """Run a full audit for a tenant."""
        return await self._audit(
            tenant_id, asset_id=None, cloud=cloud
        )

    async def audit_asset(
        self, tenant_id: UUID, asset_id: str
    ) -> AuditResult:
        """Run audit rules against a single asset."""
        return await self._audit(
            tenant_id, asset_id=asset_id, cloud=None
        )

    async def _audit(
        self,
        tenant_id: UUID,
        asset_id: str | None,
        cloud: CloudTarget | None,
    ) -> AuditResult:
        """Core audit logic."""
        session = EngramSession(
            tenant_id=tenant_id,
            agent_id="config-auditor",
            intent="Audit configuration against CIS benchmarks",
        )
        result = AuditResult()

        try:
            resources = await self._fetch_resources(
                tenant_id, asset_id
            )
            result.resources_scanned = len(resources)
            session.set_context({
                "tenant_id": str(tenant_id),
                "resource_count": len(resources),
                "asset_id": asset_id,
            })

            if not resources:
                session.add_action(
                    "no_resources",
                    "No auditable resources found",
                    success=True,
                )
                return result

            rules = get_rules(cloud=cloud)
            result.rules_evaluated = len(rules)

            session.add_decision(
                "evaluate_rules",
                (
                    f"Evaluating {len(rules)} CIS rules against"
                    f" {len(resources)} resources"
                ),
                0.95,
            )

            all_findings: list[RuleFinding] = []

            for resource_dict in resources:
                resource_label = resource_dict.get("_label", "")
                resource_id = resource_dict.get("id", "")
                applicable_rules = [
                    r
                    for r in rules
                    if resource_label in r.metadata.resource_types
                ]

                for rule in applicable_rules:
                    try:
                        findings = rule.evaluate(resource_dict)
                        all_findings.extend(findings)
                    except Exception as exc:
                        msg = (
                            f"Rule {rule.metadata.rule_id}"
                            f" on {resource_id}: {exc}"
                        )
                        result.errors.append(msg)
                        logger.warning(msg)

            # Check for config drift
            result.config_drifts = await self._check_config_drift(
                tenant_id, resources, session
            )

            # Write findings to graph
            for finding in all_findings:
                try:
                    await self._write_finding_to_graph(
                        tenant_id, finding
                    )
                    result.findings_created += 1
                    sev = finding.severity
                    if sev == "critical":
                        result.critical_count += 1
                    elif sev == "high":
                        result.high_count += 1
                    elif sev == "medium":
                        result.medium_count += 1
                    elif sev == "low":
                        result.low_count += 1
                    elif sev == "info":
                        result.info_count += 1
                except Exception as exc:
                    msg = (
                        f"Write finding {finding.rule_id}: {exc}"
                    )
                    result.errors.append(msg)
                    logger.warning(msg)

            # Save config snapshots for drift detection
            await self._save_snapshots(tenant_id, resources)

            session.add_action(
                "audit_complete",
                (
                    f"Found {result.findings_created} findings"
                    f" across {result.resources_scanned} resources"
                ),
                details=result.model_dump(),
                success=len(result.errors) == 0,
            )
        except Exception as exc:
            result.errors.append(str(exc))
            session.add_action(
                "audit_failed", str(exc), success=False
            )
        finally:
            session.finalize()

        return result

    async def _fetch_resources(
        self, tenant_id: UUID, asset_id: str | None
    ) -> list[dict[str, Any]]:
        """Fetch auditable resources from Neo4j."""
        tid = str(tenant_id)
        resources: list[dict[str, Any]] = []

        async with self._driver.session() as db_session:
            for label in AUDITABLE_LABELS:
                if asset_id:
                    cypher = (
                        f"MATCH (n:{label}"
                        " {tenant_id: $tid, id: $aid})"
                        " RETURN n"
                    )
                    params: dict[str, Any] = {
                        "tid": tid,
                        "aid": asset_id,
                    }
                else:
                    cypher = (
                        f"MATCH (n:{label}"
                        " {tenant_id: $tid})"
                        " RETURN n"
                    )
                    params = {"tid": tid}

                result = await db_session.run(cypher, **params)
                async for record in result:
                    node_dict = dict(record["n"])
                    node_dict["_label"] = label
                    resources.append(node_dict)

        return resources

    async def _write_finding_to_graph(
        self, tenant_id: UUID, finding: RuleFinding
    ) -> None:
        """Upsert a Finding node and HAS_FINDING edge."""
        tid = str(tenant_id)
        fid = str(uuid4())

        upsert_cypher = (
            "MERGE (f:Finding"
            " {tenant_id: $tid, rule_id: $rule_id,"
            " resource_id: $resource_id})"
            " ON CREATE SET"
            "  f.id = $fid,"
            "  f.severity = $severity,"
            "  f.title = $title,"
            "  f.description = $description,"
            "  f.resource_type = $resource_type,"
            "  f.remediation = $remediation,"
            "  f.details_json = $details_json,"
            "  f.status = $status,"
            "  f.found_at = datetime(),"
            "  f.first_seen = datetime(),"
            "  f.last_seen = datetime()"
            " ON MATCH SET"
            "  f.severity = $severity,"
            "  f.title = $title,"
            "  f.description = $description,"
            "  f.remediation = $remediation,"
            "  f.details_json = $details_json,"
            "  f.last_seen = datetime()"
            " RETURN f"
        )

        edge_cypher = (
            f"MATCH (r:{finding.resource_type}"
            " {tenant_id: $tid, id: $resource_id})"
            " MATCH (f:Finding"
            " {tenant_id: $tid, rule_id: $rule_id,"
            " resource_id: $resource_id})"
            " MERGE (r)-[e:HAS_FINDING]->(f)"
            " ON CREATE SET"
            "  e.first_seen = datetime(),"
            "  e.last_seen = datetime()"
            " ON MATCH SET"
            "  e.last_seen = datetime()"
            " RETURN e"
        )

        params = {
            "tid": tid,
            "fid": fid,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "remediation": finding.remediation or "",
            "details_json": json.dumps(
                finding.details, default=str
            ),
            "status": str(FindingStatus.OPEN),
        }

        async with self._driver.session() as db_session:
            await db_session.run(upsert_cypher, **params)
            await db_session.run(edge_cypher, **params)

    async def _check_config_drift(
        self,
        tenant_id: UUID,
        resources: list[dict[str, Any]],
        session: EngramSession,
    ) -> int:
        """Compare current config against stored snapshots."""
        tid = str(tenant_id)
        drift_count = 0

        fetch_snapshot_cypher = (
            "MATCH (s:ConfigSnapshot"
            " {tenant_id: $tid, resource_id: $rid})"
            " RETURN s.config_hash AS hash"
        )

        async with self._driver.session() as db_session:
            for resource in resources:
                resource_id = resource.get("id", "")
                if not resource_id:
                    continue

                current_hash = config_hash(resource)
                result = await db_session.run(
                    fetch_snapshot_cypher,
                    tid=tid,
                    rid=resource_id,
                )
                record = await result.single()

                if record and record["hash"] != current_hash:
                    drift_count += 1
                    session.add_action(
                        "config_drift",
                        (
                            "Config drift detected on"
                            f" {resource.get('_label', '')}"
                            f" {resource_id}"
                        ),
                        details={
                            "resource_id": resource_id,
                            "old_hash": record["hash"],
                            "new_hash": current_hash,
                        },
                        success=True,
                    )

        return drift_count

    async def _save_snapshots(
        self,
        tenant_id: UUID,
        resources: list[dict[str, Any]],
    ) -> None:
        """Save config snapshots for future drift comparison."""
        tid = str(tenant_id)

        upsert_cypher = (
            "MERGE (s:ConfigSnapshot"
            " {tenant_id: $tid, resource_id: $rid})"
            " ON CREATE SET"
            "  s.id = $sid,"
            "  s.config_hash = $hash,"
            "  s.resource_type = $rtype,"
            "  s.captured_at = datetime()"
            " ON MATCH SET"
            "  s.config_hash = $hash,"
            "  s.captured_at = datetime()"
            " RETURN s"
        )

        async with self._driver.session() as db_session:
            for resource in resources:
                resource_id = resource.get("id", "")
                if not resource_id:
                    continue
                await db_session.run(
                    upsert_cypher,
                    tid=tid,
                    rid=resource_id,
                    sid=str(uuid4()),
                    hash=config_hash(resource),
                    rtype=resource.get("_label", ""),
                )

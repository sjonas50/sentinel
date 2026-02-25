"""Configuration audit API endpoints — findings, triggers, and summary."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from sentinel_api.db import get_neo4j_driver
from sentinel_api.middleware.auth import TokenClaims, get_current_user
from sentinel_api.models.core import FindingSeverity, FindingStatus  # noqa: TC001

if TYPE_CHECKING:
    from uuid import UUID

router = APIRouter(prefix="/audit", tags=["audit"])


def _require_neo4j() -> Any:
    driver = get_neo4j_driver()
    if driver is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Neo4j is not available",
        )
    return driver


# ── List findings ─────────────────────────────────────────────


@router.get("/findings")
async def list_findings(
    severity: FindingSeverity | None = None,
    status_filter: FindingStatus | None = Query(
        default=None, alias="status"
    ),
    resource_type: str | None = None,
    rule_id: str | None = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """List configuration audit findings for the current tenant."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    where_clauses = ["f.tenant_id = $tid"]
    params: dict[str, Any] = {
        "tid": tid,
        "limit": limit,
        "offset": offset,
    }

    if severity is not None:
        where_clauses.append("f.severity = $severity")
        params["severity"] = str(severity)
    if status_filter is not None:
        where_clauses.append("f.status = $status")
        params["status"] = str(status_filter)
    if resource_type is not None:
        where_clauses.append("f.resource_type = $resource_type")
        params["resource_type"] = resource_type
    if rule_id is not None:
        where_clauses.append("f.rule_id = $rule_id")
        params["rule_id"] = rule_id

    where = " AND ".join(where_clauses)

    cypher = (
        f"MATCH (f:Finding) WHERE {where} "
        "RETURN f "
        "ORDER BY "
        "  CASE f.severity "
        "    WHEN 'critical' THEN 0 "
        "    WHEN 'high' THEN 1 "
        "    WHEN 'medium' THEN 2 "
        "    WHEN 'low' THEN 3 "
        "    ELSE 4 "
        "  END, f.found_at DESC "
        "SKIP $offset LIMIT $limit"
    )
    count_cypher = (
        f"MATCH (f:Finding) WHERE {where} "
        "RETURN count(f) AS cnt"
    )

    async with driver.session() as session:
        result = await session.run(cypher, **params)
        records = [dict(r["f"]) async for r in result]
        count_result = await session.run(
            count_cypher, **params
        )
        count_record = await count_result.single()
        total = count_record["cnt"] if count_record else 0

    return {
        "findings": records,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ── Findings for a specific asset ────────────────────────────


@router.get("/findings/{asset_id}")
async def get_asset_findings(
    asset_id: str,
    severity: FindingSeverity | None = None,
    status_filter: FindingStatus | None = Query(
        default=None, alias="status"
    ),
    limit: int = Query(default=50, le=500),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get configuration audit findings for a specific asset."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    where_clauses = [
        "f.tenant_id = $tid",
        "f.resource_id = $aid",
    ]
    params: dict[str, Any] = {
        "tid": tid,
        "aid": asset_id,
        "limit": limit,
    }

    if severity is not None:
        where_clauses.append("f.severity = $severity")
        params["severity"] = str(severity)
    if status_filter is not None:
        where_clauses.append("f.status = $status")
        params["status"] = str(status_filter)

    where = " AND ".join(where_clauses)
    cypher = (
        f"MATCH (f:Finding) WHERE {where} "
        "RETURN f ORDER BY "
        "  CASE f.severity "
        "    WHEN 'critical' THEN 0 "
        "    WHEN 'high' THEN 1 "
        "    WHEN 'medium' THEN 2 "
        "    WHEN 'low' THEN 3 "
        "    ELSE 4 "
        "  END "
        "LIMIT $limit"
    )

    async with driver.session() as session:
        result = await session.run(cypher, **params)
        records = [dict(r["f"]) async for r in result]

    return {
        "findings": records,
        "count": len(records),
        "asset_id": asset_id,
    }


# ── Trigger audit run ────────────────────────────────────────


@router.post("/run")
async def trigger_audit(
    asset_id: str | None = Query(default=None),
    cloud: str | None = Query(default=None),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Trigger a configuration audit run."""
    driver = _require_neo4j()

    from sentinel_api.services.cis_rules import CloudTarget
    from sentinel_api.services.config_auditor import (
        ConfigAuditor,
    )

    auditor = ConfigAuditor(driver)
    tid: UUID = user.tenant_id

    cloud_target = None
    if cloud:
        try:
            cloud_target = CloudTarget(cloud)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Invalid cloud target: {cloud}."
                    " Valid: aws, azure, gcp, any"
                ),
            ) from None

    if asset_id:
        result = await auditor.audit_asset(tid, asset_id)
    else:
        result = await auditor.audit_tenant(
            tid, cloud=cloud_target
        )

    return {"result": result.model_dump()}


# ── Update finding status ────────────────────────────────────


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    new_status: FindingStatus = Query(..., alias="status"),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Update the status of a finding."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    cypher = (
        "MATCH (f:Finding {tenant_id: $tid, id: $fid}) "
        "SET f.status = $status "
        "RETURN f"
    )

    async with driver.session() as session:
        result = await session.run(
            cypher,
            tid=tid,
            fid=finding_id,
            status=str(new_status),
        )
        record = await result.single()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    return {"finding": dict(record["f"])}


# ── Audit summary stats ─────────────────────────────────────


@router.get("/summary")
async def audit_summary(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get aggregate counts of findings by severity and status."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    cypher = (
        "MATCH (f:Finding {tenant_id: $tid}) "
        "RETURN f.severity AS severity,"
        " f.status AS status,"
        " count(f) AS cnt"
    )

    async with driver.session() as session:
        result = await session.run(cypher, tid=tid)
        rows = [
            {
                "severity": r["severity"],
                "status": r["status"],
                "count": r["cnt"],
            }
            async for r in result
        ]

    return {"tenant_id": tid, "breakdown": rows}

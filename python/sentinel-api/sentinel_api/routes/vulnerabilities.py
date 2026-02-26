"""Vulnerability API endpoints — list, filter, and trigger correlation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from sentinel_api.config import settings
from sentinel_api.db import get_neo4j_driver
from sentinel_api.middleware.auth import TokenClaims, get_current_user
from sentinel_api.models.core import VulnSeverity  # noqa: TC001

if TYPE_CHECKING:
    from uuid import UUID

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
asset_vuln_router = APIRouter(tags=["vulnerabilities"])


def _require_neo4j() -> Any:
    driver = get_neo4j_driver()
    if driver is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Neo4j is not available",
        )
    return driver


# ── Vulnerability list / detail ──────────────────────────────


@router.get("")
async def list_vulnerabilities(
    severity: VulnSeverity | None = None,
    exploitable: bool | None = None,
    in_cisa_kev: bool | None = None,
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    min_epss: float | None = Query(default=None, ge=0, le=1),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """List vulnerabilities for the current tenant."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    where_clauses = ["v.tenant_id = $tid"]
    params: dict[str, Any] = {
        "tid": tid,
        "limit": limit,
        "offset": offset,
    }

    if severity is not None:
        where_clauses.append("v.severity = $severity")
        params["severity"] = str(severity)
    if exploitable is not None:
        where_clauses.append("v.exploitable = $exploitable")
        params["exploitable"] = exploitable
    if in_cisa_kev is not None:
        where_clauses.append("v.in_cisa_kev = $in_cisa_kev")
        params["in_cisa_kev"] = in_cisa_kev
    if min_cvss is not None:
        where_clauses.append("v.cvss_score >= $min_cvss")
        params["min_cvss"] = min_cvss
    if min_epss is not None:
        where_clauses.append("v.epss_score >= $min_epss")
        params["min_epss"] = min_epss

    where = " AND ".join(where_clauses)
    cypher = (
        f"MATCH (v:Vulnerability) WHERE {where} "
        "RETURN v ORDER BY v.cvss_score DESC "
        "SKIP $offset LIMIT $limit"
    )
    count_cypher = (
        f"MATCH (v:Vulnerability) WHERE {where} "
        "RETURN count(v) AS cnt"
    )

    async with driver.session() as session:
        result = await session.run(cypher, **params)
        records = [dict(r["v"]) async for r in result]
        count_result = await session.run(count_cypher, **params)
        count_record = await count_result.single()
        total = count_record["cnt"] if count_record else 0

    return {
        "vulnerabilities": records,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ── Summary stats ────────────────────────────────────────────


@router.get("/summary")
async def vulnerability_summary(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get aggregate vulnerability counts by severity, plus exploitable/KEV."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    async with driver.session() as session:
        # Severity breakdown
        sev_result = await session.run(
            "MATCH (v:Vulnerability {tenant_id: $tid}) "
            "RETURN v.severity AS severity, count(v) AS cnt",
            tid=tid,
        )
        by_severity = [
            {"severity": r["severity"], "count": r["cnt"]}
            async for r in sev_result
        ]

        # Total count
        total = sum(row["count"] for row in by_severity)

        # Exploitable count
        exp_result = await session.run(
            "MATCH (v:Vulnerability {tenant_id: $tid, exploitable: true}) "
            "RETURN count(v) AS cnt",
            tid=tid,
        )
        exp_record = await exp_result.single()
        exploitable_count = exp_record["cnt"] if exp_record else 0

        # CISA KEV count
        kev_result = await session.run(
            "MATCH (v:Vulnerability {tenant_id: $tid, in_cisa_kev: true}) "
            "RETURN count(v) AS cnt",
            tid=tid,
        )
        kev_record = await kev_result.single()
        kev_count = kev_record["cnt"] if kev_record else 0

    return {
        "tenant_id": tid,
        "by_severity": by_severity,
        "total": total,
        "exploitable_count": exploitable_count,
        "kev_count": kev_count,
    }


# ── Vulnerability detail ─────────────────────────────────────


@router.get("/{cve_id}")
async def get_vulnerability(
    cve_id: str,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get details of a specific vulnerability."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    cypher = (
        "MATCH (v:Vulnerability "
        "{tenant_id: $tid, cve_id: $cve_id}) "
        "RETURN v"
    )

    async with driver.session() as session:
        result = await session.run(
            cypher, tid=tid, cve_id=cve_id
        )
        record = await result.single()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {cve_id} not found",
        )

    return {"vulnerability": dict(record["v"])}


@router.get("/{cve_id}/assets")
async def get_vulnerability_assets(
    cve_id: str,
    limit: int = Query(default=50, le=500),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get assets (services) affected by a specific vulnerability."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    cypher = (
        "MATCH (s:Service {tenant_id: $tid})"
        "-[:HAS_CVE]->(v:Vulnerability {tenant_id: $tid, cve_id: $cve_id}) "
        "RETURN s ORDER BY s.name LIMIT $limit"
    )

    async with driver.session() as session:
        result = await session.run(
            cypher, tid=tid, cve_id=cve_id, limit=limit
        )
        records = [dict(r["s"]) async for r in result]

    return {"assets": records, "count": len(records)}


# ── Correlation sync ─────────────────────────────────────────


@router.post("/sync")
async def trigger_sync(
    service_id: str | None = Query(default=None),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Trigger vulnerability correlation for the current tenant."""
    driver = _require_neo4j()

    from sentinel_api.services.epss_client import EpssClient
    from sentinel_api.services.kev_client import KevClient
    from sentinel_api.services.nvd_client import NvdClient
    from sentinel_api.services.vuln_correlation import (
        VulnCorrelationEngine,
    )

    nvd = NvdClient(
        base_url=settings.nvd_base_url,
        api_key=settings.nvd_api_key,
    )
    epss = EpssClient(base_url=settings.epss_base_url)
    kev = KevClient(kev_url=settings.kev_url)
    engine = VulnCorrelationEngine(driver, nvd, epss, kev)

    tid: UUID = user.tenant_id
    if service_id:
        from uuid import UUID as _UUID

        result = await engine.correlate_service(
            tid, _UUID(service_id)
        )
    else:
        result = await engine.correlate_tenant(tid)

    return {"result": result.model_dump()}


# ── Asset-scoped vulnerabilities ─────────────────────────────


@asset_vuln_router.get("/assets/{asset_id}/vulnerabilities")
async def get_asset_vulnerabilities(
    asset_id: str,
    limit: int = Query(default=50, le=500),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get vulnerabilities linked to a specific asset via HAS_CVE."""
    driver = _require_neo4j()
    tid = str(user.tenant_id)

    cypher = (
        "MATCH (s:Service {tenant_id: $tid, id: $sid})"
        "-[:HAS_CVE]->(v:Vulnerability) "
        "RETURN v ORDER BY v.cvss_score DESC LIMIT $limit"
    )

    async with driver.session() as session:
        result = await session.run(
            cypher, tid=tid, sid=asset_id, limit=limit
        )
        records = [dict(r["v"]) async for r in result]

    return {"vulnerabilities": records, "count": len(records)}

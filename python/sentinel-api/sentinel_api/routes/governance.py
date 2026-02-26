"""Governance API endpoints — Shadow AI discovery and inventory."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from sentinel_api.middleware.auth import TokenClaims, get_current_user

router = APIRouter(prefix="/governance", tags=["governance"])


# ── Shadow AI List ──────────────────────────────────────────


@router.get("/shadow-ai")
async def list_shadow_ai_services(
    user: TokenClaims = Depends(get_current_user),
    category: str | None = None,
    risk_tier: str | None = None,
    sanctioned: bool | None = None,
    min_risk_score: float | None = Query(default=None, ge=0, le=100),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List discovered shadow AI services for the tenant.

    Returns placeholder data. In production, this would query
    shadow AI service records persisted in Neo4j.
    """
    return {
        "services": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
    }


# ── Shadow AI Summary ──────────────────────────────────────


@router.get("/shadow-ai/summary")
async def shadow_ai_summary(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Get aggregate shadow AI statistics for the tenant.

    Returns placeholder data. In production, this would aggregate
    from persisted shadow AI discovery results.
    """
    return {
        "tenant_id": str(user.tenant_id),
        "total_services": 0,
        "unsanctioned_count": 0,
        "max_risk_score": 0.0,
        "by_category": [],
        "by_risk_tier": [
            {"risk_tier": "critical", "count": 0},
            {"risk_tier": "high", "count": 0},
            {"risk_tier": "medium", "count": 0},
            {"risk_tier": "low", "count": 0},
        ],
    }


# ── Known AI Domains ───────────────────────────────────────
# NOTE: Static paths must be defined before the {service_id} path param.


@router.get("/shadow-ai/domains")
async def list_known_ai_domains(
    user: TokenClaims = Depends(get_current_user),
    category: str | None = None,
) -> dict[str, Any]:
    """List the known AI service domain registry.

    This is a live endpoint returning the built-in domain list,
    optionally filtered by category.
    """
    from sentinel_connectors.governance.domains import AI_SERVICE_DOMAINS

    domains = AI_SERVICE_DOMAINS
    if category:
        domains = [d for d in domains if d.category == category]

    return {
        "domains": [d.model_dump() for d in domains],
        "total": len(domains),
    }


# ── Shadow AI Detail ───────────────────────────────────────


@router.get("/shadow-ai/{service_id}")
async def get_shadow_ai_service(
    service_id: str,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Get details of a specific shadow AI service.

    Returns placeholder data. In production, this would fetch
    the service record from Neo4j.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Shadow AI service {service_id} not found",
    )


# ── Trigger Scan ───────────────────────────────────────────


@router.post("/shadow-ai/scan")
async def trigger_shadow_ai_scan(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Trigger a shadow AI discovery scan.

    Placeholder — in production, this would initiate a scan by pulling
    DNS and network flow logs from the configured SIEM connector.
    """
    return {
        "status": "scan_initiated",
        "tenant_id": str(user.tenant_id),
        "message": "Shadow AI discovery scan queued",
    }

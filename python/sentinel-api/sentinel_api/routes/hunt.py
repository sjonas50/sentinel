"""Threat hunt findings endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from sentinel_api.middleware.auth import TokenClaims, get_current_user

router = APIRouter(prefix="/hunt", tags=["hunt"])


@router.get("/findings")
async def list_hunt_findings(
    user: TokenClaims = Depends(get_current_user),
    severity: str | None = None,
    playbook: str | None = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List threat hunt findings for the tenant.

    Returns placeholder data. In production, this would query
    hunt findings persisted by the agent framework.
    """
    return {
        "findings": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/summary")
async def hunt_summary(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Get summary statistics for threat hunting.

    Returns placeholder data. In production, this would aggregate
    findings from the hunt agent results.
    """
    return {
        "tenant_id": str(user.tenant_id),
        "by_severity": [
            {"severity": "critical", "count": 0},
            {"severity": "high", "count": 0},
            {"severity": "medium", "count": 0},
            {"severity": "low", "count": 0},
        ],
        "total_findings": 0,
        "active_hunts": 0,
    }


@router.get("/findings/{finding_id}")
async def get_hunt_finding(
    finding_id: str,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Get a single hunt finding by ID.

    Returns placeholder data. In production, this would query
    persisted hunt findings.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Hunt finding {finding_id} not found",
    )

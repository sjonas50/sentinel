"""Adversarial simulation results endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from sentinel_api.middleware.auth import TokenClaims, get_current_user

router = APIRouter(prefix="/simulations", tags=["simulations"])


@router.get("")
async def list_simulations(
    user: TokenClaims = Depends(get_current_user),
    tactic: str | None = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List simulation results for the tenant.

    Returns placeholder data. In production, this would query
    simulation results persisted by the agent framework.
    """
    return {
        "simulations": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/summary")
async def simulation_summary(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Get summary statistics for adversarial simulations.

    Returns placeholder data. In production, this would aggregate
    results from simulation agent runs.
    """
    return {
        "tenant_id": str(user.tenant_id),
        "total_runs": 0,
        "techniques_tested": 0,
        "total_findings": 0,
        "highest_risk_score": 0.0,
        "by_tactic": {
            "initial_access": 0,
            "lateral_movement": 0,
            "privilege_escalation": 0,
            "exfiltration": 0,
        },
    }

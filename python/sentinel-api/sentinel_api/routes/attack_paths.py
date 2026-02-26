"""Attack path analysis endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from sentinel_api.middleware.auth import TokenClaims, get_current_user
from sentinel_api.services.pathfind import PathfindError, run_pathfind

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


# ── Request / Response Models ──────────────────────────────────


class ComputeRequest(BaseModel):
    """Request body for attack path computation."""

    sources: list[str] | None = None
    targets: list[str] | None = None
    max_depth: int = Field(default=10, ge=1, le=20)
    max_paths: int = Field(default=100, ge=1, le=1000)
    min_exploitability: float | None = None
    include_lateral: bool = False
    include_blast: bool = False
    node_limit: int = Field(default=50000, ge=100, le=200000)


class BlastRadiusRequest(BaseModel):
    """Request body for blast radius computation."""

    compromised_node_id: str
    max_hops: int = Field(default=5, ge=1, le=15)
    min_exploitability: float = Field(default=0.3, ge=0.0, le=1.0)


class ShortestPathRequest(BaseModel):
    """Request body for shortest path computation."""

    source_id: str
    target_id: str


# ── Endpoints ──────────────────────────────────────────────────


@router.post("/compute")
async def compute_attack_paths(
    body: ComputeRequest,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Trigger full attack path computation for the tenant."""
    request = {
        "tenant_id": {"0": str(user.tenant_id)},
        "sources": body.sources,
        "targets": body.targets,
        "max_depth": body.max_depth,
        "max_paths": body.max_paths,
        "min_exploitability": body.min_exploitability,
        "include_lateral": body.include_lateral,
        "include_blast": body.include_blast,
        "node_limit": body.node_limit,
    }

    try:
        result = await run_pathfind("compute", request)
    except PathfindError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return result


@router.post("/blast-radius")
async def compute_blast_radius(
    body: BlastRadiusRequest,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Compute blast radius from a specific compromised node."""
    request = {
        "tenant_id": {"0": str(user.tenant_id)},
        "compromised_node_id": body.compromised_node_id,
        "max_hops": body.max_hops,
        "min_exploitability": body.min_exploitability,
    }

    try:
        result = await run_pathfind("blast-radius", request)
    except PathfindError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return result


@router.post("/shortest")
async def compute_shortest_path(
    body: ShortestPathRequest,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Find the shortest (most exploitable) path between two nodes."""
    try:
        result = await run_pathfind(
            "shortest",
            extra_args=[
                "--source",
                body.source_id,
                "--target",
                body.target_id,
                "--tenant-id",
                str(user.tenant_id),
            ],
        )
    except PathfindError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return result


@router.get("/summary")
async def attack_path_summary(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, Any]:
    """Get summary statistics for attack paths.

    Returns a placeholder summary. In production, this would query
    cached computation results from a database.
    """
    return {
        "tenant_id": str(user.tenant_id),
        "total_paths": 0,
        "by_risk_tier": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "top_paths": [],
    }

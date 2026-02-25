"""Health check endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from sentinel_api.db import get_neo4j_driver, get_pg_pool

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Basic health check."""
    return {"status": "ok", "service": "sentinel-api"}


@router.get("/health/detailed")
async def health_detailed() -> dict[str, object]:
    """Detailed health check with dependency status."""
    deps: dict[str, str] = {}

    pg = get_pg_pool()
    if pg is not None:
        try:
            async with pg.acquire() as conn:
                await conn.fetchval("SELECT 1")
            deps["postgres"] = "ok"
        except Exception:
            deps["postgres"] = "error"
    else:
        deps["postgres"] = "not_configured"

    neo4j = get_neo4j_driver()
    if neo4j is not None:
        try:
            await neo4j.verify_connectivity()
            deps["neo4j"] = "ok"
        except Exception:
            deps["neo4j"] = "error"
    else:
        deps["neo4j"] = "not_configured"

    overall = "ok" if all(v == "ok" for v in deps.values()) else "degraded"
    return {"status": overall, "service": "sentinel-api", "dependencies": deps}

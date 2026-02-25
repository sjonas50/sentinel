"""Graph query proxy endpoints — read-only access to the Neo4j knowledge graph."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from sentinel_api.db import get_neo4j_driver
from sentinel_api.middleware.auth import TokenClaims, get_current_user

router = APIRouter(prefix="/graph", tags=["graph"])


def _require_neo4j() -> Any:
    driver = get_neo4j_driver()
    if driver is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Neo4j is not available",
        )
    return driver


@router.get("/nodes/{label}")
async def list_nodes(
    label: str,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """List nodes of a given label for the current tenant."""
    driver = _require_neo4j()
    tenant_id = str(user.tenant_id)

    cypher = (
        f"MATCH (n:{label} {{tenant_id: $tid}}) "
        "RETURN n ORDER BY n.last_seen DESC SKIP $offset LIMIT $limit"
    )
    count_cypher = f"MATCH (n:{label} {{tenant_id: $tid}}) RETURN count(n) AS cnt"

    async with driver.session() as session:
        result = await session.run(
            cypher, tid=tenant_id, offset=offset, limit=limit
        )
        records = [dict(record["n"]) async for record in result]

        count_result = await session.run(count_cypher, tid=tenant_id)
        count_record = await count_result.single()
        total = count_record["cnt"] if count_record else 0

    return {"nodes": records, "total": total, "limit": limit, "offset": offset}


@router.get("/nodes/{label}/{node_id}")
async def get_node(
    label: str,
    node_id: str,
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get a single node by label and id."""
    driver = _require_neo4j()
    tenant_id = str(user.tenant_id)

    cypher = f"MATCH (n:{label} {{tenant_id: $tid, id: $nid}}) RETURN n"

    async with driver.session() as session:
        result = await session.run(cypher, tid=tenant_id, nid=node_id)
        record = await result.single()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{label} with id {node_id} not found",
        )

    return {"node": dict(record["n"])}


@router.get("/nodes/{label}/{node_id}/neighbors")
async def get_neighbors(
    label: str,
    node_id: str,
    limit: int = Query(default=50, le=200),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get all neighbors of a node."""
    driver = _require_neo4j()
    tenant_id = str(user.tenant_id)

    cypher = (
        f"MATCH (a:{label} {{tenant_id: $tid, id: $nid}})-[r]-(b) "
        "WHERE b.tenant_id = $tid "
        "RETURN b, type(r) AS rel_type, labels(b) AS labels "
        "LIMIT $limit"
    )

    async with driver.session() as session:
        result = await session.run(
            cypher, tid=tenant_id, nid=node_id, limit=limit
        )
        neighbors = []
        async for record in result:
            neighbors.append({
                "node": dict(record["b"]),
                "relationship": record["rel_type"],
                "labels": record["labels"],
            })

    return {"neighbors": neighbors, "count": len(neighbors)}


@router.get("/search")
async def search_nodes(
    q: str = Query(min_length=1),
    index: str = Query(default="host_search"),
    limit: int = Query(default=20, le=100),
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Full-text search across indexed nodes."""
    driver = _require_neo4j()
    tenant_id = str(user.tenant_id)

    cypher = (
        "CALL db.index.fulltext.queryNodes($idx, $term) YIELD node, score "
        "WHERE node.tenant_id = $tid "
        "RETURN node, labels(node) AS labels, score "
        "ORDER BY score DESC LIMIT $limit"
    )

    async with driver.session() as session:
        result = await session.run(
            cypher, idx=index, term=q, tid=tenant_id, limit=limit
        )
        results = []
        async for record in result:
            results.append({
                "node": dict(record["node"]),
                "labels": record["labels"],
                "score": record["score"],
            })

    return {"results": results, "count": len(results)}


@router.get("/stats")
async def graph_stats(
    user: TokenClaims = Depends(get_current_user),
) -> dict[str, object]:
    """Get node/edge count stats for the current tenant's graph."""
    driver = _require_neo4j()
    tenant_id = str(user.tenant_id)

    labels = [
        "Host", "Service", "Port", "User", "Group", "Role",
        "Policy", "Subnet", "Vpc", "Vulnerability", "Certificate",
        "Application", "McpServer",
    ]

    counts: dict[str, int] = {}
    async with driver.session() as session:
        for label in labels:
            result = await session.run(
                f"MATCH (n:{label} {{tenant_id: $tid}}) RETURN count(n) AS cnt",
                tid=tenant_id,
            )
            record = await result.single()
            counts[label] = record["cnt"] if record else 0

    return {"tenant_id": tenant_id, "node_counts": counts}

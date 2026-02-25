"""Tests for graph route endpoints (without live Neo4j)."""

from uuid import uuid4

import httpx
import pytest
from sentinel_api.main import app
from sentinel_api.middleware.auth import create_token


@pytest.fixture
def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
def auth_headers() -> dict[str, str]:
    token = create_token(sub="test-user", tenant_id=uuid4())
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_graph_stats_returns_503_without_neo4j(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    """Graph endpoints return 503 when Neo4j is not available."""
    response = await client.get("/graph/stats", headers=auth_headers)
    assert response.status_code == 503
    assert "Neo4j" in response.json()["detail"]


@pytest.mark.asyncio
async def test_list_nodes_returns_503_without_neo4j(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    response = await client.get("/graph/nodes/Host", headers=auth_headers)
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_get_node_returns_503_without_neo4j(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    response = await client.get("/graph/nodes/Host/some-id", headers=auth_headers)
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_get_neighbors_returns_503_without_neo4j(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    response = await client.get(
        "/graph/nodes/Host/some-id/neighbors", headers=auth_headers
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_search_returns_503_without_neo4j(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    response = await client.get(
        "/graph/search", params={"q": "test"}, headers=auth_headers
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_graph_stats_requires_auth(client: httpx.AsyncClient) -> None:
    response = await client.get("/graph/stats")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_search_requires_query_param(
    client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    response = await client.get("/graph/search", headers=auth_headers)
    assert response.status_code == 422

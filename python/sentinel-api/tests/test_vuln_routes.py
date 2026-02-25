"""Tests for vulnerability API routes (without live Neo4j)."""

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


# ── Auth tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_vulns_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/vulnerabilities")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_vuln_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/vulnerabilities/CVE-2024-1234")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_sync_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/vulnerabilities/sync")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_asset_vulns_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/assets/some-id/vulnerabilities")
    assert response.status_code == 401


# ── 503 tests (Neo4j unavailable) ────────────────────────────


@pytest.mark.asyncio
async def test_list_vulns_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/vulnerabilities", headers=auth_headers
    )
    assert response.status_code == 503
    assert "Neo4j" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_vuln_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/vulnerabilities/CVE-2024-1234", headers=auth_headers
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_sync_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.post(
        "/vulnerabilities/sync", headers=auth_headers
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_asset_vulns_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/assets/some-id/vulnerabilities", headers=auth_headers
    )
    assert response.status_code == 503


# ── Query param validation ────────────────────────────────────


@pytest.mark.asyncio
async def test_list_vulns_invalid_min_cvss(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/vulnerabilities",
        params={"min_cvss": 11},
        headers=auth_headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_list_vulns_invalid_min_epss(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/vulnerabilities",
        params={"min_epss": 2.0},
        headers=auth_headers,
    )
    assert response.status_code == 422

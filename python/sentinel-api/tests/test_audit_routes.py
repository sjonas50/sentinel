"""Tests for configuration audit API routes (without live Neo4j)."""

from uuid import uuid4

import httpx
import pytest
from sentinel_api.main import app
from sentinel_api.middleware.auth import create_token


@pytest.fixture
def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(
        transport=transport, base_url="http://test"
    )


@pytest.fixture
def auth_headers() -> dict[str, str]:
    token = create_token(sub="test-user", tenant_id=uuid4())
    return {"Authorization": f"Bearer {token}"}


# ── Auth tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_findings_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/audit/findings")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_asset_findings_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/audit/findings/some-id")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_trigger_audit_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/audit/run")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_update_status_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.patch(
        "/audit/findings/f-1/status",
        params={"status": "acknowledged"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_summary_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/audit/summary")
    assert response.status_code == 401


# ── 503 tests (Neo4j unavailable) ────────────────────────────


@pytest.mark.asyncio
async def test_list_findings_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/audit/findings", headers=auth_headers
    )
    assert response.status_code == 503
    assert "Neo4j" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_asset_findings_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/audit/findings/some-id", headers=auth_headers
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_trigger_audit_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.post(
        "/audit/run", headers=auth_headers
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_update_status_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.patch(
        "/audit/findings/f-1/status",
        params={"status": "acknowledged"},
        headers=auth_headers,
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_summary_503_without_neo4j(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/audit/summary", headers=auth_headers
    )
    assert response.status_code == 503


# ── Query param validation ────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_audit_invalid_cloud(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """Invalid cloud param should fail at neo4j check first (503)."""
    response = await client.post(
        "/audit/run",
        params={"cloud": "invalid"},
        headers=auth_headers,
    )
    # Without Neo4j, we get 503 before cloud validation
    assert response.status_code == 503

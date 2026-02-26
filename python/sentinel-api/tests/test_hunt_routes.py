"""Tests for hunt API routes."""

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
async def test_findings_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/hunt/findings")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_summary_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/hunt/summary")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_finding_detail_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/hunt/findings/f-123")
    assert response.status_code == 401


# ── Response structure tests ─────────────────────────────────


@pytest.mark.asyncio
async def test_findings_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/hunt/findings",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_summary_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/hunt/summary",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "tenant_id" in data
    assert "by_severity" in data
    assert "total_findings" in data
    assert "active_hunts" in data


@pytest.mark.asyncio
async def test_finding_detail_returns_404(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/hunt/findings/nonexistent",
        headers=auth_headers,
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_findings_accepts_filters(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/hunt/findings?severity=critical&playbook=credential_abuse&limit=10",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10

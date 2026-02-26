"""Tests for simulation API routes."""

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
async def test_list_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/simulations")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_summary_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/simulations/summary")
    assert response.status_code == 401


# ── Response structure tests ─────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/simulations",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "simulations" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert isinstance(data["simulations"], list)


@pytest.mark.asyncio
async def test_summary_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/simulations/summary",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "tenant_id" in data
    assert "total_runs" in data
    assert "techniques_tested" in data
    assert "total_findings" in data
    assert "highest_risk_score" in data
    assert "by_tactic" in data


@pytest.mark.asyncio
async def test_list_accepts_tactic_filter(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/simulations?tactic=initial_access&limit=10",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10

"""Tests for attack path API routes."""

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
async def test_compute_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/attack-paths/compute",
        json={"max_depth": 10},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_blast_radius_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/attack-paths/blast-radius",
        json={"compromised_node_id": "n-1"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_shortest_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/attack-paths/shortest",
        json={"source_id": "n-1", "target_id": "n-2"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_summary_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/attack-paths/summary")
    assert response.status_code == 401


# ── Summary endpoint ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_summary_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/attack-paths/summary",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "tenant_id" in data
    assert "total_paths" in data
    assert "by_risk_tier" in data
    assert "top_paths" in data


# ── Validation tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_compute_validates_max_depth(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.post(
        "/attack-paths/compute",
        json={"max_depth": 100},  # exceeds max of 20
        headers=auth_headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_blast_radius_validates_min_exploitability(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.post(
        "/attack-paths/blast-radius",
        json={
            "compromised_node_id": "n-1",
            "min_exploitability": 2.0,  # exceeds max of 1.0
        },
        headers=auth_headers,
    )
    assert response.status_code == 422

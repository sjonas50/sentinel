"""Tests for the health check endpoint."""

import httpx
import pytest
from sentinel_api.main import app


@pytest.fixture
def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health_returns_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "sentinel-api"

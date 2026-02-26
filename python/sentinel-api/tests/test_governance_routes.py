"""Tests for governance API routes."""

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
    response = await client.get("/governance/shadow-ai")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_summary_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/governance/shadow-ai/summary")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_detail_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/governance/shadow-ai/svc-123")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_domains_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/governance/shadow-ai/domains")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_scan_requires_auth(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/governance/shadow-ai/scan")
    assert response.status_code == 401


# ── Response structure tests ─────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/governance/shadow-ai",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "services" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert isinstance(data["services"], list)


@pytest.mark.asyncio
async def test_summary_returns_structure(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/governance/shadow-ai/summary",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "tenant_id" in data
    assert "total_services" in data
    assert "unsanctioned_count" in data
    assert "max_risk_score" in data
    assert "by_category" in data
    assert "by_risk_tier" in data


@pytest.mark.asyncio
async def test_detail_returns_404(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/governance/shadow-ai/nonexistent",
        headers=auth_headers,
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_domains_returns_list(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/governance/shadow-ai/domains",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "domains" in data
    assert "total" in data
    assert data["total"] >= 20
    assert isinstance(data["domains"], list)
    # Verify domain entry shape
    entry = data["domains"][0]
    assert "domain" in entry
    assert "service_name" in entry
    assert "category" in entry
    assert "risk_tier" in entry


@pytest.mark.asyncio
async def test_domains_filters_by_category(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/governance/shadow-ai/domains?category=code_ai",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for d in data["domains"]:
        assert d["category"] == "code_ai"


@pytest.mark.asyncio
async def test_list_accepts_filters(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/governance/shadow-ai?category=llm_provider&risk_tier=critical&limit=10",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10


@pytest.mark.asyncio
async def test_scan_returns_status(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    response = await client.post(
        "/governance/shadow-ai/scan",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "scan_initiated"
    assert "tenant_id" in data

"""Tests for JWT authentication middleware."""

from uuid import uuid4

import httpx
import jwt
import pytest
from sentinel_api.config import settings
from sentinel_api.main import app
from sentinel_api.middleware.auth import TokenClaims, create_token


@pytest.fixture
def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
def tenant_id() -> str:
    return str(uuid4())


@pytest.fixture
def valid_token(tenant_id: str) -> str:
    return create_token(sub="test-user", tenant_id=tenant_id)


@pytest.mark.asyncio
async def test_create_token_roundtrip(tenant_id: str) -> None:
    token = create_token(sub="alice", tenant_id=tenant_id, role="admin")
    payload = jwt.decode(
        token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
    )
    assert payload["sub"] == "alice"
    assert payload["tenant_id"] == tenant_id
    assert payload["role"] == "admin"


@pytest.mark.asyncio
async def test_missing_auth_header(client: httpx.AsyncClient) -> None:
    response = await client.get("/graph/stats")
    assert response.status_code == 401
    assert "Missing authorization header" in response.json()["detail"]


@pytest.mark.asyncio
async def test_invalid_token(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/graph/stats", headers={"Authorization": "Bearer bad-token"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_expired_token(client: httpx.AsyncClient) -> None:
    import time

    payload = {
        "sub": "test",
        "tenant_id": str(uuid4()),
        "role": "analyst",
        "exp": int(time.time()) - 60,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    response = await client.get(
        "/graph/stats", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_token_claims_model(tenant_id: str) -> None:
    from uuid import UUID

    claims = TokenClaims(sub="bob", tenant_id=UUID(tenant_id), role="admin")
    assert claims.sub == "bob"
    assert str(claims.tenant_id) == tenant_id
    assert claims.role == "admin"


@pytest.mark.asyncio
async def test_default_role_is_analyst(tenant_id: str) -> None:
    from uuid import UUID

    claims = TokenClaims(sub="carol", tenant_id=UUID(tenant_id))
    assert claims.role == "analyst"

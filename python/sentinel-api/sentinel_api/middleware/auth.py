"""JWT authentication middleware.

Placeholder implementation for Phase 0 — validates JWT tokens
and extracts tenant_id and user claims. Full RBAC comes later.
"""

from __future__ import annotations

from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from sentinel_api.config import settings

_bearer_scheme = HTTPBearer(auto_error=False)


class TokenClaims(BaseModel):
    """Claims extracted from a validated JWT token."""

    sub: str
    tenant_id: UUID
    role: str = "analyst"


def create_token(sub: str, tenant_id: UUID, role: str = "analyst") -> str:
    """Create a JWT token (used for testing and initial setup)."""
    payload = {
        "sub": sub,
        "tenant_id": str(tenant_id),
        "role": role,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _decode_token(token: str) -> TokenClaims:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        return TokenClaims(
            sub=payload["sub"],
            tenant_id=UUID(payload["tenant_id"]),
            role=payload.get("role", "analyst"),
        )
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from e
    except (jwt.InvalidTokenError, KeyError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from e


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> TokenClaims:
    """FastAPI dependency that validates the Bearer token and returns claims.

    Usage in routes::

        @router.get("/nodes")
        async def list_nodes(user: TokenClaims = Depends(get_current_user)):
            tenant_id = user.tenant_id
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _decode_token(credentials.credentials)

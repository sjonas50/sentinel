"""WebSocket endpoint stub for real-time event streaming."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from sentinel_api.middleware.auth import TokenClaims, _decode_token

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)


def _authenticate_ws(token: str) -> TokenClaims:
    """Validate a token passed as a query parameter for WebSocket connections."""
    return _decode_token(token)


@router.websocket("/ws/events")
async def event_stream(
    websocket: WebSocket,
    token: str | None = None,
) -> None:
    """WebSocket endpoint for real-time event updates.

    Clients connect with ``ws://host/ws/events?token=<jwt>``.
    Phase 0 stub — accepts connections and sends periodic heartbeats.
    Real event fan-out from Redis Streams will be wired in Phase 1.
    """
    if token is None:
        await websocket.close(code=4001, reason="Missing token")
        return

    try:
        claims = _authenticate_ws(token)
    except Exception:
        await websocket.close(code=4003, reason="Invalid token")
        return

    await websocket.accept()
    tenant_id = str(claims.tenant_id)
    logger.info("WebSocket connected: user=%s tenant=%s", claims.sub, tenant_id)

    try:
        while True:
            # Phase 0: heartbeat every 30 seconds
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "tenant_id": tenant_id})
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: user=%s", claims.sub)

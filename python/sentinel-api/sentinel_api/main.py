"""Sentinel API application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel_api.config import settings
from sentinel_api.db import close_db, init_db
from sentinel_api.routes import attack_paths, audit, graph, health, vulnerabilities, ws

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup / shutdown lifecycle."""
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title="Sentinel API",
    description="Enterprise Autonomous Cyber Defense Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(graph.router)
app.include_router(vulnerabilities.router)
app.include_router(vulnerabilities.asset_vuln_router)
app.include_router(audit.router)
app.include_router(attack_paths.router)
app.include_router(ws.router)

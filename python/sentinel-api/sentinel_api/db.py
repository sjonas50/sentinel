"""Database connection management for PostgreSQL and Neo4j."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import asyncpg
import neo4j

from sentinel_api.config import settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

# ── Connection state ──────────────────────────────────────────────

_pg_pool: asyncpg.Pool | None = None
_neo4j_driver: neo4j.AsyncDriver | None = None


async def init_db() -> None:
    """Initialize database connections. Called on app startup."""
    global _pg_pool, _neo4j_driver  # noqa: PLW0603

    try:
        _pg_pool = await asyncpg.create_pool(
            dsn=settings.postgres_dsn,
            min_size=2,
            max_size=10,
        )
        logger.info("PostgreSQL pool created")
    except Exception:
        logger.warning("PostgreSQL not available — running without PG")
        _pg_pool = None

    try:
        _neo4j_driver = neo4j.AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        await _neo4j_driver.verify_connectivity()
        logger.info("Neo4j driver connected")
    except Exception:
        logger.warning("Neo4j not available — running without Neo4j")
        _neo4j_driver = None


async def close_db() -> None:
    """Close database connections. Called on app shutdown."""
    global _pg_pool, _neo4j_driver  # noqa: PLW0603

    if _pg_pool is not None:
        await _pg_pool.close()
        _pg_pool = None
        logger.info("PostgreSQL pool closed")

    if _neo4j_driver is not None:
        await _neo4j_driver.close()
        _neo4j_driver = None
        logger.info("Neo4j driver closed")


def get_pg_pool() -> asyncpg.Pool | None:
    """Get the PostgreSQL connection pool."""
    return _pg_pool


def get_neo4j_driver() -> neo4j.AsyncDriver | None:
    """Get the Neo4j async driver."""
    return _neo4j_driver


@asynccontextmanager
async def pg_connection() -> AsyncIterator[asyncpg.Connection]:
    """Acquire a PostgreSQL connection from the pool."""
    if _pg_pool is None:
        raise RuntimeError("PostgreSQL pool not initialized")
    async with _pg_pool.acquire() as conn:
        yield conn

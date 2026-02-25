"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Fetches the full KEV JSON catalog and provides fast CVE lookup.
The catalog is cached in memory and refreshed at most once per day.
"""

from __future__ import annotations

import logging
import time

import httpx

logger = logging.getLogger(__name__)

# Default TTL: 24 hours
_DEFAULT_TTL_SECONDS = 86400


class KevClient:
    """Async client for the CISA KEV catalog."""

    def __init__(
        self,
        kev_url: str,
        http_client: httpx.AsyncClient | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._kev_url = kev_url
        self._http_client = http_client
        self._ttl = ttl_seconds
        self._cache: set[str] | None = None
        self._last_fetched: float = 0.0

    async def fetch_catalog(self) -> set[str]:
        """Fetch the KEV catalog, using cache if fresh."""
        now = time.monotonic()
        if (
            self._cache is not None
            and (now - self._last_fetched) < self._ttl
        ):
            return self._cache

        client = self._http_client or httpx.AsyncClient()
        owns_client = self._http_client is None
        try:
            resp = await client.get(self._kev_url, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            self._cache = {
                v["cveID"] for v in vulns if "cveID" in v
            }
            self._last_fetched = time.monotonic()
            logger.info("KEV catalog loaded: %d entries", len(self._cache))
            return self._cache
        finally:
            if owns_client:
                await client.aclose()

    async def is_known_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        catalog = await self.fetch_catalog()
        return cve_id in catalog

"""EPSS (Exploit Prediction Scoring System) API client.

Queries the FIRST.org EPSS API for exploitation probability scores.
Supports batch queries, chunked into groups of 30 CVE IDs.
"""

from __future__ import annotations

import contextlib
import logging

import httpx

logger = logging.getLogger(__name__)

_BATCH_SIZE = 30


class EpssClient:
    """Async client for the EPSS API."""

    def __init__(
        self,
        base_url: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._http_client = http_client

    async def get_scores(
        self, cve_ids: list[str]
    ) -> dict[str, float]:
        """Get EPSS scores for a list of CVE IDs.

        Returns a dict mapping CVE ID → EPSS probability [0, 1].
        CVEs not found in EPSS are omitted from the result.
        """
        if not cve_ids:
            return {}

        client = self._http_client or httpx.AsyncClient()
        owns_client = self._http_client is None
        try:
            result: dict[str, float] = {}
            # Chunk into batches of _BATCH_SIZE
            for i in range(0, len(cve_ids), _BATCH_SIZE):
                chunk = cve_ids[i : i + _BATCH_SIZE]
                batch_result = await self._query_batch(client, chunk)
                result.update(batch_result)
            return result
        finally:
            if owns_client:
                await client.aclose()

    async def _query_batch(
        self,
        client: httpx.AsyncClient,
        cve_ids: list[str],
    ) -> dict[str, float]:
        """Query EPSS for a single batch of CVE IDs."""
        cve_param = ",".join(cve_ids)
        try:
            resp = await client.get(
                self._base_url,
                params={"cve": cve_param},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            result: dict[str, float] = {}
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                epss_str = entry.get("epss", "")
                if cve_id and epss_str:
                    with contextlib.suppress(ValueError, TypeError):
                        result[cve_id] = float(epss_str)
            return result
        except Exception:
            logger.warning(
                "EPSS batch query failed for %d CVEs",
                len(cve_ids),
                exc_info=True,
            )
            return {}

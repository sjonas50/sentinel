"""NVD (National Vulnerability Database) API v2 client.

Queries the NIST NVD for CVE data by keyword search. Handles pagination
and rate limiting (5 req/30s without API key, 50 req/30s with key).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# NVD rate limits
_RATE_LIMIT_NO_KEY = 5  # requests per 30 seconds
_RATE_LIMIT_WITH_KEY = 50
_RATE_WINDOW = 30.0  # seconds
_PAGE_SIZE = 50  # results per page (max 2000, keep low for safety)


class NvdCveRecord(BaseModel):
    """Parsed CVE record from the NVD API response."""

    cve_id: str
    description: str | None = None
    cvss_v31_score: float | None = None
    cvss_v31_vector: str | None = None
    published_date: datetime | None = None


class _RateLimiter:
    """Sliding-window rate limiter for NVD API calls."""

    def __init__(self, max_calls: int, window: float) -> None:
        self._max_calls = max_calls
        self._window = window
        self._timestamps: list[float] = []

    async def acquire(self) -> None:
        now = time.monotonic()
        # Remove timestamps outside the window
        self._timestamps = [
            t for t in self._timestamps
            if now - t < self._window
        ]
        if len(self._timestamps) >= self._max_calls:
            oldest = self._timestamps[0]
            sleep_time = self._window - (now - oldest) + 0.1
            if sleep_time > 0:
                logger.debug(
                    "NVD rate limit: sleeping %.1fs", sleep_time
                )
                await asyncio.sleep(sleep_time)
        self._timestamps.append(time.monotonic())


class NvdClient:
    """Async client for the NVD API v2."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client
        max_calls = (
            _RATE_LIMIT_WITH_KEY if api_key else _RATE_LIMIT_NO_KEY
        )
        self._limiter = _RateLimiter(max_calls, _RATE_WINDOW)

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def search_cves(
        self,
        keyword: str,
        *,
        max_results: int = 100,
    ) -> list[NvdCveRecord]:
        """Search NVD by keyword, returning parsed CVE records."""
        client = self._http_client or httpx.AsyncClient()
        owns_client = self._http_client is None
        try:
            records: list[NvdCveRecord] = []
            start_index = 0

            while len(records) < max_results:
                await self._limiter.acquire()
                resp = await client.get(
                    self._base_url,
                    params={
                        "keywordSearch": keyword,
                        "startIndex": start_index,
                        "resultsPerPage": min(
                            _PAGE_SIZE, max_results - len(records)
                        ),
                    },
                    headers=self._headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                for item in vulns:
                    record = _parse_nvd_item(item)
                    if record:
                        records.append(record)

                total_results = data.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total_results:
                    break

            return records[:max_results]
        finally:
            if owns_client:
                await client.aclose()

    async def get_cve(
        self, cve_id: str
    ) -> NvdCveRecord | None:
        """Fetch a single CVE by ID."""
        client = self._http_client or httpx.AsyncClient()
        owns_client = self._http_client is None
        try:
            await self._limiter.acquire()
            resp = await client.get(
                self._base_url,
                params={"cveId": cve_id},
                headers=self._headers(),
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return _parse_nvd_item(vulns[0])
            return None
        finally:
            if owns_client:
                await client.aclose()


def _parse_nvd_item(item: dict[str, Any]) -> NvdCveRecord | None:
    """Parse a single NVD vulnerability item into an NvdCveRecord."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Extract English description
    description = None
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    # Extract CVSS v3.1 scores
    cvss_score = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    cvss_v31_list = metrics.get("cvssMetricV31", [])
    if cvss_v31_list:
        cvss_data = cvss_v31_list[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")

    # Extract published date
    published = cve.get("published")
    published_date = None
    if published:
        with contextlib.suppress(ValueError, TypeError):
            published_date = datetime.fromisoformat(
                published.replace("Z", "+00:00")
            )

    return NvdCveRecord(
        cve_id=cve_id,
        description=description,
        cvss_v31_score=cvss_score,
        cvss_v31_vector=cvss_vector,
        published_date=published_date,
    )

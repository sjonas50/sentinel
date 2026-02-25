"""Tests for the CISA KEV catalog client."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from sentinel_api.services.kev_client import KevClient

_SAMPLE_KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-1234"},
        {"cveID": "CVE-2024-5678"},
        {"cveID": "CVE-2023-9999"},
    ]
}


def _mock_client(json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()

    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.aclose = AsyncMock()
    return client


def test_kev_fetch_catalog() -> None:
    http = _mock_client(_SAMPLE_KEV)
    kev = KevClient(kev_url="https://example.com/kev.json", http_client=http)
    catalog = asyncio.run(kev.fetch_catalog())
    assert catalog == {"CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9999"}


def test_kev_is_known_exploited() -> None:
    http = _mock_client(_SAMPLE_KEV)
    kev = KevClient(kev_url="https://example.com/kev.json", http_client=http)
    assert asyncio.run(kev.is_known_exploited("CVE-2024-1234")) is True
    assert asyncio.run(kev.is_known_exploited("CVE-9999-0001")) is False


def test_kev_cache_reuses_data() -> None:
    """Second call should not make another HTTP request."""
    http = _mock_client(_SAMPLE_KEV)
    kev = KevClient(kev_url="https://example.com/kev.json", http_client=http)
    asyncio.run(kev.fetch_catalog())
    asyncio.run(kev.fetch_catalog())
    # Only 1 HTTP call even though fetch_catalog called twice
    assert http.get.call_count == 1


def test_kev_cache_expires() -> None:
    """Cache expires after TTL, triggering a fresh fetch."""
    http = _mock_client(_SAMPLE_KEV)
    kev = KevClient(
        kev_url="https://example.com/kev.json",
        http_client=http,
        ttl_seconds=0,  # Expire immediately
    )
    asyncio.run(kev.fetch_catalog())
    asyncio.run(kev.fetch_catalog())
    assert http.get.call_count == 2


def test_kev_empty_catalog() -> None:
    http = _mock_client({"vulnerabilities": []})
    kev = KevClient(kev_url="https://example.com/kev.json", http_client=http)
    catalog = asyncio.run(kev.fetch_catalog())
    assert catalog == set()

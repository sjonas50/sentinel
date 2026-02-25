"""Tests for the EPSS API client."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from sentinel_api.services.epss_client import EpssClient


def _mock_client(json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()

    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.aclose = AsyncMock()
    return client


def test_epss_single_cve() -> None:
    http = _mock_client({
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.00512", "percentile": "0.73"}
        ]
    })
    epss = EpssClient(base_url="https://example.com/epss", http_client=http)
    scores = asyncio.run(epss.get_scores(["CVE-2024-1234"]))
    assert scores == {"CVE-2024-1234": 0.00512}


def test_epss_multiple_cves() -> None:
    http = _mock_client({
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.5", "percentile": "0.9"},
            {"cve": "CVE-2024-5678", "epss": "0.01", "percentile": "0.3"},
        ]
    })
    epss = EpssClient(base_url="https://example.com/epss", http_client=http)
    scores = asyncio.run(epss.get_scores(["CVE-2024-1234", "CVE-2024-5678"]))
    assert scores["CVE-2024-1234"] == 0.5
    assert scores["CVE-2024-5678"] == 0.01


def test_epss_empty_input() -> None:
    http = _mock_client({"data": []})
    epss = EpssClient(base_url="https://example.com/epss", http_client=http)
    scores = asyncio.run(epss.get_scores([]))
    assert scores == {}
    # No HTTP call should be made
    http.get.assert_not_called()


def test_epss_missing_cve_omitted() -> None:
    """CVEs not in EPSS response are omitted from result."""
    http = _mock_client({
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.1", "percentile": "0.5"}
        ]
    })
    epss = EpssClient(base_url="https://example.com/epss", http_client=http)
    scores = asyncio.run(
        epss.get_scores(["CVE-2024-1234", "CVE-2024-9999"])
    )
    assert "CVE-2024-1234" in scores
    assert "CVE-2024-9999" not in scores


def test_epss_batch_chunking() -> None:
    """More than 30 CVEs should be chunked into multiple requests."""
    http = _mock_client({"data": []})
    epss = EpssClient(base_url="https://example.com/epss", http_client=http)
    cve_ids = [f"CVE-2024-{i:04d}" for i in range(35)]
    asyncio.run(epss.get_scores(cve_ids))
    # Should make 2 calls: 30 + 5
    assert http.get.call_count == 2

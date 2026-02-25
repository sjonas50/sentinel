"""Tests for the NVD API v2 client."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from sentinel_api.services.nvd_client import NvdClient, _parse_nvd_item


def _make_nvd_response(
    cve_id: str = "CVE-2024-1234",
    description: str = "A test vuln",
    base_score: float = 8.1,
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    total_results: int = 1,
) -> dict:
    return {
        "totalResults": total_results,
        "resultsPerPage": 1,
        "startIndex": 0,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-15T10:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": description},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": base_score,
                                    "vectorString": vector,
                                }
                            }
                        ]
                    },
                }
            }
        ],
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


def test_nvd_search_cves() -> None:
    data = _make_nvd_response()
    http = _mock_client(data)
    nvd = NvdClient(
        base_url="https://example.com/nvd",
        http_client=http,
    )
    records = asyncio.run(nvd.search_cves("apache http server"))
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-1234"
    assert records[0].cvss_v31_score == 8.1
    assert records[0].description == "A test vuln"
    assert records[0].published_date is not None


def test_nvd_search_empty_results() -> None:
    data = {"totalResults": 0, "vulnerabilities": []}
    http = _mock_client(data)
    nvd = NvdClient(
        base_url="https://example.com/nvd",
        http_client=http,
    )
    records = asyncio.run(nvd.search_cves("nonexistent"))
    assert records == []


def test_nvd_get_cve() -> None:
    data = _make_nvd_response(cve_id="CVE-2024-9999")
    http = _mock_client(data)
    nvd = NvdClient(
        base_url="https://example.com/nvd",
        http_client=http,
    )
    record = asyncio.run(nvd.get_cve("CVE-2024-9999"))
    assert record is not None
    assert record.cve_id == "CVE-2024-9999"


def test_nvd_get_cve_not_found() -> None:
    data = {"totalResults": 0, "vulnerabilities": []}
    http = _mock_client(data)
    nvd = NvdClient(
        base_url="https://example.com/nvd",
        http_client=http,
    )
    record = asyncio.run(nvd.get_cve("CVE-0000-0000"))
    assert record is None


def test_nvd_pagination() -> None:
    """Multiple pages are fetched until totalResults is reached."""
    page1 = _make_nvd_response(
        cve_id="CVE-2024-0001", total_results=2
    )
    page2 = {
        "totalResults": 2,
        "resultsPerPage": 1,
        "startIndex": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "descriptions": [
                        {"lang": "en", "value": "Second vuln"},
                    ],
                    "metrics": {},
                }
            }
        ],
    }
    responses = [page1, page2]
    call_count = 0

    async def mock_get(*args, **kwargs):
        nonlocal call_count
        resp = MagicMock()
        resp.json.return_value = responses[call_count]
        resp.raise_for_status = MagicMock()
        call_count += 1
        return resp

    http = AsyncMock()
    http.get = mock_get
    http.aclose = AsyncMock()

    nvd = NvdClient(
        base_url="https://example.com/nvd",
        http_client=http,
    )
    records = asyncio.run(nvd.search_cves("test", max_results=10))
    assert len(records) == 2
    assert records[0].cve_id == "CVE-2024-0001"
    assert records[1].cve_id == "CVE-2024-0002"


def test_nvd_max_results_limit() -> None:
    """search_cves respects max_results parameter."""
    data = _make_nvd_response(total_results=100)
    http = _mock_client(data)
    nvd = NvdClient(
        base_url="https://example.com/nvd",
        http_client=http,
    )
    records = asyncio.run(nvd.search_cves("test", max_results=1))
    assert len(records) <= 1


def test_nvd_api_key_in_headers() -> None:
    """API key is sent in headers when configured."""
    data = _make_nvd_response()
    http = _mock_client(data)
    nvd = NvdClient(
        base_url="https://example.com/nvd",
        api_key="test-key-123",
        http_client=http,
    )
    asyncio.run(nvd.search_cves("test"))
    call_kwargs = http.get.call_args
    headers = call_kwargs.kwargs.get("headers", {})
    assert headers.get("apiKey") == "test-key-123"


def test_parse_nvd_item_no_cvss() -> None:
    """Items without CVSS metrics parse correctly."""
    item = {
        "cve": {
            "id": "CVE-2024-0001",
            "descriptions": [
                {"lang": "en", "value": "No score vuln"}
            ],
            "metrics": {},
        }
    }
    record = _parse_nvd_item(item)
    assert record is not None
    assert record.cve_id == "CVE-2024-0001"
    assert record.cvss_v31_score is None
    assert record.cvss_v31_vector is None


def test_parse_nvd_item_missing_id() -> None:
    """Items without a CVE ID return None."""
    item = {"cve": {"descriptions": []}}
    record = _parse_nvd_item(item)
    assert record is None

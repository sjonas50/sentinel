"""Tests for the vulnerability correlation engine."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from sentinel_api.services.vuln_correlation import (
    CorrelationResult,
    VulnCorrelationEngine,
    cvss_to_severity,
)


def test_cvss_to_severity_critical() -> None:
    assert str(cvss_to_severity(9.8)) == "critical"
    assert str(cvss_to_severity(9.0)) == "critical"
    assert str(cvss_to_severity(10.0)) == "critical"


def test_cvss_to_severity_high() -> None:
    assert str(cvss_to_severity(8.9)) == "high"
    assert str(cvss_to_severity(7.0)) == "high"


def test_cvss_to_severity_medium() -> None:
    assert str(cvss_to_severity(6.9)) == "medium"
    assert str(cvss_to_severity(4.0)) == "medium"


def test_cvss_to_severity_low() -> None:
    assert str(cvss_to_severity(3.9)) == "low"
    assert str(cvss_to_severity(0.1)) == "low"


def test_cvss_to_severity_none() -> None:
    assert str(cvss_to_severity(0.0)) == "none"
    assert str(cvss_to_severity(None)) == "none"


def _make_nvd_record(
    cve_id: str = "CVE-2024-1234",
    score: float = 8.1,
) -> MagicMock:
    r = MagicMock()
    r.cve_id = cve_id
    r.description = f"Description for {cve_id}"
    r.cvss_v31_score = score
    r.cvss_v31_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    r.published_date = None
    return r


class _AsyncRecordIter:
    """Async iterator over mock Neo4j records."""

    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self._index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._records):
            raise StopAsyncIteration
        record = self._records[self._index]
        self._index += 1
        return record


def _make_neo4j_driver(services: list[dict]) -> MagicMock:
    """Create a mock Neo4j driver that returns given services."""
    records = [{"s": svc} for svc in services]

    async def mock_run(cypher, **params):
        result = _AsyncRecordIter(records)
        return result

    session = MagicMock()
    session.run = mock_run
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    driver = MagicMock()
    driver.session.return_value = session
    return driver


def test_correlate_tenant_no_services() -> None:
    """Empty graph returns zero results."""
    driver = _make_neo4j_driver([])
    nvd = MagicMock()
    epss = MagicMock()
    kev = MagicMock()

    engine = VulnCorrelationEngine(driver, nvd, epss, kev)
    result = asyncio.run(engine.correlate_tenant(uuid4()))
    assert isinstance(result, CorrelationResult)
    assert result.services_scanned == 0
    assert result.vulnerabilities_found == 0


def test_correlate_tenant_with_services() -> None:
    """Services with NVD matches produce vulnerabilities."""
    services = [
        {"id": "svc-1", "name": "Apache HTTP Server", "version": "2.4.54"},
    ]
    driver = _make_neo4j_driver(services)

    nvd_record = _make_nvd_record(score=9.1)
    nvd = MagicMock()
    nvd.search_cves = AsyncMock(return_value=[nvd_record])

    epss = MagicMock()
    epss.get_scores = AsyncMock(
        return_value={"CVE-2024-1234": 0.42}
    )

    kev = MagicMock()
    kev.fetch_catalog = AsyncMock(return_value={"CVE-2024-1234"})

    engine = VulnCorrelationEngine(driver, nvd, epss, kev)
    result = asyncio.run(engine.correlate_tenant(uuid4()))

    assert result.services_scanned == 1
    assert result.vulnerabilities_found == 1
    assert result.critical_count == 1
    assert result.kev_count == 1


def test_correlate_service_single() -> None:
    """Correlating a single service works."""
    services = [
        {"id": "svc-1", "name": "nginx", "version": "1.24.0"},
    ]
    driver = _make_neo4j_driver(services)

    nvd_record = _make_nvd_record(cve_id="CVE-2024-5555", score=5.0)
    nvd = MagicMock()
    nvd.search_cves = AsyncMock(return_value=[nvd_record])

    epss = MagicMock()
    epss.get_scores = AsyncMock(return_value={})

    kev = MagicMock()
    kev.fetch_catalog = AsyncMock(return_value=set())

    engine = VulnCorrelationEngine(driver, nvd, epss, kev)
    result = asyncio.run(
        engine.correlate_service(uuid4(), uuid4())
    )
    assert result.services_scanned == 1
    assert result.vulnerabilities_found == 1


def test_correlate_nvd_failure_partial() -> None:
    """NVD failure for one service doesn't block others."""
    services = [
        {"id": "svc-1", "name": "Apache", "version": "2.4"},
        {"id": "svc-2", "name": "nginx", "version": "1.24"},
    ]
    driver = _make_neo4j_driver(services)

    call_count = 0

    async def nvd_search(keyword, **kw):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("NVD timeout")
        return [_make_nvd_record(cve_id="CVE-2024-9999", score=4.0)]

    nvd = MagicMock()
    nvd.search_cves = nvd_search

    epss = MagicMock()
    epss.get_scores = AsyncMock(return_value={})

    kev = MagicMock()
    kev.fetch_catalog = AsyncMock(return_value=set())

    engine = VulnCorrelationEngine(driver, nvd, epss, kev)
    result = asyncio.run(engine.correlate_tenant(uuid4()))
    assert result.services_scanned == 2
    assert result.vulnerabilities_found == 1
    assert len(result.errors) >= 1


def test_correlation_result_model() -> None:
    """CorrelationResult is a valid Pydantic model."""
    r = CorrelationResult(
        services_scanned=5,
        vulnerabilities_found=10,
        critical_count=2,
        high_count=3,
        kev_count=1,
    )
    data = r.model_dump()
    assert data["services_scanned"] == 5
    assert data["kev_count"] == 1

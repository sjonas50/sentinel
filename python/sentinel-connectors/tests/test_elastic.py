"""Elasticsearch SIEM connector tests using mocked ES client."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sentinel_connectors.siem.elastic import ElasticConnector

# ── Environment setup ─────────────────────────────────────────────


def _set_elastic_env() -> None:
    """Set fake Elastic credentials."""
    os.environ["ELASTIC_HOSTS"] = "http://localhost:9200"
    os.environ["ELASTIC_AUTH_METHOD"] = "basic"
    os.environ["ELASTIC_USERNAME"] = "elastic"
    os.environ["ELASTIC_PASSWORD"] = "changeme"
    os.environ["ELASTIC_VERIFY_CERTS"] = "false"


# ── Factory helpers ───────────────────────────────────────────────


def _make_hit(
    index: str = "filebeat-2024.01.01",
    source: dict | None = None,
    _id: str = "doc-1",
) -> dict:
    return {
        "_index": index,
        "_id": _id,
        "_source": source or {},
    }


def _make_search_response(
    hits: list[dict] | None = None,
    total: int = 0,
    took_ms: int = 5,
) -> dict:
    return {
        "took": took_ms,
        "timed_out": False,
        "hits": {
            "total": {"value": total, "relation": "eq"},
            "hits": hits or [],
        },
    }


def _make_cat_indices(names: list[str]) -> list[dict]:
    return [
        {
            "index": name,
            "docs.count": "1000",
            "store.size": "10mb",
            "creation.date": "1704067200000",  # 2024-01-01
        }
        for name in names
    ]


def _make_mapping(fields: dict[str, str]) -> dict:
    properties = {}
    for field_name, field_type in fields.items():
        parts = field_name.split(".")
        current = properties
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                current[part] = {"type": field_type}
            else:
                if part not in current:
                    current[part] = {"properties": {}}
                current = current[part]["properties"]
    return {"mappings": {"properties": properties}}


# ── Mock ES client ────────────────────────────────────────────────


class MockAsyncElasticsearch:
    """Mock AsyncElasticsearch client for testing."""

    def __init__(
        self,
        *,
        ping_ok: bool = True,
        indices_list: list[str] | None = None,
        mappings: dict[str, dict] | None = None,
        search_response: dict | None = None,
        cluster_name: str = "sentinel-dev",
        cluster_version: str = "8.17.0",
    ) -> None:
        self._ping_ok = ping_ok
        self._indices_list = indices_list or []
        self._mappings = mappings or {}
        self._search_response = search_response or _make_search_response()
        self._cluster_name = cluster_name
        self._cluster_version = cluster_version

        self.cat = MagicMock()
        self.cat.indices = AsyncMock(return_value=_make_cat_indices(self._indices_list))
        self.indices = MagicMock()
        self.indices.get_mapping = AsyncMock(side_effect=self._get_mapping)

    async def ping(self) -> bool:
        return self._ping_ok

    async def info(self) -> dict:
        return {
            "cluster_name": self._cluster_name,
            "version": {"number": self._cluster_version},
        }

    async def search(self, **kwargs) -> dict:
        return self._search_response

    async def close(self) -> None:
        pass

    async def _get_mapping(self, index: str) -> dict:
        return {index: self._mappings.get(index, {"mappings": {"properties": {}}})}


# ── Tests ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _env_setup():
    _set_elastic_env()
    yield
    for key in (
        "ELASTIC_HOSTS",
        "ELASTIC_AUTH_METHOD",
        "ELASTIC_USERNAME",
        "ELASTIC_PASSWORD",
        "ELASTIC_VERIFY_CERTS",
    ):
        os.environ.pop(key, None)


def _make_connector(mock_client: MockAsyncElasticsearch) -> ElasticConnector:
    """Create a connector with a mocked ES client."""
    with patch.object(ElasticConnector, "_build_client", return_value=mock_client):
        return ElasticConnector(tenant_id=uuid4())


@pytest.mark.asyncio
async def test_health_check_success() -> None:
    connector = _make_connector(MockAsyncElasticsearch(ping_ok=True))
    assert await connector.health_check() is True


@pytest.mark.asyncio
async def test_health_check_failure() -> None:
    connector = _make_connector(MockAsyncElasticsearch(ping_ok=False))
    assert await connector.health_check() is False


@pytest.mark.asyncio
async def test_discover_indices() -> None:
    mock_client = MockAsyncElasticsearch(
        indices_list=["filebeat-2024.01.01", "winlogbeat-2024.01.01"],
        mappings={
            "filebeat-2024.01.01": _make_mapping(
                {
                    "@timestamp": "date",
                    "source.ip": "ip",
                    "message": "text",
                }
            ),
            "winlogbeat-2024.01.01": _make_mapping(
                {
                    "@timestamp": "date",
                    "event.category": "keyword",
                }
            ),
        },
    )
    connector = _make_connector(mock_client)
    result = await connector.discover_indices()

    assert result.cluster_name == "sentinel-dev"
    assert result.cluster_version == "8.17.0"
    assert result.total_indices == 2
    assert len(result.indices) == 2
    assert result.indices[0].name == "filebeat-2024.01.01"
    assert result.indices[0].doc_count == 1000
    assert "@timestamp" in result.indices[0].field_mappings


@pytest.mark.asyncio
async def test_discover_indices_filters_system() -> None:
    mock_client = MockAsyncElasticsearch(
        indices_list=[".internal-security", ".kibana", "filebeat-2024.01.01"],
    )
    # Override cat.indices to include system indices
    mock_client.cat.indices = AsyncMock(
        return_value=_make_cat_indices([".internal-security", ".kibana", "filebeat-2024.01.01"])
    )
    connector = _make_connector(mock_client)
    result = await connector.discover_indices()

    assert result.total_indices == 1
    assert result.indices[0].name == "filebeat-2024.01.01"


@pytest.mark.asyncio
async def test_execute_query_basic() -> None:
    hits = [
        _make_hit(
            source={
                "@timestamp": "2024-01-01T12:00:00Z",
                "source": {"ip": "10.0.0.1", "port": 54321},
                "destination": {"ip": "10.0.0.2", "port": 22},
                "event": {"category": "authentication"},
                "user": {"name": "admin"},
                "message": "SSH login failed",
            },
            _id="hit-1",
        ),
    ]
    response = _make_search_response(hits=hits, total=1, took_ms=3)
    mock_client = MockAsyncElasticsearch(search_response=response)
    connector = _make_connector(mock_client)

    result = await connector.execute_query(
        query_dsl={"match_all": {}},
        index="filebeat-*",
    )

    assert result.total_hits == 1
    assert result.took_ms == 3
    assert not result.timed_out
    assert len(result.events) == 1

    event = result.events[0]
    assert event.id == "hit-1"
    assert event.source_ip == "10.0.0.1"
    assert event.dest_ip == "10.0.0.2"
    assert event.source_port == 54321
    assert event.dest_port == 22
    assert event.event_type == "authentication"
    assert event.user == "admin"
    assert event.message == "SSH login failed"


@pytest.mark.asyncio
async def test_normalize_event_ecs_format() -> None:
    connector = _make_connector(MockAsyncElasticsearch())
    hit = _make_hit(
        source={
            "@timestamp": "2024-01-15T10:30:00Z",
            "source": {"ip": "192.168.1.10"},
            "destination": {"ip": "10.0.0.5"},
            "event": {"category": "network", "severity": "warning"},
            "host": {"name": "web-server-01"},
            "user": {"name": "deploy-bot"},
            "message": "Unusual outbound connection",
        }
    )
    event = connector._normalize_event(hit)

    assert event.timestamp == datetime(2024, 1, 15, 10, 30, tzinfo=UTC)
    assert event.source_ip == "192.168.1.10"
    assert event.dest_ip == "10.0.0.5"
    assert event.event_type == "network"
    assert event.severity == "warning"
    assert event.hostname == "web-server-01"
    assert event.user == "deploy-bot"


@pytest.mark.asyncio
async def test_normalize_event_legacy_format() -> None:
    connector = _make_connector(MockAsyncElasticsearch())
    hit = _make_hit(
        source={
            "timestamp": "2024-06-01T08:00:00+00:00",
            "src_ip": "172.16.0.1",
            "dst_ip": "10.0.0.99",
            "src_port": 12345,
            "dst_port": 443,
            "event_type": "firewall",
            "hostname": "fw-edge-01",
            "username": "n/a",
        }
    )
    event = connector._normalize_event(hit)

    assert event.source_ip == "172.16.0.1"
    assert event.dest_ip == "10.0.0.99"
    assert event.source_port == 12345
    assert event.dest_port == 443
    assert event.event_type == "firewall"
    assert event.hostname == "fw-edge-01"
    assert event.user == "n/a"


@pytest.mark.asyncio
async def test_normalize_event_minimal() -> None:
    connector = _make_connector(MockAsyncElasticsearch())
    hit = {"_id": "minimal-1", "_index": "test-index", "_source": {}}
    event = connector._normalize_event(hit)

    assert event.id == "minimal-1"
    assert event.index == "test-index"
    assert event.timestamp is None
    assert event.source_ip is None
    assert event.dest_ip is None
    assert event.raw == {}


@pytest.mark.asyncio
async def test_discover_creates_service_node() -> None:
    mock_client = MockAsyncElasticsearch(
        indices_list=["logs-2024"],
        cluster_name="prod-cluster",
        cluster_version="8.17.0",
    )
    connector = _make_connector(mock_client)
    result = await connector.sync()

    assert len(result.services) == 1
    svc = result.services[0]
    assert svc.name == "elasticsearch/prod-cluster"
    assert svc.version == "8.17.0"
    assert svc.port == 9200


@pytest.mark.asyncio
async def test_sync_engram_trail() -> None:
    mock_client = MockAsyncElasticsearch(indices_list=["filebeat-2024"])
    connector = _make_connector(mock_client)
    result = await connector.sync()

    assert len(result.errors) == 0
    assert result.connector_name == "elastic"


@pytest.mark.asyncio
async def test_execute_query_empty_results() -> None:
    response = _make_search_response(hits=[], total=0)
    mock_client = MockAsyncElasticsearch(search_response=response)
    connector = _make_connector(mock_client)

    result = await connector.execute_query(
        query_dsl={"term": {"user.name": "nonexistent"}},
        index="filebeat-*",
    )

    assert result.total_hits == 0
    assert len(result.events) == 0


def test_parse_size() -> None:
    assert ElasticConnector._parse_size("10mb") == 10 * 1024**2
    assert ElasticConnector._parse_size("1.5gb") == int(1.5 * 1024**3)
    assert ElasticConnector._parse_size("500kb") == 500 * 1024
    assert ElasticConnector._parse_size("1024b") == 1024
    assert ElasticConnector._parse_size("0") == 0
    assert ElasticConnector._parse_size("") == 0

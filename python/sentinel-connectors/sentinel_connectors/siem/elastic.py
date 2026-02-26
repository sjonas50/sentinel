"""Elasticsearch / OpenSearch SIEM connector.

Provides index discovery and query execution against Elasticsearch
or OpenSearch clusters. Uses the official ``elasticsearch[async]`` client.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from elasticsearch import AsyncElasticsearch
from sentinel_api.models.core import Protocol, Service, ServiceState

from sentinel_connectors.base import BaseConnector, SyncResult
from sentinel_connectors.credentials import ElasticCredentials
from sentinel_connectors.registry import register
from sentinel_connectors.retry import RateLimiter
from sentinel_connectors.siem.models import (
    IndexDiscoveryResult,
    IndexInfo,
    QueryResult,
    SiemEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_api.engram.session import EngramSession

logger = logging.getLogger(__name__)


@register
class ElasticConnector(BaseConnector):
    """Elasticsearch / OpenSearch SIEM connector.

    Provides two capabilities:

    1. **Index discovery** (via ``discover()``) — finds available log
       indices, their field mappings, and creates a Service node for
       the cluster in the digital twin graph.
    2. **Query execution** (via ``execute_query()``) — runs Elasticsearch
       DSL queries and returns normalized ``SiemEvent`` results.
    """

    NAME = "elastic"

    def __init__(self, tenant_id: UUID, config: dict[str, Any] | None = None) -> None:
        super().__init__(tenant_id, config)
        self._creds = ElasticCredentials.from_env()
        self._client = self._build_client(self._creds)
        self._limiter = RateLimiter(calls_per_second=10.0)

    @property
    def name(self) -> str:
        return "elastic"

    async def health_check(self) -> bool:
        """Verify connectivity to the Elasticsearch cluster."""
        try:
            return await self._client.ping()
        except Exception:
            logger.exception("Elasticsearch health check failed")
            return False

    async def discover(self, session: EngramSession) -> SyncResult:
        """Discover available indices and create a Service node for the cluster."""
        result = SyncResult(connector_name=self.name)

        try:
            discovery = await self.discover_indices()
            session.add_action(
                action_type="discover_indices",
                description=(
                    f"Discovered {discovery.total_indices} indices "
                    f"on cluster {discovery.cluster_name}"
                ),
                details={
                    "cluster_name": discovery.cluster_name,
                    "cluster_version": discovery.cluster_version,
                    "total_indices": discovery.total_indices,
                    "index_names": [idx.name for idx in discovery.indices],
                },
                success=True,
            )

            # Create a Service node representing the ES cluster
            cluster_service = Service(
                tenant_id=self.tenant_id,
                name=f"elasticsearch/{discovery.cluster_name}",
                version=discovery.cluster_version,
                port=9200,
                protocol=Protocol.HTTPS,
                state=ServiceState.RUNNING,
                banner=f"Elasticsearch {discovery.cluster_version}",
            )
            result.services.append(cluster_service)

        except Exception as exc:
            session.add_action(
                action_type="discover_indices_failed",
                description=str(exc),
                success=False,
            )
            result.errors.append(f"Index discovery failed: {exc}")

        return result

    async def discover_indices(self, pattern: str = "*") -> IndexDiscoveryResult:
        """Discover available indices with their field mappings.

        Args:
            pattern: Index name pattern to match (default: all non-system).

        Returns:
            Index metadata including field mappings and document counts.
        """
        await self._limiter.acquire()

        # Get cluster info
        info = await self._client.info()
        cluster_name = info["cluster_name"]
        cluster_version = info["version"]["number"]

        # List indices
        await self._limiter.acquire()
        cat_indices = await self._client.cat.indices(
            index=pattern, format="json", h="index,docs.count,store.size,creation.date"
        )

        # Filter system indices (starting with ".")
        user_indices = [idx for idx in cat_indices if not idx.get("index", "").startswith(".")]

        # Get mappings for each index
        indices: list[IndexInfo] = []
        for idx_info in user_indices:
            idx_name = idx_info["index"]
            await self._limiter.acquire()

            try:
                mapping_resp = await self._client.indices.get_mapping(index=idx_name)
                field_mappings = self._extract_field_mappings(mapping_resp.get(idx_name, {}))
            except Exception:
                logger.warning("Failed to get mapping for index %s", idx_name)
                field_mappings = {}

            creation_date = None
            if idx_info.get("creation.date"):
                with contextlib.suppress(ValueError, TypeError):
                    creation_date = datetime.fromtimestamp(
                        int(idx_info["creation.date"]) / 1000, tz=UTC
                    )

            indices.append(
                IndexInfo(
                    name=idx_name,
                    doc_count=int(idx_info.get("docs.count", 0) or 0),
                    size_bytes=self._parse_size(idx_info.get("store.size", "0")),
                    field_mappings=field_mappings,
                    creation_date=creation_date,
                )
            )

        return IndexDiscoveryResult(
            indices=indices,
            cluster_name=cluster_name,
            cluster_version=cluster_version,
            total_indices=len(indices),
        )

    async def execute_query(
        self,
        query_dsl: dict[str, Any],
        index: str,
        *,
        size: int = 100,
        sort: list[dict[str, Any]] | None = None,
        aggs: dict[str, Any] | None = None,
    ) -> QueryResult:
        """Execute an Elasticsearch DSL query and return normalized results.

        Args:
            query_dsl: The ``query`` portion of the Elasticsearch request body.
            index: Index name or pattern to search.
            size: Maximum number of results.
            sort: Sort specification.
            aggs: Aggregation specification.
        """
        await self._limiter.acquire()

        body: dict[str, Any] = {"query": query_dsl, "size": size}
        if sort:
            body["sort"] = sort
        if aggs:
            body["aggs"] = aggs

        response = await self._client.search(index=index, body=body)

        hits = response.get("hits", {})
        events = [self._normalize_event(hit) for hit in hits.get("hits", [])]

        total = hits.get("total", {})
        total_hits = total.get("value", 0) if isinstance(total, dict) else int(total)

        return QueryResult(
            events=events,
            total_hits=total_hits,
            took_ms=response.get("took", 0),
            query_dsl=query_dsl,
            timed_out=response.get("timed_out", False),
            aggregations=response.get("aggregations", {}),
        )

    async def close(self) -> None:
        """Close the Elasticsearch transport."""
        await self._client.close()

    # ── Private helpers ───────────────────────────────────────────

    def _normalize_event(self, hit: dict[str, Any]) -> SiemEvent:
        """Normalize an Elasticsearch hit into a SiemEvent.

        Handles ECS, Filebeat, and legacy field naming conventions.
        """
        source = hit.get("_source", {})

        return SiemEvent(
            id=hit.get("_id", ""),
            index=hit.get("_index", ""),
            timestamp=self._extract_timestamp(source),
            source_ip=self._get_nested(source, "source.ip", "src_ip", "source_address"),
            dest_ip=self._get_nested(source, "destination.ip", "dst_ip", "dest_address"),
            source_port=self._get_nested_int(source, "source.port", "src_port"),
            dest_port=self._get_nested_int(source, "destination.port", "dst_port"),
            event_type=self._get_nested(source, "event.category", "event_type", "type"),
            severity=self._get_nested(source, "event.severity", "severity", "log.level", "level"),
            message=self._get_nested(source, "message", "msg"),
            user=self._get_nested(source, "user.name", "username", "user_id"),
            hostname=self._get_nested(source, "host.name", "hostname", "host"),
            raw=source,
        )

    @staticmethod
    def _get_nested(source: dict[str, Any], *paths: str) -> str | None:
        """Try multiple field paths, supporting dotted notation."""
        for path in paths:
            parts = path.split(".")
            value: Any = source
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value is not None:
                return str(value)
        return None

    @staticmethod
    def _get_nested_int(source: dict[str, Any], *paths: str) -> int | None:
        """Try multiple field paths, returning an int or None."""
        for path in paths:
            parts = path.split(".")
            value: Any = source
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value is not None:
                try:
                    return int(value)
                except (ValueError, TypeError):
                    continue
        return None

    @staticmethod
    def _extract_timestamp(source: dict[str, Any]) -> datetime | None:
        """Extract timestamp from common field locations."""
        for field in ("@timestamp", "timestamp", "event.created"):
            parts = field.split(".")
            value: Any = source
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value is not None:
                try:
                    if isinstance(value, str):
                        return datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if isinstance(value, int | float):
                        return datetime.fromtimestamp(value / 1000, tz=UTC)
                except (ValueError, TypeError, OSError):
                    continue
        return None

    @staticmethod
    def _extract_field_mappings(mapping: dict[str, Any]) -> dict[str, str]:
        """Flatten Elasticsearch mapping properties into field_name -> type."""
        result: dict[str, str] = {}
        properties = mapping.get("mappings", {}).get("properties", {})

        def _flatten(props: dict[str, Any], prefix: str = "") -> None:
            for field_name, field_def in props.items():
                full_name = f"{prefix}{field_name}" if not prefix else f"{prefix}.{field_name}"
                if "type" in field_def:
                    result[full_name] = field_def["type"]
                if "properties" in field_def:
                    _flatten(field_def["properties"], full_name)

        _flatten(properties)
        return result

    @staticmethod
    def _parse_size(size_str: str) -> int:
        """Parse Elasticsearch size string (e.g. '1.2gb') to bytes."""
        if not size_str:
            return 0
        size_str = size_str.strip().lower()
        multipliers = {"tb": 1024**4, "gb": 1024**3, "mb": 1024**2, "kb": 1024, "b": 1}
        for suffix, mult in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[: -len(suffix)]) * mult)
                except ValueError:
                    return 0
        try:
            return int(size_str)
        except ValueError:
            return 0

    def _build_client(self, creds: ElasticCredentials) -> AsyncElasticsearch:
        """Configure and return an AsyncElasticsearch client."""
        kwargs: dict[str, Any] = {
            "hosts": list(creds.hosts),
            "verify_certs": creds.verify_certs,
            "request_timeout": 30,
            "retry_on_timeout": True,
            "max_retries": 3,
        }

        if creds.ca_certs:
            kwargs["ca_certs"] = creds.ca_certs

        if creds.auth_method == "api_key" and creds.api_key:
            kwargs["api_key"] = creds.api_key
        elif creds.username and creds.password:
            kwargs["basic_auth"] = (creds.username, creds.password)

        return AsyncElasticsearch(**kwargs)

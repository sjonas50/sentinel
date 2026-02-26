"""Data models for SIEM connector operations."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs runtime access
from typing import Any

from pydantic import BaseModel, Field


class IndexInfo(BaseModel):
    """Metadata about a discovered Elasticsearch index."""

    name: str
    doc_count: int = 0
    size_bytes: int = 0
    field_mappings: dict[str, str] = {}  # field_name -> ES type
    creation_date: datetime | None = None
    aliases: list[str] = []


class IndexDiscoveryResult(BaseModel):
    """Result of discovering available indices."""

    indices: list[IndexInfo]
    cluster_name: str
    cluster_version: str
    total_indices: int


class SiemEvent(BaseModel):
    """Normalized security event from a SIEM query result.

    Extracts common security fields from heterogeneous log formats
    (ECS, Filebeat, legacy) while preserving the full source document.
    """

    id: str
    index: str
    timestamp: datetime | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    event_type: str | None = None
    severity: str | None = None
    message: str | None = None
    user: str | None = None
    hostname: str | None = None
    raw: dict[str, Any] = {}


class QueryResult(BaseModel):
    """Result of an Elasticsearch query execution."""

    events: list[SiemEvent]
    total_hits: int
    took_ms: int
    query_dsl: dict[str, Any]
    timed_out: bool = False
    aggregations: dict[str, Any] = {}


class ElasticQueryDSL(BaseModel):
    """Structured output model for LLM-generated Elasticsearch DSL."""

    query: dict[str, Any]
    index_pattern: str
    sort: list[dict[str, Any]] = Field(default_factory=lambda: [{"@timestamp": {"order": "desc"}}])
    size: int = 100
    aggs: dict[str, Any] = {}
    explanation: str = ""

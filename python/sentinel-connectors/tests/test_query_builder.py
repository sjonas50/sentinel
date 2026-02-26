"""Tests for the Elasticsearch DSL query builder."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sentinel_agents.llm import MockLLMProvider
from sentinel_connectors.siem.models import IndexInfo
from sentinel_connectors.siem.query_builder import QueryBuilder

# ── DSL validation ────────────────────────────────────────────────


def test_validate_dsl_valid_query() -> None:
    builder = QueryBuilder()
    errors = builder.validate_dsl(
        {
            "bool": {
                "must": [{"match": {"message": "failed login"}}],
                "filter": [{"range": {"@timestamp": {"gte": "now-1h"}}}],
            }
        }
    )
    assert errors == []


def test_validate_dsl_rejects_script() -> None:
    builder = QueryBuilder()
    errors = builder.validate_dsl(
        {
            "bool": {
                "must": [{"script": {"source": "doc['field'].value > 5"}}],
            }
        }
    )
    assert len(errors) >= 1
    assert any("script" in e for e in errors)


def test_validate_dsl_rejects_delete() -> None:
    builder = QueryBuilder()
    errors = builder.validate_dsl(
        {
            "delete_by_query": {"match_all": {}},
        }
    )
    assert len(errors) >= 1
    assert any("delete" in e.lower() for e in errors)


def test_validate_dsl_rejects_painless() -> None:
    builder = QueryBuilder()
    errors = builder.validate_dsl(
        {
            "bool": {
                "must": [{"script_score": {"script": {"lang": "painless", "source": "1"}}}],
            }
        }
    )
    assert len(errors) >= 1


def test_validate_dsl_rejects_update() -> None:
    builder = QueryBuilder()
    errors = builder.validate_dsl({"_update": {"doc": {"field": "value"}}})
    assert len(errors) >= 1


def test_validate_dsl_not_a_dict() -> None:
    builder = QueryBuilder()
    errors = builder.validate_dsl("not a dict")  # type: ignore[arg-type]
    assert len(errors) >= 1
    assert any("dictionary" in e for e in errors)


# ── Programmatic DSL builders ─────────────────────────────────────


def test_build_time_range_filter() -> None:
    builder = QueryBuilder()
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 1, 2, tzinfo=UTC)
    result = builder.build_time_range_filter(start, end)

    assert "range" in result
    assert "@timestamp" in result["range"]
    assert result["range"]["@timestamp"]["gte"] == start.isoformat()
    assert result["range"]["@timestamp"]["lte"] == end.isoformat()


def test_build_time_range_filter_custom_field() -> None:
    builder = QueryBuilder()
    start = datetime(2024, 6, 1, tzinfo=UTC)
    end = datetime(2024, 6, 2, tzinfo=UTC)
    result = builder.build_time_range_filter(start, end, field="event.created")

    assert "event.created" in result["range"]


def test_build_ip_filter() -> None:
    builder = QueryBuilder()
    result = builder.build_ip_filter("10.0.0.1")

    assert result == {"term": {"source.ip": "10.0.0.1"}}


def test_build_ip_filter_custom_field() -> None:
    builder = QueryBuilder()
    result = builder.build_ip_filter("192.168.1.1", field="destination.ip")

    assert result == {"term": {"destination.ip": "192.168.1.1"}}


def test_build_aggregation() -> None:
    builder = QueryBuilder()
    result = builder.build_aggregation("source.ip", size=20)

    assert "source.ip_agg" in result
    assert result["source.ip_agg"]["terms"]["field"] == "source.ip"
    assert result["source.ip_agg"]["terms"]["size"] == 20


def test_build_aggregation_custom_type() -> None:
    builder = QueryBuilder()
    result = builder.build_aggregation("response_time", agg_type="avg")

    assert "response_time_agg" in result
    assert "avg" in result["response_time_agg"]


# ── NL → DSL with MockLLMProvider ────────────────────────────────


@pytest.mark.asyncio
async def test_nl_to_dsl_with_mock_llm() -> None:
    import json

    mock_response = json.dumps(
        {
            "query": {
                "bool": {
                    "must": [{"match": {"message": "failed login"}}],
                    "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                }
            },
            "index_pattern": "filebeat-*",
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 50,
            "aggs": {},
            "explanation": "Search for failed login events in the last 24 hours",
        }
    )

    llm = MockLLMProvider(responses=[mock_response])
    builder = QueryBuilder(llm=llm)

    indices = [
        IndexInfo(
            name="filebeat-2024.01.01",
            doc_count=10000,
            field_mappings={"@timestamp": "date", "message": "text", "source.ip": "ip"},
        ),
    ]

    result = await builder.natural_language_to_dsl(
        "Show me failed logins in the last 24 hours",
        available_indices=indices,
    )

    assert result.index_pattern == "filebeat-*"
    assert "bool" in result.query
    assert result.size == 50
    assert llm.call_count == 1


@pytest.mark.asyncio
async def test_nl_to_dsl_no_llm_raises() -> None:
    builder = QueryBuilder()  # no LLM

    with pytest.raises(RuntimeError, match="No LLM provider"):
        await builder.natural_language_to_dsl(
            "Show me failed logins",
            available_indices=[],
        )

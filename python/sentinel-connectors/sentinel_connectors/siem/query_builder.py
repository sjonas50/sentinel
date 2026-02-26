"""LLM-powered Elasticsearch DSL query builder with validation.

Translates natural language security questions into validated
Elasticsearch DSL queries. The LLM is optional — programmatic
DSL helpers work standalone.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, ClassVar

from sentinel_connectors.siem.models import ElasticQueryDSL

if TYPE_CHECKING:
    from datetime import datetime

    from sentinel_agents.llm import LLMProvider

    from sentinel_connectors.siem.models import IndexInfo

logger = logging.getLogger(__name__)

# Patterns that must never appear in LLM-generated DSL
_BLOCKED_PATTERNS: list[str] = [
    "script",
    "delete_by_query",
    "_delete",
    "_update",
    "_bulk",
    "painless",
    "groovy",
]


class QueryBuilder:
    """Translates natural language to Elasticsearch DSL using an LLM.

    The builder is schema-aware: it accepts index field mappings so the
    LLM can generate accurate field references. Generated DSL is
    validated before being returned.
    """

    _SYSTEM_PROMPT: ClassVar[str] = """You are an Elasticsearch query expert. Given a natural \
language security question, generate an Elasticsearch DSL query.

RULES:
- Use only field names from the provided index schemas
- Follow Elastic Common Schema (ECS) conventions
- Always include a time range filter when timestamps are available
- Use bool queries with must/should/filter/must_not
- Never use script queries or painless scripts
- Never generate delete, update, or bulk operations
- Respond with valid JSON matching the provided schema exactly

AVAILABLE INDICES AND FIELDS:
{schema_context}

TIME RANGE: {time_range}
MAX RESULTS: {max_results}
"""

    def __init__(self, llm: LLMProvider | None = None) -> None:
        self._llm = llm

    async def natural_language_to_dsl(
        self,
        question: str,
        available_indices: list[IndexInfo],
        *,
        time_range: tuple[datetime, datetime] | None = None,
        max_results: int = 100,
    ) -> ElasticQueryDSL:
        """Translate a natural language question to Elasticsearch DSL.

        Args:
            question: Natural language security question.
            available_indices: Available indices with their field mappings.
            time_range: Optional (start, end) time constraint.
            max_results: Maximum number of results to return.

        Returns:
            Validated ElasticQueryDSL ready for execution.

        Raises:
            RuntimeError: If no LLM provider is configured.
            ValueError: If the generated DSL fails validation.
        """
        if self._llm is None:
            msg = "No LLM provider configured. Pass an LLMProvider to QueryBuilder()."
            raise RuntimeError(msg)

        from sentinel_agents.llm import LLMMessage

        schema_context = self._build_schema_context(available_indices)
        time_range_str = "Not specified"
        if time_range:
            time_range_str = f"{time_range[0].isoformat()} to {time_range[1].isoformat()}"

        system = self._SYSTEM_PROMPT.format(
            schema_context=schema_context,
            time_range=time_range_str,
            max_results=max_results,
        )

        result = await self._llm.complete_structured(
            messages=[LLMMessage(role="user", content=question)],
            response_model=ElasticQueryDSL,
            system=system,
            max_tokens=2048,
        )

        # Validate the generated DSL
        errors = self.validate_dsl(result.query)
        if errors:
            msg = f"LLM generated invalid DSL: {'; '.join(errors)}"
            raise ValueError(msg)

        # Enforce max_results
        if result.size > max_results:
            result.size = max_results

        return result

    def validate_dsl(self, dsl: dict[str, Any]) -> list[str]:
        """Validate an Elasticsearch DSL query for safety and correctness.

        Returns:
            List of validation error strings. Empty means valid.
        """
        errors: list[str] = []

        if not isinstance(dsl, dict):
            errors.append("DSL must be a dictionary")
            return errors

        # Check for blocked patterns in the serialized DSL
        dsl_str = json.dumps(dsl).lower()
        for pattern in _BLOCKED_PATTERNS:
            if pattern in dsl_str:
                errors.append(f"Blocked pattern found: '{pattern}'")

        return errors

    @staticmethod
    def build_time_range_filter(
        start: datetime,
        end: datetime,
        field: str = "@timestamp",
    ) -> dict[str, Any]:
        """Build an Elasticsearch range filter for a time window."""
        return {
            "range": {
                field: {
                    "gte": start.isoformat(),
                    "lte": end.isoformat(),
                    "format": "strict_date_optional_time",
                }
            }
        }

    @staticmethod
    def build_ip_filter(ip: str, field: str = "source.ip") -> dict[str, Any]:
        """Build a term filter for an IP address."""
        return {"term": {field: ip}}

    @staticmethod
    def build_aggregation(field: str, agg_type: str = "terms", size: int = 10) -> dict[str, Any]:
        """Build a simple aggregation."""
        return {f"{field}_agg": {agg_type: {"field": field, "size": size}}}

    @staticmethod
    def _build_schema_context(indices: list[IndexInfo]) -> str:
        """Format index schemas for the LLM system prompt."""
        lines: list[str] = []
        for idx in indices:
            lines.append(f"\nIndex: {idx.name} ({idx.doc_count} documents)")
            if idx.field_mappings:
                for field_name, field_type in sorted(idx.field_mappings.items()):
                    lines.append(f"  - {field_name}: {field_type}")
        return "\n".join(lines) if lines else "No indices available."

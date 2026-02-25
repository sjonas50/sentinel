"""Tests for the OPA-based policy engine (mocked HTTP)."""

from __future__ import annotations

import httpx
import pytest
from sentinel_policy.engine import PolicyEngine
from sentinel_policy.models import PolicyInput, Tier


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(opa_url="http://localhost:8181")


@pytest.mark.asyncio
async def test_parse_allowed_result(engine: PolicyEngine) -> None:
    result = {"allow": True, "tier": "auto", "reasons": ["action_permitted"], "violations": []}
    decision = engine._parse_result(result)
    assert decision.allowed is True
    assert decision.tier == Tier.AUTO
    assert "action_permitted" in decision.reasons


@pytest.mark.asyncio
async def test_parse_denied_result(engine: PolicyEngine) -> None:
    result = {
        "allow": False,
        "tier": "deny",
        "violations": ["Action 'delete_data' is on the blocked list"],
        "reasons": ["blocked_action"],
    }
    decision = engine._parse_result(result)
    assert decision.allowed is False
    assert decision.tier == Tier.DENY
    assert len(decision.violations) == 1


@pytest.mark.asyncio
async def test_parse_unknown_tier_defaults_to_deny(engine: PolicyEngine) -> None:
    result = {"allow": False, "tier": "unknown_tier"}
    decision = engine._parse_result(result)
    assert decision.tier == Tier.DENY


@pytest.mark.asyncio
async def test_parse_fast_track_tier(engine: PolicyEngine) -> None:
    result = {"allow": True, "tier": "fast_track", "reasons": ["tier_fast_track"]}
    decision = engine._parse_result(result)
    assert decision.tier == Tier.FAST_TRACK


@pytest.mark.asyncio
async def test_parse_empty_result_denies(engine: PolicyEngine) -> None:
    decision = engine._parse_result({})
    assert decision.allowed is False
    assert decision.tier == Tier.DENY


@pytest.mark.asyncio
async def test_evaluate_connection_refused(engine: PolicyEngine) -> None:
    """When OPA is not reachable, deny by default."""
    # Use a port that's not listening
    engine._opa_url = "http://localhost:19999"
    engine._client = httpx.AsyncClient(base_url="http://localhost:19999", timeout=1.0)

    inp = PolicyInput(agent_id="h1", agent_type="hunt", action="query_logs")
    decision = await engine.evaluate("agent/base", inp)
    assert decision.allowed is False
    assert "OPA service unavailable" in decision.reasons[0]

    await engine.close()


@pytest.mark.asyncio
async def test_health_returns_false_when_unreachable() -> None:
    engine = PolicyEngine(opa_url="http://localhost:19999")
    engine._client = httpx.AsyncClient(base_url="http://localhost:19999", timeout=1.0)
    assert await engine.health() is False
    await engine.close()


@pytest.mark.asyncio
async def test_parse_result_extra_metadata(engine: PolicyEngine) -> None:
    result = {
        "allow": True,
        "tier": "auto",
        "reasons": [],
        "violations": [],
        "matched_rule": "hunt_allowlist",
    }
    decision = engine._parse_result(result)
    assert decision.metadata["matched_rule"] == "hunt_allowlist"

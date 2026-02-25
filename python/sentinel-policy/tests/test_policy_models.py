"""Tests for policy data models."""

from sentinel_policy.models import Decision, PolicyInput, Tier


def test_decision_defaults() -> None:
    d = Decision(allowed=False)
    assert d.tier == Tier.DENY
    assert d.reasons == []
    assert d.violations == []


def test_decision_with_tier() -> None:
    d = Decision(allowed=True, tier=Tier.AUTO, reasons=["ok"])
    assert d.allowed is True
    assert d.tier == Tier.AUTO


def test_policy_input_minimal() -> None:
    inp = PolicyInput(agent_id="a1", agent_type="hunt", action="query_logs")
    assert inp.target == ""
    assert inp.tenant_id == ""
    assert inp.context == {}


def test_policy_input_full() -> None:
    inp = PolicyInput(
        agent_id="a1",
        agent_type="discover",
        action="scan_network",
        target="10.0.0.0/24",
        tenant_id="t-123",
        context={"source": "scheduled"},
    )
    assert inp.target == "10.0.0.0/24"
    assert inp.context["source"] == "scheduled"


def test_tier_values() -> None:
    assert Tier.AUTO.value == "auto"
    assert Tier.FAST_TRACK.value == "fast_track"
    assert Tier.REVIEW.value == "review"
    assert Tier.DENY.value == "deny"


def test_policy_input_serialization() -> None:
    inp = PolicyInput(agent_id="a1", agent_type="hunt", action="query_logs")
    data = inp.model_dump()
    assert data["agent_id"] == "a1"
    assert data["agent_type"] == "hunt"
    roundtrip = PolicyInput.model_validate(data)
    assert roundtrip == inp

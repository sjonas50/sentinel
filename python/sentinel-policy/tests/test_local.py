"""Tests for the local (pure-Python) policy evaluator."""

from sentinel_policy.local import evaluate_agent_action, evaluate_response_tier
from sentinel_policy.models import PolicyInput, Tier

# ── Agent action tests ───────────────────────────────────────────


def test_hunt_agent_allowed_action() -> None:
    inp = PolicyInput(agent_id="h1", agent_type="hunt", action="query_logs")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is True
    assert decision.tier == Tier.AUTO
    assert "action_permitted" in decision.reasons


def test_hunt_agent_disallowed_action() -> None:
    inp = PolicyInput(agent_id="h1", agent_type="hunt", action="scan_network")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is False
    assert decision.tier == Tier.DENY
    assert len(decision.violations) > 0


def test_blocked_action_always_denied() -> None:
    inp = PolicyInput(agent_id="h1", agent_type="hunt", action="delete_data")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is False
    assert "blocked_action" in decision.reasons


def test_unknown_agent_type_denied() -> None:
    inp = PolicyInput(agent_id="x1", agent_type="rogue", action="query_logs")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is False
    assert "unknown_agent_type" in decision.reasons


def test_discover_agent_can_scan() -> None:
    inp = PolicyInput(agent_id="d1", agent_type="discover", action="scan_network")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is True


def test_simulate_agent_can_compute_path() -> None:
    inp = PolicyInput(agent_id="s1", agent_type="simulate", action="compute_path")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is True


def test_govern_agent_can_audit() -> None:
    inp = PolicyInput(agent_id="g1", agent_type="govern", action="audit_agents")
    decision = evaluate_agent_action(inp)
    assert decision.allowed is True


def test_exfiltrate_always_blocked() -> None:
    for agent_type in ("hunt", "simulate", "discover", "govern"):
        inp = PolicyInput(agent_id="x", agent_type=agent_type, action="exfiltrate")
        decision = evaluate_agent_action(inp)
        assert decision.allowed is False


# ── Response tier tests ──────────────────────────────────────────


def test_read_action_is_auto() -> None:
    inp = PolicyInput(agent_id="h1", agent_type="hunt", action="query_logs")
    decision = evaluate_response_tier(inp)
    assert decision.tier == Tier.AUTO


def test_create_finding_is_fast_track() -> None:
    inp = PolicyInput(agent_id="h1", agent_type="hunt", action="create_finding")
    decision = evaluate_response_tier(inp)
    assert decision.tier == Tier.FAST_TRACK


def test_scan_network_requires_review() -> None:
    inp = PolicyInput(agent_id="d1", agent_type="discover", action="scan_network")
    decision = evaluate_response_tier(inp)
    assert decision.tier == Tier.REVIEW


def test_unknown_action_defaults_to_review() -> None:
    inp = PolicyInput(agent_id="x1", agent_type="hunt", action="something_new")
    decision = evaluate_response_tier(inp)
    assert decision.tier == Tier.REVIEW

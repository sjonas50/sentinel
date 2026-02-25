"""Local policy evaluator — pure-Python fallback for testing without OPA.

Implements the same logic as the Rego policies so unit tests can run
without an OPA sidecar. The OPA-based engine is authoritative in production.
"""

from __future__ import annotations

from sentinel_policy.models import Decision, PolicyInput, Tier

# ── Agent action allowlist (mirrors policies/agent/base.rego) ────

ALLOWED_ACTIONS: dict[str, set[str]] = {
    "hunt": {"query_logs", "search_graph", "correlate_events", "read_alerts", "create_finding"},
    "simulate": {"read_graph", "compute_path", "generate_report"},
    "discover": {"scan_network", "query_cloud_api", "update_graph", "read_graph"},
    "govern": {"audit_agents", "check_policy", "review_engram", "list_mcp_servers"},
}

BLOCKED_ACTIONS: set[str] = {
    "delete_data",
    "modify_firewall",
    "disable_security",
    "exfiltrate",
    "execute_payload",
}


def evaluate_agent_action(input_data: PolicyInput) -> Decision:
    """Check if an agent action is allowed based on the allowlist."""
    violations: list[str] = []
    reasons: list[str] = []

    # Always block dangerous actions
    if input_data.action in BLOCKED_ACTIONS:
        violations.append(f"Action '{input_data.action}' is on the blocked list")
        return Decision(
            allowed=False,
            tier=Tier.DENY,
            violations=violations,
            reasons=["blocked_action"],
        )

    # Check if agent type is known
    allowed = ALLOWED_ACTIONS.get(input_data.agent_type)
    if allowed is None:
        violations.append(f"Unknown agent type '{input_data.agent_type}'")
        return Decision(
            allowed=False,
            tier=Tier.DENY,
            violations=violations,
            reasons=["unknown_agent_type"],
        )

    # Check if action is in the allowlist for this agent type
    if input_data.action not in allowed:
        violations.append(
            f"Action '{input_data.action}' not permitted for agent type '{input_data.agent_type}'"
        )
        return Decision(
            allowed=False,
            tier=Tier.DENY,
            violations=violations,
            reasons=["action_not_allowed"],
        )

    reasons.append("action_permitted")
    return Decision(allowed=True, tier=Tier.AUTO, reasons=reasons)


# ── Response approval tiers (mirrors policies/response/approval.rego) ─

# Actions and their required approval tiers
TIER_MAP: dict[str, Tier] = {
    # Auto-approved: read-only, low risk
    "read_alerts": Tier.AUTO,
    "query_logs": Tier.AUTO,
    "search_graph": Tier.AUTO,
    "read_graph": Tier.AUTO,
    "correlate_events": Tier.AUTO,
    "list_mcp_servers": Tier.AUTO,
    "check_policy": Tier.AUTO,
    "review_engram": Tier.AUTO,
    # Fast-track: creates artifacts but no direct system changes
    "create_finding": Tier.FAST_TRACK,
    "generate_report": Tier.FAST_TRACK,
    "compute_path": Tier.FAST_TRACK,
    "audit_agents": Tier.FAST_TRACK,
    # Review: modifies system state
    "update_graph": Tier.REVIEW,
    "scan_network": Tier.REVIEW,
    "query_cloud_api": Tier.REVIEW,
}


def evaluate_response_tier(input_data: PolicyInput) -> Decision:
    """Determine the approval tier for a response action."""
    tier = TIER_MAP.get(input_data.action, Tier.REVIEW)

    return Decision(
        allowed=True,
        tier=tier,
        reasons=[f"tier_{tier.value}"],
    )

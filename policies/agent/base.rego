# Sentinel Agent Action Policy
#
# Determines whether an agent is allowed to perform a given action
# based on agent type and action allowlists.
#
# Input:
#   {
#     "agent_id": "hunt-001",
#     "agent_type": "hunt",
#     "action": "query_logs",
#     "target": "elastic-prod",
#     "tenant_id": "t-123"
#   }
#
# Output:
#   {
#     "allow": true/false,
#     "violations": [...],
#     "reasons": [...]
#   }

package agent.base

import rego.v1

default allow := false

# ── Allowed actions per agent type ──────────────────────────────

allowed_actions := {
	"hunt": {"query_logs", "search_graph", "correlate_events", "read_alerts", "create_finding"},
	"simulate": {"read_graph", "compute_path", "generate_report"},
	"discover": {"scan_network", "query_cloud_api", "update_graph", "read_graph"},
	"govern": {"audit_agents", "check_policy", "review_engram", "list_mcp_servers"},
}

# ── Unconditionally blocked actions ─────────────────────────────

blocked_actions := {
	"delete_data",
	"modify_firewall",
	"disable_security",
	"exfiltrate",
	"execute_payload",
}

# ── Rules ───────────────────────────────────────────────────────

# Deny if the action is blocked regardless of agent type
violations contains msg if {
	input.action in blocked_actions
	msg := sprintf("Action '%s' is on the blocked list", [input.action])
}

# Deny if agent type is unknown
violations contains msg if {
	not input.agent_type in object.keys(allowed_actions)
	msg := sprintf("Unknown agent type '%s'", [input.agent_type])
}

# Deny if action is not in the allowlist for this agent type
violations contains msg if {
	input.agent_type in object.keys(allowed_actions)
	not input.action in allowed_actions[input.agent_type]
	msg := sprintf("Action '%s' not permitted for agent type '%s'", [input.action, input.agent_type])
}

# Allow only if there are no violations
allow if {
	count(violations) == 0
	input.agent_type in object.keys(allowed_actions)
	input.action in allowed_actions[input.agent_type]
}

reasons contains "action_permitted" if {
	allow
}

reasons contains "blocked_action" if {
	input.action in blocked_actions
}

reasons contains "unknown_agent_type" if {
	not input.agent_type in object.keys(allowed_actions)
}

reasons contains "action_not_allowed" if {
	input.agent_type in object.keys(allowed_actions)
	not input.action in allowed_actions[input.agent_type]
}

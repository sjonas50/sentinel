# Sentinel Response Approval Policy
#
# Determines the approval tier for a response action:
#   - auto:       No human approval needed (read-only, low risk)
#   - fast_track:  Creates artifacts but no direct system changes
#   - review:     Requires human review before execution
#   - deny:       Action is not permitted
#
# Input:
#   {
#     "agent_id": "hunt-001",
#     "agent_type": "hunt",
#     "action": "create_finding",
#     "target": "finding-report",
#     "tenant_id": "t-123"
#   }
#
# Output:
#   {
#     "allow": true,
#     "tier": "fast_track",
#     "reasons": ["tier_fast_track"]
#   }

package response.approval

import rego.v1

default allow := true

default tier := "review"

# ── Auto-approved actions (read-only, low risk) ─────────────────

auto_actions := {
	"read_alerts",
	"query_logs",
	"search_graph",
	"read_graph",
	"correlate_events",
	"list_mcp_servers",
	"check_policy",
	"review_engram",
}

# ── Fast-track actions (creates artifacts, no system changes) ───

fast_track_actions := {
	"create_finding",
	"generate_report",
	"compute_path",
	"audit_agents",
}

# ── Review-required actions (modifies system state) ─────────────

review_actions := {
	"update_graph",
	"scan_network",
	"query_cloud_api",
}

# ── Tier assignment ─────────────────────────────────────────────

tier := "auto" if {
	input.action in auto_actions
}

tier := "fast_track" if {
	input.action in fast_track_actions
}

tier := "review" if {
	input.action in review_actions
}

# ── Reasons ─────────────────────────────────────────────────────

reasons contains value if {
	value := sprintf("tier_%s", [tier])
}

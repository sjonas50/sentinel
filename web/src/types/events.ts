/**
 * Event types for real-time updates via WebSocket.
 *
 * Mirrors sentinel-core/src/events.rs and sentinel_api/models/events.py.
 */

export type EventSource = "discover" | "defend" | "govern" | "observe" | "api";

export interface SentinelEvent {
  id: string;
  tenant_id: string;
  timestamp: string;
  source: EventSource;
  payload: EventPayload;
}

export type EventPayload =
  | NodeDiscovered
  | NodeUpdated
  | NodeStale
  | EdgeDiscovered
  | VulnerabilityFound
  | ScanStarted
  | ScanCompleted
  | AttackPathComputed
  | HuntFinding
  | ShadowAiDiscovered
  | PolicyViolation
  | EngramRecorded;

export interface NodeDiscovered {
  event_type: "NodeDiscovered";
  node_id: string;
  node_type: string;
  label: string;
}

export interface NodeUpdated {
  event_type: "NodeUpdated";
  node_id: string;
  changed_fields: string[];
}

export interface NodeStale {
  event_type: "NodeStale";
  node_id: string;
  last_seen: string;
}

export interface EdgeDiscovered {
  event_type: "EdgeDiscovered";
  source_id: string;
  target_id: string;
  edge_type: string;
}

export interface VulnerabilityFound {
  event_type: "VulnerabilityFound";
  node_id: string;
  cve_id: string;
  cvss_score?: number;
  exploitable: boolean;
}

export interface ScanStarted {
  event_type: "ScanStarted";
  scan_id: string;
  scan_type: string;
  target: string;
}

export interface ScanCompleted {
  event_type: "ScanCompleted";
  scan_id: string;
  nodes_found: number;
  nodes_updated: number;
  nodes_stale: number;
  duration_ms: number;
}

export interface AttackPathComputed {
  event_type: "AttackPathComputed";
  path_id: string;
  source_node: string;
  target_node: string;
  risk_score: number;
  step_count: number;
}

export interface HuntFinding {
  event_type: "HuntFinding";
  finding_id: string;
  severity: string;
  title: string;
  description: string;
}

export interface ShadowAiDiscovered {
  event_type: "ShadowAiDiscovered";
  service_name: string;
  domain: string;
  risk_score: number;
}

export interface PolicyViolation {
  event_type: "PolicyViolation";
  agent_id: string;
  policy_name: string;
  action: string;
  details: string;
}

export interface EngramRecorded {
  event_type: "EngramRecorded";
  session_id: string;
  agent_type: string;
  intent: string;
  action_count: number;
}

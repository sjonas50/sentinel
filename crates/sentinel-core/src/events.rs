//! Event types for inter-service communication.
//!
//! Events are published to Redis Streams (Phase 0-1) or Kafka (Phase 2+)
//! for consumption by other Sentinel services.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{EdgeType, NodeId, TenantId};

/// Unique identifier for an event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EventId(pub Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

/// An event emitted by a Sentinel service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEvent {
    pub id: EventId,
    pub tenant_id: TenantId,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub payload: EventPayload,
}

impl SentinelEvent {
    pub fn new(tenant_id: TenantId, source: EventSource, payload: EventPayload) -> Self {
        Self {
            id: EventId::new(),
            tenant_id,
            timestamp: Utc::now(),
            source,
            payload,
        }
    }
}

/// Which service emitted the event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Discover,
    Defend,
    Govern,
    Observe,
    Api,
}

/// The event payload, tagged by type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum EventPayload {
    // ── Discovery events ──────────────────────────────────────
    /// A new node was discovered in the environment.
    NodeDiscovered {
        node_id: NodeId,
        node_type: String,
        label: String,
    },
    /// A node was updated (properties changed).
    NodeUpdated {
        node_id: NodeId,
        changed_fields: Vec<String>,
    },
    /// A node disappeared (not seen in latest scan).
    NodeStale {
        node_id: NodeId,
        last_seen: DateTime<Utc>,
    },
    /// A new edge was discovered.
    EdgeDiscovered {
        source_id: NodeId,
        target_id: NodeId,
        edge_type: EdgeType,
    },

    // ── Vulnerability events ──────────────────────────────────
    /// A new vulnerability was correlated to an asset.
    VulnerabilityFound {
        node_id: NodeId,
        cve_id: String,
        cvss_score: Option<f64>,
        exploitable: bool,
    },

    // ── Scan lifecycle events ─────────────────────────────────
    /// A scan operation started.
    ScanStarted {
        scan_id: Uuid,
        scan_type: String,
        target: String,
    },
    /// A scan operation completed.
    ScanCompleted {
        scan_id: Uuid,
        nodes_found: u32,
        nodes_updated: u32,
        nodes_stale: u32,
        duration_ms: u64,
    },

    // ── Defend events ─────────────────────────────────────────
    /// An attack path was computed.
    AttackPathComputed {
        path_id: Uuid,
        source_node: NodeId,
        target_node: NodeId,
        risk_score: f64,
        step_count: u32,
    },
    /// A threat hunt finding was produced.
    HuntFinding {
        finding_id: Uuid,
        severity: String,
        title: String,
        description: String,
    },

    // ── Govern events ─────────────────────────────────────────
    /// A shadow AI tool was discovered.
    ShadowAiDiscovered {
        service_name: String,
        domain: String,
        risk_score: f64,
    },
    /// A policy violation was detected.
    PolicyViolation {
        agent_id: String,
        policy_name: String,
        action: String,
        details: String,
    },

    // ── Engram events ─────────────────────────────────────────
    /// An Engram reasoning session was recorded.
    EngramRecorded {
        session_id: Uuid,
        agent_type: String,
        intent: String,
        action_count: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization_roundtrip() {
        let event = SentinelEvent::new(
            TenantId::new(),
            EventSource::Discover,
            EventPayload::NodeDiscovered {
                node_id: NodeId::new(),
                node_type: "Host".to_string(),
                label: "web-server-01".to_string(),
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: SentinelEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, deserialized.id);
    }

    #[test]
    fn event_payload_tags() {
        let payload = EventPayload::VulnerabilityFound {
            node_id: NodeId::new(),
            cve_id: "CVE-2024-1234".to_string(),
            cvss_score: Some(8.1),
            exploitable: true,
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event_type\":\"VulnerabilityFound\""));
    }
}

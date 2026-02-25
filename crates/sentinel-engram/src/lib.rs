//! Sentinel Engram — Tamper-evident reasoning capture.
//!
//! Engrams record the complete reasoning chain of AI agent actions:
//! intent, context, decisions, alternatives considered, and actions taken.
//! Each engram is content-hashed with BLAKE3 for tamper evidence and
//! stored as Git objects under `refs/engrams/`.

pub mod hash;
pub mod session;
pub mod store;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Core Types ───────────────────────────────────────────────────

/// Unique identifier for an engram session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EngramId(pub Uuid);

impl EngramId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EngramId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EngramId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A decision made during agent execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    /// What was decided.
    pub choice: String,
    /// Why this option was chosen.
    pub rationale: String,
    /// Confidence level (0.0 – 1.0).
    pub confidence: f64,
    /// When the decision was made.
    pub timestamp: DateTime<Utc>,
}

/// An alternative that was considered but not chosen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alternative {
    /// What was considered.
    pub option: String,
    /// Why it was rejected.
    pub rejection_reason: String,
}

/// An action taken by the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Action {
    /// Type of action (e.g. "graph_mutation", "api_call", "policy_check").
    pub action_type: String,
    /// Human-readable description.
    pub description: String,
    /// Structured parameters/details.
    pub details: serde_json::Value,
    /// Whether the action succeeded.
    pub success: bool,
    /// When the action was executed.
    pub timestamp: DateTime<Utc>,
}

/// The complete reasoning chain of an AI agent session.
///
/// An Engram captures everything an agent thought, decided, and did
/// during a single execution, providing a complete audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Engram {
    /// Unique session identifier.
    pub id: EngramId,
    /// Tenant this engram belongs to.
    pub tenant_id: Uuid,
    /// Which agent produced this engram.
    pub agent_id: String,
    /// The original intent / task description.
    pub intent: String,
    /// Context provided to the agent at start.
    pub context: serde_json::Value,
    /// Decisions made during execution.
    pub decisions: Vec<Decision>,
    /// Alternatives considered but not chosen.
    pub alternatives: Vec<Alternative>,
    /// Actions taken during execution.
    pub actions: Vec<Action>,
    /// When the session started.
    pub started_at: DateTime<Utc>,
    /// When the session ended.
    pub completed_at: Option<DateTime<Utc>>,
    /// BLAKE3 content hash (hex) — set on finalization.
    pub content_hash: Option<String>,
}

impl Engram {
    /// Compute and return the BLAKE3 hash of the engram's content.
    /// The hash covers all fields except `content_hash` itself.
    pub fn compute_hash(&self) -> String {
        hash::compute_engram_hash(self)
    }

    /// Verify that the stored content_hash matches a freshly computed hash.
    pub fn verify_integrity(&self) -> bool {
        match &self.content_hash {
            Some(stored) => stored == &self.compute_hash(),
            None => false,
        }
    }
}

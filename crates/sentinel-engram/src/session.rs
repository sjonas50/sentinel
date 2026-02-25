//! Builder-pattern session recorder for engram capture.
//!
//! Used by agent code to incrementally record reasoning during execution:
//!
//! ```no_run
//! # use sentinel_engram::session::EngramSession;
//! # use uuid::Uuid;
//! let mut session = EngramSession::new(
//!     Uuid::new_v4(),
//!     "discover-scanner",
//!     "Scan subnet 10.0.1.0/24 for new assets",
//! );
//! session.set_context(serde_json::json!({"subnet": "10.0.1.0/24"}));
//! session.add_decision("Use ICMP + TCP SYN scan", "Fastest for initial discovery", 0.9);
//! session.add_alternative("Full TCP connect scan", "Too slow for /24 subnet");
//! session.add_action("network_scan", "ICMP ping sweep", serde_json::json!({"hosts": 254}), true);
//! let engram = session.finalize();
//! assert!(engram.content_hash.is_some());
//! ```

use chrono::Utc;

use crate::{Action, Alternative, Decision, Engram, EngramId};

/// A session builder that records agent reasoning incrementally.
pub struct EngramSession {
    engram: Engram,
}

impl EngramSession {
    /// Start a new engram recording session.
    pub fn new(tenant_id: uuid::Uuid, agent_id: &str, intent: &str) -> Self {
        Self {
            engram: Engram {
                id: EngramId::new(),
                tenant_id,
                agent_id: agent_id.to_string(),
                intent: intent.to_string(),
                context: serde_json::Value::Null,
                decisions: Vec::new(),
                alternatives: Vec::new(),
                actions: Vec::new(),
                started_at: Utc::now(),
                completed_at: None,
                content_hash: None,
            },
        }
    }

    /// Set the context provided to the agent.
    pub fn set_context(&mut self, context: serde_json::Value) {
        self.engram.context = context;
    }

    /// Record a decision the agent made.
    pub fn add_decision(&mut self, choice: &str, rationale: &str, confidence: f64) {
        self.engram.decisions.push(Decision {
            choice: choice.to_string(),
            rationale: rationale.to_string(),
            confidence,
            timestamp: Utc::now(),
        });
    }

    /// Record an alternative that was considered but not chosen.
    pub fn add_alternative(&mut self, option: &str, rejection_reason: &str) {
        self.engram.alternatives.push(Alternative {
            option: option.to_string(),
            rejection_reason: rejection_reason.to_string(),
        });
    }

    /// Record an action taken by the agent.
    pub fn add_action(
        &mut self,
        action_type: &str,
        description: &str,
        details: serde_json::Value,
        success: bool,
    ) {
        self.engram.actions.push(Action {
            action_type: action_type.to_string(),
            description: description.to_string(),
            details,
            success,
            timestamp: Utc::now(),
        });
    }

    /// The engram ID for this session (available before finalization).
    pub fn id(&self) -> EngramId {
        self.engram.id
    }

    /// Finalize the session: set completed_at and compute the content hash.
    pub fn finalize(mut self) -> Engram {
        self.engram.completed_at = Some(Utc::now());
        let hash = self.engram.compute_hash();
        self.engram.content_hash = Some(hash);
        self.engram
    }
}

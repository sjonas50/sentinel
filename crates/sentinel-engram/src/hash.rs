//! BLAKE3 content hashing for tamper evidence.
//!
//! Computes a deterministic hash of all engram fields (excluding the
//! content_hash itself) so that any modification is detectable.

use serde::Serialize;

use crate::Engram;

/// Hashable representation of an Engram (excludes content_hash).
#[derive(Serialize)]
struct HashableEngram<'a> {
    id: &'a crate::EngramId,
    tenant_id: &'a uuid::Uuid,
    agent_id: &'a str,
    intent: &'a str,
    context: &'a serde_json::Value,
    decisions: &'a [crate::Decision],
    alternatives: &'a [crate::Alternative],
    actions: &'a [crate::Action],
    started_at: &'a chrono::DateTime<chrono::Utc>,
    completed_at: &'a Option<chrono::DateTime<chrono::Utc>>,
}

/// Compute the BLAKE3 hash of an engram's content.
///
/// Serializes all fields except `content_hash` to canonical JSON,
/// then hashes the bytes with BLAKE3. Returns the hex-encoded hash.
pub fn compute_engram_hash(engram: &Engram) -> String {
    let hashable = HashableEngram {
        id: &engram.id,
        tenant_id: &engram.tenant_id,
        agent_id: &engram.agent_id,
        intent: &engram.intent,
        context: &engram.context,
        decisions: &engram.decisions,
        alternatives: &engram.alternatives,
        actions: &engram.actions,
        started_at: &engram.started_at,
        completed_at: &engram.completed_at,
    };

    let json = serde_json::to_vec(&hashable).expect("Engram serialization should not fail");
    blake3::hash(&json).to_hex().to_string()
}

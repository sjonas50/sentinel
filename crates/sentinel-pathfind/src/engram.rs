//! Engram session helpers for pathfinding operations.

use sentinel_engram::session::EngramSession;
use sentinel_engram::store::{EngramStore, GitEngramStore};
use sentinel_engram::Engram;
use uuid::Uuid;

/// Create an Engram session for a pathfinding computation.
pub fn start_pathfind_session(
    tenant_id: Uuid,
    operation: &str,
    context: serde_json::Value,
) -> EngramSession {
    let mut session = EngramSession::new(
        tenant_id,
        "sentinel-pathfind",
        &format!("Attack path analysis: {operation}"),
    );

    session.set_context(context);

    session.add_decision(
        &format!("Execute {operation}"),
        "Requested by API for attack path analysis",
        1.0,
    );

    session
}

/// Record algorithm decision (which algorithm was chosen, why).
pub fn record_algorithm_decision(
    session: &mut EngramSession,
    algorithm: &str,
    rationale: &str,
    params: serde_json::Value,
) {
    session.add_decision(
        &format!("Use algorithm: {algorithm}"),
        rationale,
        0.95,
    );
    session.add_action(
        "algorithm_selection",
        &format!("Selected {algorithm}"),
        params,
        true,
    );
}

/// Record pathfinding results in the session.
pub fn record_pathfind_results(
    session: &mut EngramSession,
    paths_found: usize,
    top_risk_score: f64,
    duration_ms: u64,
    details: serde_json::Value,
) {
    session.add_action(
        "pathfind_computation",
        &format!(
            "Found {} attack paths (top risk: {:.1}) in {}ms",
            paths_found, top_risk_score, duration_ms
        ),
        serde_json::json!({
            "paths_found": paths_found,
            "top_risk_score": top_risk_score,
            "duration_ms": duration_ms,
            "details": details,
        }),
        true,
    );
}

/// Finalize the session and store the engram.
pub fn finalize_and_store(session: EngramSession, engram_dir: &str) -> Option<Engram> {
    let engram = session.finalize();

    match GitEngramStore::new(engram_dir) {
        Ok(store) => match store.save(&engram) {
            Ok(()) => {
                tracing::info!(
                    engram_id = %engram.id,
                    "Engram recorded for pathfind session"
                );
                Some(engram)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to store engram");
                Some(engram)
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "Failed to initialize engram store");
            Some(engram)
        }
    }
}

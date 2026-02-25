//! Engram session helpers for scan runs.

use sentinel_engram::session::EngramSession;
use sentinel_engram::store::{EngramStore, GitEngramStore};
use sentinel_engram::Engram;
use uuid::Uuid;

use crate::config::ScanProfile;
use crate::diff::DiffSummary;

/// Create an Engram session for a scan run.
pub fn start_scan_session(tenant_id: Uuid, target: &str, profile: &ScanProfile) -> EngramSession {
    let mut session = EngramSession::new(
        tenant_id,
        "sentinel-discover",
        &format!("Network scan of {target}"),
    );

    session.set_context(serde_json::json!({
        "target": target,
        "profile": format!("{profile:?}"),
        "nmap_flags": profile.nmap_flags(),
    }));

    session.add_decision(
        &format!("Use {profile:?} scan profile"),
        "Configured profile for this subnet",
        1.0,
    );

    session
}

/// Record scan results in the engram session.
pub fn record_scan_results(session: &mut EngramSession, summary: &DiffSummary, duration_ms: u64) {
    session.add_action(
        "network_scan",
        &format!(
            "Scanned {} hosts: {} new, {} changed, {} stale",
            summary.total_scanned, summary.new_count, summary.changed_count, summary.stale_count
        ),
        serde_json::json!({
            "total_scanned": summary.total_scanned,
            "new_count": summary.new_count,
            "changed_count": summary.changed_count,
            "stale_count": summary.stale_count,
            "duration_ms": duration_ms,
        }),
        true,
    );
}

/// Record a scan error in the engram session.
pub fn record_scan_error(session: &mut EngramSession, error: &str) {
    session.add_action(
        "network_scan",
        &format!("Scan failed: {error}"),
        serde_json::json!({ "error": error }),
        false,
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
                    "Engram recorded for scan session"
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

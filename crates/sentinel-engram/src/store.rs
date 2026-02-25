//! Engram storage — trait + Git-backed implementation.
//!
//! Engrams are stored as JSON files organized by date and session ID.
//! The Git-backed store keeps them under a configurable directory,
//! suitable for backing by a Git repository (refs/engrams/).

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Engram, EngramId};

/// Errors that can occur during engram storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Engram not found: {0}")]
    NotFound(EngramId),

    #[error("Integrity check failed for engram {0}: stored hash does not match content")]
    IntegrityViolation(EngramId),

    #[error("Engram has no content hash (not finalized)")]
    NotFinalized,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Query parameters for listing engrams.
#[derive(Debug, Default)]
pub struct EngramQuery {
    /// Filter by tenant.
    pub tenant_id: Option<Uuid>,
    /// Filter by agent.
    pub agent_id: Option<String>,
    /// Filter by session ID.
    pub session_id: Option<EngramId>,
    /// Only include engrams started at or after this time.
    pub from: Option<DateTime<Utc>>,
    /// Only include engrams started at or before this time.
    pub to: Option<DateTime<Utc>>,
}

/// Trait for engram persistence backends.
pub trait EngramStore {
    /// Store a finalized engram. Returns an error if the engram has no content hash.
    fn save(&self, engram: &Engram) -> Result<(), StoreError>;

    /// Retrieve an engram by ID, verifying integrity.
    fn get(&self, id: EngramId) -> Result<Engram, StoreError>;

    /// List engrams matching the given query, ordered by started_at descending.
    fn list(&self, query: &EngramQuery) -> Result<Vec<Engram>, StoreError>;
}

/// File-system backed engram store.
///
/// Stores engrams as JSON files in a directory tree:
/// ```text
/// {root}/
///   2024/
///     01/
///       15/
///         {session_id}.json
/// ```
///
/// This directory can be initialized as a Git repository for
/// version tracking under `refs/engrams/`.
pub struct GitEngramStore {
    root: PathBuf,
}

impl GitEngramStore {
    /// Create a new store rooted at the given directory.
    /// Creates the directory if it doesn't exist.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Build the file path for an engram based on its start date and ID.
    fn engram_path(&self, engram: &Engram) -> PathBuf {
        let date = engram.started_at.format("%Y/%m/%d");
        self.root.join(format!("{}/{}.json", date, engram.id.0))
    }

    /// Build the file path for an engram ID by scanning the directory tree.
    fn find_path(&self, id: EngramId) -> Result<PathBuf, StoreError> {
        let filename = format!("{}.json", id.0);
        find_file_recursive(&self.root, &filename).ok_or(StoreError::NotFound(id))
    }
}

impl EngramStore for GitEngramStore {
    fn save(&self, engram: &Engram) -> Result<(), StoreError> {
        if engram.content_hash.is_none() {
            return Err(StoreError::NotFinalized);
        }

        let path = self.engram_path(engram);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(engram)?;
        fs::write(&path, json)?;

        tracing::debug!(
            engram_id = %engram.id,
            path = %path.display(),
            "Engram saved"
        );

        Ok(())
    }

    fn get(&self, id: EngramId) -> Result<Engram, StoreError> {
        let path = self.find_path(id)?;
        let json = fs::read_to_string(&path)?;
        let engram: Engram = serde_json::from_str(&json)?;

        if !engram.verify_integrity() {
            return Err(StoreError::IntegrityViolation(id));
        }

        Ok(engram)
    }

    fn list(&self, query: &EngramQuery) -> Result<Vec<Engram>, StoreError> {
        let mut results = Vec::new();

        // Walk the directory tree and collect matching engrams
        collect_engrams_recursive(&self.root, query, &mut results)?;

        // Sort by started_at descending
        results.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        Ok(results)
    }
}

/// Recursively find a file by name.
fn find_file_recursive(dir: &Path, filename: &str) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }

    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, filename) {
                return Some(found);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            return Some(path);
        }
    }

    None
}

/// Recursively collect engrams matching a query.
fn collect_engrams_recursive(
    dir: &Path,
    query: &EngramQuery,
    results: &mut Vec<Engram>,
) -> Result<(), StoreError> {
    if !dir.is_dir() {
        return Ok(());
    }

    let entries = fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_engrams_recursive(&path, query, results)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let json = fs::read_to_string(&path)?;
            let engram: Engram = serde_json::from_str(&json)?;

            if matches_query(&engram, query) {
                results.push(engram);
            }
        }
    }

    Ok(())
}

/// Check whether an engram matches the given query filters.
fn matches_query(engram: &Engram, query: &EngramQuery) -> bool {
    if let Some(tid) = &query.tenant_id {
        if &engram.tenant_id != tid {
            return false;
        }
    }
    if let Some(aid) = &query.agent_id {
        if &engram.agent_id != aid {
            return false;
        }
    }
    if let Some(sid) = &query.session_id {
        if &engram.id != sid {
            return false;
        }
    }
    if let Some(from) = &query.from {
        if &engram.started_at < from {
            return false;
        }
    }
    if let Some(to) = &query.to {
        if &engram.started_at > to {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::EngramSession;

    fn create_test_engram(tenant_id: Uuid, agent_id: &str) -> Engram {
        let mut session = EngramSession::new(tenant_id, agent_id, "Test intent");
        session.set_context(serde_json::json!({"key": "value"}));
        session.add_decision("choice A", "best option", 0.95);
        session.add_alternative("choice B", "too slow");
        session.add_action(
            "test_action",
            "Did something",
            serde_json::json!({"result": 42}),
            true,
        );
        session.finalize()
    }

    #[test]
    fn save_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let store = GitEngramStore::new(dir.path()).unwrap();
        let tenant_id = Uuid::new_v4();
        let engram = create_test_engram(tenant_id, "test-agent");
        let id = engram.id;

        store.save(&engram).unwrap();
        let retrieved = store.get(id).unwrap();

        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.intent, "Test intent");
        assert_eq!(retrieved.decisions.len(), 1);
        assert_eq!(retrieved.actions.len(), 1);
        assert!(retrieved.verify_integrity());
    }

    #[test]
    fn integrity_violation_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = GitEngramStore::new(dir.path()).unwrap();
        let engram = create_test_engram(Uuid::new_v4(), "test-agent");
        let id = engram.id;

        // Save the engram
        store.save(&engram).unwrap();

        // Tamper with the file: change the intent
        let path = store.find_path(id).unwrap();
        let mut tampered: Engram =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.intent = "TAMPERED INTENT".to_string();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Retrieval should fail with integrity violation
        let result = store.get(id);
        assert!(matches!(result, Err(StoreError::IntegrityViolation(_))));
    }

    #[test]
    fn save_rejects_unfinalized() {
        let dir = tempfile::tempdir().unwrap();
        let store = GitEngramStore::new(dir.path()).unwrap();

        let engram = Engram {
            id: EngramId::new(),
            tenant_id: Uuid::new_v4(),
            agent_id: "test".to_string(),
            intent: "test".to_string(),
            context: serde_json::Value::Null,
            decisions: vec![],
            alternatives: vec![],
            actions: vec![],
            started_at: Utc::now(),
            completed_at: None,
            content_hash: None, // not finalized
        };

        let result = store.save(&engram);
        assert!(matches!(result, Err(StoreError::NotFinalized)));
    }

    #[test]
    fn list_filters_by_agent() {
        let dir = tempfile::tempdir().unwrap();
        let store = GitEngramStore::new(dir.path()).unwrap();
        let tenant_id = Uuid::new_v4();

        let e1 = create_test_engram(tenant_id, "scanner");
        let e2 = create_test_engram(tenant_id, "hunter");
        let e3 = create_test_engram(tenant_id, "scanner");

        store.save(&e1).unwrap();
        store.save(&e2).unwrap();
        store.save(&e3).unwrap();

        let query = EngramQuery {
            agent_id: Some("scanner".to_string()),
            ..Default::default()
        };
        let results = store.list(&query).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.agent_id == "scanner"));
    }

    #[test]
    fn list_filters_by_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let store = GitEngramStore::new(dir.path()).unwrap();

        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();

        let e1 = create_test_engram(t1, "agent-a");
        let e2 = create_test_engram(t2, "agent-a");

        store.save(&e1).unwrap();
        store.save(&e2).unwrap();

        let query = EngramQuery {
            tenant_id: Some(t1),
            ..Default::default()
        };
        let results = store.list(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tenant_id, t1);
    }
}

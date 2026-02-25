//! Nmap process wrapper.
//!
//! Executes nmap as a child process via `tokio::process::Command` and
//! parses the XML output into typed Rust structs.

use std::time::Instant;

use tokio::process::Command;
use uuid::Uuid;

use crate::config::ScanProfile;
use crate::error::{DiscoverError, Result};
use crate::nmap_xml::{self, NmapRun};

/// Result of a single nmap scan execution.
pub struct ScanResult {
    /// Unique ID for this scan run.
    pub scan_id: Uuid,
    /// The target CIDR or host expression.
    pub target: String,
    /// The scan profile used.
    pub profile: ScanProfile,
    /// Parsed nmap XML output.
    pub nmap_run: NmapRun,
    /// Wall-clock duration of the scan.
    pub duration: std::time::Duration,
}

/// Wrapper around the nmap binary.
pub struct NmapScanner {
    nmap_path: String,
}

impl NmapScanner {
    pub fn new(nmap_path: &str) -> Self {
        Self {
            nmap_path: nmap_path.to_string(),
        }
    }

    /// Verify nmap is installed and accessible.
    pub async fn verify_installation(&self) -> Result<String> {
        let output = Command::new(&self.nmap_path)
            .arg("--version")
            .output()
            .await
            .map_err(|_| DiscoverError::NmapNotFound {
                path: self.nmap_path.clone(),
            })?;

        String::from_utf8(output.stdout).map_err(|e| DiscoverError::XmlParse(e.to_string()))
    }

    /// Execute an nmap scan against the given target with the specified profile.
    ///
    /// Nmap is invoked with `-oX -` to write XML to stdout. The process runs
    /// under `tokio::process::Command` so it does not block the async runtime.
    pub async fn scan(&self, target: &str, profile: &ScanProfile) -> Result<ScanResult> {
        let scan_id = Uuid::new_v4();
        let start = Instant::now();
        let flags = profile.nmap_flags();

        tracing::info!(
            scan_id = %scan_id,
            target = %target,
            profile = ?profile,
            "Starting nmap scan"
        );

        let output = Command::new(&self.nmap_path)
            .args(&flags)
            .arg("-oX")
            .arg("-")
            .arg("--noninteractive")
            .arg(target)
            .output()
            .await
            .map_err(|e| DiscoverError::NmapNotFound {
                path: format!("{}: {e}", self.nmap_path),
            })?;

        let duration = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(DiscoverError::NmapFailed {
                code: output.status.code().unwrap_or(-1),
                stderr,
            });
        }

        let nmap_run = nmap_xml::parse_nmap_xml(&output.stdout)?;
        let host_count = nmap_run.hosts.iter().filter(|h| h.is_up()).count();

        tracing::info!(
            scan_id = %scan_id,
            target = %target,
            hosts_up = host_count,
            duration_ms = duration.as_millis(),
            "Nmap scan complete"
        );

        Ok(ScanResult {
            scan_id,
            target: target.to_string(),
            profile: profile.clone(),
            nmap_run,
            duration,
        })
    }
}

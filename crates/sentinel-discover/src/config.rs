//! Configuration for the sentinel-discover network scanner.

use serde::Deserialize;

/// Top-level discover configuration.
///
/// Loaded from `sentinel.toml` `[discover]` section or
/// `SENTINEL_DISCOVER__` environment variables.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoverConfig {
    /// Path to the nmap binary (default: "nmap").
    #[serde(default = "default_nmap_path")]
    pub nmap_path: String,

    /// Tenant ID for this scanner instance.
    #[serde(default)]
    pub tenant_id: String,

    /// Default scan profile if not specified per subnet.
    #[serde(default)]
    pub default_profile: ScanProfile,

    /// Per-subnet scheduling configuration.
    #[serde(default)]
    pub subnets: Vec<SubnetSchedule>,

    /// Stale threshold in hours: hosts not seen for this long get marked stale.
    #[serde(default = "default_stale_hours")]
    pub stale_threshold_hours: u64,

    /// Directory for engram storage.
    #[serde(default = "default_engram_dir")]
    pub engram_dir: String,

    /// Maximum concurrent nmap processes.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_scans: usize,
}

/// A subnet with its scan schedule.
#[derive(Debug, Clone, Deserialize)]
pub struct SubnetSchedule {
    /// CIDR target (e.g., "10.0.1.0/24").
    pub cidr: String,

    /// Human-readable name for this subnet.
    pub name: Option<String>,

    /// Scan profile override for this subnet.
    pub profile: Option<ScanProfile>,

    /// Scan interval in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,

    /// Whether this subnet is enabled for scanning.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Predefined scan profiles mapping to nmap flag sets.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    /// Ping sweep only: `-sn`
    Quick,
    /// SYN scan + service version, top 1000 ports: `-sS -sV`
    #[default]
    Standard,
    /// Full scan: `-sS -sV -O -A -p-`
    Deep,
}

impl ScanProfile {
    /// Return the nmap flags for this profile.
    pub fn nmap_flags(&self) -> Vec<&'static str> {
        match self {
            Self::Quick => vec!["-sn"],
            Self::Standard => vec!["-sS", "-sV", "--top-ports", "1000"],
            Self::Deep => vec!["-sS", "-sV", "-O", "-A", "-p-"],
        }
    }
}

fn default_nmap_path() -> String {
    "nmap".to_string()
}

fn default_stale_hours() -> u64 {
    24
}

fn default_engram_dir() -> String {
    "./engrams".to_string()
}

fn default_max_concurrent() -> usize {
    4
}

fn default_interval() -> u64 {
    3600
}

fn default_true() -> bool {
    true
}

impl Default for DiscoverConfig {
    fn default() -> Self {
        Self {
            nmap_path: default_nmap_path(),
            tenant_id: String::new(),
            default_profile: ScanProfile::default(),
            subnets: Vec::new(),
            stale_threshold_hours: default_stale_hours(),
            engram_dir: default_engram_dir(),
            max_concurrent_scans: default_max_concurrent(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_profile_flags() {
        assert_eq!(ScanProfile::Quick.nmap_flags(), vec!["-sn"]);
        assert_eq!(
            ScanProfile::Standard.nmap_flags(),
            vec!["-sS", "-sV", "--top-ports", "1000"]
        );
        assert_eq!(
            ScanProfile::Deep.nmap_flags(),
            vec!["-sS", "-sV", "-O", "-A", "-p-"]
        );
    }

    #[test]
    fn test_default_config() {
        let config = DiscoverConfig::default();
        assert_eq!(config.nmap_path, "nmap");
        assert_eq!(config.default_profile, ScanProfile::Standard);
        assert_eq!(config.stale_threshold_hours, 24);
        assert_eq!(config.max_concurrent_scans, 4);
    }
}

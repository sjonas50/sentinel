//! Scan scheduling engine.
//!
//! Spawns one tokio task per configured subnet, each running periodic scans
//! at the configured interval. A semaphore limits concurrent nmap processes.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::time::{interval, Duration};

use sentinel_core::types::TenantId;
use sentinel_graph::GraphClient;

use crate::config::{DiscoverConfig, ScanProfile, SubnetSchedule};
use crate::error::Result;
use crate::scanner::NmapScanner;
use crate::{diff, engram, persist};

/// The scheduler manages periodic scan jobs for multiple subnets.
pub struct ScanScheduler {
    config: DiscoverConfig,
    scanner: Arc<NmapScanner>,
    graph: GraphClient,
    tenant_id: TenantId,
    concurrency: Arc<Semaphore>,
}

impl ScanScheduler {
    pub fn new(
        config: DiscoverConfig,
        scanner: NmapScanner,
        graph: GraphClient,
        tenant_id: TenantId,
    ) -> Self {
        let concurrency = Arc::new(Semaphore::new(config.max_concurrent_scans));
        Self {
            config,
            scanner: Arc::new(scanner),
            graph,
            tenant_id,
            concurrency,
        }
    }

    /// Run the scheduler, spawning a tokio task per subnet.
    /// Blocks indefinitely until all tasks complete or the runtime shuts down.
    pub async fn run(&self) -> Result<()> {
        let mut handles = Vec::new();

        for subnet in &self.config.subnets {
            if !subnet.enabled {
                tracing::info!(cidr = %subnet.cidr, "Subnet disabled, skipping");
                continue;
            }

            let scanner = self.scanner.clone();
            let graph = self.graph.clone();
            let tenant_id = self.tenant_id.clone();
            let config = self.config.clone();
            let subnet = subnet.clone();
            let semaphore = self.concurrency.clone();

            let handle = tokio::spawn(async move {
                run_subnet_loop(scanner, graph, tenant_id, config, subnet, semaphore).await;
            });
            handles.push(handle);
        }

        tracing::info!(subnet_count = handles.len(), "Scheduler started");

        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "Subnet scan task panicked");
            }
        }

        Ok(())
    }
}

/// Per-subnet scan loop with configurable interval.
async fn run_subnet_loop(
    scanner: Arc<NmapScanner>,
    graph: GraphClient,
    tenant_id: TenantId,
    config: DiscoverConfig,
    subnet: SubnetSchedule,
    semaphore: Arc<Semaphore>,
) {
    let profile = subnet
        .profile
        .clone()
        .unwrap_or(config.default_profile.clone());
    let mut ticker = interval(Duration::from_secs(subnet.interval_secs));

    loop {
        ticker.tick().await;

        tracing::info!(cidr = %subnet.cidr, profile = ?profile, "Scheduled scan triggered");

        let _permit = semaphore.acquire().await.expect("Semaphore closed");

        if let Err(e) = run_single_scan(
            &scanner,
            &graph,
            &tenant_id,
            &config,
            &subnet.cidr,
            &profile,
        )
        .await
        {
            tracing::error!(cidr = %subnet.cidr, error = %e, "Scheduled scan failed");
        }
    }
}

/// Execute a single scan: nmap → parse → diff → persist → engram.
pub async fn run_single_scan(
    scanner: &NmapScanner,
    graph: &GraphClient,
    tenant_id: &TenantId,
    config: &DiscoverConfig,
    target: &str,
    profile: &ScanProfile,
) -> Result<()> {
    let mut session = engram::start_scan_session(tenant_id.0, target, profile);

    // Run nmap.
    let scan_result = match scanner.scan(target, profile).await {
        Ok(r) => r,
        Err(e) => {
            engram::record_scan_error(&mut session, &e.to_string());
            engram::finalize_and_store(session, &config.engram_dir);
            return Err(e);
        }
    };

    // Parse results into sentinel-core types.
    let now = chrono::Utc::now();
    let discovered = diff::parse_scan_results(&scan_result.nmap_run, tenant_id, now);

    // Diff against current graph state.
    let diff_result = diff::compute_diff(graph, tenant_id, discovered, target).await?;

    // Persist to Neo4j.
    persist::persist_diff(graph, tenant_id, &diff_result, config.stale_threshold_hours).await?;

    // Record in Engram.
    engram::record_scan_results(
        &mut session,
        &diff_result.summary,
        scan_result.duration.as_millis() as u64,
    );
    engram::finalize_and_store(session, &config.engram_dir);

    tracing::info!(
        scan_id = %scan_result.scan_id,
        target = %target,
        new = diff_result.summary.new_count,
        changed = diff_result.summary.changed_count,
        stale = diff_result.summary.stale_count,
        duration_ms = scan_result.duration.as_millis(),
        "Scan complete"
    );

    Ok(())
}

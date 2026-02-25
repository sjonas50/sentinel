//! Graph persistence: upsert discovered hosts, services, ports, and edges.

use chrono::{TimeDelta, Utc};
use sentinel_core::types::{Node, TenantId};
use sentinel_graph::GraphClient;

use crate::diff::{DiffResult, DiscoveredHost};
use crate::error::Result;

/// Persist a full diff result to Neo4j.
///
/// Upserts all new and changed hosts (including their ports, services, edges),
/// then marks stale nodes that haven't been seen within the threshold.
pub async fn persist_diff(
    graph: &GraphClient,
    tenant_id: &TenantId,
    diff: &DiffResult,
    stale_threshold_hours: u64,
) -> Result<()> {
    // Upsert new hosts.
    for discovered in &diff.new_hosts {
        persist_discovered_host(graph, discovered).await?;
    }

    // Upsert changed hosts (also updates last_seen).
    for discovered in &diff.changed_hosts {
        persist_discovered_host(graph, discovered).await?;
    }

    // Mark stale nodes.
    if let Some(delta) = TimeDelta::try_hours(stale_threshold_hours as i64) {
        let cutoff = Utc::now() - delta;
        let stale_hosts = graph.mark_stale(tenant_id, "Host", cutoff).await?;
        let stale_services = graph.mark_stale(tenant_id, "Service", cutoff).await?;

        if stale_hosts > 0 || stale_services > 0 {
            tracing::info!(stale_hosts, stale_services, "Marked stale nodes");
        }
    }

    Ok(())
}

/// Persist a single discovered host with all its ports, services, and edges.
async fn persist_discovered_host(graph: &GraphClient, discovered: &DiscoveredHost) -> Result<()> {
    graph.upsert_host(&discovered.host).await?;

    for port in &discovered.ports {
        graph.upsert_node(&Node::Port(port.clone())).await?;
    }

    for svc in &discovered.services {
        graph.upsert_service(svc).await?;
    }

    for edge in &discovered.edges {
        graph.upsert_edge(edge).await?;
    }

    Ok(())
}

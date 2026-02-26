//! Subgraph fetching from Neo4j via the GraphClient.

use sentinel_core::TenantId;
use sentinel_graph::queries::SubgraphResult;
use sentinel_graph::GraphClient;

use crate::error::Result;

/// Fetch the full tenant subgraph (all nodes and all edges).
///
/// For graphs with >10K nodes, fetching the full subgraph and running algorithms
/// in-memory is more efficient than repeated neighbor queries.
pub async fn fetch_tenant_subgraph(
    client: &GraphClient,
    tenant_id: &TenantId,
    node_limit: u32,
) -> Result<SubgraphResult> {
    let result = client
        .fetch_subgraph(tenant_id, node_limit, node_limit * 5)
        .await?;
    Ok(result)
}

/// Fetch a subgraph within N hops of a specific node.
///
/// Used for blast radius when the full graph isn't needed.
pub async fn fetch_neighborhood(
    client: &GraphClient,
    tenant_id: &TenantId,
    center_node_id: &str,
    max_hops: u32,
) -> Result<SubgraphResult> {
    let result = client
        .fetch_neighborhood(tenant_id, center_node_id, max_hops)
        .await?;
    Ok(result)
}

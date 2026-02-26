//! Request and response types for pathfinding operations.

use serde::{Deserialize, Serialize};

use sentinel_core::types::{AttackPath, AttackStep, TenantId};

/// Request to compute attack paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathfindRequest {
    pub tenant_id: TenantId,
    /// Specific source node IDs. If None, uses internet-facing nodes.
    pub sources: Option<Vec<String>>,
    /// Specific target node IDs. If None, uses crown jewels.
    pub targets: Option<Vec<String>>,
    /// Maximum DFS depth (default: 10).
    pub max_depth: Option<usize>,
    /// Maximum number of paths to return (default: 100).
    pub max_paths: Option<usize>,
    /// Minimum exploitability for edge traversal.
    pub min_exploitability: Option<f64>,
    /// Also detect lateral movement chains.
    pub include_lateral: Option<bool>,
    /// Also compute blast radius for source nodes.
    pub include_blast: Option<bool>,
    /// Maximum nodes to fetch from Neo4j (default: 50000).
    pub node_limit: Option<u32>,
}

/// Complete result of a pathfinding computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathfindResult {
    pub tenant_id: TenantId,
    pub attack_paths: Vec<AttackPath>,
    pub lateral_chains: Option<Vec<LateralChainResult>>,
    pub blast_radii: Option<Vec<BlastRadiusResult>>,
    pub graph_stats: GraphStats,
    pub computation_ms: u64,
    pub engram_id: Option<String>,
}

/// A detected lateral movement chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralChainResult {
    pub steps: Vec<AttackStep>,
    pub techniques: Vec<String>,
    pub risk_score: f64,
}

/// Request for blast radius computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusRequest {
    pub tenant_id: TenantId,
    pub compromised_node_id: String,
    pub max_hops: Option<usize>,
    pub min_exploitability: Option<f64>,
}

/// Result of a blast radius computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusResult {
    pub compromised_node_id: String,
    pub reachable_nodes: Vec<ReachableNode>,
    pub total_reachable: usize,
    pub critical_reachable: usize,
    pub blast_score: f64,
}

/// A node reachable from the compromised node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachableNode {
    pub node_id: String,
    pub label: String,
    pub hops: usize,
    pub cumulative_exploitability: f64,
}

/// Statistics about the in-memory graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub internet_facing_count: usize,
    pub crown_jewel_count: usize,
}

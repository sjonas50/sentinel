//! sentinel-pathfind: Attack path computation for the Sentinel knowledge graph.
//!
//! Fetches a tenant's subgraph from Neo4j, builds an in-memory representation,
//! and runs pathfinding algorithms (all-paths, shortest, lateral movement,
//! blast radius) with risk scoring. Records an Engram audit trail for
//! every computation.

pub mod algorithms;
pub mod blast;
pub mod engram;
pub mod error;
pub mod fetch;
pub mod graph;
pub mod lateral;
pub mod scoring;
pub mod types;

pub use error::PathfindError;
pub use types::{BlastRadiusRequest, BlastRadiusResult, PathfindRequest, PathfindResult};

use chrono::Utc;
use sentinel_core::types::{AttackPath, AttackStep, EdgeId, NodeId, TenantId};
use sentinel_graph::GraphClient;
use uuid::Uuid;

use crate::algorithms::RawPath;
use crate::graph::InMemoryGraph;
use crate::scoring::ScoringConfig;

/// The main attack path computation engine.
pub struct PathfindEngine {
    graph_client: GraphClient,
    scoring_config: ScoringConfig,
    engram_dir: Option<String>,
}

impl PathfindEngine {
    /// Create a new engine with default scoring configuration.
    pub fn new(graph_client: GraphClient) -> Self {
        Self {
            graph_client,
            scoring_config: ScoringConfig::default(),
            engram_dir: None,
        }
    }

    /// Set a custom scoring configuration.
    pub fn with_scoring_config(mut self, config: ScoringConfig) -> Self {
        self.scoring_config = config;
        self
    }

    /// Enable Engram audit trail recording.
    pub fn with_engram_dir(mut self, dir: String) -> Self {
        self.engram_dir = Some(dir);
        self
    }

    /// Compute attack paths for a tenant.
    ///
    /// Orchestrates: fetch subgraph → build in-memory graph → identify sources/targets →
    /// run algorithms → score → convert to AttackPath → engram → return.
    pub async fn compute_attack_paths(
        &self,
        request: PathfindRequest,
    ) -> error::Result<PathfindResult> {
        let start = std::time::Instant::now();
        let tenant_str = request.tenant_id.0.to_string();

        // Start engram session.
        let mut session = engram::start_pathfind_session(
            request.tenant_id.0,
            "compute_attack_paths",
            serde_json::json!({
                "max_depth": request.max_depth,
                "max_paths": request.max_paths,
                "include_lateral": request.include_lateral,
                "include_blast": request.include_blast,
            }),
        );

        // Fetch subgraph from Neo4j.
        let subgraph = fetch::fetch_tenant_subgraph(
            &self.graph_client,
            &request.tenant_id,
            request.node_limit.unwrap_or(50_000),
        )
        .await?;

        if subgraph.nodes.is_empty() {
            return Err(PathfindError::EmptySubgraph {
                tenant_id: tenant_str,
            });
        }

        // Build in-memory graph.
        let mem_graph = InMemoryGraph::from_subgraph(subgraph.nodes, subgraph.edges);
        let graph_stats = types::GraphStats {
            total_nodes: mem_graph.node_count(),
            total_edges: mem_graph.edge_count(),
            internet_facing_count: mem_graph.internet_facing_nodes().len(),
            crown_jewel_count: mem_graph.crown_jewel_nodes().len(),
        };

        engram::record_algorithm_decision(
            &mut session,
            "in_memory_graph",
            &format!(
                "Built in-memory graph with {} nodes, {} edges",
                graph_stats.total_nodes, graph_stats.total_edges
            ),
            serde_json::to_value(&graph_stats).unwrap_or_default(),
        );

        // Identify sources and targets.
        let sources = match &request.sources {
            Some(ids) => ids
                .iter()
                .filter_map(|id| mem_graph.node_index.get(id).copied())
                .collect::<Vec<_>>(),
            None => mem_graph.internet_facing_nodes(),
        };

        let targets = match &request.targets {
            Some(ids) => ids
                .iter()
                .filter_map(|id| mem_graph.node_index.get(id).copied())
                .collect::<Vec<_>>(),
            None => mem_graph.crown_jewel_nodes(),
        };

        if sources.is_empty() {
            return Err(PathfindError::NoEntryPoints {
                tenant_id: tenant_str,
            });
        }
        if targets.is_empty() {
            return Err(PathfindError::NoCrownJewels {
                tenant_id: tenant_str,
            });
        }

        // Run all-paths enumeration.
        let max_depth = request.max_depth.unwrap_or(10);
        let max_paths = request.max_paths.unwrap_or(100);
        let raw_paths = algorithms::enumerate_all_paths(&mem_graph, &sources, &targets, max_depth, max_paths);

        // Score and convert paths.
        let mut attack_paths: Vec<AttackPath> = raw_paths
            .iter()
            .map(|rp| self.raw_path_to_attack_path(rp, &mem_graph, &request.tenant_id))
            .collect();
        attack_paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));

        // Lateral movement detection.
        let lateral_chains = if request.include_lateral.unwrap_or(false) {
            let chains = lateral::detect_lateral_chains(&mem_graph, 2, 8);
            let results: Vec<types::LateralChainResult> = chains
                .into_iter()
                .map(|chain| {
                    let steps = self.raw_path_to_steps(&chain.path, &mem_graph);
                    let risk = scoring::compute_path_risk_score(&mem_graph, &chain.path, &self.scoring_config);
                    types::LateralChainResult {
                        steps,
                        techniques: chain.techniques,
                        risk_score: risk,
                    }
                })
                .collect();
            Some(results)
        } else {
            None
        };

        // Blast radius for source nodes.
        let blast_radii = if request.include_blast.unwrap_or(false) {
            let min_exploit = request.min_exploitability.unwrap_or(0.3);
            let results: Vec<BlastRadiusResult> = sources
                .iter()
                .take(10) // Cap to avoid excessive computation.
                .map(|&idx| blast::compute_blast_radius(&mem_graph, idx, 5, min_exploit))
                .collect();
            Some(results)
        } else {
            None
        };

        let computation_ms = start.elapsed().as_millis() as u64;
        let top_risk = attack_paths.first().map(|p| p.risk_score).unwrap_or(0.0);

        engram::record_pathfind_results(
            &mut session,
            attack_paths.len(),
            top_risk,
            computation_ms,
            serde_json::json!({
                "sources": sources.len(),
                "targets": targets.len(),
                "max_depth": max_depth,
            }),
        );

        let engram_id = self
            .engram_dir
            .as_ref()
            .and_then(|dir| engram::finalize_and_store(session, dir))
            .map(|e| e.id.0.to_string());

        Ok(PathfindResult {
            tenant_id: request.tenant_id,
            attack_paths,
            lateral_chains,
            blast_radii,
            graph_stats,
            computation_ms,
            engram_id,
        })
    }

    /// Compute blast radius from a specific compromised node.
    pub async fn compute_blast_radius(
        &self,
        request: BlastRadiusRequest,
    ) -> error::Result<BlastRadiusResult> {
        let subgraph = fetch::fetch_tenant_subgraph(
            &self.graph_client,
            &request.tenant_id,
            50_000,
        )
        .await?;

        let mem_graph = InMemoryGraph::from_subgraph(subgraph.nodes, subgraph.edges);
        let node_idx = mem_graph
            .node_index
            .get(&request.compromised_node_id)
            .copied()
            .ok_or_else(|| PathfindError::NodeNotFound {
                node_id: request.compromised_node_id.clone(),
            })?;

        let max_hops = request.max_hops.unwrap_or(5);
        let min_exploit = request.min_exploitability.unwrap_or(0.3);
        Ok(blast::compute_blast_radius(&mem_graph, node_idx, max_hops, min_exploit))
    }

    /// Compute the shortest (most exploitable) path between two specific nodes.
    pub async fn shortest_path(
        &self,
        tenant_id: &TenantId,
        source_id: &str,
        target_id: &str,
    ) -> error::Result<Option<AttackPath>> {
        let subgraph = fetch::fetch_tenant_subgraph(
            &self.graph_client,
            tenant_id,
            50_000,
        )
        .await?;

        let mem_graph = InMemoryGraph::from_subgraph(subgraph.nodes, subgraph.edges);
        let src_idx = mem_graph
            .node_index
            .get(source_id)
            .copied()
            .ok_or_else(|| PathfindError::NodeNotFound {
                node_id: source_id.to_string(),
            })?;
        let tgt_idx = mem_graph
            .node_index
            .get(target_id)
            .copied()
            .ok_or_else(|| PathfindError::NodeNotFound {
                node_id: target_id.to_string(),
            })?;

        let raw_path = algorithms::shortest_weighted_path(&mem_graph, src_idx, tgt_idx);
        Ok(raw_path.map(|rp| self.raw_path_to_attack_path(&rp, &mem_graph, tenant_id)))
    }

    /// Convert a `RawPath` into an `AttackPath` with scoring.
    fn raw_path_to_attack_path(
        &self,
        raw: &RawPath,
        graph: &InMemoryGraph,
        tenant_id: &TenantId,
    ) -> AttackPath {
        let risk_score = scoring::compute_path_risk_score(graph, raw, &self.scoring_config);
        let steps = self.raw_path_to_steps(raw, graph);

        let source_id = raw
            .node_indices
            .first()
            .map(|&i| &graph.nodes[i].id)
            .cloned()
            .unwrap_or_default();
        let target_id = raw
            .node_indices
            .last()
            .map(|&i| &graph.nodes[i].id)
            .cloned()
            .unwrap_or_default();

        AttackPath {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.clone(),
            steps,
            risk_score,
            source_node: NodeId(Uuid::parse_str(&source_id).unwrap_or_else(|_| Uuid::new_v4())),
            target_node: NodeId(Uuid::parse_str(&target_id).unwrap_or_else(|_| Uuid::new_v4())),
            computed_at: Utc::now(),
        }
    }

    /// Convert raw path edges into `AttackStep` entries.
    fn raw_path_to_steps(&self, raw: &RawPath, graph: &InMemoryGraph) -> Vec<AttackStep> {
        raw.edges
            .iter()
            .map(|&(from_idx, edge_pos)| {
                let edge = &graph.adjacency[from_idx][edge_pos];
                let target_node = &graph.nodes[edge.target_index];
                AttackStep {
                    node_id: NodeId(
                        Uuid::parse_str(&target_node.id).unwrap_or_else(|_| Uuid::new_v4()),
                    ),
                    edge_id: EdgeId(
                        Uuid::parse_str(&edge.id).unwrap_or_else(|_| Uuid::new_v4()),
                    ),
                    technique: lateral::detect_technique(&edge.edge_type, &target_node.properties),
                    description: format!(
                        "{} -> {} via {}",
                        graph.nodes[from_idx].label, target_node.label, edge.edge_type
                    ),
                    exploitability: edge.exploitability,
                }
            })
            .collect()
    }
}

//! Risk scoring engine for attack paths.
//!
//! Formula: `risk = target_criticality × Σ(step_exploitability) × decay^(N-1)`
//! Normalized to a 0–10 range for CVSS consistency.

use crate::algorithms::RawPath;
use crate::graph::InMemoryGraph;

/// Scoring configuration parameters.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Path probability decay per hop (default 0.9).
    pub decay_factor: f64,
    /// Score ceiling (default 10.0).
    pub max_score: f64,
    /// Default exploitability when an edge has no score (default 0.5).
    pub default_exploitability: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            decay_factor: 0.9,
            max_score: 10.0,
            default_exploitability: 0.5,
        }
    }
}

/// Compute the risk score for an attack path.
///
/// Returns a score in `[0.0, 10.0]` range.
pub fn compute_path_risk_score(
    graph: &InMemoryGraph,
    path: &RawPath,
    config: &ScoringConfig,
) -> f64 {
    if path.node_indices.is_empty() || path.edges.is_empty() {
        return 0.0;
    }

    // Target criticality (last node in path).
    let target_idx = *path.node_indices.last().unwrap();
    let target_criticality = graph.nodes[target_idx].criticality;

    // Sum of edge exploitabilities.
    let exploit_sum: f64 = path
        .edges
        .iter()
        .map(|&(from_idx, edge_pos)| graph.adjacency[from_idx][edge_pos].exploitability)
        .sum();

    // Path probability decay.
    let hop_count = path.edges.len();
    let path_probability = config.decay_factor.powi((hop_count - 1) as i32);

    // Raw score.
    let raw = target_criticality * exploit_sum * path_probability;

    // Theoretical maximum: criticality=1.0, all exploitabilities=1.0, decay=1.0
    let theoretical_max = 1.0 * hop_count as f64;

    if theoretical_max == 0.0 {
        return 0.0;
    }

    // Normalize to 0-10 range.
    let normalized = (raw / theoretical_max) * config.max_score;
    normalized.min(config.max_score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, InMemoryGraph};
    use std::collections::HashMap;

    fn build_scored_graph() -> InMemoryGraph {
        let nodes = vec![
            GraphNode {
                index: 0,
                id: "n0".to_string(),
                label: "Host".to_string(),
                criticality: 0.2,
                is_internet_facing: true,
                is_crown_jewel: false,
                properties: serde_json::json!({}),
            },
            GraphNode {
                index: 1,
                id: "n1".to_string(),
                label: "Service".to_string(),
                criticality: 0.5,
                is_internet_facing: false,
                is_crown_jewel: false,
                properties: serde_json::json!({}),
            },
            GraphNode {
                index: 2,
                id: "n2".to_string(),
                label: "Host".to_string(),
                criticality: 1.0,
                is_internet_facing: false,
                is_crown_jewel: true,
                properties: serde_json::json!({}),
            },
        ];

        let adjacency = vec![
            vec![GraphEdge {
                id: "e01".to_string(),
                edge_type: "CONNECTS_TO".to_string(),
                exploitability: 0.8,
                target_index: 1,
            }],
            vec![GraphEdge {
                id: "e12".to_string(),
                edge_type: "HAS_ACCESS".to_string(),
                exploitability: 0.9,
                target_index: 2,
            }],
            vec![],
        ];

        let mut node_index = HashMap::new();
        for n in &nodes {
            node_index.insert(n.id.clone(), n.index);
        }

        InMemoryGraph {
            nodes,
            adjacency,
            node_index,
        }
    }

    #[test]
    fn test_scoring_known_path() {
        let graph = build_scored_graph();
        let config = ScoringConfig::default();

        // Path: 0 → 1 → 2 (2 hops)
        let path = RawPath {
            node_indices: vec![0, 1, 2],
            edges: vec![(0, 0), (1, 0)],
            total_weight: 0.3,
        };

        let score = compute_path_risk_score(&graph, &path, &config);

        // target_criticality = 1.0
        // exploit_sum = 0.8 + 0.9 = 1.7
        // path_probability = 0.9^1 = 0.9
        // raw = 1.0 * 1.7 * 0.9 = 1.53
        // theoretical_max = 1.0 * 2 = 2.0
        // normalized = (1.53 / 2.0) * 10.0 = 7.65
        assert!((score - 7.65).abs() < 0.01);
    }

    #[test]
    fn test_scoring_single_hop() {
        let graph = build_scored_graph();
        let config = ScoringConfig::default();

        // Path: 0 → 1 (1 hop)
        let path = RawPath {
            node_indices: vec![0, 1],
            edges: vec![(0, 0)],
            total_weight: 0.2,
        };

        let score = compute_path_risk_score(&graph, &path, &config);

        // target_criticality = 0.5
        // exploit_sum = 0.8
        // path_probability = 0.9^0 = 1.0
        // raw = 0.5 * 0.8 * 1.0 = 0.4
        // theoretical_max = 1.0 * 1 = 1.0
        // normalized = (0.4 / 1.0) * 10.0 = 4.0
        assert!((score - 4.0).abs() < 0.01);
    }

    #[test]
    fn test_scoring_empty_path() {
        let graph = build_scored_graph();
        let config = ScoringConfig::default();

        let path = RawPath {
            node_indices: vec![],
            edges: vec![],
            total_weight: 0.0,
        };

        assert!((compute_path_risk_score(&graph, &path, &config) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_capped_at_max() {
        let graph = build_scored_graph();
        let config = ScoringConfig {
            max_score: 10.0,
            decay_factor: 1.0, // No decay
            default_exploitability: 0.5,
        };

        // All exploitabilities at 1.0, criticality at 1.0 → should not exceed 10.0
        let path = RawPath {
            node_indices: vec![0, 1, 2],
            edges: vec![(0, 0), (1, 0)],
            total_weight: 0.0,
        };

        let score = compute_path_risk_score(&graph, &path, &config);
        assert!(score <= 10.0);
    }
}

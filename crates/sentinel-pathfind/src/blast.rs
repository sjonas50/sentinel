//! Blast radius computation.
//!
//! BFS from a compromised node, following edges whose exploitability exceeds
//! a threshold. Tracks hop distance and cumulative exploitability.

use std::collections::{HashSet, VecDeque};

use crate::graph::InMemoryGraph;
use crate::types::{BlastRadiusResult, ReachableNode};

/// Compute the blast radius from a compromised node.
///
/// Uses BFS: at each hop, only continues if the edge exploitability exceeds
/// `min_exploitability`. Tracks cumulative exploitability as the product of
/// edge exploitabilities along the path.
pub fn compute_blast_radius(
    graph: &InMemoryGraph,
    compromised_node: usize,
    max_hops: usize,
    min_exploitability: f64,
) -> BlastRadiusResult {
    let mut visited = HashSet::new();
    visited.insert(compromised_node);

    let mut reachable = Vec::new();
    let mut critical_count = 0;

    // BFS queue: (node_index, hops, cumulative_exploitability)
    let mut queue: VecDeque<(usize, usize, f64)> = VecDeque::new();
    queue.push_back((compromised_node, 0, 1.0));

    while let Some((node, hops, cumul_exploit)) = queue.pop_front() {
        if hops > 0 {
            let graph_node = &graph.nodes[node];
            reachable.push(ReachableNode {
                node_id: graph_node.id.clone(),
                label: graph_node.label.clone(),
                hops,
                cumulative_exploitability: cumul_exploit,
            });
            if graph_node.is_crown_jewel {
                critical_count += 1;
            }
        }

        if hops >= max_hops {
            continue;
        }

        for edge in &graph.adjacency[node] {
            if visited.contains(&edge.target_index) {
                continue;
            }
            if edge.exploitability < min_exploitability {
                continue;
            }

            visited.insert(edge.target_index);
            queue.push_back((
                edge.target_index,
                hops + 1,
                cumul_exploit * edge.exploitability,
            ));
        }
    }

    // Sort by hops ascending, then by cumulative exploitability descending.
    reachable.sort_by(|a, b| {
        a.hops
            .cmp(&b.hops)
            .then_with(|| {
                b.cumulative_exploitability
                    .partial_cmp(&a.cumulative_exploitability)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let total_reachable = reachable.len();

    // Blast score: weighted sum of reachable node criticalities.
    let blast_score: f64 = reachable
        .iter()
        .map(|r| {
            let node_idx = graph.node_index.get(&r.node_id).copied().unwrap_or(0);
            graph.nodes[node_idx].criticality * r.cumulative_exploitability
        })
        .sum();

    BlastRadiusResult {
        compromised_node_id: graph.nodes[compromised_node].id.clone(),
        reachable_nodes: reachable,
        total_reachable,
        critical_reachable: critical_count,
        blast_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, InMemoryGraph};
    use std::collections::HashMap;

    /// Star topology: center (node 0) connects to 4 leaves.
    fn build_star_graph() -> InMemoryGraph {
        let mut nodes = vec![GraphNode {
            index: 0,
            id: "center".to_string(),
            label: "Host".to_string(),
            criticality: 0.5,
            is_internet_facing: false,
            is_crown_jewel: false,
            properties: serde_json::json!({}),
        }];

        let exploitabilities = [0.8, 0.5, 0.2, 0.9];
        let criticalities = [0.5, 1.0, 0.2, 0.8]; // leaf2 is crown jewel
        let is_crown = [false, true, false, false];

        for i in 0..4 {
            nodes.push(GraphNode {
                index: i + 1,
                id: format!("leaf{i}"),
                label: "Host".to_string(),
                criticality: criticalities[i],
                is_internet_facing: false,
                is_crown_jewel: is_crown[i],
                properties: serde_json::json!({}),
            });
        }

        let adjacency = vec![
            // Center node edges to all leaves.
            (0..4)
                .map(|i| GraphEdge {
                    id: format!("e0{}", i + 1),
                    edge_type: "CONNECTS_TO".to_string(),
                    exploitability: exploitabilities[i],
                    target_index: i + 1,
                })
                .collect(),
            vec![],
            vec![],
            vec![],
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
    fn test_blast_radius_star() {
        let graph = build_star_graph();
        let result = compute_blast_radius(&graph, 0, 5, 0.3);

        // Should reach leaf0 (0.8), leaf1 (0.5), leaf3 (0.9) — but not leaf2 (0.2 < 0.3).
        assert_eq!(result.total_reachable, 3);
        assert_eq!(result.compromised_node_id, "center");
    }

    #[test]
    fn test_blast_radius_counts_critical() {
        let graph = build_star_graph();
        let result = compute_blast_radius(&graph, 0, 5, 0.3);

        // leaf1 is a crown jewel and reachable (exploit = 0.5 >= 0.3).
        assert_eq!(result.critical_reachable, 1);
    }

    #[test]
    fn test_blast_radius_max_hops() {
        let graph = build_star_graph();
        let result = compute_blast_radius(&graph, 0, 0, 0.0);

        // With 0 max_hops, no nodes reachable.
        assert_eq!(result.total_reachable, 0);
    }

    #[test]
    fn test_blast_radius_high_threshold() {
        let graph = build_star_graph();
        let result = compute_blast_radius(&graph, 0, 5, 0.95);

        // Only leaf3 (exploit=0.9) is below threshold, no nodes reachable.
        assert_eq!(result.total_reachable, 0);
    }

    #[test]
    fn test_blast_radius_low_threshold() {
        let graph = build_star_graph();
        let result = compute_blast_radius(&graph, 0, 5, 0.0);

        // All 4 leaves reachable.
        assert_eq!(result.total_reachable, 4);
    }

    #[test]
    fn test_blast_radius_sorted_by_hops() {
        let graph = build_star_graph();
        let result = compute_blast_radius(&graph, 0, 5, 0.0);

        // All at hop 1, so should be sorted by cumulative exploitability descending.
        if result.reachable_nodes.len() >= 2 {
            assert!(
                result.reachable_nodes[0].cumulative_exploitability
                    >= result.reachable_nodes[1].cumulative_exploitability
            );
        }
    }
}

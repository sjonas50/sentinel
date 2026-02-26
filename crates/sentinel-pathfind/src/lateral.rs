//! Lateral movement chain detection.
//!
//! Identifies chains of lateral movement techniques (e.g., pass-the-hash,
//! RDP pivoting, SSH pivoting) within the knowledge graph.

use std::collections::HashSet;

use crate::algorithms::RawPath;
use crate::graph::InMemoryGraph;

/// Edge types that represent lateral movement capability.
const LATERAL_EDGE_TYPES: &[&str] = &[
    "HAS_ACCESS",
    "TRUSTS",
    "CAN_REACH",
    "CONNECTS_TO",
];

/// A detected lateral movement chain.
#[derive(Debug, Clone)]
pub struct LateralChain {
    /// The raw path forming this chain.
    pub path: RawPath,
    /// Technique used at each hop.
    pub techniques: Vec<String>,
    /// Number of hops in the chain.
    pub chain_length: usize,
}

/// Detect lateral movement chains in the graph.
///
/// A chain is a path where every edge is a lateral movement type.
/// Returns chains of length >= `min_length` and <= `max_length`.
pub fn detect_lateral_chains(
    graph: &InMemoryGraph,
    min_length: usize,
    max_length: usize,
) -> Vec<LateralChain> {
    let mut chains = Vec::new();

    for start_idx in 0..graph.node_count() {
        let mut stack: Vec<LateralDfsState> = vec![LateralDfsState {
            node: start_idx,
            path_nodes: vec![start_idx],
            path_edges: Vec::new(),
            techniques: Vec::new(),
            weight: 0.0,
            visited: {
                let mut s = HashSet::new();
                s.insert(start_idx);
                s
            },
        }];

        while let Some(state) = stack.pop() {
            // Record chain if it meets minimum length.
            if state.path_edges.len() >= min_length {
                chains.push(LateralChain {
                    path: RawPath {
                        node_indices: state.path_nodes.clone(),
                        edges: state.path_edges.clone(),
                        total_weight: state.weight,
                    },
                    techniques: state.techniques.clone(),
                    chain_length: state.path_edges.len(),
                });
            }

            // Stop extending if at max length.
            if state.path_edges.len() >= max_length {
                continue;
            }

            // Explore lateral edges only.
            for (edge_pos, edge) in graph.adjacency[state.node].iter().enumerate() {
                if state.visited.contains(&edge.target_index) {
                    continue;
                }

                if !is_lateral_edge(&edge.edge_type) {
                    continue;
                }

                let target_node = &graph.nodes[edge.target_index];
                let technique = detect_technique(&edge.edge_type, &target_node.properties)
                    .unwrap_or_else(|| "lateral-movement".to_string());

                let edge_weight = 1.0 - edge.exploitability.clamp(0.0, 1.0);

                let mut new_visited = state.visited.clone();
                new_visited.insert(edge.target_index);

                let mut new_nodes = state.path_nodes.clone();
                new_nodes.push(edge.target_index);

                let mut new_edges = state.path_edges.clone();
                new_edges.push((state.node, edge_pos));

                let mut new_techniques = state.techniques.clone();
                new_techniques.push(technique);

                stack.push(LateralDfsState {
                    node: edge.target_index,
                    path_nodes: new_nodes,
                    path_edges: new_edges,
                    techniques: new_techniques,
                    weight: state.weight + edge_weight,
                    visited: new_visited,
                });
            }
        }
    }

    // Sort by chain length descending (longest chains first).
    chains.sort_by(|a, b| b.chain_length.cmp(&a.chain_length));
    chains
}

/// Check if an edge type is a lateral movement type.
fn is_lateral_edge(edge_type: &str) -> bool {
    LATERAL_EDGE_TYPES.contains(&edge_type)
}

/// Detect the lateral movement technique based on edge type and node properties.
pub fn detect_technique(
    edge_type: &str,
    target_properties: &serde_json::Value,
) -> Option<String> {
    // Check protocol in properties.
    let protocol = target_properties
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    let port = target_properties
        .get("port")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    match edge_type {
        "HAS_ACCESS" => {
            // Check for specific protocols.
            if protocol == "ssh" || port == 22 {
                Some("ssh-pivot".to_string())
            } else if protocol == "rdp" || port == 3389 {
                Some("rdp-hop".to_string())
            } else {
                // Check permissions for admin access.
                if let Some(perms) = target_properties.get("permissions").and_then(|v| v.as_array())
                {
                    let has_admin = perms.iter().any(|p| {
                        p.as_str()
                            .map(|s| s.to_lowercase().contains("admin"))
                            .unwrap_or(false)
                    });
                    if has_admin {
                        return Some("pass-the-hash".to_string());
                    }
                }
                Some("credential-access".to_string())
            }
        }
        "TRUSTS" => Some("trust-exploitation".to_string()),
        "CAN_REACH" => {
            if protocol == "ssh" || port == 22 {
                Some("ssh-pivot".to_string())
            } else if protocol == "rdp" || port == 3389 {
                Some("rdp-hop".to_string())
            } else {
                Some("network-pivot".to_string())
            }
        }
        "CONNECTS_TO" => {
            if protocol == "ssh" || port == 22 {
                Some("ssh-pivot".to_string())
            } else if protocol == "rdp" || port == 3389 {
                Some("rdp-hop".to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Internal DFS state for lateral movement detection.
struct LateralDfsState {
    node: usize,
    path_nodes: Vec<usize>,
    path_edges: Vec<(usize, usize)>,
    techniques: Vec<String>,
    weight: f64,
    visited: HashSet<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, InMemoryGraph};
    use std::collections::HashMap;

    fn build_lateral_graph() -> InMemoryGraph {
        let nodes: Vec<GraphNode> = (0..4)
            .map(|i| GraphNode {
                index: i,
                id: format!("n{i}"),
                label: "Host".to_string(),
                criticality: 0.5,
                is_internet_facing: false,
                is_crown_jewel: false,
                properties: serde_json::json!({}),
            })
            .collect();

        let adjacency = vec![
            // Node 0: HAS_ACCESS to 1 (SSH)
            vec![GraphEdge {
                id: "e01".to_string(),
                edge_type: "HAS_ACCESS".to_string(),
                exploitability: 0.7,
                target_index: 1,
            }],
            // Node 1: TRUSTS 2
            vec![GraphEdge {
                id: "e12".to_string(),
                edge_type: "TRUSTS".to_string(),
                exploitability: 0.8,
                target_index: 2,
            }],
            // Node 2: CAN_REACH 3
            vec![GraphEdge {
                id: "e23".to_string(),
                edge_type: "CAN_REACH".to_string(),
                exploitability: 0.6,
                target_index: 3,
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
    fn test_detect_lateral_chains() {
        let graph = build_lateral_graph();
        let chains = detect_lateral_chains(&graph, 2, 8);

        assert!(!chains.is_empty());
        // Should find chains of length 2 and 3.
        let lengths: Vec<usize> = chains.iter().map(|c| c.chain_length).collect();
        assert!(lengths.contains(&2));
        assert!(lengths.contains(&3));
    }

    #[test]
    fn test_detect_lateral_chains_min_length() {
        let graph = build_lateral_graph();
        let chains = detect_lateral_chains(&graph, 3, 8);

        // Only chains of length 3+.
        for chain in &chains {
            assert!(chain.chain_length >= 3);
        }
    }

    #[test]
    fn test_detect_technique_ssh() {
        let props = serde_json::json!({"protocol": "ssh", "port": 22});
        assert_eq!(
            detect_technique("HAS_ACCESS", &props),
            Some("ssh-pivot".to_string())
        );
    }

    #[test]
    fn test_detect_technique_rdp() {
        let props = serde_json::json!({"port": 3389});
        assert_eq!(
            detect_technique("CAN_REACH", &props),
            Some("rdp-hop".to_string())
        );
    }

    #[test]
    fn test_detect_technique_trust() {
        let props = serde_json::json!({});
        assert_eq!(
            detect_technique("TRUSTS", &props),
            Some("trust-exploitation".to_string())
        );
    }

    #[test]
    fn test_non_lateral_edges_ignored() {
        let nodes: Vec<GraphNode> = (0..3)
            .map(|i| GraphNode {
                index: i,
                id: format!("n{i}"),
                label: "Host".to_string(),
                criticality: 0.5,
                is_internet_facing: false,
                is_crown_jewel: false,
                properties: serde_json::json!({}),
            })
            .collect();

        let adjacency = vec![
            vec![GraphEdge {
                id: "e01".to_string(),
                edge_type: "RUNS_ON".to_string(), // Not lateral
                exploitability: 0.7,
                target_index: 1,
            }],
            vec![GraphEdge {
                id: "e12".to_string(),
                edge_type: "HAS_CVE".to_string(), // Not lateral
                exploitability: 0.8,
                target_index: 2,
            }],
            vec![],
        ];

        let mut node_index = HashMap::new();
        for n in &nodes {
            node_index.insert(n.id.clone(), n.index);
        }

        let graph = InMemoryGraph {
            nodes,
            adjacency,
            node_index,
        };

        let chains = detect_lateral_chains(&graph, 1, 8);
        assert!(chains.is_empty());
    }
}

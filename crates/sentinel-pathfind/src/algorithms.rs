//! Core pathfinding algorithms: DFS all-paths and Dijkstra shortest weighted path.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

use crate::graph::InMemoryGraph;

/// A raw path through the in-memory graph.
#[derive(Debug, Clone)]
pub struct RawPath {
    /// Node indices along the path.
    pub node_indices: Vec<usize>,
    /// Edges along the path as (from_node_index, edge_position_in_adjacency_list).
    pub edges: Vec<(usize, usize)>,
    /// Total weight (sum of 1.0 - exploitability for each edge).
    pub total_weight: f64,
}

/// All-paths enumeration from source nodes to target nodes using DFS.
///
/// Finds all paths from any source to any target with cycle detection and depth limiting.
/// Returns paths sorted by total weight ascending (most exploitable first).
pub fn enumerate_all_paths(
    graph: &InMemoryGraph,
    sources: &[usize],
    targets: &[usize],
    max_depth: usize,
    max_paths: usize,
) -> Vec<RawPath> {
    let target_set: HashSet<usize> = targets.iter().copied().collect();
    let mut all_paths = Vec::new();

    for &source in sources {
        if all_paths.len() >= max_paths {
            break;
        }

        let mut stack: Vec<DfsState> = vec![DfsState {
            node: source,
            path_nodes: vec![source],
            path_edges: Vec::new(),
            weight: 0.0,
            visited: {
                let mut s = HashSet::new();
                s.insert(source);
                s
            },
        }];

        while let Some(state) = stack.pop() {
            if all_paths.len() >= max_paths {
                break;
            }

            // Check if we've reached a target.
            if state.path_nodes.len() > 1 && target_set.contains(&state.node) {
                all_paths.push(RawPath {
                    node_indices: state.path_nodes.clone(),
                    edges: state.path_edges.clone(),
                    total_weight: state.weight,
                });
                continue;
            }

            // Stop if we've reached max depth.
            if state.path_nodes.len() > max_depth {
                continue;
            }

            // Explore neighbors.
            for (edge_pos, edge) in graph.adjacency[state.node].iter().enumerate() {
                if state.visited.contains(&edge.target_index) {
                    continue;
                }

                let edge_weight = 1.0 - edge.exploitability.clamp(0.0, 1.0);
                let mut new_visited = state.visited.clone();
                new_visited.insert(edge.target_index);

                let mut new_nodes = state.path_nodes.clone();
                new_nodes.push(edge.target_index);

                let mut new_edges = state.path_edges.clone();
                new_edges.push((state.node, edge_pos));

                stack.push(DfsState {
                    node: edge.target_index,
                    path_nodes: new_nodes,
                    path_edges: new_edges,
                    weight: state.weight + edge_weight,
                    visited: new_visited,
                });
            }
        }
    }

    // Sort by total weight ascending (most exploitable path = lowest weight first).
    all_paths.sort_by(|a, b| {
        a.total_weight
            .partial_cmp(&b.total_weight)
            .unwrap_or(Ordering::Equal)
    });

    all_paths.truncate(max_paths);
    all_paths
}

/// Shortest weighted path using Dijkstra's algorithm.
///
/// Edge weight = `1.0 - exploitability` so the most exploitable path has the
/// lowest total weight. Returns the single shortest path, or `None` if
/// unreachable.
pub fn shortest_weighted_path(
    graph: &InMemoryGraph,
    source: usize,
    target: usize,
) -> Option<RawPath> {
    let n = graph.node_count();
    let mut dist = vec![f64::INFINITY; n];
    let mut prev: Vec<Option<(usize, usize)>> = vec![None; n]; // (parent_node, edge_pos)
    let mut visited = vec![false; n];

    dist[source] = 0.0;

    let mut heap = BinaryHeap::new();
    heap.push(DijkstraState {
        cost: 0.0,
        node: source,
    });

    while let Some(DijkstraState { cost, node }) = heap.pop() {
        if node == target {
            break;
        }

        if visited[node] {
            continue;
        }
        visited[node] = true;

        if cost > dist[node] {
            continue;
        }

        for (edge_pos, edge) in graph.adjacency[node].iter().enumerate() {
            let edge_weight = 1.0 - edge.exploitability.clamp(0.0, 1.0);
            let new_dist = dist[node] + edge_weight;

            if new_dist < dist[edge.target_index] {
                dist[edge.target_index] = new_dist;
                prev[edge.target_index] = Some((node, edge_pos));
                heap.push(DijkstraState {
                    cost: new_dist,
                    node: edge.target_index,
                });
            }
        }
    }

    // No path found.
    if dist[target].is_infinite() {
        return None;
    }

    // Reconstruct path.
    let mut node_indices = Vec::new();
    let mut edges = Vec::new();
    let mut current = target;

    while let Some((parent, edge_pos)) = prev[current] {
        node_indices.push(current);
        edges.push((parent, edge_pos));
        current = parent;
    }
    node_indices.push(source);

    node_indices.reverse();
    edges.reverse();

    Some(RawPath {
        node_indices,
        edges,
        total_weight: dist[target],
    })
}

/// Internal DFS state for all-paths enumeration.
struct DfsState {
    node: usize,
    path_nodes: Vec<usize>,
    path_edges: Vec<(usize, usize)>,
    weight: f64,
    visited: HashSet<usize>,
}

/// State for Dijkstra's priority queue (min-heap by cost).
#[derive(Debug, Clone, PartialEq)]
struct DijkstraState {
    cost: f64,
    node: usize,
}

impl Eq for DijkstraState {}

impl Ord for DijkstraState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap (BinaryHeap is a max-heap).
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for DijkstraState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, InMemoryGraph};
    use std::collections::HashMap;

    /// Build a small test graph:
    ///
    /// ```text
    /// 0 --0.8--> 1 --0.9--> 3
    /// 0 --0.3--> 2 --0.4--> 3
    /// ```
    ///
    /// Node 0 is internet-facing, node 3 is a crown jewel.
    fn build_test_graph() -> InMemoryGraph {
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
                label: "Service".to_string(),
                criticality: 0.5,
                is_internet_facing: false,
                is_crown_jewel: false,
                properties: serde_json::json!({}),
            },
            GraphNode {
                index: 3,
                id: "n3".to_string(),
                label: "Host".to_string(),
                criticality: 1.0,
                is_internet_facing: false,
                is_crown_jewel: true,
                properties: serde_json::json!({}),
            },
        ];

        let adjacency = vec![
            // Node 0: edges to 1 and 2
            vec![
                GraphEdge {
                    id: "e01".to_string(),
                    edge_type: "CONNECTS_TO".to_string(),
                    exploitability: 0.8,
                    target_index: 1,
                },
                GraphEdge {
                    id: "e02".to_string(),
                    edge_type: "CONNECTS_TO".to_string(),
                    exploitability: 0.3,
                    target_index: 2,
                },
            ],
            // Node 1: edge to 3
            vec![GraphEdge {
                id: "e13".to_string(),
                edge_type: "HAS_ACCESS".to_string(),
                exploitability: 0.9,
                target_index: 3,
            }],
            // Node 2: edge to 3
            vec![GraphEdge {
                id: "e23".to_string(),
                edge_type: "CONNECTS_TO".to_string(),
                exploitability: 0.4,
                target_index: 3,
            }],
            // Node 3: no outgoing edges
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
    fn test_enumerate_all_paths_finds_both() {
        let graph = build_test_graph();
        let sources = vec![0];
        let targets = vec![3];

        let paths = enumerate_all_paths(&graph, &sources, &targets, 10, 100);
        assert_eq!(paths.len(), 2);

        // First path should be via node 1 (most exploitable = lowest weight).
        // Path 0→1→3: weight = (1-0.8) + (1-0.9) = 0.2 + 0.1 = 0.3
        // Path 0→2→3: weight = (1-0.3) + (1-0.4) = 0.7 + 0.6 = 1.3
        assert!((paths[0].total_weight - 0.3).abs() < 0.01);
        assert!((paths[1].total_weight - 1.3).abs() < 0.01);
    }

    #[test]
    fn test_enumerate_respects_max_depth() {
        let graph = build_test_graph();
        let sources = vec![0];
        let targets = vec![3];

        // With max_depth=1, no paths should be found (all paths require 2 hops).
        let paths = enumerate_all_paths(&graph, &sources, &targets, 1, 100);
        assert_eq!(paths.len(), 0);
    }

    #[test]
    fn test_enumerate_respects_max_paths() {
        let graph = build_test_graph();
        let sources = vec![0];
        let targets = vec![3];

        let paths = enumerate_all_paths(&graph, &sources, &targets, 10, 1);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_shortest_weighted_path() {
        let graph = build_test_graph();
        let path = shortest_weighted_path(&graph, 0, 3);

        assert!(path.is_some());
        let path = path.unwrap();
        // Shortest = 0→1→3 with weight 0.3
        assert_eq!(path.node_indices, vec![0, 1, 3]);
        assert!((path.total_weight - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_shortest_path_unreachable() {
        let graph = build_test_graph();
        // Node 3 has no outgoing edges, so can't reach node 0.
        let path = shortest_weighted_path(&graph, 3, 0);
        assert!(path.is_none());
    }

    #[test]
    fn test_shortest_path_same_node() {
        let graph = build_test_graph();
        let path = shortest_weighted_path(&graph, 0, 0);
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.node_indices, vec![0]);
        assert!((path.total_weight - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cycle_detection() {
        // Build graph with a cycle: 0 → 1 → 2 → 0 → ... and 2 → 3
        let nodes: Vec<GraphNode> = (0..4)
            .map(|i| GraphNode {
                index: i,
                id: format!("n{i}"),
                label: "Host".to_string(),
                criticality: if i == 3 { 1.0 } else { 0.2 },
                is_internet_facing: i == 0,
                is_crown_jewel: i == 3,
                properties: serde_json::json!({}),
            })
            .collect();

        let adjacency = vec![
            vec![GraphEdge {
                id: "e01".to_string(),
                edge_type: "CONNECTS_TO".to_string(),
                exploitability: 0.8,
                target_index: 1,
            }],
            vec![GraphEdge {
                id: "e12".to_string(),
                edge_type: "CONNECTS_TO".to_string(),
                exploitability: 0.7,
                target_index: 2,
            }],
            vec![
                GraphEdge {
                    id: "e20".to_string(),
                    edge_type: "CONNECTS_TO".to_string(),
                    exploitability: 0.6,
                    target_index: 0,
                },
                GraphEdge {
                    id: "e23".to_string(),
                    edge_type: "HAS_ACCESS".to_string(),
                    exploitability: 0.9,
                    target_index: 3,
                },
            ],
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

        let paths = enumerate_all_paths(&graph, &[0], &[3], 10, 100);
        // Should find exactly 1 path: 0 → 1 → 2 → 3 (no cycling).
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].node_indices, vec![0, 1, 2, 3]);
    }
}

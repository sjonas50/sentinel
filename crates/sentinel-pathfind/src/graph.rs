//! In-memory graph representation for pathfinding algorithms.
//!
//! Converts Neo4j `NodeRecord` and `EdgeRecord` into a compact adjacency list
//! optimized for cache-friendly traversal during pathfinding.

use std::collections::HashMap;

use sentinel_graph::queries::{EdgeRecord, NodeRecord};

/// Compact node metadata stored in the in-memory graph.
#[derive(Debug, Clone)]
pub struct GraphNode {
    /// Dense index (0..N-1) for O(1) lookup.
    pub index: usize,
    /// Original node ID (UUID string).
    pub id: String,
    /// Node label: "Host", "Service", "Subnet", etc.
    pub label: String,
    /// Numeric criticality weight (0.0–1.0).
    pub criticality: f64,
    /// Whether this node is internet-facing (entry point).
    pub is_internet_facing: bool,
    /// Whether this node is a crown jewel (high-value target).
    pub is_crown_jewel: bool,
    /// Raw properties for technique detection.
    pub properties: serde_json::Value,
}

/// Compact edge metadata for the adjacency list.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    /// Original edge ID.
    pub id: String,
    /// Relationship type: "CONNECTS_TO", "HAS_ACCESS", etc.
    pub edge_type: String,
    /// Exploitability score (0.0–1.0). Higher = easier to exploit.
    pub exploitability: f64,
    /// Target node index in the adjacency list.
    pub target_index: usize,
}

/// The in-memory graph for pathfinding algorithms.
pub struct InMemoryGraph {
    /// All nodes, indexed by dense index.
    pub nodes: Vec<GraphNode>,
    /// Adjacency list: `adjacency[i]` = outgoing edges from node `i`.
    pub adjacency: Vec<Vec<GraphEdge>>,
    /// Map from original node ID → dense index.
    pub node_index: HashMap<String, usize>,
}

impl InMemoryGraph {
    /// Build from fetched subgraph data.
    pub fn from_subgraph(nodes: Vec<NodeRecord>, edges: Vec<EdgeRecord>) -> Self {
        let mut node_index = HashMap::with_capacity(nodes.len());
        let mut graph_nodes = Vec::with_capacity(nodes.len());

        for (i, record) in nodes.iter().enumerate() {
            node_index.insert(record.id.clone(), i);

            let criticality = extract_criticality(&record.properties);
            let is_internet_facing = detect_internet_facing(&record.label, &record.properties);
            let is_crown_jewel = detect_crown_jewel(criticality, &record.properties);

            graph_nodes.push(GraphNode {
                index: i,
                id: record.id.clone(),
                label: record.label.clone(),
                criticality,
                is_internet_facing,
                is_crown_jewel,
                properties: record.properties.clone(),
            });
        }

        let mut adjacency = vec![Vec::new(); graph_nodes.len()];

        for edge in &edges {
            if let (Some(&src_idx), Some(&tgt_idx)) = (
                node_index.get(&edge.source_id),
                node_index.get(&edge.target_id),
            ) {
                let exploitability = extract_exploitability(&edge.properties);
                adjacency[src_idx].push(GraphEdge {
                    id: edge.id.clone(),
                    edge_type: edge.edge_type.clone(),
                    exploitability,
                    target_index: tgt_idx,
                });
            }
        }

        Self {
            nodes: graph_nodes,
            adjacency,
            node_index,
        }
    }

    /// Get all internet-facing node indices (entry points).
    pub fn internet_facing_nodes(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.is_internet_facing)
            .map(|n| n.index)
            .collect()
    }

    /// Get all crown jewel node indices (high-value targets).
    pub fn crown_jewel_nodes(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.is_crown_jewel)
            .map(|n| n.index)
            .collect()
    }

    /// Number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.adjacency.iter().map(|edges| edges.len()).sum()
    }
}

/// Map criticality string to a numeric weight.
pub fn criticality_weight(criticality: &str) -> f64 {
    match criticality.to_lowercase().as_str() {
        "critical" => 1.0,
        "high" => 0.8,
        "medium" => 0.5,
        "low" => 0.2,
        "info" => 0.1,
        _ => 0.1,
    }
}

/// Extract criticality from node properties.
fn extract_criticality(properties: &serde_json::Value) -> f64 {
    properties
        .get("criticality")
        .and_then(|v| v.as_str())
        .map(criticality_weight)
        .unwrap_or(0.1)
}

/// Detect if a node is internet-facing.
fn detect_internet_facing(label: &str, properties: &serde_json::Value) -> bool {
    // Subnets with is_public = true.
    if label == "Subnet" {
        if let Some(is_public) = properties.get("is_public").and_then(|v| v.as_bool()) {
            return is_public;
        }
        if let Some(is_public) = properties.get("is_public").and_then(|v| v.as_str()) {
            return is_public == "true";
        }
    }

    // Check tags for internet-facing markers.
    if let Some(tags) = properties.get("tags").and_then(|v| v.as_array()) {
        for tag in tags {
            if let Some(s) = tag.as_str() {
                let lower = s.to_lowercase();
                if lower.contains("internet-facing")
                    || lower.contains("internet_facing")
                    || lower.contains("dmz")
                    || lower.contains("public")
                {
                    return true;
                }
            }
        }
    }

    false
}

/// Detect if a node is a crown jewel (high-value target).
fn detect_crown_jewel(criticality: f64, properties: &serde_json::Value) -> bool {
    // Critical nodes are crown jewels.
    if criticality >= 1.0 {
        return true;
    }

    // Check tags.
    if let Some(tags) = properties.get("tags").and_then(|v| v.as_array()) {
        for tag in tags {
            if let Some(s) = tag.as_str() {
                let lower = s.to_lowercase();
                if lower.contains("crown-jewel")
                    || lower.contains("crown_jewel")
                    || lower.contains("critical-asset")
                {
                    return true;
                }
            }
        }
    }

    false
}

/// Extract exploitability score from edge properties.
fn extract_exploitability(properties: &serde_json::Value) -> f64 {
    properties
        .get("exploitability_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, label: &str, props: serde_json::Value) -> NodeRecord {
        NodeRecord {
            id: id.to_string(),
            label: label.to_string(),
            tenant_id: "t-1".to_string(),
            properties: props,
        }
    }

    fn make_edge(
        id: &str,
        edge_type: &str,
        source: &str,
        target: &str,
        exploit: f64,
    ) -> EdgeRecord {
        EdgeRecord {
            id: id.to_string(),
            edge_type: edge_type.to_string(),
            source_id: source.to_string(),
            target_id: target.to_string(),
            properties: serde_json::json!({ "exploitability_score": exploit }),
        }
    }

    #[test]
    fn test_from_subgraph_basic() {
        let nodes = vec![
            make_node("n1", "Host", serde_json::json!({"criticality": "high"})),
            make_node("n2", "Service", serde_json::json!({})),
            make_node("n3", "Host", serde_json::json!({"criticality": "critical"})),
        ];
        let edges = vec![
            make_edge("e1", "CONNECTS_TO", "n1", "n2", 0.7),
            make_edge("e2", "RUNS_ON", "n2", "n3", 0.9),
        ];

        let graph = InMemoryGraph::from_subgraph(nodes, edges);

        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);
        assert_eq!(graph.adjacency[0].len(), 1);
        assert_eq!(graph.adjacency[1].len(), 1);
        assert_eq!(graph.adjacency[2].len(), 0);
    }

    #[test]
    fn test_internet_facing_detection() {
        let nodes = vec![
            make_node(
                "s1",
                "Subnet",
                serde_json::json!({"is_public": true}),
            ),
            make_node("h1", "Host", serde_json::json!({"tags": ["dmz", "web"]})),
            make_node("h2", "Host", serde_json::json!({"criticality": "low"})),
        ];

        let graph = InMemoryGraph::from_subgraph(nodes, vec![]);
        let internet_facing = graph.internet_facing_nodes();

        assert_eq!(internet_facing.len(), 2);
        assert!(internet_facing.contains(&0)); // Subnet with is_public
        assert!(internet_facing.contains(&1)); // Host with dmz tag
    }

    #[test]
    fn test_crown_jewel_detection() {
        let nodes = vec![
            make_node(
                "db1",
                "Host",
                serde_json::json!({"criticality": "critical"}),
            ),
            make_node(
                "db2",
                "Host",
                serde_json::json!({"tags": ["crown-jewel"], "criticality": "high"}),
            ),
            make_node("web1", "Host", serde_json::json!({"criticality": "low"})),
        ];

        let graph = InMemoryGraph::from_subgraph(nodes, vec![]);
        let crown_jewels = graph.crown_jewel_nodes();

        assert_eq!(crown_jewels.len(), 2);
        assert!(crown_jewels.contains(&0)); // criticality == critical
        assert!(crown_jewels.contains(&1)); // crown-jewel tag
    }

    #[test]
    fn test_criticality_weight() {
        assert_eq!(criticality_weight("critical"), 1.0);
        assert_eq!(criticality_weight("high"), 0.8);
        assert_eq!(criticality_weight("medium"), 0.5);
        assert_eq!(criticality_weight("low"), 0.2);
        assert_eq!(criticality_weight("info"), 0.1);
        assert_eq!(criticality_weight("unknown"), 0.1);
    }

    #[test]
    fn test_exploitability_extraction() {
        let props = serde_json::json!({"exploitability_score": 0.85});
        assert!((extract_exploitability(&props) - 0.85).abs() < f64::EPSILON);

        let empty = serde_json::json!({});
        assert!((extract_exploitability(&empty) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_edge_with_missing_node_ignored() {
        let nodes = vec![make_node("n1", "Host", serde_json::json!({}))];
        let edges = vec![make_edge("e1", "CONNECTS_TO", "n1", "n_missing", 0.5)];

        let graph = InMemoryGraph::from_subgraph(nodes, edges);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_node_index_mapping() {
        let nodes = vec![
            make_node("alpha", "Host", serde_json::json!({})),
            make_node("beta", "Service", serde_json::json!({})),
        ];

        let graph = InMemoryGraph::from_subgraph(nodes, vec![]);
        assert_eq!(graph.node_index.get("alpha"), Some(&0));
        assert_eq!(graph.node_index.get("beta"), Some(&1));
        assert_eq!(graph.node_index.get("gamma"), None);
    }
}

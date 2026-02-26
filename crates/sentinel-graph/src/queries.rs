//! Read operations and Cypher query builder for the knowledge graph.

use neo4rs::query;

use sentinel_core::{NodeId, TenantId};

use crate::client::{GraphClient, GraphError};

/// A lightweight record returned from node queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeRecord {
    pub id: String,
    pub label: String,
    pub tenant_id: String,
    pub properties: serde_json::Value,
}

/// A lightweight record returned from edge queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EdgeRecord {
    pub id: String,
    pub edge_type: String,
    pub source_id: String,
    pub target_id: String,
    pub properties: serde_json::Value,
}

/// A neighbor result: node + the connecting edge.
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub node: NodeRecord,
    pub edge: EdgeRecord,
}

/// Result of a subgraph query.
#[derive(Debug, Clone, Default)]
pub struct SubgraphResult {
    pub nodes: Vec<NodeRecord>,
    pub edges: Vec<EdgeRecord>,
}

impl GraphClient {
    // ── Single Node Lookups ──────────────────────────────────────

    /// Get a node by label, tenant, and id.
    pub async fn get_node(
        &self,
        tenant_id: &TenantId,
        label: &str,
        node_id: &NodeId,
    ) -> Result<NodeRecord, GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id, id: $id}})
             RETURN n"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id.0.to_string())
            .param("id", node_id.0.to_string());

        match self.query_one(q).await? {
            Some(row) => {
                let node: neo4rs::Node = row.get("n").map_err(|e| {
                    GraphError::Serialization(format!("Failed to deserialize node: {e}"))
                })?;
                Ok(neo4j_node_to_record(&node, label))
            }
            None => Err(GraphError::NotFound {
                label: label.to_string(),
                id: node_id.0.to_string(),
                tenant_id: tenant_id.0.to_string(),
            }),
        }
    }

    /// Get a node by a property lookup (e.g., Host by IP).
    pub async fn find_node_by_property(
        &self,
        tenant_id: &TenantId,
        label: &str,
        property: &str,
        value: &str,
    ) -> Result<Option<NodeRecord>, GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id, {property}: $value}})
             RETURN n LIMIT 1"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id.0.to_string())
            .param("value", value.to_string());

        match self.query_one(q).await? {
            Some(row) => {
                let node: neo4rs::Node = row.get("n").map_err(|e| {
                    GraphError::Serialization(format!("Failed to deserialize node: {e}"))
                })?;
                Ok(Some(neo4j_node_to_record(&node, label)))
            }
            None => Ok(None),
        }
    }

    // ── List Queries ─────────────────────────────────────────────

    /// List all nodes of a given label for a tenant.
    pub async fn list_nodes(
        &self,
        tenant_id: &TenantId,
        label: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<NodeRecord>, GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id}})
             RETURN n
             ORDER BY n.last_seen DESC
             SKIP $offset LIMIT $limit"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id.0.to_string())
            .param("limit", limit as i64)
            .param("offset", offset as i64);

        let rows = self.query_rows(q).await?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let node: neo4rs::Node = row.get("n").map_err(|e| {
                GraphError::Serialization(format!("Failed to deserialize node: {e}"))
            })?;
            results.push(neo4j_node_to_record(&node, label));
        }
        Ok(results)
    }

    /// Count nodes of a given label for a tenant.
    pub async fn count_nodes(&self, tenant_id: &TenantId, label: &str) -> Result<i64, GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id}})
             RETURN count(n) AS cnt"
        );

        let q = query(&cypher).param("tenant_id", tenant_id.0.to_string());

        match self.query_one(q).await? {
            Some(row) => Ok(row.get::<i64>("cnt").unwrap_or(0)),
            None => Ok(0),
        }
    }

    // ── Neighbor Queries ─────────────────────────────────────────

    /// Get all neighbors of a node (any direction, any relationship type).
    pub async fn get_neighbors(
        &self,
        tenant_id: &TenantId,
        node_id: &NodeId,
        limit: u32,
    ) -> Result<Vec<Neighbor>, GraphError> {
        let q = query(
            "MATCH (a {tenant_id: $tenant_id, id: $id})-[r]-(b)
             WHERE b.tenant_id = $tenant_id
             RETURN b, r, type(r) AS rel_type, labels(b) AS labels
             LIMIT $limit",
        )
        .param("tenant_id", tenant_id.0.to_string())
        .param("id", node_id.0.to_string())
        .param("limit", limit as i64);

        let rows = self.query_rows(q).await?;
        let mut results = Vec::with_capacity(rows.len());

        for row in rows {
            let neo_node: neo4rs::Node = row.get("b").map_err(|e| {
                GraphError::Serialization(format!("Failed to get neighbor node: {e}"))
            })?;
            let rel_type: String = row.get("rel_type").unwrap_or_default();
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let label = labels.first().cloned().unwrap_or_default();

            let node_record = neo4j_node_to_record(&neo_node, &label);

            let neo_rel: neo4rs::Relation = row
                .get("r")
                .map_err(|e| GraphError::Serialization(format!("Failed to get relation: {e}")))?;

            let edge_record = EdgeRecord {
                id: neo_rel.get::<String>("id").unwrap_or_default(),
                edge_type: rel_type,
                source_id: node_id.0.to_string(),
                target_id: node_record.id.clone(),
                properties: serde_json::Value::Object(serde_json::Map::new()),
            };

            results.push(Neighbor {
                node: node_record,
                edge: edge_record,
            });
        }

        Ok(results)
    }

    // ── Path Queries ─────────────────────────────────────────────

    /// Find shortest path between two nodes.
    pub async fn shortest_path(
        &self,
        tenant_id: &TenantId,
        from_id: &NodeId,
        to_id: &NodeId,
        max_hops: u32,
    ) -> Result<Vec<NodeRecord>, GraphError> {
        let q = query(&format!(
            "MATCH p = shortestPath(
               (a {{tenant_id: $tenant_id, id: $from}})-[*..{max_hops}]-
               (b {{tenant_id: $tenant_id, id: $to}})
             )
             UNWIND nodes(p) AS n
             RETURN n, labels(n) AS labels"
        ))
        .param("tenant_id", tenant_id.0.to_string())
        .param("from", from_id.0.to_string())
        .param("to", to_id.0.to_string());

        let rows = self.query_rows(q).await?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let neo_node: neo4rs::Node = row.get("n").map_err(|e| {
                GraphError::Serialization(format!("Failed to deserialize path node: {e}"))
            })?;
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let label = labels.first().cloned().unwrap_or_default();
            results.push(neo4j_node_to_record(&neo_node, &label));
        }
        Ok(results)
    }

    // ── Subgraph Queries ────────────────────────────────────────

    /// Fetch the full subgraph for a tenant: all nodes and all directed edges.
    ///
    /// Used by sentinel-pathfind for in-memory graph construction.
    pub async fn fetch_subgraph(
        &self,
        tenant_id: &TenantId,
        node_limit: u32,
        edge_limit: u32,
    ) -> Result<SubgraphResult, GraphError> {
        // Phase 1: fetch all nodes.
        let node_query = query(
            "MATCH (n {tenant_id: $tenant_id})
             RETURN n, labels(n) AS labels
             LIMIT $limit",
        )
        .param("tenant_id", tenant_id.0.to_string())
        .param("limit", node_limit as i64);

        let node_rows = self.query_rows(node_query).await?;
        let mut nodes = Vec::with_capacity(node_rows.len());

        for row in &node_rows {
            let neo_node: neo4rs::Node = row.get("n").map_err(|e| {
                GraphError::Serialization(format!("Failed to deserialize subgraph node: {e}"))
            })?;
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let label = labels.first().cloned().unwrap_or_default();
            nodes.push(neo4j_node_to_record(&neo_node, &label));
        }

        // Phase 2: fetch all directed edges.
        let edge_query = query(
            "MATCH (a {tenant_id: $tenant_id})-[r]->(b {tenant_id: $tenant_id})
             RETURN r, type(r) AS rel_type, a.id AS src, b.id AS tgt
             LIMIT $limit",
        )
        .param("tenant_id", tenant_id.0.to_string())
        .param("limit", edge_limit as i64);

        let edge_rows = self.query_rows(edge_query).await?;
        let mut edges = Vec::with_capacity(edge_rows.len());

        for row in &edge_rows {
            let rel_type: String = row.get("rel_type").unwrap_or_default();
            let src: String = row.get("src").unwrap_or_default();
            let tgt: String = row.get("tgt").unwrap_or_default();
            let neo_rel: neo4rs::Relation = row.get("r").map_err(|e| {
                GraphError::Serialization(format!("Failed to deserialize subgraph edge: {e}"))
            })?;
            let edge_id: String = neo_rel.get("id").unwrap_or_default();

            // Extract edge properties.
            let mut props = serde_json::Map::new();
            for key in &["exploitability_score", "protocol", "port", "encrypted"] {
                if let Ok(v) = neo_rel.get::<String>(key) {
                    props.insert((*key).to_string(), serde_json::Value::String(v));
                }
            }
            // Try numeric exploitability_score.
            if !props.contains_key("exploitability_score") {
                if let Ok(v) = neo_rel.get::<f64>("exploitability_score") {
                    props.insert(
                        "exploitability_score".to_string(),
                        serde_json::Value::from(v),
                    );
                }
            }

            edges.push(EdgeRecord {
                id: edge_id,
                edge_type: rel_type,
                source_id: src,
                target_id: tgt,
                properties: serde_json::Value::Object(props),
            });
        }

        Ok(SubgraphResult { nodes, edges })
    }

    /// Fetch a neighborhood subgraph within N hops of a specific node.
    pub async fn fetch_neighborhood(
        &self,
        tenant_id: &TenantId,
        center_node_id: &str,
        max_hops: u32,
    ) -> Result<SubgraphResult, GraphError> {
        // Fetch nodes within N hops.
        let node_query = query(&format!(
            "MATCH (center {{tenant_id: $tenant_id, id: $center_id}})
             MATCH p = (center)-[*..{max_hops}]-(n)
             WHERE n.tenant_id = $tenant_id
             WITH DISTINCT n
             RETURN n, labels(n) AS labels"
        ))
        .param("tenant_id", tenant_id.0.to_string())
        .param("center_id", center_node_id.to_string());

        let node_rows = self.query_rows(node_query).await?;
        let mut nodes = Vec::with_capacity(node_rows.len() + 1);

        // Also add the center node itself.
        let center_query = query(
            "MATCH (n {tenant_id: $tenant_id, id: $center_id})
             RETURN n, labels(n) AS labels",
        )
        .param("tenant_id", tenant_id.0.to_string())
        .param("center_id", center_node_id.to_string());

        if let Some(row) = self.query_one(center_query).await? {
            let neo_node: neo4rs::Node = row.get("n").map_err(|e| {
                GraphError::Serialization(format!("Failed to get center node: {e}"))
            })?;
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let label = labels.first().cloned().unwrap_or_default();
            nodes.push(neo4j_node_to_record(&neo_node, &label));
        }

        for row in &node_rows {
            let neo_node: neo4rs::Node = row.get("n").map_err(|e| {
                GraphError::Serialization(format!("Failed to deserialize neighborhood node: {e}"))
            })?;
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let label = labels.first().cloned().unwrap_or_default();
            nodes.push(neo4j_node_to_record(&neo_node, &label));
        }

        // Fetch edges between nodes in the neighborhood.
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        if node_ids.is_empty() {
            return Ok(SubgraphResult {
                nodes,
                edges: Vec::new(),
            });
        }

        let edge_query = query(
            "MATCH (a {tenant_id: $tenant_id})-[r]->(b {tenant_id: $tenant_id})
             WHERE a.id IN $ids AND b.id IN $ids
             RETURN r, type(r) AS rel_type, a.id AS src, b.id AS tgt",
        )
        .param("tenant_id", tenant_id.0.to_string())
        .param("ids", node_ids);

        let edge_rows = self.query_rows(edge_query).await?;
        let mut edges = Vec::with_capacity(edge_rows.len());

        for row in &edge_rows {
            let rel_type: String = row.get("rel_type").unwrap_or_default();
            let src: String = row.get("src").unwrap_or_default();
            let tgt: String = row.get("tgt").unwrap_or_default();
            let neo_rel: neo4rs::Relation = row.get("r").map_err(|e| {
                GraphError::Serialization(format!("Failed to get neighborhood edge: {e}"))
            })?;
            let edge_id: String = neo_rel.get("id").unwrap_or_default();

            let mut props = serde_json::Map::new();
            if let Ok(v) = neo_rel.get::<f64>("exploitability_score") {
                props.insert(
                    "exploitability_score".to_string(),
                    serde_json::Value::from(v),
                );
            }

            edges.push(EdgeRecord {
                id: edge_id,
                edge_type: rel_type,
                source_id: src,
                target_id: tgt,
                properties: serde_json::Value::Object(props),
            });
        }

        Ok(SubgraphResult { nodes, edges })
    }

    // ── Full-Text Search ─────────────────────────────────────────

    /// Full-text search across indexed node types.
    pub async fn search(
        &self,
        tenant_id: &TenantId,
        index_name: &str,
        search_term: &str,
        limit: u32,
    ) -> Result<Vec<NodeRecord>, GraphError> {
        let q = query(
            "CALL db.index.fulltext.queryNodes($index, $term) YIELD node, score
             WHERE node.tenant_id = $tenant_id
             RETURN node, labels(node) AS labels, score
             ORDER BY score DESC
             LIMIT $limit",
        )
        .param("tenant_id", tenant_id.0.to_string())
        .param("index", index_name.to_string())
        .param("term", search_term.to_string())
        .param("limit", limit as i64);

        let rows = self.query_rows(q).await?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let neo_node: neo4rs::Node = row.get("node").map_err(|e| {
                GraphError::Serialization(format!("Failed to deserialize search result: {e}"))
            })?;
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let label = labels.first().cloned().unwrap_or_default();
            results.push(neo4j_node_to_record(&neo_node, &label));
        }
        Ok(results)
    }
}

/// Convert a neo4rs::Node to our lightweight NodeRecord.
fn neo4j_node_to_record(node: &neo4rs::Node, label: &str) -> NodeRecord {
    let id: String = node.get("id").unwrap_or_default();
    let tenant_id: String = node.get("tenant_id").unwrap_or_default();

    let mut props = serde_json::Map::new();
    // Extract common properties that may exist on various node types
    for key in &[
        "ip",
        "hostname",
        "name",
        "username",
        "cve_id",
        "last_seen",
        "first_seen",
        "os",
        "criticality",
        "severity",
        "email",
        "cidr",
        "endpoint",
    ] {
        if let Ok(v) = node.get::<String>(key) {
            props.insert((*key).to_string(), serde_json::Value::String(v));
        }
    }

    NodeRecord {
        id,
        label: label.to_string(),
        tenant_id,
        properties: serde_json::Value::Object(props),
    }
}

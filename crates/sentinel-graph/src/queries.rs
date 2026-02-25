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

//! Write operations for the knowledge graph.
//!
//! All mutations use MERGE (upsert) semantics to handle idempotent
//! re-discovery. Nodes are identified by (tenant_id, id).

use chrono::{DateTime, Utc};
use neo4rs::query;

use sentinel_core::{
    Edge, EdgeProperties, EdgeType, Host, Node, NodeId, Service, TenantId, User, Vulnerability,
};

use crate::client::{GraphClient, GraphError};

impl GraphClient {
    // ── Node Upserts ─────────────────────────────────────────────

    /// Upsert any node type into the graph.
    pub async fn upsert_node(&self, node: &Node) -> Result<(), GraphError> {
        match node {
            Node::Host(h) => self.upsert_host(h).await,
            Node::Service(s) => self.upsert_service(s).await,
            Node::User(u) => self.upsert_user(u).await,
            Node::Vulnerability(v) => self.upsert_vulnerability(v).await,
            _ => self.upsert_generic_node(node).await,
        }
    }

    /// Upsert a Host node.
    pub async fn upsert_host(&self, host: &Host) -> Result<(), GraphError> {
        let q = query(
            "MERGE (n:Host {tenant_id: $tenant_id, id: $id})
             ON CREATE SET
               n.ip = $ip, n.hostname = $hostname, n.os = $os,
               n.os_version = $os_version, n.mac_address = $mac_address,
               n.cloud_provider = $cloud_provider,
               n.cloud_instance_id = $cloud_instance_id,
               n.cloud_region = $cloud_region, n.criticality = $criticality,
               n.tags = $tags, n.first_seen = $now, n.last_seen = $now
             ON MATCH SET
               n.ip = $ip, n.hostname = $hostname, n.os = $os,
               n.os_version = $os_version, n.mac_address = $mac_address,
               n.cloud_provider = $cloud_provider,
               n.cloud_instance_id = $cloud_instance_id,
               n.cloud_region = $cloud_region, n.criticality = $criticality,
               n.tags = $tags, n.last_seen = $now",
        )
        .param("tenant_id", host.tenant_id.0.to_string())
        .param("id", host.id.0.to_string())
        .param("ip", host.ip.clone())
        .param("hostname", opt_string(&host.hostname))
        .param("os", opt_string(&host.os))
        .param("os_version", opt_string(&host.os_version))
        .param("mac_address", opt_string(&host.mac_address))
        .param("cloud_provider", ser_opt(&host.cloud_provider))
        .param("cloud_instance_id", opt_string(&host.cloud_instance_id))
        .param("cloud_region", opt_string(&host.cloud_region))
        .param("criticality", ser(&host.criticality))
        .param("tags", host.tags.clone())
        .param("now", Utc::now().to_rfc3339());

        self.run(q).await
    }

    /// Upsert a Service node.
    pub async fn upsert_service(&self, svc: &Service) -> Result<(), GraphError> {
        let q = query(
            "MERGE (n:Service {tenant_id: $tenant_id, id: $id})
             ON CREATE SET
               n.name = $name, n.version = $version, n.port = $port,
               n.protocol = $protocol, n.state = $state, n.banner = $banner,
               n.first_seen = $now, n.last_seen = $now
             ON MATCH SET
               n.name = $name, n.version = $version, n.port = $port,
               n.protocol = $protocol, n.state = $state, n.banner = $banner,
               n.last_seen = $now",
        )
        .param("tenant_id", svc.tenant_id.0.to_string())
        .param("id", svc.id.0.to_string())
        .param("name", svc.name.clone())
        .param("version", opt_string(&svc.version))
        .param("port", svc.port as i64)
        .param("protocol", ser(&svc.protocol))
        .param("state", ser(&svc.state))
        .param("banner", opt_string(&svc.banner))
        .param("now", Utc::now().to_rfc3339());

        self.run(q).await
    }

    /// Upsert a User node.
    pub async fn upsert_user(&self, user: &User) -> Result<(), GraphError> {
        let q = query(
            "MERGE (n:User {tenant_id: $tenant_id, id: $id})
             ON CREATE SET
               n.username = $username, n.display_name = $display_name,
               n.email = $email, n.user_type = $user_type, n.source = $source,
               n.enabled = $enabled, n.mfa_enabled = $mfa_enabled,
               n.first_seen = $now, n.last_seen = $now
             ON MATCH SET
               n.username = $username, n.display_name = $display_name,
               n.email = $email, n.user_type = $user_type, n.source = $source,
               n.enabled = $enabled, n.mfa_enabled = $mfa_enabled,
               n.last_seen = $now",
        )
        .param("tenant_id", user.tenant_id.0.to_string())
        .param("id", user.id.0.to_string())
        .param("username", user.username.clone())
        .param("display_name", opt_string(&user.display_name))
        .param("email", opt_string(&user.email))
        .param("user_type", ser(&user.user_type))
        .param("source", ser(&user.source))
        .param("enabled", user.enabled)
        .param("mfa_enabled", user.mfa_enabled.unwrap_or(false))
        .param("now", Utc::now().to_rfc3339());

        self.run(q).await
    }

    /// Upsert a Vulnerability node.
    pub async fn upsert_vulnerability(&self, vuln: &Vulnerability) -> Result<(), GraphError> {
        let q = query(
            "MERGE (n:Vulnerability {tenant_id: $tenant_id, id: $id})
             ON CREATE SET
               n.cve_id = $cve_id, n.cvss_score = $cvss_score,
               n.cvss_vector = $cvss_vector, n.epss_score = $epss_score,
               n.severity = $severity, n.description = $description,
               n.exploitable = $exploitable, n.in_cisa_kev = $in_cisa_kev,
               n.first_seen = $now, n.last_seen = $now
             ON MATCH SET
               n.cve_id = $cve_id, n.cvss_score = $cvss_score,
               n.cvss_vector = $cvss_vector, n.epss_score = $epss_score,
               n.severity = $severity, n.description = $description,
               n.exploitable = $exploitable, n.in_cisa_kev = $in_cisa_kev,
               n.last_seen = $now",
        )
        .param("tenant_id", vuln.tenant_id.0.to_string())
        .param("id", vuln.id.0.to_string())
        .param("cve_id", vuln.cve_id.clone())
        .param("cvss_score", vuln.cvss_score.unwrap_or(0.0))
        .param("cvss_vector", opt_string(&vuln.cvss_vector))
        .param("epss_score", vuln.epss_score.unwrap_or(0.0))
        .param("severity", ser(&vuln.severity))
        .param("description", opt_string(&vuln.description))
        .param("exploitable", vuln.exploitable)
        .param("in_cisa_kev", vuln.in_cisa_kev)
        .param("now", Utc::now().to_rfc3339());

        self.run(q).await
    }

    /// Generic upsert for node types without specialized handling.
    async fn upsert_generic_node(&self, node: &Node) -> Result<(), GraphError> {
        let label = node_label(node);
        let tenant_id = node.tenant_id().0.to_string();
        let node_id = node.id().0.to_string();
        let props_json =
            serde_json::to_string(node).map_err(|e| GraphError::Serialization(e.to_string()))?;

        let cypher = format!(
            "MERGE (n:{label} {{tenant_id: $tenant_id, id: $id}})
             SET n += apoc.convert.fromJsonMap($props)
             SET n.last_seen = $now"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id)
            .param("id", node_id)
            .param("props", props_json)
            .param("now", Utc::now().to_rfc3339());

        self.run(q).await
    }

    // ── Edge Upserts ─────────────────────────────────────────────

    /// Upsert an edge between two nodes.
    pub async fn upsert_edge(&self, edge: &Edge) -> Result<(), GraphError> {
        let rel_type = edge_type_to_cypher(&edge.edge_type);
        let cypher = format!(
            "MATCH (a {{tenant_id: $tenant_id, id: $source_id}})
             MATCH (b {{tenant_id: $tenant_id, id: $target_id}})
             MERGE (a)-[r:{rel_type} {{id: $edge_id}}]->(b)
             ON CREATE SET
               r.tenant_id = $tenant_id,
               r.protocol = $protocol, r.port = $port,
               r.encrypted = $encrypted, r.permissions = $permissions,
               r.exploitability_score = $exploitability_score,
               r.first_seen = $now, r.last_seen = $now
             ON MATCH SET
               r.protocol = $protocol, r.port = $port,
               r.encrypted = $encrypted, r.permissions = $permissions,
               r.exploitability_score = $exploitability_score,
               r.last_seen = $now"
        );

        let q = query(&cypher)
            .param("tenant_id", edge.tenant_id.0.to_string())
            .param("source_id", edge.source_id.0.to_string())
            .param("target_id", edge.target_id.0.to_string())
            .param("edge_id", edge.id.0.to_string())
            .param("protocol", ser_opt(&edge.properties.protocol))
            .param("port", edge.properties.port.unwrap_or(0) as i64)
            .param("encrypted", edge.properties.encrypted.unwrap_or(false))
            .param("permissions", edge.properties.permissions.clone())
            .param(
                "exploitability_score",
                edge.properties.exploitability_score.unwrap_or(0.0),
            )
            .param("now", Utc::now().to_rfc3339());

        self.run(q).await
    }

    /// Upsert an edge between two nodes identified by their IDs.
    pub async fn upsert_edge_by_ids(
        &self,
        tenant_id: &TenantId,
        source_id: &NodeId,
        target_id: &NodeId,
        edge_type: &EdgeType,
        properties: &EdgeProperties,
    ) -> Result<(), GraphError> {
        let edge = Edge {
            id: sentinel_core::types::EdgeId::new(),
            tenant_id: tenant_id.clone(),
            source_id: source_id.clone(),
            target_id: target_id.clone(),
            edge_type: edge_type.clone(),
            properties: properties.clone(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        self.upsert_edge(&edge).await
    }

    // ── Staleness Management ─────────────────────────────────────

    /// Mark nodes of a given label as stale if last_seen < cutoff.
    /// Returns the count of stale nodes found.
    pub async fn mark_stale(
        &self,
        tenant_id: &TenantId,
        label: &str,
        cutoff: DateTime<Utc>,
    ) -> Result<i64, GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id}})
             WHERE n.last_seen < $cutoff
             SET n.stale = true
             RETURN count(n) AS cnt"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id.0.to_string())
            .param("cutoff", cutoff.to_rfc3339());

        match self.query_one(q).await? {
            Some(row) => Ok(row.get::<i64>("cnt").unwrap_or(0)),
            None => Ok(0),
        }
    }

    /// Delete stale nodes for a tenant and label.
    /// Returns the count of deleted nodes.
    pub async fn remove_stale(
        &self,
        tenant_id: &TenantId,
        label: &str,
        cutoff: DateTime<Utc>,
    ) -> Result<i64, GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id}})
             WHERE n.last_seen < $cutoff
             DETACH DELETE n
             RETURN count(n) AS cnt"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id.0.to_string())
            .param("cutoff", cutoff.to_rfc3339());

        match self.query_one(q).await? {
            Some(row) => Ok(row.get::<i64>("cnt").unwrap_or(0)),
            None => Ok(0),
        }
    }

    // ── Batch Operations ─────────────────────────────────────────

    /// Upsert multiple nodes in a single transaction.
    pub async fn upsert_nodes(&self, nodes: &[Node]) -> Result<(), GraphError> {
        let mut txn = self.start_txn().await?;

        for node in nodes {
            let label = node_label(node);
            let tenant_id = node.tenant_id().0.to_string();
            let node_id = node.id().0.to_string();
            let props_json = serde_json::to_string(node)
                .map_err(|e| GraphError::Serialization(e.to_string()))?;

            let cypher = format!(
                "MERGE (n:{label} {{tenant_id: $tenant_id, id: $id}})
                 SET n += apoc.convert.fromJsonMap($props)
                 SET n.last_seen = $now"
            );

            let q = query(&cypher)
                .param("tenant_id", tenant_id)
                .param("id", node_id)
                .param("props", props_json)
                .param("now", Utc::now().to_rfc3339());

            txn.run(q).await?;
        }

        txn.commit().await?;
        Ok(())
    }

    /// Delete a node by tenant, label, and id.
    pub async fn delete_node(
        &self,
        tenant_id: &TenantId,
        label: &str,
        node_id: &NodeId,
    ) -> Result<(), GraphError> {
        let cypher = format!(
            "MATCH (n:{label} {{tenant_id: $tenant_id, id: $id}})
             DETACH DELETE n"
        );

        let q = query(&cypher)
            .param("tenant_id", tenant_id.0.to_string())
            .param("id", node_id.0.to_string());

        self.run(q).await
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Get the Neo4j label for a node variant.
fn node_label(node: &Node) -> &'static str {
    match node {
        Node::Host(_) => "Host",
        Node::Service(_) => "Service",
        Node::Port(_) => "Port",
        Node::User(_) => "User",
        Node::Group(_) => "Group",
        Node::Role(_) => "Role",
        Node::Policy(_) => "Policy",
        Node::Subnet(_) => "Subnet",
        Node::Vpc(_) => "Vpc",
        Node::Vulnerability(_) => "Vulnerability",
        Node::Certificate(_) => "Certificate",
        Node::Application(_) => "Application",
        Node::McpServer(_) => "McpServer",
    }
}

/// Convert EdgeType to its Cypher relationship type string.
fn edge_type_to_cypher(et: &EdgeType) -> &'static str {
    match et {
        EdgeType::ConnectsTo => "CONNECTS_TO",
        EdgeType::HasAccess => "HAS_ACCESS",
        EdgeType::MemberOf => "MEMBER_OF",
        EdgeType::RunsOn => "RUNS_ON",
        EdgeType::Trusts => "TRUSTS",
        EdgeType::RoutesTo => "ROUTES_TO",
        EdgeType::Exposes => "EXPOSES",
        EdgeType::DependsOn => "DEPENDS_ON",
        EdgeType::CanReach => "CAN_REACH",
        EdgeType::HasCve => "HAS_CVE",
        EdgeType::HasPort => "HAS_PORT",
        EdgeType::HasCertificate => "HAS_CERTIFICATE",
        EdgeType::BelongsToSubnet => "BELONGS_TO_SUBNET",
        EdgeType::BelongsToVpc => "BELONGS_TO_VPC",
    }
}

fn opt_string(opt: &Option<String>) -> String {
    opt.clone().unwrap_or_default()
}

fn ser<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_default()
}

fn ser_opt<T: serde::Serialize>(opt: &Option<T>) -> String {
    opt.as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .unwrap_or_default()
}

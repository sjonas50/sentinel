//! Integration tests for sentinel-graph against a live Neo4j instance.
//!
//! These tests require `docker compose up` to be running.
//! Run with: cargo test --package sentinel-graph --test integration
//!
//! Skipped automatically if Neo4j is not available.

use sentinel_core::{
    types::{
        CloudProvider, Criticality, EdgeId, EdgeProperties, IdentitySource, Protocol, ServiceState,
        UserType, VulnSeverity,
    },
    Edge, EdgeType, Host, NodeId, Service, TenantId, User, Vulnerability,
};
use sentinel_graph::{GraphClient, GraphConfig};

use chrono::Utc;

async fn connect_or_skip() -> Option<GraphClient> {
    let config = GraphConfig::default();
    match GraphClient::connect(&config).await {
        Ok(client) => Some(client),
        Err(e) => {
            eprintln!("Skipping integration test (Neo4j not available): {e}");
            None
        }
    }
}

fn unique_tenant() -> TenantId {
    TenantId::new()
}

async fn cleanup(client: &GraphClient, tenant_id: &TenantId) {
    let q = neo4rs::query("MATCH (n {tenant_id: $tid}) DETACH DELETE n")
        .param("tid", tenant_id.0.to_string());
    let _ = client.run(q).await;
}

fn make_host(tenant_id: &TenantId, ip: &str, hostname: &str) -> Host {
    Host {
        id: NodeId::new(),
        tenant_id: tenant_id.clone(),
        ip: ip.to_string(),
        hostname: Some(hostname.to_string()),
        os: Some("Ubuntu".to_string()),
        os_version: Some("22.04".to_string()),
        mac_address: None,
        cloud_provider: Some(CloudProvider::Aws),
        cloud_instance_id: None,
        cloud_region: Some("us-east-1".to_string()),
        criticality: Criticality::High,
        tags: vec!["test".to_string()],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    }
}

#[tokio::test]
#[ignore = "requires live Neo4j — run with: cargo test --package sentinel-graph --test integration -- --ignored"]
async fn test_upsert_and_get_host() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let host = make_host(&tid, "10.0.1.1", "web-01");
    let host_id = host.id.clone();

    // Create
    client.upsert_host(&host).await.unwrap();

    // Read back
    let record = client.get_node(&tid, "Host", &host_id).await.unwrap();
    assert_eq!(record.id, host_id.0.to_string());
    assert_eq!(record.label, "Host");

    let ip = record
        .properties
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(ip, "10.0.1.1");

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_upsert_host_is_idempotent() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let host = make_host(&tid, "10.0.2.1", "db-01");

    // Upsert twice
    client.upsert_host(&host).await.unwrap();
    client.upsert_host(&host).await.unwrap();

    // Should still be exactly 1 node
    let count = client.count_nodes(&tid, "Host").await.unwrap();
    assert_eq!(count, 1);

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_upsert_service_and_list() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let svc = Service {
        id: NodeId::new(),
        tenant_id: tid.clone(),
        name: "nginx".to_string(),
        version: Some("1.25".to_string()),
        port: 443,
        protocol: Protocol::Https,
        state: ServiceState::Running,
        banner: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };

    client.upsert_service(&svc).await.unwrap();

    let nodes = client.list_nodes(&tid, "Service", 10, 0).await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(
        nodes[0].properties.get("name").and_then(|v| v.as_str()),
        Some("nginx")
    );

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_upsert_user() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let user = User {
        id: NodeId::new(),
        tenant_id: tid.clone(),
        username: "jdoe".to_string(),
        display_name: Some("John Doe".to_string()),
        email: Some("jdoe@example.com".to_string()),
        user_type: UserType::Human,
        source: IdentitySource::EntraId,
        enabled: true,
        mfa_enabled: Some(true),
        last_login: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };

    client.upsert_user(&user).await.unwrap();
    let count = client.count_nodes(&tid, "User").await.unwrap();
    assert_eq!(count, 1);

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_upsert_vulnerability() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let vuln = Vulnerability {
        id: NodeId::new(),
        tenant_id: tid.clone(),
        cve_id: "CVE-2024-9999".to_string(),
        cvss_score: Some(9.1),
        cvss_vector: None,
        epss_score: Some(0.85),
        severity: VulnSeverity::Critical,
        description: Some("Test vulnerability".to_string()),
        exploitable: true,
        in_cisa_kev: true,
        published_date: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };

    client.upsert_vulnerability(&vuln).await.unwrap();
    let count = client.count_nodes(&tid, "Vulnerability").await.unwrap();
    assert_eq!(count, 1);

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_upsert_edge_and_neighbors() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let host = make_host(&tid, "10.0.3.1", "app-01");
    let host_id = host.id.clone();
    client.upsert_host(&host).await.unwrap();

    let svc = Service {
        id: NodeId::new(),
        tenant_id: tid.clone(),
        name: "api".to_string(),
        version: None,
        port: 8080,
        protocol: Protocol::Http,
        state: ServiceState::Running,
        banner: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let svc_id = svc.id.clone();
    client.upsert_service(&svc).await.unwrap();

    // Create edge: Host -[RUNS_ON]-> Service
    let edge = Edge {
        id: EdgeId::new(),
        tenant_id: tid.clone(),
        source_id: svc_id.clone(),
        target_id: host_id.clone(),
        edge_type: EdgeType::RunsOn,
        properties: EdgeProperties::default(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    client.upsert_edge(&edge).await.unwrap();

    // Query neighbors of the host
    let neighbors = client.get_neighbors(&tid, &host_id, 10).await.unwrap();
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].edge.edge_type, "RUNS_ON");

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_find_node_by_property() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let host = make_host(&tid, "192.168.1.100", "lookup-test");
    client.upsert_host(&host).await.unwrap();

    // Find by IP
    let found = client
        .find_node_by_property(&tid, "Host", "ip", "192.168.1.100")
        .await
        .unwrap();
    assert!(found.is_some());
    assert_eq!(
        found.unwrap().properties.get("ip").and_then(|v| v.as_str()),
        Some("192.168.1.100")
    );

    // Not found
    let not_found = client
        .find_node_by_property(&tid, "Host", "ip", "1.2.3.4")
        .await
        .unwrap();
    assert!(not_found.is_none());

    cleanup(&client, &tid).await;
}

#[tokio::test]
#[ignore = "requires live Neo4j"]
async fn test_delete_node() {
    let Some(client) = connect_or_skip().await else {
        return;
    };
    let tid = unique_tenant();
    cleanup(&client, &tid).await;

    let host = make_host(&tid, "10.0.9.1", "delete-me");
    let host_id = host.id.clone();
    client.upsert_host(&host).await.unwrap();

    assert_eq!(client.count_nodes(&tid, "Host").await.unwrap(), 1);

    client.delete_node(&tid, "Host", &host_id).await.unwrap();
    assert_eq!(client.count_nodes(&tid, "Host").await.unwrap(), 0);

    cleanup(&client, &tid).await;
}

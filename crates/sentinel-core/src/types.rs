//! Core domain types for the Sentinel knowledge graph.
//!
//! These types represent nodes and edges in the network digital twin,
//! shared across all Sentinel services (Rust, Python, TypeScript).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Tenant ────────────────────────────────────────────────────────

/// Every entity in the system belongs to a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TenantId(pub Uuid);

impl TenantId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

// ── Node Types ────────────────────────────────────────────────────

/// Unique identifier for any node in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeId(pub Uuid);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// A network host (physical server, VM, container host, cloud instance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub mac_address: Option<String>,
    pub cloud_provider: Option<CloudProvider>,
    pub cloud_instance_id: Option<String>,
    pub cloud_region: Option<String>,
    pub criticality: Criticality,
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A running service on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub name: String,
    pub version: Option<String>,
    pub port: u16,
    pub protocol: Protocol,
    pub state: ServiceState,
    pub banner: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// An open port on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A user account (human or service account).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub user_type: UserType,
    pub source: IdentitySource,
    pub enabled: bool,
    pub mfa_enabled: Option<bool>,
    pub last_login: Option<DateTime<Utc>>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A group of users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub name: String,
    pub description: Option<String>,
    pub source: IdentitySource,
    pub member_count: Option<u32>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// An IAM role or permission set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub name: String,
    pub description: Option<String>,
    pub source: IdentitySource,
    pub permissions: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A security policy (IAM policy, firewall rule set, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub name: String,
    pub policy_type: PolicyType,
    pub source: String,
    pub rules_json: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A network subnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subnet {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub cidr: String,
    pub name: Option<String>,
    pub cloud_provider: Option<CloudProvider>,
    pub vpc_id: Option<String>,
    pub is_public: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A virtual private cloud / virtual network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vpc {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub vpc_id: String,
    pub name: Option<String>,
    pub cidr: Option<String>,
    pub cloud_provider: CloudProvider,
    pub region: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A known vulnerability (CVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub severity: VulnSeverity,
    pub description: Option<String>,
    pub exploitable: bool,
    pub in_cisa_kev: bool,
    pub published_date: Option<DateTime<Utc>>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A TLS/SSL certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// An application or container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub name: String,
    pub version: Option<String>,
    pub app_type: AppType,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// An MCP (Model Context Protocol) server discovered in the environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub id: NodeId,
    pub tenant_id: TenantId,
    pub name: String,
    pub endpoint: String,
    pub tools: Vec<String>,
    pub authenticated: bool,
    pub tls_enabled: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Enum wrapper for all node types in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "node_type")]
pub enum Node {
    Host(Host),
    Service(Service),
    Port(Port),
    User(User),
    Group(Group),
    Role(Role),
    Policy(Policy),
    Subnet(Subnet),
    Vpc(Vpc),
    Vulnerability(Vulnerability),
    Certificate(Certificate),
    Application(Application),
    McpServer(McpServer),
}

impl Node {
    pub fn id(&self) -> &NodeId {
        match self {
            Node::Host(n) => &n.id,
            Node::Service(n) => &n.id,
            Node::Port(n) => &n.id,
            Node::User(n) => &n.id,
            Node::Group(n) => &n.id,
            Node::Role(n) => &n.id,
            Node::Policy(n) => &n.id,
            Node::Subnet(n) => &n.id,
            Node::Vpc(n) => &n.id,
            Node::Vulnerability(n) => &n.id,
            Node::Certificate(n) => &n.id,
            Node::Application(n) => &n.id,
            Node::McpServer(n) => &n.id,
        }
    }

    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Node::Host(n) => &n.tenant_id,
            Node::Service(n) => &n.tenant_id,
            Node::Port(n) => &n.tenant_id,
            Node::User(n) => &n.tenant_id,
            Node::Group(n) => &n.tenant_id,
            Node::Role(n) => &n.tenant_id,
            Node::Policy(n) => &n.tenant_id,
            Node::Subnet(n) => &n.tenant_id,
            Node::Vpc(n) => &n.tenant_id,
            Node::Vulnerability(n) => &n.tenant_id,
            Node::Certificate(n) => &n.tenant_id,
            Node::Application(n) => &n.tenant_id,
            Node::McpServer(n) => &n.tenant_id,
        }
    }
}

// ── Edge Types ────────────────────────────────────────────────────

/// Unique identifier for an edge in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EdgeId(pub Uuid);

impl EdgeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EdgeId {
    fn default() -> Self {
        Self::new()
    }
}

/// A relationship between two nodes in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub tenant_id: TenantId,
    pub source_id: NodeId,
    pub target_id: NodeId,
    pub edge_type: EdgeType,
    pub properties: EdgeProperties,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// The type of relationship between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeType {
    ConnectsTo,
    HasAccess,
    MemberOf,
    RunsOn,
    Trusts,
    RoutesTo,
    Exposes,
    DependsOn,
    CanReach,
    HasCve,
    HasPort,
    HasCertificate,
    BelongsToSubnet,
    BelongsToVpc,
}

/// Properties attached to an edge.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EdgeProperties {
    pub protocol: Option<Protocol>,
    pub port: Option<u16>,
    pub encrypted: Option<bool>,
    pub permissions: Vec<String>,
    pub exploitability_score: Option<f64>,
    pub extra: serde_json::Value,
}

// ── Enums ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    OnPrem,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
    Ssh,
    Rdp,
    Dns,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserType {
    Human,
    ServiceAccount,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    EntraId,
    Okta,
    AwsIam,
    AzureRbac,
    GcpIam,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    IamPolicy,
    FirewallRule,
    SecurityGroup,
    ConditionalAccess,
    NetworkAcl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppType {
    WebApp,
    ContainerImage,
    Lambda,
    Daemon,
    Database,
}

// ── Attack Path Types ─────────────────────────────────────────────

/// A computed attack path through the network graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub steps: Vec<AttackStep>,
    pub risk_score: f64,
    pub source_node: NodeId,
    pub target_node: NodeId,
    pub computed_at: DateTime<Utc>,
}

/// A single step in an attack path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub node_id: NodeId,
    pub edge_id: EdgeId,
    pub technique: Option<String>,
    pub description: String,
    pub exploitability: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_serialization_roundtrip() {
        let host = Host {
            id: NodeId::new(),
            tenant_id: TenantId::new(),
            ip: "10.0.1.42".to_string(),
            hostname: Some("web-server-01".to_string()),
            os: Some("Ubuntu".to_string()),
            os_version: Some("22.04".to_string()),
            mac_address: None,
            cloud_provider: Some(CloudProvider::Aws),
            cloud_instance_id: Some("i-abc123".to_string()),
            cloud_region: Some("us-east-1".to_string()),
            criticality: Criticality::High,
            tags: vec!["production".to_string(), "web".to_string()],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };

        let node = Node::Host(host);
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(node.id().0, deserialized.id().0);
    }

    #[test]
    fn edge_type_serializes_screaming_snake() {
        let json = serde_json::to_string(&EdgeType::ConnectsTo).unwrap();
        assert_eq!(json, "\"CONNECTS_TO\"");

        let json = serde_json::to_string(&EdgeType::HasAccess).unwrap();
        assert_eq!(json, "\"HAS_ACCESS\"");
    }

    #[test]
    fn vulnerability_fields() {
        let vuln = Vulnerability {
            id: NodeId::new(),
            tenant_id: TenantId::new(),
            cve_id: "CVE-2024-1234".to_string(),
            cvss_score: Some(8.1),
            cvss_vector: None,
            epss_score: Some(0.42),
            severity: VulnSeverity::High,
            description: Some("Test vulnerability".to_string()),
            exploitable: true,
            in_cisa_kev: true,
            published_date: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };

        let json = serde_json::to_string(&vuln).unwrap();
        assert!(json.contains("CVE-2024-1234"));
        assert!(json.contains("8.1"));
    }
}

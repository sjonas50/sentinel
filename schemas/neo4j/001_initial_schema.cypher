// ============================================================================
// Sentinel — Neo4j Knowledge Graph Schema
// Migration 001: Initial schema
//
// Defines constraints, indexes, and node/edge type structure for the
// network digital twin. All nodes carry a tenant_id for multi-tenant isolation.
// ============================================================================

// ── Uniqueness Constraints ─────────────────────────────────────────
// Every node type has a unique (tenant_id, id) pair.

CREATE CONSTRAINT host_id IF NOT EXISTS
FOR (n:Host) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT service_id IF NOT EXISTS
FOR (n:Service) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT port_id IF NOT EXISTS
FOR (n:Port) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT user_id IF NOT EXISTS
FOR (n:User) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT group_id IF NOT EXISTS
FOR (n:Group) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT role_id IF NOT EXISTS
FOR (n:Role) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT policy_id IF NOT EXISTS
FOR (n:Policy) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT subnet_id IF NOT EXISTS
FOR (n:Subnet) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT vpc_id IF NOT EXISTS
FOR (n:Vpc) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT vulnerability_id IF NOT EXISTS
FOR (n:Vulnerability) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT certificate_id IF NOT EXISTS
FOR (n:Certificate) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT application_id IF NOT EXISTS
FOR (n:Application) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT mcp_server_id IF NOT EXISTS
FOR (n:McpServer) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

// ── Lookup Indexes ─────────────────────────────────────────────────
// Indexes for common query patterns. Every query scopes by tenant_id first.

// Host lookups: by IP, hostname, cloud instance
CREATE INDEX host_ip IF NOT EXISTS FOR (n:Host) ON (n.tenant_id, n.ip);
CREATE INDEX host_hostname IF NOT EXISTS FOR (n:Host) ON (n.tenant_id, n.hostname);
CREATE INDEX host_cloud_instance IF NOT EXISTS FOR (n:Host) ON (n.tenant_id, n.cloud_instance_id);

// Service lookups: by name, port
CREATE INDEX service_name IF NOT EXISTS FOR (n:Service) ON (n.tenant_id, n.name);
CREATE INDEX service_port IF NOT EXISTS FOR (n:Service) ON (n.tenant_id, n.port);

// User lookups: by username, email
CREATE INDEX user_username IF NOT EXISTS FOR (n:User) ON (n.tenant_id, n.username);
CREATE INDEX user_email IF NOT EXISTS FOR (n:User) ON (n.tenant_id, n.email);

// Vulnerability lookups: by CVE ID, severity
CREATE INDEX vuln_cve IF NOT EXISTS FOR (n:Vulnerability) ON (n.tenant_id, n.cve_id);
CREATE INDEX vuln_severity IF NOT EXISTS FOR (n:Vulnerability) ON (n.tenant_id, n.severity);

// Subnet lookups: by CIDR
CREATE INDEX subnet_cidr IF NOT EXISTS FOR (n:Subnet) ON (n.tenant_id, n.cidr);

// VPC lookups: by vpc_id
CREATE INDEX vpc_cloud_id IF NOT EXISTS FOR (n:Vpc) ON (n.tenant_id, n.vpc_id);

// Certificate lookups: by subject, expiry
CREATE INDEX cert_subject IF NOT EXISTS FOR (n:Certificate) ON (n.tenant_id, n.subject);
CREATE INDEX cert_expiry IF NOT EXISTS FOR (n:Certificate) ON (n.tenant_id, n.not_after);

// MCP Server lookups: by name, endpoint
CREATE INDEX mcp_name IF NOT EXISTS FOR (n:McpServer) ON (n.tenant_id, n.name);

// ── Staleness Index ────────────────────────────────────────────────
// Used by the scanner to find nodes that haven't been seen recently.

CREATE INDEX host_last_seen IF NOT EXISTS FOR (n:Host) ON (n.tenant_id, n.last_seen);
CREATE INDEX service_last_seen IF NOT EXISTS FOR (n:Service) ON (n.tenant_id, n.last_seen);

// ── Attack Path Support ────────────────────────────────────────────
// Indexes on edge properties used during path computation.

CREATE INDEX host_criticality IF NOT EXISTS FOR (n:Host) ON (n.tenant_id, n.criticality);
CREATE INDEX vuln_exploitable IF NOT EXISTS FOR (n:Vulnerability) ON (n.tenant_id, n.exploitable);
CREATE INDEX vuln_cvss IF NOT EXISTS FOR (n:Vulnerability) ON (n.tenant_id, n.cvss_score);

// ── Full-Text Search ───────────────────────────────────────────────
// For natural language asset search in the dashboard.

CREATE FULLTEXT INDEX host_search IF NOT EXISTS
FOR (n:Host) ON EACH [n.ip, n.hostname, n.os, n.cloud_instance_id];

CREATE FULLTEXT INDEX user_search IF NOT EXISTS
FOR (n:User) ON EACH [n.username, n.display_name, n.email];

CREATE FULLTEXT INDEX vuln_search IF NOT EXISTS
FOR (n:Vulnerability) ON EACH [n.cve_id, n.description];

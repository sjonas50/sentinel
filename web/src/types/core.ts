/**
 * Core domain types for the Sentinel platform.
 *
 * These mirror the Rust types in sentinel-core/src/types.rs
 * and the Pydantic models in sentinel_api/models/core.py.
 * Keep all three in sync when modifying.
 */

// ── Enums ──────────────────────────────────────────────────────────

export type CloudProvider = "aws" | "azure" | "gcp" | "onprem";
export type Protocol = "tcp" | "udp" | "http" | "https" | "ssh" | "rdp" | "dns";
export type ServiceState = "running" | "stopped" | "unknown";
export type PortState = "open" | "closed" | "filtered";
export type UserType = "human" | "service_account" | "system";
export type IdentitySource = "entra_id" | "okta" | "aws_iam" | "azure_rbac" | "gcp_iam" | "local";
export type Criticality = "critical" | "high" | "medium" | "low" | "info";
export type VulnSeverity = "critical" | "high" | "medium" | "low" | "none";
export type PolicyType =
  | "iam_policy"
  | "firewall_rule"
  | "security_group"
  | "conditional_access"
  | "network_acl";
export type AppType = "web_app" | "container_image" | "lambda" | "daemon" | "database";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "remediated" | "false_positive";

export type EdgeType =
  | "CONNECTS_TO"
  | "HAS_ACCESS"
  | "MEMBER_OF"
  | "RUNS_ON"
  | "TRUSTS"
  | "ROUTES_TO"
  | "EXPOSES"
  | "DEPENDS_ON"
  | "CAN_REACH"
  | "HAS_CVE"
  | "HAS_PORT"
  | "HAS_CERTIFICATE"
  | "BELONGS_TO_SUBNET"
  | "BELONGS_TO_VPC"
  | "HAS_FINDING";

// ── Node Types ─────────────────────────────────────────────────────

export interface Host {
  id: string;
  tenant_id: string;
  ip: string;
  hostname?: string;
  os?: string;
  os_version?: string;
  mac_address?: string;
  cloud_provider?: CloudProvider;
  cloud_instance_id?: string;
  cloud_region?: string;
  criticality: Criticality;
  tags: string[];
  first_seen: string;
  last_seen: string;
}

export interface Service {
  id: string;
  tenant_id: string;
  name: string;
  version?: string;
  port: number;
  protocol: Protocol;
  state: ServiceState;
  banner?: string;
  first_seen: string;
  last_seen: string;
}

export interface Port {
  id: string;
  tenant_id: string;
  number: number;
  protocol: Protocol;
  state: PortState;
  first_seen: string;
  last_seen: string;
}

export interface User {
  id: string;
  tenant_id: string;
  username: string;
  display_name?: string;
  email?: string;
  user_type: UserType;
  source: IdentitySource;
  enabled: boolean;
  mfa_enabled?: boolean;
  last_login?: string;
  first_seen: string;
  last_seen: string;
}

export interface Group {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  source: IdentitySource;
  member_count?: number;
  first_seen: string;
  last_seen: string;
}

export interface Role {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  source: IdentitySource;
  permissions: string[];
  first_seen: string;
  last_seen: string;
}

export interface Policy {
  id: string;
  tenant_id: string;
  name: string;
  policy_type: PolicyType;
  source: string;
  rules_json?: string;
  first_seen: string;
  last_seen: string;
}

export interface Subnet {
  id: string;
  tenant_id: string;
  cidr: string;
  name?: string;
  cloud_provider?: CloudProvider;
  vpc_id?: string;
  is_public: boolean;
  first_seen: string;
  last_seen: string;
}

export interface Vpc {
  id: string;
  tenant_id: string;
  vpc_id: string;
  name?: string;
  cidr?: string;
  cloud_provider: CloudProvider;
  region: string;
  first_seen: string;
  last_seen: string;
}

export interface Vulnerability {
  id: string;
  tenant_id: string;
  cve_id: string;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  severity: VulnSeverity;
  description?: string;
  exploitable: boolean;
  in_cisa_kev: boolean;
  published_date?: string;
  first_seen: string;
  last_seen: string;
}

export interface Certificate {
  id: string;
  tenant_id: string;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  fingerprint_sha256: string;
  first_seen: string;
  last_seen: string;
}

export interface Application {
  id: string;
  tenant_id: string;
  name: string;
  version?: string;
  app_type: AppType;
  first_seen: string;
  last_seen: string;
}

export interface McpServer {
  id: string;
  tenant_id: string;
  name: string;
  endpoint: string;
  tools: string[];
  authenticated: boolean;
  tls_enabled: boolean;
  first_seen: string;
  last_seen: string;
}

export interface Finding {
  id: string;
  tenant_id: string;
  rule_id: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  resource_id: string;
  resource_type: string;
  remediation?: string;
  details_json?: string;
  status: FindingStatus;
  found_at: string;
  first_seen: string;
  last_seen: string;
}

export type Node =
  | Host
  | Service
  | Port
  | User
  | Group
  | Role
  | Policy
  | Subnet
  | Vpc
  | Vulnerability
  | Certificate
  | Application
  | McpServer
  | Finding;

// ── Edge Types ─────────────────────────────────────────────────────

export interface EdgeProperties {
  protocol?: Protocol;
  port?: number;
  encrypted?: boolean;
  permissions: string[];
  exploitability_score?: number;
  extra: Record<string, unknown>;
}

export interface Edge {
  id: string;
  tenant_id: string;
  source_id: string;
  target_id: string;
  edge_type: EdgeType;
  properties: EdgeProperties;
  first_seen: string;
  last_seen: string;
}

// ── Attack Path Types ──────────────────────────────────────────────

export interface AttackStep {
  node_id: string;
  edge_id: string;
  technique?: string;
  description: string;
  exploitability: number;
}

export interface AttackPath {
  id: string;
  tenant_id: string;
  steps: AttackStep[];
  risk_score: number;
  source_node: string;
  target_node: string;
  computed_at: string;
}

// ── Remediation ─────────────────────────────────────────────────────

export interface RemediationStep {
  title: string;
  description: string;
  priority: string;
  effort: string;
  automated: boolean;
}

// ── Hunt Finding Types ──────────────────────────────────────────────

export interface HuntFindingRecord {
  id: string;
  playbook: string;
  severity: string;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  recommendations: string[];
  affected_hosts: string[];
  affected_users: string[];
  mitre_technique_ids: string[];
  mitre_tactic: string;
  timestamp: string;
}

// ── Simulation Types ────────────────────────────────────────────────

export interface SimulationRecord {
  id: string;
  tactic: string;
  techniques_tested: number;
  techniques_with_findings: number;
  findings_count: number;
  highest_risk_score: number;
  duration_seconds: number;
  summary: string;
  created_at: string;
}

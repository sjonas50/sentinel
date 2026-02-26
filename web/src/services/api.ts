/**
 * API client for the Sentinel backend.
 *
 * All requests include the JWT Bearer token when available.
 * The Vite dev server proxies /api → http://localhost:8000.
 */

import { getToken } from "./auth";

const API_BASE = "/api";

// ── Generic helpers ─────────────────────────────────────────────

function authHeaders(): Record<string, string> {
  const token = getToken();
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...init?.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, (body as { detail?: string }).detail ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ── Health ──────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  service: string;
}

export interface HealthDetailedResponse {
  status: string;
  service: string;
  dependencies: Record<string, string>;
}

export function fetchHealth(): Promise<HealthResponse> {
  return request("/health");
}

export function fetchHealthDetailed(): Promise<HealthDetailedResponse> {
  return request("/health/detailed");
}

// ── Graph ───────────────────────────────────────────────────────

export interface NodeListResponse {
  nodes: Record<string, unknown>[];
  total: number;
  limit: number;
  offset: number;
}

export interface NodeResponse {
  node: Record<string, unknown>;
}

export interface NeighborEntry {
  node: Record<string, unknown>;
  relationship: string;
  labels: string[];
}

export interface NeighborsResponse {
  neighbors: NeighborEntry[];
  count: number;
}

export interface SearchResult {
  node: Record<string, unknown>;
  labels: string[];
  score: number;
}

export interface SearchResponse {
  results: SearchResult[];
  count: number;
}

export interface GraphStatsResponse {
  tenant_id: string;
  node_counts: Record<string, number>;
}

export function listNodes(label: string, limit = 50, offset = 0): Promise<NodeListResponse> {
  return request(`/graph/nodes/${label}?limit=${limit}&offset=${offset}`);
}

export function getNode(label: string, nodeId: string): Promise<NodeResponse> {
  return request(`/graph/nodes/${label}/${nodeId}`);
}

export function getNeighbors(label: string, nodeId: string, limit = 50): Promise<NeighborsResponse> {
  return request(`/graph/nodes/${label}/${nodeId}/neighbors?limit=${limit}`);
}

export function searchNodes(q: string, index = "host_search", limit = 20): Promise<SearchResponse> {
  return request(`/graph/search?q=${encodeURIComponent(q)}&index=${index}&limit=${limit}`);
}

export function fetchGraphStats(): Promise<GraphStatsResponse> {
  return request("/graph/stats");
}

// ── Topology ─────────────────────────────────────────────────────

export interface TopologyNode {
  id: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface TopologyEdge {
  id: string;
  source_id: string;
  target_id: string;
  edge_type: string;
}

export interface TopologyResponse {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  total_nodes: number;
  total_edges: number;
  truncated: boolean;
}

export function fetchTopology(
  labels = "Host,Service,Subnet,Vpc",
  nodeLimit = 200,
  edgeLimit = 500,
): Promise<TopologyResponse> {
  return request(
    `/graph/topology?labels=${encodeURIComponent(labels)}&node_limit=${nodeLimit}&edge_limit=${edgeLimit}`,
  );
}

// ── Audit ────────────────────────────────────────────────────────

export interface FindingsResponse {
  findings: Record<string, unknown>[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditSummaryRow {
  severity: string;
  status: string;
  count: number;
}

export interface AuditSummaryResponse {
  tenant_id: string;
  breakdown: AuditSummaryRow[];
}

export function fetchFindings(
  params: { severity?: string; status?: string; limit?: number; offset?: number } = {},
): Promise<FindingsResponse> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.status) qs.set("status", params.status);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return request(`/audit/findings${q ? `?${q}` : ""}`);
}

export function fetchAuditSummary(): Promise<AuditSummaryResponse> {
  return request("/audit/summary");
}

// ── Vulnerabilities ──────────────────────────────────────────────

export interface VulnListParams {
  severity?: string;
  exploitable?: boolean;
  in_cisa_kev?: boolean;
  min_cvss?: number;
  min_epss?: number;
  limit?: number;
  offset?: number;
}

export interface VulnRecord {
  id: string;
  cve_id: string;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  severity: string;
  description?: string;
  exploitable: boolean;
  in_cisa_kev: boolean;
  published_date?: string;
  first_seen: string;
  last_seen: string;
  affected_count?: number;
}

export interface VulnListResponse {
  vulnerabilities: VulnRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface VulnSeverityRow {
  severity: string;
  count: number;
}

export interface VulnSummaryResponse {
  tenant_id: string;
  by_severity: VulnSeverityRow[];
  total: number;
  exploitable_count: number;
  kev_count: number;
}

export interface VulnDetailResponse {
  vulnerability: VulnRecord;
}

export interface VulnAssetsResponse {
  assets: Record<string, unknown>[];
  count: number;
}

export function listVulnerabilities(params: VulnListParams = {}): Promise<VulnListResponse> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.exploitable !== undefined) qs.set("exploitable", String(params.exploitable));
  if (params.in_cisa_kev !== undefined) qs.set("in_cisa_kev", String(params.in_cisa_kev));
  if (params.min_cvss !== undefined) qs.set("min_cvss", String(params.min_cvss));
  if (params.min_epss !== undefined) qs.set("min_epss", String(params.min_epss));
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return request(`/vulnerabilities${q ? `?${q}` : ""}`);
}

export function getVulnerability(cveId: string): Promise<VulnDetailResponse> {
  return request(`/vulnerabilities/${encodeURIComponent(cveId)}`);
}

export function fetchVulnSummary(): Promise<VulnSummaryResponse> {
  return request("/vulnerabilities/summary");
}

export function getVulnAssets(cveId: string, limit = 50): Promise<VulnAssetsResponse> {
  return request(`/vulnerabilities/${encodeURIComponent(cveId)}/assets?limit=${limit}`);
}

// ── Attack Paths ────────────────────────────────────────────────

import type { AttackPath, HuntFindingRecord, RemediationStep, SimulationRecord } from "../types/core";

export interface AttackPathListParams {
  min_risk?: number;
  limit?: number;
  offset?: number;
}

export interface AttackPathListResponse {
  paths: AttackPath[];
  total: number;
  limit: number;
  offset: number;
}

export interface AttackPathSummaryResponse {
  tenant_id: string;
  total_paths: number;
  by_risk_tier: Record<string, number>;
  top_paths: AttackPath[];
}

export interface AttackPathDetailResponse {
  path: AttackPath & { remediation: RemediationStep[] };
}

export function listAttackPaths(params: AttackPathListParams = {}): Promise<AttackPathListResponse> {
  const qs = new URLSearchParams();
  if (params.min_risk !== undefined) qs.set("min_risk", String(params.min_risk));
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return request(`/attack-paths${q ? `?${q}` : ""}`);
}

export function getAttackPath(pathId: string): Promise<AttackPathDetailResponse> {
  return request(`/attack-paths/${encodeURIComponent(pathId)}`);
}

export function fetchAttackPathSummary(): Promise<AttackPathSummaryResponse> {
  return request("/attack-paths/summary");
}

// ── Hunt ────────────────────────────────────────────────────────

export interface HuntFindingListParams {
  severity?: string;
  playbook?: string;
  limit?: number;
  offset?: number;
}

export interface HuntFindingListResponse {
  findings: HuntFindingRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface HuntSummaryResponse {
  tenant_id: string;
  by_severity: { severity: string; count: number }[];
  total_findings: number;
  active_hunts: number;
}

export interface HuntFindingDetailResponse {
  finding: HuntFindingRecord;
}

export function listHuntFindings(params: HuntFindingListParams = {}): Promise<HuntFindingListResponse> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.playbook) qs.set("playbook", params.playbook);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return request(`/hunt/findings${q ? `?${q}` : ""}`);
}

export function getHuntFinding(findingId: string): Promise<HuntFindingDetailResponse> {
  return request(`/hunt/findings/${encodeURIComponent(findingId)}`);
}

export function fetchHuntSummary(): Promise<HuntSummaryResponse> {
  return request("/hunt/summary");
}

// ── Simulations ─────────────────────────────────────────────────

export interface SimulationListParams {
  tactic?: string;
  limit?: number;
  offset?: number;
}

export interface SimulationListResponse {
  simulations: SimulationRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface SimulationSummaryResponse {
  tenant_id: string;
  total_runs: number;
  techniques_tested: number;
  total_findings: number;
  highest_risk_score: number;
  by_tactic: Record<string, number>;
}

export function listSimulations(params: SimulationListParams = {}): Promise<SimulationListResponse> {
  const qs = new URLSearchParams();
  if (params.tactic) qs.set("tactic", params.tactic);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return request(`/simulations${q ? `?${q}` : ""}`);
}

export function fetchSimulationSummary(): Promise<SimulationSummaryResponse> {
  return request("/simulations/summary");
}

// ── Shadow AI (Governance) ────────────────────────────────────

import type { ShadowAiService } from "../types/core";

export interface ShadowAiListParams {
  category?: string;
  risk_tier?: string;
  sanctioned?: boolean;
  min_risk_score?: number;
  limit?: number;
  offset?: number;
}

export interface ShadowAiListResponse {
  services: ShadowAiService[];
  total: number;
  limit: number;
  offset: number;
}

export interface ShadowAiSummaryResponse {
  tenant_id: string;
  total_services: number;
  unsanctioned_count: number;
  max_risk_score: number;
  by_category: { category: string; count: number }[];
  by_risk_tier: { risk_tier: string; count: number }[];
}

export interface ShadowAiDetailResponse {
  service: ShadowAiService;
}

export function listShadowAiServices(
  params: ShadowAiListParams = {},
): Promise<ShadowAiListResponse> {
  const qs = new URLSearchParams();
  if (params.category) qs.set("category", params.category);
  if (params.risk_tier) qs.set("risk_tier", params.risk_tier);
  if (params.sanctioned !== undefined) qs.set("sanctioned", String(params.sanctioned));
  if (params.min_risk_score !== undefined) qs.set("min_risk_score", String(params.min_risk_score));
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return request(`/governance/shadow-ai${q ? `?${q}` : ""}`);
}

export function getShadowAiService(serviceId: string): Promise<ShadowAiDetailResponse> {
  return request(`/governance/shadow-ai/${encodeURIComponent(serviceId)}`);
}

export function fetchShadowAiSummary(): Promise<ShadowAiSummaryResponse> {
  return request("/governance/shadow-ai/summary");
}

// ── Auth ────────────────────────────────────────────────────────

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
}

/**
 * Login endpoint — Phase 0 stub. In production this would hit
 * an actual authentication backend (SSO/SAML/OIDC).
 */
export function login(credentials: LoginRequest): Promise<LoginResponse> {
  return request("/auth/login", {
    method: "POST",
    body: JSON.stringify(credentials),
  });
}

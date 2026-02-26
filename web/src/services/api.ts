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

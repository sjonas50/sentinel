# Sentinel — Structured Build Plan

## Context Recovery Guide

> **For any session resuming work on Sentinel, read this section first.**
>
> - **What is Sentinel?** Autonomous enterprise cyber defense platform with 4 pillars: DISCOVER (network digital twin), DEFEND (threat hunting/attack sim), GOVERN (AI governance), OBSERVE (Engram audit trail)
> - **Original plan:** `plan.md` — full product/business context
> - **This file:** Engineering build plan with atomic tasks, dependencies, and acceptance criteria
> - **Memory:** `~/.claude/projects/-Users-sjonas-Sentinel/memory/MEMORY.md` — session-persistent context
> - **Conventions:** `CLAUDE.md` at project root — coding standards and patterns
> - **Current phase progress:** Check the `## Progress Tracker` section at the bottom of this file

---

## Monorepo Structure

```
sentinel/
├── CLAUDE.md                    # Project conventions for AI assistants
├── BUILD_PLAN.md                # This file — master build plan
├── plan.md                      # Original product/business plan
├── docker-compose.yml           # Local dev environment
├── docker-compose.prod.yml      # Production deployment
├── Makefile                     # Top-level build commands
├── .github/
│   └── workflows/               # CI/CD pipelines
│
├── crates/                      # Rust workspace
│   ├── Cargo.toml               # Workspace root
│   ├── sentinel-core/           # Shared types, config, error handling
│   │   └── src/
│   ├── sentinel-discover/       # Network scanner daemon
│   │   └── src/
│   ├── sentinel-engram/         # Engram reasoning capture library
│   │   └── src/
│   ├── sentinel-graph/          # Neo4j client + graph operations
│   │   └── src/
│   └── sentinel-pathfind/       # Attack path computation engine
│       └── src/
│
├── python/                      # Python packages
│   ├── pyproject.toml           # Workspace-level Python config
│   ├── sentinel-api/            # FastAPI backend
│   │   ├── pyproject.toml
│   │   ├── sentinel_api/
│   │   │   ├── main.py
│   │   │   ├── routes/
│   │   │   ├── models/
│   │   │   ├── services/
│   │   │   └── middleware/
│   │   └── tests/
│   ├── sentinel-agents/         # LLM-powered agent framework
│   │   ├── pyproject.toml
│   │   ├── sentinel_agents/
│   │   │   ├── base.py          # Base agent class with Engram integration
│   │   │   ├── orchestrator.py  # Agent lifecycle management
│   │   │   ├── hunt/            # Threat hunting agents
│   │   │   ├── simulate/        # Adversarial simulation agents
│   │   │   └── govern/          # Governance agents
│   │   └── tests/
│   ├── sentinel-connectors/     # Integration connectors
│   │   ├── pyproject.toml
│   │   ├── sentinel_connectors/
│   │   │   ├── base.py          # Abstract connector interface
│   │   │   ├── cloud/           # AWS, Azure, GCP
│   │   │   ├── identity/        # Entra ID, Okta
│   │   │   ├── siem/            # Elastic, Splunk
│   │   │   ├── edr/             # CrowdStrike, SentinelOne
│   │   │   └── firewall/        # Palo Alto, Fortinet
│   │   └── tests/
│   └── sentinel-policy/         # OPA/Rego policy engine wrapper
│       ├── pyproject.toml
│       ├── sentinel_policy/
│       └── tests/
│
├── web/                         # React frontend
│   ├── package.json
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── layout/          # Shell, nav, auth
│   │   │   ├── network-map/     # D3 force-directed graph
│   │   │   ├── attack-paths/    # Attack path visualization
│   │   │   ├── hunt-feed/       # Threat hunt findings
│   │   │   ├── governance/      # AI governance views
│   │   │   └── compliance/      # Audit & compliance
│   │   ├── hooks/
│   │   ├── services/            # API client
│   │   ├── stores/              # State management
│   │   └── types/
│   └── tests/
│
├── policies/                    # OPA/Rego policy files
│   ├── agent/                   # Agent behavior policies
│   ├── mcp/                     # MCP security policies
│   └── response/                # Automated response approval policies
│
├── schemas/                     # Shared schemas
│   ├── neo4j/                   # Cypher schema definitions + migrations
│   ├── postgres/                # SQL migrations (via sqlx or similar)
│   ├── clickhouse/              # ClickHouse table definitions
│   └── events/                  # Kafka event schemas (Avro/JSON Schema)
│
├── deploy/                      # Deployment configs
│   ├── k8s/                     # Kubernetes manifests
│   ├── helm/                    # Helm charts
│   └── terraform/               # Infrastructure as code
│
└── docs/                        # Internal documentation
    ├── architecture/            # ADRs (Architecture Decision Records)
    ├── api/                     # API documentation
    └── runbooks/                # Operational runbooks
```

---

## Architecture Decisions (Lock Down Before Coding)

### ADR-001: Monorepo with Rust Workspace + Python Packages
- **Decision:** Single repo, Rust crates under `crates/`, Python packages under `python/`
- **Rationale:** Shared types, atomic commits across components, simpler CI/CD

### ADR-002: API Layer — FastAPI (Python)
- **Decision:** Python FastAPI as the primary API layer, not Rust
- **Rationale:** Faster iteration, easier LLM integration, Python team larger. Rust handles performance-critical paths only (scanning, pathfinding, Engram hashing)

### ADR-003: Event Bus — Start with Redis Streams, Migrate to Kafka
- **Decision:** Use Redis Streams for Phase 0-1, plan Kafka migration for Phase 2+
- **Rationale:** Kafka is heavy for early dev. Redis Streams provides ordered, persistent messaging that's sufficient until event volume justifies Kafka. Abstract behind an interface so the swap is clean.

### ADR-004: Graph Database Access Pattern
- **Decision:** Rust `sentinel-graph` crate provides a typed Neo4j client. Python accesses Neo4j through the FastAPI service (not directly)
- **Rationale:** Single source of truth for graph mutations. Prevents schema drift between Rust and Python codepaths.

### ADR-005: Engram Storage — Git Object Store
- **Decision:** Engram records stored as content-addressed Git objects under `refs/engrams/`
- **Rationale:** Tamper-evident by design (BLAKE3), versionable, diff-able, works with standard Git tooling

### ADR-006: Authentication — JWT + RBAC
- **Decision:** JWT-based auth with role-based access control (CISO, SOC Analyst, Auditor)
- **Rationale:** Standard enterprise pattern, works with SSO/SAML integration later

### ADR-007: LLM Provider Abstraction
- **Decision:** Abstract LLM calls behind a provider interface. Default to Claude API, support local models
- **Rationale:** Enterprise customers may require airgapped deployments

---

## Dependency Graph

```
LAYER 0 — Must exist first (no dependencies):
  ├── sentinel-core (shared types, config, errors)
  ├── schemas/ (all DB schemas)
  ├── docker-compose.yml (local infra)
  └── CI/CD pipeline

LAYER 1 — Depends on Layer 0:
  ├── sentinel-engram (depends on: sentinel-core)
  ├── sentinel-graph (depends on: sentinel-core, neo4j schema)
  ├── sentinel-api shell (depends on: sentinel-core, postgres schema)
  ├── sentinel-policy (depends on: sentinel-core)
  └── web/ shell (depends on: sentinel-api)

LAYER 2 — Depends on Layer 1:
  ├── sentinel-connectors (depends on: sentinel-core, sentinel-graph, sentinel-engram)
  ├── sentinel-discover (depends on: sentinel-core, sentinel-graph, sentinel-engram)
  └── sentinel-agents base (depends on: sentinel-core, sentinel-engram, sentinel-policy)

LAYER 3 — Depends on Layer 2:
  ├── DISCOVER features (depends on: sentinel-discover, sentinel-connectors, sentinel-graph)
  ├── sentinel-pathfind (depends on: sentinel-graph, sentinel-engram)
  └── SIEM connectors (depends on: sentinel-connectors)

LAYER 4 — Depends on Layer 3:
  ├── DEFEND features (depends on: sentinel-pathfind, sentinel-agents, SIEM connectors)
  ├── GOVERN features (depends on: sentinel-agents, sentinel-policy, sentinel-connectors)
  └── Dashboard views (depends on: respective pillar APIs)

LAYER 5 — Depends on Layer 4:
  ├── Compliance reporting (depends on: sentinel-engram, all pillar data)
  ├── Automated response (depends on: DEFEND, sentinel-policy)
  └── Adversarial co-evolution (depends on: DEFEND agents, sentinel-pathfind)
```

---

## Phase 0: Foundation (Weeks 1-4)

### Task 0.1: Initialize Repository
**Depends on:** Nothing
**Acceptance criteria:**
- [ ] Git repo initialized with `.gitignore` for Rust, Python, Node
- [ ] Rust workspace `Cargo.toml` with `sentinel-core` crate stub
- [ ] Python workspace with `pyproject.toml` (uv or poetry)
- [ ] React app scaffolded with Vite + TypeScript
- [ ] `Makefile` with targets: `build`, `test`, `lint`, `docker-up`, `docker-down`
- [ ] `.github/workflows/ci.yml` — lint + test on PR

**Key files created:**
- `Cargo.toml`, `crates/sentinel-core/Cargo.toml`, `crates/sentinel-core/src/lib.rs`
- `python/pyproject.toml`, `python/sentinel-api/pyproject.toml`
- `web/package.json`, `web/vite.config.ts`, `web/src/App.tsx`

---

### Task 0.2: Shared Types & Config (sentinel-core)
**Depends on:** 0.1
**Acceptance criteria:**
- [ ] Rust crate `sentinel-core` with:
  - Common error types (`SentinelError` enum)
  - Configuration loader (TOML/env vars)
  - Asset types: `Host`, `Service`, `Port`, `User`, `Group`, `Role`, `Subnet`, `VPC`, `Vulnerability`
  - Edge types: `ConnectsTo`, `HasAccess`, `MemberOf`, `RunsOn`, `Trusts`, `RoutesTo`, `Exposes`, `DependsOn`, `CanReach`
  - Serialization (serde) for all types
  - Event types for inter-service communication
- [ ] Python `sentinel-core` package mirroring Rust types (Pydantic models)
- [ ] TypeScript types in `web/src/types/` mirroring the same

**Key files:**
- `crates/sentinel-core/src/types.rs` — all node/edge types
- `crates/sentinel-core/src/config.rs` — config management
- `crates/sentinel-core/src/error.rs` — error types
- `crates/sentinel-core/src/events.rs` — event schemas
- `python/sentinel-api/sentinel_api/models/core.py` — Pydantic mirrors
- `web/src/types/core.ts` — TypeScript mirrors

---

### Task 0.3: Database Schemas
**Depends on:** 0.2
**Acceptance criteria:**
- [ ] Neo4j schema: Cypher constraints + indexes for all node/edge types from sentinel-core
- [ ] PostgreSQL schema: users, tenants, api_keys, sessions, audit_log tables
- [ ] ClickHouse schema: events table (partitioned by date, ordered by tenant+timestamp)
- [ ] Schema files in `schemas/` directory with migration numbering

**Key files:**
- `schemas/neo4j/001_initial_schema.cypher`
- `schemas/postgres/001_initial_schema.sql`
- `schemas/clickhouse/001_events_table.sql`

---

### Task 0.4: Local Development Infrastructure
**Depends on:** 0.3
**Acceptance criteria:**
- [ ] `docker-compose.yml` with services: Neo4j, PostgreSQL, ClickHouse, Redis
- [ ] Health checks on all services
- [ ] Volume mounts for data persistence
- [ ] `make docker-up` starts everything, `make docker-down` stops
- [ ] Seed script that applies all schemas on first run
- [ ] `.env.example` with all required config vars

**Key files:**
- `docker-compose.yml`
- `scripts/seed.sh` — applies schemas to all DBs
- `.env.example`

---

### Task 0.5: Engram Core Library (sentinel-engram)
**Depends on:** 0.2
**Acceptance criteria:**
- [ ] Rust crate `sentinel-engram` with:
  - `Engram` struct: session_id, intent, context, decisions[], alternatives[], actions[], timestamps
  - `EngramStore` trait with Git-backed implementation
  - BLAKE3 content hashing for tamper evidence
  - `EngamSession` — builder pattern for recording during agent execution
  - Serialize to/from JSON for the reasoning chain
  - Query interface: list engrams by time range, agent_id, session_id
- [ ] Python bindings via PyO3 OR pure Python reimplementation (decide in ADR)
- [ ] Unit tests for create, store, retrieve, verify hash integrity

**Key files:**
- `crates/sentinel-engram/src/lib.rs`
- `crates/sentinel-engram/src/store.rs` — Git object storage
- `crates/sentinel-engram/src/session.rs` — session builder
- `crates/sentinel-engram/src/hash.rs` — BLAKE3 hashing

---

### Task 0.6: Graph Client (sentinel-graph)
**Depends on:** 0.2, 0.3
**Acceptance criteria:**
- [ ] Rust crate `sentinel-graph` with:
  - Neo4j connection pool (bolt protocol via `neo4rs` crate)
  - Typed CRUD operations for all node/edge types
  - Delta update API: upsert node, upsert edge, remove stale (by last_seen timestamp)
  - Cypher query builder for common patterns (neighbors, paths, subgraph)
- [ ] Integration tests against local Neo4j (docker-compose)

**Key files:**
- `crates/sentinel-graph/src/lib.rs`
- `crates/sentinel-graph/src/client.rs` — connection management
- `crates/sentinel-graph/src/mutations.rs` — write operations
- `crates/sentinel-graph/src/queries.rs` — read operations

---

### Task 0.7: API Layer Shell (sentinel-api)
**Depends on:** 0.2, 0.3, 0.4
**Acceptance criteria:**
- [ ] FastAPI app with:
  - Health check endpoint (`GET /health`)
  - Auth middleware (JWT verification, placeholder for now)
  - CORS configuration
  - PostgreSQL connection via `asyncpg` or `sqlalchemy[asyncio]`
  - Neo4j read-only proxy endpoints for graph queries
  - WebSocket endpoint stub for real-time updates
  - OpenAPI docs auto-generated
- [ ] Docker build for the API service
- [ ] Integration tests

**Key files:**
- `python/sentinel-api/sentinel_api/main.py`
- `python/sentinel-api/sentinel_api/routes/health.py`
- `python/sentinel-api/sentinel_api/routes/graph.py`
- `python/sentinel-api/sentinel_api/middleware/auth.py`
- `python/sentinel-api/sentinel_api/db.py`

---

### Task 0.8: Dashboard Shell (web/)
**Depends on:** 0.7
**Acceptance criteria:**
- [ ] React + Vite + TypeScript app with:
  - Layout: sidebar navigation, header with user menu, main content area
  - Auth flow: login page, JWT storage, protected routes
  - API client service (axios/fetch wrapper)
  - Placeholder pages for each pillar: Discover, Defend, Govern, Observe
  - WebSocket connection for real-time updates (stub)
  - Dark theme (enterprise security products are always dark)
- [ ] Component tests with Vitest

**Key files:**
- `web/src/App.tsx` — routing + layout
- `web/src/components/layout/Sidebar.tsx`
- `web/src/components/layout/Header.tsx`
- `web/src/services/api.ts` — API client
- `web/src/services/ws.ts` — WebSocket client
- `web/src/pages/Discover.tsx`, `Defend.tsx`, `Govern.tsx`, `Observe.tsx`

---

### Task 0.9: Policy Engine Bootstrap (sentinel-policy)
**Depends on:** 0.2
**Acceptance criteria:**
- [ ] Python package `sentinel-policy` with:
  - OPA client (REST API to OPA sidecar or embedded via `opa-python`)
  - Policy evaluation interface: `evaluate(input_data, policy_path) → Decision`
  - Initial policies in `policies/`:
    - `policies/agent/base.rego` — agent action allowlist
    - `policies/response/approval.rego` — response action tiers (auto/fast-track/review)
- [ ] OPA added to docker-compose
- [ ] Unit tests with sample policy evaluations

**Key files:**
- `python/sentinel-policy/sentinel_policy/engine.py`
- `policies/agent/base.rego`
- `policies/response/approval.rego`

---

### Task 0.10: Connector Framework (sentinel-connectors)
**Depends on:** 0.2, 0.5, 0.6
**Acceptance criteria:**
- [ ] Python package `sentinel-connectors` with:
  - Abstract `BaseConnector` class: `discover()`, `sync()`, `health_check()`
  - Connector registry for dynamic loading
  - Credential management (read from env/vault, never hardcoded)
  - Rate limiting / retry logic
  - Engram session auto-created for each sync operation
  - Output: structured asset records matching sentinel-core types → Neo4j via API
- [ ] First connector: AWS (`sentinel_connectors/cloud/aws.py`)
  - EC2 instances, security groups, IAM roles/policies, VPCs, S3 buckets
- [ ] Second connector: Azure (`sentinel_connectors/cloud/azure.py`)
  - VMs, NSGs, Entra ID users/groups, subscriptions
- [ ] Integration tests with mocked APIs (moto for AWS, etc.)

**Key files:**
- `python/sentinel-connectors/sentinel_connectors/base.py`
- `python/sentinel-connectors/sentinel_connectors/registry.py`
- `python/sentinel-connectors/sentinel_connectors/cloud/aws.py`
- `python/sentinel-connectors/sentinel_connectors/cloud/azure.py`

---

## Phase 1: DISCOVER MVP (Weeks 5-10)

### Task 1.1: Network Scanner (sentinel-discover)
**Depends on:** 0.2, 0.5, 0.6
**Acceptance criteria:**
- [ ] Rust binary `sentinel-discover` with:
  - Nmap wrapper: configurable scan profiles (quick, standard, deep)
  - Scheduling engine: periodic scans with configurable intervals per subnet
  - Change detection: diff current scan against previous, emit only deltas
  - Output: asset records → Neo4j via sentinel-graph
  - Engram session for each scan run (what was scanned, what changed, what was skipped)
- [ ] Docker build for scanner
- [ ] CLI mode for one-shot scans

**Key files:**
- `crates/sentinel-discover/src/main.rs`
- `crates/sentinel-discover/src/scanner.rs` — Nmap integration
- `crates/sentinel-discover/src/scheduler.rs` — scan scheduling
- `crates/sentinel-discover/src/diff.rs` — change detection

---

### Task 1.2: Cloud Discovery Connectors
**Depends on:** 0.10
**Acceptance criteria:**
- [ ] AWS connector fully operational: EC2, VPC, SG, IAM, S3, RDS, Lambda, ECS/EKS
- [ ] Azure connector fully operational: VMs, VNets, NSGs, Entra ID, Key Vault, AKS
- [ ] GCP connector: Compute, VPC, IAM, GKE, Cloud SQL
- [ ] All connectors produce normalized asset records that map to Neo4j schema
- [ ] Engram trail for each discovery session

**Key files:**
- `python/sentinel-connectors/sentinel_connectors/cloud/aws.py` (expand)
- `python/sentinel-connectors/sentinel_connectors/cloud/azure.py` (expand)
- `python/sentinel-connectors/sentinel_connectors/cloud/gcp.py` (new)

---

### Task 1.3: Identity Connectors
**Depends on:** 0.10
**Acceptance criteria:**
- [ ] Entra ID connector: users, groups, roles, conditional access policies, MFA status
- [ ] Okta connector: users, groups, apps, policies
- [ ] Output: User/Group/Role nodes with HAS_ACCESS/MEMBER_OF edges
- [ ] Tests with mocked identity provider responses

**Key files:**
- `python/sentinel-connectors/sentinel_connectors/identity/entra.py`
- `python/sentinel-connectors/sentinel_connectors/identity/okta.py`

---

### Task 1.4: Vulnerability Correlation Engine
**Depends on:** 0.6
**Acceptance criteria:**
- [ ] NVD API v2 client: daily sync of CVE data
- [ ] EPSS score integration (probability of exploitation)
- [ ] CISA KEV catalog sync
- [ ] Matching engine: given a (software_name, version) → list of CVEs with scores
- [ ] Graph integration: Vulnerability nodes linked to Service nodes via HAS_CVE edges
- [ ] API endpoints: GET /vulnerabilities, GET /assets/{id}/vulnerabilities

**Key files:**
- `python/sentinel-api/sentinel_api/services/vuln_correlation.py`
- `python/sentinel-api/sentinel_api/routes/vulnerabilities.py`

---

### Task 1.5: Configuration Auditor
**Depends on:** 0.10, 1.2, 1.3
**Acceptance criteria:**
- [ ] CIS Benchmark rules engine (start with AWS CIS Benchmark v2.0)
- [ ] Configuration snapshot + diff against baseline
- [ ] Misconfiguration scoring (severity: critical/high/medium/low)
- [ ] Findings stored as properties on affected graph nodes
- [ ] API endpoints: GET /audit/findings, GET /audit/findings/{asset_id}

**Key files:**
- `python/sentinel-api/sentinel_api/services/config_auditor.py`
- `python/sentinel-api/sentinel_api/routes/audit.py`

---

### Task 1.6: Dashboard — Network Map View
**Depends on:** 0.8, 1.1, 1.2
**Acceptance criteria:**
- [ ] Interactive network topology visualization using D3.js force-directed graph
- [ ] Node types visually distinguished (hosts, services, users, subnets — different shapes/colors)
- [ ] Edge labels showing relationship type
- [ ] Click node → detail panel (properties, vulnerabilities, connections)
- [ ] Zoom, pan, search by IP/hostname
- [ ] Real-time updates via WebSocket when graph changes
- [ ] Asset inventory table view (alternative to graph view)

**Key files:**
- `web/src/components/network-map/NetworkGraph.tsx`
- `web/src/components/network-map/NodeDetail.tsx`
- `web/src/components/network-map/AssetTable.tsx`

---

### Task 1.7: Dashboard — Vulnerability Overview
**Depends on:** 0.8, 1.4
**Acceptance criteria:**
- [ ] Vulnerability summary: count by severity, trend chart
- [ ] Ranked vulnerability list with CVE details, EPSS score, affected assets
- [ ] Click-through from vulnerability → affected assets on network map
- [ ] CISA KEV badge for actively exploited vulnerabilities
- [ ] Export to CSV

**Key files:**
- `web/src/components/vulnerabilities/VulnSummary.tsx`
- `web/src/components/vulnerabilities/VulnTable.tsx`

---

## Phase 2: DEFEND MVP (Weeks 11-18)

### Task 2.1: Attack Path Calculator (sentinel-pathfind)
**Depends on:** 0.5, 0.6
**Acceptance criteria:**
- [ ] Rust crate `sentinel-pathfind` with:
  - All-paths enumeration: internet-facing → crown jewels (configurable targets)
  - Shortest weighted path (edge weights from exploitability/difficulty)
  - Lateral movement chain detection
  - Blast radius computation (N-hop reachability from compromised node)
  - Risk scoring: `risk = Σ(node_criticality × edge_exploitability × path_probability)`
  - Engram integration: reasoning trail for each path computation
- [ ] API endpoints exposed through sentinel-api
- [ ] Performance: handle graphs with 10K+ nodes within 30 seconds

**Key files:**
- `crates/sentinel-pathfind/src/lib.rs`
- `crates/sentinel-pathfind/src/algorithms.rs`
- `crates/sentinel-pathfind/src/scoring.rs`
- `python/sentinel-api/sentinel_api/routes/attack_paths.py`

---

### Task 2.2: Agent Framework Base (sentinel-agents)
**Depends on:** 0.5, 0.9
**Acceptance criteria:**
- [ ] Python package `sentinel-agents` with:
  - `BaseAgent` class: lifecycle (init → plan → execute → report), Engram auto-capture
  - LLM provider abstraction (Claude API default, pluggable)
  - Tool registry: agents declare tools they can use
  - Policy check: every tool call validated against OPA policies before execution
  - Agent session management: start, pause, resume, cancel
  - Structured output: findings, recommendations, actions
- [ ] Unit tests with mock LLM responses

**Key files:**
- `python/sentinel-agents/sentinel_agents/base.py`
- `python/sentinel-agents/sentinel_agents/llm.py`
- `python/sentinel-agents/sentinel_agents/orchestrator.py`
- `python/sentinel-agents/sentinel_agents/tools.py`

---

### Task 2.3: SIEM Connector — Elastic/OpenSearch
**Depends on:** 0.10
**Acceptance criteria:**
- [ ] Elastic/OpenSearch connector with:
  - Connection management (API key + basic auth)
  - Index discovery: list available indices and their fields
  - Query execution: Elasticsearch DSL queries
  - Natural language → query translation (LLM-powered)
  - Result parsing and normalization
- [ ] Integration test with local Elastic (added to docker-compose)

**Key files:**
- `python/sentinel-connectors/sentinel_connectors/siem/elastic.py`
- `python/sentinel-connectors/sentinel_connectors/siem/query_builder.py`

---

### Task 2.4: Threat Hunt Agents
**Depends on:** 2.2, 2.3
**Acceptance criteria:**
- [ ] 3 pre-built hunt playbooks:
  1. **Credential Abuse:** failed logins, brute force, credential stuffing patterns
  2. **Lateral Movement:** unusual internal traffic, service account hopping, RDP chains
  3. **Data Exfiltration:** large outbound transfers, unusual destinations, DNS tunneling indicators
- [ ] Each playbook: parameterized, produces structured findings, generates Sigma detection rules
- [ ] Hunt findings feed: real-time display in dashboard
- [ ] Engram trail for every hunt session

**Key files:**
- `python/sentinel-agents/sentinel_agents/hunt/credential_abuse.py`
- `python/sentinel-agents/sentinel_agents/hunt/lateral_movement.py`
- `python/sentinel-agents/sentinel_agents/hunt/data_exfiltration.py`

---

### Task 2.5: Adversarial Simulation v1
**Depends on:** 2.1, 2.2
**Acceptance criteria:**
- [ ] Offensive agents for top 20 MITRE ATT&CK techniques:
  - Initial Access (phishing simulation, exposed services)
  - Lateral Movement (credential reuse, trust exploitation)
  - Privilege Escalation (misconfig exploitation)
  - Exfiltration (data path analysis)
- [ ] All simulations run against the digital twin ONLY
- [ ] Each simulation produces: paths found, risk scores, remediation recommendations
- [ ] Engram captures full reasoning chain for each simulation

**Key files:**
- `python/sentinel-agents/sentinel_agents/simulate/offensive.py`
- `python/sentinel-agents/sentinel_agents/simulate/mitre.py` — ATT&CK technique definitions

---

### Task 2.6: Dashboard — Attack Paths & Hunt Feed
**Depends on:** 0.8, 2.1, 2.4
**Acceptance criteria:**
- [ ] Attack path visualization: ranked list, click to expand step-by-step path
- [ ] Path rendered on network map (highlight nodes/edges in the path)
- [ ] Remediation recommendations per path
- [ ] Hunt findings feed: real-time, filterable by severity/type
- [ ] Simulation results view

**Key files:**
- `web/src/components/attack-paths/AttackPathList.tsx`
- `web/src/components/attack-paths/PathDetail.tsx`
- `web/src/components/hunt-feed/HuntFeed.tsx`

---

## Phase 3: GOVERN MVP (Weeks 19-24)

### Task 3.1: Shadow AI Discovery
**Depends on:** 0.6, 0.10
**Acceptance criteria:**
- [ ] Known AI service domain list (OpenAI, Anthropic, Google AI, Cohere, HuggingFace, etc.)
- [ ] DNS log analysis: detect queries to AI service domains
- [ ] Network flow analysis: identify API calls to AI endpoints
- [ ] Shadow AI inventory: discovered tools with risk scoring
- [ ] API endpoints for shadow AI data

**Key files:**
- `python/sentinel-connectors/sentinel_connectors/governance/shadow_ai.py`
- `python/sentinel-api/sentinel_api/routes/governance.py`

---

### Task 3.2: MCP Interceptor Proxy
**Depends on:** 0.9
**Acceptance criteria:**
- [ ] Proxy service that intercepts MCP tool calls between agents and servers
- [ ] Real-time inspection of every tool call
- [ ] OPA/Rego policy enforcement on tool calls
- [ ] Threat detection: tool shadowing, parameter injection, secrets leakage
- [ ] TLS termination + mTLS to MCP servers
- [ ] Engram logging of all intercepted calls

**Key files:**
- `python/sentinel-api/sentinel_api/services/mcp_proxy.py`
- `policies/mcp/tool_allowlist.rego`
- `policies/mcp/data_inspection.rego`

---

### Task 3.3: Agent Identity & Behavior
**Depends on:** 0.9, 2.2
**Acceptance criteria:**
- [ ] Agent registry: register, update, deactivate agent identities
- [ ] Permission model: what tools/resources each agent can access
- [ ] Behavioral baseline: record action patterns over time
- [ ] Drift detection: alert when agent deviates from baseline
- [ ] API endpoints for agent management

**Key files:**
- `python/sentinel-api/sentinel_api/services/agent_registry.py`
- `python/sentinel-api/sentinel_api/routes/agents.py`

---

### Task 3.4: AI Data Loss Prevention
**Depends on:** 3.2
**Acceptance criteria:**
- [ ] PII detection engine (regex + ML-based for names, emails, SSNs, credit cards)
- [ ] Code/IP scanning (detect source code, API keys, secrets)
- [ ] Policy framework: block, redact, or alert based on data classification
- [ ] Audit log of all data flows to AI services

**Key files:**
- `python/sentinel-agents/sentinel_agents/govern/dlp.py`
- `policies/mcp/dlp.rego`

---

### Task 3.5: Dashboard — Governance Views
**Depends on:** 0.8, 3.1, 3.3
**Acceptance criteria:**
- [ ] Shadow AI inventory table with risk scores
- [ ] Agent activity timeline
- [ ] Policy violation feed
- [ ] Data flow visualization (what data goes to which AI services)

**Key files:**
- `web/src/components/governance/ShadowAITable.tsx`
- `web/src/components/governance/AgentActivity.tsx`
- `web/src/components/governance/PolicyViolations.tsx`

---

## Phase 4: Integration & Polish (Weeks 25-30)

### Task 4.1: Compliance Reporting Engine
**Depends on:** 0.5, all pillar data
**Acceptance criteria:**
- [ ] SOC 2 Type II evidence auto-generation from Engram data
- [ ] ISO 27001 control mapping
- [ ] NIST CSF alignment dashboard
- [ ] Report templates: executive summary, detailed findings, evidence packages
- [ ] PDF export

---

### Task 4.2: Automated Response Framework
**Depends on:** 0.9, 2.4
**Acceptance criteria:**
- [ ] Response action types: auto-execute, fast-track, full-review
- [ ] Execution engine: run actions via existing tool APIs
- [ ] Rollback capability for every action
- [ ] Approval workflow (WebSocket notifications to dashboard)
- [ ] Engram trail for every response action

---

### Task 4.3: Additional Integrations
**Depends on:** 0.10
- [ ] SIEM: Splunk, Microsoft Sentinel
- [ ] EDR: CrowdStrike, SentinelOne connectors
- [ ] Firewall: Palo Alto, Fortinet connectors
- [ ] Device Management: Intune, Jamf connectors

---

### Task 4.4: Adversarial Simulation v2
**Depends on:** 2.5
- [ ] Full MITRE ATT&CK coverage
- [ ] Co-evolution loop: offense → defense → re-attack → repeat
- [ ] Generational tracking in Engram

---

## Progress Tracker

> **Update this section as tasks complete. Format: `[x]` = done, `[ ]` = not started, `[~]` = in progress**

### Phase 0: Foundation
- [x] 0.1 Initialize Repository
- [x] 0.2 Shared Types & Config
- [x] 0.3 Database Schemas
- [x] 0.4 Local Dev Infrastructure
- [ ] 0.5 Engram Core Library
- [ ] 0.6 Graph Client
- [ ] 0.7 API Layer Shell
- [ ] 0.8 Dashboard Shell
- [ ] 0.9 Policy Engine Bootstrap
- [ ] 0.10 Connector Framework

### Phase 1: DISCOVER MVP
- [ ] 1.1 Network Scanner
- [ ] 1.2 Cloud Discovery Connectors
- [ ] 1.3 Identity Connectors
- [ ] 1.4 Vulnerability Correlation Engine
- [ ] 1.5 Configuration Auditor
- [ ] 1.6 Dashboard — Network Map
- [ ] 1.7 Dashboard — Vulnerability Overview

### Phase 2: DEFEND MVP
- [ ] 2.1 Attack Path Calculator
- [ ] 2.2 Agent Framework Base
- [ ] 2.3 SIEM Connector (Elastic)
- [ ] 2.4 Threat Hunt Agents
- [ ] 2.5 Adversarial Simulation v1
- [ ] 2.6 Dashboard — Attack Paths & Hunt Feed

### Phase 3: GOVERN MVP
- [ ] 3.1 Shadow AI Discovery
- [ ] 3.2 MCP Interceptor Proxy
- [ ] 3.3 Agent Identity & Behavior
- [ ] 3.4 AI Data Loss Prevention
- [ ] 3.5 Dashboard — Governance Views

### Phase 4: Integration & Polish
- [ ] 4.1 Compliance Reporting Engine
- [ ] 4.2 Automated Response Framework
- [ ] 4.3 Additional Integrations
- [ ] 4.4 Adversarial Simulation v2

---

## Technical Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **Neo4j performance at scale** (>100K nodes) | Attack path computation slows down | sentinel-pathfind in Rust performs heavy graph traversal locally, uses Neo4j for storage/simple queries only |
| **Engram storage growth** | Git repos grow large with many sessions | Implement pruning/archival policies; consider blob storage for old engrams |
| **LLM hallucination in security context** | False positives/missed threats | Human-in-the-loop for all actions; Engram captures reasoning for review; structured output validation |
| **Rust-Python boundary** | FFI complexity, deployment friction | PyO3 for critical paths; otherwise pure Python reimplementation where Rust isn't needed for perf |
| **Multi-tenant data isolation** | Customer data leakage | Neo4j: tenant label on every node; PostgreSQL: row-level security; strict tenant context in every query |
| **Connector API changes** | Cloud/tool providers change APIs | Abstract connector interface; version pinning; integration test suite run weekly |

# Sentinel Platform — Architectural Analysis

**Date:** 2026-02-24
**Author:** Architecture Review
**Status:** Proposed

---

## Table of Contents

1. [Recommended Monorepo Structure](#1-recommended-monorepo-structure)
2. [Dependency Analysis and Build Order](#2-dependency-analysis-and-build-order)
3. [Critical Architectural Decisions (ADRs)](#3-critical-architectural-decisions)
4. [Technical Risk Assessment](#4-technical-risk-assessment)
5. [Shared Infrastructure Inventory](#5-shared-infrastructure-inventory)

---

## 1. Recommended Monorepo Structure

The structure below is organized around three principles: (a) shared infrastructure
lives at the top so every pillar depends downward, (b) each pillar is a self-contained
workspace that can be built and tested independently, and (c) the Rust and Python
ecosystems are separated at the workspace level to keep their respective toolchains
clean (Cargo workspace for Rust, Python virtual environments per service).

```
sentinel/
├── .github/
│   ├── workflows/
│   │   ├── ci-rust.yml              # Cargo check, clippy, test, build
│   │   ├── ci-python.yml            # pytest, mypy, ruff
│   │   ├── ci-frontend.yml          # vitest, eslint, build
│   │   ├── ci-integration.yml       # docker-compose based integration tests
│   │   └── release.yml              # multi-arch container builds + push
│   └── CODEOWNERS
│
├── Cargo.toml                       # Rust workspace root
├── pyproject.toml                   # Python monorepo root (uv / hatch workspace)
├── package.json                     # Node workspace root (pnpm)
├── pnpm-workspace.yaml
│
├── docs/
│   ├── architecture/
│   │   ├── 001-architectural-analysis.md   # This document
│   │   ├── adr/                            # Architecture Decision Records
│   │   │   ├── ADR-001-monorepo-structure.md
│   │   │   ├── ADR-002-event-backbone.md
│   │   │   ├── ADR-003-graph-database.md
│   │   │   ├── ADR-004-rust-python-boundary.md
│   │   │   ├── ADR-005-engram-storage-model.md
│   │   │   └── ADR-006-multi-tenancy.md
│   │   ├── diagrams/                       # C4, sequence, data-flow diagrams
│   │   └── api-contracts/                  # OpenAPI specs, proto files
│   ├── runbooks/
│   └── onboarding/
│
├── proto/                           # Shared protobuf / gRPC definitions
│   ├── sentinel/
│   │   ├── common.proto             # Shared types (AssetId, TenantId, Timestamp)
│   │   ├── events.proto             # Domain event schemas
│   │   ├── discovery.proto          # DISCOVER service contract
│   │   ├── defense.proto            # DEFEND service contract
│   │   ├── governance.proto         # GOVERN service contract
│   │   └── engram.proto             # OBSERVE / Engram service contract
│   └── buf.yaml
│
├── schemas/                         # Shared data schemas (not RPC)
│   ├── neo4j/
│   │   ├── constraints.cypher       # Graph constraints and indexes
│   │   ├── node-types.cypher        # Node label definitions
│   │   └── migrations/              # Versioned graph schema migrations
│   ├── clickhouse/
│   │   └── migrations/
│   ├── postgres/
│   │   └── migrations/              # SQL migrations (sqlx or refinery)
│   ├── kafka/
│   │   └── topic-config.yaml        # Topic definitions, partitioning, retention
│   └── opa/
│       ├── base-policies/           # Shared OPA/Rego policy library
│       └── test/
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   SHARED RUST CRATES
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
├── crates/
│   ├── sentinel-common/             # Shared types, error handling, config
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs             # AssetId, TenantId, EventId, etc.
│   │       ├── config.rs            # Unified configuration model
│   │       └── error.rs             # Sentinel error taxonomy
│   │
│   ├── sentinel-events/             # Event definitions + Kafka producer/consumer
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── schemas.rs           # Strongly-typed event structs
│   │       ├── producer.rs          # Kafka producer wrapper
│   │       └── consumer.rs          # Kafka consumer wrapper
│   │
│   ├── sentinel-graph/              # Neo4j client + typed query builder
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── client.rs            # Neo4j connection pool + query execution
│   │       ├── models.rs            # Rust structs matching graph node/edge types
│   │       └── queries.rs           # Parameterized Cypher query templates
│   │
│   ├── sentinel-engram/             # Engram core (existing IP, adapted)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── session.rs           # Reasoning session lifecycle
│   │       ├── storage.rs           # Git object storage with BLAKE3
│   │       ├── refs.rs              # refs/engrams/ management
│   │       └── query.rs             # Query/search over engram history
│   │
│   └── sentinel-auth/               # Shared authentication/authorization
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── jwt.rs               # JWT validation
│           ├── rbac.rs              # Role-based access control
│           └── tenant.rs            # Multi-tenant context extraction
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   PILLAR 1: DISCOVER
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
├── services/
│   ├── discover/
│   │   ├── scanner/                 # Rust binary: network scanning daemon
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── main.rs
│   │   │       ├── nmap.rs          # Nmap wrapper + result parser
│   │   │       ├── passive.rs       # Passive traffic analysis
│   │   │       ├── scheduler.rs     # Scan scheduling + rate limiting
│   │   │       ├── dedup.rs         # Change detection / deduplication
│   │   │       └── output.rs        # Structured JSON asset records
│   │   │
│   │   ├── cloud-connectors/        # Python: cloud API discovery
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── base.py          # Abstract connector interface
│   │   │       ├── aws.py           # AWS discovery (boto3)
│   │   │       ├── azure.py         # Azure discovery (azure-mgmt)
│   │   │       ├── gcp.py           # GCP discovery (google-cloud)
│   │   │       └── registry.py      # Connector registration + scheduling
│   │   │
│   │   ├── config-auditor/          # Python: configuration audit engine
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── base.py          # Abstract auditor interface
│   │   │       ├── cis_benchmarks/  # CIS Benchmark rule definitions
│   │   │       ├── connectors/      # Per-tool config pullers
│   │   │       └── scoring.py       # Misconfiguration scoring
│   │   │
│   │   ├── vuln-correlator/         # Python: CVE/EPSS/KEV correlation
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── nvd.py           # NVD API v2 sync
│   │   │       ├── epss.py          # EPSS integration
│   │   │       ├── kev.py           # CISA KEV catalog
│   │   │       ├── sbom.py          # SBOM ingestion
│   │   │       └── correlator.py    # Match versions to CVEs, link to graph
│   │   │
│   │   └── graph-ingestor/          # Python: writes discovery data into Neo4j
│   │       ├── pyproject.toml
│   │       └── src/
│   │           ├── __init__.py
│   │           ├── consumer.py      # Kafka consumer for discovery events
│   │           ├── mutations.py     # Neo4j delta update logic
│   │           └── reconciler.py    # Periodic full reconciliation
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   PILLAR 2: DEFEND
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
│   ├── defend/
│   │   ├── attack-paths/            # Rust: high-performance path computation
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── main.rs          # gRPC server wrapping path engine
│   │   │       ├── engine.rs        # Core pathfinding algorithms
│   │   │       ├── scoring.rs       # Risk scoring model
│   │   │       ├── blast_radius.rs  # Blast radius computation
│   │   │       └── cache.rs         # Computed path caching + invalidation
│   │   │
│   │   ├── simulation/              # Python: adversarial simulation engine
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── orchestrator.py  # LangGraph simulation coordinator
│   │   │       ├── offensive/       # Offensive agent definitions
│   │   │       │   ├── base.py
│   │   │       │   └── tactics/     # Per-tactic agent implementations
│   │   │       ├── defensive/       # Defensive agent definitions
│   │   │       ├── mitre/           # ATT&CK technique library
│   │   │       └── evolution.py     # Co-evolution loop controller
│   │   │
│   │   ├── threat-hunting/          # Python: SIEM-integrated threat hunting
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── agents/          # Hunt agent definitions
│   │   │       ├── siem/
│   │   │       │   ├── base.py      # Abstract SIEM connector
│   │   │       │   ├── elastic.py   # Elastic/OpenSearch
│   │   │       │   └── splunk.py    # Splunk (Phase 2)
│   │   │       ├── nl_query.py      # Natural language to query translation
│   │   │       ├── correlation.py   # Cross-index correlation engine
│   │   │       └── sigma.py         # Sigma rule generation
│   │   │
│   │   └── response/                # Python: automated response framework
│   │       ├── pyproject.toml
│   │       └── src/
│   │           ├── __init__.py
│   │           ├── taxonomy.py      # Response classification (auto/fast/full)
│   │           ├── actions/         # Per-integration response actions
│   │           ├── approval.py      # Approval gate logic
│   │           └── rollback.py      # Rollback tracking
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   PILLAR 3: GOVERN
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
│   ├── govern/
│   │   ├── shadow-ai/               # Python: shadow AI discovery
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── traffic_analyzer.py   # Network traffic AI service detection
│   │   │       ├── dns_monitor.py        # DNS monitoring for AI domains
│   │   │       ├── saas_inventory.py     # SaaS app cross-reference
│   │   │       └── risk_scorer.py        # Shadow AI risk scoring
│   │   │
│   │   ├── mcp-proxy/               # Rust: MCP security interceptor proxy
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── main.rs
│   │   │       ├── interceptor.rs   # MCP message inspection
│   │   │       ├── policy.rs        # OPA/Rego policy evaluation
│   │   │       ├── threats.rs       # MCP threat detection (shadowing, rug pull)
│   │   │       └── tls.rs           # TLS enforcement
│   │   │
│   │   ├── agent-identity/          # Python: agent registry + behavioral baseline
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── registry.py      # Agent registration + identity management
│   │   │       ├── baseline.py      # Behavioral baselining
│   │   │       ├── drift.py         # Drift detection
│   │   │       └── intent.py        # Intent verification
│   │   │
│   │   └── ai-dlp/                  # Python: AI data loss prevention
│   │       ├── pyproject.toml
│   │       └── src/
│   │           ├── __init__.py
│   │           ├── inspector.py     # Data flow inspection
│   │           ├── detectors/       # PII, code, classification detectors
│   │           ├── actions.py       # Block / redact / alert
│   │           └── audit.py         # DLP audit logging
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   PILLAR 4: OBSERVE
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
│   ├── observe/
│   │   ├── compliance/              # Python: compliance reporting engine
│   │   │   ├── pyproject.toml
│   │   │   └── src/
│   │   │       ├── __init__.py
│   │   │       ├── frameworks/      # SOC2, ISO27001, NIST CSF, CIS
│   │   │       ├── evidence.py      # Evidence extraction from Engram
│   │   │       ├── mapper.py        # Control-to-evidence mapping
│   │   │       └── reports.py       # Report generation
│   │   │
│   │   └── insurance/               # Python: cyber insurance evidence packages
│   │       ├── pyproject.toml
│   │       └── src/
│   │           ├── __init__.py
│   │           ├── packages.py      # Evidence package assembly
│   │           └── trends.py        # Posture trend analysis
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   API GATEWAY + FRONTEND
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
│   └── api-gateway/                 # Python (FastAPI): unified API layer
│       ├── pyproject.toml
│       └── src/
│           ├── __init__.py
│           ├── main.py              # FastAPI application
│           ├── routers/
│           │   ├── discover.py
│           │   ├── defend.py
│           │   ├── govern.py
│           │   ├── observe.py
│           │   └── admin.py
│           ├── middleware/
│           │   ├── auth.py          # JWT + RBAC middleware
│           │   ├── tenant.py        # Multi-tenant context
│           │   └── audit.py         # Request audit logging
│           └── websocket/
│               └── realtime.py      # WebSocket hub for dashboard
│
├── frontend/
│   ├── dashboard/                   # React + D3.js: main dashboard
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── App.tsx
│   │       ├── views/
│   │       │   ├── NetworkMap/      # D3 force-directed graph
│   │       │   ├── AttackPaths/     # Attack path visualization
│   │       │   ├── ThreatHunt/      # Hunt findings feed
│   │       │   ├── AIGovernance/    # Shadow AI, agent activity
│   │       │   ├── Compliance/      # Compliance dashboards
│   │       │   └── Admin/           # Settings, integrations
│   │       ├── components/          # Shared UI components
│   │       ├── hooks/               # Custom React hooks
│   │       ├── stores/              # State management
│   │       └── api/                 # API client (generated from OpenAPI)
│   └── ui-library/                  # Shared component library
│       ├── package.json
│       └── src/
│
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│   DEPLOYMENT + TOOLING
│── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ─── ──
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.scanner       # Multi-stage Rust build
│   │   ├── Dockerfile.python        # Shared Python base image
│   │   ├── Dockerfile.frontend      # Nginx + React build
│   │   └── Dockerfile.mcp-proxy     # Multi-stage Rust build
│   ├── helm/
│   │   └── sentinel/                # Helm chart for full platform
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       ├── values-dev.yaml
│   │       ├── values-staging.yaml
│   │       └── templates/
│   ├── docker-compose.yml           # Local development environment
│   ├── docker-compose.test.yml      # Integration test environment
│   └── terraform/
│       ├── modules/
│       │   ├── eks/
│       │   ├── neo4j/
│       │   ├── clickhouse/
│       │   ├── kafka/
│       │   ├── postgres/
│       │   └── networking/
│       ├── environments/
│       │   ├── dev/
│       │   ├── staging/
│       │   └── production/
│       └── main.tf
│
├── tools/
│   ├── dev-setup.sh                 # One-command development environment setup
│   ├── generate-api-client.sh       # OpenAPI -> TypeScript client generation
│   └── seed-data/                   # Development seed data
│
└── tests/
    ├── integration/                 # Cross-service integration tests
    │   ├── test_discover_to_graph.py
    │   ├── test_graph_to_attack_paths.py
    │   ├── test_engram_capture.py
    │   └── conftest.py              # Shared fixtures (docker services)
    └── e2e/                         # End-to-end tests
        └── playwright/
```

### Key structural decisions

**Why a monorepo, not polyrepo:** With 7-9 engineers and tightly coupled pillars that
share a knowledge graph, event bus, and audit trail, a monorepo eliminates cross-repo
dependency coordination overhead. Atomic commits across the graph schema, event schemas,
and the services that use them are essential during rapid early development.

**Why separate Cargo workspace members from Python packages:** Rust and Python have
fundamentally different build, test, and dependency resolution toolchains. Mixing them
into the same directory creates confusion. The `crates/` directory hosts all Rust
workspace members. Python services each get their own `pyproject.toml` for isolated
virtual environments, but share a workspace root for cross-cutting tooling (linting,
formatting).

**Why `proto/` at the top level:** The protobuf definitions are the contract between
services. Placing them at the root makes them a first-class citizen that every service
depends on, and ensures they are version-controlled atomically with the services that
produce/consume them.

---

## 2. Dependency Analysis and Build Order

### 2.1 Pillar Dependency Graph

```
                    ┌──────────────────────────────────────┐
                    │        SHARED INFRASTRUCTURE          │
                    │                                       │
                    │  sentinel-common (types, config)      │
                    │  sentinel-events (Kafka schemas)      │
                    │  sentinel-graph  (Neo4j client)       │
                    │  sentinel-engram (reasoning capture)  │
                    │  sentinel-auth   (JWT, RBAC, tenant)  │
                    │  OPA/Rego base policies               │
                    │  Neo4j schema + constraints           │
                    │  PostgreSQL schema                    │
                    │  Kafka topic configuration            │
                    └──────────┬───────────────────────────┘
                               │
           ┌───────────────────┼──────────────────────┐
           │                   │                      │
           ▼                   ▼                      ▼
    ┌──────────────┐   ┌──────────────┐      ┌──────────────┐
    │   DISCOVER    │   │    GOVERN    │      │   OBSERVE    │
    │              │   │              │      │              │
    │ Scanner      │   │ Shadow AI    │      │ Compliance   │
    │ Cloud APIs   │   │ MCP Proxy    │      │ Insurance    │
    │ Config Audit │   │ Agent ID     │      │ Dashboard    │
    │ Vuln Corr.   │   │ AI DLP       │      │              │
    │ Graph Ingest │   │              │      │              │
    └──────┬───────┘   └──────┬───────┘      └──────┬───────┘
           │                   │                      │
           │    DISCOVER       │                      │
           │    populates      │  GOVERN needs        │  OBSERVE reads
           │    the graph      │  graph data for      │  from ALL other
           │    that DEFEND    │  agent context        │  pillars via
           │    traverses      │                      │  Engram + graph
           │                   │                      │
           └────────┬──────────┘                      │
                    │                                  │
                    ▼                                  │
             ┌──────────────┐                         │
             │    DEFEND     │                         │
             │              │                         │
             │ Attack Paths │◄────────────────────────┘
             │ Simulation   │   OBSERVE consumes
             │ Threat Hunt  │   reasoning from
             │ Response     │   DEFEND's actions
             └──────────────┘
```

### 2.2 Detailed inter-pillar dependencies

| Dependency | Direction | Nature | Coupling |
|---|---|---|---|
| DEFEND reads network topology | DISCOVER -> DEFEND | DEFEND **requires** a populated graph to compute attack paths | Hard dependency: DEFEND is useless without graph data |
| DEFEND reads vulnerability data | DISCOVER -> DEFEND | Attack path scoring uses CVE/EPSS data on graph nodes | Hard dependency: scoring accuracy depends on vuln data |
| GOVERN reads network context | DISCOVER -> GOVERN | Shadow AI discovery cross-references discovered assets | Soft dependency: GOVERN can operate without it but is less accurate |
| OBSERVE reads engram data | ALL -> OBSERVE | Every pillar writes engrams; OBSERVE queries them | Hard dependency: OBSERVE needs engram data to report on |
| OBSERVE reads graph state | DISCOVER -> OBSERVE | Compliance reports reference current posture from graph | Soft dependency: reports are richer with graph data |
| DEFEND triggers GOVERN checks | DEFEND -> GOVERN | Automated responses may need policy approval from OPA | Soft dependency: can be added incrementally |
| GOVERN feeds DISCOVER | GOVERN -> DISCOVER | Discovered AI tools/MCP servers become graph nodes | Soft dependency: enrichment, not blocking |
| All pillars write events | ALL -> Kafka -> ALL | Event-driven architecture allows loose coupling | The event bus decouples timing but couples on schema |

### 2.3 Recommended Build Order

The build order below respects hard dependencies and maximizes parallelism for a
7-9 person team.

```
WEEK  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
      ├──────────────┤
      │  PHASE 0:    │
      │  Foundation  │
      │              │
      │  - sentinel-common, sentinel-events, sentinel-auth
      │  - sentinel-engram core (adapt existing Engram IP)
      │  - sentinel-graph (Neo4j client + schema deploy)
      │  - Kafka topic setup, PostgreSQL schema
      │  - OPA/Rego base policy framework
      │  - API gateway shell (FastAPI + auth middleware)
      │  - Dashboard shell (React + auth + routing)
      │  - docker-compose local dev environment
      │  - CI/CD pipelines for all three languages
      │
                     ├──────────────────────────┤
                     │  PHASE 1: DISCOVER        │
                     │                           │
                     │  - Scanner daemon (Rust)  │
                     │  - Cloud connectors (AWS, Azure, GCP)
                     │  - Graph ingestor         │
                     │  - Config auditor (top 5) │
                     │  - Vuln correlator        │
                     │  - Dashboard: network map │
                     │                           │
                     │  PARALLEL: OBSERVE v0     │
                     │  - Engram integration into│
                     │    discovery agents       │
                     │  - Basic engram query API │
                     │                           │
                                                 ├──────────────────────────────────┤
                                                 │  PHASE 2: DEFEND                  │
                                                 │                                   │
                                                 │  - Attack path engine (Rust)      │
                                                 │  - Risk scoring                   │
                                                 │  - SIEM connector (Elastic)       │
                                                 │  - Hunt agents (3 playbooks)      │
                                                 │  - Simulation v1 (top 20 ATT&CK) │
                                                 │  - Dashboard: paths + hunt feed   │
                                                 │                                   │
                                                 │  PARALLEL: GOVERN v0              │
                                                 │  - MCP proxy (Rust, from AgentOps)│
                                                 │  - Shadow AI traffic analysis     │
                                                 │  - OPA policy library             │
                                                 │                                   │
                                                                                     ├──────────────┤
                                                                                     │  PHASE 3:    │
                                                                                     │  GOVERN +    │
                                                                                     │  OBSERVE     │
                                                                                     │  complete    │
                                                                                     │              │
                                                                                     │  - Agent ID  │
                                                                                     │  - AI DLP    │
                                                                                     │  - Compliance│
                                                                                     │  - Insurance │
                                                                                     │  - Response  │
                                                                                     │    framework │
```

**Critical path analysis:** The longest dependency chain is:

```
Shared infra (4 wk) -> DISCOVER (6 wk) -> DEFEND attack paths (4 wk)
Total: 14 weeks minimum before attack path demo is possible
```

**Recommendation to compress the timeline:** Start the attack path engine (Rust) in
Phase 1 using synthetic/seed graph data. This lets the Rust engineer build and test
the pathfinding algorithms while the graph is being populated by DISCOVER. Integration
testing with real data happens at the start of Phase 2 rather than being gated on
DISCOVER completion.

### 2.4 Shared infrastructure that MUST be built first

These items are on the critical path for every pillar. None of the four pillars can
make meaningful progress without them.

| Component | Blocks | Owner | Effort |
|---|---|---|---|
| `sentinel-common` (types, config, errors) | Everything | Rust engineer | 2-3 days |
| `sentinel-events` (Kafka client + event schemas) | All event-driven communication | Rust engineer | 1 week |
| `sentinel-graph` (Neo4j client + schema) | DISCOVER, DEFEND, OBSERVE | Rust + Python engineer | 1 week |
| `sentinel-engram` (adapted from existing Engram) | OBSERVE and all audit trails | Rust engineer | 1-2 weeks |
| `sentinel-auth` (JWT, RBAC, multi-tenant) | API gateway, all services | Full-stack engineer | 1 week |
| Neo4j schema + constraints | DISCOVER, DEFEND | Python engineer | 3-5 days |
| Kafka topic definitions | All pillars | DevOps | 2-3 days |
| PostgreSQL schema (app state) | API gateway, dashboard | Full-stack engineer | 3-5 days |
| OPA/Rego base policies | GOVERN, DEFEND response | Python engineer | 1 week |
| Docker-compose dev environment | All developers | DevOps | 3-5 days |
| CI pipelines (Rust + Python + JS) | All developers | DevOps | 3-5 days |

**Minimum viable shared infra delivery: 3-4 weeks with 3 engineers working in parallel.**

---

## 3. Critical Architectural Decisions

### ADR-001: Monorepo with Polyglot Workspaces

**Status:** Proposed

**Context:** Sentinel spans three languages (Rust, Python, TypeScript) and four
product pillars with shared data schemas, event contracts, and infrastructure. The
team is 7-9 engineers. We need to decide between a monorepo and a polyrepo approach.

**Decision:** Use a single monorepo with language-specific workspace tooling:
- Cargo workspace for Rust crates
- uv/hatch workspace for Python packages
- pnpm workspace for TypeScript packages

**Consequences:**
- Easier: Atomic cross-service changes, shared CI, unified code review, single version of truth for schemas
- Harder: Build times grow with repo size, CI must be selective (only build what changed), tooling must handle three language ecosystems

**Alternatives Considered:**
- Polyrepo per pillar: rejected because the tight coupling between pillars (shared graph, shared events, shared engram) would create constant cross-repo coordination overhead for a small team
- Polyrepo per language: rejected because a "Rust services" repo and "Python services" repo would split features across repos, making it harder to reason about a pillar holistically

---

### ADR-002: Event Backbone — Kafka vs. Alternatives

**Status:** Proposed

**Context:** All four pillars need to communicate asynchronously. Discovery events
must flow to the graph ingestor. Threat findings must flow to the dashboard. Engram
sessions must be recorded. We need a reliable, ordered event stream.

**Decision:** Use Apache Kafka (or Redpanda as a cost-effective drop-in replacement
for early stages) as the central event backbone.

**Consequences:**
- Easier: Proven at scale, excellent Rust client (rdkafka), excellent Python client (confluent-kafka-python), natural fit for event sourcing
- Harder: Operational complexity (ZooKeeper or KRaft), resource overhead for small deployments

**Alternatives Considered:**
- NATS JetStream: simpler operationally, but weaker ecosystem for exactly-once semantics and less proven at enterprise scale for audit-critical workloads
- RabbitMQ: good for task queues but weaker for event streaming / log-style consumption
- Redis Streams: insufficient durability guarantees for an audit-trail-critical system
- Direct gRPC: too tightly coupled; would create cascading failures

**Key topic design:**

| Topic | Producer | Consumers | Partitioning |
|---|---|---|---|
| `sentinel.discovery.assets` | Scanner, Cloud connectors | Graph ingestor, Dashboard | By tenant_id |
| `sentinel.discovery.vulns` | Vuln correlator | Graph ingestor, Dashboard | By tenant_id |
| `sentinel.defend.findings` | Hunt agents, Simulation | Dashboard, Response engine | By tenant_id |
| `sentinel.defend.responses` | Response engine | Dashboard, Engram | By tenant_id |
| `sentinel.govern.events` | Shadow AI, MCP proxy, DLP | Dashboard, Engram | By tenant_id |
| `sentinel.engram.sessions` | All pillars | Engram storage, Compliance | By session_id |

---

### ADR-003: Neo4j as Sole Graph Store vs. Hybrid

**Status:** Proposed

**Context:** The plan specifies Neo4j for the knowledge graph. Neo4j is well-proven
for property graph queries, but has known limitations for high-throughput analytical
workloads and very large graph computations. The attack path calculator needs to
perform intensive graph traversals.

**Decision:** Use Neo4j as the primary graph database for topology storage and
standard Cypher queries. Use a Rust in-memory graph representation (petgraph or
custom adjacency list) for the attack path computation engine, populated by
periodic snapshots from Neo4j.

**Consequences:**
- Easier: Neo4j handles CRUD, schema enforcement, and ad-hoc Cypher queries well. Rust in-memory graph avoids Neo4j query planner overhead for pathfinding.
- Harder: Two representations of the graph must be kept in sync. Snapshot staleness must be managed.

**Rationale:** Neo4j's Cypher query planner is not designed for exhaustive all-paths
enumeration on graphs with thousands of nodes and complex edge weights. Benchmarks
from similar systems (e.g., BloodHound CE) show that dumping the graph to an
in-memory representation and running Dijkstra/BFS/DFS in Rust or Go is 10-100x
faster for pathfinding workloads. Neo4j remains the source of truth; the Rust engine
is a read-only projection optimized for computation.

**Alternatives Considered:**
- Neo4j only (Cypher for everything): rejected due to performance concerns for all-paths enumeration
- Neo4j GDS (Graph Data Science) plugin: viable for simpler algorithms but restrictive licensing (not included in Community Edition) and limited customization for weighted multi-hop path scoring
- Apache AGE (PostgreSQL extension): less mature, smaller ecosystem, would consolidate with PostgreSQL but at the cost of graph query expressiveness
- TigerGraph: better for analytical graph workloads but much higher operational complexity and cost, smaller talent pool

---

### ADR-004: Rust-Python Boundary Definition

**Status:** Proposed

**Context:** The system uses both Rust and Python. We need a clear, enforceable rule
for which language to use where, to prevent ambiguity and ensure the team can predict
where code lives.

**Decision:** Apply the following rule:

| Use Rust when... | Use Python when... |
|---|---|
| The component is on the data plane (handles every packet/event) | The component is on the control plane (orchestrates, configures) |
| Latency matters (sub-millisecond response required) | LLM/AI integration is the primary purpose |
| CPU-bound computation (pathfinding, hashing, scanning) | Cloud API integration (boto3, azure-mgmt) |
| The component is a long-running daemon | Rapid prototyping / iteration speed matters |
| Memory safety is critical (security-sensitive parsing) | The ecosystem is Python-dominated (ML, NLP) |

Specifically:
- **Rust:** Scanner daemon, MCP proxy, attack path engine, Engram core
- **Python:** Cloud connectors, agent orchestration (LangGraph), SIEM connectors, config auditor, vuln correlator, compliance reporting, API gateway

**Inter-language communication:** Rust services expose gRPC APIs consumed by Python.
No PyO3/FFI bindings in v1 -- the complexity is not justified until profiling proves
that gRPC latency is a bottleneck (unlikely for control-plane calls).

**Consequences:**
- Easier: Clear ownership, no ambiguity about where new code goes, Rust engineers and Python engineers can work independently
- Harder: gRPC adds serialization overhead vs. in-process calls; debugging spans two processes

**Alternatives Considered:**
- All Python with Rust only for Engram: rejected because scanner performance and MCP proxy latency requirements strongly favor Rust
- PyO3 bindings to call Rust from Python: rejected for v1 due to build complexity and debugging difficulty; can be introduced later for specific hot paths

---

### ADR-005: Engram Storage Model

**Status:** Proposed

**Context:** Engram stores reasoning sessions as Git objects with BLAKE3 hashing.
This is existing IP that needs to be adapted for Sentinel's multi-tenant,
high-throughput environment. Key questions: (a) where do the Git repositories
live, (b) how do we handle multi-tenancy, and (c) what is the query model.

**Decision:**

1. **Storage:** Each tenant gets a dedicated bare Git repository stored in object
   storage (S3) with a local cache layer. The Git object format is preserved for
   tamper evidence, but the repositories are NOT served via Git protocol -- they
   are accessed via the Engram library API.

2. **Multi-tenancy:** Tenant isolation at the repository level. Tenant A's engrams
   are in a completely separate repository from Tenant B's. No shared refs.

3. **Indexing:** A secondary index in ClickHouse stores engram metadata (session_id,
   tenant_id, timestamp, pillar, agent_id, outcome, tags) for fast querying. The
   Git objects are the source of truth; ClickHouse is a materialized projection
   for search and analytics.

4. **Integrity:** BLAKE3 content addressing provides tamper evidence. Periodic
   integrity verification jobs walk the Git object graph and verify hashes. An
   independent audit endpoint lets external auditors verify integrity.

**Consequences:**
- Easier: Per-tenant repos give strong isolation and easy data deletion (right to erasure). Git format is well-understood and verifiable by standard tools. ClickHouse index enables fast search without scanning Git objects.
- Harder: Managing thousands of Git repos at scale requires careful file handle and storage management. The secondary index must be kept consistent with the Git objects.

**Alternatives Considered:**
- Single shared Git repository with tenant prefixes in refs: rejected due to blast radius (corruption affects all tenants) and data isolation concerns
- Abandon Git format, use ClickHouse directly: rejected because Git's content-addressed storage is the tamper-evidence mechanism, which is a core differentiator
- SQLite per tenant: simpler but loses the Git tooling compatibility and the BLAKE3 content-addressed integrity model

---

### ADR-006: Multi-Tenancy Model

**Status:** Proposed

**Context:** Enterprise SaaS requires multi-tenancy. We need to decide between
shared infrastructure with logical isolation vs. dedicated infrastructure per tenant.

**Decision:** Logical multi-tenancy with tenant-scoped data:
- PostgreSQL: row-level security (RLS) with `tenant_id` column on every table
- Neo4j: `tenant_id` property on every node; all queries include tenant filter
  (enforced at the `sentinel-graph` client level, not by convention)
- Kafka: partition by `tenant_id`; consumer groups are tenant-aware
- ClickHouse: `tenant_id` column, used as partition key
- Engram: separate Git repository per tenant (physical isolation for audit data)
- Kubernetes: shared cluster, namespace-per-environment (not per-tenant)

For the highest-tier enterprise customers who require dedicated infrastructure,
offer dedicated Neo4j and Kafka instances deployed via Terraform modules.

**Consequences:**
- Easier: Lower infrastructure cost, simpler deployment, faster onboarding
- Harder: Must rigorously enforce tenant isolation in every query; a missing WHERE clause is a data leak. Neo4j lacks native RLS, so isolation must be enforced at the application layer.

**Risk mitigation:** The `sentinel-graph` crate MUST enforce tenant context on every
query. No raw Cypher queries bypass this layer. Integration tests MUST include
cross-tenant isolation verification.

---

### ADR-007: API Architecture — Gateway Pattern

**Status:** Proposed

**Context:** The platform has multiple backend services (Rust and Python) that need
to be exposed to the frontend dashboard. We need to decide how the frontend
communicates with backend services.

**Decision:** A single Python (FastAPI) API gateway that:
- Handles authentication, authorization, and tenant context extraction
- Routes requests to backend services via gRPC (for Rust services) and direct
  Python imports (for co-located Python services)
- Provides a unified REST API for the frontend (OpenAPI spec auto-generated)
- Provides WebSocket endpoints for real-time dashboard updates
- Serves as the only externally-exposed HTTP surface (all other services are
  cluster-internal)

**Consequences:**
- Easier: Single auth enforcement point, single API contract for frontend, centralized rate limiting and audit logging
- Harder: Gateway is a single point of failure (mitigated by horizontal scaling); adds latency for Rust service calls (one additional network hop)

**Alternatives Considered:**
- GraphQL gateway: more flexible for frontend queries but adds schema complexity and is harder to secure (query depth attacks)
- Direct service-to-frontend: rejected because it would require auth enforcement in every service and expose internal service topology
- Envoy/Kong gateway: viable for routing but still needs a custom auth layer; adds operational complexity for a small team

---

## 4. Technical Risk Assessment

### 4.1 Risk Matrix

| # | Risk | Likelihood | Impact | Severity | Mitigation |
|---|---|---|---|---|---|
| R1 | Neo4j performance degrades at scale with multi-tenant queries | Medium | High | **High** | ADR-003 (Rust in-memory graph for pathfinding); tenant-specific indexes; load test early with synthetic data at 10x expected scale |
| R2 | Rust-Python integration friction slows development | Medium | Medium | **Medium** | ADR-004 (clear boundary); invest in gRPC codegen and shared proto definitions; integration tests in CI |
| R3 | Engram Git-based storage hits throughput ceiling | Medium | High | **High** | Benchmark early: target 1000 engram writes/sec per tenant. If Git object creation is the bottleneck, consider batching writes. ClickHouse index absorbs read load. |
| R4 | LLM reliability for security-critical decisions | High | High | **Critical** | NEVER auto-execute LLM recommendations without policy checks. OPA/Rego gates on all automated responses. Engram captures LLM reasoning for post-hoc review. Human-in-the-loop for High/Critical actions. |
| R5 | Kafka operational complexity for small team | Medium | Medium | **Medium** | Start with Redpanda (Kafka-compatible, single binary, no ZooKeeper). Migrate to Confluent Cloud when revenue justifies it. |
| R6 | Neo4j licensing costs at scale | Medium | Medium | **Medium** | Neo4j Community Edition is AGPL -- acceptable if Sentinel is SaaS (not distributed). If on-prem deployment is needed, budget for Enterprise license or evaluate Memgraph (Bolt-compatible, permissive license). |
| R7 | Attack path computation is NP-hard for large graphs | Medium | High | **High** | Bound computation: max path length, max paths per source-target pair, timeout per computation. Use heuristics (A* with admissible heuristic) rather than exhaustive enumeration for large graphs. Cache results aggressively. |
| R8 | Multi-tenant data isolation failure in Neo4j | Low | Critical | **High** | Enforce tenant context at the `sentinel-graph` crate level. Zero raw Cypher queries bypass this. Automated cross-tenant penetration tests in CI. Consider Neo4j Fabric for physical tenant isolation if customer demands it. |
| R9 | Scope creep across four pillars delays all deliveries | High | High | **Critical** | Strict phase gating. DISCOVER must reach MVP before significant DEFEND investment. Resist the temptation to build all four pillars simultaneously. Each phase has a demo-able milestone. |
| R10 | Security domain expertise gap (no red teamer on team) | High | High | **Critical** | Hire before Phase 2 (DEFEND). Without this person, adversarial simulation and threat hunting playbooks will lack credibility with enterprise buyers. This is called out in the plan and is non-negotiable. |
| R11 | LangGraph / agent framework maturity | Medium | Medium | **Medium** | LangGraph is evolving rapidly. Pin versions aggressively. Abstract the orchestration layer behind an interface so the framework can be swapped. Keep agent logic in pure Python functions that are framework-agnostic. |
| R12 | ClickHouse + Neo4j + PostgreSQL + Kafka = high ops burden | Medium | Medium | **Medium** | Use managed services (Neo4j Aura, ClickHouse Cloud, Confluent Cloud, RDS) for production. Self-host only in development. Budget for managed services from day one. |

### 4.2 Technology-Specific Risk Deep Dives

**Neo4j risk (R1, R6, R8):**
Neo4j is the right choice for this domain -- property graphs are the natural data
model for network topology and attack paths. However, three risks compound:
- Multi-tenant queries with `WHERE n.tenant_id = $tid` on every query add overhead
- Community Edition lacks role-based access control, encryption at rest, and clustering
- AGPL licensing constrains distribution (fine for SaaS, problematic for on-prem)

Mitigation path: Start with Community for development, plan for Enterprise (or Aura
Professional) for production. Evaluate Memgraph as a backup -- it is Bolt/Cypher
compatible and has an enterprise-friendly license.

**Engram risk (R3):**
The Git object model is elegant for tamper evidence but has characteristics that
may not suit high-throughput writes:
- Creating Git objects involves filesystem operations (or custom object store)
- BLAKE3 hashing is fast (~1 GB/s) but the bottleneck is the storage layer, not hashing
- Git's pack file format is optimized for infrequent packing, not continuous writes

Mitigation path: Benchmark with a synthetic workload (1000 sessions/sec, each with
10-50 reasoning steps). If filesystem I/O is the bottleneck, implement a write-ahead
log that batches Git object creation. The ClickHouse index absorbs all read queries,
so Git repository read performance is not on the hot path.

**LLM reliability risk (R4):**
This is the highest-impact risk because LLM-powered agents making security decisions
is inherently probabilistic. A hallucinated threat finding or a missed real threat
both have serious consequences.

Mitigation architecture:
```
LLM Agent Decision
       │
       ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Engram Record │────>│ OPA Policy   │────>│ Confidence   │
│ (reasoning    │     │ Gate         │     │ Threshold    │
│  captured)    │     │ (authorized?)│     │ Gate         │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                    ┌─────────────┼─────────────┐
                                    │             │             │
                                    ▼             ▼             ▼
                              Auto-execute   Fast-track    Full review
                              (low risk,     (1-click      (human
                               high conf)    approval)     sign-off)
```

Every LLM decision passes through three gates before execution. No shortcuts.

---

## 5. Additional Recommendations

### 5.1 Schema-First Development

Before writing any service code, define and freeze these schemas:

1. **Neo4j graph schema** -- all node labels, relationship types, and their properties.
   This is the contract between DISCOVER (writes) and DEFEND (reads). Changes here
   cascade to both pillars.

2. **Kafka event schemas** -- use Avro or Protobuf with a schema registry. Do not use
   JSON without schema enforcement. Schema evolution (backward/forward compatibility)
   must be planned from day one.

3. **gRPC service definitions** -- define the proto files for Rust service APIs before
   implementing the services. This lets Python consumers start coding against stubs.

4. **PostgreSQL schema** -- define the application state model (tenants, users, roles,
   integrations, scan schedules, approval workflows).

### 5.2 Observability from Day One

The platform monitors customers' security -- it must monitor itself rigorously.

- **Tracing:** OpenTelemetry across all services (Rust: `tracing` + `opentelemetry-rust`; Python: `opentelemetry-python`). Distributed trace IDs propagated through Kafka message headers.
- **Metrics:** Prometheus exposition from all services. Key metrics: graph query latency, engram write throughput, scan completion times, agent decision latency.
- **Logging:** Structured JSON logging everywhere. Correlation IDs linking log entries to traces.
- **Alerting:** PagerDuty / OpsGenie integration for production. Alert on: graph ingestion lag, engram write failures, Kafka consumer lag, attack path computation timeouts.

### 5.3 Development Environment

Invest heavily in the local development experience. A `docker-compose.yml` that
brings up Neo4j, PostgreSQL, ClickHouse, Redpanda (Kafka-compatible), and an OPA
server with a single command. Seed data that populates a realistic but synthetic
network graph for development. Without this, every developer wastes hours setting
up dependencies.

Target: `make dev-up` brings up all infrastructure. `make seed` populates test data.
Any engineer can be productive within 30 minutes of cloning the repo.

### 5.4 Testing Strategy

| Level | Scope | Tooling | Runs |
|---|---|---|---|
| Unit (Rust) | Individual functions, modules | `cargo test` | On every commit |
| Unit (Python) | Individual functions, classes | `pytest` | On every commit |
| Unit (Frontend) | Components, hooks | `vitest` + React Testing Library | On every commit |
| Integration | Cross-service with real databases | `pytest` + docker-compose | On PR merge |
| Contract | gRPC proto compatibility | `buf breaking` | On proto file changes |
| E2E | Full user workflows through UI | Playwright | Nightly / pre-release |
| Security | Dependency scanning, SAST | Trivy, Semgrep | On every commit |
| Load | Performance under expected load | k6 or Locust | Weekly / pre-release |

---

## Summary of Recommendations

**Immediate actions (before any code is written):**

1. Finalize and document the Neo4j graph schema (node types, edge types, properties, constraints). This is the single most important shared artifact.

2. Define Kafka event schemas using Protobuf with a schema registry. Publish v0.1.0 of each event schema.

3. Set up the monorepo structure with CI pipelines for all three languages. Make `main` branch protection require passing CI.

4. Build the docker-compose development environment with Neo4j, PostgreSQL, ClickHouse, Redpanda, and OPA.

5. Adapt the existing Engram library into `sentinel-engram` crate. This is on the critical path for the audit trail differentiator.

6. Hire the security domain expert (red teamer / pen tester). This person must be onboard before Phase 2 starts.

**Decisions that can be deferred:**

- ClickHouse schema optimization (can evolve as query patterns emerge)
- Frontend state management approach (can start with simple React context)
- SIEM connector abstraction (only Elastic in Phase 2; abstract when adding Splunk)
- On-premises deployment model (SaaS-first; on-prem is a Phase 4+ concern)
- LLM provider selection (abstract behind interface; start with Claude API)

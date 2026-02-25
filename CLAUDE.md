# Sentinel — Project Conventions

## What is This Project?
Sentinel is an enterprise autonomous cyber defense platform with 4 pillars:
- **DISCOVER** — Network digital twin (Rust scanner → Neo4j graph)
- **DEFEND** — Threat hunting + attack path simulation (Rust pathfinder + Python LLM agents)
- **GOVERN** — AI agent governance, MCP security, shadow AI discovery
- **OBSERVE** — Engram audit trail, compliance reporting

## Key Documents
- `plan.md` — Full product/business plan
- `BUILD_PLAN.md` — Engineering build plan with tasks, dependencies, acceptance criteria
- `docs/architecture/001-architectural-analysis.md` — Detailed architecture analysis
- `docs/architecture/diagrams/` — Mermaid diagrams (dependency graph, build order, C4)

## Repository Structure
- `crates/` — Rust workspace (sentinel-core, sentinel-engram, sentinel-discover, sentinel-graph, sentinel-pathfind)
- `python/` — Python packages (sentinel-api, sentinel-agents, sentinel-connectors, sentinel-policy)
- `web/` — React + TypeScript frontend
- `schemas/` — Database schemas (Neo4j, PostgreSQL, ClickHouse, events)
- `policies/` — OPA/Rego policy files
- `deploy/` — Kubernetes, Helm, Terraform configs

## Coding Standards

### Rust
- Edition 2021, MSRV 1.75+
- Use `thiserror` for error types, `anyhow` for application errors
- All public APIs documented with `///` doc comments
- Run `cargo clippy` with no warnings
- Tests in same file (`#[cfg(test)]` module) for unit tests, `tests/` dir for integration

### Python
- Python 3.12+, use `uv` for package management
- Type hints on all function signatures (enforce with mypy strict mode)
- Pydantic v2 for data models
- FastAPI for API endpoints
- `ruff` for linting and formatting
- pytest for testing

### TypeScript/React
- TypeScript strict mode
- Vite for build tooling
- Vitest for testing
- Functional components with hooks only (no class components)
- `@tanstack/react-query` for server state

### General
- Every service writes structured JSON logs
- Every autonomous action creates an Engram session
- All database access goes through the API layer (Python doesn't query Neo4j directly)
- Multi-tenant: every query includes tenant_id, enforced at the data layer
- Secrets come from environment variables, never hardcoded

## Build Commands
```bash
make build          # Build all (Rust + Python + web)
make test           # Run all tests
make lint           # Lint all languages
make docker-up      # Start local infrastructure
make docker-down    # Stop local infrastructure
```

## Working on Tasks
- Check `BUILD_PLAN.md` → Progress Tracker for current status
- Each task has dependencies — verify prerequisites are complete before starting
- Update the Progress Tracker when starting (`[~]`) and completing (`[x]`) tasks
- When a task is done, ensure acceptance criteria are all checked off

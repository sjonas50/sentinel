# Intent

lets clone this repo: git@github.com:sjonas50/sentinel.git

## Interpreted Goal

Build the sentinel security platform by systematically implementing the connector and vulnerability analysis subsystems. The strategy was to: (1) expand the base connector framework with cloud discovery for major providers, (2) add identity-specific connectors for deeper user/group/policy enumeration, (3) create a vulnerability correlation engine that enriches discovered services with threat intelligence from multiple sources, and (4) wire everything into the API layer with proper caching and rate limiting.

## Summary

Implemented Tasks 1.2-1.4: added cloud discovery connectors (AWS/Azure/GCP), identity connectors (Entra ID/Okta), and vulnerability correlation engine (NVD/EPSS/KEV integration). All 205+ tests passing with clean linting.

## Dead Ends

- **Using `with *patches` syntax to combine multiple mock patches in Python 3.12**: Syntax not supported; switched to contextlib.ExitStack and explicit with statements instead
- **MockAsyncClient route matching using simple substring matching (if key in url)**: Too ambiguous - '/api/v1/users' would match '/api/v1/users/id/factors'; switched to exact URL match with longest-match-first fallback
- **Moving VulnSeverity enum to TYPE_CHECKING block for lint compliance**: FastAPI needs it at runtime for query parameter validation; reverted to regular import
- **Using plain async generators for Neo4j driver mock iteration**: Protocol requires __aiter__ to be a proper method with self; implemented _AsyncRecordIter class instead

## Decisions

- **Organized cloud/identity/vulnerability code into separate service modules (cloud/, identity/, services/)**: Clear separation of concerns - cloud infrastructure discovery, identity/access management, and threat intelligence each have their own domain logic and can be evolved independently
- **Added _make_edge helper to BaseConnector to standardize edge creation across all connectors**: Eliminates repetitive edge creation logic (UUID generation, relationship type lookup) and ensures consistency in how relationships are represented in the graph
- **Implemented TTL-based in-memory cache for KEV catalog (24h default)**: KEV data changes infrequently but is queried frequently; caching reduces external API calls and improves response latency
- **Batched EPSS queries into groups of 30 CPEs per request**: EPSS API has implicit limits on batch size; batching handles arbitrary numbers of CVEs efficiently while respecting API constraints
- **Implemented dual rate limiting for NVD (5 req/30s unauthenticated, 50 req/30s with API key)**: NVD's public API has strict rate limits; the client enforces them locally to avoid 403 responses and provide predictable performance
- **Correlation engine queries services by tenant, then by region, enriching with vulnerability data**: Multi-tenant isolation and regional grouping helps with scaling and allows future optimizations (regional cache, locality-aware scoring)

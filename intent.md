# Intent

lets clone this repo: git@github.com:sjonas50/sentinel.git

## Interpreted Goal

The user wanted to systematically progress through the project's task list, starting with cloud discovery connectors to collect infrastructure data across multiple cloud providers, then adding identity connectors to gather identity and access management data, and finally building a vulnerability correlation engine to enrich discovered services with vulnerability intelligence. The strategy was to leverage the existing connector framework pattern and implement each task as a complete, tested module with proper error handling and integration into the API layer.

## Summary

Successfully cloned the sentinel repository and completed Tasks 1.2, 1.3, and 1.4 by implementing cloud discovery connectors (AWS/Azure/GCP), identity connectors (Entra ID/Okta), and a vulnerability correlation engine with NVD/EPSS/KEV integration.

## Dead Ends

- **Using SSH clone with git@github.com URL**: SSH key authentication not configured; switched to HTTPS clone instead
- **Putting VulnSeverity in TYPE_CHECKING block in vulnerability routes**: FastAPI needs the enum at runtime for query parameter validation; moved back to regular imports
- **Using google-cloud-sqladmin package for GCP Cloud SQL discovery**: Package doesn't exist on PyPI; switched to google-api-python-client with googleapiclient.discovery
- **Using `with *patches` syntax in async test fixtures**: Python 3.12 doesn't support unpacking with contextmanager; rewrote using contextlib.ExitStack
- **Simple route matching in MockAsyncClient using `if key in url`**: Prefix matching caused incorrect routes to match (e.g., /api/v1/users matched /api/v1/users/user-1/factors); refactored to exact match

## Decisions

- **Expanded SyncResult with applications, groups, services fields; added _make_edge helper to BaseConnector**: Provides consistent interface for all connectors to create relationship edges (BELONGS_TO_SUBNET, MEMBER_OF, etc.) without duplicating edge creation logic
- **Created separate identity connectors (Entra ID, Okta) rather than extending cloud connectors**: Identity systems have different discovery patterns and require dedicated API clients; separating concerns improves maintainability and allows specialized credential handling
- **Implemented external service clients (KEV, EPSS, NVD) with mocking-friendly dependency injection patterns**: Allows easy testing without external API calls while keeping code flexible for real API integration; supports rate limiting and batch processing internally
- **Used async/await patterns throughout (AsyncClient, async generators, async iterators)**: Matches FastAPI's async runtime and enables concurrent API calls to multiple external services without blocking
- **Organized services as a new sentinel_api/services package with separate client files**: Separates business logic (services) from HTTP routing concerns; makes the architecture scalable for adding more service clients
- **Added optional dependency groups (aws, azure, gcp, okta) in pyproject.toml**: Users can install only the connectors they need; reduces dependency bloat for minimal deployments

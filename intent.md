# Intent

lets clone this repo: git@github.com:sjonas50/sentinel.git

## Interpreted Goal

Build out core Sentinel infrastructure components following the BUILD_PLAN roadmap: expand cloud discovery to multi-cloud with full resource discovery, add dedicated identity provider connectors for user/group enumeration, and create a vulnerability enrichment pipeline that correlates cloud services with CVEs. Strategy involved implementing connector framework extensions, creating new service layer clients for external APIs, and wiring everything into the existing FastAPI backend.

## Summary

Implemented and deployed three major features for the Sentinel security project: Cloud Discovery Connectors (AWS/Azure/GCP), Identity Connectors (Entra ID/Okta), and a Vulnerability Correlation Engine with NVD/EPSS/KEV integration. All changes tested and pushed to main branch.

## Dead Ends

- **Using SSH key for git clone**: SSH key not configured; switched to HTTPS clone which succeeded
- **Using `google-cloud-sqladmin` package for GCP Cloud SQL discovery**: Package doesn't exist on PyPI; switched to `google-api-python-client` with googleapiclient.discovery
- **Using `with *patches` syntax for multiple context managers in Okta tests**: Not supported in Python 3.12; rewrote using ExitStack pattern
- **Moving `VulnSeverity` to TYPE_CHECKING block in vulnerability routes**: FastAPI needs enum at runtime for query parameter validation; reverted to main imports

## Decisions

- **Expanded SyncResult dataclass with applications, groups, services fields and added _make_edge helper to BaseConnector**: Unified way to handle different asset types across all connectors and create relationships; reduces code duplication
- **Implemented parallel discovery methods in cloud connectors (S3, RDS, Lambda, ECS, EKS for AWS; Storage, SQL, AKS for Azure; Compute, GKE, Cloud SQL for GCP)**: Comprehensive resource discovery maximizes security coverage; cloud-specific services critical for finding exposed resources
- **Created separate identity/ package with dedicated Entra ID and Okta connectors instead of integrating into cloud connectors**: Identity providers have different APIs and require different discovery patterns (users, groups, roles, MFA status); separation of concerns enables specialized logic per IdP
- **Implemented vulnerability correlation engine with three independent clients (KEV, EPSS, NVD) that work together**: Each data source serves different purpose: KEV for active exploits, EPSS for likelihood, NVD for detailed metadata; independent clients allow flexible composition
- **Added caching to KEV client (in-memory with TTL) but made NVD/EPSS calls live**: KEV catalog updates infrequently (good for caching); NVD/EPSS need fresh data; separate strategies optimize performance vs freshness

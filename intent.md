# Intent

lets clone this repo: git@github.com:sjonas50/sentinel.git

## Interpreted Goal

The user wanted to systematically build out the Sentinel security platform by completing a series of interconnected tasks: first expanding cloud connectors to discover infrastructure across major providers, then adding identity/IdP connectors for user/group visibility, integrating vulnerability data from multiple sources, and finally building audit capabilities for cloud configuration compliance.

## Summary

Implemented cloud discovery connectors (AWS, Azure, GCP), identity connectors (Entra ID, Okta), vulnerability correlation engine (NVD/EPSS/KEV), and began planning a configuration auditor.

## Dead Ends

- **SSH clone with git@github.com URL**: SSH key not configured or recognized by GitHub; user requested HTTPS fallback instead
- **Using google-cloud-sqladmin package for GCP Cloud SQL discovery**: Package doesn't exist on PyPI; switched to google-api-python-client with googleapiclient.discovery
- **Using 'with *patches, ...' syntax for multiple mock patches in tests**: Not supported in Python 3.12; refactored to use contextlib.ExitStack instead

## Decisions

- **Structured cloud connectors by provider (aws.py, azure.py, gcp.py) with common BaseConnector framework**: Enables code reuse, consistent error handling, and easy addition of new providers while leveraging existing patterns from Task 0.10
- **Created separate identity/ package for dedicated IdP connectors (entra.py, okta.py) distinct from cloud connectors**: Identity systems have different data models and APIs than cloud infrastructure; separate package keeps concerns isolated
- **Implemented vuln correlation as a service layer (services/) with separate clients for KEV, EPSS, NVD**: Allows independent caching/rate-limiting per source, testability, and future extensibility to other vuln sources
- **Used async/await throughout (httpx.AsyncClient, async generators) for all external API calls**: Matches existing codebase patterns and enables concurrent requests without blocking
- **Added TTL-based in-memory caching for KEV catalog and EPSS scores**: Reduces load on external APIs while keeping data reasonably fresh; KEV updates weekly, EPSS scores are stable

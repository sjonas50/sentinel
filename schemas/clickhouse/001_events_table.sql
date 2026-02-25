-- ============================================================================
-- Sentinel — ClickHouse Event Analytics Schema
-- Migration 001: Events table
--
-- High-performance OLAP storage for security events. Partitioned by month,
-- ordered by (tenant_id, timestamp) for fast tenant-scoped time-range queries.
-- ============================================================================

-- ── Events Table ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS events (
    -- Identity
    id              UUID,
    tenant_id       UUID,

    -- Timing
    timestamp       DateTime64(3, 'UTC'),

    -- Classification
    source          Enum8(
                        'discover' = 1,
                        'defend'   = 2,
                        'govern'   = 3,
                        'observe'  = 4,
                        'api'      = 5
                    ),
    event_type      LowCardinality(String),

    -- Payload
    severity        Enum8(
                        'critical' = 1,
                        'high'     = 2,
                        'medium'   = 3,
                        'low'      = 4,
                        'info'     = 5
                    ) DEFAULT 'info',
    node_id         Nullable(UUID),
    node_type       LowCardinality(Nullable(String)),
    edge_type       LowCardinality(Nullable(String)),
    cve_id          Nullable(String),
    cvss_score      Nullable(Float64),
    risk_score      Nullable(Float64),
    title           Nullable(String),
    description     Nullable(String),

    -- Metadata
    agent_id        Nullable(String),
    scan_id         Nullable(UUID),
    engram_session  Nullable(UUID),
    payload_json    String DEFAULT '{}'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_type)
TTL toDateTime(timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ── Materialized Views for Common Queries ──────────────────────────

-- Event counts by type per hour (for dashboard charts)
CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_counts
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, source, event_type)
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    source,
    event_type,
    severity,
    count() AS event_count
FROM events
GROUP BY tenant_id, hour, source, event_type, severity;

-- Vulnerability events aggregated per day (for trend charts)
CREATE MATERIALIZED VIEW IF NOT EXISTS vuln_daily_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, severity)
AS SELECT
    tenant_id,
    toDate(timestamp) AS day,
    severity,
    countIf(event_type = 'VulnerabilityFound') AS vulns_found,
    avgIf(cvss_score, cvss_score IS NOT NULL) AS avg_cvss,
    maxIf(cvss_score, cvss_score IS NOT NULL) AS max_cvss
FROM events
GROUP BY tenant_id, day, severity;

-- Scan performance tracking
CREATE MATERIALIZED VIEW IF NOT EXISTS scan_performance
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp)
AS SELECT
    tenant_id,
    timestamp,
    scan_id,
    event_type,
    JSONExtractInt(payload_json, 'nodes_found') AS nodes_found,
    JSONExtractInt(payload_json, 'nodes_updated') AS nodes_updated,
    JSONExtractInt(payload_json, 'nodes_stale') AS nodes_stale,
    JSONExtractInt(payload_json, 'duration_ms') AS duration_ms
FROM events
WHERE event_type = 'ScanCompleted';

#!/usr/bin/env bash
# ============================================================================
# Sentinel — Database Seed Script
#
# Applies all schema migrations to local development databases.
# Requires docker-compose services to be running (make docker-up).
# Uses docker exec to run queries inside containers — no local DB CLI needed.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCHEMAS_DIR="$PROJECT_DIR/schemas"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Wait for healthy service ─────────────────────────────────────

wait_for_healthy() {
    local container="$1"
    local max_wait="${2:-60}"
    local elapsed=0

    info "Waiting for $container to be healthy..."
    while [ $elapsed -lt "$max_wait" ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_found")
        if [ "$status" = "healthy" ]; then
            info "$container is healthy."
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    error "$container did not become healthy within ${max_wait}s (status: $status)"
    return 1
}

# ── PostgreSQL ──────────────────────────────────────────────────

apply_postgres() {
    wait_for_healthy sentinel-postgres

    info "Applying PostgreSQL schemas..."
    for migration in "$SCHEMAS_DIR"/postgres/*.sql; do
        info "  Applying $(basename "$migration")..."
        docker exec -i sentinel-postgres \
            psql -U sentinel -d sentinel --set ON_ERROR_STOP=1 \
            < "$migration"
    done
    info "PostgreSQL schemas applied."
}

# ── Neo4j ────────────────────────────────────────────────────────

apply_neo4j() {
    wait_for_healthy sentinel-neo4j

    info "Applying Neo4j schemas..."
    for migration in "$SCHEMAS_DIR"/neo4j/*.cypher; do
        info "  Applying $(basename "$migration")..."
        # cypher-shell inside the container reads from stdin
        docker exec -i sentinel-neo4j \
            cypher-shell -u neo4j -p sentinel-dev \
            < "$migration"
    done
    info "Neo4j schemas applied."
}

# ── ClickHouse ────────────────────────────────────────────────────

apply_clickhouse() {
    wait_for_healthy sentinel-clickhouse

    # Create the sentinel database if it doesn't exist
    info "Ensuring ClickHouse 'sentinel' database exists..."
    echo "CREATE DATABASE IF NOT EXISTS sentinel;" | \
        docker exec -i sentinel-clickhouse \
            clickhouse-client --user default

    info "Applying ClickHouse schemas..."
    for migration in "$SCHEMAS_DIR"/clickhouse/*.sql; do
        info "  Applying $(basename "$migration")..."
        docker exec -i sentinel-clickhouse \
            clickhouse-client --user default --database sentinel \
            < "$migration"
    done
    info "ClickHouse schemas applied."
}

# ── Main ─────────────────────────────────────────────────────────

main() {
    info "Sentinel Database Seed Script"
    info "=============================="

    case "${1:-all}" in
        postgres)   apply_postgres ;;
        neo4j)      apply_neo4j ;;
        clickhouse) apply_clickhouse ;;
        all)
            apply_postgres
            apply_neo4j
            apply_clickhouse
            ;;
        *)
            error "Unknown target: $1"
            echo "Usage: $0 [postgres|neo4j|clickhouse|all]"
            exit 1
            ;;
    esac

    info "Done!"
}

main "$@"

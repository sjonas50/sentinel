#!/usr/bin/env bash
# ============================================================================
# Sentinel — Database Seed Script
#
# Applies all schema migrations to local development databases.
# Requires docker-compose services to be running (make docker-up).
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

# ── Load env ────────────────────────────────────────────────────────

if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$PROJECT_DIR/.env"
    set +a
fi

POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-sentinel}"
POSTGRES_USER="${POSTGRES_USER:-sentinel}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-sentinel-dev}"

NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-sentinel-dev}"

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_DB="${CLICKHOUSE_DB:-sentinel}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

# ── PostgreSQL ──────────────────────────────────────────────────────

apply_postgres() {
    info "Applying PostgreSQL schemas..."

    for migration in "$SCHEMAS_DIR"/postgres/*.sql; do
        info "  Applying $(basename "$migration")..."
        PGPASSWORD="$POSTGRES_PASSWORD" psql \
            -h "$POSTGRES_HOST" \
            -p "$POSTGRES_PORT" \
            -U "$POSTGRES_USER" \
            -d "$POSTGRES_DB" \
            -f "$migration" \
            --set ON_ERROR_STOP=1
    done

    info "PostgreSQL schemas applied."
}

# ── Neo4j ───────────────────────────────────────────────────────────

apply_neo4j() {
    info "Applying Neo4j schemas..."

    for migration in "$SCHEMAS_DIR"/neo4j/*.cypher; do
        info "  Applying $(basename "$migration")..."
        cypher-shell \
            -a "$NEO4J_URI" \
            -u "$NEO4J_USER" \
            -p "$NEO4J_PASSWORD" \
            -f "$migration"
    done

    info "Neo4j schemas applied."
}

# ── ClickHouse ──────────────────────────────────────────────────────

apply_clickhouse() {
    info "Applying ClickHouse schemas..."

    for migration in "$SCHEMAS_DIR"/clickhouse/*.sql; do
        info "  Applying $(basename "$migration")..."
        if [ -n "$CLICKHOUSE_PASSWORD" ]; then
            clickhouse-client \
                --host "$CLICKHOUSE_HOST" \
                --port 9000 \
                --user "$CLICKHOUSE_USER" \
                --password "$CLICKHOUSE_PASSWORD" \
                --database "$CLICKHOUSE_DB" \
                --queries-file "$migration"
        else
            clickhouse-client \
                --host "$CLICKHOUSE_HOST" \
                --port 9000 \
                --user "$CLICKHOUSE_USER" \
                --database "$CLICKHOUSE_DB" \
                --queries-file "$migration"
        fi
    done

    info "ClickHouse schemas applied."
}

# ── Main ────────────────────────────────────────────────────────────

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

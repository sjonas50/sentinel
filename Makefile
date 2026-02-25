.PHONY: build test lint docker-up docker-down docker-clean seed clean

# ── Build ──────────────────────────────────────────────────────────
build: build-rust build-python build-web

build-rust:
	cargo build --workspace

build-python:
	cd python && uv sync --all-packages

build-web:
	cd web && npm install && npm run build

# ── Test ───────────────────────────────────────────────────────────
test: test-rust test-python test-web

test-rust:
	cargo test --workspace

test-python:
	cd python/sentinel-api && uv run pytest

test-web:
	cd web && npm run test

# ── Lint ───────────────────────────────────────────────────────────
lint: lint-rust lint-python lint-web

lint-rust:
	cargo clippy --workspace -- -D warnings
	cargo fmt --check

lint-python:
	cd python && uv run ruff check .
	cd python && uv run mypy sentinel-api/sentinel_api

lint-web:
	cd web && npm run lint

# ── Format ─────────────────────────────────────────────────────────
fmt:
	cargo fmt
	cd python && uv run ruff format .

# ── Infrastructure ─────────────────────────────────────────────────
docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-clean:
	docker compose down -v

seed:
	bash scripts/seed.sh

docker-fresh: docker-clean docker-up seed

# ── Clean ──────────────────────────────────────────────────────────
clean:
	cargo clean
	rm -rf web/dist web/node_modules
	find python -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

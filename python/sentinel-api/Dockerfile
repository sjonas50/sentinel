FROM python:3.11-slim AS base

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml ./
COPY sentinel_api/ sentinel_api/

# Install dependencies (production only)
RUN uv pip install --system --no-cache .

EXPOSE 8000

CMD ["uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

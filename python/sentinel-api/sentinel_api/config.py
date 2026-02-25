"""Application settings loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Sentinel API configuration.

    All settings can be overridden via environment variables
    prefixed with their section (e.g., POSTGRES_HOST, NEO4J_URI).
    """

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_log_level: str = "info"
    cors_origins: list[str] = ["http://localhost:5173"]

    # Auth
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "sentinel"
    postgres_user: str = "sentinel"
    postgres_password: str = "sentinel-dev"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "sentinel-dev"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Vulnerability Correlation
    nvd_api_key: str | None = None
    nvd_base_url: str = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds"
        "/known_exploited_vulnerabilities.json"
    )

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()

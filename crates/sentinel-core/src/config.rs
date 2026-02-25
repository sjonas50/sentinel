//! Configuration management for Sentinel services.
//!
//! Configuration is loaded from (in priority order):
//! 1. Environment variables (SENTINEL_ prefix)
//! 2. Config file (sentinel.toml)
//! 3. Defaults

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

/// Top-level configuration for a Sentinel service.
#[derive(Debug, Clone, Deserialize)]
pub struct SentinelConfig {
    pub api: ApiConfig,
    pub neo4j: Neo4jConfig,
    pub postgres: PostgresConfig,
    pub clickhouse: ClickhouseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub llm: LlmConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_host")]
    pub host: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Neo4jConfig {
    #[serde(default = "default_neo4j_uri")]
    pub uri: String,
    #[serde(default = "default_neo4j_user")]
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostgresConfig {
    #[serde(default = "default_pg_host")]
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    #[serde(default = "default_pg_db")]
    pub db: String,
    #[serde(default = "default_pg_user")]
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClickhouseConfig {
    #[serde(default = "default_ch_host")]
    pub host: String,
    #[serde(default = "default_ch_port")]
    pub port: u16,
    #[serde(default = "default_ch_db")]
    pub db: String,
    #[serde(default = "default_ch_user")]
    pub user: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    #[serde(default = "default_jwt_algorithm")]
    pub jwt_algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    #[serde(default = "default_llm_provider")]
    pub provider: String,
    pub api_key: Option<String>,
    pub model: Option<String>,
}

impl SentinelConfig {
    /// Load configuration from file + environment variables.
    ///
    /// Looks for `sentinel.toml` in the current directory, then overlays
    /// environment variables with the `SENTINEL_` prefix. Nested keys use
    /// `__` as separator (e.g., `SENTINEL_NEO4J__URI`).
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from("sentinel")
    }

    /// Load configuration from a named file prefix + environment variables.
    pub fn load_from(file_prefix: &str) -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name(file_prefix).required(false))
            .add_source(
                Environment::with_prefix("SENTINEL")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        config.try_deserialize()
    }
}

impl PostgresConfig {
    /// Build a connection string from the config fields.
    pub fn connection_string(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.db
        )
    }
}

// ── Defaults ──────────────────────────────────────────────────────

fn default_api_host() -> String {
    "0.0.0.0".to_string()
}
fn default_api_port() -> u16 {
    8000
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_neo4j_uri() -> String {
    "bolt://localhost:7687".to_string()
}
fn default_neo4j_user() -> String {
    "neo4j".to_string()
}
fn default_pg_host() -> String {
    "localhost".to_string()
}
fn default_pg_port() -> u16 {
    5432
}
fn default_pg_db() -> String {
    "sentinel".to_string()
}
fn default_pg_user() -> String {
    "sentinel".to_string()
}
fn default_ch_host() -> String {
    "localhost".to_string()
}
fn default_ch_port() -> u16 {
    8123
}
fn default_ch_db() -> String {
    "sentinel".to_string()
}
fn default_ch_user() -> String {
    "default".to_string()
}
fn default_redis_url() -> String {
    "redis://localhost:6379".to_string()
}
fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}
fn default_llm_provider() -> String {
    "anthropic".to_string()
}

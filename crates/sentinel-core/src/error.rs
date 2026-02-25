use thiserror::Error;

/// Top-level error type for the Sentinel platform.
#[derive(Error, Debug)]
pub enum SentinelError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Graph error: {0}")]
    Graph(String),

    #[error("Connector error: {source}")]
    Connector {
        connector: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

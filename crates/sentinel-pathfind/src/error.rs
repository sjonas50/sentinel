//! Error types for the sentinel-pathfind crate.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PathfindError {
    #[error("Graph error: {0}")]
    Graph(#[from] sentinel_graph::GraphError),

    #[error("No internet-facing nodes found for tenant {tenant_id}")]
    NoEntryPoints { tenant_id: String },

    #[error("No crown jewel nodes found for tenant {tenant_id}")]
    NoCrownJewels { tenant_id: String },

    #[error("Node not found: {node_id}")]
    NodeNotFound { node_id: String },

    #[error("Empty subgraph: no nodes or edges fetched for tenant {tenant_id}")]
    EmptySubgraph { tenant_id: String },

    #[error("Computation timeout: exceeded {max_seconds}s limit")]
    Timeout { max_seconds: u64 },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PathfindError>;

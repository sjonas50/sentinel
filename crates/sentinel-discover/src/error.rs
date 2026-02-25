//! Error types for the sentinel-discover crate.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscoverError {
    #[error("Nmap not found at path: {path}")]
    NmapNotFound { path: String },

    #[error("Nmap exited with code {code}: {stderr}")]
    NmapFailed { code: i32, stderr: String },

    #[error("Failed to parse nmap XML output: {0}")]
    XmlParse(String),

    #[error("Graph error: {0}")]
    Graph(#[from] sentinel_graph::GraphError),

    #[error("Config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DiscoverError>;

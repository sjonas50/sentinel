//! Neo4j connection management and shared graph client.

use neo4rs::{ConfigBuilder, Graph, Query};

/// Errors from graph operations.
#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("Neo4j connection error: {0}")]
    Connection(String),

    #[error("Neo4j query error: {0}")]
    Query(#[from] neo4rs::Error),

    #[error("Node not found: {label} with id {id} in tenant {tenant_id}")]
    NotFound {
        label: String,
        id: String,
        tenant_id: String,
    },

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Configuration for connecting to Neo4j.
#[derive(Debug, Clone)]
pub struct GraphConfig {
    pub uri: String,
    pub user: String,
    pub password: String,
    pub max_connections: u32,
    pub fetch_size: usize,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            uri: "bolt://localhost:7687".to_string(),
            user: "neo4j".to_string(),
            password: "sentinel-dev".to_string(),
            max_connections: 16,
            fetch_size: 256,
        }
    }
}

/// Thread-safe Neo4j graph client with connection pooling.
///
/// This is the single point of access for all knowledge graph operations.
/// Clone is cheap (inner Arc).
#[derive(Clone)]
pub struct GraphClient {
    graph: Graph,
}

impl GraphClient {
    /// Connect to Neo4j with the given configuration.
    pub async fn connect(config: &GraphConfig) -> Result<Self, GraphError> {
        let neo_config = ConfigBuilder::default()
            .uri(&config.uri)
            .user(&config.user)
            .password(&config.password)
            .max_connections(config.max_connections as usize)
            .fetch_size(config.fetch_size)
            .build()
            .map_err(|e| GraphError::Connection(e.to_string()))?;

        let graph = Graph::connect(neo_config)
            .await
            .map_err(|e| GraphError::Connection(e.to_string()))?;

        tracing::info!(uri = %config.uri, "Connected to Neo4j");
        Ok(Self { graph })
    }

    /// Get a reference to the underlying neo4rs Graph for direct operations.
    pub fn inner(&self) -> &Graph {
        &self.graph
    }

    /// Execute a write-only query (CREATE, MERGE, DELETE, SET).
    pub async fn run(&self, query: Query) -> Result<(), GraphError> {
        self.graph.run(query).await?;
        Ok(())
    }

    /// Execute a read query and collect all rows.
    pub async fn query_rows(&self, query: Query) -> Result<Vec<neo4rs::Row>, GraphError> {
        let mut stream = self.graph.execute(query).await?;
        let mut rows = Vec::new();
        while let Some(row) = stream.next().await? {
            rows.push(row);
        }
        Ok(rows)
    }

    /// Execute a read query and return the first row, if any.
    pub async fn query_one(&self, query: Query) -> Result<Option<neo4rs::Row>, GraphError> {
        let mut stream = self.graph.execute(query).await?;
        Ok(stream.next().await?)
    }

    /// Begin a transaction.
    pub async fn start_txn(&self) -> Result<neo4rs::Txn, GraphError> {
        Ok(self.graph.start_txn().await?)
    }
}

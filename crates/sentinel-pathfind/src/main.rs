//! CLI entry point for the sentinel-pathfind attack path calculator.
//!
//! Designed for subprocess invocation from the Python API:
//! reads a JSON request from stdin, writes a JSON result to stdout.

use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

use sentinel_core::types::TenantId;
use sentinel_graph::{GraphClient, GraphConfig};
use sentinel_pathfind::types::{BlastRadiusRequest, PathfindRequest};
use sentinel_pathfind::PathfindEngine;

#[derive(Parser)]
#[command(name = "sentinel-pathfind")]
#[command(about = "Attack path computation engine for the Sentinel knowledge graph")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Override tenant ID.
    #[arg(long, global = true)]
    tenant_id: Option<String>,

    /// Config file prefix (default: sentinel).
    #[arg(short, long, default_value = "sentinel", global = true)]
    config: String,
}

#[derive(Subcommand)]
enum Command {
    /// Compute all attack paths for a tenant (reads JSON from stdin).
    Compute,
    /// Compute blast radius for a specific node (reads JSON from stdin).
    BlastRadius,
    /// Compute shortest attack path between two nodes.
    Shortest {
        /// Source node ID.
        #[arg(long)]
        source: String,
        /// Target node ID.
        #[arg(long)]
        target: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).with_writer(std::io::stderr).init();

    let cli = Cli::parse();

    // Connect to Neo4j.
    let graph_config = load_graph_config(&cli.config);
    let graph = GraphClient::connect(&graph_config).await?;

    let engine = PathfindEngine::new(graph);

    match cli.command {
        Command::Compute => {
            let input = std::io::read_to_string(std::io::stdin())?;
            let request: PathfindRequest = serde_json::from_str(&input)?;
            let result = engine.compute_attack_paths(request).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::BlastRadius => {
            let input = std::io::read_to_string(std::io::stdin())?;
            let request: BlastRadiusRequest = serde_json::from_str(&input)?;
            let result = engine.compute_blast_radius(request).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::Shortest { ref source, ref target } => {
            let tenant_id = resolve_tenant_id(&cli)?;
            let result = engine.shortest_path(&tenant_id, source, target).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
    }

    Ok(())
}

fn resolve_tenant_id(cli: &Cli) -> anyhow::Result<TenantId> {
    let raw = cli
        .tenant_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--tenant-id is required for this command"))?;
    let uuid = uuid::Uuid::parse_str(raw)?;
    Ok(TenantId(uuid))
}

fn load_graph_config(file_prefix: &str) -> GraphConfig {
    let cfg = config::Config::builder()
        .add_source(config::File::with_name(file_prefix).required(false))
        .add_source(
            config::Environment::with_prefix("SENTINEL")
                .separator("__")
                .try_parsing(true),
        )
        .build();

    match cfg {
        Ok(c) => GraphConfig {
            uri: c
                .get_string("neo4j.uri")
                .unwrap_or_else(|_| "bolt://localhost:7687".to_string()),
            user: c
                .get_string("neo4j.user")
                .unwrap_or_else(|_| "neo4j".to_string()),
            password: c
                .get_string("neo4j.password")
                .unwrap_or_else(|_| "sentinel-dev".to_string()),
            ..Default::default()
        },
        Err(_) => GraphConfig::default(),
    }
}

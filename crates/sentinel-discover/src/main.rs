//! CLI entry point for the sentinel-discover network scanner.

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

use sentinel_core::types::TenantId;
use sentinel_graph::{GraphClient, GraphConfig};

use sentinel_discover::config::{DiscoverConfig, ScanProfile};
use sentinel_discover::scanner::NmapScanner;
use sentinel_discover::scheduler::{run_single_scan, ScanScheduler};

#[derive(Parser)]
#[command(name = "sentinel-discover")]
#[command(about = "Network scanner for the Sentinel knowledge graph")]
struct Cli {
    /// Target to scan (CIDR notation, e.g., 10.0.1.0/24).
    #[arg(short, long)]
    target: Option<String>,

    /// Scan profile: quick, standard, deep.
    #[arg(short, long, default_value = "standard")]
    profile: String,

    /// Run a single one-shot scan and exit.
    #[arg(long)]
    once: bool,

    /// Run as daemon with scheduled scans.
    #[arg(long)]
    daemon: bool,

    /// Override tenant ID (otherwise read from config).
    #[arg(long)]
    tenant_id: Option<String>,

    /// Config file prefix (default: sentinel).
    #[arg(short, long, default_value = "sentinel")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).json().init();

    let cli = Cli::parse();
    let discover_config = load_discover_config(&cli.config)?;

    // Connect to Neo4j.
    let graph_config = load_graph_config(&cli.config);
    let graph = GraphClient::connect(&graph_config).await?;
    tracing::info!("Connected to Neo4j");

    // Verify nmap installation.
    let scanner = NmapScanner::new(&discover_config.nmap_path);
    let version = scanner.verify_installation().await?;
    tracing::info!(nmap_version = %version.trim(), "Nmap verified");

    if cli.once {
        let target = cli
            .target
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--target is required in --once mode"))?;
        let profile = parse_profile(&cli.profile)?;
        let tenant_id = resolve_tenant_id(&cli, &discover_config)?;

        run_single_scan(
            &scanner,
            &graph,
            &tenant_id,
            &discover_config,
            target,
            &profile,
        )
        .await?;
    } else if cli.daemon {
        let tenant_id = resolve_tenant_id(&cli, &discover_config)?;
        let sched = ScanScheduler::new(discover_config, scanner, graph, tenant_id);
        sched.run().await?;
    } else {
        anyhow::bail!("Specify --once (one-shot scan) or --daemon (scheduled scanning)");
    }

    Ok(())
}

fn parse_profile(s: &str) -> anyhow::Result<ScanProfile> {
    match s.to_lowercase().as_str() {
        "quick" => Ok(ScanProfile::Quick),
        "standard" => Ok(ScanProfile::Standard),
        "deep" => Ok(ScanProfile::Deep),
        _ => anyhow::bail!("Invalid profile: {s}. Choose: quick, standard, deep"),
    }
}

fn resolve_tenant_id(cli: &Cli, config: &DiscoverConfig) -> anyhow::Result<TenantId> {
    let raw = cli.tenant_id.as_deref().unwrap_or(&config.tenant_id);
    if raw.is_empty() {
        anyhow::bail!("Tenant ID required: set --tenant-id or discover.tenant_id in config");
    }
    let uuid = Uuid::parse_str(raw)?;
    Ok(TenantId(uuid))
}

fn load_discover_config(file_prefix: &str) -> anyhow::Result<DiscoverConfig> {
    let cfg = config::Config::builder()
        .add_source(config::File::with_name(file_prefix).required(false))
        .add_source(
            config::Environment::with_prefix("SENTINEL_DISCOVER")
                .separator("__")
                .try_parsing(true),
        )
        .build()?;

    match cfg.get::<DiscoverConfig>("discover") {
        Ok(c) => Ok(c),
        Err(_) => Ok(DiscoverConfig::default()),
    }
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

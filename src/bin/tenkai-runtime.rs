//! Environment-scoped, pull-only Tenkai runtime.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use tenkai::runtime_agent::RuntimeClient;

#[derive(Parser)]
#[command(name = "tenkai-runtime", version, about = "Tenkai environment runtime")]
struct Cli {
    #[arg(long, env = "TENKAI_SERVER_URL")]
    server_url: String,
    #[arg(long, env = "TENKAI_RUNTIME_ENVIRONMENT")]
    environment: String,
    #[arg(long, env = "TENKAI_RUNTIME_EXECUTOR")]
    executor: PathBuf,
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,
    #[arg(long)]
    once: bool,
    /// Disable inventory fact reports to the hub (#136). Also honors
    /// `TENKAI_RUNTIME_INVENTORY=0|false|off|no`.
    #[arg(long, default_value_t = false)]
    no_inventory_report: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let token =
        std::env::var("TENKAI_RUNTIME_TOKEN").context("TENKAI_RUNTIME_TOKEN is required")?;
    let inventory_report = !cli.no_inventory_report && env_inventory_enabled();
    let client = RuntimeClient::new_with_options(
        cli.server_url,
        cli.environment,
        token,
        cli.executor,
        inventory_report,
    )?;
    if cli.once {
        client.run_once().await?;
    } else {
        client.run(Duration::from_secs(cli.poll_interval)).await?;
    }
    Ok(())
}

fn env_inventory_enabled() -> bool {
    match std::env::var("TENKAI_RUNTIME_INVENTORY") {
        Ok(value) => {
            let lower = value.trim().to_ascii_lowercase();
            !matches!(lower.as_str(), "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

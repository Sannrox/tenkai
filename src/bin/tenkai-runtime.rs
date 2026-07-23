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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let token =
        std::env::var("TENKAI_RUNTIME_TOKEN").context("TENKAI_RUNTIME_TOKEN is required")?;
    let client = RuntimeClient::new(cli.server_url, cli.environment, token, cli.executor)?;
    if cli.once {
        client.run_once().await?;
    } else {
        client.run(Duration::from_secs(cli.poll_interval)).await?;
    }
    Ok(())
}

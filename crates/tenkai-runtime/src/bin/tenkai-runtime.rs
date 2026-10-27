//! Environment-scoped, pull-only Tenkai runtime.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use tenkai::runtime_agent::RuntimeClient;

#[derive(Parser)]
#[command(name = "tenkai-runtime", version, about = "Tenkai environment runtime")]
struct Cli {
    #[command(subcommand)]
    command: Option<HomeCommand>,
    #[arg(long, env = "TENKAI_SERVER_URL")]
    server_url: Option<String>,
    #[arg(long, env = "TENKAI_RUNTIME_ENVIRONMENT")]
    environment: Option<String>,
    #[arg(long, env = "TENKAI_RUNTIME_EXECUTOR")]
    executor: Option<PathBuf>,
    /// Where the agent keeps its own versions, so Tenkai can upgrade and
    /// roll it back as a release of `tenkai-runtime` (#685). The supervisor
    /// runs `<home>/current/tenkai-runtime`.
    #[arg(long, env = "TENKAI_RUNTIME_HOME", global = true)]
    home: Option<PathBuf>,
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,
    #[arg(long)]
    once: bool,
    /// Disable inventory fact reports to the hub (#136). Also honors
    /// `TENKAI_RUNTIME_INVENTORY=0|false|off|no`.
    #[arg(long, default_value_t = false)]
    no_inventory_report: bool,
    /// Where the agent keeps its own credential (#630). Created on first
    /// start from a single-use enrollment token
    /// (`TENKAI_RUNTIME_ENROLLMENT_TOKEN`, from `tenkaictl runtime enroll`).
    /// Without it, `TENKAI_RUNTIME_TOKEN` is used as before.
    #[arg(long, env = "TENKAI_RUNTIME_CREDENTIAL_FILE")]
    credential_file: Option<PathBuf>,
}

/// Manage the agent's own versions under `--home`.
#[derive(clap::Subcommand)]
enum HomeCommand {
    /// Make this binary and its guard the first version under the home.
    Install,
    /// Switch back to the version a pending switch came from: the
    /// supervisor's hook when a new version does not start.
    Revert,
    /// Run before every start, from a version known to run: counts the
    /// starts of a switch not yet reported and reverts it after a few.
    Prestart,
    /// Print the runtime protocol this version speaks, as JSON. A running
    /// agent asks a new version before switching to it.
    Protocol,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(HomeCommand::Protocol) = &cli.command {
        println!(
            "{}",
            tenkai::runtime_self_upgrade::Protocol::this().to_json()?
        );
        return Ok(());
    }
    if let Some(command) = &cli.command {
        let home = tenkai::runtime_self_upgrade::Home::new(
            cli.home
                .clone()
                .context("--home or TENKAI_RUNTIME_HOME is required")?,
        );
        match command {
            HomeCommand::Install => println!("installed runtime agent {}", home.install_running()?),
            HomeCommand::Revert => match home.revert()? {
                Some(version) => println!("reverted the runtime agent to {version}"),
                None => println!("no runtime agent switch to revert"),
            },
            HomeCommand::Prestart => {
                if let Some(version) = home.prestart()? {
                    println!("reverted the runtime agent to {version}");
                }
            }
            HomeCommand::Protocol => unreachable!("answered above"),
        }
        return Ok(());
    }
    let server_url = cli
        .server_url
        .context("--server-url or TENKAI_SERVER_URL is required")?;
    let environment = cli
        .environment
        .context("--environment or TENKAI_RUNTIME_ENVIRONMENT is required")?;
    let executor = cli
        .executor
        .context("--executor or TENKAI_RUNTIME_EXECUTOR is required")?;
    let token = match &cli.credential_file {
        Some(file) => {
            tenkai::runtime_agent::enrolled_credential(
                &server_url,
                &environment,
                || tenkai::secret_source::read("TENKAI_RUNTIME_ENROLLMENT_TOKEN"),
                file,
            )
            .await?
        }
        None => tenkai::secret_source::require("TENKAI_RUNTIME_TOKEN")?,
    };
    let inventory_report = !cli.no_inventory_report && env_inventory_enabled();
    let mut client = RuntimeClient::new_with_options(
        server_url,
        environment,
        token,
        executor,
        inventory_report,
    )?;
    if let Some(home) = cli.home {
        client = client.with_home(tenkai::runtime_self_upgrade::Home::new(home))?;
    }
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

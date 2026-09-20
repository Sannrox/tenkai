use anyhow::{Result, bail};
use tenkai::plan;

use crate::args::{Cli, Command};
use crate::env_args::EnvCommand;
use crate::fleet_args::FleetCommand;
use crate::fleet_watch::{FleetWatchOptions, print_fleet_status, run_fleet_watch};
use crate::output::print_reconcile_report;

pub(crate) async fn run(cli: Cli) -> Result<()> {
    let server_url = cli
        .server_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--server-url is required with --target remote"))?;
    let token = std::env::var("TENKAI_MANAGEMENT_TOKEN")
        .map_err(|_| anyhow::anyhow!("TENKAI_MANAGEMENT_TOKEN is required for remote mode"))?;
    let client = tenkai::server::RemoteClient::new(server_url, token)?;
    match cli.command {
        Command::Reconcile {
            once: true, bypass, ..
        } => {
            if bypass.allow_unapproved_development || bypass.development_reason.is_some() {
                bail!(
                    "the local-development reconciliation bypass is available only with --target embedded"
                );
            }
            let report = client.reconcile().await?;
            let failures = report.failures();
            print_reconcile_report(report);
            if failures > 0 {
                bail!("{failures} environment(s) failed to reconcile");
            }
            Ok(())
        }
        Command::Reconcile { once: false, .. } => {
            bail!("remote servers reconcile continuously; use --once to request an immediate tick")
        }
        Command::Fleet {
            command: FleetCommand::Status,
        } => {
            let report = client.fleet_status().await?;
            print_fleet_status(&report);
            Ok(())
        }
        Command::Fleet {
            command:
                FleetCommand::Watch {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
        } => {
            run_fleet_watch(
                || {
                    let client = client.clone();
                    async move { client.fleet_status().await }
                },
                FleetWatchOptions {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
            )
            .await?;
            Ok(())
        }
        Command::Env {
            command: EnvCommand::List,
        } => {
            let entries = client.list_environments().await?;
            if entries.is_empty() {
                println!("no environments registered");
            } else {
                println!(
                    "{:<20} {:<8} {:<10} {:<6} description",
                    "name", "subs", "deployed", "lease"
                );
                for entry in entries {
                    let lease = if entry.lease_held { "held" } else { "-" };
                    println!(
                        "{:<20} {:<8} {:<10} {:<6} {}",
                        entry.name,
                        entry.subscription_count,
                        entry.deployed_product_count,
                        lease,
                        entry.description
                    );
                }
            }
            Ok(())
        }
        Command::Env {
            command: EnvCommand::Inspect { env },
        } => {
            let report = client.inspect_environment(&env).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Status { env } => {
            let rows = client.environment_status(&env).await?;
            if rows.is_empty() {
                println!("{env} has no channel subscriptions");
            } else {
                println!(
                    "{:<24} {:<10} {:<12} {:<12} state",
                    "product", "channel", "deployed", "head"
                );
                for r in rows {
                    let deployed = r.deployed.clone().unwrap_or_else(|| "-".into());
                    let state = plan::subscription_state(
                        r.deployed.as_deref(),
                        &r.head,
                        r.health.as_deref(),
                        r.overlay_stale,
                    );
                    println!(
                        "{:<24} {:<10} {:<12} {:<12} {state}",
                        r.product, r.channel, deployed, r.head
                    );
                }
            }
            Ok(())
        }
        Command::Migrate { command } => {
            crate::remote_delivery::run_migrate(&client, command).await?;
            Ok(())
        }
        other => crate::remote_catalog::run(&client, other).await,
    }
}

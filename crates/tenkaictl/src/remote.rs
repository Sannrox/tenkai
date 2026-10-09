use anyhow::{Result, bail};
use tenkai::plan;

use crate::args::{Cli, Command, OutputFormat};
use crate::env_args::EnvCommand;
use crate::fleet_args::FleetCommand;
use crate::fleet_watch::{FleetWatchOptions, print_fleet_status, run_fleet_watch};
use crate::output::{print_machine_result, print_reconcile_report};

pub(crate) async fn run(cli: Cli) -> Result<()> {
    let server_url = crate::login::require_server_url(cli.server_url.as_deref())?;
    let runtime = crate::login::LoginRuntime::from_env()?;
    let token = crate::login::bearer_token(&runtime, &server_url).await?;
    let client = tenkai_http::RemoteClient::new(&server_url, token)?;
    let output = cli.output;
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
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::fleet_status_result(&report));
            }
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
                {
                    let runtime = runtime.clone();
                    let server_url = server_url.clone();
                    move || {
                        let runtime = runtime.clone();
                        let server_url = server_url.clone();
                        async move {
                            // Refresh each sample so a saved OIDC access token
                            // can expire during watch.
                            let token = crate::login::bearer_token(&runtime, &server_url).await?;
                            let client = tenkai_http::RemoteClient::new(&server_url, token)?;
                            client.fleet_status().await
                        }
                    }
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
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::list_environments_result(
                    entries.len(),
                ));
            }
            if entries.is_empty() {
                println!("no environments registered");
            } else {
                println!(
                    "{:<20} {:<8} {:<10} {:<6} {:<6} description",
                    "name", "subs", "deployed", "lease", "hold"
                );
                for entry in entries {
                    let lease = if entry.lease_held { "held" } else { "-" };
                    let hold = if entry.delivery_held { "hold" } else { "-" };
                    println!(
                        "{:<20} {:<8} {:<10} {:<6} {:<6} {}",
                        entry.name,
                        entry.subscription_count,
                        entry.deployed_product_count,
                        lease,
                        hold,
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
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::inspect_result(&report));
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Env {
            command: EnvCommand::Compatibility { command },
        } => {
            match command {
                crate::env_args::CompatibilityCommand::Record { env, evidence } => {
                    let evidence = serde_json::from_slice(&std::fs::read(evidence)?)?;
                    client
                        .record_software_compatibility_evidence(&env, &evidence)
                        .await?;
                    println!("recorded software compatibility evidence for {env}");
                }
                crate::env_args::CompatibilityCommand::Check { env, release } => {
                    crate::embedded_env_config::print_compatibility_report(
                        client.software_compatibility_report(&env, &release).await?,
                    )?;
                }
            }
            Ok(())
        }
        Command::Status { env } => {
            let rows = client.environment_status(&env).await?;
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::status_result(&env, rows.len()));
            }
            if let Ok(report) = client.inspect_environment(&env).await
                && let Some(hold) = report.delivery_hold
            {
                println!(
                    "{env} held at {} by {}: {}",
                    hold.held_at, hold.actor, hold.reason
                );
            }
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
                    if let Some(hold) = &r.delivery_hold {
                        println!(
                            "  channel hold at {} by {}: {}",
                            hold.held_at, hold.actor, hold.reason
                        );
                    }
                }
            }
            Ok(())
        }
        Command::Migrate { command } => {
            crate::remote_delivery::run_migrate(&client, command).await?;
            Ok(())
        }
        other => crate::remote_catalog::run(&client, other, output).await,
    }
}

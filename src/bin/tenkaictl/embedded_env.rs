use anyhow::{Context as _, Result, bail};
use tenkai::command_result::{CommandName, CommandResultV1};
use tenkai::{apply, client, connectivity, plan, preview};

use crate::args::OutputFormat;
use crate::env_args::EnvCommand;
use crate::output::print_machine_result;

pub(crate) async fn run(
    ctx: &mut client::Ctx,
    command: EnvCommand,
    output: OutputFormat,
) -> Result<()> {
    match command {
        EnvCommand::Add { name, description } => {
            println!("{}", plan::env_add(ctx, &name, &description).await?);
        }
        EnvCommand::Preview {
            name,
            pin,
            expires_at,
            description,
        } => {
            let pin = preview::BranchPin::load_file(&pin)?;
            let expires_at = parse_preview_expiry(&expires_at)?;
            println!(
                "{}",
                preview::provision(
                    ctx,
                    &name,
                    pin,
                    expires_at,
                    &description,
                    tenkai::now_millis(),
                )
                .await?
            );
        }
        EnvCommand::ClosePreview { env } => {
            let evidence = preview::close_branch(ctx, &env, tenkai::now_millis()).await?;
            println!(
                "preview environment {} torn down ({}); pin {}; plan digest {}",
                evidence.environment, evidence.reason, evidence.pin_digest, evidence.plan_digest
            );
        }
        EnvCommand::List => {
            let entries = plan::list_environments(ctx).await?;
            if entries.is_empty() {
                println!("no environments registered (tenkaictl env add <name>)");
                return Ok(());
            }
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
        EnvCommand::Inspect { env } => {
            let report = plan::inspect_environment_with_outcomes(ctx, &env).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::InspectEnvironment)
                        .resource("environment", report.id)
                        .counts(None, Some(report.subscriptions.len())),
                )?;
            } else {
                // JSON keeps multi-env inspect machine-readable without secrets.
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
        EnvCommand::Subscribe { env, spec, .. } => {
            let Some((product, channel)) = spec.split_once('=') else {
                bail!("expected <product>=<channel>, got {spec:?}");
            };
            println!("{}", plan::subscribe(ctx, &env, product, channel).await?);
        }
        EnvCommand::Unlock { env } => {
            println!("{}", apply::unlock_environment(ctx, &env).await?);
        }
        EnvCommand::Reconcile {
            env,
            product,
            deployed,
        } => {
            println!(
                "{}",
                plan::reconcile_deployment(ctx, &env, &product, deployed.as_deref()).await?
            );
        }
        EnvCommand::Maintenance { command } => {
            crate::embedded_env_config::maintenance(ctx, command).await?;
        }
        EnvCommand::Connectivity { env, class } => {
            let class = connectivity::ConnectivityClass::parse(&class)?;
            println!(
                "{}",
                connectivity::set_connectivity_class(ctx, &env, class).await?
            );
        }
        EnvCommand::Observe {
            env,
            type_digest,
            runtime_digest,
        } => {
            println!(
                "{}",
                plan::set_observed_compatibility(ctx, &env, &type_digest, &runtime_digest).await?
            );
        }
        EnvCommand::Facts { command } => {
            crate::embedded_env_config::facts(ctx, command).await?;
        }
        EnvCommand::Constraints { command } => {
            crate::embedded_env_config::constraints(ctx, command).await?;
        }
        EnvCommand::Overlay { command } => {
            crate::embedded_env_config::overlay(ctx, command).await?;
        }
        EnvCommand::ArtifactMirror { command } => {
            crate::embedded_env_config::artifact_mirror(ctx, command).await?;
        }
        EnvCommand::ClusterConfig { command } => {
            crate::embedded_env_config::cluster_config(ctx, command).await?;
        }
    }
    Ok(())
}

pub(crate) fn parse_preview_expiry(value: &str) -> Result<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("preview expiry {value:?} is not RFC 3339"))?;
    Ok(parsed.timestamp_millis())
}

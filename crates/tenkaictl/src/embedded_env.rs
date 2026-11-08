use anyhow::{Context as _, Result, bail};
use tenkai::{apply, client, connectivity, plan, preview};

use crate::args::OutputFormat;
use crate::env_args::{DependencyFormat, EnvCommand};
use crate::output::{print_history_page, print_machine_result};

pub(crate) async fn run(
    ctx: &mut client::Ctx,
    command: EnvCommand,
    output: OutputFormat,
) -> Result<()> {
    match command {
        EnvCommand::Add {
            name,
            description,
            connectivity,
            ..
        } => {
            // Parsed first, so invalid input registers nothing.
            let class = connectivity
                .as_deref()
                .map(connectivity::ConnectivityClass::parse)
                .transpose()?;
            println!("{}", plan::env_add(ctx, &name, &description).await?);
            if let Some(class) = class {
                println!(
                    "{}",
                    connectivity::set_connectivity_class(ctx, &name, class).await?
                );
            }
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
            if output == OutputFormat::JsonV1 {
                return print_machine_result(&crate::output::list_environments_result(
                    entries.len(),
                ));
            }
            if entries.is_empty() {
                println!("no environments registered (tenkaictl env add <name>)");
                return Ok(());
            }
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
        EnvCommand::Inspect { env } => {
            let report = plan::inspect_environment_with_outcomes(ctx, &env).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(&crate::output::inspect_result(&report))?;
            } else {
                // JSON keeps multi-env inspect machine-readable without secrets.
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
        EnvCommand::History {
            env,
            product,
            limit,
            cursor,
        } => {
            let page = tenkai::deployment_history::list_deployment_history(
                ctx,
                &env,
                &tenkai::deployment_history::DeploymentHistoryQuery {
                    limit,
                    cursor,
                    product,
                },
            )
            .await?;
            if output == OutputFormat::JsonV1 {
                // The machine form is the history page, not a command-result envelope.
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                print_history_page(&page);
            }
        }
        EnvCommand::Dependencies { env, format } => {
            let view = tenkai::environment_dependencies::for_environment(ctx, &env).await?;
            match format {
                DependencyFormat::Json => println!("{}", serde_json::to_string_pretty(&view)?),
                DependencyFormat::Dot => println!("{}", view.to_dot()),
                DependencyFormat::Text => println!("{}", view.to_text()),
            }
        }
        EnvCommand::Retire { env, reason } => {
            let actor =
                std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "local-operator".into());
            let retirement =
                tenkai::environment::retire_environment(ctx, &env, &reason, &actor).await?;
            println!(
                "environment {env} retired at {} by {}: {}",
                retirement.retired_at, retirement.actor, retirement.reason
            );
        }
        EnvCommand::Subscribe {
            env,
            spec,
            instance,
            ..
        } => {
            let Some((product, channel)) = spec.split_once('=') else {
                bail!("expected <product>=<channel>, got {spec:?}");
            };
            let message =
                plan::subscribe_instance(ctx, &env, product, channel, instance.as_deref()).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(&crate::output::subscribe_result(&env, &spec))?;
            } else {
                println!("{message}");
            }
        }
        EnvCommand::Unsubscribe {
            env,
            product,
            instance,
            ..
        } => {
            println!(
                "{}",
                tenkai::environment::unsubscribe_instance(
                    ctx,
                    &env,
                    &product,
                    instance.as_deref(),
                    &tenkai::software_executor::SoftwareExecutors::try_from_process()?,
                    |_| Ok(()),
                )
                .await?
            );
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
        EnvCommand::Compatibility { command } => {
            crate::embedded_env_config::compatibility(ctx, command).await?;
        }
        EnvCommand::Bind {
            env,
            dependent,
            spec,
            ..
        } => {
            let Some((contract, provider)) = spec.split_once('=') else {
                bail!("expected <contract>=<provider>, got {spec:?}");
            };
            println!(
                "{}",
                tenkai::environment_bindings::bind(ctx, &env, &dependent, contract, provider)
                    .await?
            );
        }
        EnvCommand::Unbind {
            env,
            dependent,
            contract,
            ..
        } => {
            println!(
                "{}",
                tenkai::environment_bindings::unbind(ctx, &env, &dependent, &contract).await?
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
        EnvCommand::DockerSecrets { command } => {
            crate::embedded_env_config::docker_secrets(ctx, command).await?;
        }
        EnvCommand::ApprovalPolicy { command } => {
            crate::embedded_env_config::approval_policy(ctx, command).await?;
        }
        EnvCommand::Webhooks { command } => {
            crate::embedded_env_config::webhooks(ctx, command).await?;
        }
        EnvCommand::RunnerAttestation { command } => {
            crate::embedded_env_config::runner_attestation(ctx, command).await?;
        }
        EnvCommand::Criticality { command } => {
            crate::embedded_env_config::criticality(ctx, command).await?;
        }
        EnvCommand::Hold {
            env,
            generation: _,
            action,
        } => {
            crate::embedded_hold::run(
                ctx,
                tenkai::delivery_hold::HoldScope::environment(&env),
                action,
            )
            .await?;
        }
        EnvCommand::Retry {
            env,
            product,
            reason,
            generation: _,
        } => {
            crate::embedded_hold::retry(ctx, &env, &product, &reason).await?;
        }
    }
    Ok(())
}

pub(crate) fn parse_preview_expiry(value: &str) -> Result<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("preview expiry {value:?} is not RFC 3339"))?;
    Ok(parsed.timestamp_millis())
}

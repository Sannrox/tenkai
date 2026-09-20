use std::path::Path;

use anyhow::{Result, bail};
use tenkai::command_result::{CommandName, CommandResultV1, RetryGuidance};
use tenkai::{apply, client, plan};

use crate::args::{Command, OutputFormat, RecoveryCommand};
use crate::authorization::execution_authorization;
use crate::output::{print_machine_result, print_steps, reported_machine_failure};

pub(crate) struct PlanResultContext<'a> {
    pub(crate) command: CommandName,
    pub(crate) environment: &'a str,
    pub(crate) step_count: usize,
    pub(crate) output: OutputFormat,
}

pub(crate) async fn run(
    ctx: &mut client::Ctx,
    command: Command,
    output: OutputFormat,
    database: &Path,
) -> Result<()> {
    match command {
        Command::Plan { env, generation: _ } => {
            if output == OutputFormat::JsonV1 {
                tenkai::command_result::validate_resource_reference(
                    "plan",
                    &format!("tenkai:plan:{env}:18446744073709551615:{}", "0".repeat(64)),
                )
                .map_err(|message| anyhow::anyhow!(message))?;
            }
            let stored = plan::create(ctx, &env).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Plan)
                        .resource("plan", stored.id)
                        .resource("environment", stored.environment)
                        .counts(Some(stored.steps.len()), None),
                )?;
            } else {
                println!("plan id: {}", stored.id);
                if stored.steps.is_empty() {
                    println!("{env} is up to date");
                } else {
                    println!("plan for {env}:");
                    print_steps(&stored.steps);
                }
            }
        }
        Command::Apply {
            plan_id,
            approval,
            skip_gates,
            emergency_reason,
            generation: _,
        } => {
            let stored = plan::load(ctx, &plan_id).await?;
            if output == OutputFormat::JsonV1 {
                CommandResultV1::succeeded(CommandName::Apply)
                    .resource("plan", &stored.id)
                    .resource("environment", &stored.environment)
                    .counts(Some(stored.steps.len()), None)
                    .validate()
                    .map_err(|message| anyhow::anyhow!(message))?;
            }
            if output == OutputFormat::Human {
                println!("applying {} to {}:", stored.id, stored.environment);
                print_steps(&stored.steps);
            }
            let authorization = execution_authorization(
                approval.approval.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
                "plan execution requires --approval and --approval-trust-roots; local development may explicitly use --allow-unapproved-development with --development-reason",
            )?;
            run_plan(
                ctx,
                &plan_id,
                apply::ExecutionOptions {
                    skip_gates,
                    emergency_reason: emergency_reason.as_deref(),
                    authorization,
                    software_executor: None,
                    worker_lifecycle: None,
                    artifact_registry: None,
                    delivery_adapter: None,
                    delivery_fence: None,
                },
                PlanResultContext {
                    command: CommandName::Apply,
                    environment: &stored.environment,
                    step_count: stored.steps.len(),
                    output,
                },
            )
            .await?;
        }
        Command::Status { env } => {
            let rows = plan::status(ctx, &env).await?;
            if output == OutputFormat::JsonV1 {
                print_machine_result(
                    &CommandResultV1::succeeded(CommandName::Status)
                        .resource("environment", env)
                        .counts(None, Some(rows.len())),
                )?;
                return Ok(());
            }
            if rows.is_empty() {
                println!("{env} has no channel subscriptions");
                return Ok(());
            }
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
                if matches!(state, "unknown" | "unhealthy")
                    && let Some(error) = r.error.as_deref()
                {
                    println!("  recovery required: {error}");
                }
            }
        }
        Command::Recovery { command } => match command {
            RecoveryCommand::Export { env, plan, output } => {
                let bundle = tenkai::recovery_bundle::export(ctx, &env, &plan).await?;
                tenkai::recovery_bundle::write_verified(&output, &bundle)?;
                println!(
                    "wrote recovery diagnostic {} (authority=none)",
                    output.display()
                );
            }
        },
        Command::Inspect => {
            let summary = serde_json::json!({
                "mode": "embedded",
                "database": database,
                "products": ctx.list_kind(tenkai::ontology::KIND_PRODUCT).await?.len(),
                "releases": ctx.list_kind(tenkai::ontology::KIND_RELEASE).await?.len(),
                "channels": ctx.list_kind(tenkai::ontology::KIND_CHANNEL).await?.len(),
                "environments": ctx.list_kind(tenkai::ontology::KIND_ENVIRONMENT).await?.len(),
                "plans": ctx.list_kind(tenkai::ontology::KIND_PLAN).await?.len(),
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::Backup { destination } => {
            ctx.backup_embedded(&destination).await?;
            println!("backed up embedded state to {}", destination.display());
        }
        _ => unreachable!("apply dispatcher received a non-apply command"),
    }
    Ok(())
}

pub(crate) async fn run_plan(
    ctx: &mut client::Ctx,
    plan_id: &str,
    execution: apply::ExecutionOptions<'_>,
    result_context: PlanResultContext<'_>,
) -> Result<()> {
    let software =
        tenkai::software_executor::selected_software_executor().map(std::sync::Arc::from);
    let worker_lifecycle =
        tenkai::worker_pool::selected_worker_lifecycle()?.map(std::sync::Arc::from);
    let delivery = tenkai::delivery_bridge::selected_delivery_adapter();
    let execution = apply::ExecutionOptions {
        skip_gates: execution.skip_gates,
        emergency_reason: execution.emergency_reason,
        authorization: execution.authorization,
        software_executor: software,
        worker_lifecycle,
        artifact_registry: tenkai::oci_artifact::selected_registry()?,
        delivery_adapter: delivery,
        delivery_fence: None,
    };
    let outcomes = apply::execute_with_options(ctx, plan_id, execution).await?;
    let mut failed = false;
    for o in &outcomes {
        if result_context.output == OutputFormat::JsonV1 {
            failed |= !o.classified_status()?.is_success();
            continue;
        }
        match o.classified_status()? {
            apply::StepOutcomeStatus::Succeeded => {
                println!("  ok        {:<24} {}", o.step.product, o.step.to)
            }
            apply::StepOutcomeStatus::Blocked => {
                failed = true;
                println!("  BLOCKED   {:<24} {}", o.step.product, o.detail);
            }
            apply::StepOutcomeStatus::RolledBack => {
                failed = true;
                println!("  ROLLBACK  {:<24} {}", o.step.product, o.detail);
            }
            apply::StepOutcomeStatus::Failed => {
                failed = true;
                println!("  FAILED    {:<24} {}", o.step.product, o.detail);
            }
        }
    }
    if failed {
        if result_context.output == OutputFormat::JsonV1 {
            return Err(reported_machine_failure(
                CommandResultV1::failed(
                    result_context.command,
                    "execution_failed",
                    "One or more delivery steps did not succeed",
                    RetryGuidance::ReconcileBeforeRetry,
                )
                .resource("plan", plan_id)
                .resource("environment", result_context.environment)
                .counts(Some(result_context.step_count), None),
            ));
        }
        bail!("one or more delivery steps did not succeed");
    }
    if result_context.output == OutputFormat::JsonV1 {
        print_machine_result(
            &CommandResultV1::succeeded(result_context.command)
                .resource("plan", plan_id)
                .resource("environment", result_context.environment)
                .counts(Some(result_context.step_count), None),
        )?;
    }
    Ok(())
}

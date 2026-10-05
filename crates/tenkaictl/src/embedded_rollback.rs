use anyhow::{Result, bail};
use tenkai::command_result::{CommandName, CommandOutcome, CommandResultV1, RetryGuidance};
use tenkai::{apply, client, plan};

use crate::args::{Command, OutputFormat};
use crate::embedded_apply::{PlanResultContext, run_plan};
use crate::output::{print_steps, reported_machine_failure};

pub(crate) async fn run(
    ctx: &mut client::Ctx,
    command: Command,
    output: OutputFormat,
) -> Result<()> {
    match command {
        Command::Rollback {
            product,
            env,
            bypass,
            emergency_reason,
            allow_recalled_recovery,
            recovery_reason,
            generation: _,
        } => {
            if output == OutputFormat::JsonV1 {
                tenkai::command_result::validate_resource_reference(
                    "plan",
                    &format!("tenkai:plan:{env}:18446744073709551615:{}", "0".repeat(64)),
                )
                .map_err(|message| anyhow::anyhow!(message))?;
            }
            let recovery = if allow_recalled_recovery {
                Some(
                    recovery_reason
                        .as_deref()
                        .expect("clap requires a recovery reason"),
                )
            } else {
                None
            };
            let step = plan::rollback_step_with_recovery(ctx, &env, &product, recovery).await?;
            let stored = if let Some(reason) = recovery {
                plan::create_from_steps_with_recovery(ctx, &env, vec![step], reason.to_string())
                    .await?
            } else {
                plan::create_from_steps(ctx, &env, vec![step]).await?
            };
            if output == OutputFormat::Human {
                println!("rolling back in {env}:");
                print_steps(&stored.steps);
            }
            if bypass.allow_unapproved_development {
                run_plan(
                    ctx,
                    &stored.id,
                    apply::ExecutionOptions {
                        skip_gates: true,
                        emergency_reason: emergency_reason.as_deref(),
                        authorization: apply::ExecutionAuthorization::LocalDevelopment {
                            reason: bypass
                                .development_reason
                                .as_deref()
                                .expect("clap requires a development reason"),
                        },
                        software_executor: None,
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
                        delivery_fence: None,
                    },
                    PlanResultContext {
                        command: CommandName::Rollback,
                        environment: &stored.environment,
                        step_count: stored.steps.len(),
                        output,
                    },
                )
                .await?;
            } else if output == OutputFormat::JsonV1 {
                let mut result = CommandResultV1::failed(
                    CommandName::Rollback,
                    "approval_required",
                    "The rollback plan requires signed approval",
                    RetryGuidance::NotSafe,
                )
                .resource("plan", stored.id)
                .resource("environment", stored.environment)
                .counts(Some(stored.steps.len()), None);
                result.outcome = CommandOutcome::AwaitingApproval;
                return Err(reported_machine_failure(result));
            } else {
                bail!(
                    "rollback was not executed; plan {} requires signed approval. Run `tenkaictl apply {}` with --approval and --approval-trust-roots{}",
                    stored.id,
                    stored.id,
                    if emergency_reason.is_some() {
                        " and repeat --emergency-reason"
                    } else {
                        ""
                    }
                );
            }
        }
        Command::Restart {
            product,
            env,
            bypass,
            emergency_reason,
        } => {
            let step = plan::restart_step(ctx, &env, &product).await?;
            let stored = plan::create_from_steps(ctx, &env, vec![step]).await?;
            if output == OutputFormat::Human {
                println!("restarting in {env}:");
                print_steps(&stored.steps);
            }
            if bypass.allow_unapproved_development {
                run_plan(
                    ctx,
                    &stored.id,
                    apply::ExecutionOptions {
                        skip_gates: true,
                        emergency_reason: emergency_reason.as_deref(),
                        authorization: apply::ExecutionAuthorization::LocalDevelopment {
                            reason: bypass
                                .development_reason
                                .as_deref()
                                .expect("clap requires a development reason"),
                        },
                        software_executor: tenkai::software_executor::selected_software_executor()
                            .map(std::sync::Arc::from),
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
                        delivery_fence: None,
                    },
                    PlanResultContext {
                        command: CommandName::Restart,
                        environment: &stored.environment,
                        step_count: stored.steps.len(),
                        output,
                    },
                )
                .await?;
            } else if output == OutputFormat::JsonV1 {
                let mut result = CommandResultV1::failed(
                    CommandName::Restart,
                    "approval_required",
                    "The restart plan requires signed approval",
                    RetryGuidance::NotSafe,
                )
                .resource("plan", stored.id)
                .resource("environment", stored.environment)
                .counts(Some(stored.steps.len()), None);
                result.outcome = CommandOutcome::AwaitingApproval;
                return Err(reported_machine_failure(result));
            } else {
                bail!(
                    "restart was not executed; plan {} requires signed approval. Run `tenkaictl apply {}` with --approval and --approval-trust-roots{}",
                    stored.id,
                    stored.id,
                    if emergency_reason.is_some() {
                        " and repeat --emergency-reason"
                    } else {
                        ""
                    }
                );
            }
        }
        _ => unreachable!("rollback dispatcher received a non-rollback command"),
    }
    Ok(())
}

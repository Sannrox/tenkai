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
            no_hold,
            reason: hold_skip_reason,
        } => {
            let env = crate::client_config::require_env(env)?;
            // Refuse an invalid flag combination before a plan is stored, so
            // it cannot leave an orphan rollback plan behind.
            if no_hold && !bypass.allow_unapproved_development {
                bail!(
                    "--no-hold applies only when rollback executes now; pass --allow-unapproved-development or clear the hold after apply"
                );
            }
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
            let had_hold = tenkai::delivery_hold::get(
                ctx,
                &tenkai::delivery_hold::HoldScope::environment(&env),
            )
            .await?
            .is_some();
            if bypass.allow_unapproved_development {
                run_plan(
                    ctx,
                    &stored.id,
                    apply::ExecutionOptions {
                        rollback_hold: true,
                        skip_gates: true,
                        emergency_reason: emergency_reason.as_deref(),
                        authorization: apply::ExecutionAuthorization::LocalDevelopment {
                            reason: bypass
                                .development_reason
                                .as_deref()
                                .expect("clap requires a development reason"),
                        },
                        software_executors: tenkai::software_executor::SoftwareExecutors::default(),
                        model_runtime_executor:
                            tenkai::model_runtime::selected_model_runtime_executor_factory(),
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
                    },
                    PlanResultContext {
                        command: CommandName::Rollback,
                        environment: &stored.environment,
                        step_count: stored.steps.len(),
                        output,
                    },
                )
                .await?;
                if no_hold && !had_hold {
                    // `--reason` is required by `--no-hold` but not yet stored: the
                    // hold audit record has no field for it (#1346).
                    let _ = hold_skip_reason;
                    let actor = crate::authorization::embedded_management_actor()?;
                    tenkai::delivery_hold::clear_if_reason(
                        ctx,
                        &tenkai::delivery_hold::HoldScope::environment(&env),
                        actor.principal_id(),
                        tenkai::apply::ROLLBACK_HOLD_REASON,
                    )
                    .await?;
                }
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
            let env = crate::client_config::require_env(env)?;
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
                        rollback_hold: true,
                        skip_gates: true,
                        emergency_reason: emergency_reason.as_deref(),
                        authorization: apply::ExecutionAuthorization::LocalDevelopment {
                            reason: bypass
                                .development_reason
                                .as_deref()
                                .expect("clap requires a development reason"),
                        },
                        software_executors:
                            tenkai::software_executor::SoftwareExecutors::try_from_process()?,
                        model_runtime_executor:
                            tenkai::model_runtime::selected_model_runtime_executor_factory(),
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
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
        Command::Stop {
            product,
            env,
            reason,
            bypass,
            emergency_reason,
            generation: _,
        } => {
            let env = crate::client_config::require_env(env)?;
            let step = plan::stop_step(ctx, &env, &product, &reason).await?;
            store_and_maybe_apply(
                ctx,
                SameVersionCommand {
                    env: &env,
                    step,
                    command: CommandName::Stop,
                    verb: "stop",
                    gerund: "stopping",
                    approval_message: "The stop plan requires signed approval",
                    bypass,
                    emergency_reason,
                    output,
                },
            )
            .await?;
        }
        Command::Start {
            product,
            env,
            bypass,
            emergency_reason,
            generation: _,
        } => {
            let env = crate::client_config::require_env(env)?;
            let step = plan::start_step(ctx, &env, &product).await?;
            store_and_maybe_apply(
                ctx,
                SameVersionCommand {
                    env: &env,
                    step,
                    command: CommandName::Start,
                    verb: "start",
                    gerund: "starting",
                    approval_message: "The start plan requires signed approval",
                    bypass,
                    emergency_reason,
                    output,
                },
            )
            .await?;
        }
        _ => unreachable!("rollback dispatcher received a non-rollback command"),
    }
    Ok(())
}

struct SameVersionCommand<'a> {
    env: &'a str,
    step: tenkai::plan::Step,
    command: CommandName,
    verb: &'a str,
    gerund: &'a str,
    approval_message: &'static str,
    bypass: crate::flags::DevelopmentBypassFlags,
    emergency_reason: Option<String>,
    output: OutputFormat,
}

async fn store_and_maybe_apply(
    ctx: &mut client::Ctx,
    command: SameVersionCommand<'_>,
) -> Result<()> {
    let SameVersionCommand {
        env,
        step,
        command,
        verb,
        gerund,
        approval_message,
        bypass,
        emergency_reason,
        output,
    } = command;
    let stored = plan::create_from_steps(ctx, env, vec![step]).await?;
    if output == OutputFormat::Human {
        println!("{gerund} in {env}:");
        print_steps(&stored.steps);
    }
    if bypass.allow_unapproved_development {
        run_plan(
            ctx,
            &stored.id,
            apply::ExecutionOptions {
                rollback_hold: false,
                skip_gates: true,
                emergency_reason: emergency_reason.as_deref(),
                authorization: apply::ExecutionAuthorization::LocalDevelopment {
                    reason: bypass
                        .development_reason
                        .as_deref()
                        .expect("clap requires a development reason"),
                },
                software_executors: tenkai::software_executor::SoftwareExecutors::try_from_process(
                )?,
                model_runtime_executor:
                    tenkai::model_runtime::selected_model_runtime_executor_factory(),
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
            },
            PlanResultContext {
                command,
                environment: &stored.environment,
                step_count: stored.steps.len(),
                output,
            },
        )
        .await?;
        return Ok(());
    }
    if output == OutputFormat::JsonV1 {
        let mut result = CommandResultV1::failed(
            command,
            "approval_required",
            approval_message,
            RetryGuidance::NotSafe,
        )
        .resource("plan", stored.id)
        .resource("environment", stored.environment)
        .counts(Some(stored.steps.len()), None);
        result.outcome = CommandOutcome::AwaitingApproval;
        return Err(reported_machine_failure(result));
    }
    bail!(
        "{verb} was not executed; plan {} requires signed approval. Run `tenkaictl apply {}` with --approval and --approval-trust-roots{}",
        stored.id,
        stored.id,
        if emergency_reason.is_some() {
            " and repeat --emergency-reason"
        } else {
            ""
        }
    );
}

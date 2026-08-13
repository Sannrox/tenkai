//! Target, recovery, observation, and compensation for one Plan Step.

use super::*;

#[derive(Clone, Copy)]
struct StepContext<'a> {
    lease: &'a EnvironmentLease,
    environment: &'a str,
    plan_id: &'a str,
    software: Option<&'a dyn crate::software_executor::SoftwareExecutor>,
}

/// Execute one immutable Plan Step and durably record its Environment outcome.
pub(super) async fn execute(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    environment: &str,
    plan_id: &str,
    step: &Step,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<Outcome> {
    let step_context = StepContext {
        lease,
        environment,
        plan_id,
        software,
    };
    let target = ReleasePin {
        release_id: step.release_id.clone(),
        digest: step.release_digest.clone(),
        artifact_digest: step.artifact_digest.clone(),
        workdir: step.workdir.clone(),
    };
    let content = admit_release(ctx, &target, environment, &step.product).await?;
    let restore_content = match step.restore.as_ref() {
        Some(pin) => Some(admit_release(ctx, pin, environment, &step.product).await?),
        None => None,
    };

    if step.action == Action::Rollback
        && let Some(outgoing) = restore_content.as_ref()
        && outgoing
            .manifest
            .deploy
            .uninstall
            .as_deref()
            .is_some_and(|command| !command.is_empty())
    {
        let cleanup_failure =
            match product_execution::deactivate(ctx, lease, outgoing, software).await {
                Ok(Ok(())) => None,
                Ok(Err(detail)) => Some(detail),
                Err(error) => Some(format!("cleanup executor failed: {error}")),
            };
        if let Some(detail) = cleanup_failure {
            let outcome = Outcome::new(
                step.clone(),
                StepOutcomeStatus::Failed,
                format!("rollback blocked: outgoing release cleanup failed: {detail}"),
            );
            record(
                ctx,
                lease,
                environment,
                plan_id,
                &outcome,
                crate::environment::DeploymentTransition::Unknown,
            )
            .await?;
            return Ok(outcome);
        }
    }

    let activation = match product_execution::activate(ctx, lease, &content, software).await {
        Ok(result) => result,
        Err(error) => Err(format!("deployment executor failed: {error}")),
    };
    let outcome = match activation {
        Ok(()) => {
            let outcome = Outcome::new(step.clone(), StepOutcomeStatus::Succeeded, String::new());
            if let Err(error) = record(
                ctx,
                lease,
                environment,
                plan_id,
                &outcome,
                crate::environment::DeploymentTransition::Deployed {
                    version: step.to.clone(),
                    previous: step.from.clone(),
                },
            )
            .await
            {
                compensate_activation(ctx, lease, environment, step, &content, &error, software)
                    .await;
                return Err(error);
            }
            return Ok(outcome);
        }
        Err(detail) => {
            recover_activation(
                ctx,
                step_context,
                step,
                &content,
                restore_content.as_ref(),
                detail,
            )
            .await?
        }
    };

    let (outcome, transition) = outcome;
    if let Some(transition) = transition {
        record(ctx, lease, environment, plan_id, &outcome, transition).await?;
    }
    Ok(outcome)
}

async fn recover_activation(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    step: &Step,
    content: &ReleaseContent,
    restore_content: Option<&ReleaseContent>,
    detail: String,
) -> Result<(Outcome, Option<crate::environment::DeploymentTransition>)> {
    let (cleaned, detail) = product_execution::cleanup_failed_activation(
        ctx,
        step_context.lease,
        content,
        detail,
        step_context.software,
    )
    .await?;
    let Some(previous) = step.from.as_deref() else {
        return Ok((
            Outcome::new(step.clone(), StepOutcomeStatus::Failed, detail),
            Some(if cleaned {
                crate::environment::DeploymentTransition::Unchanged
            } else {
                crate::environment::DeploymentTransition::Unknown
            }),
        ));
    };
    let Some(previous_content) = restore_content else {
        let outcome = Outcome::new(
            step.clone(),
            StepOutcomeStatus::Failed,
            format!("{detail}; step {} has no pinned restore release", step.id),
        );
        record(
            ctx,
            step_context.lease,
            step_context.environment,
            step_context.plan_id,
            &outcome,
            crate::environment::DeploymentTransition::Unknown,
        )
        .await?;
        return Ok((outcome, None));
    };
    let (restored, detail) = restore_previous(
        ctx,
        step_context.lease,
        previous_content,
        previous,
        detail,
        step_context.software,
    )
    .await?;
    let recovered = cleaned && restored;
    Ok((
        Outcome::new(
            step.clone(),
            if recovered {
                StepOutcomeStatus::RolledBack
            } else {
                StepOutcomeStatus::Failed
            },
            detail,
        ),
        Some(if recovered {
            crate::environment::DeploymentTransition::Unchanged
        } else {
            crate::environment::DeploymentTransition::Unknown
        }),
    ))
}

async fn restore_previous(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    content: &ReleaseContent,
    version: &str,
    failure: String,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) -> Result<(bool, String)> {
    let channel_note = crate::software_executor::rollback_channel_note(&content.product, version);
    let restore_result = match product_execution::activate(ctx, lease, content, software).await {
        Ok(Ok(())) => Ok(Ok(())),
        Ok(Err(detail)) => Ok(Err(crate::software_executor::format_software_phase_error(
            crate::software_executor::SoftwareDeployPhase::Restore,
            &content.product,
            version,
            &content.environment,
            &detail,
        ))),
        Err(error) => Err(error),
    };
    Ok(match restore_result {
        Ok(Ok(())) => (
            true,
            format!("{failure}; restored {version}; {channel_note}"),
        ),
        Ok(Err(restore)) => (
            false,
            format!(
                "{failure}; restore or health check of {version} also failed: {restore}; {channel_note}"
            ),
        ),
        Err(error) => (
            false,
            format!(
                "{failure}; restore executor failed for {version}: {}; {channel_note}",
                crate::software_executor::format_software_phase_error(
                    crate::software_executor::SoftwareDeployPhase::Restore,
                    &content.product,
                    version,
                    &content.environment,
                    &error.to_string(),
                )
            ),
        ),
    })
}

async fn compensate_activation(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    environment: &str,
    step: &Step,
    content: &ReleaseContent,
    failure: &anyhow::Error,
    software: Option<&dyn crate::software_executor::SoftwareExecutor>,
) {
    let failure = format!("deployment bookkeeping failed after activation: {failure}");
    let cleaned = matches!(
        product_execution::deactivate(ctx, lease, content, software).await,
        Ok(Ok(()))
    );
    let mut restored = step.from.is_none();
    if let (Some(previous), Some(pin)) = (step.from.as_deref(), step.restore.as_ref())
        && let Ok(previous_content) = admit_release(ctx, pin, environment, &step.product).await
        && matches!(
            product_execution::activate(ctx, lease, &previous_content, software).await,
            Ok(Ok(()))
        )
    {
        restored = crate::environment::record_deployed(
            ctx,
            lease,
            environment,
            &step.product,
            previous,
            Some(&step.to),
        )
        .await
        .is_ok();
    }
    if !cleaned || !restored || step.from.is_none() {
        let _ =
            crate::environment::record_unknown(ctx, lease, environment, &step.product, &failure)
                .await;
    }
}

async fn record(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    environment: &str,
    plan_id: &str,
    outcome: &Outcome,
    transition: crate::environment::DeploymentTransition,
) -> Result<()> {
    crate::environment::record_deployment_observation(
        ctx,
        lease,
        crate::environment::DeploymentObservation {
            environment,
            plan_id,
            step: &outcome.step,
            status: &outcome.status,
            detail: &outcome.detail,
            transition,
        },
    )
    .await
}

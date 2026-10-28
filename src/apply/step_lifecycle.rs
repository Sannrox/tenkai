//! Target, recovery, observation, and compensation for one Plan Step.

use super::*;

#[derive(Clone)]
struct StepContext<'a> {
    lease: &'a EnvironmentLease,
    environment: &'a str,
    plan_id: &'a str,
    adapters: TargetAdapters<'a>,
    /// When this step's execution began, for its feedback observation (#802).
    started_at_ms: i64,
}

/// Execute one immutable Plan Step and durably record its Environment outcome.
pub(super) async fn execute(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &Plan,
    step: &Step,
    adapters: TargetAdapters<'_>,
    recalled_recovery: bool,
    skip_gates: bool,
) -> Result<Outcome> {
    let started_at_ms = crate::now_millis();
    let environment = plan.environment.as_str();
    let plan_id = plan.id.as_str();
    let step_context = StepContext {
        lease,
        environment,
        plan_id,
        adapters: adapters.clone(),
        started_at_ms,
    };
    let target = ReleasePin {
        release_id: step.release_id.clone(),
        digest: step.release_digest.clone(),
        artifact_digest: step.artifact_digest.clone(),
        workdir: step.workdir.clone(),
    };
    let admit_recalled = recalled_recovery && step.action == Action::Rollback;
    let mut content =
        admit_release(ctx, &target, environment, &step.product, admit_recalled).await?;
    let mut restore_content = match step.restore.as_ref() {
        Some(pin) => {
            Some(admit_release(ctx, pin, environment, &step.product, admit_recalled).await?)
        }
        None => None,
    };
    let env_object = crate::environment::environment(ctx, environment).await?;
    content.artifact_pulls = crate::oci_artifact::verify_environment_pull(
        &content.manifest.artifacts,
        &env_object.properties,
        adapters.artifact_registry,
    )?;
    if let Some(restore) = restore_content.as_mut() {
        restore.artifact_pulls = crate::oci_artifact::verify_environment_pull(
            &restore.manifest.artifacts,
            &env_object.properties,
            adapters.artifact_registry,
        )?;
    }

    crate::software_compatibility::require_manifest(
        ctx,
        environment,
        &content.manifest,
        &content.manifest_digest,
    )
    .await?;
    // Replica facts may have moved since the plan was made (#689). The
    // release a failure would restore is checked too, before anything is
    // removed, so neither outcome lands in a placement its manifest forbids.
    crate::topology::require_manifest_placement(ctx, environment, &content.manifest).await?;
    if let Some(restore) = restore_content.as_ref() {
        crate::topology::require_manifest_placement(ctx, environment, &restore.manifest).await?;
    }
    if !skip_gates
        && crate::health_gate::step_requires_slo_evaluation(ctx, environment, step).await?
    {
        crate::health_gate::resolve_spec(ctx, environment, &step.product, &content.manifest.gate)
            .await?;
    }

    let mut outgoing_removed = false;
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
            match product_execution::deactivate(ctx, lease, outgoing, adapters.clone()).await {
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
                started_at_ms,
                lease,
                environment,
                plan_id,
                &outcome,
                crate::environment::DeploymentTransition::Unknown,
            )
            .await?;
            return Ok(outcome);
        }
        outgoing_removed = true;
    }

    let activation = match if step.action == Action::Restart {
        product_execution::restart(ctx, lease, &content, adapters.clone()).await
    } else {
        product_execution::activate(ctx, lease, &content, adapters.clone()).await
    } {
        Ok(result) => result,
        // Admission refusals before any mutation: nothing to clean up.
        Err(error)
            if error
                .downcast_ref::<crate::software_compatibility::CompatibilityBlocked>()
                .is_some()
                || error
                    .downcast_ref::<crate::topology::PlacementRefused>()
                    .is_some() =>
        {
            if outgoing_removed {
                let outcome =
                    Outcome::new(step.clone(), StepOutcomeStatus::Blocked, error.to_string());
                record(
                    ctx,
                    started_at_ms,
                    lease,
                    environment,
                    plan_id,
                    &outcome,
                    crate::environment::DeploymentTransition::Unknown,
                )
                .await?;
            }
            return Err(error);
        }
        Err(error) => Err(format!("deployment executor failed: {error}")),
    };
    let outcome = match activation {
        Ok(()) => {
            match crate::health_gate::decide_after_success(
                ctx,
                lease,
                plan,
                step,
                skip_gates,
                &content.manifest.gate,
            )
            .await
            {
                Ok(None) => {}
                Ok(Some(decision))
                    if decision.action == crate::manifest::GateFailPolicy::Rollback =>
                {
                    return restore_after_health_gate(
                        ctx,
                        step_context,
                        step,
                        decision.evidence.summary(),
                    )
                    .await;
                }
                Ok(Some(decision)) => {
                    let outcome = decision.halted_outcome(step);
                    let transition = if step.action == Action::Restart {
                        crate::environment::DeploymentTransition::Refreshed
                    } else {
                        crate::environment::DeploymentTransition::Deployed {
                            version: step.to.clone(),
                            previous: step.from.clone(),
                        }
                    };
                    if let Err(error) = record(
                        ctx,
                        started_at_ms,
                        lease,
                        environment,
                        plan_id,
                        &outcome,
                        transition,
                    )
                    .await
                    {
                        compensate_activation(
                            ctx,
                            lease,
                            environment,
                            step,
                            &content,
                            &error,
                            adapters.clone(),
                        )
                        .await;
                        return Err(error);
                    }
                    return Ok(outcome);
                }
                Err(error) => {
                    compensate_activation(
                        ctx,
                        lease,
                        environment,
                        step,
                        &content,
                        &error,
                        adapters.clone(),
                    )
                    .await;
                    return Err(error);
                }
            }
            let outcome = Outcome::new(step.clone(), StepOutcomeStatus::Succeeded, String::new());
            let transition = if step.action == Action::Restart {
                crate::environment::DeploymentTransition::Refreshed
            } else {
                crate::environment::DeploymentTransition::Deployed {
                    version: step.to.clone(),
                    previous: step.from.clone(),
                }
            };
            if let Err(error) = record(
                ctx,
                started_at_ms,
                lease,
                environment,
                plan_id,
                &outcome,
                transition,
            )
            .await
            {
                compensate_activation(
                    ctx,
                    lease,
                    environment,
                    step,
                    &content,
                    &error,
                    adapters.clone(),
                )
                .await;
                return Err(error);
            }
            return Ok(outcome);
        }
        Err(detail) if detail.contains("waiting for bounded drain") => (
            Outcome::new(step.clone(), StepOutcomeStatus::Blocked, detail),
            Some(crate::environment::DeploymentTransition::Unknown),
        ),
        Err(detail) if step.action == Action::Restart => {
            recover_restart(ctx, step_context, step, &content, detail).await?
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
        record(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            &outcome,
            transition,
        )
        .await?;
    }
    Ok(outcome)
}

async fn recover_restart(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    step: &Step,
    content: &ReleaseContent,
    detail: String,
) -> Result<(Outcome, Option<crate::environment::DeploymentTransition>)> {
    let reapplied = matches!(
        product_execution::activate(
            ctx,
            step_context.lease,
            content,
            step_context.adapters.clone()
        )
        .await,
        Ok(Ok(()))
    );
    Ok((
        Outcome::new(
            step.clone(),
            StepOutcomeStatus::Failed,
            if reapplied {
                format!("{detail}; current pin remains deployed")
            } else {
                format!("{detail}; re-apply of the current pin also failed")
            },
        ),
        Some(if reapplied {
            crate::environment::DeploymentTransition::Refreshed
        } else {
            crate::environment::DeploymentTransition::Unknown
        }),
    ))
}

async fn recover_activation(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    step: &Step,
    content: &ReleaseContent,
    restore_content: Option<&ReleaseContent>,
    detail: String,
) -> Result<(Outcome, Option<crate::environment::DeploymentTransition>)> {
    let started_at_ms = step_context.started_at_ms;
    let (cleaned, detail) = product_execution::cleanup_failed_activation(
        ctx,
        step_context.lease,
        content,
        detail,
        step_context.adapters.clone(),
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
            started_at_ms,
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
        step_context.adapters,
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
    adapters: TargetAdapters<'_>,
) -> Result<(bool, String)> {
    let channel_note = crate::software_executor::rollback_channel_note(&content.product, version);
    let restore_result = match product_execution::activate(ctx, lease, content, adapters).await {
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
    adapters: TargetAdapters<'_>,
) {
    if step.action == Action::Restart {
        return;
    }
    let failure = format!("deployment bookkeeping failed after activation: {failure}");
    let cleaned = matches!(
        product_execution::deactivate(ctx, lease, content, adapters.clone()).await,
        Ok(Ok(()))
    );
    let mut restored = step.from.is_none();
    if let (Some(previous), Some(pin)) = (step.from.as_deref(), step.restore.as_ref())
        && let Ok(previous_content) =
            admit_release(ctx, pin, environment, &step.product, false).await
        && matches!(
            product_execution::activate(ctx, lease, &previous_content, adapters).await,
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

/// Restore the plan's previous signed pin after a failing SLO gate (#590).
///
/// Activation already succeeded, but this path runs before any success
/// observation is recorded. It deactivates the new release, activates the
/// restore pin, and records `RolledBack` so the same execution does not
/// re-evaluate SLO gates (#549). Admission or pull failures leave the new
/// release running, so bookkeeping records that live version and the failed
/// target instead of returning with a stale prior deploy.
async fn restore_after_health_gate(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    step: &Step,
    detail: String,
) -> Result<Outcome> {
    let StepContext {
        lease,
        environment,
        plan_id,
        adapters,
        started_at_ms,
    } = step_context;
    let Some(pin) = step.restore.as_ref() else {
        return record_live_restore_failure(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            step,
            format!("{detail}; automatic rollback refused: no restore pin"),
        )
        .await;
    };
    let mut current = match admit_release(
        ctx,
        &ReleasePin {
            release_id: step.release_id.clone(),
            digest: step.release_digest.clone(),
            artifact_digest: step.artifact_digest.clone(),
            workdir: step.workdir.clone(),
        },
        environment,
        &step.product,
        false,
    )
    .await
    {
        Ok(content) => content,
        Err(error) => {
            return record_live_restore_failure(
                ctx,
                started_at_ms,
                lease,
                environment,
                plan_id,
                step,
                format!("{detail}; automatic rollback blocked: {error}"),
            )
            .await;
        }
    };
    let mut previous = match admit_release(ctx, pin, environment, &step.product, false).await {
        Ok(content) => content,
        Err(error) => {
            return record_live_restore_failure(
                ctx,
                started_at_ms,
                lease,
                environment,
                plan_id,
                step,
                format!("{detail}; automatic rollback blocked: {error}"),
            )
            .await;
        }
    };
    if let Err(error) =
        admit_artifact_pulls(ctx, environment, adapters.artifact_registry, &mut current).await
    {
        return record_live_restore_failure(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            step,
            format!("{detail}; automatic rollback blocked: {error}"),
        )
        .await;
    }
    if let Err(error) =
        admit_artifact_pulls(ctx, environment, adapters.artifact_registry, &mut previous).await
    {
        return record_live_restore_failure(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            step,
            format!("{detail}; automatic rollback blocked: {error}"),
        )
        .await;
    }
    if let Err(error) = crate::software_compatibility::require_manifest(
        ctx,
        environment,
        &previous.manifest,
        &previous.manifest_digest,
    )
    .await
    {
        return record_live_restore_failure(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            step,
            format!("{detail}; automatic rollback blocked: {error}"),
        )
        .await;
    }
    // Checked before the current release is deactivated, so a refused
    // placement leaves it in place instead of half-rolled-back.
    if let Err(error) =
        crate::topology::require_manifest_placement(ctx, environment, &previous.manifest).await
    {
        return record_live_restore_failure(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            step,
            format!("{detail}; automatic rollback blocked: {error}"),
        )
        .await;
    }
    let software_shell_without_cleanup = current.manifest.product.kind.policy().target()
        == crate::product_kind::ProductTarget::Software
        && adapters.software.is_none()
        && current
            .manifest
            .deploy
            .uninstall
            .as_deref()
            .is_none_or(|command| command.is_empty());
    if !software_shell_without_cleanup {
        match product_execution::deactivate(ctx, lease, &current, adapters.clone()).await {
            Ok(Ok(())) => {}
            Ok(Err(cleanup)) => {
                let outcome = Outcome::new(
                    step.clone(),
                    StepOutcomeStatus::Failed,
                    format!(
                        "{detail}; automatic rollback blocked: outgoing release cleanup failed: {cleanup}"
                    ),
                );
                record(
                    ctx,
                    started_at_ms,
                    lease,
                    environment,
                    plan_id,
                    &outcome,
                    crate::environment::DeploymentTransition::Unknown,
                )
                .await?;
                return Ok(outcome);
            }
            Err(error) => {
                let outcome = Outcome::new(
                    step.clone(),
                    StepOutcomeStatus::Failed,
                    format!(
                        "{detail}; automatic rollback blocked: outgoing release cleanup failed: {error}"
                    ),
                );
                record(
                    ctx,
                    started_at_ms,
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
    }
    let version = step
        .from
        .as_deref()
        .unwrap_or(&previous.manifest.product.version);
    let (restored, detail) =
        restore_previous(ctx, lease, &previous, version, detail, adapters).await?;
    let outcome = Outcome::new(
        step.clone(),
        if restored {
            StepOutcomeStatus::RolledBack
        } else {
            StepOutcomeStatus::Failed
        },
        detail,
    );
    record(
        ctx,
        started_at_ms,
        lease,
        environment,
        plan_id,
        &outcome,
        if restored {
            // Keep the environment's existing rollback history. The rejected
            // release never recorded a successful deploy, so it must not become
            // the next ordinary rollback destination.
            crate::environment::DeploymentTransition::Unchanged
        } else {
            crate::environment::DeploymentTransition::Unknown
        },
    )
    .await?;
    Ok(outcome)
}

async fn record_live_restore_failure(
    ctx: &mut Ctx,
    started_at_ms: i64,
    lease: &EnvironmentLease,
    environment: &str,
    plan_id: &str,
    step: &Step,
    detail: String,
) -> Result<Outcome> {
    let outcome = Outcome::new(step.clone(), StepOutcomeStatus::Failed, detail);
    record(
        ctx,
        started_at_ms,
        lease,
        environment,
        plan_id,
        &outcome,
        crate::environment::DeploymentTransition::Deployed {
            version: step.to.clone(),
            previous: step.from.clone(),
        },
    )
    .await?;
    Ok(outcome)
}

async fn admit_artifact_pulls(
    ctx: &mut Ctx,
    environment: &str,
    registry: Option<&dyn crate::oci_artifact::ArtifactRegistry>,
    content: &mut ReleaseContent,
) -> Result<()> {
    let env_object = crate::environment::environment(ctx, environment).await?;
    content.artifact_pulls = crate::oci_artifact::verify_environment_pull(
        &content.manifest.artifacts,
        &env_object.properties,
        registry,
    )?;
    Ok(())
}

async fn record(
    ctx: &mut Ctx,
    started_at_ms: i64,
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
            started_at_ms: Some(started_at_ms),
        },
    )
    .await
}

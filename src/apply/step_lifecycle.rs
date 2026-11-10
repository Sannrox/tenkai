//! Target, recovery, observation, and compensation for one Plan Step.

use super::*;
use crate::host_executor::step::HostStepEnd;

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
    // Removing a recalled release deploys nothing, so it is admitted like an
    // audited recovery; signature and integrity are still checked.
    let admit_recalled =
        (recalled_recovery && step.action == Action::Rollback) || step.action == Action::Remove;
    let mut content = admit_release(ctx, &target, environment, step, admit_recalled).await?;
    let mut restore_content = match step.restore.as_ref() {
        Some(pin) => Some(admit_release(ctx, pin, environment, step, admit_recalled).await?),
        None => None,
    };
    // A host release runs only as a host step, and a host step only runs a
    // host release (ADR 0041 section 2).
    let host_release = !restores_automatically(&content);
    if host_release != step.host.is_some() {
        if host_release {
            bail!(
                "step {} runs host release {} without a host binding; create the plan again",
                step.id,
                step.release_id
            );
        }
        bail!(
            "step {} is a host step, but release {} does not declare deploy.executor = \"host\"",
            step.id,
            step.release_id
        );
    }
    // Each release runs with its own executor (ADR 0041). Check both before
    // anything mutates, so an unavailable one fails closed and is never
    // replaced by another, and refuse a step that changes the product's executor.
    adapters
        .software
        .require_available(content.manifest.deploy.executor)?;
    if let Some(restore) = restore_content.as_ref() {
        adapters
            .software
            .require_available(restore.manifest.deploy.executor)?;
    }
    if step.action != Action::Restart
        && let Some(installed) = step.from.as_deref()
    {
        // The restore pin, when there is one, is the installed release.
        let installed = match restore_content.as_ref() {
            Some(restore) => restore.manifest.deploy.executor,
            None => {
                crate::plan::stored_release_executor(
                    ctx,
                    &crate::ontology::release_id(&step.product, installed),
                )
                .await?
            }
        };
        adapters.software.require_same_executor(
            &step.product,
            installed,
            content.manifest.deploy.executor,
        )?;
    }
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

    // A removal deploys nothing: it need not prove the release is still
    // compatible with, or placeable in, the environment.
    if step.action != Action::Remove {
        crate::software_compatibility::require_manifest(
            ctx,
            environment,
            &content.manifest,
            &content.manifest_digest,
            content.instance_name(),
        )
        .await?;
        // Replica facts may have moved since the plan was made (#689).
        crate::topology::require_manifest_placement(ctx, environment, &content.manifest).await?;
    }
    // The release a failure would restore is checked too, before anything
    // is removed, so neither outcome lands in a placement its manifest
    // forbids.
    if let Some(restore) = restore_content.as_ref() {
        crate::topology::require_manifest_placement(ctx, environment, &restore.manifest).await?;
    }
    if !skip_gates
        && crate::health_gate::step_requires_slo_evaluation(ctx, environment, step).await?
    {
        crate::health_gate::resolve_spec(ctx, environment, &step.product, &content.manifest.gate)
            .await?;
    }

    if let Some(host) = step.host {
        return execute_host(ctx, step_context, plan, step, host, &content).await;
    }
    if step.action == Action::Remove {
        return Box::pin(execute_removal(ctx, step_context, step, &content)).await;
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
                Err(error) if is_execution_fence_lost(&error) => return Err(error),
                Err(error) => Some(format!("cleanup executor failed: {error}")),
            };
        if let Some(detail) = cleanup_failure {
            let mut outcome = Outcome::new(
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
                &mut outcome,
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
                    .is_some()
                || error
                    .downcast_ref::<crate::software_executor::TargetUnavailable>()
                    .is_some() =>
        {
            if outgoing_removed {
                let mut outcome =
                    Outcome::new(step.clone(), StepOutcomeStatus::Blocked, error.to_string());
                record(
                    ctx,
                    started_at_ms,
                    lease,
                    environment,
                    plan_id,
                    &mut outcome,
                    crate::environment::DeploymentTransition::Unknown,
                )
                .await?;
            }
            return Err(error);
        }
        Err(error) if is_execution_fence_lost(&error) => return Err(error),
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
                        decision.evidence.cause(),
                    )
                    .await;
                }
                Ok(Some(decision)) => {
                    let mut outcome = decision.halted_outcome(step);
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
                        &mut outcome,
                        transition,
                    )
                    .await
                    {
                        return Err(compensate_or_fence(
                            ctx,
                            lease,
                            environment,
                            step,
                            &content,
                            adapters.clone(),
                            error,
                        )
                        .await);
                    }
                    return Ok(outcome);
                }
                Err(error) => {
                    return Err(compensate_or_fence(
                        ctx,
                        lease,
                        environment,
                        step,
                        &content,
                        adapters.clone(),
                        error,
                    )
                    .await);
                }
            }
            let mut outcome =
                Outcome::new(step.clone(), StepOutcomeStatus::Succeeded, String::new());
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
                &mut outcome,
                transition,
            )
            .await
            {
                return Err(compensate_or_fence(
                    ctx,
                    lease,
                    environment,
                    step,
                    &content,
                    adapters.clone(),
                    error,
                )
                .await);
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

    let (mut outcome, transition) = outcome;
    if let Some(transition) = transition {
        record(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            &mut outcome,
            transition,
        )
        .await?;
    }
    Ok(outcome)
}

/// Remove the release of a non-host step with its own executor (ADR 0049)
/// and record the outcome. A removal is never restored: a failed one leaves
/// the deployment unknown, and the next plan removes it again. Removing what
/// is already gone succeeds, so a retry after a crash is safe.
async fn execute_removal(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    step: &Step,
    content: &ReleaseContent,
) -> Result<Outcome> {
    let StepContext {
        lease,
        environment,
        plan_id,
        adapters,
        started_at_ms,
    } = step_context;
    // Subscribing does not wait for an apply, so a removal approved and
    // admitted earlier must not remove an instance that is desired again.
    let env_object = crate::environment::environment(ctx, environment).await?;
    let resubscribed = crate::environment::list_subscriptions(ctx, &env_object)
        .await?
        .iter()
        .any(|subscription| subscription.instance == step.instance_name());
    let removed = if resubscribed {
        Err(format!(
            "{environment} subscribes to {} again",
            step.instance_name()
        ))
    } else {
        match product_execution::deactivate(ctx, lease, content, adapters).await {
            Ok(removed) => removed,
            Err(error) if is_execution_fence_lost(&error) => return Err(error),
            Err(error) => Err(format!("removal executor failed: {error}")),
        }
    };
    let (mut outcome, transition) = match removed {
        Ok(()) => (
            Outcome::new(step.clone(), StepOutcomeStatus::Succeeded, String::new()),
            crate::environment::DeploymentTransition::Removed {
                version: step.to.clone(),
            },
        ),
        Err(detail) if resubscribed => (
            Outcome::new(step.clone(), StepOutcomeStatus::Failed, detail),
            crate::environment::DeploymentTransition::Unchanged,
        ),
        Err(detail) => (
            Outcome::new(
                step.clone(),
                StepOutcomeStatus::Failed,
                format!("removal of {} {} failed: {detail}", step.product, step.to),
            ),
            crate::environment::DeploymentTransition::Unknown,
        ),
    };
    record(
        ctx,
        started_at_ms,
        lease,
        environment,
        plan_id,
        &mut outcome,
        transition,
    )
    .await?;
    Ok(outcome)
}

/// Run one host step through the root-side applier and record its outcome.
/// It never restores, re-applies, or cleans up: the applier authorizes one
/// release and one action, once, and a failed step stays failed.
async fn execute_host(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    plan: &Plan,
    step: &Step,
    host: crate::plan::HostStep,
    content: &ReleaseContent,
) -> Result<Outcome> {
    let StepContext {
        lease,
        environment,
        plan_id,
        adapters,
        started_at_ms,
    } = step_context;
    let executor = adapters.software.host()?;
    // The product may have been deployed with another executor since the
    // plan was made; admission leaves host steps to the applier.
    crate::plan::require_host_product(ctx, adapters.software, environment, &step.product).await?;
    // Subscribing does not wait for an apply, so a removal approved and
    // admitted earlier must not uninstall a product that is desired again.
    let resubscribed = host.action == crate::plan::HostAction::Uninstall
        && crate::environment::subscribes(ctx, environment, &step.product).await?;
    let request = match crate::catalog::signature_envelope(ctx, &step.release_id).await {
        Ok(signature) => host_request(
            plan,
            step,
            host,
            content,
            signature,
            adapters.host_approvals,
        )
        .map_err(|error| format!("{error:#}")),
        Err(error) => Err(format!("{error:#}")),
    };
    let sealed = product_execution::sealed_refusal(content);
    let ended = match request {
        _ if resubscribed => HostStepEnd::NotRun(format!(
            "{environment} subscribes to {} again",
            step.product
        )),
        // Only a runtime opens sealed values, so only a runtime spools them.
        _ if sealed.is_some() => HostStepEnd::NotRun(sealed.unwrap_or_default()),
        Ok(request) => match host_dependency_document(ctx, content).await {
            Ok(dependency_document) => {
                let inputs = content.manifest.immutable_inputs();
                crate::host_executor::step::run(
                    &mut super::execution_lease::ApplyMutationFence { ctx, lease },
                    executor,
                    &request,
                    &crate::host_executor::step::SpooledRelease {
                        environment: &content.environment,
                        product: &content.product,
                        release_digest: &content.manifest_digest,
                        root: &content.content_root,
                        inputs: &inputs,
                        artifact_digest: &content.artifact_digest,
                        dependency_document: dependency_document.as_deref(),
                        sealed: None,
                    },
                )
                .await?
            }
            Err(error) => HostStepEnd::NotRun(format!("{error:#}")),
        },
        Err(detail) => HostStepEnd::NotRun(detail),
    };
    let (mut outcome, transition) = match ended {
        HostStepEnd::Recorded(result) if result.outcome.succeeded() => (
            Outcome::new(
                step.clone(),
                StepOutcomeStatus::Succeeded,
                result.detail.clone(),
            ),
            Some(match host.action {
                crate::plan::HostAction::Install => {
                    crate::environment::DeploymentTransition::Deployed {
                        version: step.to.clone(),
                        previous: step.from.clone(),
                    }
                }
                // A health step proves the applied release healthy again,
                // also after a failed health step made it unknown; it
                // leaves the rollback history alone.
                crate::plan::HostAction::Health => {
                    crate::environment::DeploymentTransition::Deployed {
                        version: step.to.clone(),
                        previous: None,
                    }
                }
                crate::plan::HostAction::Uninstall => {
                    crate::environment::DeploymentTransition::Removed {
                        version: step.to.clone(),
                    }
                }
            }),
        ),
        HostStepEnd::Recorded(result) => host_step_failed(
            step,
            format!(
                "host {} of {} {} ended {:?}: {}",
                host.action, step.product, step.to, result.outcome, result.detail
            ),
        ),
        HostStepEnd::Unknown(detail) => host_step_failed(
            step,
            format!(
                "host {} of {} {} failed: {detail}",
                host.action, step.product, step.to
            ),
        ),
        // Nothing ran, so what is deployed did not change.
        HostStepEnd::NotRun(detail) => (
            Outcome::new(
                step.clone(),
                StepOutcomeStatus::Failed,
                format!(
                    "host {} of {} {} did not run: {detail}",
                    host.action, step.product, step.to
                ),
            ),
            Some(crate::environment::DeploymentTransition::Unchanged),
        ),
    };
    let transition = transition.unwrap_or(crate::environment::DeploymentTransition::Unknown);
    if let Err(error) = record(
        ctx,
        started_at_ms,
        lease,
        environment,
        plan_id,
        &mut outcome,
        transition,
    )
    .await
    {
        return Err(
            compensate_or_fence(ctx, lease, environment, step, content, adapters, error).await,
        );
    }
    Ok(outcome)
}

/// The request for `step`: the stored plan, the signed release with its
/// `signature`, and the plan's approval envelopes.
pub(super) fn host_request(
    plan: &Plan,
    step: &Step,
    host: crate::plan::HostStep,
    content: &ReleaseContent,
    signature: crate::release_signing::SignatureEnvelope,
    approvals: &[crate::plan_approval::ApprovalEnvelope],
) -> Result<crate::host_apply::HostApplyRequest> {
    crate::host_apply::HostApplyRequest::new(
        plan,
        &step.id,
        host.action,
        &content.raw_manifest,
        signature,
        approvals,
    )
}

/// The dependency document a host release reads from its spool, when its
/// manifest declares a compatibility profile.
async fn host_dependency_document(
    ctx: &mut Ctx,
    content: &ReleaseContent,
) -> Result<Option<String>> {
    let Some(profile) = &content.manifest.compatibility else {
        return Ok(None);
    };
    let env = crate::environment::environment(ctx, &content.environment).await?;
    crate::dependency_document::json_for_release(
        ctx,
        &env,
        content.instance_name(),
        profile,
        &content.manifest_digest,
    )
    .await
}

use crate::host_executor::step::HOST_NOT_RESTORED;

/// Whether a failure of `content` may trigger unapproved cleanup, restore, or
/// re-apply. A host step authorizes one release and one action, once.
fn restores_automatically(content: &ReleaseContent) -> bool {
    content.manifest.deploy.executor != Some(crate::software_executor::SoftwareExecutorKind::Host)
}

/// A failed host step: no automatic recovery, and the deployment is unknown.
fn host_step_failed(
    step: &Step,
    detail: String,
) -> (Outcome, Option<crate::environment::DeploymentTransition>) {
    let original = DeploymentCause::classify(&detail);
    (
        Outcome::recorded(
            step.clone(),
            StepOutcomeStatus::Failed,
            format!("{detail}; {HOST_NOT_RESTORED}"),
            Some(original),
            Some(DeploymentCause::new(
                DeploymentCausePhase::Restore,
                DeploymentCauseKind::HostNotRestored,
                HOST_NOT_RESTORED,
            )),
        ),
        Some(crate::environment::DeploymentTransition::Unknown),
    )
}

async fn recover_restart(
    ctx: &mut Ctx,
    step_context: StepContext<'_>,
    step: &Step,
    content: &ReleaseContent,
    detail: String,
) -> Result<(Outcome, Option<crate::environment::DeploymentTransition>)> {
    if !restores_automatically(content) {
        return Ok(host_step_failed(step, detail));
    }
    let reapplied = match product_execution::activate(
        ctx,
        step_context.lease,
        content,
        step_context.adapters.clone(),
    )
    .await
    {
        Ok(Ok(())) => true,
        Err(error) if is_execution_fence_lost(&error) => return Err(error),
        Ok(Err(_)) | Err(_) => false,
    };
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
    if !restores_automatically(content) {
        return Ok(host_step_failed(step, detail));
    }
    let original = DeploymentCause::classify(&detail);
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
            Outcome::recorded(
                step.clone(),
                StepOutcomeStatus::Failed,
                detail,
                Some(original),
                None,
            ),
            Some(if cleaned {
                crate::environment::DeploymentTransition::Unchanged
            } else {
                crate::environment::DeploymentTransition::Unknown
            }),
        ));
    };
    let Some(previous_content) = restore_content else {
        let mut outcome = Outcome::recorded(
            step.clone(),
            StepOutcomeStatus::Failed,
            format!("{detail}; step {} has no pinned restore release", step.id),
            Some(original.clone()),
            Some(DeploymentCause::new(
                DeploymentCausePhase::Restore,
                DeploymentCauseKind::RestoreFailed,
                format!("step {} has no pinned restore release", step.id),
            )),
        );
        record(
            ctx,
            started_at_ms,
            step_context.lease,
            step_context.environment,
            step_context.plan_id,
            &mut outcome,
            crate::environment::DeploymentTransition::Unknown,
        )
        .await?;
        return Ok((outcome, None));
    };
    let (restored, detail, restore) = restore_previous(
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
        Outcome::recorded(
            step.clone(),
            if recovered {
                StepOutcomeStatus::RolledBack
            } else {
                StepOutcomeStatus::Failed
            },
            detail,
            Some(original),
            Some(restore),
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
) -> Result<(bool, String, DeploymentCause)> {
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
        Err(error) if is_execution_fence_lost(&error) => return Err(error),
        Err(error) => Err(error),
    };
    Ok(match restore_result {
        Ok(Ok(())) => (
            true,
            format!("{failure}; restored {version}; {channel_note}"),
            DeploymentCause::new(
                DeploymentCausePhase::Restore,
                DeploymentCauseKind::Restored,
                format!("restored {version}"),
            ),
        ),
        Ok(Err(restore)) => (
            false,
            format!(
                "{failure}; restore or health check of {version} also failed: {restore}; {channel_note}"
            ),
            DeploymentCause::new(
                DeploymentCausePhase::Restore,
                DeploymentCauseKind::RestoreFailed,
                format!("restore or health check of {version} also failed"),
            )
            .with_raw(restore),
        ),
        Err(error) => {
            let wrapped = crate::software_executor::format_software_phase_error(
                crate::software_executor::SoftwareDeployPhase::Restore,
                &content.product,
                version,
                &content.environment,
                &error.to_string(),
            );
            (
                false,
                format!(
                    "{failure}; restore executor failed for {version}: {wrapped}; {channel_note}"
                ),
                DeploymentCause::new(
                    DeploymentCausePhase::Restore,
                    DeploymentCauseKind::RestoreFailed,
                    format!("restore executor failed for {version}"),
                )
                .with_raw(wrapped),
            )
        }
    })
}

async fn compensate_or_fence(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    environment: &str,
    step: &Step,
    content: &ReleaseContent,
    adapters: TargetAdapters<'_>,
    error: anyhow::Error,
) -> anyhow::Error {
    if is_execution_fence_lost(&error) {
        return error;
    }
    match compensate_activation(ctx, lease, environment, step, content, &error, adapters).await {
        Err(compensate) if is_execution_fence_lost(&compensate) => compensate,
        _ => error,
    }
}

async fn compensate_activation(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    environment: &str,
    step: &Step,
    content: &ReleaseContent,
    failure: &anyhow::Error,
    adapters: TargetAdapters<'_>,
) -> Result<()> {
    if step.action == Action::Restart {
        return Ok(());
    }
    let failure = format!("deployment bookkeeping failed after activation: {failure}");
    if !restores_automatically(content) {
        let _ = crate::environment::record_unknown(
            ctx,
            lease,
            environment,
            &step.product,
            step.instance_name(),
            &failure,
        )
        .await;
        return Ok(());
    }
    let cleaned = match product_execution::deactivate(ctx, lease, content, adapters.clone()).await {
        Ok(Ok(())) => true,
        Err(error) if is_execution_fence_lost(&error) => return Err(error),
        Ok(Err(_)) | Err(_) => false,
    };
    let mut restored = step.from.is_none();
    if let (Some(previous), Some(pin)) = (step.from.as_deref(), step.restore.as_ref())
        && let Ok(previous_content) = admit_release(ctx, pin, environment, step, false).await
    {
        match product_execution::activate(ctx, lease, &previous_content, adapters).await {
            Ok(Ok(())) => {
                restored = crate::environment::record_deployed(
                    ctx,
                    lease,
                    environment,
                    step,
                    previous,
                    Some(&step.to),
                )
                .await
                .is_ok();
            }
            Err(error) if is_execution_fence_lost(&error) => return Err(error),
            Ok(Err(_)) | Err(_) => {}
        }
    }
    if !cleaned || !restored || step.from.is_none() {
        let _ = crate::environment::record_unknown(
            ctx,
            lease,
            environment,
            &step.product,
            step.instance_name(),
            &failure,
        )
        .await;
    }
    Ok(())
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
    original: DeploymentCause,
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
            detail,
            original,
            "automatic rollback refused: no restore pin".into(),
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
        step,
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
                detail.clone(),
                original.clone(),
                format!("automatic rollback blocked: {error}"),
            )
            .await;
        }
    };
    if !restores_automatically(&current) {
        return record_live_restore_failure(
            ctx,
            started_at_ms,
            lease,
            environment,
            plan_id,
            step,
            detail.clone(),
            original.clone(),
            HOST_NOT_RESTORED.into(),
        )
        .await;
    }
    let mut previous = match admit_release(ctx, pin, environment, step, false).await {
        Ok(content) => content,
        Err(error) => {
            return record_live_restore_failure(
                ctx,
                started_at_ms,
                lease,
                environment,
                plan_id,
                step,
                detail.clone(),
                original.clone(),
                format!("automatic rollback blocked: {error}"),
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
            detail.clone(),
            original.clone(),
            format!("automatic rollback blocked: {error}"),
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
            detail.clone(),
            original.clone(),
            format!("automatic rollback blocked: {error}"),
        )
        .await;
    }
    if let Err(error) = crate::software_compatibility::require_manifest(
        ctx,
        environment,
        &previous.manifest,
        &previous.manifest_digest,
        previous.instance_name(),
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
            detail.clone(),
            original.clone(),
            format!("automatic rollback blocked: {error}"),
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
            detail.clone(),
            original.clone(),
            format!("automatic rollback blocked: {error}"),
        )
        .await;
    }
    let software_shell_without_cleanup = current.manifest.product.kind.policy().target()
        == crate::product_kind::ProductTarget::Software
        && adapters
            .software
            .resolve(current.manifest.deploy.executor)?
            .is_none()
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
                let mut outcome = Outcome::recorded(
                    step.clone(),
                    StepOutcomeStatus::Failed,
                    format!(
                        "{detail}; automatic rollback blocked: outgoing release cleanup failed: {cleanup}"
                    ),
                    Some(original.clone()),
                    Some(
                        DeploymentCause::new(
                            DeploymentCausePhase::Cleanup,
                            DeploymentCauseKind::CleanupFailed,
                            "outgoing release cleanup failed",
                        )
                        .with_raw(cleanup),
                    ),
                );
                record(
                    ctx,
                    started_at_ms,
                    lease,
                    environment,
                    plan_id,
                    &mut outcome,
                    crate::environment::DeploymentTransition::Unknown,
                )
                .await?;
                return Ok(outcome);
            }
            Err(error) if is_execution_fence_lost(&error) => return Err(error),
            Err(error) => {
                let mut outcome = Outcome::recorded(
                    step.clone(),
                    StepOutcomeStatus::Failed,
                    format!(
                        "{detail}; automatic rollback blocked: outgoing release cleanup failed: {error}"
                    ),
                    Some(original.clone()),
                    Some(
                        DeploymentCause::new(
                            DeploymentCausePhase::Cleanup,
                            DeploymentCauseKind::CleanupFailed,
                            "outgoing release cleanup failed",
                        )
                        .with_raw(error.to_string()),
                    ),
                );
                record(
                    ctx,
                    started_at_ms,
                    lease,
                    environment,
                    plan_id,
                    &mut outcome,
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
    let (restored, detail, restore) =
        restore_previous(ctx, lease, &previous, version, detail, adapters).await?;
    let mut outcome = Outcome::recorded(
        step.clone(),
        if restored {
            StepOutcomeStatus::RolledBack
        } else {
            StepOutcomeStatus::Failed
        },
        detail,
        Some(original),
        Some(restore),
    );
    record(
        ctx,
        started_at_ms,
        lease,
        environment,
        plan_id,
        &mut outcome,
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

#[allow(clippy::too_many_arguments)]
async fn record_live_restore_failure(
    ctx: &mut Ctx,
    started_at_ms: i64,
    lease: &EnvironmentLease,
    environment: &str,
    plan_id: &str,
    step: &Step,
    detail: String,
    original: DeploymentCause,
    restore_reason: String,
) -> Result<Outcome> {
    let restore_kind = if restore_reason.contains(HOST_NOT_RESTORED) {
        DeploymentCauseKind::HostNotRestored
    } else {
        DeploymentCauseKind::RestoreFailed
    };
    let mut outcome = Outcome::recorded(
        step.clone(),
        StepOutcomeStatus::Failed,
        format!("{detail}; {restore_reason}"),
        Some(original),
        Some(
            DeploymentCause::new(
                DeploymentCausePhase::Restore,
                restore_kind,
                restore_reason.clone(),
            )
            .with_raw(restore_reason),
        ),
    );
    record(
        ctx,
        started_at_ms,
        lease,
        environment,
        plan_id,
        &mut outcome,
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
    outcome: &mut Outcome,
    transition: crate::environment::DeploymentTransition,
) -> Result<()> {
    outcome.attempt_id = Some(
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
                cause: outcome.cause.as_ref(),
                restore: outcome.restore.as_ref(),
            },
        )
        .await?,
    );
    Ok(())
}

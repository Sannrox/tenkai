//! Plan execution: eval gates, install commands, health probes, SLO gates, auto-rollback.
//!
//! Every execution writes durable plan and deployment objects so Tenkai can
//! answer "what ran, when, gated by what, and what happened" after the fact.

use crate::client::Ctx;
use crate::manifest::{self, Manifest};
use crate::plan::{self, Action, Plan, PlanState, ReleasePin, Step};
use crate::routing::RoutingConfigExecutor as _;
use anyhow::{Context as _, Result, bail};

mod cancel;
mod execution_admission;
mod execution_attempt;
mod execution_lease;
#[cfg(test)]
mod host_step_tests;
mod outcome;
mod plan_completion;
mod product_execution;
mod release_content;
#[cfg(test)]
mod release_executor_tests;
mod runtime_release;
mod start_admission;
mod step_lifecycle;

pub(crate) use cancel::hold_after_rollback;
pub use cancel::{
    CancelApplyReport, ROLLBACK_REASON as ROLLBACK_HOLD_REASON, request as cancel_apply,
};
pub(crate) use execution_admission::{CandidateAdmission, classify_candidate};
pub(crate) use execution_lease::{
    ENVIRONMENT_LEASE_NAMESPACE, EnvironmentLease, claim_environment,
    claim_environment_for_completion, claim_environment_for_drill, environment_lease_status,
    is_execution_fence_lost, refresh_environment_lease, release_environment,
    release_environment_fence, runtime_may_take_over,
};
pub use execution_lease::{EnvironmentLeaseInspect, inspect_environment_lease, unlock_environment};
use execution_lease::{
    claim_execution_environment, run_guarded_mutation, run_mutation_command, run_with_lease_renewal,
};
pub use outcome::{
    DeploymentCause, DeploymentCauseKind, DeploymentCausePhase, Outcome, StepOutcomeStatus,
};
use release_content::{ReleaseContent, admit as admit_release, verify_integrity};
pub(crate) use runtime_release::{ReleaseRefused, runtime_release};

#[derive(Clone)]
struct TargetAdapters<'a> {
    software: &'a crate::software_executor::SoftwareExecutors,
    model_runtime: Option<&'a dyn crate::model_runtime::ModelRuntimeExecutorFactory>,
    worker_lifecycle: Option<&'a dyn crate::worker_pool::WorkerLifecyclePort>,
    artifact_registry: Option<&'a dyn crate::oci_artifact::ArtifactRegistry>,
    artifact_registry_handle: Option<std::sync::Arc<dyn crate::oci_artifact::ArtifactRegistry>>,
    /// The plan's approval envelopes, which host steps hand to the root-side
    /// applier; empty for plans without host steps.
    host_approvals: &'a [crate::plan_approval::ApprovalEnvelope],
}

#[allow(deprecated)]
pub use execution_attempt::{
    ExecutionAuthorization, ExecutionOptions, execute, execute_with_options,
};

async fn admit_plan_artifact_pulls(
    ctx: &mut Ctx,
    environment: &str,
    steps: &[Step],
    registry: Option<&dyn crate::oci_artifact::ArtifactRegistry>,
) -> Result<()> {
    let env_object = crate::environment::environment(ctx, environment).await?;
    let mut seen = std::collections::BTreeSet::new();
    for step in steps {
        let restore_id = step.restore.as_ref().map(|pin| pin.release_id.as_str());
        for release_id in std::iter::once(step.release_id.as_str()).chain(restore_id) {
            if !seen.insert(release_id.to_string()) {
                continue;
            }
            let Some(release) = ctx.get(release_id).await? else {
                bail!("release {release_id} is missing during artifact admission");
            };
            let raw = release
                .properties
                .get("manifest")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow::anyhow!("release {release_id} has no stored manifest"))?;
            let parsed = manifest::parse_raw(raw)?;
            crate::oci_artifact::verify_environment_pull(
                &parsed.artifacts,
                &env_object.properties,
                registry,
            )?;
        }
    }
    Ok(())
}

/// Host steps sample no SLO metrics and record no gate evidence; a host
/// release proves health with its approved health step (ADR 0041 section 2).
/// Refuse an SLO gate such a step would otherwise skip, before anything runs.
async fn refuse_host_slo_gate(ctx: &mut Ctx, environment: &str, step: &Step) -> Result<()> {
    if !crate::health_gate::step_requires_slo_evaluation(ctx, environment, step).await? {
        return Ok(());
    }
    let gate =
        crate::health_gate::load_release_gate_section(ctx, &step.release_id, &step.release_digest)
            .await?;
    if !crate::health_gate::resolve_spec(ctx, environment, &step.product, &gate)
        .await?
        .is_empty()
    {
        bail!(
            "host step {} has SLO health gates, which host releases do not evaluate; drop the gate or apply with gates skipped",
            step.id
        );
    }
    Ok(())
}

async fn execute_locked(
    ctx: &mut Ctx,
    mut stored_plan: Plan,
    options: execution_attempt::AttemptExecutionPolicy<'_>,
    lease: &EnvironmentLease,
) -> Result<Vec<Outcome>> {
    let skip_gates = options.skip_gates;
    execution_admission::admit(ctx, &stored_plan).await?;
    crate::delivery_hold::require_not_held(ctx, &stored_plan).await?;
    crate::upgrade_pace::require_for_plan(ctx, &stored_plan, crate::now_millis()).await?;
    let env = stored_plan.environment.clone();
    let steps = stored_plan.steps.clone();
    if let Some(outcomes) = start_admission::admit(
        ctx,
        lease,
        &mut stored_plan,
        start_admission::AdmissionPolicy {
            skip_gates,
            emergency_reason: options.emergency_reason,
        },
    )
    .await?
    {
        return Ok(outcomes);
    }

    if let Err(error) =
        admit_plan_artifact_pulls(ctx, &env, &steps, options.artifact_registry).await
    {
        plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string()).await?;
        return Err(error);
    }

    if !skip_gates {
        for step in steps.iter().filter(|step| step.host.is_some()) {
            if let Err(error) = refuse_host_slo_gate(ctx, &env, step).await {
                plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string())
                    .await?;
                return Err(error);
            }
        }
    }

    if options.delivery_adapter.is_some() && !skip_gates {
        for step in &steps {
            let requires =
                match crate::health_gate::step_requires_slo_evaluation(ctx, &env, step).await {
                    Ok(requires) => requires,
                    Err(error) => {
                        plan_completion::fail(
                            ctx,
                            lease,
                            &mut stored_plan,
                            skip_gates,
                            error.to_string(),
                        )
                        .await?;
                        return Err(error);
                    }
                };
            if !requires {
                continue;
            }
            let spec = match async {
                let release_gate = crate::health_gate::load_release_gate_section(
                    ctx,
                    &step.release_id,
                    &step.release_digest,
                )
                .await?;
                crate::health_gate::resolve_spec(ctx, &env, &step.product, &release_gate).await
            }
            .await
            {
                Ok(spec) => spec,
                Err(error) => {
                    plan_completion::fail(
                        ctx,
                        lease,
                        &mut stored_plan,
                        skip_gates,
                        error.to_string(),
                    )
                    .await?;
                    return Err(error);
                }
            };
            if !spec.is_empty() {
                let error = anyhow::anyhow!(
                    "SLO health gates require built-in execution; delegated delivery cannot evaluate [[gate.slo]]"
                );
                plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string())
                    .await?;
                return Err(error);
            }
        }
    }

    if let Some(adapter) = options.delivery_adapter.clone() {
        if steps.iter().any(|step| step.host.is_some()) {
            let error = anyhow::anyhow!(
                "host steps run only through the root-side applier; delegated delivery cannot run them"
            );
            plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string())
                .await?;
            return Err(error);
        }
        let report = crate::delivery_bridge::execute_bridged_plan(
            ctx,
            adapter.as_ref(),
            &stored_plan,
            crate::delivery_bridge::BridgeExecution {
                expected_environment: &env,
                approval: options
                    .approval
                    .as_ref()
                    .map(|(approval, trust)| (approval.as_path(), trust.as_path())),
                requester: options.requester.as_deref(),
                skip_gates,
                now: crate::now_millis(),
            },
        )
        .await?;
        let status = if report.recovery_required {
            StepOutcomeStatus::Failed
        } else if report.rollback_triggered {
            StepOutcomeStatus::RolledBack
        } else if report.state == PlanState::Succeeded {
            StepOutcomeStatus::Succeeded
        } else if report.state == PlanState::Failed {
            StepOutcomeStatus::Failed
        } else {
            StepOutcomeStatus::Blocked
        };
        if status == StepOutcomeStatus::Succeeded
            && !stored_plan.steps.is_empty()
            && stored_plan
                .steps
                .iter()
                .all(|step| step.action == Action::Rollback)
        {
            let actor = options.requester.as_deref().unwrap_or("apply");
            cancel::hold_after_rollback(
                ctx,
                &stored_plan.environment,
                actor,
                lease.generation,
                &lease.fencing_token,
            )
            .await?;
        }
        return Ok(stored_plan
            .steps
            .iter()
            .cloned()
            .map(|step| Outcome::new(step, status, report.detail.clone()))
            .collect());
    }

    // Host steps hand the plan's approvals to the root-side applier, which
    // verifies them itself (ADR 0041 section 2).
    let host_approvals = if steps.iter().any(|step| step.host.is_some()) {
        match crate::plan_approval::execution_envelopes(
            ctx,
            &stored_plan,
            options
                .approval
                .as_ref()
                .map(|(approval, _)| approval.as_path()),
        )
        .await
        {
            Ok(envelopes) => envelopes,
            Err(error) => {
                plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string())
                    .await?;
                return Err(error);
            }
        }
    } else {
        Vec::new()
    };
    let mut completion = plan_completion::ExecutionCompletion::new();
    let mut remaining = steps.into_iter();

    while let Some(step) = remaining.next() {
        if let Err(error) = refresh_environment_lease(ctx, lease).await {
            let detail = format!("refreshing environment apply lease failed: {error}");
            if is_execution_fence_lost(&error) {
                // Leave the plan Running so min_available still refuses (#690).
                return Err(error);
            }
            plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, &detail).await?;
            return Err(error.context(detail));
        }
        if cancel::matches_lease(ctx, lease).await? {
            completion.skip_remaining(
                std::iter::once(step).chain(remaining),
                cancel::skip_detail(),
                cancel::plan_detail(),
            );
            break;
        }
        let recalled_recovery = stored_plan
            .recalled_recovery_reason
            .as_deref()
            .is_some_and(|reason| !reason.trim().is_empty());
        let adapters = TargetAdapters {
            software: options.software_executors,
            model_runtime: options.model_runtime_executor,
            worker_lifecycle: options.worker_lifecycle,
            artifact_registry: options.artifact_registry,
            artifact_registry_handle: options.artifact_registry_handle.clone(),
            host_approvals: &host_approvals,
        };
        let outcome = match step_lifecycle::execute(
            ctx,
            lease,
            &stored_plan,
            &step,
            adapters,
            recalled_recovery,
            skip_gates,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if is_execution_fence_lost(&error) {
                    return Err(error);
                }
                plan_completion::fail(ctx, lease, &mut stored_plan, skip_gates, error.to_string())
                    .await?;
                return Err(error);
            }
        };
        if completion.record(outcome)? {
            break;
        }
    }

    let rollback_only = stored_plan
        .steps
        .iter()
        .all(|step| step.action == Action::Rollback)
        && !stored_plan.steps.is_empty();
    if rollback_only && completion.all_succeeded() {
        let actor = options.requester.as_deref().unwrap_or("apply");
        cancel::hold_after_rollback(
            ctx,
            &stored_plan.environment,
            actor,
            lease.generation,
            &lease.fencing_token,
        )
        .await?;
    }
    let outcomes = completion
        .finish(ctx, lease, &mut stored_plan, skip_gates)
        .await?;
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DeploySection, GateSection, ProductKind, ProductSection};

    fn test_dir(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tenkai-{name}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn content(workdir: std::path::PathBuf, install: &str) -> ReleaseContent {
        ReleaseContent {
            sealed: Vec::new(),
            manifest_digest: String::new(),
            manifest: Manifest {
                compatibility: None,
                product: ProductSection {
                    name: "api".into(),
                    version: "1.0.0".into(),
                    description: String::new(),
                    kind: ProductKind::Software,
                },
                deploy: DeploySection {
                    workdir: ".".into(),
                    install: install.into(),
                    inputs: Vec::new(),
                    uninstall: None,
                    health: None,
                    executor: None,
                    instances: crate::manifest::DeployInstances::One,
                    identity: None,
                },
                config: None,
                routing: None,
                model: None,
                runtime: None,
                requirements: None,
                model_health: None,
                policy: None,
                eval_suite_product: None,
                agent: None,
                prompt: None,
                module: None,
                change_set_pin: None,
                worker_pool: None,
                artifacts: Vec::new(),
                gate: GateSection::default(),
                delivery: Default::default(),
                inventory: None,
                topology: None,
            },
            artifact_digest: manifest::artifact_digest(&workdir, &[]).unwrap(),
            workdir,
            environment: "test".into(),
            product: "api".into(),
            instance: String::new(),
            mutation_lock: std::env::temp_dir().join("tenkai-test-mutation.lock"),
            routing_state: std::env::temp_dir().join("tenkai-test-routing-state.json"),
            model_runtime_state: std::env::temp_dir().join("tenkai-test-model-runtime-state.json"),
            artifact_pulls: Vec::new(),
            raw_manifest: String::new(),
            content_root: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn mutated_immutable_inputs_are_refused() {
        let dir = test_dir("immutable-inputs");
        std::fs::write(dir.join("deploy.sh"), "original\n").unwrap();
        let mut release = content(dir.clone(), "true");
        release.manifest.deploy.inputs = vec!["deploy.sh".into()];
        release.artifact_digest =
            manifest::artifact_digest(&release.workdir, &release.manifest.deploy.inputs).unwrap();
        std::fs::write(dir.join("deploy.sh"), "changed\n").unwrap();

        let failure = verify_integrity(&release).unwrap_err().to_string();

        assert!(
            failure.contains("immutable deployment inputs changed"),
            "{failure}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_lost_held_lease_stops_a_supervised_command_as_fence_loss() {
        let dir = test_dir("held-command");
        let mut release = content(dir.clone(), "true");
        release.environment = "prod".into();
        release.mutation_lock = dir.join("mutation.lock");
        let mut ctx = Ctx::embedded(dir.join("tenkai.db")).unwrap();
        let held = ctx
            .acquire_lease("tenkai/topology-availability", "ledger-ha", "wave", 60_000)
            .await
            .unwrap();
        ctx.release_lease(
            "tenkai/topology-availability",
            "ledger-ha",
            &held.fencing_token,
        )
        .await
        .unwrap();
        ctx.held_execution_leases = vec![crate::client::HeldExecutionLease::new(
            "tenkai/topology-availability",
            "ledger-ha",
            held.fencing_token,
            60_000,
        )];
        let lease = claim_environment(&mut ctx, "prod", "plan-1").await.unwrap();
        let err = run_mutation_command(&mut ctx, &lease, &release, "true")
            .await
            .unwrap_err();
        assert!(is_execution_fence_lost(&err), "{err:#}");
        assert!(err.to_string().contains("ledger-ha"), "{err:#}");
        let _ = std::fs::remove_dir_all(dir);
    }
}

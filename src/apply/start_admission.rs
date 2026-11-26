//! Evaluation, maintenance, and durable state admission for one Plan start.

use anyhow::{Context as _, Result, bail};

use crate::maintenance::{self, Eligibility};
use crate::model_release_evidence::ModelReleaseEvidenceFailure;

use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct AdmissionPolicy<'a> {
    pub skip_gates: bool,
    pub emergency_reason: Option<&'a str>,
}

pub(super) fn validate_emergency_override(reason: Option<&str>) -> Result<Option<&str>> {
    let reason = reason.map(str::trim);
    if reason.is_some_and(str::is_empty) {
        bail!("emergency maintenance override requires a non-empty reason");
    }
    Ok(reason)
}

pub(super) async fn authorize_maintenance(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    skip_gates: bool,
    emergency_reason: Option<&str>,
) -> Result<()> {
    let authorization = async {
        let decision = maintenance_decision(ctx, plan, emergency_reason).await?;
        if let MaintenanceDecision::EmergencyOverride(reason) = &decision {
            ctx.authorize_emergency_override(&plan.id, reason).await?;
        }
        if let MaintenanceDecision::Denied(detail) = &decision {
            block_for_maintenance(ctx, lease, plan, skip_gates, detail).await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match (authorization, emergency_reason) {
        (Err(error), Some(_)) => {
            let detail = format!("emergency maintenance override was not authorized: {error}");
            match block_for_maintenance(ctx, lease, plan, skip_gates, &detail).await {
                Err(blocked) => Err(blocked.context(detail)),
                Ok(()) => unreachable!("maintenance authorization failure always blocks"),
            }
        }
        (result, _) => result,
    }
}

pub(super) async fn admit(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    policy: AdmissionPolicy<'_>,
) -> Result<Option<Vec<Outcome>>> {
    // A removal deploys nothing, so it need not prove the release could
    // still be deployed here.
    for step in plan
        .steps
        .iter()
        .filter(|step| step.deploys_release() && step.action != Action::Remove)
    {
        crate::software_compatibility::require_release(
            ctx,
            &plan.environment,
            &step.release_id,
            step.instance_name(),
        )
        .await?;
    }
    if !policy.skip_gates {
        if let Some(detail) = crate::exposure::plan_gate_with_admissions(
            ctx,
            &plan.environment,
            &plan.steps,
            &plan.recalled_upgrade,
        )
        .await?
        {
            let step = plan
                .steps
                .iter()
                .find(|step| step.action != Action::Rollback)
                .cloned();
            let outcomes = step.as_ref().map(|step| {
                vec![Outcome::recorded(
                    step.clone(),
                    StepOutcomeStatus::Blocked,
                    detail.clone(),
                    Some(DeploymentCause::gate_blocked("exposure", None, &detail)),
                    None,
                )]
            });
            let observation = plan_completion::plan_observation(
                lease,
                plan,
                step.as_ref(),
                crate::feedback_observation::Operation::PlanBlocked,
                "blocked",
                crate::feedback_observation::Reason::GateBlocked,
            );
            plan_completion::transition_confirmed(
                ctx,
                lease,
                plan,
                PlanState::Blocked,
                policy.skip_gates,
                detail,
                &[observation],
            )
            .await?;
            return Ok(Some(outcomes.unwrap_or_default()));
        }
        for step in &plan.steps.clone() {
            // A removal deploys nothing, so no eval gate applies to it.
            if matches!(
                step.action,
                Action::Rollback | Action::Remove | Action::Stop | Action::Adopt
            ) {
                continue;
            }
            let target = ReleasePin {
                release_id: step.release_id.clone(),
                digest: step.release_digest.clone(),
                artifact_digest: step.artifact_digest.clone(),
                workdir: step.workdir.clone(),
            };
            let content = admit_release(ctx, &target, &plan.environment, step, false).await?;
            let Some(suite) = content
                .manifest
                .gate
                .eval_suite
                .as_deref()
                .filter(|suite| !suite.is_empty())
            else {
                continue;
            };
            let detail = match check_eval_gate(ctx, suite, &step.artifact_digest).await {
                GateDecision::Allowed => continue,
                GateDecision::Denied(detail) | GateDecision::Unavailable(detail) => detail,
            };
            let outcome = Outcome::recorded(
                step.clone(),
                StepOutcomeStatus::Blocked,
                detail.clone(),
                Some(DeploymentCause::gate_blocked(
                    "eval_suite",
                    Some(suite.to_string()),
                    &detail,
                )),
                None,
            );
            let observation = plan_completion::plan_observation(
                lease,
                plan,
                Some(step),
                crate::feedback_observation::Operation::PlanBlocked,
                "blocked",
                crate::feedback_observation::Reason::GateBlocked,
            );
            plan_completion::transition_confirmed(
                ctx,
                lease,
                plan,
                PlanState::Blocked,
                policy.skip_gates,
                detail,
                &[observation],
            )
            .await?;
            return Ok(Some(vec![outcome]));
        }
    }

    let final_maintenance = maintenance_decision(ctx, plan, policy.emergency_reason).await?;
    if let MaintenanceDecision::Denied(detail) = &final_maintenance {
        block_for_maintenance(ctx, lease, plan, policy.skip_gates, detail).await?;
    }
    if let MaintenanceDecision::Allowed { closes_at } = &final_maintenance
        && crate::now_millis() >= *closes_at
    {
        block_for_maintenance(
            ctx,
            lease,
            plan,
            policy.skip_gates,
            "maintenance window closed while start authorization was being recorded",
        )
        .await?;
    }
    plan_completion::transition_confirmed(
        ctx,
        lease,
        plan,
        PlanState::Running,
        policy.skip_gates,
        "",
        &[],
    )
    .await?;
    let running_maintenance = maintenance_decision(ctx, plan, policy.emergency_reason).await?;
    match running_maintenance {
        MaintenanceDecision::Denied(detail) => {
            block_for_maintenance(ctx, lease, plan, policy.skip_gates, &detail).await?;
        }
        MaintenanceDecision::Allowed { closes_at } if crate::now_millis() >= closes_at => {
            block_for_maintenance(
                ctx,
                lease,
                plan,
                policy.skip_gates,
                "maintenance window closed before execution entered the running state",
            )
            .await?;
        }
        MaintenanceDecision::Allowed { .. } | MaintenanceDecision::EmergencyOverride(_) => {}
    }
    Ok(None)
}

async fn maintenance_decision(
    ctx: &mut Ctx,
    plan: &Plan,
    emergency_reason: Option<&str>,
) -> Result<MaintenanceDecision> {
    let now = chrono::DateTime::from_timestamp_millis(crate::now_millis())
        .context("current time is outside the supported maintenance-window range")?;
    let env_eligibility = match maintenance::list(ctx, &plan.environment).await {
        Ok(windows) => maintenance::evaluate(&windows, now),
        Err(error) => Eligibility::Invalid {
            detail: format!("maintenance window configuration is invalid: {error}"),
        },
    };
    let mut eligibility = env_eligibility;
    let mut products: Vec<String> = plan
        .steps
        .iter()
        .filter(|step| step.deploys_release())
        .map(|step| step.product.clone())
        .collect();
    products.sort();
    products.dedup();
    for product in products {
        let product_eligibility = match maintenance::list_product(ctx, &product).await {
            Ok(windows) if windows.is_empty() => continue,
            Ok(windows) => maintenance::evaluate(&windows, now),
            Err(error) => Eligibility::Invalid {
                detail: format!("product maintenance window configuration is invalid: {error}"),
            },
        };
        eligibility = maintenance::intersect(eligibility, product_eligibility);
    }
    if let Some(reason) = emergency_reason {
        return Ok(MaintenanceDecision::EmergencyOverride(reason.into()));
    }
    Ok(match eligibility {
        Eligibility::Open { closes_at, .. } => MaintenanceDecision::Allowed { closes_at },
        Eligibility::Closed { next_opens_at } => {
            MaintenanceDecision::Denied(next_opens_at.map_or_else(
                || "maintenance window is closed".to_string(),
                |next| {
                    format!(
                        "maintenance window is closed; next opens at {}",
                        format_maintenance_timestamp(next)
                    )
                },
            ))
        }
        Eligibility::Invalid { detail } => MaintenanceDecision::Denied(format!(
            "maintenance window evaluation failed closed: {detail}"
        )),
    })
}

fn format_maintenance_timestamp(timestamp_millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(timestamp_millis).map_or_else(
        || format!("unrepresentable timestamp ({timestamp_millis} ms since epoch)"),
        |timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

async fn block_for_maintenance(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    skip_gates: bool,
    detail: &str,
) -> Result<()> {
    let observation = plan_completion::plan_observation(
        lease,
        plan,
        None,
        crate::feedback_observation::Operation::PlanBlocked,
        "blocked",
        crate::feedback_observation::Reason::MaintenanceBlocked,
    );
    plan::transition(
        ctx,
        plan,
        plan::Transition::maintenance_blocked(skip_gates, detail),
        plan::Persistence::Guarded {
            namespace: ENVIRONMENT_LEASE_NAMESPACE,
            key: &lease.environment,
            fencing_token: &lease.fencing_token,
            confirm_ambiguous: false,
            observations: &[observation],
        },
    )
    .await?;
    bail!("{detail}")
}

enum MaintenanceDecision {
    Allowed { closes_at: i64 },
    Denied(String),
    EmergencyOverride(String),
}

enum GateDecision {
    Allowed,
    Denied(String),
    Unavailable(String),
}

async fn check_eval_gate(ctx: &mut Ctx, suite_id: &str, artifact_digest: &str) -> GateDecision {
    match crate::model_release_evidence::admit_eval_suite_gate(ctx, suite_id, artifact_digest).await
    {
        Ok(Ok(())) => GateDecision::Allowed,
        Ok(Err(ModelReleaseEvidenceFailure::Missing)) => GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} has no recorded evaluation evidence bound to this artifact"
        )),
        Ok(Err(ModelReleaseEvidenceFailure::Stale)) => GateDecision::Denied(format!(
            "gate blocked: recorded evaluation evidence for suite {suite_id} is stale"
        )),
        Ok(Err(ModelReleaseEvidenceFailure::Invalid)) => GateDecision::Denied(format!(
            "gate blocked: recorded evaluation evidence for suite {suite_id} is invalid"
        )),
        Err(error) => GateDecision::Unavailable(format!(
            "gate unavailable: could not read recorded evaluation evidence for suite {suite_id}: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_step() -> crate::plan::Step {
        crate::plan::Step {
            id: String::new(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: crate::plan::Action::Rollback,
            from: Some("1.1.0".into()),
            to: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "fixture".into(),
            artifact_digest: "fixture".into(),
            workdir: ".".into(),
            host: None,
            sealed: Vec::new(),
            restore: None,
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
            target_changes: Vec::new(),
            reason: String::new(),
            cluster_namespace: None,
            provision: None,
        }
    }

    /// Blocks and plan-level failures commit no step outcome; each leaves
    /// one observation with its retry and recovery context, and repeating
    /// the same transition under the same lease adds nothing (#803).
    #[tokio::test]
    async fn plan_blocks_and_failures_leave_observations_with_context() {
        use crate::feedback_observation::{Operation, Reason};
        let root =
            std::env::temp_dir().join(format!("tenkai-plan-feedback-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "feedback fixture")
            .await
            .unwrap();
        let mut blocked = crate::plan::create_from_steps_with_recovery(
            &mut ctx,
            "local",
            vec![fixture_step()],
            "incident 7: recalled release is the last good one".into(),
        )
        .await
        .unwrap();
        let lease = crate::apply::claim_environment(&mut ctx, "local", "feedback-test")
            .await
            .unwrap();
        for _ in 0..2 {
            let error =
                block_for_maintenance(&mut ctx, &lease, &mut blocked, false, "window closed")
                    .await
                    .unwrap_err();
            assert_eq!(error.to_string(), "window closed");
        }
        let stored = crate::plan::load(&mut ctx, &blocked.id).await.unwrap();
        assert_eq!(stored.state, crate::plan::PlanState::Blocked);
        assert!(stored.maintenance_blocked);
        let mut failed = crate::plan::create_from_steps(&mut ctx, "local", vec![fixture_step()])
            .await
            .unwrap();
        plan_completion::transition(
            &mut ctx,
            &lease,
            &mut failed,
            crate::plan::PlanState::Running,
            false,
            "",
            &[],
        )
        .await
        .unwrap();
        plan_completion::fail(
            &mut ctx,
            &lease,
            &mut failed,
            false,
            "executor refused: secret=x",
        )
        .await
        .unwrap();

        let observations = ctx
            .catalog_port()
            .unwrap()
            .0
            .feedback_observations(None, "local")
            .unwrap();
        assert_eq!(observations.len(), 2, "{observations:?}");
        let block = &observations[0];
        assert_eq!(
            (block.operation, block.reason, block.plan_id.as_str()),
            (
                Operation::PlanBlocked,
                Reason::MaintenanceBlocked,
                blocked.id.as_str()
            )
        );
        assert_eq!(block.lease_generation, lease.generation);
        assert_eq!(
            block.context.recovery_reason.as_deref(),
            Some("incident 7: recalled release is the last good one")
        );
        let failure = &observations[1];
        assert_eq!(
            (failure.operation, failure.reason, failure.plan_id.as_str()),
            (
                Operation::PlanFailed,
                Reason::PlanFailed,
                failed.id.as_str()
            )
        );
        assert!(!serde_json::to_string(failure).unwrap().contains("secret"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn emergency_override_requires_a_reason() {
        assert!(validate_emergency_override(Some("incident 42")).is_ok());
        assert!(validate_emergency_override(Some("  ")).is_err());
        assert_eq!(validate_emergency_override(None).unwrap(), None);
    }

    #[test]
    fn maintenance_timestamps_are_operator_readable() {
        let timestamp = "2026-07-21T22:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            .timestamp_millis();
        assert_eq!(
            format_maintenance_timestamp(timestamp),
            "2026-07-21T22:00:00Z"
        );
    }

    async fn gated_software_fixture(name: &str) -> (std::path::PathBuf, crate::client::Ctx) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-eval-suite-gate-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let product = root.join("product");
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            "[product]\nname = \"gated-app\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n\n[gate]\neval_suite = \"quality\"\n",
        )
        .unwrap();
        let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::catalog::publish(
            &mut ctx,
            &product.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("eval-suite-gate");
        crate::catalog::promote(&mut ctx, &actor, "gated-app@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::env_add(&mut ctx, "local", "eval-suite gate")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "gated-app", "stable")
            .await
            .unwrap();
        (root, ctx)
    }

    struct SucceedingExecutor;

    impl crate::software_executor::SoftwareExecutor for SucceedingExecutor {
        fn apply(
            &self,
            _request: &crate::software_executor::SoftwareApplyRequest,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn remove(
            &self,
            _request: &crate::software_executor::SoftwareApplyRequest,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn observe(
            &self,
            _request: &crate::software_executor::SoftwareApplyRequest,
        ) -> anyhow::Result<crate::software_executor::SoftwareObserveStatus> {
            Ok(crate::software_executor::SoftwareObserveStatus::Present)
        }
    }

    async fn apply_local(
        ctx: &mut crate::client::Ctx,
    ) -> anyhow::Result<Vec<crate::apply::Outcome>> {
        let plan = crate::plan::create(ctx, "local").await?;
        crate::apply::execute_with_options(
            ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                rollback_hold: true,
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "eval-suite gate fixture",
                },
                software_executors: crate::software_executor::SoftwareExecutors::with_default(
                    std::sync::Arc::new(SucceedingExecutor),
                ),
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
            },
        )
        .await
    }

    #[tokio::test]
    async fn eval_suite_apply_refuses_without_recorded_evidence() {
        let (root, mut ctx) = gated_software_fixture("refuse").await;
        let outcomes = apply_local(&mut ctx).await.unwrap();
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            crate::apply::StepOutcomeStatus::Blocked,
            "{outcomes:?}"
        );
        assert!(
            outcomes[0]
                .detail
                .contains("no recorded evaluation evidence"),
            "{outcomes:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn eval_suite_apply_admits_valid_recorded_evidence() {
        let (root, mut ctx) = gated_software_fixture("admit").await;
        crate::model_release_evidence::record_passing_evaluation_for_suite(
            &mut ctx,
            "quality",
            "gated-app@1.0.0",
        )
        .await
        .unwrap();
        let outcomes = apply_local(&mut ctx).await.unwrap();
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            crate::apply::StepOutcomeStatus::Succeeded,
            "{outcomes:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

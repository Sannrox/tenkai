//! Evaluation, maintenance, and durable state admission for one Plan start.

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::maintenance::{self, Eligibility};
use crate::pb::chisei::{EvaluationGateCaseResult, GetEvaluationGateEvidenceRequest};

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
    for step in &plan.steps {
        crate::software_compatibility::require_release(ctx, &plan.environment, &step.release_id)
            .await?;
    }
    if !policy.skip_gates {
        for step in &plan.steps.clone() {
            if step.action == Action::Rollback {
                continue;
            }
            let target = ReleasePin {
                release_id: step.release_id.clone(),
                digest: step.release_digest.clone(),
                artifact_digest: step.artifact_digest.clone(),
                workdir: step.workdir.clone(),
            };
            let content =
                admit_release(ctx, &target, &plan.environment, &step.product, false).await?;
            let Some(suite) = content
                .manifest
                .gate
                .eval_suite
                .as_deref()
                .filter(|suite| !suite.is_empty())
            else {
                continue;
            };
            let detail = match check_eval_gate(
                ctx,
                suite,
                &step.release_digest,
                &step.artifact_digest,
            )
            .await
            {
                GateDecision::Allowed => continue,
                GateDecision::Denied(detail) | GateDecision::Unavailable(detail) => detail,
            };
            let outcome = Outcome::new(step.clone(), StepOutcomeStatus::Blocked, detail.clone());
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
    let mut products: Vec<String> = plan.steps.iter().map(|step| step.product.clone()).collect();
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
    Err(MaintenanceBlocked(detail.to_string()).into())
}

#[cfg(test)]
fn is_maintenance_block_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<MaintenanceBlocked>().is_some()
}

enum MaintenanceDecision {
    Allowed { closes_at: i64 },
    Denied(String),
    EmergencyOverride(String),
}

#[derive(Debug)]
struct MaintenanceBlocked(String);

impl std::fmt::Display for MaintenanceBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MaintenanceBlocked {}

enum GateDecision {
    Allowed,
    Denied(String),
    Unavailable(String),
}

fn evaluate_gate(
    results: &[EvaluationGateCaseResult],
    suite_id: &str,
    expected_cases: &[String],
) -> GateDecision {
    if results.is_empty() {
        return GateDecision::Denied(format!(
            "gate blocked: latest run of eval suite {suite_id} has no case results"
        ));
    }
    let expected: std::collections::HashSet<_> = expected_cases.iter().collect();
    let actual: std::collections::HashSet<_> =
        results.iter().map(|result| &result.case_id).collect();
    if expected.is_empty() || actual.len() != results.len() || actual != expected {
        return GateDecision::Denied(format!(
            "gate blocked: latest run of eval suite {suite_id} does not contain exactly one result for every current case"
        ));
    }
    let failed: Vec<_> = results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.case_id.clone())
        .collect();
    if !failed.is_empty() {
        return GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} latest run failing cases: {}",
            failed.join(", ")
        ));
    }
    GateDecision::Allowed
}

async fn check_eval_gate(
    ctx: &mut Ctx,
    suite_id: &str,
    release_digest: &str,
    artifact_digest: &str,
) -> GateDecision {
    let max_timestamp_ms = crate::now_millis().saturating_add(60_000);
    let response = match ctx
        .evaluation_gate_evidence(GetEvaluationGateEvidenceRequest {
            suite_id: suite_id.into(),
            release_digest: release_digest.into(),
            artifact_digest: artifact_digest.into(),
            max_timestamp_ms,
        })
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return GateDecision::Unavailable(format!(
                "gate unavailable: could not read evaluation gate evidence for suite {suite_id}: {error}"
            ));
        }
    };
    match response.status.as_str() {
        "suite_not_found" => GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} does not exist"
        )),
        "no_matching_run" => GateDecision::Denied(format!(
            "gate blocked: eval suite {suite_id} has no current run bound to this release and artifact"
        )),
        "found" => {
            let Some(evidence) = response.evidence else {
                return GateDecision::Unavailable(format!(
                    "gate unavailable: evaluation gate evidence for suite {suite_id} omitted its projection"
                ));
            };
            if evidence.suite_id != suite_id
                || evidence.release_digest != release_digest
                || evidence.artifact_digest != artifact_digest
                || evidence.suite_digest.is_empty()
                || evidence.config_ref
                    != gate_config_ref(release_digest, artifact_digest, &evidence.suite_digest)
                || evidence.run_id.is_empty()
                || evidence.run_timestamp <= 0
                || evidence.run_timestamp > max_timestamp_ms
            {
                return GateDecision::Unavailable(format!(
                    "gate unavailable: evaluation gate evidence for suite {suite_id} had an invalid binding"
                ));
            }
            evaluate_gate(&evidence.results, suite_id, &evidence.expected_case_ids)
        }
        status => GateDecision::Unavailable(format!(
            "gate unavailable: evaluation gate evidence for suite {suite_id} returned unknown status {status:?}"
        )),
    }
}

fn gate_config_ref(release_digest: &str, artifact_digest: &str, suite_digest: &str) -> String {
    let mut hasher = Sha256::new();
    for value in [
        b"tenkai-gate-v1".as_slice(),
        release_digest.as_bytes(),
        artifact_digest.as_bytes(),
        suite_digest.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    format!("tenkai:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_step() -> crate::plan::Step {
        crate::plan::Step {
            id: String::new(),
            order: 0,
            product: "api".into(),
            action: crate::plan::Action::Rollback,
            from: Some("1.1.0".into()),
            to: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "fixture".into(),
            artifact_digest: "fixture".into(),
            workdir: ".".into(),
            restore: None,
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
            assert!(is_maintenance_block_error(&error));
        }
        let mut failed = crate::plan::create_from_steps(&mut ctx, "local", vec![fixture_step()])
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
            .embedded_arc()
            .unwrap()
            .feedback_observations("local")
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
    fn maintenance_block_errors_are_typed() {
        let maintenance = anyhow::Error::new(MaintenanceBlocked("window closed".into()));
        let unrelated = anyhow::anyhow!("maintenance window text from another error");
        assert!(is_maintenance_block_error(&maintenance));
        assert!(!is_maintenance_block_error(&unrelated));
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

    #[test]
    fn gate_uses_latest_run_and_reports_failed_cases() {
        let results = vec![
            EvaluationGateCaseResult {
                case_id: "old".into(),
                passed: true,
            },
            EvaluationGateCaseResult {
                case_id: "smoke".into(),
                passed: false,
            },
        ];
        match evaluate_gate(&results, "suite", &["smoke".into(), "old".into()]) {
            GateDecision::Denied(detail) => assert!(detail.contains("smoke")),
            _ => panic!("a failing case must deny the gate"),
        }
    }

    #[test]
    fn gate_rejects_incomplete_or_duplicate_case_results() {
        let results = vec![
            EvaluationGateCaseResult {
                case_id: "first".into(),
                passed: true,
            },
            EvaluationGateCaseResult {
                case_id: "first".into(),
                passed: true,
            },
        ];
        assert!(matches!(
            evaluate_gate(&results, "suite", &["first".into(), "second".into()]),
            GateDecision::Denied(detail) if detail.contains("exactly one result")
        ));
    }

    #[test]
    fn gate_reference_changes_with_artifact_or_suite_content() {
        let original = gate_config_ref("manifest", "artifact-one", "suite-digest-one");
        let changed_artifact = gate_config_ref("manifest", "artifact-two", "suite-digest-one");
        let changed_suite = gate_config_ref("manifest", "artifact-one", "suite-digest-two");

        assert_ne!(original, changed_artifact);
        assert_ne!(original, changed_suite);
    }
}

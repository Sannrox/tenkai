//! Multi-environment rollout waves.
//!
//! `run_wave_observe` reports ordered delivery posture and never applies or
//! promotes. Executable waves (`start_or_resume` / `advance`) persist a durable
//! coordinator over existing per-environment plans (ADR 0017). Canary
//! promotion evidence remains the promotion gate; waves do not replace it.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::fleet::{self, FleetEnvironmentRow};
use crate::plan;

mod execution;

pub use execution::{
    ExecutableWaveSpec, WAVE_FORMAT_VERSION, WaveAuthorization, WaveEnvironmentRecord,
    WaveEnvironmentStatus, WaveRecord, WaveStatus, advance, format_wave, load_wave, rollback_wave,
    run_until_blocked, start_or_resume, stop_wave,
};

/// How the wave behaves after an environment fails observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveFailPolicy {
    /// Stop the wave; remaining environments are skipped.
    StopOnFailure,
    /// Continue through the full cohort.
    Continue,
}

/// Explicit ordered cohort for one wave run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveSpec {
    pub environments: Vec<String>,
    pub fail_policy: WaveFailPolicy,
}

impl WaveSpec {
    pub fn new(
        environments: impl IntoIterator<Item = String>,
        stop_on_failure: bool,
    ) -> Result<Self> {
        let environments: Vec<String> = environments.into_iter().collect();
        if environments.is_empty() {
            bail!("wave cohort must not be empty");
        }
        let mut seen = std::collections::BTreeSet::new();
        for name in &environments {
            if name.trim().is_empty() {
                bail!("wave cohort environment names must not be empty");
            }
            if !seen.insert(name.clone()) {
                bail!("wave cohort contains duplicate environment {name}");
            }
        }
        Ok(Self {
            environments,
            fail_policy: if stop_on_failure {
                WaveFailPolicy::StopOnFailure
            } else {
                WaveFailPolicy::Continue
            },
        })
    }
}

/// Outcome for one environment in the wave order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveOutcomeStatus {
    /// Environment is current on all subscribed products and healthy.
    Success,
    /// Deployed versions lag channel heads (not a hard failure unless policy says so).
    Behind,
    /// Health unknown/error or inspection failed.
    Failed,
    /// No subscriptions.
    Empty,
    /// Not processed because an earlier failure stopped the wave.
    Skipped,
    /// Environment is not registered.
    Missing,
}

impl WaveOutcomeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Behind => "behind",
            Self::Failed => "failed",
            Self::Empty => "empty",
            Self::Skipped => "skipped",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveEnvironmentOutcome {
    pub environment: String,
    pub order: u32,
    pub status: WaveOutcomeStatus,
    pub detail: String,
    /// When observed, the fleet posture string for the environment.
    pub posture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveReport {
    pub outcomes: Vec<WaveEnvironmentOutcome>,
    pub stopped_early: bool,
    pub success_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
}

/// Observe an ordered cohort using existing inspect/fleet posture (no apply).
///
/// Failures are `Failed` or `Missing`. With `StopOnFailure`, later environments
/// are `Skipped`. Behind/empty are reported but do not stop the wave.
pub async fn run_wave_observe(ctx: &mut Ctx, spec: &WaveSpec) -> Result<WaveReport> {
    let mut outcomes = Vec::with_capacity(spec.environments.len());
    let mut stopped_early = false;
    let mut failing = false;

    for (index, name) in spec.environments.iter().enumerate() {
        let order = index as u32;
        if failing && matches!(spec.fail_policy, WaveFailPolicy::StopOnFailure) {
            outcomes.push(WaveEnvironmentOutcome {
                environment: name.clone(),
                order,
                status: WaveOutcomeStatus::Skipped,
                detail: "skipped after earlier wave failure".into(),
                posture: None,
            });
            stopped_early = true;
            continue;
        }

        let outcome = match plan::inspect_environment(ctx, name).await {
            Ok(report) => {
                let row = fleet::fleet_status_from_inspects(vec![report]).environments;
                let row = row
                    .into_iter()
                    .next()
                    .expect("single inspect yields one fleet row");
                classify_row(name, order, &row)
            }
            Err(error) => {
                let message = error.to_string();
                if message.contains("not registered") {
                    WaveEnvironmentOutcome {
                        environment: name.clone(),
                        order,
                        status: WaveOutcomeStatus::Missing,
                        detail: message,
                        posture: None,
                    }
                } else {
                    WaveEnvironmentOutcome {
                        environment: name.clone(),
                        order,
                        status: WaveOutcomeStatus::Failed,
                        detail: message,
                        posture: None,
                    }
                }
            }
        };

        if matches!(
            outcome.status,
            WaveOutcomeStatus::Failed | WaveOutcomeStatus::Missing
        ) {
            failing = true;
        }
        outcomes.push(outcome);
    }

    Ok(summarize(outcomes, stopped_early))
}

fn classify_row(name: &str, order: u32, row: &FleetEnvironmentRow) -> WaveEnvironmentOutcome {
    let (status, detail) = match row.posture.as_str() {
        "current" => (
            WaveOutcomeStatus::Success,
            "all subscribed products current and healthy".into(),
        ),
        "behind" => (
            WaveOutcomeStatus::Behind,
            format!(
                "behind={} missing={} (not a hard wave failure)",
                row.products_behind, row.products_missing
            ),
        ),
        "unhealthy" => (
            WaveOutcomeStatus::Failed,
            format!("unhealthy health_summary={}", row.health_summary),
        ),
        "empty" => (WaveOutcomeStatus::Empty, "no channel subscriptions".into()),
        other => (
            WaveOutcomeStatus::Failed,
            format!("unexpected posture {other}"),
        ),
    };
    WaveEnvironmentOutcome {
        environment: name.into(),
        order,
        status,
        detail,
        posture: Some(row.posture.clone()),
    }
}

fn summarize(outcomes: Vec<WaveEnvironmentOutcome>, stopped_early: bool) -> WaveReport {
    let success_count = outcomes
        .iter()
        .filter(|o| matches!(o.status, WaveOutcomeStatus::Success))
        .count();
    let failed_count = outcomes
        .iter()
        .filter(|o| {
            matches!(
                o.status,
                WaveOutcomeStatus::Failed | WaveOutcomeStatus::Missing
            )
        })
        .count();
    let skipped_count = outcomes
        .iter()
        .filter(|o| matches!(o.status, WaveOutcomeStatus::Skipped))
        .count();
    WaveReport {
        outcomes,
        stopped_early,
        success_count,
        failed_count,
        skipped_count,
    }
}

/// Format a human-readable wave report (no secrets).
pub fn format_report(report: &WaveReport) -> String {
    let mut lines = vec![format!(
        "wave outcomes={} success={} failed={} skipped={} stopped_early={}",
        report.outcomes.len(),
        report.success_count,
        report.failed_count,
        report.skipped_count,
        report.stopped_early
    )];
    lines.push(format!(
        "{:<6} {:<16} {:<10} detail",
        "order", "environment", "status"
    ));
    for outcome in &report.outcomes {
        lines.push(format!(
            "{:<6} {:<16} {:<10} {}",
            outcome.order,
            outcome.environment,
            outcome.status.as_str(),
            outcome.detail
        ));
    }
    lines.push(
        "note: waves observe delivery posture; canary promotion evidence remains the channel promotion gate (see canary docs / #7)"
            .into(),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::fleet::fleet_status_from_inspects;
    use crate::plan::{EnvironmentInspectReport, EnvironmentSubscriptionView};

    fn report(
        name: &str,
        posture_state: &str,
        health: Option<&str>,
        error: Option<&str>,
    ) -> EnvironmentInspectReport {
        let (deployed, head, state) = match posture_state {
            "current" => (Some("1.0.0"), "1.0.0", "current"),
            "behind" => (Some("1.0.0"), "2.0.0", "behind"),
            "unhealthy" => (Some("1.0.0"), "1.0.0", "unknown"),
            _ => (None, "1.0.0", "missing"),
        };
        EnvironmentInspectReport {
            name: name.into(),
            id: format!("tenkai:env:{name}"),
            description: String::new(),
            subscriptions: if posture_state == "empty" {
                Vec::new()
            } else {
                vec![EnvironmentSubscriptionView {
                    product: "api".into(),
                    channel: "stable".into(),
                    head: head.into(),
                    deployed: deployed.map(str::to_string),
                    health: health.map(str::to_string),
                    error: error.map(str::to_string),
                    overlay_digest: None,
                    applied_overlay: None,
                    state: state.into(),
                }]
            },
            facts: Default::default(),
            overlays: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
        }
    }

    #[test]
    fn stop_on_failure_skips_remaining() {
        let a = report("alpha", "current", Some("healthy"), None);
        let b = report("beta", "unhealthy", Some("unknown"), Some("probe failed"));
        let c = report("gamma", "current", Some("healthy"), None);
        // Simulate classify order without full store.
        let rows: Vec<_> = [a, b, c]
            .into_iter()
            .map(|r| {
                fleet_status_from_inspects(vec![r])
                    .environments
                    .into_iter()
                    .next()
                    .unwrap()
            })
            .collect();
        let mut outcomes = Vec::new();
        let mut failing = false;
        let stop = true;
        for (index, row) in rows.iter().enumerate() {
            if failing && stop {
                outcomes.push(WaveEnvironmentOutcome {
                    environment: row.name.clone(),
                    order: index as u32,
                    status: WaveOutcomeStatus::Skipped,
                    detail: "skipped".into(),
                    posture: None,
                });
                continue;
            }
            let outcome = classify_row(&row.name, index as u32, row);
            if matches!(outcome.status, WaveOutcomeStatus::Failed) {
                failing = true;
            }
            outcomes.push(outcome);
        }
        let report = summarize(outcomes, true);
        assert_eq!(report.outcomes[0].status, WaveOutcomeStatus::Success);
        assert_eq!(report.outcomes[1].status, WaveOutcomeStatus::Failed);
        assert_eq!(report.outcomes[2].status, WaveOutcomeStatus::Skipped);
        assert!(report.stopped_early);
        let text = format_report(&report);
        assert!(!text.contains("Bearer"));
        assert!(text.contains("canary"));
    }

    #[test]
    fn wave_spec_rejects_duplicates_and_empty() {
        assert!(WaveSpec::new(Vec::<String>::new(), true).is_err());
        assert!(WaveSpec::new(["a".into(), "a".into()], true).is_err());
        assert!(WaveSpec::new(["a".into(), "b".into()], true).is_ok());
    }

    #[tokio::test]
    async fn observe_wave_missing_environment() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-wave-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "alpha", "first").await.unwrap();
        let spec = WaveSpec::new(["alpha".into(), "missing".into(), "beta".into()], true).unwrap();
        let report = run_wave_observe(&mut ctx, &spec).await.unwrap();
        assert_eq!(report.outcomes[0].status, WaveOutcomeStatus::Empty);
        assert_eq!(report.outcomes[1].status, WaveOutcomeStatus::Missing);
        assert_eq!(report.outcomes[2].status, WaveOutcomeStatus::Skipped);
        let _ = std::fs::remove_file(&database);
    }

    fn temp_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-wave-{name}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_software_manifest(dir: &std::path::Path, product: &str, version: &str, extra: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "{product}"
version = "{version}"

[deploy]
workdir = "."
install = "true"
{extra}
"#
            ),
        )
        .unwrap();
    }

    fn write_eval_manifest(dir: &std::path::Path, product: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("suite.json"),
            r#"{"version":1,"suite_id":"wave-suite","cases":["health"]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "{product}"
version = "{version}"
kind = "eval_suite"

[eval_suite_product]
document = "suite.json"
"#
            ),
        )
        .unwrap();
    }

    async fn publish_unsigned(ctx: &mut Ctx, manifest: &std::path::Path) {
        crate::catalog::publish(
            ctx,
            manifest,
            &crate::catalog::PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
            },
        )
        .await
        .unwrap();
    }

    async fn signed_release(
        keys: &std::path::Path,
        manifest: &std::path::Path,
        ctx: &mut Ctx,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let signature = manifest.parent().unwrap().join("release.sig.json");
        let trust = manifest.parent().unwrap().join("release-trust.toml");
        crate::dev_sign::sign_release(keys, manifest, &signature, &trust).unwrap();
        crate::catalog::publish(
            ctx,
            manifest,
            &crate::catalog::PublishOptions {
                signature: Some(signature.clone()),
                trust_roots: Some(trust.clone()),
                allow_unsigned_development: false,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
            },
        )
        .await
        .unwrap();
        (signature, trust)
    }

    async fn sign_current_approvals(
        keys: &std::path::Path,
        db: &std::path::Path,
        approval_dir: &std::path::Path,
        trust: &std::path::Path,
        record: &WaveRecord,
    ) {
        std::fs::create_dir_all(approval_dir).unwrap();
        for environment in &record.environments {
            let Some(plan_id) = &environment.plan_id else {
                continue;
            };
            let envelope = approval_dir.join(format!("{plan_id}.json"));
            if envelope.exists() {
                continue;
            }
            crate::dev_sign::sign_plan_approval(keys, db, plan_id, &envelope, trust, 3600)
                .await
                .unwrap();
        }
    }

    async fn run_signed_wave(
        ctx: &mut Ctx,
        spec: &ExecutableWaveSpec,
        db: &std::path::Path,
        keys: &std::path::Path,
        approval_dir: &std::path::Path,
        trust: &std::path::Path,
    ) -> WaveRecord {
        let _ = start_or_resume(ctx, spec).await.unwrap();
        loop {
            let current = load_wave(ctx, &spec.name).await.unwrap();
            if matches!(
                current.status,
                WaveStatus::Succeeded
                    | WaveStatus::Failed
                    | WaveStatus::RolledBack
                    | WaveStatus::RecoveryRequired
            ) {
                return current;
            }
            if current.status == WaveStatus::AwaitingApproval
                || current
                    .environments
                    .iter()
                    .any(|environment| environment.plan_id.is_some())
            {
                sign_current_approvals(keys, db, approval_dir, trust, &current).await;
            }
            let next = advance(
                ctx,
                &spec.name,
                WaveAuthorization::Signed {
                    approval_dir,
                    trust_roots: trust,
                },
            )
            .await
            .unwrap();
            if next.status == WaveStatus::AwaitingApproval {
                sign_current_approvals(keys, db, approval_dir, trust, &next).await;
                continue;
            }
            if matches!(
                next.status,
                WaveStatus::Succeeded
                    | WaveStatus::Failed
                    | WaveStatus::RolledBack
                    | WaveStatus::RecoveryRequired
            ) {
                return next;
            }
        }
    }

    #[tokio::test]
    async fn observe_does_not_create_executable_wave_records() {
        let root = temp_root("observe-no-persist");
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "local", "fixture").await.unwrap();
        let spec = WaveSpec::new(["local".into()], true).unwrap();
        let _ = run_wave_observe(&mut ctx, &spec).await.unwrap();
        let waves = ctx.list_kind(crate::ontology::KIND_WAVE).await.unwrap();
        assert!(
            waves.is_empty(),
            "observe-only waves must not persist execution records"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn executable_wave_completes_local_cohort_and_is_idempotent() {
        let root = temp_root("local-success");
        let database = root.join("tenkai.db");
        let product = root.join("product");
        write_eval_manifest(&product, "wave-demo", "1.0.0");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_unsigned(&mut ctx, &product.join("tenkai.toml")).await;
        let actor = crate::auth_context::test_management_context("wave-local");
        crate::catalog::promote(&mut ctx, &actor, "wave-demo@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "local", "fixture").await.unwrap();
        plan::subscribe(&mut ctx, "local", "wave-demo", "stable")
            .await
            .unwrap();

        let spec = ExecutableWaveSpec::new(
            "rollout-1",
            "wave-demo",
            "1.0.0",
            "stable",
            ["local".to_string()],
            true,
        )
        .unwrap();
        let first = start_or_resume(&mut ctx, &spec).await.unwrap();
        let replay = start_or_resume(&mut ctx, &spec).await.unwrap();
        assert_eq!(first.identity_digest, replay.identity_digest);
        assert_eq!(first.status, WaveStatus::Admitted);

        plan::env_add(&mut ctx, "stage", "unused").await.unwrap();
        let conflict = ExecutableWaveSpec::new(
            "rollout-1",
            "wave-demo",
            "1.0.0",
            "stable",
            ["local".to_string(), "stage".to_string()],
            true,
        )
        .unwrap();
        let err = start_or_resume(&mut ctx, &conflict)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("conflicting identity"), "{err}");

        let executed = advance(
            &mut ctx,
            "rollout-1",
            WaveAuthorization::LocalDevelopment { reason: "wave e2e" },
        )
        .await
        .unwrap();
        assert_eq!(executed.status, WaveStatus::Succeeded);
        assert_eq!(
            executed.environments[0].status,
            WaveEnvironmentStatus::Succeeded
        );
        assert!(executed.environments[0].plan_id.is_some());
        assert_eq!(
            executed.environments[0].gate_result.as_deref(),
            Some("satisfied")
        );
        assert_eq!(
            executed.environments[0].health_result.as_deref(),
            Some("passed_or_not_configured")
        );
        let plan_id = executed.environments[0].plan_id.clone().unwrap();

        let again = advance(
            &mut ctx,
            "rollout-1",
            WaveAuthorization::LocalDevelopment { reason: "wave e2e" },
        )
        .await
        .unwrap();
        assert_eq!(again.status, WaveStatus::Succeeded);
        assert_eq!(
            again.environments[0].plan_id.as_deref(),
            Some(plan_id.as_str())
        );

        let observe = run_wave_observe(&mut ctx, &WaveSpec::new(["local".into()], true).unwrap())
            .await
            .unwrap();
        assert_eq!(observe.outcomes[0].status, WaveOutcomeStatus::Success);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failed_gate_stop_skips_later_signed_cohort() {
        let root = temp_root("gate-stop");
        let database = root.join("tenkai.db");
        let keys = root.join("keys");
        crate::dev_sign::init_dev_keys(&keys).unwrap();
        let product = root.join("product");
        write_software_manifest(
            &product,
            "gated-demo",
            "1.0.0",
            "[gate]\neval_suite = \"missing-suite\"\n",
        );
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_release(&keys, &product.join("tenkai.toml"), &mut ctx).await;
        let actor = crate::auth_context::test_management_context("wave-gate");
        crate::catalog::promote(&mut ctx, &actor, "gated-demo@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "canary", "c").await.unwrap();
        plan::env_add(&mut ctx, "stage", "s").await.unwrap();
        plan::subscribe(&mut ctx, "canary", "gated-demo", "stable")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "stage", "gated-demo", "stable")
            .await
            .unwrap();
        let spec = ExecutableWaveSpec::new(
            "gated-rollout",
            "gated-demo",
            "1.0.0",
            "stable",
            ["canary".to_string(), "stage".to_string()],
            true,
        )
        .unwrap();
        let record = run_signed_wave(
            &mut ctx,
            &spec,
            &database,
            &keys,
            &root.join("approvals"),
            &root.join("approval-trust.toml"),
        )
        .await;
        assert_eq!(record.status, WaveStatus::Failed);
        assert_eq!(
            record.environments[0].status,
            WaveEnvironmentStatus::Blocked
        );
        assert_eq!(
            record.environments[0].gate_result.as_deref(),
            Some("blocked")
        );
        assert_eq!(
            record.environments[1].status,
            WaveEnvironmentStatus::Skipped
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn continue_policy_attempts_later_environment_after_gate_failure() {
        let root = temp_root("gate-continue");
        let database = root.join("tenkai.db");
        let keys = root.join("keys");
        crate::dev_sign::init_dev_keys(&keys).unwrap();
        let product = root.join("product");
        write_software_manifest(
            &product,
            "gated-cont",
            "1.0.0",
            "[gate]\neval_suite = \"missing-suite\"\n",
        );
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_release(&keys, &product.join("tenkai.toml"), &mut ctx).await;
        let actor = crate::auth_context::test_management_context("wave-continue");
        crate::catalog::promote(&mut ctx, &actor, "gated-cont@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "canary", "c").await.unwrap();
        plan::env_add(&mut ctx, "stage", "s").await.unwrap();
        plan::subscribe(&mut ctx, "canary", "gated-cont", "stable")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "stage", "gated-cont", "stable")
            .await
            .unwrap();
        let spec = ExecutableWaveSpec::new(
            "continue-rollout",
            "gated-cont",
            "1.0.0",
            "stable",
            ["canary".to_string(), "stage".to_string()],
            false,
        )
        .unwrap();
        let record = run_signed_wave(
            &mut ctx,
            &spec,
            &database,
            &keys,
            &root.join("approvals"),
            &root.join("approval-trust.toml"),
        )
        .await;
        assert_eq!(record.status, WaveStatus::Failed);
        assert_eq!(
            record.environments[0].status,
            WaveEnvironmentStatus::Blocked
        );
        assert_eq!(
            record.environments[1].status,
            WaveEnvironmentStatus::Blocked
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn restart_resumes_without_repeating_completed_mutations() {
        let root = temp_root("restart");
        let database = root.join("tenkai.db");
        let keys = root.join("keys");
        crate::dev_sign::init_dev_keys(&keys).unwrap();
        let product = root.join("product");
        write_eval_manifest(&product, "wave-restart", "1.0.0");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_release(&keys, &product.join("tenkai.toml"), &mut ctx).await;
        let actor = crate::auth_context::test_management_context("wave-restart");
        crate::catalog::promote(&mut ctx, &actor, "wave-restart@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "canary", "c").await.unwrap();
        plan::env_add(&mut ctx, "stage", "s").await.unwrap();
        plan::subscribe(&mut ctx, "canary", "wave-restart", "stable")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "stage", "wave-restart", "stable")
            .await
            .unwrap();
        let spec = ExecutableWaveSpec::new(
            "restart-rollout",
            "wave-restart",
            "1.0.0",
            "stable",
            ["canary".to_string(), "stage".to_string()],
            true,
        )
        .unwrap();
        let _ = start_or_resume(&mut ctx, &spec).await.unwrap();
        let approvals = root.join("approvals");
        let trust = root.join("approval-trust.toml");
        let mut first = advance(
            &mut ctx,
            "restart-rollout",
            WaveAuthorization::Signed {
                approval_dir: &approvals,
                trust_roots: &trust,
            },
        )
        .await
        .unwrap();
        while first.status == WaveStatus::AwaitingApproval {
            sign_current_approvals(&keys, &database, &approvals, &trust, &first).await;
            first = advance(
                &mut ctx,
                "restart-rollout",
                WaveAuthorization::Signed {
                    approval_dir: &approvals,
                    trust_roots: &trust,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            first.environments[0].status,
            WaveEnvironmentStatus::Succeeded
        );
        assert_eq!(
            first.environments[1].status,
            WaveEnvironmentStatus::Unstarted
        );
        let first_plan = first.environments[0].plan_id.clone().unwrap();
        let stopped = stop_wave(&mut ctx, "restart-rollout").await.unwrap();
        assert_eq!(stopped.status, WaveStatus::Stopped);
        drop(ctx);

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let resumed = run_signed_wave(&mut ctx, &spec, &database, &keys, &approvals, &trust).await;
        assert_eq!(
            resumed.status,
            WaveStatus::Succeeded,
            "{:?} {:?}",
            resumed.status,
            resumed.environments
        );
        assert_eq!(
            resumed.environments[0].plan_id.as_deref(),
            Some(first_plan.as_str())
        );
        assert_eq!(
            resumed.environments[1].status,
            WaveEnvironmentStatus::Succeeded
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stale_head_recall_unauthorized_and_foreign_lease_fail_closed() {
        let root = temp_root("fail-closed");
        let database = root.join("tenkai.db");
        let keys = root.join("keys");
        crate::dev_sign::init_dev_keys(&keys).unwrap();
        let v1 = root.join("v1");
        let v2 = root.join("v2");
        write_eval_manifest(&v1, "wave-pin", "1.0.0");
        write_eval_manifest(&v2, "wave-pin", "2.0.0");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_release(&keys, &v1.join("tenkai.toml"), &mut ctx).await;
        signed_release(&keys, &v2.join("tenkai.toml"), &mut ctx).await;
        let actor = crate::auth_context::test_management_context("wave-pin");
        crate::catalog::promote(&mut ctx, &actor, "wave-pin@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "stage", "s").await.unwrap();
        plan::subscribe(&mut ctx, "stage", "wave-pin", "stable")
            .await
            .unwrap();
        let spec = ExecutableWaveSpec::new(
            "pin-rollout",
            "wave-pin",
            "1.0.0",
            "stable",
            ["stage".to_string()],
            true,
        )
        .unwrap();
        let admitted = start_or_resume(&mut ctx, &spec).await.unwrap();
        assert_eq!(admitted.status, WaveStatus::Admitted);

        let unauthorized = advance(
            &mut ctx,
            "pin-rollout",
            WaveAuthorization::LocalDevelopment {
                reason: "should fail",
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            unauthorized.contains("restricted to the built-in local environment"),
            "{unauthorized}"
        );

        ctx.acquire_lease(
            "tenkai/environment-execution",
            "stage",
            "foreign-controller",
            60_000,
        )
        .await
        .unwrap();
        let lease_err = advance(
            &mut ctx,
            "pin-rollout",
            WaveAuthorization::LocalDevelopment {
                reason: "still unauthorized",
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            lease_err.contains("apply lease") || lease_err.contains("stale controllers"),
            "{lease_err}"
        );

        crate::catalog::promote(&mut ctx, &actor, "wave-pin@2.0.0", "stable")
            .await
            .unwrap();
        let stale = advance(
            &mut ctx,
            "pin-rollout",
            WaveAuthorization::LocalDevelopment {
                reason: "still unauthorized",
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(stale.contains("stale channel head"), "{stale}");

        crate::catalog::promote(&mut ctx, &actor, "wave-pin@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::recall(&mut ctx, &actor, "wave-pin@1.0.0")
            .await
            .unwrap();
        let recalled = advance(
            &mut ctx,
            "pin-rollout",
            WaveAuthorization::LocalDevelopment {
                reason: "still unauthorized",
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(recalled.contains("recalled"), "{recalled}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stop_then_rollback_uses_tenkai_owned_plan() {
        let root = temp_root("rollback");
        let database = root.join("tenkai.db");
        let product = root.join("product");
        write_eval_manifest(&product, "wave-rb", "1.0.0");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_unsigned(&mut ctx, &product.join("tenkai.toml")).await;
        let actor = crate::auth_context::test_management_context("wave-rb");
        crate::catalog::promote(&mut ctx, &actor, "wave-rb@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "local", "fixture").await.unwrap();
        plan::subscribe(&mut ctx, "local", "wave-rb", "stable")
            .await
            .unwrap();
        let spec = ExecutableWaveSpec::new(
            "rb-rollout",
            "wave-rb",
            "1.0.0",
            "stable",
            ["local".to_string()],
            true,
        )
        .unwrap();
        let _ = start_or_resume(&mut ctx, &spec).await.unwrap();
        let executed = advance(
            &mut ctx,
            "rb-rollout",
            WaveAuthorization::LocalDevelopment {
                reason: "wave rollback e2e",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            executed.status,
            WaveStatus::Succeeded,
            "{:?} {}",
            executed.status,
            executed.environments[0].detail
        );
        let stopped = stop_wave(&mut ctx, "rb-rollout").await.unwrap();
        assert_eq!(
            stopped.status,
            WaveStatus::Succeeded,
            "stop must not rewrite a terminal succeeded wave"
        );
        assert_eq!(
            stopped.environments[0].status,
            WaveEnvironmentStatus::Succeeded
        );

        let rolled = rollback_wave(
            &mut ctx,
            "rb-rollout",
            WaveAuthorization::LocalDevelopment {
                reason: "wave rollback e2e",
            },
        )
        .await;
        // First install has no prior version; rollback_step may fail closed.
        match rolled {
            Ok(record) => {
                assert!(
                    matches!(
                        record.status,
                        WaveStatus::RolledBack | WaveStatus::RecoveryRequired
                    ),
                    "{:?}",
                    record.status
                );
            }
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("rollback")
                        || message.contains("restore")
                        || message.contains("previous"),
                    "{message}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }
}

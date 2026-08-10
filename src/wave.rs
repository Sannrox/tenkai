//! Multi-environment rollout wave observation.
//!
//! A wave is an ordered cohort of environments observed (and optionally
//! reconciled later) without fleet-wide DAG inference. Canary promotion
//! evidence (#7) remains the promotion gate; waves do not replace it.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::fleet::{self, FleetEnvironmentRow};
use crate::plan;

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
                    state: state.into(),
                }]
            },
            facts: Default::default(),
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
}

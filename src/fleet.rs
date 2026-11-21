//! Fleet delivery posture: aggregation, drift comparison, and baseline I/O.
//!
//! Inspect reports and store-backed listing remain in [`crate::environment`]
//! (re-exported from [`crate::plan`]). This
//! module is the pure posture interface: callers feed inspect rows or fleet
//! rows and get deterministic aggregates, drift deltas, and baseline files
//! without learning subscription/lease classification details.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::plan::EnvironmentInspectReport;

/// One environment's row in a fleet posture table (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FleetEnvironmentRow {
    pub name: String,
    pub id: String,
    pub description: String,
    pub subscription_count: usize,
    /// Subscribed products whose deployed version matches channel head.
    pub products_current: usize,
    /// Subscribed products with a deployment that is not the channel head.
    pub products_behind: usize,
    /// Subscribed products with no deployed version.
    pub products_missing: usize,
    /// True when any subscription has health `unknown` or a non-empty error.
    pub unhealthy: bool,
    /// `ok` | `unknown` | `error` | `n/a` (no subscriptions).
    pub health_summary: String,
    pub lease_held: bool,
    /// Latest plan state when a plan exists, as `inspect_environment`
    /// reports it (#1372).
    pub latest_plan_state: Option<String>,
    /// True while the latest plan waits for a person to approve it: it is
    /// still to run and its approval source is `required`. Omitted when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub awaiting_approval: bool,
    /// Instances whose live spec was modified outside Tenkai (#1028), as
    /// `status` reports them. Omitted when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub drifted_instances: usize,
    /// Workload certificates reported in this environment (ADR 0046 §3).
    /// Omitted when none was reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub certificates: Option<FleetCertificateSummary>,
    /// The environment's runtime instances and their recorded executors
    /// and engines (ADR 0057). Empty when no runtime runs it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtimes: Vec<crate::execution_capabilities::ProcessExecutors>,
    /// Aggregate posture: `empty` | `unhealthy` | `behind` | `current`.
    pub posture: String,
    /// Effective environment criticality when set (#694).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub criticality: Option<String>,
    /// Open (release, advisory) matches on this environment (#900).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_exposures: Vec<OpenEnvironmentExposure>,
    /// Environment owner contact when set (#1066).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub owner: Option<String>,
    /// True when the environment has neither an owner nor a webhook endpoint
    /// of its own. Product endpoints are not counted. Omitted when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unrouted: bool,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// The workload certificates of one environment, folded for the fleet table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FleetCertificateSummary {
    /// The earliest expiry among the reported certificates, in Unix seconds.
    pub nearest_expires_at: i64,
    /// True when any certificate is in the last sixth of its lifetime.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub near_expiry: bool,
    /// Instances whose latest renewal attempt failed. Omitted when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub renewal_failing: usize,
}

impl FleetCertificateSummary {
    /// Fold the `status` view of each instance's certificate; `None` when
    /// the environment reported none.
    pub fn from_statuses<'a>(
        statuses: impl IntoIterator<Item = &'a crate::certificate_reports::CertificateStatus>,
    ) -> Option<Self> {
        statuses.into_iter().fold(None, |summary, status| {
            let failing = usize::from(status.renewal_failure.is_some());
            Some(match summary {
                None => Self {
                    nearest_expires_at: status.expires_at,
                    near_expiry: status.near_expiry,
                    renewal_failing: failing,
                },
                Some(summary) => Self {
                    nearest_expires_at: summary.nearest_expires_at.min(status.expires_at),
                    near_expiry: summary.near_expiry || status.near_expiry,
                    renewal_failing: summary.renewal_failing + failing,
                },
            })
        })
    }
}

/// One open deployed exposure, with age, on a fleet row (#900).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OpenEnvironmentExposure {
    pub release: String,
    pub advisory_id: String,
    pub severity: String,
    pub first_seen_at: i64,
    pub age_ms: i64,
    /// True when `age_ms` exceeds `exposure.max_age_ms.<severity>` on the environment.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub overdue: bool,
    /// First-seen plus the environment's (or its channel's) exposure grace.
    /// Omitted when no grace applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub grace_ends_at: Option<i64>,
    /// True while `grace_ends_at` is in the future.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_grace: bool,
}

/// Fleet-wide delivery posture (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FleetStatusReport {
    /// The server's own version, which runners and consoles compare
    /// against (#761).
    #[serde(default)]
    pub server_version: String,
    pub environments: Vec<FleetEnvironmentRow>,
    pub environment_count: usize,
    pub environments_current: usize,
    pub environments_behind: usize,
    pub environments_unhealthy: usize,
    pub environments_empty: usize,
    /// Active channel promotion policies and soak state (#899).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub promotion_policies: Vec<crate::channel_promotion::ChannelPromotionPolicyStatus>,
    /// Server replicas that checked in recently and their installed
    /// executors and engines (ADR 0057). Empty on a single-replica server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replicas: Vec<crate::execution_capabilities::ProcessExecutors>,
}

/// Build a fleet report from inspect reports (used by tests and filtered hosts).
pub fn fleet_status_from_inspects(reports: Vec<EnvironmentInspectReport>) -> FleetStatusReport {
    let mut environments: Vec<_> = reports.iter().map(fleet_row_from_inspect).collect();
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    aggregate_fleet_report(environments)
}

/// Derive one fleet row from an environment inspect report.
pub fn fleet_row_from_inspect(report: &EnvironmentInspectReport) -> FleetEnvironmentRow {
    let mut products_current = 0usize;
    let mut products_behind = 0usize;
    let mut products_missing = 0usize;
    let mut saw_unknown = false;
    let mut saw_error = false;
    for sub in &report.subscriptions {
        match sub.state.as_str() {
            "current" => products_current += 1,
            "behind" | "config_stale" => products_behind += 1,
            "missing" => products_missing += 1,
            "unknown" | "unhealthy" => {
                // Health unknown/unhealthy: still count version drift when known.
                if sub.deployed.as_ref() == Some(&sub.head) {
                    products_current += 1;
                } else if sub.deployed.is_some() {
                    products_behind += 1;
                } else {
                    products_missing += 1;
                }
            }
            _ => {
                if sub.deployed.as_ref() == Some(&sub.head) {
                    products_current += 1;
                } else if sub.deployed.is_some() {
                    products_behind += 1;
                } else {
                    products_missing += 1;
                }
            }
        }
        if sub.health.as_deref() == Some("unknown") {
            saw_unknown = true;
        }
        if sub.health.as_deref() == Some("unhealthy")
            || sub.error.as_ref().is_some_and(|error| !error.is_empty())
        {
            saw_error = true;
        }
    }
    let unhealthy = saw_unknown || saw_error;
    let health_summary = if report.subscriptions.is_empty() {
        "n/a".into()
    } else if saw_error {
        "error".into()
    } else if saw_unknown {
        "unknown".into()
    } else {
        "ok".into()
    };
    let posture = if report.subscriptions.is_empty() {
        "empty"
    } else if unhealthy {
        "unhealthy"
    } else if products_behind > 0 || products_missing > 0 {
        "behind"
    } else {
        "current"
    }
    .to_string();
    FleetEnvironmentRow {
        name: report.name.clone(),
        id: report.id.clone(),
        description: report.description.clone(),
        subscription_count: report.subscriptions.len(),
        products_current,
        products_behind,
        products_missing,
        unhealthy,
        health_summary,
        lease_held: report.lease.held,
        latest_plan_state: report.latest_plan.as_ref().map(|plan| plan.state.clone()),
        awaiting_approval: report.latest_plan.as_ref().is_some_and(|plan| {
            matches!(plan.state.as_str(), "computed" | "blocked")
                && plan
                    .approval
                    .as_ref()
                    .is_some_and(|approval| approval.source == "required")
        }),
        drifted_instances: report
            .subscriptions
            .iter()
            .filter(|sub| {
                sub.spec_drift
                    .as_ref()
                    .is_some_and(|drift| drift.is_modified())
            })
            .count(),
        certificates: None,
        runtimes: Vec::new(),
        posture,
        criticality: report
            .criticality
            .as_ref()
            .and_then(|value| value.effective.clone()),
        open_exposures: Vec::new(),
        owner: report.owner.as_ref().map(|owner| owner.contact.clone()),
        unrouted: report.owner.is_none() && report.webhooks.is_empty(),
    }
}

/// Recompute fleet aggregates after filtering rows (e.g. tenant scope).
pub fn fleet_status_from_rows(environments: Vec<FleetEnvironmentRow>) -> FleetStatusReport {
    aggregate_fleet_report(environments)
}

/// Compact posture snapshot for baseline files and drift watch (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPostureSnapshot {
    /// Schema marker for optional JSON baseline files.
    #[serde(default = "fleet_posture_snapshot_schema")]
    pub schema: String,
    /// Environment name → posture (`empty` | `unhealthy` | `behind` | `current`).
    pub postures: BTreeMap<String, String>,
}

impl Default for FleetPostureSnapshot {
    fn default() -> Self {
        Self {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::new(),
        }
    }
}

fn fleet_posture_snapshot_schema() -> String {
    "tenkai.fleet-posture.v1".into()
}

/// Deterministic delta between two posture samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetDriftSummary {
    pub previous: FleetPostureSnapshot,
    pub current: FleetPostureSnapshot,
    pub entered_behind: Vec<String>,
    pub left_behind: Vec<String>,
    pub entered_unhealthy: Vec<String>,
    pub left_unhealthy: Vec<String>,
    pub entered_empty: Vec<String>,
    pub left_empty: Vec<String>,
    pub entered_current: Vec<String>,
    pub left_current: Vec<String>,
    pub appeared: Vec<String>,
    pub disappeared: Vec<String>,
    /// Environments that newly entered `behind` or `unhealthy` vs the baseline.
    pub new_hard_drift: Vec<String>,
    pub has_new_hard_drift: bool,
    pub has_any_posture_change: bool,
    /// True when any current environment is `behind` or `unhealthy`.
    pub has_any_hard_drift: bool,
}

/// Build a baseline-friendly posture snapshot from a fleet status report.
pub fn fleet_posture_snapshot(report: &FleetStatusReport) -> FleetPostureSnapshot {
    let mut postures = BTreeMap::new();
    for row in &report.environments {
        postures.insert(row.name.clone(), row.posture.clone());
    }
    FleetPostureSnapshot {
        schema: fleet_posture_snapshot_schema(),
        postures,
    }
}

/// True for postures that count as hard delivery drift for watch exit codes.
pub fn is_hard_drift_posture(posture: &str) -> bool {
    matches!(posture, "behind" | "unhealthy")
}

/// Open exposures whose age exceeds the environment's configured maximum.
pub fn overdue_exposures(report: &FleetStatusReport) -> Vec<(String, OpenEnvironmentExposure)> {
    let mut overdue = Vec::new();
    for row in &report.environments {
        for exposure in &row.open_exposures {
            if exposure.overdue {
                overdue.push((row.name.clone(), exposure.clone()));
            }
        }
    }
    overdue
}

/// Compare two posture samples and list environments that entered/left each class.
pub fn compare_fleet_posture(
    previous: &FleetPostureSnapshot,
    current: &FleetPostureSnapshot,
) -> FleetDriftSummary {
    let mut all_names = previous
        .postures
        .keys()
        .chain(current.postures.keys())
        .cloned()
        .collect::<Vec<_>>();
    all_names.sort();
    all_names.dedup();

    let mut entered_behind = Vec::new();
    let mut left_behind = Vec::new();
    let mut entered_unhealthy = Vec::new();
    let mut left_unhealthy = Vec::new();
    let mut entered_empty = Vec::new();
    let mut left_empty = Vec::new();
    let mut entered_current = Vec::new();
    let mut left_current = Vec::new();
    let mut appeared = Vec::new();
    let mut disappeared = Vec::new();
    let mut new_hard_drift = Vec::new();
    let mut has_any_posture_change = false;
    let mut has_any_hard_drift = false;

    for name in all_names {
        let prev = previous.postures.get(&name).map(String::as_str);
        let curr = current.postures.get(&name).map(String::as_str);
        match (prev, curr) {
            (None, Some(c)) => {
                appeared.push(name.clone());
                has_any_posture_change = true;
                track_enter(
                    c,
                    &name,
                    &mut entered_behind,
                    &mut entered_unhealthy,
                    &mut entered_empty,
                    &mut entered_current,
                );
                if is_hard_drift_posture(c) {
                    new_hard_drift.push(name.clone());
                }
            }
            (Some(p), None) => {
                disappeared.push(name.clone());
                has_any_posture_change = true;
                track_leave(
                    p,
                    &name,
                    &mut left_behind,
                    &mut left_unhealthy,
                    &mut left_empty,
                    &mut left_current,
                );
            }
            (Some(p), Some(c)) if p != c => {
                has_any_posture_change = true;
                track_leave(
                    p,
                    &name,
                    &mut left_behind,
                    &mut left_unhealthy,
                    &mut left_empty,
                    &mut left_current,
                );
                track_enter(
                    c,
                    &name,
                    &mut entered_behind,
                    &mut entered_unhealthy,
                    &mut entered_empty,
                    &mut entered_current,
                );
                if is_hard_drift_posture(c) && !is_hard_drift_posture(p) {
                    new_hard_drift.push(name.clone());
                } else if is_hard_drift_posture(c) && p != c {
                    // behind ↔ unhealthy still counts as new hard drift for alerts
                    new_hard_drift.push(name.clone());
                }
            }
            (Some(_), Some(c)) => {
                // unchanged
                if is_hard_drift_posture(c) {
                    // existing hard drift is not "new"
                }
            }
            (None, None) => {}
        }
        if let Some(c) = curr
            && is_hard_drift_posture(c)
        {
            has_any_hard_drift = true;
        }
    }

    let has_new_hard_drift = !new_hard_drift.is_empty();
    FleetDriftSummary {
        previous: previous.clone(),
        current: current.clone(),
        entered_behind,
        left_behind,
        entered_unhealthy,
        left_unhealthy,
        entered_empty,
        left_empty,
        entered_current,
        left_current,
        appeared,
        disappeared,
        new_hard_drift,
        has_new_hard_drift,
        has_any_posture_change,
        has_any_hard_drift,
    }
}

fn track_enter(
    posture: &str,
    name: &str,
    behind: &mut Vec<String>,
    unhealthy: &mut Vec<String>,
    empty: &mut Vec<String>,
    current: &mut Vec<String>,
) {
    match posture {
        "behind" => behind.push(name.to_string()),
        "unhealthy" => unhealthy.push(name.to_string()),
        "empty" => empty.push(name.to_string()),
        "current" => current.push(name.to_string()),
        _ => {}
    }
}

fn track_leave(
    posture: &str,
    name: &str,
    behind: &mut Vec<String>,
    unhealthy: &mut Vec<String>,
    empty: &mut Vec<String>,
    current: &mut Vec<String>,
) {
    match posture {
        "behind" => behind.push(name.to_string()),
        "unhealthy" => unhealthy.push(name.to_string()),
        "empty" => empty.push(name.to_string()),
        "current" => current.push(name.to_string()),
        _ => {}
    }
}

/// Load a posture baseline from a JSON file. Only a missing file is an empty
/// snapshot; any other read error is reported.
pub fn load_fleet_posture_baseline(path: &Path) -> Result<FleetPostureSnapshot> {
    let Some(raw) = crate::atomic_state::read_optional(path)
        .with_context(|| format!("read fleet posture baseline {}", path.display()))?
    else {
        return Ok(FleetPostureSnapshot::default());
    };
    serde_json::from_slice(&raw)
        .with_context(|| format!("parse fleet posture baseline {}", path.display()))
}

/// Atomically replace a posture baseline with JSON (no secrets; names and
/// postures only). A crash leaves the previous baseline or the new one.
pub fn write_fleet_posture_baseline(path: &Path, snapshot: &FleetPostureSnapshot) -> Result<()> {
    let raw = serde_json::to_string_pretty(snapshot).context("encode fleet posture baseline")?;
    crate::atomic_state::write_bytes_verified(path, format!("{raw}\n").as_bytes(), |_| Ok(()))
        .with_context(|| format!("write fleet posture baseline {}", path.display()))
}

fn aggregate_fleet_report(environments: Vec<FleetEnvironmentRow>) -> FleetStatusReport {
    let environment_count = environments.len();
    let environments_current = environments
        .iter()
        .filter(|row| row.posture == "current")
        .count();
    let environments_behind = environments
        .iter()
        .filter(|row| row.posture == "behind")
        .count();
    let environments_unhealthy = environments
        .iter()
        .filter(|row| row.posture == "unhealthy")
        .count();
    let environments_empty = environments
        .iter()
        .filter(|row| row.posture == "empty")
        .count();
    FleetStatusReport {
        server_version: crate::version_skew::SERVER_VERSION.into(),
        environments,
        environment_count,
        environments_current,
        environments_behind,
        environments_unhealthy,
        environments_empty,
        promotion_policies: Vec::new(),
        replicas: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{
        EnvironmentInspectReport, EnvironmentPlanSummary, EnvironmentSubscriptionView,
    };
    use std::collections::BTreeMap;

    fn current_subscription(
        product: &str,
        spec_drift: Option<crate::spec_drift::SpecDriftView>,
    ) -> EnvironmentSubscriptionView {
        EnvironmentSubscriptionView {
            product: product.into(),
            instance: product.into(),
            channel: "stable".into(),
            head: "1.0.0".into(),
            deployed: Some("1.0.0".into()),
            health: Some("healthy".into()),
            error: None,
            overlay_digest: None,
            applied_overlay: None,
            state: "current".into(),
            delivery_hold: None,
            spec_drift,
        }
    }

    fn empty_inspect(subscriptions: Vec<EnvironmentSubscriptionView>) -> EnvironmentInspectReport {
        EnvironmentInspectReport {
            name: "alpha".into(),
            id: "tenkai:env:alpha".into(),
            description: String::new(),
            subscriptions,
            facts: Default::default(),
            overlays: Default::default(),
            config: Vec::new(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            owner: None,
            approval_policy: None,
            exposure_grace_ms: None,
            terminal_outcomes: Vec::new(),
            execution_note: String::new(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
            delivery_freezes: Vec::new(),
            criticality: None,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
            cluster_namespaces: Vec::new(),
        }
    }

    fn certificate(
        expires_at: i64,
        near_expiry: bool,
        failure: Option<&str>,
    ) -> crate::certificate_reports::CertificateStatus {
        crate::certificate_reports::CertificateStatus {
            expires_at,
            near_expiry,
            renewal_failure: failure.map(Into::into),
        }
    }

    // #1372: the nearest expiry wins, and near expiry or a failing renewal on
    // any instance shows, not only on the nearest one.
    #[test]
    fn certificate_summary_folds_every_instance() {
        assert_eq!(FleetCertificateSummary::from_statuses([]), None);
        let statuses = [
            certificate(300, false, Some("issuer unreachable")),
            certificate(200, false, None),
            certificate(900, true, Some("refused")),
        ];
        assert_eq!(
            FleetCertificateSummary::from_statuses(&statuses),
            Some(FleetCertificateSummary {
                nearest_expires_at: 200,
                near_expiry: true,
                renewal_failing: 2,
            })
        );
    }

    // #1372: only instances modified outside Tenkai count as drifted.
    #[test]
    fn drifted_instances_count_modified_specs_only() {
        let drift = |status: &str| {
            Some(crate::spec_drift::SpecDriftView {
                status: status.into(),
                objects: Vec::new(),
            })
        };
        let report = empty_inspect(vec![
            current_subscription("api", drift(crate::spec_drift::SPEC_DRIFT_MODIFIED)),
            current_subscription("web", drift(crate::spec_drift::SPEC_DRIFT_CURRENT)),
            current_subscription("worker", drift(crate::spec_drift::SPEC_DRIFT_MODIFIED)),
            current_subscription("cron", None),
        ]);
        assert_eq!(fleet_row_from_inspect(&report).drifted_instances, 2);
    }

    #[test]
    fn fleet_status_classifies_current_behind_unhealthy_and_empty() {
        let current = EnvironmentInspectReport {
            name: "alpha".into(),
            id: "tenkai:env:alpha".into(),
            description: "ok".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),

                instance: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                overlay_digest: None,
                applied_overlay: None,
                state: "current".into(),
                delivery_hold: None,
                spec_drift: None,
            }],
            facts: Default::default(),
            overlays: Default::default(),
            config: Vec::new(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: Some(EnvironmentPlanSummary {
                id: "plan-a".into(),
                state: "succeeded".into(),
                created_at: 1,
                step_count: 1,
                digest: None,
                approval_brief: None,
                artifact_availability: Vec::new(),
                config_presets: Vec::new(),
                status_detail: String::new(),
                steps: Vec::new(),
                steps_truncated: false,
                approval: None,
            }),
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            owner: None,
            approval_policy: None,
            exposure_grace_ms: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
            delivery_freezes: Vec::new(),
            criticality: None,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
            cluster_namespaces: Vec::new(),
        };
        let behind = EnvironmentInspectReport {
            name: "beta".into(),
            id: "tenkai:env:beta".into(),
            description: "drift".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),

                instance: "api".into(),
                channel: "stable".into(),
                head: "2.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                overlay_digest: None,
                applied_overlay: None,
                state: "behind".into(),
                delivery_hold: None,
                spec_drift: None,
            }],
            facts: Default::default(),
            overlays: Default::default(),
            config: Vec::new(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: true,
                owner: Some("owner".into()),
                generation: Some(1),
                expires_at_ms: Some(99),
                status: "active".into(),
            },
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            owner: None,
            approval_policy: None,
            exposure_grace_ms: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
            delivery_freezes: Vec::new(),
            criticality: None,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
            cluster_namespaces: Vec::new(),
        };
        let unhealthy = EnvironmentInspectReport {
            name: "gamma".into(),
            id: "tenkai:env:gamma".into(),
            description: "bad".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),

                instance: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("unknown".into()),
                error: Some("probe failed".into()),
                overlay_digest: None,
                applied_overlay: None,
                state: "unknown".into(),
                delivery_hold: None,
                spec_drift: None,
            }],
            facts: Default::default(),
            overlays: Default::default(),
            config: Vec::new(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            owner: None,
            approval_policy: None,
            exposure_grace_ms: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
            delivery_freezes: Vec::new(),
            criticality: None,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
            cluster_namespaces: Vec::new(),
        };
        let empty = EnvironmentInspectReport {
            name: "delta".into(),
            id: "tenkai:env:delta".into(),
            description: "idle".into(),
            subscriptions: Vec::new(),
            facts: Default::default(),
            overlays: Default::default(),
            config: Vec::new(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            owner: None,
            approval_policy: None,
            exposure_grace_ms: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
            delivery_freezes: Vec::new(),
            criticality: None,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
            cluster_namespaces: Vec::new(),
        };
        let report = fleet_status_from_inspects(vec![behind, empty, unhealthy, current]);
        assert_eq!(report.environment_count, 4);
        assert_eq!(report.environments_current, 1);
        assert_eq!(report.environments_behind, 1);
        assert_eq!(report.environments_unhealthy, 1);
        assert_eq!(report.environments_empty, 1);
        let by_name = |name: &str| {
            report
                .environments
                .iter()
                .find(|row| row.name == name)
                .unwrap()
        };
        assert_eq!(by_name("alpha").posture, "current");
        assert_eq!(by_name("beta").posture, "behind");
        assert!(by_name("beta").lease_held);
        assert_eq!(by_name("gamma").posture, "unhealthy");
        assert_eq!(by_name("gamma").health_summary, "error");
        assert_eq!(by_name("delta").posture, "empty");
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("Bearer"));
        assert!(!encoded.contains("token="));
    }

    #[test]
    fn fleet_status_treats_config_stale_as_behind() {
        let stale = EnvironmentInspectReport {
            name: "edge".into(),
            id: "tenkai:env:edge".into(),
            description: "overlay".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),

                instance: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                overlay_digest: Some("abc".into()),
                applied_overlay: None,
                state: "config_stale".into(),
                delivery_hold: None,
                spec_drift: None,
            }],
            facts: Default::default(),
            overlays: Default::default(),
            config: Vec::new(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            maintenance: None,
            constraints: Vec::new(),
            webhooks: Vec::new(),
            owner: None,
            approval_policy: None,
            exposure_grace_ms: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
            retirement: None,
            preview: None,
            delivery_hold: None,
            delivery_freezes: Vec::new(),
            criticality: None,
            latest_failures: Vec::new(),
            sealed_recovery_warning: None,
            identity_issuer: None,
            identity_issuer_waiting: Vec::new(),
            cluster_namespaces: Vec::new(),
        };
        let report = fleet_status_from_inspects(vec![stale]);
        assert_eq!(report.environments[0].posture, "behind");
        assert_eq!(report.environments[0].products_behind, 1);
        assert!(!report.environments[0].unhealthy);
    }

    #[test]
    fn fleet_drift_reports_new_behind_and_unhealthy_transitions() {
        let previous = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "current".into()),
                ("gamma".into(), "current".into()),
            ]),
        };
        let current = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "behind".into()),
                ("gamma".into(), "unhealthy".into()),
            ]),
        };
        let delta = compare_fleet_posture(&previous, &current);
        assert_eq!(delta.entered_behind, vec!["beta".to_string()]);
        assert_eq!(delta.entered_unhealthy, vec!["gamma".to_string()]);
        assert_eq!(
            delta.new_hard_drift,
            vec!["beta".to_string(), "gamma".to_string()]
        );
        assert!(delta.has_new_hard_drift);
        assert!(delta.has_any_hard_drift);
        assert!(delta.has_any_posture_change);
        assert!(delta.left_current.contains(&"beta".to_string()));
        assert!(delta.left_current.contains(&"gamma".to_string()));
        assert!(delta.entered_empty.is_empty());
        assert!(delta.appeared.is_empty());
        assert!(delta.disappeared.is_empty());

        let stable = compare_fleet_posture(&current, &current);
        assert!(!stable.has_new_hard_drift);
        assert!(stable.has_any_hard_drift);
        assert!(!stable.has_any_posture_change);
        assert!(stable.new_hard_drift.is_empty());

        let recovered = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "current".into()),
                ("gamma".into(), "current".into()),
            ]),
        };
        let back = compare_fleet_posture(&current, &recovered);
        assert!(!back.has_new_hard_drift);
        assert!(!back.has_any_hard_drift);
        assert_eq!(back.left_behind, vec!["beta".to_string()]);
        assert_eq!(back.left_unhealthy, vec!["gamma".to_string()]);
        assert_eq!(back.entered_current.len(), 2);

        let from_status = fleet_posture_snapshot(&fleet_status_from_inspects(vec![]));
        assert!(from_status.postures.is_empty());
        assert_eq!(from_status.schema, "tenkai.fleet-posture.v1");

        let encoded = serde_json::to_string(&delta).unwrap();
        assert!(!encoded.contains("Bearer"));
        assert!(!encoded.contains("token="));
        assert!(!encoded.contains("TENKAI_MANAGEMENT_TOKEN"));
    }

    #[test]
    fn fleet_posture_baseline_round_trip_without_secrets() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-fleet-baseline-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        let snapshot = FleetPostureSnapshot {
            schema: fleet_posture_snapshot_schema(),
            postures: BTreeMap::from([
                ("alpha".into(), "current".into()),
                ("beta".into(), "behind".into()),
            ]),
        };
        write_fleet_posture_baseline(&path, &snapshot).unwrap();
        let loaded = load_fleet_posture_baseline(&path).unwrap();
        assert_eq!(loaded, snapshot);
        let missing = load_fleet_posture_baseline(&dir.join("missing.json")).unwrap();
        assert!(missing.postures.is_empty());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("Bearer"));
        assert!(!raw.contains("secret"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overdue_exposures_list_configured_max_age_breaches() {
        let mut report = fleet_status_from_inspects(Vec::new());
        report.environments = vec![FleetEnvironmentRow {
            name: "prod".into(),
            id: "tenkai:env:prod".into(),
            description: String::new(),
            subscription_count: 0,
            products_current: 0,
            products_behind: 0,
            products_missing: 0,
            unhealthy: false,
            health_summary: "n/a".into(),
            lease_held: false,
            latest_plan_state: None,
            awaiting_approval: false,
            drifted_instances: 0,
            certificates: None,
            runtimes: Vec::new(),
            posture: "empty".into(),
            criticality: None,
            open_exposures: vec![
                OpenEnvironmentExposure {
                    release: "api@1.0.0".into(),
                    advisory_id: "TENKAI-2026-1".into(),
                    severity: "high".into(),
                    first_seen_at: 1,
                    age_ms: 5,
                    overdue: true,
                    grace_ends_at: None,
                    in_grace: false,
                },
                OpenEnvironmentExposure {
                    release: "api@1.0.0".into(),
                    advisory_id: "TENKAI-2026-2".into(),
                    severity: "low".into(),
                    first_seen_at: 1,
                    age_ms: 5,
                    overdue: false,
                    grace_ends_at: None,
                    in_grace: false,
                },
            ],
            owner: None,
            unrouted: false,
        }];
        let overdue = overdue_exposures(&report);
        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0].0, "prod");
        assert_eq!(overdue[0].1.advisory_id, "TENKAI-2026-1");
    }
}

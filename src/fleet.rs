//! Fleet delivery posture: aggregation, drift comparison, and baseline I/O.
//!
//! Inspect reports and store-backed listing remain in [`crate::plan`]. This
//! module is the pure posture interface: callers feed inspect rows or fleet
//! rows and get deterministic aggregates, drift deltas, and baseline files
//! without learning subscription/lease classification details.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::plan::EnvironmentInspectReport;

/// One environment's row in a fleet posture table (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Latest plan state when a plan exists.
    pub latest_plan_state: Option<String>,
    /// Aggregate posture: `empty` | `unhealthy` | `behind` | `current`.
    pub posture: String,
}

/// Fleet-wide delivery posture (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatusReport {
    pub environments: Vec<FleetEnvironmentRow>,
    pub environment_count: usize,
    pub environments_current: usize,
    pub environments_behind: usize,
    pub environments_unhealthy: usize,
    pub environments_empty: usize,
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
        posture,
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

/// Load a posture baseline from a JSON file (missing file → empty snapshot).
pub fn load_fleet_posture_baseline(path: &Path) -> Result<FleetPostureSnapshot> {
    if !path.exists() {
        return Ok(FleetPostureSnapshot::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read fleet posture baseline {}", path.display()))?;
    let snapshot: FleetPostureSnapshot = serde_json::from_str(&raw)
        .with_context(|| format!("parse fleet posture baseline {}", path.display()))?;
    Ok(snapshot)
}

/// Persist a posture baseline as JSON (no secrets; names and postures only).
pub fn write_fleet_posture_baseline(path: &Path, snapshot: &FleetPostureSnapshot) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create baseline directory {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(snapshot).context("encode fleet posture baseline")?;
    std::fs::write(path, format!("{raw}\n"))
        .with_context(|| format!("write fleet posture baseline {}", path.display()))?;
    Ok(())
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
        environments,
        environment_count,
        environments_current,
        environments_behind,
        environments_unhealthy,
        environments_empty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{
        EnvironmentInspectReport, EnvironmentPlanSummary, EnvironmentSubscriptionView,
    };
    use std::collections::BTreeMap;

    #[test]
    fn fleet_status_classifies_current_behind_unhealthy_and_empty() {
        let current = EnvironmentInspectReport {
            name: "alpha".into(),
            id: "tenkai:env:alpha".into(),
            description: "ok".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                overlay_digest: None,
                applied_overlay: None,
                state: "current".into(),
            }],
            facts: Default::default(),
            overlays: Default::default(),
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
                status_detail: String::new(),
                steps: Vec::new(),
                steps_truncated: false,
            }),
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
        };
        let behind = EnvironmentInspectReport {
            name: "beta".into(),
            id: "tenkai:env:beta".into(),
            description: "drift".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),
                channel: "stable".into(),
                head: "2.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                overlay_digest: None,
                applied_overlay: None,
                state: "behind".into(),
            }],
            facts: Default::default(),
            overlays: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: true,
                owner: Some("owner".into()),
                generation: Some(1),
                expires_at_ms: Some(99),
                status: "active".into(),
            },
            latest_plan: None,
            terminal_outcomes: Vec::new(),
            execution_note: "fixture".into(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
        };
        let unhealthy = EnvironmentInspectReport {
            name: "gamma".into(),
            id: "tenkai:env:gamma".into(),
            description: "bad".into(),
            subscriptions: vec![EnvironmentSubscriptionView {
                product: "api".into(),
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("unknown".into()),
                error: Some("probe failed".into()),
                overlay_digest: None,
                applied_overlay: None,
                state: "unknown".into(),
            }],
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
        };
        let empty = EnvironmentInspectReport {
            name: "delta".into(),
            id: "tenkai:env:delta".into(),
            description: "idle".into(),
            subscriptions: Vec::new(),
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
                channel: "stable".into(),
                head: "1.0.0".into(),
                deployed: Some("1.0.0".into()),
                health: Some("healthy".into()),
                error: None,
                overlay_digest: Some("abc".into()),
                applied_overlay: None,
                state: "config_stale".into(),
            }],
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
}

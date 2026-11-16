use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use tenkai::plan;

pub(crate) fn print_fleet_status(report: &plan::FleetStatusReport) {
    println!(
        "fleet environments={} current={} behind={} unhealthy={} empty={}",
        report.environment_count,
        report.environments_current,
        report.environments_behind,
        report.environments_unhealthy,
        report.environments_empty
    );
    if report.environments.is_empty() {
        println!("no environments registered (tenkaictl env add <name>)");
        return;
    }
    println!(
        "{:<16} {:<10} {:<6} {:<6} {:<6} {:<6} {:<8} {:<10}",
        "name", "posture", "subs", "cur", "behind", "miss", "health", "lease"
    );
    for row in &report.environments {
        let lease = if row.lease_held { "held" } else { "-" };
        println!(
            "{:<16} {:<10} {:<6} {:<6} {:<6} {:<6} {:<8} {:<10}",
            row.name,
            row.posture,
            row.subscription_count,
            row.products_current,
            row.products_behind,
            row.products_missing,
            row.health_summary,
            lease
        );
        if let Some(owner) = &row.owner {
            println!("  owner {owner}");
        }
    }
    if !report.promotion_policies.is_empty() {
        println!("promotion policies:");
        for policy in &report.promotion_policies {
            let reason = policy.reason.as_deref().unwrap_or("-");
            println!(
                "  {}/{} <- {} {} {}",
                policy.product, policy.target_channel, policy.source_channel, policy.state, reason
            );
        }
    }
    print_open_exposures(report);
}

fn print_open_exposures(report: &plan::FleetStatusReport) {
    let mut any_exposure = false;
    for row in &report.environments {
        for exposure in &row.open_exposures {
            if !any_exposure {
                println!("open exposures:");
                any_exposure = true;
            }
            let overdue = if exposure.overdue { " overdue" } else { "" };
            println!(
                "  {} {} {} {} age_ms={}{overdue}",
                row.name,
                exposure.release,
                exposure.advisory_id,
                exposure.severity,
                exposure.age_ms
            );
        }
    }
}

pub(crate) struct FleetWatchOptions {
    pub(crate) interval: u64,
    pub(crate) once: bool,
    pub(crate) baseline: Option<PathBuf>,
    pub(crate) write_baseline: Option<PathBuf>,
    pub(crate) exit_on_any_posture_change: bool,
    pub(crate) exit_on_any_hard_drift: bool,
    pub(crate) json: bool,
    pub(crate) max_samples: u64,
}

/// Terminal program status reports (OSC 7501 program status specification,
/// revision 0.4). Fixed bytes: a root record carrying only the state and the
/// program name, never an environment, release, or advisory name.
const STATUS_IDLE: &[u8] = b"\x1b]7501;state=idle:app=tenkaictl\x1b\\";
const STATUS_ERROR: &[u8] = b"\x1b]7501;state=error:app=tenkaictl\x1b\\";

/// Runs `fleet watch` against stdout. When stdout is a terminal and output is
/// text, it also reports `idle` or `error` program status after each sample
/// and `error` before any non-zero exit.
pub(crate) async fn run_fleet_watch<F, Fut>(sample: F, opts: FleetWatchOptions) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<plan::FleetStatusReport>>,
{
    let terminal = std::io::stdout().is_terminal();
    watch_with_status(sample, opts, terminal, &mut std::io::stdout()).await
}

/// The watch loop with the terminal check injected, so tests can script it.
/// `out` receives only status reports; it shares stdout's buffer in
/// production, so reports follow the text they summarize.
async fn watch_with_status<F, Fut, W: Write>(
    sample: F,
    opts: FleetWatchOptions,
    terminal: bool,
    out: &mut W,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<plan::FleetStatusReport>>,
{
    let mut status = (terminal && !opts.json).then_some(out);
    let result = watch_samples(sample, opts, &mut status).await;
    if result.is_err() {
        // Best effort: the watch error is what the caller must see.
        let _ = report_status(&mut status, STATUS_ERROR);
    }
    result
}

fn report_status<W: Write>(status: &mut Option<&mut W>, bytes: &[u8]) -> std::io::Result<()> {
    let Some(out) = status else {
        return Ok(());
    };
    out.write_all(bytes)?;
    out.flush()
}

async fn watch_samples<F, Fut, W: Write>(
    mut sample: F,
    opts: FleetWatchOptions,
    status: &mut Option<&mut W>,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<plan::FleetStatusReport>>,
{
    let mut previous = if let Some(path) = &opts.baseline {
        plan::load_fleet_posture_baseline(path)?
    } else {
        plan::FleetPostureSnapshot::default()
    };
    let mut samples = 0u64;
    loop {
        let report = sample().await?;
        let current = plan::fleet_posture_snapshot(&report);
        let delta = plan::compare_fleet_posture(&previous, &current);
        if opts.json {
            let mut value = serde_json::to_value(&delta)?;
            if let serde_json::Value::Object(map) = &mut value {
                map.insert(
                    "open_exposures".into(),
                    serde_json::to_value(watch_open_exposures(&report))?,
                );
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            print_fleet_drift(&delta, &report);
        }
        if let Some(path) = &opts.write_baseline {
            plan::write_fleet_posture_baseline(path, &current)?;
        }
        samples += 1;
        let overdue = tenkai::fleet::overdue_exposures(&report);
        if !overdue.is_empty() {
            let detail = overdue
                .iter()
                .map(|(environment, exposure)| {
                    format!(
                        "{environment} {} {} age_ms={}",
                        exposure.release, exposure.advisory_id, exposure.age_ms
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            bail!("fleet watch: exposure exceeded maximum age ({detail})");
        }
        let should_exit_error = if opts.exit_on_any_posture_change {
            delta.has_any_posture_change
        } else if opts.exit_on_any_hard_drift {
            delta.has_any_hard_drift
        } else {
            // Default: non-zero only when *new* hard drift appears vs baseline/prior sample.
            delta.has_new_hard_drift
        };
        if should_exit_error {
            bail!(
                "fleet drift watch: new hard drift detected ({})",
                if delta.new_hard_drift.is_empty() {
                    if delta.has_any_hard_drift {
                        "hard drift present".to_string()
                    } else {
                        "posture changed".to_string()
                    }
                } else {
                    delta.new_hard_drift.join(",")
                }
            );
        }
        let clean = report.environments_behind == 0 && report.environments_unhealthy == 0;
        report_status(status, if clean { STATUS_IDLE } else { STATUS_ERROR })?;
        if opts.once || (opts.max_samples > 0 && samples >= opts.max_samples) {
            return Ok(());
        }
        previous = current;
        tokio::time::sleep(Duration::from_secs(opts.interval.max(1))).await;
    }
}

pub(crate) fn print_fleet_drift(delta: &plan::FleetDriftSummary, report: &plan::FleetStatusReport) {
    let change = if delta.has_any_posture_change {
        "changed"
    } else {
        "stable"
    };
    println!(
        "fleet watch {change} new_hard_drift={} any_hard_drift={} environments={} current={} behind={} unhealthy={} empty={}",
        delta.has_new_hard_drift,
        delta.has_any_hard_drift,
        report.environment_count,
        report.environments_current,
        report.environments_behind,
        report.environments_unhealthy,
        report.environments_empty
    );
    if !delta.has_any_posture_change {
        println!("no posture drift vs baseline");
    } else {
        let print_list = |label: &str, names: &[String]| {
            if !names.is_empty() {
                println!("{label}: {}", names.join(", "));
            }
        };
        print_list("entered behind", &delta.entered_behind);
        print_list("left behind", &delta.left_behind);
        print_list("entered unhealthy", &delta.entered_unhealthy);
        print_list("left unhealthy", &delta.left_unhealthy);
        print_list("entered empty", &delta.entered_empty);
        print_list("left empty", &delta.left_empty);
        print_list("entered current", &delta.entered_current);
        print_list("left current", &delta.left_current);
        print_list("appeared", &delta.appeared);
        print_list("disappeared", &delta.disappeared);
        print_list("new hard drift", &delta.new_hard_drift);
    }
    print_open_exposures(report);
}

fn watch_open_exposures(report: &plan::FleetStatusReport) -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for row in &report.environments {
        for exposure in &row.open_exposures {
            rows.push(serde_json::json!({
                "environment": row.name,
                "release": exposure.release,
                "advisory_id": exposure.advisory_id,
                "severity": exposure.severity,
                "first_seen_at": exposure.first_seen_at,
                "age_ms": exposure.age_ms,
                "overdue": exposure.overdue,
            }));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use anyhow::anyhow;
    use tenkai::fleet::{FleetEnvironmentRow, FleetStatusReport, OpenEnvironmentExposure};

    use super::*;

    const ENV: &str = "prod-eu";
    const RELEASE: &str = "api@1.0.0";
    const ADVISORY: &str = "adv-7";

    fn options() -> FleetWatchOptions {
        FleetWatchOptions {
            interval: 0,
            once: false,
            baseline: None,
            write_baseline: None,
            exit_on_any_posture_change: false,
            exit_on_any_hard_drift: false,
            json: false,
            max_samples: 0,
        }
    }

    /// One-environment report with the given posture and an optional overdue exposure.
    fn report(posture: &str, overdue: bool) -> FleetStatusReport {
        let open_exposures = if overdue {
            vec![OpenEnvironmentExposure {
                release: RELEASE.into(),
                advisory_id: ADVISORY.into(),
                severity: "high".into(),
                first_seen_at: 0,
                age_ms: 10,
                overdue: true,
                grace_ends_at: None,
                in_grace: false,
            }]
        } else {
            Vec::new()
        };
        FleetStatusReport {
            server_version: String::new(),
            environments: vec![FleetEnvironmentRow {
                name: ENV.into(),
                id: "env-1".into(),
                description: String::new(),
                subscription_count: 1,
                products_current: usize::from(posture == "current"),
                products_behind: usize::from(posture == "behind"),
                products_missing: 0,
                unhealthy: posture == "unhealthy",
                health_summary: "ok".into(),
                lease_held: false,
                latest_plan_state: None,
                posture: posture.into(),
                criticality: None,
                open_exposures,
                owner: None,
                unrouted: false,
            }],
            environment_count: 1,
            environments_current: usize::from(posture == "current"),
            environments_behind: usize::from(posture == "behind"),
            environments_unhealthy: usize::from(posture == "unhealthy"),
            environments_empty: 0,
            promotion_policies: Vec::new(),
        }
    }

    /// Runs the watch over scripted samples and returns its result and status bytes.
    async fn watch(
        samples: Vec<Result<FleetStatusReport>>,
        opts: FleetWatchOptions,
        terminal: bool,
    ) -> (Result<()>, Vec<u8>) {
        let mut samples = VecDeque::from(samples);
        let mut out = Vec::new();
        let result = watch_with_status(
            || std::future::ready(samples.pop_front().expect("scripted sample")),
            opts,
            terminal,
            &mut out,
        )
        .await;
        (result, out)
    }

    fn statuses(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[tokio::test]
    async fn reports_idle_on_clean_samples_and_error_on_hard_drift() {
        let opts = FleetWatchOptions {
            max_samples: 3,
            ..options()
        };
        let (result, out) = watch(
            vec![
                Ok(report("current", false)),
                Ok(report("current", false)),
                Ok(report("behind", false)),
            ],
            opts,
            true,
        )
        .await;
        assert!(result.is_err(), "new hard drift exits non-zero");
        assert_eq!(out, statuses(&[STATUS_IDLE, STATUS_IDLE, STATUS_ERROR]));
    }

    fn temp_baseline(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-fleet-watch-{label}-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    #[tokio::test]
    async fn known_drift_keeps_watching_and_reports_error() {
        // Drift already in the baseline does not exit, but is still not idle.
        let baseline = temp_baseline("known");
        plan::write_fleet_posture_baseline(
            &baseline,
            &plan::fleet_posture_snapshot(&report("behind", false)),
        )
        .expect("write baseline");
        let opts = FleetWatchOptions {
            baseline: Some(baseline.clone()),
            max_samples: 2,
            ..options()
        };
        let (result, out) = watch(
            vec![Ok(report("behind", false)), Ok(report("behind", false))],
            opts,
            true,
        )
        .await;
        std::fs::remove_file(&baseline).expect("remove baseline");
        result.expect("known drift keeps watching");
        assert_eq!(out, statuses(&[STATUS_ERROR, STATUS_ERROR]));
    }

    #[tokio::test]
    async fn every_failing_exit_reports_error_once() {
        let failing = [
            vec![Err(anyhow!("server unreachable"))],
            vec![Ok(report("current", true))],
            vec![Ok(report("unhealthy", false))],
            vec![Ok(report("current", false)), Err(anyhow!("token expired"))],
        ];
        for (index, samples) in failing.into_iter().enumerate() {
            let clean_before = samples.len() - 1;
            let (result, out) = watch(samples, options(), true).await;
            assert!(result.is_err(), "case {index} exits non-zero");
            let mut expected = vec![STATUS_IDLE; clean_before];
            expected.push(STATUS_ERROR);
            assert_eq!(out, statuses(&expected), "case {index}");
        }
    }

    #[tokio::test]
    async fn an_unreadable_baseline_reports_error() {
        let baseline = temp_baseline("corrupt");
        std::fs::write(&baseline, "not json").expect("write baseline");
        let opts = FleetWatchOptions {
            baseline: Some(baseline.clone()),
            ..options()
        };
        let (result, out) = watch(Vec::new(), opts, true).await;
        std::fs::remove_file(&baseline).expect("remove baseline");
        assert!(result.is_err());
        assert_eq!(out, STATUS_ERROR);
    }

    #[tokio::test]
    async fn no_terminal_or_json_writes_no_status() {
        for (terminal, json) in [(false, false), (false, true), (true, true)] {
            for samples in [
                vec![Ok(report("current", false))],
                vec![Ok(report("behind", false))],
                vec![Err(anyhow!("server unreachable"))],
            ] {
                let opts = FleetWatchOptions {
                    once: true,
                    json,
                    ..options()
                };
                let (_, out) = watch(samples, opts, terminal).await;
                assert!(out.is_empty(), "terminal={terminal} json={json}");
            }
        }
    }

    #[test]
    fn status_reports_carry_only_state_and_program() {
        for (bytes, state) in [(STATUS_IDLE, "idle"), (STATUS_ERROR, "error")] {
            let text = std::str::from_utf8(bytes).expect("ascii");
            let body = text
                .strip_prefix("\x1b]7501;")
                .and_then(|rest| rest.strip_suffix("\x1b\\"))
                .expect("OSC 7501 framing with ST");
            assert_eq!(body, format!("state={state}:app=tenkaictl"));
            for name in [ENV, RELEASE, ADVISORY] {
                assert!(!text.contains(name));
            }
        }
    }
}

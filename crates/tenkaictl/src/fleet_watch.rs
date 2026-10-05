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

pub(crate) async fn run_fleet_watch<F, Fut>(mut sample: F, opts: FleetWatchOptions) -> Result<()>
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
            println!("{}", serde_json::to_string_pretty(&delta)?);
        } else {
            print_fleet_drift(&delta, &report);
        }
        if let Some(path) = &opts.write_baseline {
            plan::write_fleet_posture_baseline(path, &current)?;
        }
        samples += 1;
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
        return;
    }
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

//! `tenkaictl report`: read-only reports computed from recorded state.

use clap::Subcommand;
use tenkai::delivery_report::{DeliveryReport, DeliveryReportQuery};

use crate::args::OutputFormat;

#[derive(Subcommand)]
pub(crate) enum ReportCommand {
    /// Deployment frequency, lead time, change failure rate, time to restore,
    /// and advisory exposure age per product and channel.
    Delivery {
        #[arg(long, env = "TENKAI_ENVIRONMENT")]
        env: String,
        /// Inclusive start, Unix milliseconds. Default: 30 days before the end.
        #[arg(long)]
        since_ms: Option<i64>,
        /// Exclusive end, Unix milliseconds. Default: now.
        #[arg(long)]
        until_ms: Option<i64>,
    },
}

impl ReportCommand {
    /// The environment and query of `report delivery`.
    pub(crate) fn delivery(&self) -> (&str, DeliveryReportQuery) {
        let Self::Delivery {
            env,
            since_ms,
            until_ms,
        } = self;
        (
            env,
            DeliveryReportQuery {
                since_ms: *since_ms,
                until_ms: *until_ms,
            },
        )
    }
}

/// The report itself as JSON under `-o json`, otherwise one line per row.
pub(crate) fn print_delivery_report(
    report: &DeliveryReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    if output == OutputFormat::JsonV1 {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "{} from {} to {} (Unix ms){}",
        report.environment,
        report.since_ms,
        report.until_ms,
        if report.missing_data {
            ": missing data, nothing recorded or reported in this period"
        } else {
            ""
        }
    );
    println!(
        "{:<20} {:<12} {:>7} {:>9} {:>13} {:>8} {:>10} {:>14} {:>9} {:>14}",
        "product",
        "channel",
        "deploys",
        "failures",
        "failure_rate",
        "restores",
        "unrestored",
        "restore_ms",
        "exposures",
        "exposure_age_ms"
    );
    let or_dash = |value: Option<i64>| value.map_or_else(|| "-".into(), |v| v.to_string());
    for row in &report.rows {
        println!(
            "{:<20} {:<12} {:>7} {:>9} {:>13} {:>8} {:>10} {:>14} {:>9} {:>14}  lead_time_ms={}",
            row.product,
            row.channel.as_deref().unwrap_or("-"),
            row.deployments,
            format!("{}/{}", row.change_failures, row.change_attempts),
            row.change_failure_rate
                .map_or_else(|| "-".into(), |rate| format!("{:.1}%", rate * 100.0)),
            row.restores,
            row.unrestored,
            or_dash(row.time_to_restore_ms),
            row.open_exposures,
            or_dash(row.oldest_exposure_age_ms),
            or_dash(row.lead_time_ms),
        );
    }
    Ok(())
}

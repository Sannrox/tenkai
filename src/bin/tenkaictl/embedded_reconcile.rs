use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use tenkai::{client, reconciler};

use crate::args::Command;
use crate::output::print_reconcile_report;

pub(crate) async fn run(ctx: client::Ctx, command: Command) -> Result<()> {
    let Command::Reconcile {
        once,
        interval,
        initial_backoff,
        max_backoff,
        max_concurrency,
        skip_gates,
        bypass,
    } = command
    else {
        unreachable!("reconcile dispatcher received a non-reconcile command");
    };
    let reconciler = reconciler::Reconciler::new(
        ctx.clone(),
        reconciler::Config {
            initial_backoff: Duration::from_secs(initial_backoff),
            max_backoff: Duration::from_secs(max_backoff),
            max_concurrency,
            skip_gates,
            unapproved_development_reason: bypass.allow_unapproved_development.then(|| {
                bypass
                    .development_reason
                    .clone()
                    .expect("clap requires a development reason")
            }),
            approval_directory: std::env::var_os("TENKAI_PLAN_APPROVAL_DIR").map(PathBuf::from),
            approval_trust_roots: std::env::var_os("TENKAI_PLAN_APPROVAL_TRUST_ROOTS")
                .map(PathBuf::from),
            ..reconciler::Config::default()
        },
    )?;
    if once {
        let report = reconciler.run_once().await?;
        let failures = report.failures();
        print_reconcile_report(report);
        if failures > 0 {
            bail!("{failures} environment(s) failed to reconcile");
        }
    } else {
        reconciler
            .run_until(Duration::from_secs(interval), |report| match report {
                Ok(report) => print_reconcile_report(report),
                Err(error) => eprintln!("reconciliation tick failed: {error:#}"),
            })
            .await?;
    }
    Ok(())
}

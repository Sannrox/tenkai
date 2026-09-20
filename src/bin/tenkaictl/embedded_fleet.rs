use std::path::Path;

use anyhow::Result;
use tenkai::{client, fleet_budget, fleet_fairness, fleet_workload, plan};

use crate::fleet_args::FleetCommand;
use crate::fleet_watch::{FleetWatchOptions, print_fleet_status, run_fleet_watch};

pub(crate) async fn run(
    ctx: &mut client::Ctx,
    command: FleetCommand,
    database: &Path,
) -> Result<()> {
    match command {
        FleetCommand::Status => {
            let report = plan::fleet_status(ctx).await?;
            print_fleet_status(&report);
        }
        FleetCommand::Generate {
            seed,
            product,
            channel,
            current_version,
            behind_version,
        } => {
            let spec = fleet_workload::WorkloadSpec {
                seed,
                product,
                channel,
                current_version,
                behind_version,
            };
            let record = fleet_workload::materialize(ctx, &spec).await?;
            println!("{}", fleet_workload::format_workload(&record));
        }
        FleetCommand::Measure {
            seed,
            product,
            channel,
            current_version,
            behind_version,
        } => {
            let spec = fleet_workload::WorkloadSpec {
                seed,
                product,
                channel,
                current_version,
                behind_version,
            };
            let budget = fleet_budget::ResourceBudget::ci_embedded_sqlite();
            let (plan, report) = fleet_budget::measure(ctx, &spec, database, &budget).await?;
            println!("{}", fleet_workload::format_workload(&plan));
            println!("{}", fleet_budget::format_report(&report));
        }
        FleetCommand::Fairness {
            seed,
            product,
            channel,
            current_version,
            behind_version,
            backup,
        } => {
            let spec = fleet_workload::WorkloadSpec {
                seed,
                product,
                channel,
                current_version,
                behind_version,
            };
            let (plan, report) = fleet_fairness::observe(ctx, &spec, &backup, database).await?;
            println!("{}", fleet_workload::format_workload(&plan));
            println!("{}", fleet_fairness::format_report(&report));
        }
        FleetCommand::Watch {
            interval,
            once,
            baseline,
            write_baseline,
            exit_on_any_posture_change,
            exit_on_any_hard_drift,
            json,
            max_samples,
        } => {
            run_fleet_watch(
                || {
                    // Re-open embedded ctx per sample so long watches see durable writes.
                    let database = database.to_path_buf();
                    async move {
                        let mut sample_ctx = client::Ctx::embedded(&database)?;
                        plan::fleet_status(&mut sample_ctx).await
                    }
                },
                FleetWatchOptions {
                    interval,
                    once,
                    baseline,
                    write_baseline,
                    exit_on_any_posture_change,
                    exit_on_any_hard_drift,
                    json,
                    max_samples,
                },
            )
            .await?;
        }
    }
    Ok(())
}

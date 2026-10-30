use anyhow::Result;
use tenkai::client;
use tenkai::recall_notice::{self, ProposeRequest, RecallNotice};
use tenkai::release_signing::TrustRoots;
use tenkai::wave;

use crate::args::RemediateCommand;
use crate::authorization::embedded_management_actor;

pub(crate) async fn run(ctx: &mut client::Ctx, command: RemediateCommand) -> Result<()> {
    let actor = embedded_management_actor()?;
    match command {
        RemediateCommand::Propose {
            exposure,
            fix,
            channel,
            cohort,
            wave_name,
            signing_key,
            notice_out,
        } => {
            let environments: Vec<String> = cohort
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
            let wave_name = wave_name.unwrap_or_else(|| format!("recall-{exposure}"));
            let proposal = recall_notice::propose(
                ctx,
                &actor,
                ProposeRequest {
                    exposure: exposure.clone(),
                    fix,
                    channel,
                    environments,
                    wave_name,
                    signing_key,
                    notice_out: notice_out.clone(),
                },
            )
            .await?;
            println!(
                "proposed recall of {} release(s) for {}; wave {} {}; notice {}",
                proposal.recalled.len(),
                proposal.advisory_id,
                proposal.wave.name,
                proposal.wave.status.as_str(),
                notice_out.display()
            );
            for spec in &proposal.recalled {
                println!("recalled {spec}");
            }
            for running in &proposal.environments {
                println!(
                    "running {} on {}",
                    running.deployed_release, running.environment
                );
            }
            println!("{}", wave::format_wave(&proposal.wave));
        }
        RemediateCommand::ImportNotice {
            notice,
            trust_roots,
        } => {
            let notice = RecallNotice::load(&notice)?;
            let authorities = TrustRoots::load(&trust_roots)?;
            let report = recall_notice::import(ctx, &actor, &notice, &authorities).await?;
            println!(
                "imported recall notice for {} ({} recalled, {} already recalled, {} missing)",
                report.advisory_id,
                report.recalled.len(),
                report.already_recalled.len(),
                report.missing.len()
            );
            for spec in &report.recalled {
                println!("recalled {spec}");
            }
            for running in &report.environments {
                println!(
                    "running {} on {}",
                    running.deployed_release, running.environment
                );
            }
        }
    }
    Ok(())
}

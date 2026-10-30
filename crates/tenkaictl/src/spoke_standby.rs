use anyhow::Result;
use tenkai::spoke_standby;

use crate::args::SpokeStandbyCommand;

/// Spoke-standby profile commands need no Tenkai operational store.
pub(crate) fn run(command: &SpokeStandbyCommand) -> Result<()> {
    match command {
        SpokeStandbyCommand::Validate { profile } => {
            let profile = spoke_standby::SpokeStandbyProfile::load(profile)?;
            println!(
                "spoke-standby members={} backup_interval_ms={} promotion={:?} exclusive_lock={} witness={}",
                profile.members,
                profile.backup_interval_ms,
                profile.promotion,
                profile.exclusive_lock,
                profile.witness
            );
        }
        SpokeStandbyCommand::Promote {
            profile,
            holder,
            lease_dir,
            state,
            signing_key,
        } => {
            let profile = spoke_standby::SpokeStandbyProfile::load(profile)?;
            let evidence = spoke_standby::promote_on_disk(
                &profile,
                holder,
                lease_dir,
                state,
                signing_key,
                tenkai::now_millis() as u64,
            )?;
            println!(
                "promoted {} generation {} (fenced {})",
                evidence.statement.holder,
                evidence.statement.generation,
                evidence.statement.fenced_generation
            );
        }
        SpokeStandbyCommand::Drill {
            profile,
            signing_key,
            out,
        } => {
            let profile = spoke_standby::SpokeStandbyProfile::load(profile)?;
            let evidence = spoke_standby::drill(&profile, signing_key)?;
            if let Some(path) = out {
                spoke_standby::write_evidence(path, &evidence)?;
            }
            let s = &evidence.statement;
            println!(
                "spoke-standby drill passed: killed {} promoted {} generation {} interruption_window_ms={} acknowledged_loss_bound_ms={}",
                s.killed,
                s.promoted,
                s.generation,
                s.interruption_window_ms,
                s.acknowledged_loss_bound_ms
            );
        }
    }
    Ok(())
}

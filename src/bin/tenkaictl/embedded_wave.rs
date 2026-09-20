use anyhow::{Result, bail};
use tenkai::{client, wave};

use crate::authorization::wave_authorization;
use crate::wave_args::WaveCommand;

pub(crate) async fn run(ctx: &mut client::Ctx, command: WaveCommand) -> Result<()> {
    match command {
        WaveCommand::Run {
            cohort,
            continue_on_failure,
        } => {
            let environments: Vec<String> = cohort
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
            let spec = wave::WaveSpec::new(environments, !continue_on_failure)?;
            let report = wave::run_wave_observe(ctx, &spec).await?;
            println!("{}", wave::format_report(&report));
            if report.failed_count > 0 {
                bail!("wave failed for {} environment(s)", report.failed_count);
            }
        }
        WaveCommand::Execute {
            name,
            product,
            version,
            channel,
            cohort,
            continue_on_failure,
            approval,
        } => {
            let environments: Vec<String> = cohort
                .split(',')
                .map(str::trim)
                .filter(|env| !env.is_empty())
                .map(str::to_string)
                .collect();
            let spec = wave::ExecutableWaveSpec::new(
                name,
                product,
                version,
                channel,
                environments,
                !continue_on_failure,
            )?;
            let authorization = wave_authorization(
                approval.approval_dir.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
            )?;
            let record = wave::run_until_blocked(ctx, &spec, authorization).await?;
            println!("{}", wave::format_wave(&record));
            if matches!(
                record.status,
                wave::WaveStatus::Failed | wave::WaveStatus::RecoveryRequired
            ) {
                bail!("wave {} ended in {}", record.name, record.status.as_str());
            }
        }
        WaveCommand::Status { name } => {
            let record = wave::load_wave(ctx, &name).await?;
            println!("{}", wave::format_wave(&record));
        }
        WaveCommand::Stop { name } => {
            let record = wave::stop_wave(ctx, &name).await?;
            println!("{}", wave::format_wave(&record));
        }
        WaveCommand::Resume { name, approval } => {
            let authorization = wave_authorization(
                approval.approval_dir.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
            )?;
            loop {
                let record = wave::advance(ctx, &name, authorization).await?;
                if record.status == wave::WaveStatus::AwaitingApproval
                    || record.status == wave::WaveStatus::Succeeded
                    || record.status == wave::WaveStatus::Failed
                    || record.status == wave::WaveStatus::RolledBack
                    || record.status == wave::WaveStatus::RecoveryRequired
                {
                    println!("{}", wave::format_wave(&record));
                    if matches!(
                        record.status,
                        wave::WaveStatus::Failed | wave::WaveStatus::RecoveryRequired
                    ) {
                        bail!("wave {} ended in {}", record.name, record.status.as_str());
                    }
                    break;
                }
            }
        }
        WaveCommand::Rollback { name, approval } => {
            let authorization = wave_authorization(
                approval.approval_dir.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
            )?;
            let record = wave::rollback_wave(ctx, &name, authorization).await?;
            println!("{}", wave::format_wave(&record));
            if record.status == wave::WaveStatus::RecoveryRequired {
                bail!("wave {} rollback requires recovery", record.name);
            }
        }
    }
    Ok(())
}

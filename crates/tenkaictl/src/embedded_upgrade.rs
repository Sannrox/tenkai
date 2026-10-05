use anyhow::{Result, bail};
use tenkai::{apply, client, connectivity, offline_bundle, release_signing};

use crate::authorization::execution_authorization;
use crate::upgrade_args::UpgradeCommand;

pub(crate) async fn run(ctx: &mut client::Ctx, command: UpgradeCommand) -> Result<()> {
    match command {
        UpgradeCommand::Start {
            name,
            product,
            version,
            channel,
            cohort,
        } => {
            let environments: Vec<String> = cohort
                .split(',')
                .map(str::trim)
                .filter(|env| !env.is_empty())
                .map(str::to_string)
                .collect();
            let spec = connectivity::UpgradeSpec {
                name,
                product,
                version,
                channel,
                environments,
            };
            let record = connectivity::start_or_resume(ctx, &spec).await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::Status { name } => {
            let record = connectivity::load_upgrade(ctx, &name).await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::Advance { name, approval } => {
            let authorization = execution_authorization(
                approval.approval.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
                "upgrade execution requires --approval and --approval-trust-roots, or --allow-unapproved-development with --development-reason",
            )?;
            let record = connectivity::advance(ctx, &name, authorization).await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::Interrupt { name, env } => {
            let record = connectivity::interrupt_transfer(ctx, &name, &env).await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::Resume { name, env } => {
            let record = connectivity::resume_transfer(ctx, &name, &env).await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::BindBundle {
            name,
            env,
            bundle,
            trust_roots,
        } => {
            let envelope = offline_bundle::BundleEnvelope::load(&bundle)?;
            let roots = release_signing::TrustRoots::load(&trust_roots)?;
            let record =
                connectivity::bind_isolated_bundle(ctx, &name, &env, &envelope, &roots).await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::ImportReceipt {
            name,
            env,
            receipt,
            bundle,
            trust_roots,
        } => {
            let bundle_envelope = offline_bundle::BundleEnvelope::load(&bundle)?;
            let receipt_envelope = offline_bundle::ReceiptEnvelope::load(&receipt)?;
            let roots = release_signing::TrustRoots::load(&trust_roots)?;
            let record = connectivity::import_isolated_receipt(
                ctx,
                &name,
                &env,
                &receipt_envelope,
                &bundle_envelope,
                &roots,
            )
            .await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
        UpgradeCommand::Rollback { name, bypass } => {
            if !bypass.allow_unapproved_development {
                bail!(
                    "upgrade rollback requires --allow-unapproved-development; signed rollback plans are created at apply time and cannot reuse a pre-issued approval envelope"
                );
            }
            let record = connectivity::rollback_upgrade(
                ctx,
                &name,
                apply::ExecutionAuthorization::LocalDevelopment {
                    reason: bypass
                        .development_reason
                        .as_deref()
                        .unwrap_or("upgrade rollback"),
                },
            )
            .await?;
            println!("{}", connectivity::format_upgrade(&record));
        }
    }
    Ok(())
}

use anyhow::{Result, bail};
use tenkai::{client, package_migration};

use crate::authorization::migration_authorization;
use crate::migrate_args::MigrateCommand;

pub(crate) async fn run(ctx: &mut client::Ctx, command: MigrateCommand) -> Result<()> {
    match command {
        MigrateCommand::Preview {
            name,
            env,
            declaration,
            backup_receipt_digest,
        } => {
            let declaration = package_migration::MigrationDeclaration::load(&declaration)?;
            let record = package_migration::preview(
                ctx,
                &name,
                &env,
                declaration,
                backup_receipt_digest.as_deref(),
            )
            .await?;
            println!("{}", package_migration::format_migration(&record));
        }
        MigrateCommand::Apply {
            name,
            env,
            declaration,
            backup_receipt_digest,
            expected_generation: _,
            approval,
        } => {
            let declaration = package_migration::MigrationDeclaration::load(&declaration)?;
            let authorization = migration_authorization(
                approval.approval.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
            )?;
            let record = package_migration::run_until_blocked(
                ctx,
                &name,
                &env,
                declaration,
                backup_receipt_digest.as_deref(),
                authorization,
                None,
            )
            .await?;
            println!("{}", package_migration::format_migration(&record));
            if matches!(
                record.status,
                package_migration::MigrationStatus::Failed
                    | package_migration::MigrationStatus::RecoveryRequired
            ) {
                bail!(
                    "package migration {} ended in {}",
                    record.name,
                    record.status.as_str()
                );
            }
        }
        MigrateCommand::Status { name } => {
            let record = package_migration::load(ctx, &name).await?;
            println!("{}", package_migration::format_migration(&record));
        }
        MigrateCommand::Resume {
            name,
            expected_generation,
            approval,
        } => {
            let authorization = migration_authorization(
                approval.approval.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
            )?;
            let mut last_receipts = 0;
            loop {
                let record =
                    package_migration::resume(ctx, &name, authorization, expected_generation)
                        .await?;
                if matches!(
                    record.status,
                    package_migration::MigrationStatus::Succeeded
                        | package_migration::MigrationStatus::Failed
                        | package_migration::MigrationStatus::RolledBack
                        | package_migration::MigrationStatus::RecoveryRequired
                ) || record.receipts.len() == last_receipts
                {
                    println!("{}", package_migration::format_migration(&record));
                    if matches!(
                        record.status,
                        package_migration::MigrationStatus::Failed
                            | package_migration::MigrationStatus::RecoveryRequired
                    ) {
                        bail!(
                            "package migration {} ended in {}",
                            record.name,
                            record.status.as_str()
                        );
                    }
                    break;
                }
                last_receipts = record.receipts.len();
            }
        }
        MigrateCommand::Rollback {
            name,
            expected_generation,
            approval,
        } => {
            let authorization = migration_authorization(
                approval.approval.as_deref(),
                approval.approval_trust_roots.as_deref(),
                approval.allow_unapproved_development,
                approval.development_reason.as_deref(),
            )?;
            let record =
                package_migration::rollback(ctx, &name, authorization, expected_generation).await?;
            println!("{}", package_migration::format_migration(&record));
            if record.status == package_migration::MigrationStatus::RecoveryRequired {
                bail!(
                    "package migration {} rollback requires recovery",
                    record.name
                );
            }
        }
    }
    Ok(())
}

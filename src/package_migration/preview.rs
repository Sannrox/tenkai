//! Preview, create, and run-until-blocked admission orchestration.

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::ontology::require_package_migration_schema;

use super::admit::admit;
use super::approval::require_approval;
use super::execute::{approve_in, execute_in};
use super::rollback::load_in;
use super::types::{
    MigrationAuthorization, MigrationDeclaration, MigrationRecord, MigrationStatus,
};

pub async fn preview(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
) -> Result<MigrationRecord> {
    preview_in(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        None,
    )
    .await
}

pub async fn preview_in(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    admit(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        true,
        partition,
    )
    .await
}

pub async fn create(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
) -> Result<MigrationRecord> {
    create_in(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        None,
    )
    .await
}

pub async fn create_in(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    admit(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        false,
        partition,
    )
    .await
}

/// Admit (if needed), approve, and execute until the migration is terminal or stuck.
pub async fn run_until_blocked(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    run_until_blocked_in(
        ctx,
        name,
        environment,
        declaration,
        backup_receipt_digest,
        authorization,
        expected_generation,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_until_blocked_in(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    require_package_migration_schema(ctx).await?;
    let existing = ctx.get(&super::types::catalog_id(partition, name)).await?;
    let record = if existing.is_some() {
        let stored = load_in(ctx, name, partition).await?;
        let expected = declaration.identity_digest(environment, backup_receipt_digest)?;
        if stored.identity_digest != expected || stored.environment != environment {
            bail!("package migration {name} already exists with a different identity");
        }
        stored
    } else {
        create_in(
            ctx,
            name,
            environment,
            declaration,
            backup_receipt_digest,
            partition,
        )
        .await?
    };
    match record.status {
        MigrationStatus::Succeeded
        | MigrationStatus::Failed
        | MigrationStatus::RolledBack
        | MigrationStatus::RecoveryRequired => return Ok(record),
        MigrationStatus::Admitted if record.approval_digest.is_empty() => {
            approve_in(ctx, name, authorization, partition).await?;
        }
        MigrationStatus::Admitted | MigrationStatus::Running => {
            require_approval(&record, authorization)?;
        }
    }
    let mut last_receipts = record.receipts.len();
    let mut fence_checked = false;
    loop {
        let expected = if fence_checked {
            None
        } else {
            fence_checked = true;
            expected_generation
        };
        let next = execute_in(ctx, name, authorization, expected, partition).await?;
        if matches!(
            next.status,
            MigrationStatus::Succeeded
                | MigrationStatus::Failed
                | MigrationStatus::RolledBack
                | MigrationStatus::RecoveryRequired
        ) {
            return Ok(next);
        }
        if next.receipts.len() == last_receipts {
            return Ok(next);
        }
        last_receipts = next.receipts.len();
    }
}

pub fn format_migration(record: &MigrationRecord) -> String {
    let mut lines = vec![format!(
        "package-migration name={} status={} identity={} env={} fence={} approval={}",
        record.name,
        record.status.as_str(),
        record.identity_digest,
        record.environment,
        record.fence_generation,
        if record.approval_digest.is_empty() {
            "-"
        } else {
            &record.approval_digest
        }
    )];
    lines.push(format!(
        "source {}@{} {}",
        record.declaration.source.product,
        record.declaration.source.version,
        record.declaration.source.digest
    ));
    lines.push(format!(
        "target {}@{} {}",
        record.declaration.target.product,
        record.declaration.target.version,
        record.declaration.target.digest
    ));
    if let Some(backup) = &record.backup_receipt_digest {
        lines.push(format!("backup {backup}"));
    }
    if let Some(plan_id) = &record.pending_plan_id {
        lines.push(format!("pending-plan {plan_id}"));
    }
    if let Some(plan_id) = &record.pending_rollback_plan_id {
        lines.push(format!("pending-rollback-plan {plan_id}"));
    }
    lines.push(format!(
        "{:<16} {:<14} {:<12} fence",
        "checkpoint", "class", "result"
    ));
    for checkpoint in &record.declaration.checkpoints {
        let receipt = record
            .receipts
            .iter()
            .find(|receipt| receipt.checkpoint_id == checkpoint.id);
        match receipt {
            Some(receipt) => lines.push(format!(
                "{:<16} {:<14} {:<12} {}",
                checkpoint.id,
                checkpoint.class.as_str(),
                receipt.result,
                receipt.fence_generation
            )),
            None => lines.push(format!(
                "{:<16} {:<14} {:<12} -",
                checkpoint.id,
                checkpoint.class.as_str(),
                "-"
            )),
        }
    }
    lines.push(
        "note: accepted irreversible work cannot report rollback success; recover from Tenkai receipts"
            .into(),
    );
    lines.join("\n")
}

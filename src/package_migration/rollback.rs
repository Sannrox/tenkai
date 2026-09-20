//! Rollback and catalog load for stored migration records.

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::ontology::{require_package_migration_schema, validate_identifier};

use super::approval::require_approval;
use super::compensate::{compensate_accepted, require_rollback_target};
use super::leases::{
    acquire_environment_lock, acquire_execution_lease, release_environment_lock,
    release_execution_lease,
};
use super::persist::persist;
use super::types::{
    CheckpointClass, MigrationAuthorization, MigrationRecord, MigrationStatus, catalog_id,
};

pub async fn rollback(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    rollback_in(ctx, name, authorization, expected_generation, None).await
}

pub async fn rollback_in(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    require_package_migration_schema(ctx).await?;
    let record = load_in(ctx, name, partition).await?;
    require_approval(&record, authorization)?;
    if let Some(expected) = expected_generation
        && expected != record.fence_generation
    {
        bail!(
            "stale fencing generation {expected} for package migration rollback {name}; current is {}",
            record.fence_generation
        );
    }
    let exec_lease = acquire_execution_lease(ctx, name, partition).await?;
    let result = rollback_locked(ctx, record, authorization, &exec_lease).await;
    release_execution_lease(ctx, name, partition, &exec_lease).await;
    result
}

async fn rollback_locked(
    ctx: &mut Ctx,
    mut record: MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<MigrationRecord> {
    if matches!(
        record.status,
        MigrationStatus::Admitted | MigrationStatus::RolledBack
    ) {
        record.status = MigrationStatus::RolledBack;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record).await?;
        return Ok(record);
    }
    acquire_environment_lock(ctx, &record).await?;
    if let Err(error) = require_rollback_target(ctx, &record).await {
        record.status = MigrationStatus::RecoveryRequired;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record).await?;
        return Err(error);
    }
    record.fence_generation += 1;
    for receipt in record.receipts.iter().rev() {
        if receipt.class == CheckpointClass::Irreversible && receipt.result == "accepted" {
            record.status = MigrationStatus::RecoveryRequired;
            persist(ctx, &record).await?;
            release_environment_lock(ctx, &record).await?;
            bail!(
                "package migration {} crossed irreversible checkpoint {}; rollback cannot claim success",
                record.name,
                receipt.checkpoint_id
            );
        }
        if receipt.result == "accepted"
            && !matches!(
                receipt.class,
                CheckpointClass::Reversible | CheckpointClass::Compensating
            )
        {
            record.status = MigrationStatus::RecoveryRequired;
            persist(ctx, &record).await?;
            release_environment_lock(ctx, &record).await?;
            bail!(
                "package migration {} cannot compensate checkpoint {}",
                record.name,
                receipt.checkpoint_id
            );
        }
    }
    if let Err(error) = compensate_accepted(ctx, &mut record, authorization, exec_lease).await {
        record.status = MigrationStatus::RecoveryRequired;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record).await?;
        return Err(error);
    }
    for receipt in &mut record.receipts {
        if receipt.result == "accepted" {
            receipt.result = "rolled_back".into();
            receipt.fence_generation = record.fence_generation;
        }
    }
    record.status = MigrationStatus::RolledBack;
    record.pending_plan_id = None;
    record.pending_rollback_plan_id = None;
    persist(ctx, &record).await?;
    release_environment_lock(ctx, &record).await?;
    Ok(record)
}

pub async fn load(ctx: &mut Ctx, name: &str) -> Result<MigrationRecord> {
    load_in(ctx, name, None).await
}

pub async fn load_in(
    ctx: &mut Ctx,
    name: &str,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    validate_identifier("migration name", name)?;
    if let Some(partition) = partition {
        validate_identifier("migration partition", partition)?;
    }
    require_package_migration_schema(ctx).await?;
    let object = ctx
        .get(&catalog_id(partition, name))
        .await?
        .with_context(|| format!("package migration {name} is not stored"))?;
    let raw = object
        .properties
        .get("record")
        .context("package migration record is missing")?;
    let record: MigrationRecord = serde_json::from_str(raw)?;
    if record.name != name {
        bail!("stored package migration name does not match {name}");
    }
    if record.partition.as_deref() != partition.filter(|value| !value.is_empty()) {
        bail!("stored package migration partition does not match");
    }
    Ok(record)
}

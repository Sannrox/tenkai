//! Approve, execute, and resume one migration checkpoint.

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::ontology::require_package_migration_schema;
use crate::plan::{self, PlanState};

use super::approval::require_approval;
use super::checkpoint::{CheckpointProgress, execute_checkpoint};
use super::declaration::checkpoint_effect;
use super::leases::{
    acquire_environment_lock, acquire_execution_lease, release_environment_lock,
    release_execution_lease,
};
use super::persist::persist;
use super::rollback::load_in;
use super::types::{CheckpointReceipt, MigrationAuthorization, MigrationRecord, MigrationStatus};

pub async fn approve(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
) -> Result<MigrationRecord> {
    approve_in(ctx, name, authorization, None).await
}

pub(super) async fn approve_in(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    let mut record = load_in(ctx, name, partition).await?;
    if record.status != MigrationStatus::Admitted {
        bail!(
            "package migration {name} is {}, not admitted",
            record.status.as_str()
        );
    }
    record.approval_digest = super::approval::approval_digest(&record, authorization)?;
    persist(ctx, &record).await?;
    Ok(record)
}

pub async fn execute(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    execute_in(ctx, name, authorization, expected_generation, None).await
}

pub(super) async fn execute_in(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    step(
        ctx,
        name,
        authorization,
        expected_generation,
        false,
        partition,
    )
    .await
}

pub async fn resume(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
) -> Result<MigrationRecord> {
    resume_in(ctx, name, authorization, expected_generation, None).await
}

pub async fn resume_in(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    step(
        ctx,
        name,
        authorization,
        expected_generation,
        true,
        partition,
    )
    .await
}

async fn step(
    ctx: &mut Ctx,
    name: &str,
    authorization: MigrationAuthorization<'_>,
    expected_generation: Option<u64>,
    resume: bool,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    require_package_migration_schema(ctx).await?;
    let record = load_in(ctx, name, partition).await?;
    require_approval(&record, authorization)?;
    if let Some(expected) = expected_generation
        && expected != record.fence_generation
    {
        bail!(
            "stale fencing generation {expected} for package migration {name}; current is {}",
            record.fence_generation
        );
    }
    let exec_lease = acquire_execution_lease(ctx, name, partition).await?;
    let result = step_locked(ctx, record, authorization, resume, &exec_lease).await;
    release_execution_lease(ctx, name, partition, &exec_lease).await;
    result
}

async fn step_locked(
    ctx: &mut Ctx,
    mut record: MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    resume: bool,
    exec_lease: &str,
) -> Result<MigrationRecord> {
    match record.status {
        MigrationStatus::Admitted if !resume => {
            record.fence_generation += 1;
            record.status = MigrationStatus::Running;
        }
        MigrationStatus::Running if resume || !record.receipts.is_empty() => {}
        MigrationStatus::Succeeded if resume => return Ok(record),
        other => bail!(
            "package migration {} cannot execute from {}",
            record.name,
            other.as_str()
        ),
    }
    acquire_environment_lock(ctx, &record).await?;
    let next = record.declaration.checkpoints.get(record.receipts.len());
    let Some(checkpoint) = next.cloned() else {
        record.status = MigrationStatus::Succeeded;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record).await?;
        return Ok(record);
    };
    if checkpoint.class == super::types::CheckpointClass::Irreversible
        && record.backup_receipt_digest.is_none()
    {
        record.status = MigrationStatus::Failed;
        persist(ctx, &record).await?;
        release_environment_lock(ctx, &record).await?;
        bail!(
            "irreversible checkpoint {} has no backup receipt; refusing the first effect",
            checkpoint.id
        );
    }
    if record
        .receipts
        .iter()
        .any(|receipt| receipt.checkpoint_id == checkpoint.id)
    {
        persist(ctx, &record).await?;
        return Ok(record);
    }
    match execute_checkpoint(ctx, &mut record, &checkpoint, authorization, exec_lease).await {
        Ok(CheckpointProgress::Accepted { plan_id }) => {
            record.pending_plan_id = None;
            record.pending_rollback_plan_id = None;
            record.receipts.push(CheckpointReceipt {
                checkpoint_id: checkpoint.id.clone(),
                class: checkpoint.class,
                effect: checkpoint_effect(checkpoint.class).into(),
                result: "accepted".into(),
                fence_generation: record.fence_generation,
                plan_id,
            });
            if record.receipts.len() == record.declaration.checkpoints.len() {
                record.status = MigrationStatus::Succeeded;
            } else {
                record.status = MigrationStatus::Running;
            }
            persist(ctx, &record).await?;
            if record.status == MigrationStatus::Succeeded {
                release_environment_lock(ctx, &record).await?;
            }
            Ok(record)
        }
        Ok(CheckpointProgress::AwaitingPlanApproval { plan_id }) => {
            record.pending_plan_id = Some(plan_id);
            persist(ctx, &record).await?;
            Ok(record)
        }
        Err(error) => {
            if let Some(plan_id) = record.pending_plan_id.clone()
                && let Ok(plan) = plan::load(ctx, &plan_id).await
            {
                if plan.state == PlanState::Succeeded {
                    record.pending_plan_id = None;
                    record.receipts.push(CheckpointReceipt {
                        checkpoint_id: checkpoint.id.clone(),
                        class: checkpoint.class,
                        effect: checkpoint_effect(checkpoint.class).into(),
                        result: "accepted".into(),
                        fence_generation: record.fence_generation,
                        plan_id: Some(plan_id),
                    });
                    record.status = if record.receipts.len() == record.declaration.checkpoints.len()
                    {
                        MigrationStatus::Succeeded
                    } else {
                        MigrationStatus::Running
                    };
                    persist(ctx, &record).await?;
                    if record.status == MigrationStatus::Succeeded {
                        release_environment_lock(ctx, &record).await?;
                    }
                    return Ok(record);
                }
                if plan.state != PlanState::Computed {
                    record.status = MigrationStatus::RecoveryRequired;
                    persist(ctx, &record).await?;
                    return Err(error);
                }
            }
            record.status = MigrationStatus::Failed;
            persist(ctx, &record).await?;
            release_environment_lock(ctx, &record).await?;
            Err(error)
        }
    }
}

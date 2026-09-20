//! Compensation, source restore, and rollback-target checks.

use anyhow::{Context as _, Result, bail};

use crate::apply::{self, ExecutionAuthorization, ExecutionOptions};
use crate::client::Ctx;
use crate::plan::{self, PlanState};

use super::checkpoint::create_pin_plan;
use super::leases::{authorize_plan_on_lock, clear_authorized_plan, refresh_execution_lease};
use super::persist::persist;
use super::types::{MigrationAuthorization, MigrationRecord};

pub(super) async fn pending_plan_started(ctx: &mut Ctx, record: &MigrationRecord) -> Result<bool> {
    let Some(plan_id) = &record.pending_plan_id else {
        return Ok(false);
    };
    let plan = plan::load(ctx, plan_id).await?;
    Ok(plan.state != PlanState::Computed)
}

pub(super) async fn require_rollback_target(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    if !record
        .receipts
        .iter()
        .any(|receipt| receipt.result == "accepted" && receipt.effect == "apply_target")
        && !pending_plan_started(ctx, record).await?
    {
        return Ok(());
    }
    let env = crate::environment::environment(ctx, &record.environment).await?;
    let deployed = env
        .properties
        .get(&format!("deployed.{}", record.declaration.target.product))
        .map(String::as_str);
    if deployed != Some(record.declaration.target.version.as_str()) {
        bail!(
            "package migration {} cannot roll back because {} is no longer at target {}",
            record.name,
            record.declaration.target.product,
            record.declaration.target.version
        );
    }
    Ok(())
}

pub(super) async fn compensate_accepted(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<()> {
    let attempted_apply = pending_plan_started(ctx, record).await?
        || record
            .receipts
            .iter()
            .any(|receipt| receipt.result == "accepted" && receipt.effect == "apply_target");
    if attempted_apply {
        restore_source(ctx, record, authorization, exec_lease).await?;
    }
    Ok(())
}

async fn restore_source(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<()> {
    refresh_execution_lease(ctx, &record.name, record.partition.as_deref(), exec_lease).await?;
    let pin = record.declaration.source.clone();
    let plan_id = match record.pending_rollback_plan_id.clone() {
        Some(id) => id,
        None => {
            let plan_id = create_pin_plan(ctx, record, &pin).await?.id;
            record.pending_rollback_plan_id = Some(plan_id.clone());
            persist(ctx, record).await?;
            plan_id
        }
    };
    apply_pin_plan(ctx, record, &plan_id, authorization, exec_lease).await
}

async fn apply_pin_plan(
    ctx: &mut Ctx,
    record: &MigrationRecord,
    plan_id: &str,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<()> {
    let approval_path;
    let exec = match authorization {
        MigrationAuthorization::LocalDevelopment { reason } => {
            ExecutionAuthorization::LocalDevelopment { reason }
        }
        MigrationAuthorization::Signed {
            approval,
            trust_roots,
        } => {
            let dir = approval
                .parent()
                .context("package migration approval path has no parent")?;
            approval_path = dir.join(format!("{plan_id}.json"));
            if !approval_path.is_file() {
                bail!(
                    "package migration rollback plan {plan_id} is waiting for a signed plan approval at {}",
                    approval_path.display()
                );
            }
            ExecutionAuthorization::Signed {
                approval: &approval_path,
                trust_roots,
            }
        }
    };
    refresh_execution_lease(ctx, &record.name, record.partition.as_deref(), exec_lease).await?;
    authorize_plan_on_lock(ctx, record, plan_id).await?;
    let applied = apply::execute_with_options(
        ctx,
        plan_id,
        ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: exec,
            software_executor: crate::software_executor::selected_software_executor()
                .map(std::sync::Arc::from),
            worker_lifecycle: None,
            artifact_registry: crate::oci_artifact::selected_registry()?,
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await;
    clear_authorized_plan(ctx, record).await?;
    applied?;
    let plan = plan::load(ctx, plan_id).await?;
    if plan.state != PlanState::Succeeded {
        bail!("package migration plan {plan_id} ended in {}", plan.state);
    }
    Ok(())
}

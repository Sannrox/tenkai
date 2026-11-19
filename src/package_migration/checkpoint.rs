//! Checkpoint execution, pin revalidation, and target apply.

use anyhow::{Context as _, Result, bail};

use crate::apply::{self, ExecutionAuthorization, ExecutionOptions};
use crate::catalog::{self, CatalogReader as _};
use crate::client::Ctx;
use crate::plan::{self, Action, ReleasePin as PlanReleasePin, Step};

use super::admit::{catalog_digest, require_package_pin};
use super::declaration::checkpoint_effect;
use super::leases::{authorize_plan_on_lock, clear_authorized_plan, refresh_execution_lease};
use super::persist::persist;
use super::types::{
    CheckpointDecl, CompatibilityStatus, MigrationAuthorization, MigrationRecord, PackagePin,
};

pub(super) enum CheckpointProgress {
    Accepted { plan_id: Option<String> },
    AwaitingPlanApproval { plan_id: String },
}

pub(super) async fn execute_checkpoint(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    checkpoint: &CheckpointDecl,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<CheckpointProgress> {
    refresh_execution_lease(ctx, &record.name, record.partition.as_deref(), exec_lease).await?;
    match checkpoint_effect(checkpoint.class) {
        "revalidate" => {
            let owner = format!("package-migration:{}", record.name);
            let lease = apply::claim_environment(ctx, &record.environment, &owner).await?;
            let result = revalidate_pins(ctx, record).await;
            let released = apply::release_environment(ctx, &lease).await;
            primary_first(
                result,
                released,
                "revalidation passed",
                "releasing the environment lease",
            )?;
            Ok(CheckpointProgress::Accepted { plan_id: None })
        }
        "apply_target" => {
            let pin = record.declaration.target.clone();
            apply_pin(ctx, record, &pin, authorization, exec_lease).await
        }
        other => bail!("unknown package migration checkpoint effect {other}"),
    }
}

async fn revalidate_pins(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    if record.declaration.compatibility.status != CompatibilityStatus::Compatible {
        bail!("package migration compatibility evidence is not compatible");
    }
    require_package_pin(ctx, &record.declaration.source).await?;
    require_package_pin(ctx, &record.declaration.target).await?;
    let env = crate::environment::environment(ctx, &record.environment).await?;
    let deployed = env
        .properties
        .get(&format!("deployed.{}", record.declaration.source.product))
        .map(String::as_str);
    if deployed != Some(record.declaration.source.version.as_str())
        && deployed != Some(record.declaration.target.version.as_str())
    {
        bail!(
            "package migration {} requires {} to be at source {} or target {}",
            record.name,
            record.declaration.source.product,
            record.declaration.source.version,
            record.declaration.target.version
        );
    }
    if catalog::release_is_recalled(
        ctx,
        &crate::ontology::release_id(
            &record.declaration.source.product,
            &record.declaration.source.version,
        ),
    )
    .await?
        || catalog::release_is_recalled(
            ctx,
            &crate::ontology::release_id(
                &record.declaration.target.product,
                &record.declaration.target.version,
            ),
        )
        .await?
    {
        bail!("package migration cannot use a recalled source or target release");
    }
    Ok(())
}

pub(super) async fn apply_pin(
    ctx: &mut Ctx,
    record: &mut MigrationRecord,
    pin: &PackagePin,
    authorization: MigrationAuthorization<'_>,
    exec_lease: &str,
) -> Result<CheckpointProgress> {
    revalidate_pins(ctx, record).await?;
    let plan_id = match record.pending_plan_id.clone() {
        Some(id) => id,
        None => {
            let plan_id = create_pin_plan(ctx, record, pin).await?.id;
            record.pending_plan_id = Some(plan_id.clone());
            persist(ctx, record).await?;
            plan_id
        }
    };
    refresh_execution_lease(ctx, &record.name, record.partition.as_deref(), exec_lease).await?;
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
                return Ok(CheckpointProgress::AwaitingPlanApproval { plan_id });
            }
            ExecutionAuthorization::Signed {
                approval: &approval_path,
                trust_roots,
                requester: None,
            }
        }
    };
    authorize_plan_on_lock(ctx, record, &plan_id).await?;
    let applied = apply::execute_with_options(
        ctx,
        &plan_id,
        ExecutionOptions {
            rollback_hold: true,
            skip_gates: false,
            emergency_reason: None,
            authorization: exec,
            software_executors: crate::software_executor::SoftwareExecutors::try_from_process()?,
            model_runtime_executor: crate::model_runtime::selected_model_runtime_executor_factory(),
            worker_lifecycle: None,
            artifact_registry: crate::oci_artifact::selected_registry()?,
            delivery_adapter: None,
        },
    )
    .await;
    // Both run whatever the apply did; neither replaces its result (#1338).
    // A lost execution lease still fails the checkpoint: it is a fence.
    let cleared = clear_authorized_plan(ctx, record).await;
    let refreshed =
        refresh_execution_lease(ctx, &record.name, record.partition.as_deref(), exec_lease).await;
    primary_first(
        applied.map(drop),
        cleared.and(refreshed.map(drop)),
        &format!("plan {plan_id} applied"),
        "clearing its authorization or refreshing the migration execution lease",
    )?;
    let plan = plan::load(ctx, &plan_id).await?;
    if plan.state != plan::PlanState::Succeeded {
        bail!("package migration plan {plan_id} ended in {}", plan.state);
    }
    Ok(CheckpointProgress::Accepted {
        plan_id: Some(plan_id),
    })
}

pub(super) async fn create_pin_plan(
    ctx: &mut Ctx,
    record: &MigrationRecord,
    pin: &PackagePin,
) -> Result<plan::Plan> {
    let release_id = crate::ontology::release_id(&pin.product, &pin.version);
    let descriptor = catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(&release_id, &record.environment)
        .await
        .map_err(anyhow::Error::from)?;
    let stored = catalog_digest(&descriptor.manifest_digest)?;
    if stored != pin.digest {
        bail!(
            "release {release_id} digest {stored} does not match migration pin {}",
            pin.digest
        );
    }
    let env = crate::environment::environment(ctx, &record.environment).await?;
    let deployed = env
        .properties
        .get(&format!("deployed.{}", pin.product))
        .cloned()
        .filter(|value| !value.is_empty());
    let restore = match deployed.as_deref() {
        Some(version) => {
            let current_id = crate::ontology::release_id(&pin.product, version);
            let current = catalog::EmbeddedCatalog::new(ctx)
                .lookup_release(&current_id, &record.environment)
                .await
                .map_err(anyhow::Error::from)?;
            Some(PlanReleasePin {
                release_id: current.release_id,
                digest: current.manifest_digest,
                artifact_digest: current.artifact_digest,
                workdir: current.content_path,
            })
        }
        None => {
            let source_id = crate::ontology::release_id(
                &record.declaration.source.product,
                &record.declaration.source.version,
            );
            let source = catalog::EmbeddedCatalog::new(ctx)
                .lookup_release(&source_id, &record.environment)
                .await
                .map_err(anyhow::Error::from)?;
            Some(PlanReleasePin {
                release_id: source.release_id,
                digest: source.manifest_digest,
                artifact_digest: source.artifact_digest,
                workdir: source.content_path,
            })
        }
    };
    let action = match deployed.as_deref() {
        None => Action::Install,
        Some(version) if version == pin.version => Action::Restart,
        Some(_) => Action::Upgrade,
    };
    let peers = crate::plan::current_peers(
        ctx,
        &record.environment,
        &env,
        &pin.product,
        &descriptor.release_id,
    )
    .await?;
    let identity = crate::plan::step_identity(
        ctx,
        &env,
        &record.environment,
        &descriptor.release_id,
        &pin.product,
        &peers,
    )
    .await?;
    let restore_identity = match &restore {
        Some(restore) => {
            let peers = crate::plan::current_peers(
                ctx,
                &record.environment,
                &env,
                &pin.product,
                &restore.release_id,
            )
            .await?;
            crate::plan::step_identity(
                ctx,
                &env,
                &record.environment,
                &restore.release_id,
                &pin.product,
                &peers,
            )
            .await?
        }
        None => None,
    };
    let step = Step {
        id: String::new(),
        order: 0,
        product: pin.product.clone(),
        instance: String::new(),
        action,
        from: deployed,
        to: pin.version.clone(),
        release_id: descriptor.release_id,
        release_digest: descriptor.manifest_digest,
        artifact_digest: descriptor.artifact_digest,
        workdir: descriptor.content_path,
        host: None,
        sealed: Vec::new(),
        restore,
        rewrap: None,
        issuer: None,
        identity,
        restore_identity,
        target_changes: Vec::new(),
    };
    plan::create_from_steps(ctx, &record.environment, vec![step]).await
}

/// The primary step's result with a cleanup failure attached to it, never in
/// its place (#1338): a failed step keeps its own error first, and a step
/// that took effect says so (`done`) before naming the failed `cleanup`.
pub(super) fn primary_first<T>(
    primary: Result<T>,
    cleanup: Result<()>,
    done: &str,
    cleanup_name: &str,
) -> Result<T> {
    match (primary, cleanup) {
        (primary, Ok(())) => primary,
        (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
            "{error:#}; {cleanup_name} also failed: {cleanup:#}"
        )),
        (Ok(_), Err(cleanup)) => Err(cleanup.context(format!("{done}, but {cleanup_name} failed"))),
    }
}

#[cfg(test)]
mod tests {
    use super::primary_first;

    #[test]
    fn a_cleanup_failure_never_replaces_the_primary_result() {
        let cleanup = || Err(anyhow::anyhow!("lock store unavailable"));
        let applied =
            primary_first(Ok(()), cleanup(), "plan p applied", "clearing it").unwrap_err();
        assert!(
            format!("{applied:#}").starts_with("plan p applied, but clearing it failed"),
            "{applied:#}"
        );
        let refused = primary_first::<()>(
            Err(anyhow::anyhow!("gate refused")),
            cleanup(),
            "plan p applied",
            "clearing it",
        )
        .unwrap_err();
        assert!(
            refused
                .to_string()
                .starts_with("gate refused; clearing it also failed"),
            "{refused}"
        );
        assert!(primary_first(Ok(7), Ok(()), "", "").is_ok_and(|value| value == 7));
    }
}

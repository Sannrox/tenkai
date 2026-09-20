//! Execution leases and environment migration locks.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};

use crate::apply;
use crate::client::Ctx;
use crate::ontology::{KIND_PACKAGE_MIGRATION_LOCK, NS};
use crate::pb::sekai::Object;

use super::types::{
    MIGRATION_EXEC_NAMESPACE, MIGRATION_EXEC_TTL_MS, MigrationRecord, exec_lease_name,
    record_lock_id,
};

pub(super) async fn acquire_execution_lease(
    ctx: &mut Ctx,
    name: &str,
    partition: Option<&str>,
) -> Result<String> {
    let lease_name = exec_lease_name(partition, name);
    match ctx
        .acquire_lease(
            MIGRATION_EXEC_NAMESPACE,
            &lease_name,
            "execute",
            MIGRATION_EXEC_TTL_MS,
        )
        .await
    {
        Ok(lease) => Ok(lease.fencing_token),
        Err(error)
            if error
                .downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::AlreadyExists) =>
        {
            bail!("package migration {name} already has an execution in progress")
        }
        Err(error) => Err(error),
    }
}

pub(super) async fn release_execution_lease(
    ctx: &mut Ctx,
    name: &str,
    partition: Option<&str>,
    fencing_token: &str,
) {
    let lease_name = exec_lease_name(partition, name);
    let _ = ctx
        .release_lease(MIGRATION_EXEC_NAMESPACE, &lease_name, fencing_token)
        .await;
}

pub(super) async fn refresh_execution_lease(
    ctx: &mut Ctx,
    name: &str,
    partition: Option<&str>,
    fencing_token: &str,
) -> Result<()> {
    let lease_name = exec_lease_name(partition, name);
    ctx.refresh_lease(
        MIGRATION_EXEC_NAMESPACE,
        &lease_name,
        fencing_token,
        MIGRATION_EXEC_TTL_MS,
    )
    .await?;
    Ok(())
}

pub(super) async fn authorize_plan_on_lock(
    ctx: &mut Ctx,
    record: &MigrationRecord,
    plan_id: &str,
) -> Result<()> {
    let id = record_lock_id(record);
    let environment = &record.environment;
    let mut object = ctx
        .get(&id)
        .await?
        .with_context(|| format!("package migration lock for {environment} is missing"))?;
    object
        .properties
        .insert("allowed_plan_id".into(), plan_id.into());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(())
}

pub(super) async fn clear_authorized_plan(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    let id = record_lock_id(record);
    let Some(mut object) = ctx.get(&id).await? else {
        return Ok(());
    };
    object.properties.remove("allowed_plan_id");
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(())
}

pub(super) async fn acquire_environment_lock(
    ctx: &mut Ctx,
    record: &MigrationRecord,
) -> Result<()> {
    let owner = format!("package-migration:{}", record.name);
    let lease = apply::claim_environment(ctx, &record.environment, &owner).await?;
    let id = record_lock_id(record);
    let result = async {
        if let Some(existing) = ctx.get(&id).await? {
            let lock_owner = existing
                .properties
                .get("owner")
                .map(String::as_str)
                .unwrap_or_default();
            if lock_owner != record.name {
                bail!(
                    "environment {} already has package migration {lock_owner} in progress",
                    record.environment
                );
            }
            return Ok(());
        }
        ctx.create_once(Object {
            id,
            kind: KIND_PACKAGE_MIGRATION_LOCK.into(),
            name: format!("lock-{}", record.environment),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), record.environment.clone()),
                ("owner".into(), record.name.clone()),
            ]),
            created: crate::now_millis(),
            updated: crate::now_millis(),
        })
        .await?;
        Ok(())
    }
    .await;
    apply::release_environment(ctx, &lease).await?;
    result
}

pub(super) async fn release_environment_lock(
    ctx: &mut Ctx,
    record: &MigrationRecord,
) -> Result<()> {
    let id = record_lock_id(record);
    let Some(existing) = ctx.get(&id).await? else {
        return Ok(());
    };
    if existing.properties.get("owner").map(String::as_str) != Some(record.name.as_str()) {
        return Ok(());
    }
    ctx.delete(&id).await?;
    Ok(())
}

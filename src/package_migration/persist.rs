//! Durable create and update of package migration catalog objects.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::ontology::{KIND_PACKAGE_MIGRATION, NS, require_package_migration_schema};
use crate::pb::record::Object;

use super::types::{MigrationListEntry, MigrationRecord, record_catalog_id};

/// List stored package migrations in `partition` (community hosts pass `None`).
pub async fn list_in(ctx: &mut Ctx, partition: Option<&str>) -> Result<Vec<MigrationListEntry>> {
    let expected = partition.filter(|value| !value.is_empty());
    let mut items = Vec::new();
    for object in ctx.list_kind(KIND_PACKAGE_MIGRATION).await? {
        let Some(raw) = object.properties.get("record") else {
            continue;
        };
        let record: MigrationRecord = serde_json::from_str(raw)?;
        if record.partition.as_deref() != expected {
            continue;
        }
        items.push(MigrationListEntry {
            id: object.id,
            name: record.name,
            environment: record.environment,
            status: record.status,
        });
    }
    items.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(items)
}

pub(super) async fn persist_new(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    require_package_migration_schema(ctx).await?;
    let id = record_catalog_id(record);
    if let Some(existing) = ctx.get(&id).await? {
        let stored: MigrationRecord = serde_json::from_str(
            existing
                .properties
                .get("record")
                .context("stored package migration has no record")?,
        )?;
        if stored.identity_digest == record.identity_digest
            && stored.declaration == record.declaration
        {
            return Ok(());
        }
        bail!(
            "package migration {} already exists with a different identity",
            record.name
        );
    }
    ctx.create_once(record_object(record, crate::now_millis())?)
        .await?;
    Ok(())
}

pub(super) async fn persist(ctx: &mut Ctx, record: &MigrationRecord) -> Result<()> {
    require_package_migration_schema(ctx).await?;
    let object = updated_object(ctx, record).await?;
    ctx.put(object).await?;
    Ok(())
}

/// [`persist`] committed only while the migration execution lease
/// `fencing_token` names is still held (#1294).
pub(super) async fn persist_fenced(
    ctx: &mut Ctx,
    record: &MigrationRecord,
    lease_name: &str,
    fencing_token: &str,
) -> Result<()> {
    require_package_migration_schema(ctx).await?;
    let object = updated_object(ctx, record).await?;
    ctx.guarded_update(
        object,
        super::types::MIGRATION_EXEC_NAMESPACE,
        lease_name,
        fencing_token,
    )
    .await?;
    Ok(())
}

/// The object for an update of `record`: stamped `updated` now, keeping the
/// stored object's `created` (#1336).
async fn updated_object(ctx: &mut Ctx, record: &MigrationRecord) -> Result<Object> {
    let mut object = record_object(record, crate::now_millis())?;
    if let Some(existing) = ctx.get(&object.id).await? {
        object.created = existing.created;
    }
    Ok(object)
}

fn record_object(record: &MigrationRecord, now: i64) -> Result<Object> {
    Ok(Object {
        id: record_catalog_id(record),
        kind: KIND_PACKAGE_MIGRATION.into(),
        name: record.name.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("name".into(), record.name.clone()),
            ("identity_digest".into(), record.identity_digest.clone()),
            ("environment".into(), record.environment.clone()),
            ("status".into(), record.status.as_str().into()),
            ("record".into(), serde_json::to_string(record)?),
        ]),
        created: now,
        updated: now,
    })
}

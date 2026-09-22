use super::*;

pub(super) fn import_objects_in(tx: &Transaction<'_>, objects: &[Object]) -> Result<()> {
    let mut ordered = objects.to_vec();
    ordered.sort_by_key(|object| authority_rank(&object.kind));
    for object in &ordered {
        upsert_object_in(tx, object, "tenkai")?;
    }
    Ok(())
}

pub(super) fn authority_rank(kind: &str) -> u8 {
    match kind {
        KIND_ENVIRONMENT => 0,
        KIND_RELEASE => 1,
        KIND_CHANNEL => 2,
        KIND_PLAN => 3,
        _ => 4,
    }
}

pub(super) fn upsert_object_in(
    tx: &Transaction<'_>,
    object: &Object,
    _principal: &str,
) -> Result<()> {
    match object.kind.as_str() {
        KIND_ENVIRONMENT => upsert_environment_in(tx, object)?,
        KIND_RELEASE => upsert_release_in(tx, object)?,
        KIND_CHANNEL => upsert_channel_in(tx, object)?,
        KIND_PLAN => upsert_plan_in(tx, object)?,
        _ => upsert_catalog_in(tx, object)?,
    }
    Ok(())
}

pub(super) fn upsert_environment_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let revision: Option<u64> = tx
        .query_row(
            "SELECT revision FROM environments WHERE id=?1",
            [&object.id],
            |row| row.get(0),
        )
        .optional()?;
    let next = revision.map(|value| value + 1).unwrap_or(1);
    tx.execute(
        "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,?2,?3)
         ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, configuration_json=excluded.configuration_json",
        params![object.id, next, encode_object(object)],
    )?;
    upsert_catalog_in(tx, object)?;
    Ok(())
}

pub(super) fn upsert_release_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let version = object
        .properties
        .get("version")
        .cloned()
        .unwrap_or_default();
    let digest = object
        .properties
        .get("digest")
        .cloned()
        .or_else(|| object.properties.get("content_digest").cloned())
        .unwrap_or_default();
    let id = if object.id.is_empty() {
        release_id(&product, &version)
    } else {
        object.id.clone()
    };
    let existing: Option<String> = tx
        .query_row(
            "SELECT content_digest FROM releases WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing != digest {
            return Err(StoreError::ImmutableConflict {
                kind: "release",
                id,
            });
        }
        tx.execute(
            "UPDATE releases SET descriptor_json=?2 WHERE id=?1",
            params![id, encode_object(object)],
        )?;
        upsert_catalog_in(tx, object)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO releases(id,product,version,content_digest,descriptor_json)
         VALUES(?1,?2,?3,?4,?5)",
        params![id, product, version, digest, encode_object(object)],
    )?;
    upsert_catalog_in(tx, object)?;
    Ok(())
}

pub(super) fn upsert_channel_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let name = object
        .properties
        .get("name")
        .cloned()
        .or_else(|| object.properties.get("channel").cloned())
        .unwrap_or_else(|| object.name.clone());
    let release = object
        .properties
        .get("current_release")
        .cloned()
        .unwrap_or_default();
    let revision: Option<u64> = tx
        .query_row(
            "SELECT revision FROM channels WHERE id=?1",
            [&object.id],
            |row| row.get(0),
        )
        .optional()?;
    let next = revision.map(|value| value + 1).unwrap_or(1);
    let release_exists = !release.is_empty()
        && tx
            .query_row("SELECT 1 FROM releases WHERE id=?1", [&release], |_| Ok(()))
            .optional()?
            .is_some();
    if !release_exists {
        upsert_catalog_in(tx, object)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO channels(id,product,name,release_id,revision) VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(id) DO UPDATE SET release_id=excluded.release_id, revision=excluded.revision",
        params![object.id, product, name, release, next],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO catalog_objects(id,kind,payload) VALUES(?1,?2,?3)",
        params![object.id, object.kind, object.encode_to_vec()],
    )?;
    replace_catalog_properties(tx, object)?;
    Ok(())
}

pub(super) fn upsert_plan_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let Some(raw) = object.properties.get("plan") else {
        upsert_catalog_in(tx, object)?;
        return Ok(());
    };
    let Ok(plan) = serde_json::from_str::<Plan>(raw) else {
        upsert_catalog_in(tx, object)?;
        return Ok(());
    };
    let environment_id = env_id(&plan.environment);
    if tx
        .query_row(
            "SELECT 1 FROM environments WHERE id=?1",
            [&environment_id],
            |_| Ok(()),
        )
        .optional()?
        .is_none()
    {
        tx.execute(
            "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,1,?2)",
            params![
                environment_id,
                encode_object(&Object {
                    id: environment_id.clone(),
                    kind: KIND_ENVIRONMENT.into(),
                    name: plan.environment.clone(),
                    namespace: NS.into(),
                    properties: BTreeMap::new().into_iter().collect(),
                    created: plan.created_at,
                    updated: plan.created_at,
                    ..Object::default()
                })
            ],
        )?;
    }
    let digest = object
        .properties
        .get("content_digest")
        .cloned()
        .unwrap_or_default();
    let status = object
        .properties
        .get("status")
        .and_then(|value| PlanStatus::parse(value).ok())
        .unwrap_or(PlanStatus::Computed);
    tx.execute(
        "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
         VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(id) DO UPDATE SET
            status=excluded.status,
            status_detail=excluded.status_detail,
            plan_json=excluded.plan_json",
        params![
            object.id,
            environment_id,
            plan.format_version,
            digest,
            object.properties.get("plan").cloned().unwrap_or_default(),
            status.as_str(),
            plan.status_detail
        ],
    )?;
    upsert_catalog_in(tx, object)?;
    Ok(())
}

pub(super) fn upsert_catalog_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    tx.execute(
        "INSERT INTO catalog_objects(id,kind,payload) VALUES(?1,?2,?3)
         ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,payload=excluded.payload",
        params![object.id, object.kind, object.encode_to_vec()],
    )?;
    replace_catalog_properties(tx, object)?;
    Ok(())
}

pub(super) fn replace_catalog_properties(
    tx: &Transaction<'_>,
    object: &Object,
) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM catalog_object_properties WHERE object_id=?1",
        [&object.id],
    )?;
    for (key, value) in &object.properties {
        tx.execute(
            "INSERT INTO catalog_object_properties(object_id,kind,key,value) VALUES(?1,?2,?3,?4)",
            params![object.id, object.kind, key, value],
        )?;
    }
    Ok(())
}

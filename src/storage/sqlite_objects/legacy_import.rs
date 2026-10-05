use super::*;

/// Rows committed per import batch so a restart keeps already-copied data (#516).
const IMPORT_COMMIT_ROWS: usize = 256;

/// Move a pre-0.3 graph store (`embedded_*` tables) into the typed and catalog
/// tables, then drop the graph tables.
///
/// Rows are streamed one at a time and committed in batches so memory stays
/// flat and a readiness restart does not redo finished work. Already-copied
/// typed rows are skipped.
pub(in crate::storage) fn import_legacy_graph(connection: &mut Connection) -> Result<()> {
    if !table_exists(connection, "embedded_objects")? {
        return Ok(());
    }
    import_objects(connection)?;
    if table_exists(connection, "embedded_links")? {
        import_links(connection)?;
    }
    for (legacy, target) in [
        ("embedded_schema_types", "catalog_schema_types"),
        ("embedded_action_types", "catalog_action_types"),
    ] {
        if table_exists(connection, legacy)? {
            import_named_payloads(connection, legacy, target)?;
        }
    }
    if table_exists(connection, "embedded_leases")? {
        import_leases(connection)?;
    }
    if table_exists(connection, "embedded_decisions")? {
        import_decisions(connection)?;
    }
    if table_exists(connection, "embedded_changes")? {
        import_changes(connection)?;
    }
    let tx = connection.transaction()?;
    tx.execute_batch(
        "DROP TABLE IF EXISTS embedded_object_properties;
         DROP TABLE IF EXISTS embedded_links;
         DROP TABLE IF EXISTS embedded_schema_types;
         DROP TABLE IF EXISTS embedded_action_types;
         DROP TABLE IF EXISTS embedded_leases;
         DROP TABLE IF EXISTS embedded_decisions;
         DROP TABLE IF EXISTS embedded_changes;
         DROP TABLE IF EXISTS embedded_objects;
         DROP TABLE IF EXISTS embedded_metadata;",
    )?;
    tx.commit()?;
    Ok(())
}

/// Objects in authority order (environments, releases, channels, plans, then
/// the rest, each by kind and id), so typed rows exist before rows that
/// reference them.
fn import_objects(connection: &mut Connection) -> Result<()> {
    let mut last_rank: i64 = -1;
    let mut last_kind = String::new();
    let mut last_id = String::new();
    loop {
        let tx = connection.transaction()?;
        let mut imported = 0;
        loop {
            if imported == IMPORT_COMMIT_ROWS {
                break;
            }
            let Some((rank, kind, id, object)) = next_object(&tx, last_rank, &last_kind, &last_id)?
            else {
                tx.commit()?;
                return Ok(());
            };
            if !typed_object_exists(&tx, &object)? {
                upsert_object_in(&tx, &object, "tenkai")?;
            }
            last_rank = rank;
            last_kind = kind;
            last_id = id;
            imported += 1;
        }
        tx.commit()?;
    }
}

fn next_object(
    tx: &Transaction<'_>,
    last_rank: i64,
    last_kind: &str,
    last_id: &str,
) -> Result<Option<(i64, String, String, Object)>> {
    let sql = format!(
        "SELECT kind, id, payload FROM embedded_objects
         WHERE (
           CASE kind WHEN '{KIND_ENVIRONMENT}' THEN 0 WHEN '{KIND_RELEASE}' THEN 1
                     WHEN '{KIND_CHANNEL}' THEN 2 WHEN '{KIND_PLAN}' THEN 3 ELSE 4 END,
           kind, id
         ) > (?1, ?2, ?3)
         ORDER BY CASE kind WHEN '{KIND_ENVIRONMENT}' THEN 0 WHEN '{KIND_RELEASE}' THEN 1
                            WHEN '{KIND_CHANNEL}' THEN 2 WHEN '{KIND_PLAN}' THEN 3 ELSE 4 END,
                   kind, id
         LIMIT 1"
    );
    tx.query_row(&sql, params![last_rank, last_kind, last_id], |row| {
        let kind: String = row.get(0)?;
        let id: String = row.get(1)?;
        let payload: Vec<u8> = row.get(2)?;
        Ok((kind, id, payload))
    })
    .optional()?
    .map(|(kind, id, payload)| {
        let rank = object_rank(&kind);
        let object = decode_one::<Object>(payload, "legacy_object")?;
        Ok((rank, kind, id, object))
    })
    .transpose()
}

fn object_rank(kind: &str) -> i64 {
    match kind {
        KIND_ENVIRONMENT => 0,
        KIND_RELEASE => 1,
        KIND_CHANNEL => 2,
        KIND_PLAN => 3,
        _ => 4,
    }
}

fn typed_object_exists(tx: &Transaction<'_>, object: &Object) -> Result<bool> {
    let id = match object.kind.as_str() {
        KIND_RELEASE if object.id.is_empty() => {
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
            release_id(&product, &version)
        }
        _ => object.id.clone(),
    };
    let sql = match object.kind.as_str() {
        KIND_ENVIRONMENT => "SELECT EXISTS(SELECT 1 FROM environments WHERE id=?1)",
        KIND_RELEASE => "SELECT EXISTS(SELECT 1 FROM releases WHERE id=?1)",
        KIND_CHANNEL => "SELECT EXISTS(SELECT 1 FROM channels WHERE id=?1)",
        KIND_PLAN => "SELECT EXISTS(SELECT 1 FROM plans WHERE id=?1)",
        _ => "SELECT EXISTS(SELECT 1 FROM catalog_objects WHERE id=?1)",
    };
    Ok(tx.query_row(sql, [id], |row| row.get(0))?)
}

fn import_links(connection: &mut Connection) -> Result<()> {
    let mut last = String::new();
    loop {
        let tx = connection.transaction()?;
        let mut imported = 0;
        loop {
            if imported == IMPORT_COMMIT_ROWS {
                break;
            }
            let Some((id, payload)) = tx
                .query_row(
                    "SELECT id, payload FROM embedded_links WHERE id > ?1 ORDER BY id LIMIT 1",
                    [&last],
                    |row| {
                        let id: String = row.get(0)?;
                        let payload: Vec<u8> = row.get(1)?;
                        Ok((id, payload))
                    },
                )
                .optional()?
            else {
                tx.commit()?;
                return Ok(());
            };
            let link = decode_one::<Link>(payload, "legacy_link")?;
            tx.execute(
                "INSERT OR IGNORE INTO catalog_links(id,from_id,to_id,relation,payload)
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    link.id,
                    link.from_id,
                    link.to_id,
                    link.relation,
                    link.encode_to_vec()
                ],
            )?;
            last = id;
            imported += 1;
        }
        tx.commit()?;
    }
}

fn import_named_payloads(connection: &mut Connection, legacy: &str, target: &str) -> Result<()> {
    let mut last = String::new();
    let select =
        format!("SELECT name, payload FROM {legacy} WHERE name > ?1 ORDER BY name LIMIT 1");
    let insert = format!("INSERT OR REPLACE INTO {target}(name,payload) VALUES(?1,?2)");
    loop {
        let tx = connection.transaction()?;
        let mut imported = 0;
        loop {
            if imported == IMPORT_COMMIT_ROWS {
                break;
            }
            let Some((name, payload)) = tx
                .query_row(&select, [&last], |row| {
                    let name: String = row.get(0)?;
                    let payload: Vec<u8> = row.get(1)?;
                    Ok((name, payload))
                })
                .optional()?
            else {
                tx.commit()?;
                return Ok(());
            };
            tx.execute(&insert, params![name, payload])?;
            last = name;
            imported += 1;
        }
        tx.commit()?;
    }
}

fn import_leases(connection: &mut Connection) -> Result<()> {
    let mut last_namespace = String::new();
    let mut last_key = String::new();
    loop {
        let tx = connection.transaction()?;
        let mut imported = 0;
        loop {
            if imported == IMPORT_COMMIT_ROWS {
                break;
            }
            let Some((namespace, key, payload)) = tx
                .query_row(
                    "SELECT namespace, lease_key, payload FROM embedded_leases
                     WHERE (namespace, lease_key) > (?1, ?2)
                     ORDER BY namespace, lease_key LIMIT 1",
                    params![last_namespace, last_key],
                    |row| {
                        let namespace: String = row.get(0)?;
                        let key: String = row.get(1)?;
                        let payload: Vec<u8> = row.get(2)?;
                        Ok((namespace, key, payload))
                    },
                )
                .optional()?
            else {
                tx.commit()?;
                return Ok(());
            };
            tx.execute(
                "INSERT OR REPLACE INTO catalog_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)",
                params![namespace, key, payload],
            )?;
            last_namespace = namespace;
            last_key = key;
            imported += 1;
        }
        tx.commit()?;
    }
}

fn import_decisions(connection: &mut Connection) -> Result<()> {
    let mut last = String::new();
    loop {
        let tx = connection.transaction()?;
        let mut imported = 0;
        loop {
            if imported == IMPORT_COMMIT_ROWS {
                break;
            }
            let Some((id, timestamp, actor, action, payload)) = tx
                .query_row(
                    "SELECT id, timestamp, actor, action, payload FROM embedded_decisions
                     WHERE id > ?1 ORDER BY id LIMIT 1",
                    [&last],
                    |row| {
                        let id: String = row.get(0)?;
                        let timestamp: i64 = row.get(1)?;
                        let actor: String = row.get(2)?;
                        let action: String = row.get(3)?;
                        let payload: Vec<u8> = row.get(4)?;
                        Ok((id, timestamp, actor, action, payload))
                    },
                )
                .optional()?
            else {
                tx.commit()?;
                return Ok(());
            };
            tx.execute(
                "INSERT OR IGNORE INTO catalog_decisions(id,timestamp,actor,action,payload)
                 VALUES(?1,?2,?3,?4,?5)",
                params![id, timestamp, actor, action, payload],
            )?;
            last = id;
            imported += 1;
        }
        tx.commit()?;
    }
}

fn import_changes(connection: &mut Connection) -> Result<()> {
    let mut last = String::new();
    loop {
        let tx = connection.transaction()?;
        let mut imported = 0;
        loop {
            if imported == IMPORT_COMMIT_ROWS {
                break;
            }
            let Some((id, object_id, timestamp, payload)) = tx
                .query_row(
                    "SELECT id, object_id, timestamp, payload FROM embedded_changes
                     WHERE id > ?1 ORDER BY id LIMIT 1",
                    [&last],
                    |row| {
                        let id: String = row.get(0)?;
                        let object_id: String = row.get(1)?;
                        let timestamp: i64 = row.get(2)?;
                        let payload: Vec<u8> = row.get(3)?;
                        Ok((id, object_id, timestamp, payload))
                    },
                )
                .optional()?
            else {
                tx.commit()?;
                return Ok(());
            };
            tx.execute(
                "INSERT OR IGNORE INTO catalog_changes(id,object_id,timestamp,payload)
                 VALUES(?1,?2,?3,?4)",
                params![id, object_id, timestamp, payload],
            )?;
            last = id;
            imported += 1;
        }
        tx.commit()?;
    }
}

fn decode_one<T: Message + Default>(payload: Vec<u8>, kind: &'static str) -> Result<T> {
    T::decode(payload.as_slice()).map_err(|error| StoreError::InvalidData {
        kind,
        detail: error.to_string(),
    })
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )?)
}

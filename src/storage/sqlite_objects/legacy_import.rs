use super::*;

/// Move a pre-0.3 graph store (`embedded_*` tables) into the typed and catalog
/// tables, then drop the graph tables.
///
/// Rows are streamed one at a time inside a single transaction, so memory stays
/// flat however large the legacy store is, and an interrupted import rolls back
/// and starts cleanly on the next open (#498).
pub(in crate::storage) fn import_legacy_graph(connection: &mut Connection) -> Result<()> {
    if !table_exists(connection, "embedded_objects")? {
        return Ok(());
    }
    let tx = connection.transaction()?;
    import_objects(&tx)?;
    if table_exists(&tx, "embedded_links")? {
        stream(&tx, "SELECT payload FROM embedded_links", |tx, row| {
            let link = decode_one::<Link>(row.get(0)?, "legacy_link")?;
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
            Ok(())
        })?;
    }
    for (legacy, target) in [
        ("embedded_schema_types", "catalog_schema_types"),
        ("embedded_action_types", "catalog_action_types"),
    ] {
        if table_exists(&tx, legacy)? {
            let insert = format!("INSERT OR REPLACE INTO {target}(name,payload) VALUES(?1,?2)");
            stream(
                &tx,
                &format!("SELECT name,payload FROM {legacy}"),
                |tx, row| {
                    let name: String = row.get(0)?;
                    let payload: Vec<u8> = row.get(1)?;
                    tx.execute(&insert, params![name, payload])?;
                    Ok(())
                },
            )?;
        }
    }
    if table_exists(&tx, "embedded_leases")? {
        stream(
            &tx,
            "SELECT namespace,lease_key,payload FROM embedded_leases",
            |tx, row| {
                let namespace: String = row.get(0)?;
                let key: String = row.get(1)?;
                let payload: Vec<u8> = row.get(2)?;
                tx.execute(
                    "INSERT OR REPLACE INTO catalog_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)",
                    params![namespace, key, payload],
                )?;
                Ok(())
            },
        )?;
    }
    if table_exists(&tx, "embedded_decisions")? {
        stream(
            &tx,
            "SELECT id,timestamp,actor,action,payload FROM embedded_decisions",
            |tx, row| {
                let (id, timestamp, actor, action, payload): DecisionRow = (
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                );
                tx.execute(
                    "INSERT OR IGNORE INTO catalog_decisions(id,timestamp,actor,action,payload)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![id, timestamp, actor, action, payload],
                )?;
                Ok(())
            },
        )?;
    }
    if table_exists(&tx, "embedded_changes")? {
        stream(
            &tx,
            "SELECT id,object_id,timestamp,payload FROM embedded_changes",
            |tx, row| {
                let (id, object_id, timestamp, payload): ChangeRow =
                    (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
                tx.execute(
                    "INSERT OR IGNORE INTO catalog_changes(id,object_id,timestamp,payload)
                     VALUES(?1,?2,?3,?4)",
                    params![id, object_id, timestamp, payload],
                )?;
                Ok(())
            },
        )?;
    }
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
fn import_objects(tx: &Transaction<'_>) -> Result<()> {
    let sql = format!(
        "SELECT payload FROM embedded_objects
         ORDER BY CASE kind WHEN '{KIND_ENVIRONMENT}' THEN 0 WHEN '{KIND_RELEASE}' THEN 1
                            WHEN '{KIND_CHANNEL}' THEN 2 WHEN '{KIND_PLAN}' THEN 3 ELSE 4 END,
                  kind, id"
    );
    stream(tx, &sql, |tx, row| {
        let object = decode_one::<Object>(row.get(0)?, "legacy_object")?;
        upsert_object_in(tx, &object, "tenkai")
    })
}

/// Run `each` for every row of `sql` without collecting the result set.
fn stream(
    tx: &Transaction<'_>,
    sql: &str,
    mut each: impl FnMut(&Transaction<'_>, &rusqlite::Row<'_>) -> Result<()>,
) -> Result<()> {
    let mut statement = tx.prepare(sql)?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        each(tx, row)?;
    }
    Ok(())
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

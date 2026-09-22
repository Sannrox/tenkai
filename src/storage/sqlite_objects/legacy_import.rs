use super::*;

pub(in crate::storage) fn import_legacy_graph(connection: &mut Connection) -> Result<()> {
    let has_graph: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_objects')",
        [],
        |row| row.get(0),
    )?;
    if !has_graph {
        return Ok(());
    }
    let objects = load_embedded_objects(connection)?;
    let links = load_embedded_links(connection)?;
    let schemas = load_blob_rows(connection, "SELECT name,payload FROM embedded_schema_types")?;
    let actions = load_blob_rows(connection, "SELECT name,payload FROM embedded_action_types")?;
    let leases = load_lease_rows(connection)?;
    let decisions = load_named_blobs(
        connection,
        "SELECT id,timestamp,actor,action,payload FROM embedded_decisions",
    )?;
    let changes = load_change_rows(connection)?;
    {
        let tx = connection.transaction()?;
        import_objects_in(&tx, &objects)?;
        for link in &links {
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
        }
        for (name, payload) in &schemas {
            tx.execute(
                "INSERT OR REPLACE INTO catalog_schema_types(name,payload) VALUES(?1,?2)",
                params![name, payload],
            )?;
        }
        for (name, payload) in &actions {
            tx.execute(
                "INSERT OR REPLACE INTO catalog_action_types(name,payload) VALUES(?1,?2)",
                params![name, payload],
            )?;
        }
        for (namespace, key, payload) in &leases {
            tx.execute(
                "INSERT OR REPLACE INTO catalog_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)",
                params![namespace, key, payload],
            )?;
        }
        for (id, timestamp, actor, action, payload) in &decisions {
            tx.execute(
                "INSERT OR IGNORE INTO catalog_decisions(id,timestamp,actor,action,payload)
                 VALUES(?1,?2,?3,?4,?5)",
                params![id, timestamp, actor, action, payload],
            )?;
        }
        for (id, object_id, timestamp, payload) in &changes {
            tx.execute(
                "INSERT OR IGNORE INTO catalog_changes(id,object_id,timestamp,payload)
                 VALUES(?1,?2,?3,?4)",
                params![id, object_id, timestamp, payload],
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
    }
    Ok(())
}

pub(super) fn load_embedded_objects(connection: &Connection) -> Result<Vec<Object>> {
    let mut statement =
        connection.prepare("SELECT payload FROM embedded_objects ORDER BY kind,id")?;
    let payloads = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    decode_many(payloads, "object").map_err(|error| StoreError::InvalidData {
        kind: "legacy_object",
        detail: error.to_string(),
    })
}

pub(super) fn load_embedded_links(connection: &Connection) -> Result<Vec<Link>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_links')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare("SELECT payload FROM embedded_links")?;
    let payloads = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    decode_many(payloads, "link").map_err(|error| StoreError::InvalidData {
        kind: "legacy_link",
        detail: error.to_string(),
    })
}

pub(super) fn load_blob_rows(connection: &Connection, sql: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let table = sql
        .split_whitespace()
        .rev()
        .find(|part| part.starts_with("embedded_"))
        .unwrap_or("");
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub(super) fn load_lease_rows(connection: &Connection) -> Result<Vec<(String, String, Vec<u8>)>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_leases')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement =
        connection.prepare("SELECT namespace,lease_key,payload FROM embedded_leases")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub(super) fn load_named_blobs(connection: &Connection, sql: &str) -> Result<Vec<DecisionRow>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_decisions')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub(super) fn load_change_rows(connection: &Connection) -> Result<Vec<ChangeRow>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_changes')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement =
        connection.prepare("SELECT id,object_id,timestamp,payload FROM embedded_changes")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

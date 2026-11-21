use super::*;

pub(super) fn ensure_provider_event_sequence_table(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS provider_event_sequences (
             provider_kind TEXT PRIMARY KEY,
             next_sequence INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

pub(crate) fn ensure_provider_event_environment_column(connection: &mut Connection) -> Result<()> {
    let columns = {
        let mut statement = connection.prepare("PRAGMA table_info(provider_events)")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !columns.iter().any(|name| name == "environment_id") {
        connection.execute(
            "ALTER TABLE provider_events ADD COLUMN environment_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !columns.iter().any(|name| name == "observed_at") {
        connection.execute(
            "ALTER TABLE provider_events ADD COLUMN observed_at INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS provider_events_environment
         ON provider_events(provider_kind, environment_id, next_attempt_at, id)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS provider_events_environment_observed
         ON provider_events(provider_kind, environment_id, observed_at, id)",
        [],
    )?;

    let tx = connection.transaction()?;
    let rows = {
        let mut statement = tx.prepare(
            "SELECT provider_kind,id,payload_json,next_attempt_at,environment_id,observed_at
             FROM provider_events WHERE environment_id='' OR observed_at=0",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (provider_kind, id, payload_json, next_attempt_at, environment_id, observed_at) in rows {
        if environment_id.is_empty()
            && let Some(environment_id) = provider_event_environment_id(&payload_json)
        {
            tx.execute(
                "UPDATE provider_events SET environment_id=?1
                 WHERE provider_kind=?2 AND id=?3 AND environment_id=''",
                params![environment_id, provider_kind, id],
            )?;
        }
        if observed_at == 0 {
            tx.execute(
                "UPDATE provider_events SET observed_at=?1
                 WHERE provider_kind=?2 AND id=?3 AND observed_at=0",
                params![
                    provider_event_observed_at(&payload_json, next_attempt_at),
                    provider_kind,
                    id
                ],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

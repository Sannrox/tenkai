//! Store write log (#1569): one row per object a write created, replaced, or
//! deleted, and per endpoint of a link it added or removed. Rows are written in
//! the write's own transaction so the reconciler never misses a committed
//! change; it maps rows to the environments it evaluates again.

use super::*;

/// Append one row for `object_id`.
pub(crate) fn record_write(
    connection: &Connection,
    object_id: &str,
    kind: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO catalog_writes(object_id,kind,recorded_at) VALUES(?1,?2,?3)",
        params![object_id, kind, tenkai::now_millis()],
    )?;
    Ok(())
}

/// Append a row for `object_id` with the kind the store holds for it. Call
/// before a delete, while the kind is still readable.
pub(super) fn record_stored_write(
    connection: &Connection,
    object_id: &str,
) -> rusqlite::Result<()> {
    let kind: Option<String> = connection
        .query_row(
            "SELECT kind FROM catalog_objects WHERE id=?1
             UNION ALL SELECT ?2 FROM plans WHERE id=?1
             UNION ALL SELECT ?3 FROM environments WHERE id=?1
             UNION ALL SELECT ?4 FROM releases WHERE id=?1
             UNION ALL SELECT ?5 FROM channels WHERE id=?1
             LIMIT 1",
            params![
                object_id,
                KIND_PLAN,
                KIND_ENVIRONMENT,
                KIND_RELEASE,
                KIND_CHANNEL
            ],
            |row| row.get(0),
        )
        .optional()?;
    record_write(connection, object_id, kind.as_deref().unwrap_or_default())
}

/// Append rows for both endpoints of link `id`, if it exists.
pub(super) fn record_link_write(connection: &Connection, id: &str) -> rusqlite::Result<()> {
    let endpoints: Option<(String, String)> = connection
        .query_row(
            "SELECT from_id,to_id FROM catalog_links WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((from, to)) = endpoints {
        record_stored_write(connection, &from)?;
        record_stored_write(connection, &to)?;
    }
    Ok(())
}

impl SqliteStore {
    pub fn writes_after(&self, after: i64, limit: usize) -> AnyResult<Vec<CatalogWrite>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT seq,object_id,kind FROM catalog_writes WHERE seq > ?1 ORDER BY seq LIMIT ?2",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = statement
            .query_map(params![after, limit], |row| {
                Ok(CatalogWrite {
                    seq: row.get(0)?,
                    object_id: row.get(1)?,
                    kind: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn latest_write(&self) -> AnyResult<i64> {
        Ok(self.connection()?.query_row(
            "SELECT COALESCE(MAX(seq),0) FROM catalog_writes",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn prune_writes(&self, before_ms: i64) -> AnyResult<()> {
        self.connection()?.execute(
            "DELETE FROM catalog_writes WHERE recorded_at < ?1",
            [before_ms],
        )?;
        Ok(())
    }
}

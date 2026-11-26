//! Store write log (#1569), as on SQLite: one row per object a write created,
//! replaced, or deleted, and per endpoint of a link it added or removed, in the
//! write's own transaction. A sequence can commit after a higher one, so the
//! reconciler re-reads a window behind its cursor.

use postgres::Transaction;
use tenkai::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, KIND_PLAN, KIND_RELEASE};
use tenkai::storage::CatalogWrite;

use super::*;
use super::{Inner, pg};

/// Append one row for `object_id`.
pub(super) fn record_write(tx: &mut Transaction<'_>, object_id: &str, kind: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO catalog_writes(object_id,kind,recorded_at) VALUES($1,$2,$3)",
        &[&object_id, &kind, &tenkai::now_millis()],
    )
    .map_err(pg)?;
    Ok(())
}

/// Append a row for `object_id` with the kind the store holds for it. Call
/// before a delete, while the kind is still readable.
pub(super) fn record_stored_write(tx: &mut Transaction<'_>, object_id: &str) -> Result<()> {
    let kind: Option<String> = tx
        .query_opt(
            "SELECT kind FROM catalog_objects WHERE id=$1
             UNION ALL SELECT $2 FROM plans WHERE id=$1
             UNION ALL SELECT $3 FROM environments WHERE id=$1
             UNION ALL SELECT $4 FROM releases WHERE id=$1
             UNION ALL SELECT $5 FROM channels WHERE id=$1
             LIMIT 1",
            &[
                &object_id,
                &KIND_PLAN,
                &KIND_ENVIRONMENT,
                &KIND_RELEASE,
                &KIND_CHANNEL,
            ],
        )
        .map_err(pg)?
        .map(|row| row.get(0));
    record_write(tx, object_id, kind.as_deref().unwrap_or_default())
}

/// Append rows for both endpoints of link `id`, if it exists.
pub(super) fn record_link_write(tx: &mut Transaction<'_>, id: &str) -> Result<()> {
    let endpoints = tx
        .query_opt(
            "SELECT from_id,to_id FROM catalog_links WHERE id=$1",
            &[&id],
        )
        .map_err(pg)?
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)));
    if let Some((from, to)) = endpoints {
        record_stored_write(tx, &from)?;
        record_stored_write(tx, &to)?;
    }
    Ok(())
}

/// Append rows for every link touching `object_id`, before they are deleted.
pub(super) fn record_object_link_writes(tx: &mut Transaction<'_>, object_id: &str) -> Result<()> {
    let links: Vec<String> = tx
        .query(
            "SELECT id FROM catalog_links WHERE from_id=$1 OR to_id=$1",
            &[&object_id],
        )
        .map_err(pg)?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    for link in links {
        record_link_write(tx, &link)?;
    }
    Ok(())
}

impl Inner {
    pub fn catalog_writes_after(
        &self,
        schema: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<CatalogWrite>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_schema(schema, move |tx| {
            Ok(tx
                .query(
                    "SELECT seq,object_id,kind FROM catalog_writes
                     WHERE seq > $1 ORDER BY seq LIMIT $2",
                    &[&after, &limit],
                )
                .map_err(pg)?
                .into_iter()
                .map(|row| CatalogWrite {
                    seq: row.get(0),
                    object_id: row.get(1),
                    kind: row.get(2),
                })
                .collect())
        })
    }

    pub fn catalog_latest_write(&self, schema: &str) -> Result<i64> {
        self.with_schema(schema, |tx| {
            Ok(tx
                .query_one("SELECT COALESCE(MAX(seq),0) FROM catalog_writes", &[])
                .map_err(pg)?
                .get(0))
        })
    }

    pub fn catalog_prune_writes(&self, schema: &str, before_ms: i64) -> Result<()> {
        self.with_schema(schema, move |tx| {
            tx.execute(
                "DELETE FROM catalog_writes WHERE recorded_at < $1",
                &[&before_ms],
            )
            .map_err(pg)?;
            Ok(())
        })
    }
}

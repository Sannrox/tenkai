use super::*;
use super::{Inner, pg};
use tenkai::fleet_budget::DatabaseLoad;

impl Inner {
    /// Bytes of tables, their indexes, and TOAST in one tenant schema.
    pub(crate) fn schema_bytes(&self, schema: &str) -> Result<u64> {
        let schema = schema.to_owned();
        self.worker.run(
            move |client| {
                let row = client
                    .query_one(
                        "SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0)::bigint
                           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                          WHERE n.nspname = $1 AND c.relkind IN ('r', 'm')",
                        &[&schema],
                    )
                    .map_err(pg)?;
                Ok(row.get::<_, i64>(0).max(0) as u64)
            },
            StoreError::Postgres("postgres operation panicked or the worker stopped".into()),
        )
    }

    /// `pg_stat_database` counters for this database. The store does all its
    /// work on this one connection, so forcing its pending statistics out
    /// first makes the reading exact rather than seconds behind.
    pub(crate) fn database_counters(&self) -> Result<DatabaseLoad> {
        self.worker.run(
            |client| {
                // The flush happens when the backend goes idle after this
                // statement, before the next one runs.
                client
                    .batch_execute("SELECT pg_stat_force_next_flush()")
                    .map_err(pg)?;
                let row = client
                    .query_one(
                        "SELECT xact_commit + xact_rollback,
                                tup_returned + tup_fetched,
                                tup_inserted + tup_updated + tup_deleted,
                                blks_read, blks_hit
                           FROM pg_stat_database WHERE datname = current_database()",
                        &[],
                    )
                    .map_err(pg)?;
                let count = |index: usize| row.get::<_, i64>(index).max(0) as u64;
                Ok(DatabaseLoad {
                    transactions: count(0),
                    rows_read: count(1),
                    rows_written: count(2),
                    blocks_read: count(3),
                    blocks_hit: count(4),
                })
            },
            StoreError::Postgres("postgres operation panicked or the worker stopped".into()),
        )
    }
}

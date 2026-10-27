//! The hub writer lease (#748): acquire, renew and fence on it.
//!
//! One row in `tenkai_hub_writer_lease` names the holder, its generation and
//! when the lease expires. Times come from the database clock, so replicas
//! with skewed clocks agree on expiry. A lapsed lease goes to the next
//! claimant at generation + 1; the generation is never reset.

use std::sync::Arc;

use postgres::Transaction;
use tenkai::writer_fence::{WriterFence, WriterRole};

use super::{Inner, Result, StoreError, pg};

/// Milliseconds since the epoch on the database clock.
const DB_NOW: &str = "(extract(epoch from clock_timestamp()) * 1000)::bigint";

/// A leader's transaction that goes quiet is ended by the database after
/// this long, so a paused or partitioned replica cannot keep the lease row,
/// or rows it wrote, locked and block a takeover or its successor's work.
/// Both the lease and the write connections reconnect after the database
/// ends such a session.
const LEASE_IDLE_LIMIT: &str = "SET LOCAL idle_in_transaction_session_timeout = '5s'";

impl Inner {
    /// Fence this store's writes on `fence` (#748). Set once, at startup.
    pub(crate) fn fence_writes(&self, fence: Arc<WriterFence>) -> Result<()> {
        self.fence.set(fence).map_err(|_| StoreError::InvalidData {
            kind: "writer fence",
            detail: "the writer fence is already set".into(),
        })
    }

    /// Like [`Inner::with_schema`] for an authoritative write: refused on a
    /// standby, and refused at commit unless the lease still names this
    /// holder at this generation and has not expired.
    ///
    /// The lease is checked after the write's own statements, just before
    /// commit, so its lock is held only for the commit: a write stalled on
    /// other locks never blocks a renewal or a takeover. A takeover cannot
    /// slip between the check and the commit, because the check holds the
    /// lease row `FOR SHARE` until then.
    pub(crate) fn with_writer_schema<T: Send + 'static>(
        &self,
        schema: &str,
        f: impl FnOnce(&mut Transaction<'_>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let Some(fence) = self.fence.get() else {
            return self.with_schema(schema, f);
        };
        match fence.role() {
            WriterRole::Standby => Err(StoreError::NotActiveWriter(
                "this replica is a standby".into(),
            )),
            WriterRole::Leader { holder, generation } => self.with_schema(schema, move |tx| {
                tx.batch_execute(LEASE_IDLE_LIMIT).map_err(pg)?;
                let out = f(tx)?;
                require_writer(tx, &holder, generation)?;
                Ok(out)
            }),
        }
    }

    /// Take the lease for `holder`, or renew it, for `ttl_ms`. A live lease
    /// held by another replica leaves this one a standby.
    pub fn acquire_writer_lease(&self, holder: &str, ttl_ms: i64) -> Result<WriterRole> {
        if holder.trim().is_empty() || ttl_ms <= 0 {
            return Err(StoreError::InvalidData {
                kind: "writer lease",
                detail: "a holder and a positive ttl are required".into(),
            });
        }
        let holder = holder.to_owned();
        // A renewal that cannot finish within a third of the lease fails, so
        // the replica turns standby instead of waiting on a lock.
        let timeout_ms = (ttl_ms / 3).max(1);
        self.with_schema("public", move |tx| {
            bound_lease_transaction(tx, timeout_ms)?;
            let row = tx
                .query_opt(
                    &format!(
                        "SELECT holder, generation, expires_at > {DB_NOW}
                         FROM tenkai_hub_writer_lease WHERE id = 1 FOR UPDATE"
                    ),
                    &[],
                )
                .map_err(pg)?;
            let generation = match row {
                Some(row) => {
                    let (current, generation, live): (String, i64, bool) =
                        (row.get(0), row.get(1), row.get(2));
                    if live && current != holder {
                        return Ok(WriterRole::Standby);
                    }
                    // A live lease of ours is renewed at its generation;
                    // a lapsed one is taken at the next.
                    let generation = if live { generation } else { generation + 1 };
                    tx.execute(
                        &format!(
                            "UPDATE tenkai_hub_writer_lease
                             SET holder = $1, generation = $2, expires_at = {DB_NOW} + $3
                             WHERE id = 1"
                        ),
                        &[&holder, &generation, &ttl_ms],
                    )
                    .map_err(pg)?;
                    generation
                }
                None => {
                    // Concurrent first claims meet on the primary key; the
                    // loser sees the winner's row and stays a standby.
                    let inserted = tx
                        .execute(
                            &format!(
                                "INSERT INTO tenkai_hub_writer_lease (id, holder, generation, expires_at)
                                 VALUES (1, $1, 1, {DB_NOW} + $2) ON CONFLICT (id) DO NOTHING"
                            ),
                            &[&holder, &ttl_ms],
                        )
                        .map_err(pg)?;
                    if inserted == 0 {
                        return Ok(WriterRole::Standby);
                    }
                    1
                }
            };
            Ok(WriterRole::Leader {
                holder,
                generation: generation as u64,
            })
        })
    }

    /// Let the lease lapse now if `holder` still holds it, so a standby can
    /// take over without waiting for expiry. The generation stays.
    pub fn release_writer_lease(&self, holder: &str) -> Result<()> {
        let holder = holder.to_owned();
        self.with_schema("public", move |tx| {
            bound_lease_transaction(tx, 5_000)?;
            tx.execute(
                &format!(
                    "UPDATE tenkai_hub_writer_lease SET expires_at = LEAST(expires_at, {DB_NOW})
                     WHERE id = 1 AND holder = $1"
                ),
                &[&holder],
            )
            .map_err(pg)?;
            Ok(())
        })
    }
}

/// A transaction that locks the lease row waits at most `timeout_ms` on any
/// statement or lock, and never sits idle holding the row.
fn bound_lease_transaction(tx: &mut Transaction<'_>, timeout_ms: i64) -> Result<()> {
    tx.batch_execute(&format!(
        "SET LOCAL statement_timeout = {timeout_ms}; SET LOCAL lock_timeout = {timeout_ms}; {LEASE_IDLE_LIMIT}"
    ))
    .map_err(pg)
}

/// Refuses the transaction unless the lease names `holder` at `generation`
/// and has not expired. `FOR SHARE` makes a concurrent takeover wait for, or
/// be seen by, this write.
pub(crate) fn require_writer(
    tx: &mut Transaction<'_>,
    holder: &str,
    generation: u64,
) -> Result<()> {
    let row = tx
        .query_opt(
            &format!(
                "SELECT holder, generation, expires_at > {DB_NOW}
                 FROM tenkai_hub_writer_lease WHERE id = 1 FOR SHARE"
            ),
            &[],
        )
        .map_err(pg)?;
    let Some(row) = row else {
        return Err(StoreError::NotActiveWriter(
            "no replica holds the writer lease".into(),
        ));
    };
    let (current, current_generation, live): (String, i64, bool) =
        (row.get(0), row.get(1), row.get(2));
    if current != holder || current_generation as u64 != generation {
        return Err(StoreError::NotActiveWriter(format!(
            "generation {generation} was superseded by generation {current_generation}"
        )));
    }
    if !live {
        return Err(StoreError::NotActiveWriter(format!(
            "the writer lease at generation {generation} expired"
        )));
    }
    Ok(())
}

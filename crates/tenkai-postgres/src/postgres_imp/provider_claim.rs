use super::*;
use super::{Inner, pg};
use postgres::Transaction;

impl Inner {
    pub fn claim_provider_events(
        &self,
        schema: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        if claim_token.is_empty() || claim_until <= now {
            return Err(StoreError::InvalidData {
                kind: "provider event claim",
                detail: "claim token must be non-empty and expiry must be in the future".into(),
            });
        }
        let claim_token = claim_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            claim(tx, None, now, limit, &claim_token, claim_until)
        })
    }

    pub fn claim_provider_events_for_kind(
        &self,
        schema: &str,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        if provider_kind.trim().is_empty() || claim_token.is_empty() || claim_until <= now {
            return Err(StoreError::InvalidData {
                kind: "provider event claim",
                detail: "provider kind, fresh claim token, and future expiry are required".into(),
            });
        }
        let provider_kind = provider_kind.to_owned();
        let claim_token = claim_token.to_owned();
        self.with_writer_schema(schema, move |tx| {
            claim(
                tx,
                Some(&provider_kind),
                now,
                limit,
                &claim_token,
                claim_until,
            )
        })
    }
}

/// Claim up to `limit` due, undelivered events (of `provider_kind`, or of any
/// kind) for `claim_token` until `claim_until`, in delivery order.
///
/// Safe with several claimers on separate connections (#1295): candidates are
/// locked with `FOR UPDATE SKIP LOCKED`, so a row another claimer is taking is
/// skipped instead of waited on, and the `UPDATE` repeats the claimability
/// predicate, so a row claimed since the snapshot is never overwritten.
fn claim(
    tx: &mut Transaction<'_>,
    provider_kind: Option<&str>,
    now: i64,
    limit: usize,
    claim_token: &str,
    claim_until: i64,
) -> Result<Vec<ProviderEventRecord>> {
    // Release lapsed claims. Rows another claimer holds are its to release.
    tx.execute(
        "UPDATE provider_events SET claim_token=NULL,claim_until=NULL
         WHERE (provider_kind,id) IN (
           SELECT provider_kind,id FROM provider_events
           WHERE delivered_at IS NULL AND claim_until <= $1
           FOR UPDATE SKIP LOCKED
         )",
        &[&now],
    )
    .map_err(pg)?;
    let token_in_use: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM provider_events
             WHERE delivered_at IS NULL AND claim_token = $1)",
            &[&claim_token],
        )
        .map_err(pg)?
        .get(0);
    if token_in_use {
        return Err(StoreError::InvalidData {
            kind: "provider event claim",
            detail: "claim token is already active; every claim operation requires a fresh token"
                .into(),
        });
    }
    let limit = limit as i64;
    let rows = tx
        .query(
            "WITH candidates AS (
               SELECT provider_kind,id FROM provider_events
               WHERE ($1::text IS NULL OR provider_kind=$1)
                 AND delivered_at IS NULL AND next_attempt_at <= $2
                 AND (claim_until IS NULL OR claim_until <= $2)
               ORDER BY next_attempt_at,provider_kind,id LIMIT $3
               FOR UPDATE SKIP LOCKED
             )
             UPDATE provider_events e SET claim_token=$4,claim_until=$5
             FROM candidates c
             WHERE e.provider_kind=c.provider_kind AND e.id=c.id
               AND e.delivered_at IS NULL
               AND (e.claim_until IS NULL OR e.claim_until <= $2)
             RETURNING e.id,e.provider_kind,e.binding_digest,e.payload_json,e.attempts,
                       e.next_attempt_at,e.delivered_at,e.last_error,e.claim_token,e.claim_until",
            &[&provider_kind, &now, &limit, &claim_token, &claim_until],
        )
        .map_err(pg)?;
    let mut claimed: Vec<ProviderEventRecord> = rows
        .into_iter()
        .map(|row| ProviderEventRecord {
            id: row.get(0),
            provider_kind: row.get(1),
            binding_digest: row.get(2),
            payload_json: row.get(3),
            attempts: row.get::<_, i32>(4) as u32,
            next_attempt_at: row.get(5),
            delivered_at: row.get(6),
            last_error: row.get(7),
            claim_token: row.get(8),
            claim_until: row.get(9),
        })
        .collect();
    // RETURNING has no order; callers deliver in queue order.
    claimed.sort_by(|a, b| {
        (a.next_attempt_at, &a.provider_kind, &a.id).cmp(&(
            b.next_attempt_at,
            &b.provider_kind,
            &b.id,
        ))
    });
    Ok(claimed)
}

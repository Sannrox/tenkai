use super::*;
use super::{Inner, pg};

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
        self.with_schema(schema, |tx| {
            tx.execute(
                "UPDATE provider_events SET claim_token=NULL,claim_until=NULL
                 WHERE delivered_at IS NULL AND claim_until <= $1",
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
            let limit_i = limit as i64;
            tx.execute(
                "UPDATE provider_events SET claim_token=$3,claim_until=$4
                 WHERE (provider_kind,id) IN (
                   SELECT provider_kind,id FROM provider_events
                   WHERE delivered_at IS NULL AND next_attempt_at <= $1
                     AND (claim_until IS NULL OR claim_until <= $1)
                   ORDER BY next_attempt_at,provider_kind,id LIMIT $2
                 )",
                &[&now, &limit_i, &claim_token, &claim_until],
            )
            .map_err(pg)?;
            let rows = tx
                .query(
                    "SELECT id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until
                     FROM provider_events WHERE delivered_at IS NULL AND claim_token = $1
                     ORDER BY next_attempt_at,provider_kind,id",
                    &[&claim_token],
                )
                .map_err(pg)?;
            Ok(rows
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
                .collect())
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
        self.with_schema(schema, |tx| {
            tx.execute(
                "UPDATE provider_events SET claim_token=NULL,claim_until=NULL
                 WHERE delivered_at IS NULL AND claim_until <= $1",
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
            let limit_i = limit as i64;
            tx.execute(
                "UPDATE provider_events SET claim_token=$4,claim_until=$5
                 WHERE (provider_kind,id) IN (
                   SELECT provider_kind,id FROM provider_events
                   WHERE provider_kind=$1 AND delivered_at IS NULL
                     AND next_attempt_at <= $2
                     AND (claim_until IS NULL OR claim_until <= $2)
                   ORDER BY next_attempt_at,id LIMIT $3
                 )",
                &[&provider_kind, &now, &limit_i, &claim_token, &claim_until],
            )
            .map_err(pg)?;
            let rows = tx
                .query(
                    "SELECT id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until
                     FROM provider_events
                     WHERE provider_kind=$1 AND delivered_at IS NULL AND claim_token=$2
                     ORDER BY next_attempt_at,id",
                    &[&provider_kind, &claim_token],
                )
                .map_err(pg)?;
            Ok(rows
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
                .collect())
        })
    }
}

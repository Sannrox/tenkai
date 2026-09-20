use super::*;
use super::{Inner, pg};

impl Inner {
    pub fn enqueue_provider_event(&self, schema: &str, event: &ProviderEventRecord) -> Result<()> {
        if event.attempts != 0
            || event.delivered_at.is_some()
            || !event.last_error.is_empty()
            || event.claim_token.is_some()
            || event.claim_until.is_some()
        {
            return Err(StoreError::InvalidData {
                kind: "provider event",
                detail: "new events must have pristine delivery state".into(),
            });
        }
        self.with_schema(schema, |tx| {
            let existing = tx
                .query_opt(
                    "SELECT provider_kind,binding_digest,payload_json FROM provider_events
                     WHERE provider_kind = $1 AND id = $2",
                    &[&event.provider_kind, &event.id],
                )
                .map_err(pg)?;
            if let Some(row) = existing {
                let kind: String = row.get(0);
                let digest: String = row.get(1);
                let payload: String = row.get(2);
                if kind != event.provider_kind
                    || digest != event.binding_digest
                    || !provider_event_payloads_match(&payload, &event.payload_json)
                {
                    return Err(StoreError::ImmutableConflict {
                        kind: "provider event",
                        id: event.id.clone(),
                    });
                }
                return Ok(());
            }
            let attempts = event.attempts as i32;
            let environment_id = crate::storage::provider_event_environment_id(
                &event.payload_json,
            )
            .unwrap_or_default();
            let observed_at = crate::storage::provider_event_observed_at(
                &event.payload_json,
                event.next_attempt_at,
            );
            tx.execute(
                "INSERT INTO provider_events(id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until,environment_id,observed_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                &[
                    &event.id,
                    &event.provider_kind,
                    &event.binding_digest,
                    &event.payload_json,
                    &attempts,
                    &event.next_attempt_at,
                    &event.delivered_at,
                    &event.last_error,
                    &event.claim_token,
                    &event.claim_until,
                    &environment_id,
                    &observed_at,
                ],
            )
            .map_err(pg)?;
            Ok(())
        })
    }

    pub fn list_provider_events(
        &self,
        schema: &str,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        if provider_kind.trim().is_empty() || environment_id.trim().is_empty() || limit == 0 {
            return Err(StoreError::InvalidData {
                kind: "provider event inspection",
                detail: "provider kind, environment, and a positive result limit are required"
                    .into(),
            });
        }
        self.with_schema(schema, |tx| {
            let limit_i = limit.min(128) as i64;
            let rows = tx
                .query(
                    "SELECT id,provider_kind,binding_digest,payload_json,attempts,
                            next_attempt_at,delivered_at,last_error,claim_token,claim_until
                    FROM provider_events
                    WHERE provider_kind=$1 AND environment_id=$2
                     ORDER BY observed_at DESC,id DESC LIMIT $3",
                    &[&provider_kind, &environment_id, &limit_i],
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

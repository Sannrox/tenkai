use super::*;

impl SqliteStore {
    pub(super) fn claim_provider_events_sqlite(
        &self,
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
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            "UPDATE provider_events SET claim_token=NULL,claim_until=NULL
             WHERE delivered_at IS NULL AND claim_until<=?1",
            [now],
        )?;
        let token_in_use: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_events WHERE delivered_at IS NULL AND claim_token=?1)",
            [claim_token],
            |row| row.get(0),
        )?;
        if token_in_use {
            return Err(StoreError::InvalidData {
                kind: "provider event claim",
                detail:
                    "claim token is already active; every claim operation requires a fresh token"
                        .into(),
            });
        }
        tx.execute(
            "UPDATE provider_events SET claim_token=?3,claim_until=?4
             WHERE (provider_kind,id) IN (
               SELECT provider_kind,id FROM provider_events
               WHERE delivered_at IS NULL AND next_attempt_at<=?1
                 AND (claim_until IS NULL OR claim_until<=?1)
               ORDER BY next_attempt_at,provider_kind,id LIMIT ?2
             )",
            params![now, limit as u64, claim_token, claim_until],
        )?;
        let mut statement = tx.prepare(
            "SELECT id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until
             FROM provider_events WHERE delivered_at IS NULL AND claim_token=?1
             ORDER BY next_attempt_at,provider_kind,id",
        )?;
        let rows = statement.query_map([claim_token], |row| {
            Ok(ProviderEventRecord {
                id: row.get(0)?,
                provider_kind: row.get(1)?,
                binding_digest: row.get(2)?,
                payload_json: row.get(3)?,
                attempts: row.get(4)?,
                next_attempt_at: row.get(5)?,
                delivered_at: row.get(6)?,
                last_error: row.get(7)?,
                claim_token: row.get(8)?,
                claim_until: row.get(9)?,
            })
        })?;
        let claimed = rows.map(|row| row.map_err(StoreError::from)).collect();
        drop(statement);
        tx.commit()?;
        claimed
    }

    pub(super) fn claim_provider_events_for_kind_sqlite(
        &self,
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
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            "UPDATE provider_events SET claim_token=NULL,claim_until=NULL
             WHERE delivered_at IS NULL AND claim_until<=?1",
            [now],
        )?;
        let token_in_use: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_events WHERE delivered_at IS NULL AND claim_token=?1)",
            [claim_token],
            |row| row.get(0),
        )?;
        if token_in_use {
            return Err(StoreError::InvalidData {
                kind: "provider event claim",
                detail:
                    "claim token is already active; every claim operation requires a fresh token"
                        .into(),
            });
        }
        tx.execute(
            "UPDATE provider_events SET claim_token=?4,claim_until=?5
             WHERE (provider_kind,id) IN (
               SELECT provider_kind,id FROM provider_events
               WHERE provider_kind=?1 AND delivered_at IS NULL AND next_attempt_at<=?2
                 AND (claim_until IS NULL OR claim_until<=?2)
               ORDER BY next_attempt_at,id LIMIT ?3
             )",
            params![provider_kind, now, limit as u64, claim_token, claim_until],
        )?;
        let mut statement = tx.prepare(
            "SELECT id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until
             FROM provider_events
             WHERE provider_kind=?1 AND delivered_at IS NULL AND claim_token=?2
             ORDER BY next_attempt_at,id",
        )?;
        let rows = statement.query_map(params![provider_kind, claim_token], |row| {
            Ok(ProviderEventRecord {
                id: row.get(0)?,
                provider_kind: row.get(1)?,
                binding_digest: row.get(2)?,
                payload_json: row.get(3)?,
                attempts: row.get(4)?,
                next_attempt_at: row.get(5)?,
                delivered_at: row.get(6)?,
                last_error: row.get(7)?,
                claim_token: row.get(8)?,
                claim_until: row.get(9)?,
            })
        })?;
        let claimed = rows.map(|row| row.map_err(StoreError::from)).collect();
        drop(statement);
        tx.commit()?;
        claimed
    }

    pub(super) fn reserve_provider_event_sequence_sqlite(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> Result<i64> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let claimed: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM provider_events
                 WHERE provider_kind=?1 AND id=?2 AND claim_token=?3 AND delivered_at IS NULL
             )",
            params![provider_kind, id, claim_token],
            |row| row.get(0),
        )?;
        if !claimed {
            return Err(StoreError::NotFound {
                kind: "claimed provider event",
                id: id.into(),
            });
        }
        tx.execute(
            "INSERT INTO provider_event_sequences(provider_kind,next_sequence)
             VALUES(?1,1) ON CONFLICT(provider_kind) DO NOTHING",
            [provider_kind],
        )?;
        tx.execute(
            "UPDATE provider_event_sequences SET next_sequence=next_sequence+1
             WHERE provider_kind=?1",
            [provider_kind],
        )?;
        let sequence: i64 = tx.query_row(
            "SELECT next_sequence-1 FROM provider_event_sequences WHERE provider_kind=?1",
            [provider_kind],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(sequence)
    }
}

pub(super) fn validate_new_provider_event(event: &ProviderEventRecord) -> Result<()> {
    if event.id.trim().is_empty()
        || event.provider_kind.trim().is_empty()
        || event.binding_digest.trim().is_empty()
        || event.payload_json.is_empty()
        || event.attempts != 0
        || event.delivered_at.is_some()
        || !event.last_error.is_empty()
        || event.claim_token.is_some()
        || event.claim_until.is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "provider event",
            detail: "new events require identities, content, and pristine delivery state".into(),
        });
    }
    Ok(())
}

pub(crate) fn enqueue_provider_event_in(
    connection: &Connection,
    event: &ProviderEventRecord,
) -> Result<()> {
    validate_new_provider_event(event)?;
    let existing: Option<(String, String, String)> = connection
        .query_row(
            "SELECT provider_kind,binding_digest,payload_json FROM provider_events WHERE provider_kind=?1 AND id=?2",
            params![event.provider_kind, event.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing.0 != event.provider_kind
            || existing.1 != event.binding_digest
            || !provider_event_payloads_match(&existing.2, &event.payload_json)
        {
            return Err(StoreError::ImmutableConflict {
                kind: "provider event",
                id: event.id.clone(),
            });
        }
        return Ok(());
    }
    let environment_id = provider_event_environment_id(&event.payload_json).unwrap_or_default();
    let observed_at = provider_event_observed_at(&event.payload_json, event.next_attempt_at);
    connection.execute(
        "INSERT INTO provider_events(id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until,environment_id,observed_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![event.id, event.provider_kind, event.binding_digest, event.payload_json,
            event.attempts, event.next_attempt_at, event.delivered_at, event.last_error,
            event.claim_token, event.claim_until, environment_id, observed_at],
    )?;
    Ok(())
}

/// A first-delivery collection timestamp is the only field allowed to be
/// added to a durable provider envelope after enqueue. Preserve enqueue
/// idempotency when the same event is submitted again after that binding.
pub(crate) fn provider_event_payloads_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let Ok(mut left) = serde_json::from_str::<serde_json::Value>(left) else {
        return false;
    };
    let Ok(mut right) = serde_json::from_str::<serde_json::Value>(right) else {
        return false;
    };
    let (Some(left), Some(right)) = (left.as_object_mut(), right.as_object_mut()) else {
        return false;
    };
    let metadata = |object: &serde_json::Map<String, serde_json::Value>| {
        ["collected_at_ms", "source_sequence"]
            .map(|key| object.get(key).filter(|value| !value.is_null()).cloned())
    };
    let left_metadata = metadata(left);
    let right_metadata = metadata(right);
    if left_metadata == right_metadata
        || !((left_metadata.iter().all(Option::is_none)
            && right_metadata.iter().all(Option::is_some))
            || (right_metadata.iter().all(Option::is_none)
                && left_metadata.iter().all(Option::is_some)))
    {
        return false;
    }
    left.remove("collected_at_ms");
    left.remove("source_sequence");
    right.remove("collected_at_ms");
    right.remove("source_sequence");
    left == right
}

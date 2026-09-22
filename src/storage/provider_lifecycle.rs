use super::*;

impl SqliteStore {
    pub(super) fn list_provider_events_sqlite(
        &self,
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
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id,provider_kind,binding_digest,payload_json,attempts,
                    next_attempt_at,delivered_at,last_error,claim_token,claim_until
             FROM provider_events WHERE provider_kind=?1 AND environment_id=?2
             ORDER BY observed_at DESC,id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![provider_kind, environment_id, limit.min(128) as u64],
            |row| {
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
            },
        )?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }

    pub(super) fn bind_provider_event_collection_time_sqlite(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE provider_events SET payload_json=?4
             WHERE provider_kind=?1 AND id=?2 AND claim_token=?3 AND delivered_at IS NULL",
            params![provider_kind, id, claim_token, payload_json],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                kind: "claimed provider event",
                id: id.into(),
            });
        }
        Ok(())
    }

    pub(super) fn record_provider_failure_sqlite(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE provider_events SET attempts=attempts+1,next_attempt_at=?4,last_error=?5,claim_token=NULL,claim_until=NULL
             WHERE provider_kind=?1 AND id=?2 AND claim_token=?3 AND delivered_at IS NULL",
            params![provider_kind, id, claim_token, next_attempt_at, error],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                kind: "pending provider event",
                id: id.into(),
            });
        }
        Ok(())
    }

    pub(super) fn mark_provider_event_delivered_sqlite(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE provider_events SET delivered_at=?4,last_error='',claim_token=NULL,claim_until=NULL
             WHERE provider_kind=?1 AND id=?2 AND claim_token=?3 AND delivered_at IS NULL",
            params![provider_kind, id, claim_token, delivered_at],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                kind: "provider event",
                id: id.into(),
            });
        }
        Ok(())
    }
}

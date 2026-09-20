use super::*;
use super::{Inner, pg};

impl Inner {
    pub fn reserve_provider_event_sequence(
        &self,
        schema: &str,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> Result<i64> {
        self.with_schema(schema, |tx| {
            let claimed: bool = tx
                .query_one(
                    "SELECT EXISTS(
                         SELECT 1 FROM provider_events
                         WHERE provider_kind=$1 AND id=$2
                           AND claim_token=$3 AND delivered_at IS NULL
                     )",
                    &[&provider_kind, &id, &claim_token],
                )
                .map_err(pg)?
                .get(0);
            if !claimed {
                return Err(StoreError::NotFound {
                    kind: "claimed provider event",
                    id: id.into(),
                });
            }
            tx.execute(
                "INSERT INTO provider_event_sequences(provider_kind,next_sequence)
                 VALUES($1,1) ON CONFLICT(provider_kind) DO NOTHING",
                &[&provider_kind],
            )
            .map_err(pg)?;
            tx.execute(
                "UPDATE provider_event_sequences SET next_sequence=next_sequence+1
                 WHERE provider_kind=$1",
                &[&provider_kind],
            )
            .map_err(pg)?;
            let sequence: i64 = tx
                .query_one(
                    "SELECT next_sequence-1 FROM provider_event_sequences
                     WHERE provider_kind=$1",
                    &[&provider_kind],
                )
                .map_err(pg)?
                .get(0);
            Ok(sequence)
        })
    }

    pub fn bind_provider_event_collection_time(
        &self,
        schema: &str,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()> {
        self.with_schema(schema, |tx| {
            let changed = tx
                .execute(
                    "UPDATE provider_events SET payload_json=$4
                     WHERE provider_kind=$1 AND id=$2 AND claim_token=$3 AND delivered_at IS NULL",
                    &[&provider_kind, &id, &claim_token, &payload_json],
                )
                .map_err(pg)?;
            if changed == 0 {
                return Err(StoreError::NotFound {
                    kind: "claimed provider event",
                    id: id.into(),
                });
            }
            Ok(())
        })
    }

    pub fn record_provider_failure(
        &self,
        schema: &str,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        self.with_schema(schema, |tx| {
            let changed = tx
                .execute(
                    "UPDATE provider_events SET attempts=attempts+1,next_attempt_at=$4,last_error=$5,
                       claim_token=NULL,claim_until=NULL
                     WHERE provider_kind=$1 AND id=$2 AND claim_token=$3 AND delivered_at IS NULL",
                    &[&provider_kind, &id, &claim_token, &next_attempt_at, &error],
                )
                .map_err(pg)?;
            if changed == 0 {
                return Err(StoreError::NotFound {
                    kind: "pending provider event",
                    id: id.into(),
                });
            }
            Ok(())
        })
    }

    pub fn mark_provider_event_delivered(
        &self,
        schema: &str,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        self.with_schema(schema, |tx| {
            let changed = tx
                .execute(
                    "UPDATE provider_events SET delivered_at=$4,last_error='',claim_token=NULL,claim_until=NULL
                     WHERE provider_kind=$1 AND id=$2 AND claim_token=$3 AND delivered_at IS NULL",
                    &[&provider_kind, &id, &claim_token, &delivered_at],
                )
                .map_err(pg)?;
            if changed == 0 {
                return Err(StoreError::NotFound {
                    kind: "provider event",
                    id: id.into(),
                });
            }
            Ok(())
        })
    }

    pub fn append_audit(&self, schema: &str, event: &AuditRecord) -> Result<()> {
        if event.id.is_empty()
            || event.principal.is_empty()
            || event.operation.is_empty()
            || event.outcome.is_empty()
        {
            return Err(StoreError::InvalidData {
                kind: "audit event",
                detail: "id, principal, operation, and outcome must be non-empty".into(),
            });
        }
        self.with_schema(schema, |tx| {
            tx.execute(
                "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
                 VALUES($1,$2,$3,$4,$5,$6)",
                &[
                    &event.id,
                    &event.occurred_at,
                    &event.principal,
                    &event.operation,
                    &event.resource,
                    &event.outcome,
                ],
            )
            .map_err(pg)?;
            Ok(())
        })
    }

    pub fn audit_events(&self, schema: &str) -> Result<Vec<AuditRecord>> {
        self.with_schema(schema, |tx| {
            let rows = tx
                .query(
                    "SELECT id,occurred_at,principal,operation,resource,outcome
                     FROM audit_events ORDER BY occurred_at,id",
                    &[],
                )
                .map_err(pg)?;
            Ok(rows
                .into_iter()
                .map(|row| AuditRecord {
                    id: row.get(0),
                    occurred_at: row.get(1),
                    principal: row.get(2),
                    operation: row.get(3),
                    resource: row.get(4),
                    outcome: row.get(5),
                })
                .collect())
        })
    }
}

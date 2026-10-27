use super::*;
use tenkai::change_stream::{ChangeEvent, ChangeEventKind};

impl Inner {
    pub fn append_change_event(
        &self,
        schema: &str,
        occurred_at: i64,
        kind: &str,
        resource: &str,
        environment_id: &str,
    ) -> Result<ChangeEvent> {
        let kind = ChangeEventKind::parse(kind).map_err(|error| StoreError::InvalidData {
            kind: "change event",
            detail: error.to_string(),
        })?;
        if resource.is_empty() {
            return Err(StoreError::InvalidData {
                kind: "change event",
                detail: "resource must be non-empty".into(),
            });
        }
        let kind_name = kind.as_str().to_string();
        let resource = resource.to_string();
        let environment_id = environment_id.to_string();
        let lock_key = format!("{schema}:change_events");
        self.with_writer_schema(schema, move |tx| {
            // Serialize seq allocation with commit so a later cursor cannot skip
            // an earlier event whose BIGSERIAL value was assigned first.
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .map_err(pg)?;
            let row = tx
                .query_one(
                    "INSERT INTO change_events(occurred_at, kind, resource, environment_id)
                     VALUES($1,$2,$3,$4)
                     RETURNING seq",
                    &[&occurred_at, &kind_name, &resource, &environment_id],
                )
                .map_err(pg)?;
            let seq: i64 = row.get(0);
            Ok(ChangeEvent::new(
                seq,
                occurred_at,
                kind,
                resource,
                &environment_id,
            ))
        })
    }

    pub fn list_change_events_after(
        &self,
        schema: &str,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<ChangeEvent>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query(
                    "SELECT seq, occurred_at, kind, resource, environment_id
                     FROM change_events
                     WHERE seq > $1
                     ORDER BY seq
                     LIMIT $2",
                    &[&cursor, &limit],
                )
                .map_err(pg)?;
            let mut events = Vec::new();
            for row in rows {
                let seq: i64 = row.get(0);
                let occurred_at: i64 = row.get(1);
                let kind: String = row.get(2);
                let resource: String = row.get(3);
                let environment_id: String = row.get(4);
                let kind =
                    ChangeEventKind::parse(&kind).map_err(|error| StoreError::InvalidData {
                        kind: "change event",
                        detail: error.to_string(),
                    })?;
                events.push(ChangeEvent::new(
                    seq,
                    occurred_at,
                    kind,
                    resource,
                    &environment_id,
                ));
            }
            Ok(events)
        })
    }
}

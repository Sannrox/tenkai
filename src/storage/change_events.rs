use super::*;

use crate::change_stream::{ChangeEvent, ChangeEventKind};

impl SqliteStore {
    pub(super) fn append_change_event_sqlite(
        &self,
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
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "INSERT INTO change_events(occurred_at, kind, resource, environment_id)
             VALUES(?1,?2,?3,?4)
             RETURNING seq",
            params![occurred_at, kind.as_str(), resource, environment_id],
            |row| row.get(0),
        )?;
        Ok(ChangeEvent::new(
            seq,
            occurred_at,
            kind,
            resource,
            environment_id,
        ))
    }

    pub(super) fn list_change_events_after_sqlite(
        &self,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<ChangeEvent>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT seq, occurred_at, kind, resource, environment_id
             FROM change_events
             WHERE seq > ?1 AND kind IN (SELECT value FROM json_each(?3))
             ORDER BY seq
             LIMIT ?2",
        )?;
        // Kinds a newer replica wrote are skipped, not fatal, so a rolling
        // deploy or rollback can introduce a kind without breaking readers.
        let known = serde_json::Value::from(ChangeEventKind::names()).to_string();
        let rows = statement.query_map(params![cursor, limit as i64, known], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (seq, occurred_at, kind, resource, environment_id) = row?;
            let kind = ChangeEventKind::parse(&kind).map_err(|error| StoreError::InvalidData {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_kinds_from_a_newer_replica_are_skipped() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .append_change_event_sqlite(1, "plan_created", "plan/a", "")
            .unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO change_events (occurred_at, kind, resource, environment_id)
                 VALUES (2, 'from_a_newer_version', 'x', '')",
                [],
            )
            .unwrap();
        store
            .append_change_event_sqlite(3, "plan_applied", "plan/a", "")
            .unwrap();
        let kinds: Vec<_> = store
            .list_change_events_after_sqlite(0, 10)
            .unwrap()
            .into_iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(
            kinds,
            [ChangeEventKind::PlanCreated, ChangeEventKind::PlanApplied]
        );
    }
}

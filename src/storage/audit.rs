use super::*;

impl SqliteStore {
    pub(super) fn append_audit_sqlite(&self, event: &AuditRecord) -> Result<()> {
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
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                event.id,
                event.occurred_at,
                event.principal,
                event.operation,
                event.resource,
                event.outcome
            ],
        )?;
        Ok(())
    }

    pub(super) fn audit_events_sqlite(&self) -> Result<Vec<AuditRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id,occurred_at,principal,operation,resource,outcome
             FROM audit_events ORDER BY occurred_at,id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AuditRecord {
                id: row.get(0)?,
                occurred_at: row.get(1)?,
                principal: row.get(2)?,
                operation: row.get(3)?,
                resource: row.get(4)?,
                outcome: row.get(5)?,
            })
        })?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }
}

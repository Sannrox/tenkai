use super::*;

/// Add the explicit audit cursor column `seq` (#1341). The implicit rowid is
/// not promised to survive `VACUUM` or a table rebuild; `seq` is. Existing
/// rows are seeded from their rowid, so a consumer's stored cursor (a rowid
/// value) keeps pointing at the same event. The schema version is unchanged,
/// so a binary from before this column still opens the database.
pub(crate) fn ensure_audit_sequence_column(connection: &mut Connection) -> Result<()> {
    let has_seq = {
        let mut statement = connection.prepare("PRAGMA table_info(audit_events)")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|name| name == "seq")
    };
    if !has_seq {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "ALTER TABLE audit_events ADD COLUMN seq INTEGER;
             UPDATE audit_events SET seq = rowid;",
        )?;
        tx.commit()?;
    }
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS audit_events_seq ON audit_events(seq)",
        [],
    )?;
    Ok(())
}

/// Give rows written without `seq` (by a binary from before the column,
/// during a rolling deploy) the next sequence numbers, in insertion order,
/// so a cursor reader sees them as new rather than never.
fn sequence_unsequenced_audit_events(connection: &mut Connection) -> Result<()> {
    // The common case reads only; the write lock is taken only when an
    // older binary left a row unsequenced.
    let pending: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM audit_events WHERE seq IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if !pending {
        return Ok(());
    }
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let pending = {
        let mut statement =
            tx.prepare("SELECT rowid FROM audit_events WHERE seq IS NULL ORDER BY rowid")?;
        let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for rowid in pending {
        tx.execute(
            "UPDATE audit_events SET seq = (SELECT COALESCE(MAX(seq),0)+1 FROM audit_events)
             WHERE rowid = ?1",
            [rowid],
        )?;
    }
    tx.commit()?;
    Ok(())
}

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
        // One statement, so concurrent writers serialize on SQLite's write
        // lock and the unique index refuses a duplicate sequence.
        connection.execute(
            "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome,seq)
             VALUES(?1,?2,?3,?4,?5,?6,
                    (SELECT COALESCE(MAX(seq),0)+1 FROM audit_events))",
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

    pub(super) fn audit_events_after_sqlite(
        &self,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<(i64, AuditRecord)>> {
        let mut connection = self.connection()?;
        sequence_unsequenced_audit_events(&mut connection)?;
        let mut statement = connection.prepare(
            "SELECT seq,id,occurred_at,principal,operation,resource,outcome
             FROM audit_events WHERE seq > ?1 ORDER BY seq LIMIT ?2",
        )?;
        let rows = statement.query_map(params![cursor, limit as i64], |row| {
            Ok((
                row.get(0)?,
                AuditRecord {
                    id: row.get(1)?,
                    occurred_at: row.get(2)?,
                    principal: row.get(3)?,
                    operation: row.get(4)?,
                    resource: row.get(5)?,
                    outcome: row.get(6)?,
                },
            ))
        })?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::OperationalStore;

    fn temp_db() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-audit-seq-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn event(id: &str) -> AuditRecord {
        AuditRecord {
            id: id.into(),
            occurred_at: 1,
            principal: "operator".into(),
            operation: "test".into(),
            resource: "r".into(),
            outcome: "ok".into(),
        }
    }

    fn cursor_read(store: &SqliteStore) -> Vec<(i64, String)> {
        store
            .audit_events_after(0, 100)
            .unwrap()
            .into_iter()
            .map(|(cursor, record)| (cursor, record.id))
            .collect()
    }

    #[test]
    fn a_table_rebuild_does_not_reorder_or_repeat_the_cursor() {
        let path = temp_db();
        let store = SqliteStore::open(&path).unwrap();
        for id in ["c", "a", "b"] {
            store.append_audit(&event(id)).unwrap();
        }
        let before = cursor_read(&store);
        // Rebuild the table with rows copied in a different order, which
        // renumbers the implicit rowid.
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TABLE audit_rebuilt AS SELECT * FROM audit_events ORDER BY id DESC;
                 DROP TABLE audit_events;
                 ALTER TABLE audit_rebuilt RENAME TO audit_events;
                 CREATE UNIQUE INDEX audit_events_seq ON audit_events(seq);
                 VACUUM;",
            )
            .unwrap();

        assert_eq!(cursor_read(&store), before);
        assert_eq!(
            before.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            ["c", "a", "b"]
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upgraded_rows_keep_their_rowid_cursor_and_old_writers_are_sequenced() {
        let path = temp_db();
        {
            let store = SqliteStore::open(&path).unwrap();
            for id in ["a", "b", "c"] {
                store.append_audit(&event(id)).unwrap();
            }
            // A database from before the column, with a gap in rowids.
            store
                .connection()
                .unwrap()
                .execute_batch(
                    "DELETE FROM audit_events WHERE id = 'b';
                     DROP INDEX audit_events_seq;
                     ALTER TABLE audit_events DROP COLUMN seq;",
                )
                .unwrap();
        }
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(
            cursor_read(&store),
            [(1, "a".to_string()), (3, "c".to_string())]
        );
        // A binary from before the column writes without `seq`.
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
                 VALUES('old',1,'operator','test','r','ok')",
                [],
            )
            .unwrap();
        assert_eq!(
            store.audit_events_after(3, 10).unwrap()[0].1.id,
            "old",
            "an unsequenced row is read after the cursor"
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}

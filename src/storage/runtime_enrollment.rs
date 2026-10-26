//! Runtime agent enrollments and credentials in SQLite (#630). The tables
//! are additive, so an older binary on the same database ignores them.

use super::*;

pub(super) fn ensure_runtime_enrollment_tables(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS runtime_enrollments (
             token_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             expires_at INTEGER NOT NULL, created_by TEXT NOT NULL,
             redeemed_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS runtime_credentials (
             credential_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             enrollment_digest TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );",
    )?;
    Ok(())
}

fn refused(detail: &str) -> StoreError {
    StoreError::InvalidData {
        kind: "runtime enrollment",
        detail: detail.into(),
    }
}

fn credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuntimeCredentialRecord> {
    Ok(RuntimeCredentialRecord {
        credential_digest: row.get(0)?,
        environment_id: row.get(1)?,
        enrollment_digest: row.get(2)?,
        created_at: row.get(3)?,
        revoked_at: row.get(4)?,
    })
}

impl SqliteStore {
    pub(super) fn create_runtime_enrollment_sqlite(
        &self,
        enrollment: &RuntimeEnrollmentRecord,
    ) -> Result<()> {
        let connection = self.connection()?;
        let inserted = connection.execute(
            "INSERT INTO runtime_enrollments(token_digest,environment_id,expires_at,created_by)
             VALUES(?1,?2,?3,?4) ON CONFLICT(token_digest) DO NOTHING",
            params![
                enrollment.token_digest,
                enrollment.environment_id,
                enrollment.expires_at,
                enrollment.created_by
            ],
        )?;
        if inserted == 0 {
            return Err(StoreError::AlreadyExists {
                kind: "runtime enrollment",
                id: enrollment.token_digest.clone(),
            });
        }
        Ok(())
    }

    pub(super) fn redeem_runtime_enrollment_sqlite(
        &self,
        environment: &str,
        token_digest: &str,
        credential_digest: &str,
        now: i64,
    ) -> Result<RuntimeCredentialRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Spent only once: the update matches an unredeemed, unexpired row.
        let spent = tx.execute(
            "UPDATE runtime_enrollments SET redeemed_at=?3
             WHERE token_digest=?1 AND environment_id=?2
               AND redeemed_at IS NULL AND expires_at>?3",
            params![token_digest, environment, now],
        )?;
        if spent == 0 {
            return Err(refused("unknown, spent or expired"));
        }
        let environment_id = environment.to_owned();
        tx.execute(
            "INSERT INTO runtime_credentials(credential_digest,environment_id,enrollment_digest,created_at)
             VALUES(?1,?2,?3,?4)",
            params![credential_digest, environment_id, token_digest, now],
        )?;
        tx.commit()?;
        Ok(RuntimeCredentialRecord {
            credential_digest: credential_digest.into(),
            environment_id,
            enrollment_digest: token_digest.into(),
            created_at: now,
            revoked_at: None,
        })
    }

    pub(super) fn lapsed_runtime_completion_sqlite(
        &self,
        environment: &str,
        plan_id: &str,
        now: i64,
    ) -> Result<Option<String>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT completion_json FROM runtime_claims
                 WHERE plan_id=?1 AND environment_id=?2
                   AND completion_json IS NOT NULL AND expires_at<=?3",
                params![plan_id, environment, now],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(super) fn runtime_credential_sqlite(
        &self,
        credential_digest: &str,
    ) -> Result<Option<RuntimeCredentialRecord>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT credential_digest,environment_id,enrollment_digest,created_at,revoked_at
                 FROM runtime_credentials WHERE credential_digest=?1",
                [credential_digest],
                credential_from_row,
            )
            .optional()?)
    }

    pub(super) fn revoke_runtime_credential_sqlite(
        &self,
        credential_digest: &str,
        now: i64,
    ) -> Result<()> {
        let connection = self.connection()?;
        let known = connection.execute(
            "UPDATE runtime_credentials SET revoked_at=COALESCE(revoked_at, ?2)
             WHERE credential_digest=?1",
            params![credential_digest, now],
        )?;
        if known == 0 {
            return Err(StoreError::NotFound {
                kind: "runtime credential",
                id: credential_digest.into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(token: &str, environment: &str, expires_at: i64) -> RuntimeEnrollmentRecord {
        RuntimeEnrollmentRecord {
            token_digest: token.into(),
            environment_id: environment.into(),
            expires_at,
            created_by: "operator".into(),
        }
    }

    fn refused(result: Result<RuntimeCredentialRecord>) -> bool {
        matches!(result, Err(StoreError::InvalidData { .. }))
    }

    #[test]
    fn an_enrollment_is_spent_once_before_it_expires_and_only_in_its_environment() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .create_runtime_enrollment(&enrollment("t1", "prod", 1_000))
            .unwrap();
        assert!(matches!(
            store.create_runtime_enrollment(&enrollment("t1", "prod", 1_000)),
            Err(StoreError::AlreadyExists { .. })
        ));
        // Another environment's redemption refuses and does not spend it.
        assert!(refused(
            store.redeem_runtime_enrollment("stage", "t1", "c0", 10)
        ));
        let credential = store
            .redeem_runtime_enrollment("prod", "t1", "c1", 10)
            .unwrap();
        assert_eq!(
            (credential.environment_id.as_str(), credential.revoked_at),
            ("prod", None)
        );
        assert!(refused(
            store.redeem_runtime_enrollment("prod", "t1", "c2", 20)
        ));
        assert!(store.runtime_credential("c2").unwrap().is_none());

        store
            .create_runtime_enrollment(&enrollment("t2", "prod", 100))
            .unwrap();
        assert!(refused(
            store.redeem_runtime_enrollment("prod", "t2", "c3", 100)
        ));
        assert!(refused(
            store.redeem_runtime_enrollment("prod", "unknown", "c4", 10)
        ));

        store.revoke_runtime_credential("c1", 50).unwrap();
        store.revoke_runtime_credential("c1", 60).unwrap();
        assert_eq!(
            store.runtime_credential("c1").unwrap().unwrap().revoked_at,
            Some(50)
        );
        assert!(matches!(
            store.revoke_runtime_credential("unknown", 60),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn of_two_instances_redeeming_one_token_one_wins() {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tenkai-enrollment-race-{}-{}.db",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let first = SqliteStore::open(&path).unwrap();
        let second = SqliteStore::open(&path).unwrap();
        first
            .create_runtime_enrollment(&enrollment("t1", "prod", i64::MAX))
            .unwrap();
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| first.redeem_runtime_enrollment("prod", "t1", "ca", 10));
            let b = scope.spawn(|| second.redeem_runtime_enrollment("prod", "t1", "cb", 10));
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "{results:?}"
        );
        drop((first, second));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}

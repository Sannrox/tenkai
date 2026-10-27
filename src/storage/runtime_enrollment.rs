//! Runtime agent enrollments and credentials in SQLite (#630), and the
//! runner registry's revocation reasons and activity (#673). The tables are
//! additive, so an older binary on the same database ignores them.

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
         );
         CREATE TABLE IF NOT EXISTS runtime_credential_revocations (
             credential_digest TEXT PRIMARY KEY, reason TEXT NOT NULL,
             revoked_by TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS runtime_activity (
             runner_id TEXT NOT NULL, instance_id TEXT NOT NULL,
             environment_id TEXT NOT NULL, owner TEXT NOT NULL,
             runtime_version TEXT, last_work_at INTEGER,
             last_heartbeat_at INTEGER, last_inventory_at INTEGER,
             PRIMARY KEY (runner_id, instance_id)
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
        revocation: &RuntimeRevocation,
    ) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let known = tx.execute(
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
        tx.execute(
            "INSERT INTO runtime_credential_revocations(credential_digest,reason,revoked_by)
             VALUES(?1,?2,?3) ON CONFLICT(credential_digest) DO NOTHING",
            params![credential_digest, revocation.reason, revocation.revoked_by],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn runtime_runners_sqlite(&self) -> Result<Vec<RuntimeRunnerRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT c.credential_digest,c.environment_id,c.enrollment_digest,c.created_at,
                    c.revoked_at,COALESCE(e.created_by,''),r.reason,r.revoked_by
             FROM runtime_credentials c
             LEFT JOIN runtime_enrollments e ON e.token_digest=c.enrollment_digest
             LEFT JOIN runtime_credential_revocations r
                 ON r.credential_digest=c.credential_digest
             ORDER BY c.environment_id, c.created_at, c.credential_digest",
        )?;
        let rows = statement.query_map([], |row| {
            let reason: Option<String> = row.get(6)?;
            let revoked_by: Option<String> = row.get(7)?;
            Ok(RuntimeRunnerRecord {
                credential: credential_from_row(row)?,
                created_by: row.get(5)?,
                revocation: reason
                    .zip(revoked_by)
                    .map(|(reason, revoked_by)| RuntimeRevocation { reason, revoked_by }),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub(super) fn record_runtime_activity_sqlite(
        &self,
        activity: &RuntimeActivityRecord,
    ) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO runtime_activity(runner_id,instance_id,environment_id,owner,
                 runtime_version,last_work_at,last_heartbeat_at,last_inventory_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(runner_id,instance_id) DO UPDATE SET
                 environment_id=excluded.environment_id, owner=excluded.owner,
                 runtime_version=COALESCE(excluded.runtime_version, runtime_version),
                 last_work_at=COALESCE(MAX(excluded.last_work_at, last_work_at),
                     excluded.last_work_at, last_work_at),
                 last_heartbeat_at=COALESCE(MAX(excluded.last_heartbeat_at, last_heartbeat_at),
                     excluded.last_heartbeat_at, last_heartbeat_at),
                 last_inventory_at=COALESCE(MAX(excluded.last_inventory_at, last_inventory_at),
                     excluded.last_inventory_at, last_inventory_at)",
            params![
                activity.runner_id,
                activity.instance_id,
                activity.environment_id,
                activity.owner,
                activity.runtime_version,
                activity.last_work_at,
                activity.last_heartbeat_at,
                activity.last_inventory_at
            ],
        )?;
        Ok(())
    }

    pub(super) fn runtime_activity_sqlite(&self) -> Result<Vec<RuntimeActivityRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT runner_id,instance_id,environment_id,owner,runtime_version,
                    last_work_at,last_heartbeat_at,last_inventory_at
             FROM runtime_activity ORDER BY runner_id, instance_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RuntimeActivityRecord {
                runner_id: row.get(0)?,
                instance_id: row.get(1)?,
                environment_id: row.get(2)?,
                owner: row.get(3)?,
                runtime_version: row.get(4)?,
                last_work_at: row.get(5)?,
                last_heartbeat_at: row.get(6)?,
                last_inventory_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub(super) fn live_runtime_claim_owners_sqlite(&self, now: i64) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT DISTINCT owner FROM runtime_claims WHERE expires_at>?1 ORDER BY owner",
        )?;
        let rows = statement.query_map([now], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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

        let first = RuntimeRevocation {
            reason: "host retired".into(),
            revoked_by: "operator-a".into(),
        };
        let second = RuntimeRevocation {
            reason: "again".into(),
            revoked_by: "operator-b".into(),
        };
        store.revoke_runtime_credential("c1", 50, &first).unwrap();
        store.revoke_runtime_credential("c1", 60, &second).unwrap();
        assert_eq!(
            store.runtime_credential("c1").unwrap().unwrap().revoked_at,
            Some(50)
        );
        assert!(matches!(
            store.revoke_runtime_credential("unknown", 60, &first),
            Err(StoreError::NotFound { .. })
        ));
        // The registry lists the credential with its issuer and the first reason.
        let runners = store.runtime_runners().unwrap();
        let c1 = runners
            .iter()
            .find(|runner| runner.credential.credential_digest == "c1")
            .unwrap();
        assert_eq!(c1.created_by, "operator");
        assert_eq!(c1.revocation.as_ref(), Some(&first));
    }

    /// Activity merges per runner instance: timestamps only advance, a
    /// report without a version keeps the recorded one, and live claims
    /// name their owners (#673).
    #[test]
    fn activity_merges_per_instance_and_claims_name_lease_holders() {
        let store = SqliteStore::open_in_memory().unwrap();
        let activity =
            |instance: &str, work: Option<i64>, beat: Option<i64>, version: Option<&str>| {
                RuntimeActivityRecord {
                    runner_id: "sha256:r1".into(),
                    instance_id: instance.into(),
                    environment_id: "prod".into(),
                    owner: format!("runtime:{instance}"),
                    runtime_version: version.map(str::to_string),
                    last_work_at: work,
                    last_heartbeat_at: beat,
                    last_inventory_at: None,
                }
            };
        store
            .record_runtime_activity(&activity("a", Some(100), None, Some("0.5.0")))
            .unwrap();
        store
            .record_runtime_activity(&activity("a", Some(90), Some(120), None))
            .unwrap();
        store
            .record_runtime_activity(&activity("b", Some(110), None, Some("0.6.0")))
            .unwrap();
        let recorded = store.runtime_activity().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].instance_id, "a");
        assert_eq!(recorded[0].last_work_at, Some(100));
        assert_eq!(recorded[0].last_heartbeat_at, Some(120));
        assert_eq!(recorded[0].runtime_version.as_deref(), Some("0.5.0"));
        assert_eq!(recorded[1].runtime_version.as_deref(), Some("0.6.0"));

        let expires = crate::now_millis() + 60_000;
        assert!(
            store
                .claim_runtime_plan("prod", "plan-1", "runtime:b", expires)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store.live_runtime_claim_owners(expires - 1).unwrap(),
            ["runtime:b"]
        );
        assert!(store.live_runtime_claim_owners(expires).unwrap().is_empty());
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

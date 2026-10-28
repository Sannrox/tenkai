//! Runtime agent enrollments and credentials in SQLite (#630), and the
//! runner registry's revocation reasons and activity (#673), and runner
//! attestation bindings and refusals (#675). The tables are
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
         );
         CREATE TABLE IF NOT EXISTS runtime_attestations (
             runner_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             evidence_digest TEXT, key_fingerprint TEXT, checked_at INTEGER,
             bound_at INTEGER, refusal_reason TEXT, refused_at INTEGER
         );",
    )?;
    Ok(())
}

/// Bind a runner's attestation or record its refusal: a binding (evidence
/// present) replaces the bound fields and clears the refusal; a refusal
/// keeps the binding (#675).
fn upsert_attestation(connection: &Connection, record: &RuntimeAttestationRecord) -> Result<()> {
    connection.execute(
        "INSERT INTO runtime_attestations(runner_id,environment_id,evidence_digest,
             key_fingerprint,checked_at,bound_at,refusal_reason,refused_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(runner_id) DO UPDATE SET
             environment_id=excluded.environment_id,
             evidence_digest=COALESCE(excluded.evidence_digest, evidence_digest),
             key_fingerprint=CASE WHEN excluded.evidence_digest IS NULL
                 THEN key_fingerprint ELSE excluded.key_fingerprint END,
             checked_at=CASE WHEN excluded.evidence_digest IS NULL
                 THEN checked_at ELSE excluded.checked_at END,
             bound_at=CASE WHEN excluded.evidence_digest IS NULL
                 THEN bound_at ELSE excluded.bound_at END,
             refusal_reason=excluded.refusal_reason, refused_at=excluded.refused_at",
        params![
            record.runner_id,
            record.environment_id,
            record.evidence_digest,
            record.key_fingerprint,
            record.checked_at,
            record.bound_at,
            record.refusal_reason,
            record.refused_at
        ],
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
        attestation: Option<&RuntimeAttestationRecord>,
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
        if let Some(attestation) = attestation {
            upsert_attestation(&tx, attestation)?;
        }
        tx.commit()?;
        Ok(RuntimeCredentialRecord {
            credential_digest: credential_digest.into(),
            environment_id,
            enrollment_digest: token_digest.into(),
            created_at: now,
            revoked_at: None,
        })
    }

    pub(super) fn runtime_enrollment_usable_sqlite(
        &self,
        environment: &str,
        token_digest: &str,
        now: i64,
    ) -> Result<bool> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT 1 FROM runtime_enrollments
                 WHERE token_digest=?1 AND environment_id=?2
                   AND redeemed_at IS NULL AND expires_at>?3",
                params![token_digest, environment, now],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
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

    pub(super) fn record_runtime_attestation_sqlite(
        &self,
        record: &RuntimeAttestationRecord,
    ) -> Result<()> {
        upsert_attestation(&*self.connection()?, record)
    }

    pub(super) fn runtime_attestations_sqlite(&self) -> Result<Vec<RuntimeAttestationRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT runner_id,environment_id,evidence_digest,key_fingerprint,checked_at,
                    bound_at,refusal_reason,refused_at
             FROM runtime_attestations ORDER BY runner_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RuntimeAttestationRecord {
                runner_id: row.get(0)?,
                environment_id: row.get(1)?,
                evidence_digest: row.get(2)?,
                key_fingerprint: row.get(3)?,
                checked_at: row.get(4)?,
                bound_at: row.get(5)?,
                refusal_reason: row.get(6)?,
                refused_at: row.get(7)?,
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
            store.redeem_runtime_enrollment("stage", "t1", "c0", 10, None)
        ));
        let credential = store
            .redeem_runtime_enrollment("prod", "t1", "c1", 10, None)
            .unwrap();
        assert_eq!(
            (credential.environment_id.as_str(), credential.revoked_at),
            ("prod", None)
        );
        assert!(refused(
            store.redeem_runtime_enrollment("prod", "t1", "c2", 20, None)
        ));
        assert!(store.runtime_credential("c2").unwrap().is_none());

        store
            .create_runtime_enrollment(&enrollment("t2", "prod", 100))
            .unwrap();
        assert!(refused(
            store.redeem_runtime_enrollment("prod", "t2", "c3", 100, None)
        ));
        assert!(refused(
            store.redeem_runtime_enrollment("prod", "unknown", "c4", 10, None)
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

    /// Runner attestation (#675): a refusal keeps the binding; a binding
    /// replaces it and clears the refusal.
    #[test]
    fn a_refusal_keeps_the_binding_and_a_binding_clears_the_refusal() {
        let store = SqliteStore::open_in_memory().unwrap();
        let record = |digest: Option<&str>, refusal: Option<&str>| RuntimeAttestationRecord {
            runner_id: "sha256:r1".into(),
            environment_id: "prod".into(),
            evidence_digest: digest.map(str::to_string),
            key_fingerprint: digest.map(|_| "sha256:key".into()),
            checked_at: digest.map(|_| 10),
            bound_at: digest.map(|_| 11),
            refusal_reason: refusal.map(str::to_string),
            refused_at: refusal.map(|_| 12),
        };
        store
            .record_runtime_attestation(&record(None, Some("attestation_missing")))
            .unwrap();
        store
            .record_runtime_attestation(&record(Some("sha256:e1"), None))
            .unwrap();
        store
            .record_runtime_attestation(&record(None, Some("fact_mismatch")))
            .unwrap();
        let [kept] = store.runtime_attestations().unwrap().try_into().unwrap();
        assert_eq!(kept.evidence_digest.as_deref(), Some("sha256:e1"));
        assert_eq!(kept.key_fingerprint.as_deref(), Some("sha256:key"));
        assert_eq!(kept.refusal_reason.as_deref(), Some("fact_mismatch"));
        store
            .record_runtime_attestation(&record(Some("sha256:e2"), None))
            .unwrap();
        let [bound] = store.runtime_attestations().unwrap().try_into().unwrap();
        assert_eq!(bound.evidence_digest.as_deref(), Some("sha256:e2"));
        assert_eq!((bound.refusal_reason, bound.refused_at), (None, None));
    }

    /// Redemption, credential and attestation binding commit together
    /// (#675): a binding that fails leaves the token unspent and no runner,
    /// and a usable-token check spends nothing.
    #[test]
    fn a_failed_binding_rolls_back_the_redemption() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .create_runtime_enrollment(&enrollment("t1", "prod", 1_000))
            .unwrap();
        assert!(store.runtime_enrollment_usable("prod", "t1", 10).unwrap());
        assert!(!store.runtime_enrollment_usable("stage", "t1", 10).unwrap());
        assert!(
            !store
                .runtime_enrollment_usable("prod", "t1", 1_000)
                .unwrap()
        );
        let binding = RuntimeAttestationRecord {
            runner_id: "c1".into(),
            environment_id: "prod".into(),
            evidence_digest: Some("sha256:e1".into()),
            key_fingerprint: Some("sha256:key".into()),
            checked_at: Some(5),
            bound_at: Some(10),
            ..Default::default()
        };
        // Inject a failing binding write.
        store
            .connection()
            .unwrap()
            .execute_batch("ALTER TABLE runtime_attestations RENAME TO runtime_attestations_away")
            .unwrap();
        assert!(
            store
                .redeem_runtime_enrollment("prod", "t1", "c1", 10, Some(&binding))
                .is_err()
        );
        assert!(store.runtime_credential("c1").unwrap().is_none());
        assert!(store.runtime_enrollment_usable("prod", "t1", 10).unwrap());
        store
            .connection()
            .unwrap()
            .execute_batch("ALTER TABLE runtime_attestations_away RENAME TO runtime_attestations")
            .unwrap();
        store
            .redeem_runtime_enrollment("prod", "t1", "c1", 10, Some(&binding))
            .unwrap();
        let [bound] = store.runtime_attestations().unwrap().try_into().unwrap();
        assert_eq!(bound.evidence_digest.as_deref(), Some("sha256:e1"));
        assert!(!store.runtime_enrollment_usable("prod", "t1", 10).unwrap());
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
            let a = scope.spawn(|| first.redeem_runtime_enrollment("prod", "t1", "ca", 10, None));
            let b = scope.spawn(|| second.redeem_runtime_enrollment("prod", "t1", "cb", 10, None));
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

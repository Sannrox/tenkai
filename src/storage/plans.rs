use super::*;

impl SqliteStore {
    pub(super) fn create_plan_sqlite(&self, plan: &PlanRecord) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        ensure_environment_active_in(&tx, &plan.environment_id, "new plans")?;
        if tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE object_kind='environment' AND object_id=?1
             )",
            [&plan.environment_id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture environments cannot accept executable plans".into(),
            });
        }
        let existing: Option<(String, u32, String, String)> = tx.query_row(
            "SELECT environment_id,format_version,content_digest,plan_json FROM plans WHERE id=?1", [&plan.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    plan.environment_id.clone(),
                    plan.format_version,
                    plan.content_digest.clone(),
                    plan.plan_json.clone(),
                )
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "plan",
                    id: plan.id.clone(),
                });
            }
            return Ok(());
        }
        if plan.status != PlanStatus::Computed {
            return Err(StoreError::InvalidPlanTransition {
                id: plan.id.clone(),
                from: PlanStatus::Computed,
                to: plan.status,
            });
        }
        tx.execute(
            "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![plan.id, plan.environment_id, plan.format_version, plan.content_digest, plan.plan_json, plan.status.as_str(), plan.status_detail],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn transition_plan_sqlite(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE object_kind='plan' AND object_id=?1
             )",
            [id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture plans are non-executable".into(),
            });
        }
        let current: String = tx
            .query_row("SELECT status FROM plans WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(|| StoreError::NotFound {
                kind: "plan",
                id: id.into(),
            })?;
        let current = PlanStatus::parse(&current)?;
        let environment = plan_environment(&tx, id)?;
        require_lease(&tx, &environment, owner, generation, crate::now_millis())?;
        if !current.allows(status) {
            return Err(StoreError::InvalidPlanTransition {
                id: id.into(),
                from: current,
                to: status,
            });
        }
        tx.execute(
            "UPDATE plans SET status=?2,status_detail=?3 WHERE id=?1",
            params![id, status.as_str(), detail],
        )?;
        tx.commit()?;
        drop(connection);
        self.get_plan(id)?.ok_or_else(|| StoreError::NotFound {
            kind: "plan",
            id: id.into(),
        })
    }

    pub(super) fn acquire_lease_sqlite(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        self.grant_lease(environment, owner, expires_at, None)
    }

    /// Take over `environment`'s lease for `owner` at exactly `generation`,
    /// which must be above the current one, recording `evidence_json` (the
    /// signed promotion) in the same transaction. Refused while any holder's
    /// lease, including `owner`'s own, is unexpired, so the result always
    /// fences the previous generation.
    pub fn takeover_expired_lease(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
        evidence_json: &str,
    ) -> Result<LeaseRecord> {
        self.grant_lease(
            environment,
            owner,
            expires_at,
            Some(Takeover {
                generation,
                evidence_json,
            }),
        )
    }

    /// Owner and evidence recorded by the takeover that issued `generation`.
    pub fn lease_takeover(
        &self,
        environment: &str,
        generation: u64,
    ) -> Result<Option<(String, String)>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT owner, evidence_json FROM lease_takeovers
                 WHERE environment_id=?1 AND generation=?2",
                params![environment, generation],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Shared lease grant. `takeover` carries the exact generation and its
    /// evidence; `None` is a plain acquire that renews the owner's own lease.
    fn grant_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
        takeover: Option<Takeover<'_>>,
    ) -> Result<LeaseRecord> {
        let wanted = takeover.as_ref().map(|takeover| takeover.generation);
        let now = crate::now_millis();
        if expires_at <= now {
            return Err(StoreError::LeaseExpired {
                environment: environment.into(),
                generation: 0,
            });
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        ensure_environment_active_in(&tx, environment, "new apply leases")?;
        if tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE object_kind='environment' AND object_id=?1
             )",
            [environment],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture environments are non-executable".into(),
            });
        }
        let current = lease_in(&tx, environment)?;
        let generation = match current {
            Some(current)
                if current.expires_at > now && (current.owner != owner || wanted.is_some()) =>
            {
                return Err(StoreError::LeaseHeld {
                    environment: environment.into(),
                    owner: current.owner,
                    expires_at: current.expires_at,
                });
            }
            Some(current) if current.expires_at > now => current.generation,
            Some(current) if wanted.is_some_and(|wanted| wanted <= current.generation) => {
                return Err(StoreError::InvalidData {
                    kind: "lease",
                    detail: format!(
                        "takeover generation must exceed {} for {environment}",
                        current.generation
                    ),
                });
            }
            Some(current) => wanted.unwrap_or(current.generation + 1),
            None => wanted.unwrap_or(1).max(1),
        };
        tx.execute(
            "INSERT INTO leases(environment_id,owner,generation,expires_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(environment_id) DO UPDATE SET owner=excluded.owner,generation=excluded.generation,expires_at=excluded.expires_at",
            params![environment, owner, generation, expires_at],
        )?;
        if let Some(takeover) = takeover {
            tx.execute(
                "INSERT INTO lease_takeovers(environment_id,generation,owner,evidence_json)
                 VALUES(?1,?2,?3,?4)",
                params![environment, generation, owner, takeover.evidence_json],
            )?;
        }
        tx.commit()?;
        Ok(LeaseRecord {
            environment_id: environment.into(),
            owner: owner.into(),
            generation,
            expires_at,
        })
    }
}

/// A fenced takeover's exact generation and the evidence stored with it.
struct Takeover<'a> {
    generation: u64,
    evidence_json: &'a str,
}

/// Evidence of each fenced takeover, written in the takeover's transaction.
/// Additive: older binaries ignore the table.
pub(super) fn ensure_lease_takeover_table(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS lease_takeovers (
             environment_id TEXT NOT NULL, generation INTEGER NOT NULL,
             owner TEXT NOT NULL, evidence_json TEXT NOT NULL,
             PRIMARY KEY(environment_id, generation)
         );",
    )?;
    Ok(())
}

pub(super) fn lease_in(tx: &Transaction<'_>, environment: &str) -> Result<Option<LeaseRecord>> {
    Ok(tx
        .query_row(
            "SELECT environment_id, owner, generation, expires_at FROM leases WHERE environment_id=?1",
            [environment],
            |row| {
                Ok(LeaseRecord {
                    environment_id: row.get(0)?,
                    owner: row.get(1)?,
                    generation: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        )
        .optional()?)
}

pub(super) fn require_lease(
    tx: &Transaction<'_>,
    environment: &str,
    owner: &str,
    generation: u64,
    now: i64,
) -> Result<()> {
    let lease = lease_in(tx, environment)?.ok_or_else(|| StoreError::StaleLease {
        environment: environment.into(),
        expected: 0,
        actual: generation,
    })?;
    if lease.generation != generation {
        return Err(StoreError::StaleLease {
            environment: environment.into(),
            expected: lease.generation,
            actual: generation,
        });
    }
    if lease.owner != owner {
        return Err(StoreError::LeaseOwnerMismatch {
            environment: environment.into(),
            expected: lease.owner,
            actual: owner.into(),
        });
    }
    if lease.expires_at <= now {
        return Err(StoreError::LeaseExpired {
            environment: environment.into(),
            generation,
        });
    }
    Ok(())
}

pub(super) fn plan_environment(tx: &Transaction<'_>, plan_id: &str) -> Result<String> {
    tx.query_row(
        "SELECT environment_id FROM plans WHERE id=?1",
        [plan_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or_else(|| StoreError::NotFound {
        kind: "plan",
        id: plan_id.into(),
    })
}

pub(super) fn require_plan_environment(
    tx: &Transaction<'_>,
    plan_id: &str,
    environment: &str,
    kind: &'static str,
) -> Result<()> {
    let expected = plan_environment(tx, plan_id)?;
    if expected != environment {
        return Err(StoreError::EnvironmentMismatch {
            kind,
            id: plan_id.into(),
            expected,
            actual: environment.into(),
        });
    }
    Ok(())
}

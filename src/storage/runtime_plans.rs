use super::*;

impl SqliteStore {
    pub(super) fn claim_runtime_plan_sqlite(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        let now = crate::now_millis();
        if environment.is_empty() || plan_id.is_empty() || owner.is_empty() || expires_at <= now {
            return Err(StoreError::InvalidData {
                kind: "runtime claim",
                detail: "environment, plan, owner, and future expiry are required".into(),
            });
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE object_kind='plan' AND object_id=?1
             )",
            [plan_id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture plans are non-executable".into(),
            });
        }
        let current: Option<(String, String, u64, i64, Option<String>)> = tx
            .query_row(
                "SELECT environment_id,owner,generation,expires_at,completion_json FROM runtime_claims WHERE plan_id=?1",
                [plan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let generation = match current {
            Some((stored_environment, _, _, _, _)) if stored_environment != environment => {
                return Err(StoreError::EnvironmentMismatch {
                    kind: "runtime claim",
                    id: plan_id.into(),
                    expected: stored_environment,
                    actual: environment.into(),
                });
            }
            Some((stored_environment, stored_owner, generation, stored_expiry, completion))
                if stored_owner == owner && completion.is_some() =>
            {
                return Ok(Some(RuntimeClaim {
                    plan_id: plan_id.into(),
                    environment_id: stored_environment,
                    owner: stored_owner,
                    generation,
                    expires_at: stored_expiry,
                    completion_json: completion,
                }));
            }
            Some((_, _, _, _, Some(_))) => return Ok(None),
            Some((stored_environment, stored_owner, generation, stored_expiry, _))
                if stored_expiry > now && stored_owner == owner =>
            {
                tx.execute(
                    "UPDATE runtime_claims SET expires_at=?2 WHERE plan_id=?1",
                    params![plan_id, expires_at],
                )?;
                tx.commit()?;
                return Ok(Some(RuntimeClaim {
                    plan_id: plan_id.into(),
                    environment_id: stored_environment,
                    owner: stored_owner,
                    generation,
                    expires_at,
                    completion_json: None,
                }));
            }
            Some((_, _, _, stored_expiry, _)) if stored_expiry > now => return Ok(None),
            Some((_, _, generation, _, _)) => generation.saturating_add(1),
            None => 1,
        };
        tx.execute(
            "INSERT INTO runtime_claims(plan_id,environment_id,owner,generation,expires_at)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(plan_id) DO UPDATE SET owner=excluded.owner,
               generation=excluded.generation,expires_at=excluded.expires_at",
            params![plan_id, environment, owner, generation, expires_at],
        )?;
        tx.commit()?;
        Ok(Some(RuntimeClaim {
            plan_id: plan_id.into(),
            environment_id: environment.into(),
            owner: owner.into(),
            generation,
            expires_at,
            completion_json: None,
        }))
    }

    pub(super) fn renew_runtime_plan_sqlite(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        let now = crate::now_millis();
        if plan_id.is_empty() || owner.is_empty() || generation == 0 || expires_at <= now {
            return Err(StoreError::InvalidData {
                kind: "runtime heartbeat",
                detail: "plan, owner, generation, and future expiry are required".into(),
            });
        }
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE runtime_claims SET expires_at=?4
             WHERE plan_id=?1 AND owner=?2 AND generation=?3
               AND expires_at>?5 AND completion_json IS NULL",
            params![plan_id, owner, generation, expires_at, now],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        let claim = connection.query_row(
            "SELECT plan_id,environment_id,owner,generation,expires_at,completion_json
             FROM runtime_claims WHERE plan_id=?1",
            [plan_id],
            |row| {
                Ok(RuntimeClaim {
                    plan_id: row.get(0)?,
                    environment_id: row.get(1)?,
                    owner: row.get(2)?,
                    generation: row.get(3)?,
                    expires_at: row.get(4)?,
                    completion_json: row.get(5)?,
                })
            },
        )?;
        Ok(Some(claim))
    }

    pub(super) fn complete_runtime_plan_sqlite(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        let connection = self.connection()?;
        let current: (String, u64, i64, Option<String>) = connection
            .query_row(
                "SELECT owner,generation,expires_at,completion_json FROM runtime_claims WHERE plan_id=?1",
                [plan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound {
                kind: "runtime claim",
                id: plan_id.into(),
            })?;
        if current.0 != owner {
            return Err(StoreError::LeaseOwnerMismatch {
                environment: plan_id.into(),
                expected: current.0,
                actual: owner.into(),
            });
        }
        if current.1 != generation {
            return Err(StoreError::StaleLease {
                environment: plan_id.into(),
                expected: current.1,
                actual: generation,
            });
        }
        if let Some(existing) = current.3 {
            return if existing == completion_json {
                Ok(())
            } else {
                Err(StoreError::ImmutableConflict {
                    kind: "runtime completion",
                    id: plan_id.into(),
                })
            };
        }
        if current.2 <= crate::now_millis() {
            return Err(StoreError::LeaseExpired {
                environment: plan_id.into(),
                generation,
            });
        }
        let changed = connection.execute(
            "UPDATE runtime_claims SET completion_json=?4
             WHERE plan_id=?1 AND owner=?2 AND generation=?3 AND completion_json IS NULL",
            params![plan_id, owner, generation, completion_json],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let stored: Option<String> = connection.query_row(
            "SELECT completion_json FROM runtime_claims WHERE plan_id=?1",
            [plan_id],
            |row| row.get(0),
        )?;
        if stored.as_deref() == Some(completion_json) {
            Ok(())
        } else {
            Err(StoreError::ImmutableConflict {
                kind: "runtime completion",
                id: plan_id.into(),
            })
        }
    }
}

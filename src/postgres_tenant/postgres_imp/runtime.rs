use super::*;
use super::{Inner, pg};

impl Inner {
    pub fn claim_runtime_plan(
        &self,
        schema: &str,
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
        self.with_schema(schema, |tx| {
            if tx
                .query_one(
                    "SELECT EXISTS(
                        SELECT 1 FROM development_fixture_objects
                        WHERE object_kind='plan' AND object_id=$1
                     )",
                    &[&plan_id],
                )
                .map_err(pg)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture plans are non-executable".into(),
                });
            }
            let current = tx
                .query_opt(
                    "SELECT environment_id,owner,generation,expires_at,completion_json
                     FROM runtime_claims WHERE plan_id = $1",
                    &[&plan_id],
                )
                .map_err(pg)?;
            let generation = match current {
                Some(row) => {
                    let stored_env: String = row.get(0);
                    let stored_owner: String = row.get(1);
                    let generation: i64 = row.get(2);
                    let stored_expiry: i64 = row.get(3);
                    let completion: Option<String> = row.get(4);
                    if stored_env != environment {
                        return Err(StoreError::EnvironmentMismatch {
                            kind: "runtime claim",
                            id: plan_id.into(),
                            expected: stored_env,
                            actual: environment.into(),
                        });
                    }
                    if stored_owner == owner && completion.is_some() {
                        return Ok(Some(RuntimeClaim {
                            plan_id: plan_id.into(),
                            environment_id: stored_env,
                            owner: stored_owner,
                            generation: generation as u64,
                            expires_at: stored_expiry,
                            completion_json: completion,
                        }));
                    }
                    if completion.is_some() {
                        return Ok(None);
                    }
                    if stored_expiry > now && stored_owner == owner {
                        tx.execute(
                            "UPDATE runtime_claims SET expires_at = $2 WHERE plan_id = $1",
                            &[&plan_id, &expires_at],
                        )
                        .map_err(pg)?;
                        return Ok(Some(RuntimeClaim {
                            plan_id: plan_id.into(),
                            environment_id: stored_env,
                            owner: stored_owner,
                            generation: generation as u64,
                            expires_at,
                            completion_json: None,
                        }));
                    }
                    if stored_expiry > now {
                        return Ok(None);
                    }
                    (generation as u64).saturating_add(1)
                }
                None => 1,
            };
            let gen_i = generation as i64;
            tx.execute(
                "INSERT INTO runtime_claims(plan_id,environment_id,owner,generation,expires_at)
                 VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT(plan_id) DO UPDATE SET owner=EXCLUDED.owner,
                   generation=EXCLUDED.generation,expires_at=EXCLUDED.expires_at",
                &[&plan_id, &environment, &owner, &gen_i, &expires_at],
            )
            .map_err(pg)?;
            Ok(Some(RuntimeClaim {
                plan_id: plan_id.into(),
                environment_id: environment.into(),
                owner: owner.into(),
                generation,
                expires_at,
                completion_json: None,
            }))
        })
    }

    pub fn renew_runtime_plan(
        &self,
        schema: &str,
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
        self.with_schema(schema, |tx| {
            let lease_gen = generation as i64;
            let changed = tx
                .execute(
                    "UPDATE runtime_claims SET expires_at = $4
                     WHERE plan_id = $1 AND owner = $2 AND generation = $3
                       AND expires_at > $5 AND completion_json IS NULL",
                    &[&plan_id, &owner, &lease_gen, &expires_at, &now],
                )
                .map_err(pg)?;
            if changed == 0 {
                return Ok(None);
            }
            let row = tx
                .query_one(
                    "SELECT plan_id,environment_id,owner,generation,expires_at,completion_json
                     FROM runtime_claims WHERE plan_id = $1",
                    &[&plan_id],
                )
                .map_err(pg)?;
            Ok(Some(RuntimeClaim {
                plan_id: row.get(0),
                environment_id: row.get(1),
                owner: row.get(2),
                generation: row.get::<_, i64>(3) as u64,
                expires_at: row.get(4),
                completion_json: row.get(5),
            }))
        })
    }

    pub fn complete_runtime_plan(
        &self,
        schema: &str,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        self.with_schema(schema, |tx| {
            let row = tx
                .query_opt(
                    "SELECT owner,generation,expires_at,completion_json FROM runtime_claims
                     WHERE plan_id = $1",
                    &[&plan_id],
                )
                .map_err(pg)?
                .ok_or_else(|| StoreError::NotFound {
                    kind: "runtime claim",
                    id: plan_id.into(),
                })?;
            let stored_owner: String = row.get(0);
            let stored_gen: i64 = row.get(1);
            let expiry: i64 = row.get(2);
            let completion: Option<String> = row.get(3);
            if stored_owner != owner {
                return Err(StoreError::LeaseOwnerMismatch {
                    environment: plan_id.into(),
                    expected: stored_owner,
                    actual: owner.into(),
                });
            }
            if stored_gen as u64 != generation {
                return Err(StoreError::StaleLease {
                    environment: plan_id.into(),
                    expected: generation,
                    actual: stored_gen as u64,
                });
            }
            if let Some(existing) = completion {
                if existing != completion_json {
                    return Err(StoreError::ImmutableConflict {
                        kind: "runtime completion",
                        id: plan_id.into(),
                    });
                }
                return Ok(());
            }
            if expiry <= crate::now_millis() {
                return Err(StoreError::LeaseExpired {
                    environment: plan_id.into(),
                    generation,
                });
            }
            let lease_gen = generation as i64;
            tx.execute(
                "UPDATE runtime_claims SET completion_json = $4
                 WHERE plan_id = $1 AND owner = $2 AND generation = $3 AND completion_json IS NULL",
                &[&plan_id, &owner, &lease_gen, &completion_json],
            )
            .map_err(pg)?;
            Ok(())
        })
    }
}

use super::Inner;

fn fence_store(message: impl Into<String>) -> tenkai::reconcile_fence::FenceError {
    tenkai::reconcile_fence::FenceError::Store(message.into())
}

impl Inner {
    pub fn try_begin_reconcile_claim(
        &self,
        environment: &str,
        owner: &str,
        now: i64,
        ttl_ms: i64,
    ) -> std::result::Result<
        tenkai::reconcile_fence::FenceAdmission,
        tenkai::reconcile_fence::FenceError,
    > {
        use tenkai::reconcile_fence::{FenceAdmission, FenceError};
        if environment.trim().is_empty() || owner.trim().is_empty() {
            return Err(FenceError::InvalidIdentity);
        }
        if ttl_ms <= 0 {
            return Err(FenceError::InvalidExpiry);
        }
        let expires_at = now.saturating_add(ttl_ms);
        let environment = environment.to_owned();
        let owner = owner.to_owned();
        self.worker.run(
            move |client| {
                let mut tx = client
                    .transaction()
                    .map_err(|error| fence_store(error.to_string()))?;
                let row = tx
                    .query_opt(
                        "SELECT owner, generation, expires_at
                 FROM tenkai_reconcile_tick_claims
                 WHERE environment = $1
                 FOR UPDATE",
                        &[&environment],
                    )
                    .map_err(|error| fence_store(error.to_string()))?;
                let admission = match row {
                    Some(row) => {
                        let claim_owner: String = row.get(0);
                        let generation: i64 = row.get(1);
                        let claim_expires: i64 = row.get(2);
                        if claim_expires > now && claim_owner != owner {
                            FenceAdmission::Busy { owner: claim_owner }
                        } else if claim_expires > now && claim_owner == owner {
                            tx.execute(
                                "UPDATE tenkai_reconcile_tick_claims
                         SET expires_at = $1
                         WHERE environment = $2",
                                &[&expires_at, &environment],
                            )
                            .map_err(|error| fence_store(error.to_string()))?;
                            FenceAdmission::Started {
                                generation: generation as u64,
                            }
                        } else {
                            let next_gen = (generation as u64).saturating_add(1);
                            tx.execute(
                                "UPDATE tenkai_reconcile_tick_claims
                         SET owner = $1, generation = $2, expires_at = $3
                         WHERE environment = $4",
                                &[&owner, &(next_gen as i64), &expires_at, &environment],
                            )
                            .map_err(|error| fence_store(error.to_string()))?;
                            FenceAdmission::Started {
                                generation: next_gen,
                            }
                        }
                    }
                    None => {
                        tx.execute(
                            "INSERT INTO tenkai_reconcile_tick_claims
                     (environment, owner, generation, expires_at)
                     VALUES ($1, $2, 1, $3)",
                            &[&environment, &owner, &expires_at],
                        )
                        .map_err(|error| fence_store(error.to_string()))?;
                        FenceAdmission::Started { generation: 1 }
                    }
                };
                if matches!(admission, FenceAdmission::Busy { .. }) {
                    // No write; still commit to end the FOR UPDATE transaction cleanly.
                    tx.commit()
                        .map_err(|error| fence_store(error.to_string()))?;
                    return Ok(admission);
                }
                tx.commit()
                    .map_err(|error| fence_store(error.to_string()))?;
                Ok(admission)
            },
            fence_store("postgres worker thread panicked"),
        )
    }

    pub fn release_reconcile_claim(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        now: i64,
    ) -> std::result::Result<(), tenkai::reconcile_fence::FenceError> {
        let environment = environment.to_owned();
        let owner = owner.to_owned();
        self.worker.run(
            move |client| {
                let mut tx = client
                    .transaction()
                    .map_err(|error| fence_store(error.to_string()))?;
                let row = tx
                    .query_opt(
                        "SELECT owner, generation, expires_at
                 FROM tenkai_reconcile_tick_claims
                 WHERE environment = $1
                 FOR UPDATE",
                        &[&environment],
                    )
                    .map_err(|error| fence_store(error.to_string()))?;
                if let Some(row) = row {
                    let claim_owner: String = row.get(0);
                    let claim_gen: i64 = row.get(1);
                    if claim_owner == owner && claim_gen as u64 == generation {
                        tx.execute(
                            "UPDATE tenkai_reconcile_tick_claims
                     SET expires_at = LEAST(expires_at, $1)
                     WHERE environment = $2",
                            &[&now, &environment],
                        )
                        .map_err(|error| fence_store(error.to_string()))?;
                    }
                    // Stale release must not steal another host's claim.
                }
                tx.commit()
                    .map_err(|error| fence_store(error.to_string()))?;
                Ok(())
            },
            fence_store("postgres worker thread panicked"),
        )
    }
}

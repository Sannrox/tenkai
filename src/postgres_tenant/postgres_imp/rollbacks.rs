use super::*;
use super::{Inner, pg, require_lease, require_plan_environment};
use postgres::Transaction;

pub(crate) fn legacy_rollback_intent(rollback: &RollbackRecord) -> String {
    format!(
        "{}:{}:{}",
        rollback.environment_id, rollback.plan_id, rollback.lease_generation
    )
}

pub(crate) fn rollback_intent_matches(
    tx: &mut Transaction<'_>,
    rollback: &RollbackRecord,
) -> Result<bool> {
    let row = tx
        .query_one(
            "SELECT intent_digest,environment_id,plan_id,intent_lease_generation,
                    creation_checkpoint_json,creation_status_detail
             FROM rollbacks WHERE id=$1",
            &[&rollback.id],
        )
        .map_err(pg)?;
    let stored: String = row.get(0);
    let expected = rollback_intent_digest(rollback);
    let intent_generation = row.get::<_, Option<i64>>(3);
    let creation_checkpoint = row.get::<_, Option<String>>(4);
    let creation_detail = row.get::<_, Option<String>>(5);
    if intent_generation.is_none() && creation_checkpoint.is_none() && creation_detail.is_none() {
        // Progressed rows from the legacy schema no longer contain their
        // original mutable fields. Preserve their historical idempotency
        // contract without rewriting or claiming stronger validation.
        return Ok(stored == legacy_rollback_intent(rollback));
    }
    Ok(
        (stored == expected || stored == legacy_rollback_intent(rollback))
            && row.get::<_, String>(1) == rollback.environment_id
            && row.get::<_, String>(2) == rollback.plan_id
            && intent_generation == Some(rollback.lease_generation as i64)
            && creation_checkpoint.as_deref() == Some(&rollback.checkpoint_json)
            && creation_detail.as_deref() == Some(&rollback.status_detail),
    )
}

pub(crate) fn rollback_in(tx: &mut Transaction<'_>, id: &str) -> Result<Option<RollbackRecord>> {
    let row = tx
        .query_opt(
            "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail
             FROM rollbacks WHERE id = $1",
            &[&id],
        )
        .map_err(pg)?;
    row.map(|row| {
        let status: String = row.get(5);
        Ok(RollbackRecord {
            id: row.get(0),
            environment_id: row.get(1),
            plan_id: row.get(2),
            lease_generation: row.get::<_, i64>(3) as u64,
            checkpoint_json: row.get(4),
            status: RollbackStatus::parse(&status)?,
            status_detail: row.get(6),
        })
    })
    .transpose()
}

impl Inner {
    pub fn create_rollback(
        &self,
        schema: &str,
        owner: &str,
        rollback: &RollbackRecord,
    ) -> Result<()> {
        if rollback.status != RollbackStatus::Pending {
            return Err(StoreError::InvalidRollbackTransition {
                id: rollback.id.clone(),
                from: RollbackStatus::Pending,
                to: rollback.status,
            });
        }
        self.with_schema(schema, |tx| {
            if rollback_in(tx, &rollback.id)?.is_some() {
                if !rollback_intent_matches(tx, rollback)? {
                    return Err(StoreError::ImmutableConflict {
                        kind: "rollback",
                        id: rollback.id.clone(),
                    });
                }
                return Ok(());
            }
            require_plan_environment(tx, &rollback.plan_id, &rollback.environment_id)?;
            require_lease(
                tx,
                &rollback.environment_id,
                owner,
                rollback.lease_generation,
                crate::now_millis(),
            )?;
            let lease_gen = rollback.lease_generation as i64;
            let intent = rollback_intent_digest(rollback);
            tx.execute(
                "INSERT INTO rollbacks(
                    id,environment_id,plan_id,lease_generation,intent_digest,
                    checkpoint_json,status,status_detail,intent_lease_generation,
                    creation_checkpoint_json,creation_status_detail
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$4,$6,$8)
                 ON CONFLICT(id) DO NOTHING",
                &[
                    &rollback.id,
                    &rollback.environment_id,
                    &rollback.plan_id,
                    &lease_gen,
                    &intent,
                    &rollback.checkpoint_json,
                    &rollback.status.as_str(),
                    &rollback.status_detail,
                ],
            )
            .map_err(pg)?;
            if !rollback_intent_matches(tx, rollback)? {
                return Err(StoreError::ImmutableConflict {
                    kind: "rollback",
                    id: rollback.id.clone(),
                });
            }
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_rollback(
        &self,
        schema: &str,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord> {
        self.with_schema(schema, |tx| {
            let environment: String = tx
                .query_opt(
                    "SELECT environment_id FROM rollbacks WHERE id=$1",
                    &[&id],
                )
                .map_err(pg)?
                .map(|row| row.get(0))
                .ok_or_else(|| StoreError::NotFound {
                    kind: "rollback",
                    id: id.into(),
                })?;
            lock_lease(tx, &environment)?;
            let current = rollback_in(tx, id)?.ok_or_else(|| StoreError::NotFound {
                kind: "rollback",
                id: id.into(),
            })?;
            require_plan_environment(tx, &current.plan_id, &current.environment_id)?;
            require_lease(
                tx,
                &current.environment_id,
                owner,
                generation,
                crate::now_millis(),
            )?;
            if !current.status.allows(status) {
                return Err(StoreError::InvalidRollbackTransition {
                    id: id.into(),
                    from: current.status,
                    to: status,
                });
            }
            let lease_gen = generation as i64;
            tx.execute(
                "UPDATE rollbacks SET lease_generation=$2,checkpoint_json=$3,status=$4,status_detail=$5
                 WHERE id=$1",
                &[&id, &lease_gen, &checkpoint_json, &status.as_str(), &detail],
            )
            .map_err(pg)?;
            rollback_in(tx, id)?.ok_or_else(|| StoreError::NotFound {
                kind: "rollback",
                id: id.into(),
            })
        })
    }

    pub fn pending_rollbacks(&self, schema: &str) -> Result<Vec<RollbackRecord>> {
        self.with_schema(schema, |tx| {
            let rows = tx
                .query(
                    "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail
                     FROM rollbacks WHERE status IN ('pending','running') ORDER BY id",
                    &[],
                )
                .map_err(pg)?;
            rows.into_iter()
                .map(|row| {
                    let status: String = row.get(5);
                    Ok(RollbackRecord {
                        id: row.get(0),
                        environment_id: row.get(1),
                        plan_id: row.get(2),
                        lease_generation: row.get::<_, i64>(3) as u64,
                        checkpoint_json: row.get(4),
                        status: RollbackStatus::parse(&status)?,
                        status_detail: row.get(6),
                    })
                })
                .collect()
        })
    }
}

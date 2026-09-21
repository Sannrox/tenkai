use super::*;

impl SqliteStore {
    pub(super) fn create_rollback_sqlite(
        &self,
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
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if rollback_in(&tx, &rollback.id)?.is_some() {
            let stored_digest: String = tx.query_row(
                "SELECT intent_digest FROM rollbacks WHERE id=?1",
                [&rollback.id],
                |row| row.get(0),
            )?;
            if rollback_intent_digest(rollback) != stored_digest {
                return Err(StoreError::ImmutableConflict {
                    kind: "rollback",
                    id: rollback.id.clone(),
                });
            }
            return Ok(());
        }
        require_plan_environment(&tx, &rollback.plan_id, &rollback.environment_id, "rollback")?;
        require_lease(
            &tx,
            &rollback.environment_id,
            owner,
            rollback.lease_generation,
            crate::now_millis(),
        )?;
        tx.execute(
            "INSERT INTO rollbacks(id,environment_id,plan_id,lease_generation,intent_digest,checkpoint_json,status,status_detail) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![rollback.id, rollback.environment_id, rollback.plan_id, rollback.lease_generation, rollback_intent_digest(rollback), rollback.checkpoint_json, rollback.status.as_str(), rollback.status_detail],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn transition_rollback_sqlite(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current = rollback_in(&tx, id)?.ok_or_else(|| StoreError::NotFound {
            kind: "rollback",
            id: id.into(),
        })?;
        require_plan_environment(&tx, &current.plan_id, &current.environment_id, "rollback")?;
        require_lease(
            &tx,
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
        tx.execute(
            "UPDATE rollbacks SET lease_generation=?2,checkpoint_json=?3,status=?4,status_detail=?5 WHERE id=?1",
            params![id, generation, checkpoint_json, status.as_str(), detail],
        )?;
        let updated = rollback_in(&tx, id)?.expect("updated rollback exists");
        tx.commit()?;
        Ok(updated)
    }
}

pub(crate) fn rollback_intent_digest(rollback: &RollbackRecord) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    for value in [
        rollback.environment_id.as_bytes(),
        rollback.plan_id.as_bytes(),
        &rollback.lease_generation.to_le_bytes(),
        rollback.checkpoint_json.as_bytes(),
        rollback.status_detail.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

pub(super) fn rollback_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RollbackRecord> {
    let status: String = row.get(5)?;
    let status = RollbackStatus::parse(&status).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(RollbackRecord {
        id: row.get(0)?,
        environment_id: row.get(1)?,
        plan_id: row.get(2)?,
        lease_generation: row.get(3)?,
        checkpoint_json: row.get(4)?,
        status,
        status_detail: row.get(6)?,
    })
}

pub(super) fn rollback_in(tx: &Transaction<'_>, id: &str) -> Result<Option<RollbackRecord>> {
    Ok(tx.query_row(
        "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail FROM rollbacks WHERE id=?1",
        [id], rollback_from_row,
    ).optional()?)
}

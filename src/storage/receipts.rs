use super::*;

impl SqliteStore {
    pub(super) fn record_receipt_sqlite(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing: Option<(String, String, String, u64, String)> = tx.query_row(
            "SELECT environment_id,plan_id,step_id,lease_generation,payload_json FROM receipts WHERE id=?1", [&receipt.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    receipt.environment_id.clone(),
                    receipt.plan_id.clone(),
                    receipt.step_id.clone(),
                    receipt.lease_generation,
                    receipt.payload_json.clone(),
                )
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "receipt",
                    id: receipt.id.clone(),
                });
            }
            return Ok(());
        }
        require_plan_environment(&tx, &receipt.plan_id, &receipt.environment_id, "receipt")?;
        require_lease(
            &tx,
            &receipt.environment_id,
            owner,
            receipt.lease_generation,
            crate::now_millis(),
        )?;
        tx.execute(
            "INSERT INTO receipts(id,environment_id,plan_id,step_id,lease_generation,payload_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![receipt.id, receipt.environment_id, receipt.plan_id, receipt.step_id, receipt.lease_generation, receipt.payload_json],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn record_offline_import_sqlite(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT environment_id,plan_id,receipt_json FROM offline_imports WHERE bundle_digest=?1",
                [&receipt.bundle_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing
            && existing
                != (
                    receipt.environment_id.clone(),
                    receipt.plan_id.clone(),
                    receipt.receipt_json.clone(),
                )
        {
            return Err(StoreError::ImmutableConflict {
                kind: "offline import",
                id: receipt.bundle_digest.clone(),
            });
        }
        for step in steps {
            let existing = tx
                .query_row(
                    "SELECT environment_id,plan_id,step_id,attempt,result_digest,succeeded
                     FROM offline_step_receipts WHERE receipt_id=?1",
                    [&step.receipt_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, u32>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, bool>(5)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing
                && existing
                    != (
                        step.environment_id.clone(),
                        step.plan_id.clone(),
                        step.step_id.clone(),
                        step.attempt,
                        step.result_digest.clone(),
                        step.succeeded,
                    )
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "offline step receipt",
                    id: step.receipt_id.clone(),
                });
            }
        }
        require_plan_environment(
            &tx,
            &receipt.plan_id,
            &receipt.environment_id,
            "offline import",
        )?;
        tx.execute(
            "INSERT INTO offline_imports(bundle_digest,environment_id,plan_id,receipt_json)
             VALUES(?1,?2,?3,?4)
             ON CONFLICT(bundle_digest) DO NOTHING",
            params![
                receipt.bundle_digest,
                receipt.environment_id,
                receipt.plan_id,
                receipt.receipt_json
            ],
        )?;
        for step in steps {
            tx.execute(
                "INSERT INTO offline_step_receipts(
                    receipt_id,environment_id,plan_id,step_id,attempt,result_digest,succeeded
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(receipt_id) DO NOTHING",
                params![
                    step.receipt_id,
                    step.environment_id,
                    step.plan_id,
                    step.step_id,
                    step.attempt,
                    step.result_digest,
                    step.succeeded
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn get_offline_import_sqlite(
        &self,
        bundle_digest: &str,
    ) -> Result<Option<OfflineImportRecord>> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT bundle_digest,environment_id,plan_id,receipt_json
                 FROM offline_imports WHERE bundle_digest=?1",
                [bundle_digest],
                |row| {
                    Ok(OfflineImportRecord {
                        bundle_digest: row.get(0)?,
                        environment_id: row.get(1)?,
                        plan_id: row.get(2)?,
                        receipt_json: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }
}

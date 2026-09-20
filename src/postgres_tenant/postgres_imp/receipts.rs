use super::*;
use super::{Inner, pg, require_lease, require_plan_environment};

impl Inner {
    pub fn record_receipt(&self, schema: &str, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        self.with_schema(schema, |tx| {
            let existing = tx
                .query_opt(
                    "SELECT environment_id,plan_id,step_id,lease_generation,payload_json
                     FROM receipts WHERE id = $1",
                    &[&receipt.id],
                )
                .map_err(pg)?;
            if let Some(row) = existing {
                let env: String = row.get(0);
                let plan: String = row.get(1);
                let step: String = row.get(2);
                let lease_gen: i64 = row.get(3);
                let payload: String = row.get(4);
                if env != receipt.environment_id
                    || plan != receipt.plan_id
                    || step != receipt.step_id
                    || lease_gen as u64 != receipt.lease_generation
                    || payload != receipt.payload_json
                {
                    return Err(StoreError::ImmutableConflict {
                        kind: "receipt",
                        id: receipt.id.clone(),
                    });
                }
                return Ok(());
            }
            require_plan_environment(tx, &receipt.plan_id, &receipt.environment_id)?;
            require_lease(
                tx,
                &receipt.environment_id,
                owner,
                receipt.lease_generation,
                crate::now_millis(),
            )?;
            let lease_gen = receipt.lease_generation as i64;
            tx.execute(
                "INSERT INTO receipts(id,environment_id,plan_id,step_id,lease_generation,payload_json)
                 VALUES($1,$2,$3,$4,$5,$6)
                 ON CONFLICT(id) DO NOTHING",
                &[
                    &receipt.id,
                    &receipt.environment_id,
                    &receipt.plan_id,
                    &receipt.step_id,
                    &lease_gen,
                    &receipt.payload_json,
                ],
            )
            .map_err(pg)?;
            let stored = tx
                .query_one(
                    "SELECT environment_id,plan_id,step_id,lease_generation,payload_json
                     FROM receipts WHERE id = $1",
                    &[&receipt.id],
                )
                .map_err(pg)?;
            if stored.get::<_, String>(0) != receipt.environment_id
                || stored.get::<_, String>(1) != receipt.plan_id
                || stored.get::<_, String>(2) != receipt.step_id
                || stored.get::<_, i64>(3) as u64 != receipt.lease_generation
                || stored.get::<_, String>(4) != receipt.payload_json
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "receipt",
                    id: receipt.id.clone(),
                });
            }
            Ok(())
        })
    }

    pub fn get_receipt(&self, schema: &str, id: &str) -> Result<Option<ReceiptRecord>> {
        self.with_schema(schema, |tx| {
            let row = tx
                .query_opt(
                    "SELECT id,environment_id,plan_id,step_id,lease_generation,payload_json
                     FROM receipts WHERE id = $1",
                    &[&id],
                )
                .map_err(pg)?;
            Ok(row.map(|row| ReceiptRecord {
                id: row.get(0),
                environment_id: row.get(1),
                plan_id: row.get(2),
                step_id: row.get(3),
                lease_generation: row.get::<_, i64>(4) as u64,
                payload_json: row.get(5),
            }))
        })
    }

    pub fn record_offline_import(
        &self,
        schema: &str,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        self.with_schema(schema, |tx| {
            let existing = tx
                .query_opt(
                    "SELECT environment_id,plan_id,receipt_json FROM offline_imports
                     WHERE bundle_digest = $1",
                    &[&receipt.bundle_digest],
                )
                .map_err(pg)?;
            if let Some(row) = existing {
                let env: String = row.get(0);
                let plan: String = row.get(1);
                let json: String = row.get(2);
                if env != receipt.environment_id
                    || plan != receipt.plan_id
                    || json != receipt.receipt_json
                {
                    return Err(StoreError::ImmutableConflict {
                        kind: "offline import",
                        id: receipt.bundle_digest.clone(),
                    });
                }
            }
            require_plan_environment(tx, &receipt.plan_id, &receipt.environment_id)?;
            tx.execute(
                "INSERT INTO offline_imports(bundle_digest,environment_id,plan_id,receipt_json)
                 VALUES($1,$2,$3,$4) ON CONFLICT(bundle_digest) DO NOTHING",
                &[
                    &receipt.bundle_digest,
                    &receipt.environment_id,
                    &receipt.plan_id,
                    &receipt.receipt_json,
                ],
            )
            .map_err(pg)?;
            for step in steps {
                let attempt = step.attempt as i32;
                tx.execute(
                    "INSERT INTO offline_step_receipts(
                        receipt_id,environment_id,plan_id,step_id,attempt,result_digest,succeeded
                     ) VALUES($1,$2,$3,$4,$5,$6,$7)
                     ON CONFLICT(receipt_id) DO NOTHING",
                    &[
                        &step.receipt_id,
                        &step.environment_id,
                        &step.plan_id,
                        &step.step_id,
                        &attempt,
                        &step.result_digest,
                        &step.succeeded,
                    ],
                )
                .map_err(pg)?;
            }
            Ok(())
        })
    }

    pub fn get_offline_import(
        &self,
        schema: &str,
        bundle_digest: &str,
    ) -> Result<Option<OfflineImportRecord>> {
        self.with_schema(schema, |tx| {
            let row = tx
                .query_opt(
                    "SELECT bundle_digest,environment_id,plan_id,receipt_json
                     FROM offline_imports WHERE bundle_digest = $1",
                    &[&bundle_digest],
                )
                .map_err(pg)?;
            Ok(row.map(|row| OfflineImportRecord {
                bundle_digest: row.get(0),
                environment_id: row.get(1),
                plan_id: row.get(2),
                receipt_json: row.get(3),
            }))
        })
    }
}

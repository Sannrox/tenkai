use super::*;
use super::{Inner, lock_lease, pg, require_lease};

impl Inner {
    pub fn create_plan(&self, schema: &str, plan: &PlanRecord) -> Result<()> {
        self.with_schema(schema, |tx| {
            if tx
                .query_one(
                    "SELECT EXISTS(
                        SELECT 1 FROM development_fixture_objects
                        WHERE object_kind='environment' AND object_id=$1
                     )",
                    &[&plan.environment_id],
                )
                .map_err(pg)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture environments cannot accept executable plans".into(),
                });
            }
            if plan.status != PlanStatus::Computed {
                return Err(StoreError::InvalidPlanTransition {
                    id: plan.id.clone(),
                    from: PlanStatus::Computed,
                    to: plan.status,
                });
            }
            let format = plan.format_version as i32;
            tx.execute(
                "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
                 VALUES($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT(id) DO NOTHING",
                &[
                    &plan.id,
                    &plan.environment_id,
                    &format,
                    &plan.content_digest,
                    &plan.plan_json,
                    &plan.status.as_str(),
                    &plan.status_detail,
                ],
            )
            .map_err(pg)?;
            let existing = tx
                .query_one(
                    "SELECT environment_id,format_version,content_digest,plan_json
                     FROM plans WHERE id = $1",
                    &[&plan.id],
                )
                .map_err(pg)?;
            let env: String = existing.get(0);
            let stored_format: i32 = existing.get(1);
            let digest: String = existing.get(2);
            let json: String = existing.get(3);
            if env != plan.environment_id
                || stored_format as u32 != plan.format_version
                || digest != plan.content_digest
                || json != plan.plan_json
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "plan",
                    id: plan.id.clone(),
                });
            }
            Ok(())
        })
    }

    pub fn get_plan(&self, schema: &str, id: &str) -> Result<Option<PlanRecord>> {
        self.with_schema(schema, |tx| {
            let row = tx
                .query_opt(
                    "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                     FROM plans WHERE id = $1",
                    &[&id],
                )
                .map_err(pg)?;
            row.map(|row| {
                let status: String = row.get(5);
                Ok(PlanRecord {
                    id: row.get(0),
                    environment_id: row.get(1),
                    format_version: row.get::<_, i32>(2) as u32,
                    content_digest: row.get(3),
                    plan_json: row.get(4),
                    status: PlanStatus::parse(&status)?,
                    status_detail: row.get(6),
                })
            })
            .transpose()
        })
    }

    pub fn transition_plan(
        &self,
        schema: &str,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        self.with_schema(schema, |tx| {
            if tx
                .query_one(
                    "SELECT EXISTS(
                        SELECT 1 FROM development_fixture_objects
                        WHERE object_kind='plan' AND object_id=$1
                     )",
                    &[&id],
                )
                .map_err(pg)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture plans are non-executable".into(),
                });
            }
            let environment: String = tx
                .query_opt("SELECT environment_id FROM plans WHERE id = $1", &[&id])
                .map_err(pg)?
                .map(|row| row.get(0))
                .ok_or_else(|| StoreError::NotFound {
                    kind: "plan",
                    id: id.into(),
                })?;
            lock_lease(tx, &environment)?;
            let current: String = tx
                .query_one("SELECT status FROM plans WHERE id = $1", &[&id])
                .map_err(pg)?
                .get(0);
            let current = PlanStatus::parse(&current)?;
            require_lease(tx, &environment, owner, generation, crate::now_millis())?;
            if !current.allows(status) {
                return Err(StoreError::InvalidPlanTransition {
                    id: id.into(),
                    from: current,
                    to: status,
                });
            }
            tx.execute(
                "UPDATE plans SET status = $2, status_detail = $3 WHERE id = $1",
                &[&id, &status.as_str(), &detail],
            )
            .map_err(pg)?;
            let row = tx
                .query_one(
                    "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                     FROM plans WHERE id = $1",
                    &[&id],
                )
                .map_err(pg)?;
            let status_s: String = row.get(5);
            Ok(PlanRecord {
                id: row.get(0),
                environment_id: row.get(1),
                format_version: row.get::<_, i32>(2) as u32,
                content_digest: row.get(3),
                plan_json: row.get(4),
                status: PlanStatus::parse(&status_s)?,
                status_detail: row.get(6),
            })
        })
    }
}

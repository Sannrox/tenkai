use super::*;
use super::{Inner, pg};

impl Inner {
    pub fn reset_development_fixture(
        &self,
        schema: &str,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        self.with_schema(schema, |tx| {
            let lock_key = format!("{schema}:{fixture_id}");
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .map_err(pg)?;
            let row = tx
                .query_one(
                    "SELECT
                       (SELECT COUNT(*) FROM leases WHERE environment_id IN
                          (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='environment')) +
                       (SELECT COUNT(*) FROM receipts WHERE environment_id IN
                          (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='environment')
                          OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='plan')) +
                       (SELECT COUNT(*) FROM rollbacks WHERE environment_id IN
                          (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='environment')
                          OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='plan')) +
                       (SELECT COUNT(*) FROM offline_imports WHERE environment_id IN
                          (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='environment')
                          OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='plan')) +
                       (SELECT COUNT(*) FROM offline_step_receipts WHERE environment_id IN
                          (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='environment')
                          OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='plan')) +
                       (SELECT COUNT(*) FROM runtime_claims WHERE environment_id IN
                          (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='environment')
                          OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=$1 AND object_kind='plan'))",
                    &[&fixture_id],
                )
                .map_err(pg)?;
            let dependent: i64 = row.get(0);
            if dependent != 0 {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail:
                        "fixture reset refused because operational state depends on it".into(),
                });
            }
            let mut removed = 0_usize;
            for (table, kind) in [
                ("plans", "plan"),
                ("channels", "channel"),
                ("environments", "environment"),
                ("releases", "release"),
            ] {
                removed += tx
                    .execute(
                        &format!(
                            "DELETE FROM {table} WHERE id IN
                             (SELECT object_id FROM development_fixture_objects
                              WHERE fixture_id=$1 AND object_kind=$2)"
                        ),
                        &[&fixture_id, &kind],
                    )
                    .map_err(pg)? as usize;
            }
            tx.execute(
                "DELETE FROM development_fixture_objects WHERE fixture_id=$1",
                &[&fixture_id],
            )
            .map_err(pg)?;
            tx.execute(
                "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
                 VALUES($1,$2,$3,'development_fixture.reset',$4,'reset')",
                &[
                    &format!("development_fixture.reset:{request_id}"),
                    &crate::now_millis(),
                    &actor,
                    &fixture_id,
                ],
            )
            .map_err(pg)?;
            Ok(crate::development_fixtures::FixtureResetResult {
                contract_version:
                    crate::development_fixtures::DEVELOPMENT_FIXTURE_CONTRACT_VERSION,
                fixture_id: fixture_id.into(),
                removed,
            })
        })
    }

    pub fn development_fixture_environment(
        &self,
        schema: &str,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        self.with_schema(schema, |tx| {
            let fixture = tx
                .query_opt(
                    "SELECT fixture_id FROM development_fixture_objects
                     WHERE object_kind='environment' AND object_id=$1",
                    &[&environment_id],
                )
                .map_err(pg)?;
            let Some(fixture) = fixture else {
                return Ok(None);
            };
            let fixture_id: String = fixture.get(0);
            let row = tx
                .query_one(
                    "SELECT id,revision,configuration_json FROM environments WHERE id=$1",
                    &[&environment_id],
                )
                .map_err(pg)?;
            let environment = EnvironmentRecord {
                id: row.get(0),
                revision: row.get::<_, i64>(1) as u64,
                configuration_json: row.get(2),
            };
            let channels = tx
                .query(
                    "SELECT c.product,c.name,r.version
                     FROM development_fixture_objects owned
                     JOIN channels c ON c.id=owned.object_id
                     JOIN releases r ON r.id=c.release_id
                     WHERE owned.fixture_id=$1 AND owned.object_kind='channel'
                     ORDER BY owned.object_order DESC, c.id",
                    &[&fixture_id],
                )
                .map_err(pg)?
                .into_iter()
                .map(|row| crate::development_fixtures::FixtureChannelProjection {
                    product: row.get(0),
                    channel: row.get(1),
                    head: row.get(2),
                })
                .collect();
            let latest_plan = tx
                .query_opt(
                    "SELECT p.id,p.environment_id,p.format_version,p.content_digest,p.plan_json,p.status,p.status_detail
                     FROM development_fixture_objects owned
                     JOIN plans p ON p.id=owned.object_id
                     WHERE owned.fixture_id=$1 AND owned.object_kind='plan' AND p.environment_id=$2
                     ORDER BY owned.object_order DESC, p.id DESC
                     LIMIT 1",
                    &[&fixture_id, &environment_id],
                )
                .map_err(pg)?
                .map(|row| {
                    let status: String = row.get(5);
                    Ok::<PlanRecord, StoreError>(PlanRecord {
                        id: row.get(0),
                        environment_id: row.get(1),
                        format_version: row.get::<_, i32>(2) as u32,
                        content_digest: row.get(3),
                        plan_json: row.get(4),
                        status: PlanStatus::parse(&status)?,
                        status_detail: row.get(6),
                    })
                })
                .transpose()?;
            crate::development_fixtures::parse_environment_projection(
                environment,
                channels,
                latest_plan,
            )
            .map(Some)
        })
    }
}

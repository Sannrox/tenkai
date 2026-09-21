use super::*;

impl SqliteStore {
    pub(super) fn import_development_fixture_sqlite(
        &self,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (existing, persisted_digest): (i64, Option<String>) = tx.query_row(
            "SELECT COUNT(*), MIN(fixture_digest)
             FROM development_fixture_objects WHERE fixture_id=?1",
            [&fixture.map.fixture_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let expected = fixture.releases.len()
            + fixture.channels.len()
            + fixture.environments.len()
            + fixture.plans.len();
        if existing != 0 {
            if existing as usize != expected
                || persisted_digest.as_deref() != Some(&fixture.map.fixture_digest)
                || !sqlite_fixture_matches(&tx, fixture)?
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "development_fixture",
                    id: fixture.map.fixture_id.clone(),
                });
            }
            return Ok(fixture.map.clone());
        }
        for release in &fixture.releases {
            tx.execute(
                "INSERT INTO releases(id,product,version,content_digest,descriptor_json)
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    release.id,
                    release.product,
                    release.version,
                    release.content_digest,
                    release.descriptor_json
                ],
            )?;
        }
        for channel in &fixture.channels {
            tx.execute(
                "INSERT INTO channels(id,product,name,release_id,revision)
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    channel.id,
                    channel.product,
                    channel.name,
                    channel.release_id,
                    channel.revision
                ],
            )?;
        }
        for environment in &fixture.environments {
            tx.execute(
                "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,?2,?3)",
                params![
                    environment.id,
                    environment.revision,
                    environment.configuration_json
                ],
            )?;
        }
        for plan in &fixture.plans {
            tx.execute(
                "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
                 VALUES(?1,?2,?3,?4,?5,'blocked',?6)",
                params![
                    plan.id,
                    plan.environment_id,
                    plan.format_version,
                    plan.content_digest,
                    plan.plan_json,
                    plan.status_detail
                ],
            )?;
        }
        for (kind, ids) in [
            ("release", &fixture.map.releases),
            ("channel", &fixture.map.channels),
            ("environment", &fixture.map.environments),
            ("plan", &fixture.map.plans),
        ] {
            for (object_order, id) in ids.iter().enumerate() {
                let object_order = object_order as i64;
                tx.execute(
                    "INSERT INTO development_fixture_objects(fixture_id,fixture_digest,object_kind,object_id,object_order)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![
                        fixture.map.fixture_id,
                        fixture.map.fixture_digest,
                        kind,
                        id,
                        object_order
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
             VALUES(?1,?2,?3,'development_fixture.imported',?4,'imported')",
            params![
                request_id,
                crate::now_millis(),
                actor,
                fixture.map.fixture_digest
            ],
        )?;
        tx.commit()?;
        Ok(fixture.map.clone())
    }

    pub(super) fn reset_development_fixture_sqlite(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let dependent: i64 = tx.query_row(
            "SELECT
               (SELECT COUNT(*) FROM leases WHERE environment_id IN
                  (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='environment')) +
               (SELECT COUNT(*) FROM receipts WHERE environment_id IN
                  (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='environment')
                  OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='plan')) +
               (SELECT COUNT(*) FROM rollbacks WHERE environment_id IN
                  (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='environment')
                  OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='plan')) +
               (SELECT COUNT(*) FROM offline_imports WHERE environment_id IN
                  (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='environment')
                  OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='plan')) +
               (SELECT COUNT(*) FROM offline_step_receipts WHERE environment_id IN
                  (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='environment')
                  OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='plan')) +
               (SELECT COUNT(*) FROM runtime_claims WHERE environment_id IN
                  (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='environment')
                  OR plan_id IN (SELECT object_id FROM development_fixture_objects WHERE fixture_id=?1 AND object_kind='plan'))",
            [fixture_id],
            |row| row.get(0),
        )?;
        if dependent != 0 {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture reset refused because operational state depends on it".into(),
            });
        }
        let mut removed = 0_usize;
        for (table, kind) in [
            ("plans", "plan"),
            ("channels", "channel"),
            ("environments", "environment"),
            ("releases", "release"),
        ] {
            removed += tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE id IN
                     (SELECT object_id FROM development_fixture_objects
                      WHERE fixture_id=?1 AND object_kind=?2)"
                ),
                params![fixture_id, kind],
            )?;
        }
        tx.execute(
            "DELETE FROM development_fixture_objects WHERE fixture_id=?1",
            [fixture_id],
        )?;
        tx.execute(
            "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
             VALUES(?1,?2,?3,'development_fixture.reset',?4,'reset')",
            params![request_id, crate::now_millis(), actor, fixture_id],
        )?;
        tx.commit()?;
        Ok(crate::development_fixtures::FixtureResetResult {
            contract_version: crate::development_fixtures::DEVELOPMENT_FIXTURE_CONTRACT_VERSION,
            fixture_id: fixture_id.into(),
            removed,
        })
    }

    pub(super) fn development_fixture_environment_sqlite(
        &self,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        let connection = self.connection()?;
        let fixture_id: Option<String> = connection
            .query_row(
                "SELECT fixture_id FROM development_fixture_objects
                 WHERE object_kind='environment' AND object_id=?1",
                [environment_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(fixture_id) = fixture_id else {
            return Ok(None);
        };
        let environment = connection.query_row(
            "SELECT id,revision,configuration_json FROM environments WHERE id=?1",
            [environment_id],
            |row| {
                Ok(EnvironmentRecord {
                    id: row.get(0)?,
                    revision: row.get(1)?,
                    configuration_json: row.get(2)?,
                })
            },
        )?;
        let mut channel_statement = connection.prepare(
            "SELECT c.product,c.name,r.version
                 FROM development_fixture_objects owned
                 JOIN channels c ON c.id=owned.object_id
                 JOIN releases r ON r.id=c.release_id
                 WHERE owned.fixture_id=?1 AND owned.object_kind='channel'
                 ORDER BY owned.object_order DESC, c.id",
        )?;
        let channels = channel_statement
            .query_map([&fixture_id], |row| {
                Ok(crate::development_fixtures::FixtureChannelProjection {
                    product: row.get(0)?,
                    channel: row.get(1)?,
                    head: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let latest_plan = connection
            .query_row(
                "SELECT p.id,p.environment_id,p.format_version,p.content_digest,p.plan_json,p.status,p.status_detail
                 FROM development_fixture_objects owned
                 JOIN plans p ON p.id=owned.object_id
                 WHERE owned.fixture_id=?1 AND owned.object_kind='plan' AND p.environment_id=?2
                 ORDER BY owned.object_order DESC, p.id DESC
                 LIMIT 1",
                params![fixture_id, environment_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(id, environment_id, format_version, content_digest, plan_json, status, detail)| {
                    Ok::<PlanRecord, StoreError>(PlanRecord {
                        id,
                        environment_id,
                        format_version,
                        content_digest,
                        plan_json,
                        status: PlanStatus::parse(&status)?,
                        status_detail: detail,
                    })
                },
            )
            .transpose()?;
        crate::development_fixtures::parse_environment_projection(
            environment,
            channels,
            latest_plan,
        )
        .map(Some)
    }
}

use super::*;
use super::{Inner, pg};
use postgres::Transaction;

fn postgres_fixture_matches(
    tx: &mut Transaction<'_>,
    fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
) -> Result<bool> {
    for release in &fixture.releases {
        let row = tx
            .query_opt(
                "SELECT product,version,content_digest,descriptor_json FROM releases WHERE id=$1",
                &[&release.id],
            )
            .map_err(pg)?;
        let Some(row) = row else {
            return Ok(false);
        };
        if (
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2),
            row.get::<_, String>(3),
        ) != (
            release.product.clone(),
            release.version.clone(),
            release.content_digest.clone(),
            release.descriptor_json.clone(),
        ) {
            return Ok(false);
        }
    }
    for channel in &fixture.channels {
        let row = tx
            .query_opt(
                "SELECT product,name,release_id,revision FROM channels WHERE id=$1",
                &[&channel.id],
            )
            .map_err(pg)?;
        let Some(row) = row else {
            return Ok(false);
        };
        if (
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2),
            row.get::<_, i64>(3) as u64,
        ) != (
            channel.product.clone(),
            channel.name.clone(),
            channel.release_id.clone(),
            channel.revision,
        ) {
            return Ok(false);
        }
    }
    for environment in &fixture.environments {
        let row = tx
            .query_opt(
                "SELECT revision,configuration_json FROM environments WHERE id=$1",
                &[&environment.id],
            )
            .map_err(pg)?;
        let Some(row) = row else {
            return Ok(false);
        };
        if (row.get::<_, i64>(0) as u64, row.get::<_, String>(1))
            != (environment.revision, environment.configuration_json.clone())
        {
            return Ok(false);
        }
    }
    for plan in &fixture.plans {
        let row = tx
            .query_opt(
                "SELECT environment_id,format_version,content_digest,plan_json,status,status_detail
                 FROM plans WHERE id=$1",
                &[&plan.id],
            )
            .map_err(pg)?;
        let Some(row) = row else {
            return Ok(false);
        };
        if (
            row.get::<_, String>(0),
            row.get::<_, i32>(1) as u32,
            row.get::<_, String>(2),
            row.get::<_, String>(3),
            row.get::<_, String>(4),
            row.get::<_, String>(5),
        ) != (
            plan.environment_id.clone(),
            plan.format_version,
            plan.content_digest.clone(),
            plan.plan_json.clone(),
            "blocked".into(),
            plan.status_detail.clone(),
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

impl Inner {
    pub fn import_development_fixture(
        &self,
        schema: &str,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        self.with_schema(schema, |tx| {
            let lock_key = format!("{schema}:{}", fixture.map.fixture_id);
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .map_err(pg)?;
            let row = tx
                .query_one(
                    "SELECT COUNT(*), MIN(fixture_digest)
                     FROM development_fixture_objects WHERE fixture_id=$1",
                    &[&fixture.map.fixture_id],
                )
                .map_err(pg)?;
            let existing: i64 = row.get(0);
            let persisted_digest: Option<String> = row.get(1);
            let expected = fixture.releases.len()
                + fixture.channels.len()
                + fixture.environments.len()
                + fixture.plans.len();
            if existing != 0 {
                if existing as usize != expected
                    || persisted_digest.as_deref() != Some(&fixture.map.fixture_digest)
                    || !postgres_fixture_matches(tx, fixture)?
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
                     VALUES($1,$2,$3,$4,$5)",
                    &[
                        &release.id,
                        &release.product,
                        &release.version,
                        &release.content_digest,
                        &release.descriptor_json,
                    ],
                )
                .map_err(pg)?;
            }
            for channel in &fixture.channels {
                tx.execute(
                    "INSERT INTO channels(id,product,name,release_id,revision)
                     VALUES($1,$2,$3,$4,$5)",
                    &[
                        &channel.id,
                        &channel.product,
                        &channel.name,
                        &channel.release_id,
                        &(channel.revision as i64),
                    ],
                )
                .map_err(pg)?;
            }
            for environment in &fixture.environments {
                tx.execute(
                    "INSERT INTO environments(id,revision,configuration_json)
                     VALUES($1,$2,$3)",
                    &[
                        &environment.id,
                        &(environment.revision as i64),
                        &environment.configuration_json,
                    ],
                )
                .map_err(pg)?;
            }
            for plan in &fixture.plans {
                tx.execute(
                    "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
                     VALUES($1,$2,$3,$4,$5,'blocked',$6)",
                    &[
                        &plan.id,
                        &plan.environment_id,
                        &(plan.format_version as i32),
                        &plan.content_digest,
                        &plan.plan_json,
                        &plan.status_detail,
                    ],
                )
                .map_err(pg)?;
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
                         VALUES($1,$2,$3,$4,$5)",
                        &[
                            &fixture.map.fixture_id,
                            &fixture.map.fixture_digest,
                            &kind,
                            &id,
                            &object_order,
                        ],
                    )
                    .map_err(pg)?;
                }
            }
            tx.execute(
                "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
                 VALUES($1,$2,$3,'development_fixture.imported',$4,'imported')",
                &[
                    &format!("development_fixture.imported:{request_id}"),
                    &crate::now_millis(),
                    &actor,
                    &fixture.map.fixture_digest,
                ],
            )
            .map_err(pg)?;
            Ok(fixture.map.clone())
        })
    }
}

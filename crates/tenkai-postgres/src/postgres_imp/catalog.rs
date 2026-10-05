use super::*;
use super::{Inner, pg};

impl Inner {
    pub fn get_environment(&self, schema: &str, id: &str) -> Result<Option<EnvironmentRecord>> {
        let id = id.to_owned();
        self.with_schema(schema, move |tx| {
            let row = tx
                .query_opt(
                    "SELECT id, revision, configuration_json FROM environments WHERE id = $1",
                    &[&id],
                )
                .map_err(pg)?;
            Ok(row.map(|row| EnvironmentRecord {
                id: row.get(0),
                revision: row.get::<_, i64>(1) as u64,
                configuration_json: row.get(2),
            }))
        })
    }

    pub fn list_environment_ids(&self, schema: &str) -> Result<Vec<String>> {
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query("SELECT id FROM environments ORDER BY id ASC", &[])
                .map_err(pg)?;
            Ok(rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    /// Non-retired environment ids in stable order, served by `environments_active`.
    pub fn list_active_environment_ids(&self, schema: &str) -> Result<Vec<String>> {
        self.with_schema(schema, move |tx| {
            let rows = tx
                .query(
                    "SELECT id FROM environments WHERE retired_at IS NULL ORDER BY id ASC",
                    &[],
                )
                .map_err(pg)?;
            Ok(rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    pub fn put_environment(
        &self,
        schema: &str,
        environment: &EnvironmentRecord,
    ) -> Result<EnvironmentRecord> {
        let environment = environment.clone();
        self.with_schema(schema, move |tx| {
            lock_lease(tx, &environment.id)?;
            if tx
                .query_one(
                    "SELECT EXISTS(
                        SELECT 1 FROM development_fixture_objects
                        WHERE object_kind='environment' AND object_id=$1
                     )",
                    &[&environment.id],
                )
                .map_err(pg)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::InvalidData {
                    kind: "development_fixture",
                    detail: "fixture environments are immutable".into(),
                });
            }
            let existing = tx
                .query_opt(
                    "SELECT revision,configuration_json FROM environments WHERE id = $1",
                    &[&environment.id],
                )
                .map_err(pg)?;
            if existing.as_ref().is_some_and(|row| {
                tenkai::environment::retirement_from_configuration_json(&row.get::<_, String>(1))
                    .is_some()
            }) {
                return Err(StoreError::InvalidData {
                    kind: "environment",
                    detail: format!(
                        "environment {} is retired; registering it again requires a new environment name",
                        environment.id
                    ),
                });
            }
            if tenkai::environment::retirement_from_configuration_json(
                &environment.configuration_json,
            )
            .is_some()
            {
                let active_claim: bool = tx
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM runtime_claims
                         WHERE environment_id=$1 AND expires_at>$2 AND completion_json IS NULL)",
                        &[&environment.id, &tenkai::now_millis()],
                    )
                    .map_err(pg)?
                    .get(0);
                let active_lease: bool = tx
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM leases
                         WHERE environment_id=$1 AND expires_at>$2)",
                        &[&environment.id, &tenkai::now_millis()],
                    )
                    .map_err(pg)?
                    .get(0);
                if active_claim || active_lease {
                    return Err(StoreError::InvalidData {
                        kind: "environment",
                        detail: format!("environment {} has active delivery work", environment.id),
                    });
                }
            }
            let revision: Option<i64> = existing.map(|row| row.get(0));
            let next = match revision {
                Some(revision) if revision as u64 == environment.revision => revision as u64 + 1,
                Some(revision) => {
                    return Err(StoreError::RevisionConflict {
                        kind: "environment",
                        id: environment.id.clone(),
                        expected: environment.revision,
                        actual: revision as u64,
                    });
                }
                None if environment.revision == 0 => 1,
                None => {
                    return Err(StoreError::RevisionConflict {
                        kind: "environment",
                        id: environment.id.clone(),
                        expected: environment.revision,
                        actual: 0,
                    });
                }
            };
            let next_i = next as i64;
            tx.execute(
                "INSERT INTO environments(id,revision,configuration_json,retired_at)
                 VALUES($1,$2,$3,$4)
                 ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,
                   configuration_json=EXCLUDED.configuration_json,
                   retired_at=EXCLUDED.retired_at",
                &[
                    &environment.id,
                    &next_i,
                    &environment.configuration_json,
                    &tenkai::environment::retirement_from_configuration_json(
                        &environment.configuration_json,
                    )
                    .map(|retirement| retirement.retired_at),
                ],
            )
            .map_err(pg)?;
            Ok(EnvironmentRecord {
                revision: next,
                ..environment.clone()
            })
        })
    }

    pub fn publish_release(&self, schema: &str, release: &ReleaseRecord) -> Result<()> {
        let release = release.clone();
        self.with_schema(schema, move |tx| {
            tx.execute(
                "INSERT INTO releases(id,product,version,content_digest,descriptor_json)
                 VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT DO NOTHING",
                &[
                    &release.id,
                    &release.product,
                    &release.version,
                    &release.content_digest,
                    &release.descriptor_json,
                ],
            )
            .map_err(pg)?;
            let existing = tx
                .query_one(
                    "SELECT product, version, content_digest, descriptor_json
                     FROM releases WHERE id = $1",
                    &[&release.id],
                )
                .map_err(pg)?;
            let product: String = existing.get(0);
            let version: String = existing.get(1);
            let digest: String = existing.get(2);
            let descriptor: String = existing.get(3);
            if product != release.product
                || version != release.version
                || digest != release.content_digest
                || descriptor != release.descriptor_json
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "release",
                    id: release.id.clone(),
                });
            }
            Ok(())
        })
    }

    pub fn get_release(&self, schema: &str, id: &str) -> Result<Option<ReleaseRecord>> {
        let id = id.to_owned();
        self.with_schema(schema, move |tx| {
            let row = tx
                .query_opt(
                    "SELECT id,product,version,content_digest,descriptor_json FROM releases WHERE id=$1",
                    &[&id],
                )
                .map_err(pg)?;
            Ok(row.map(|row| ReleaseRecord {
                id: row.get(0),
                product: row.get(1),
                version: row.get(2),
                content_digest: row.get(3),
                descriptor_json: row.get(4),
            }))
        })
    }
}

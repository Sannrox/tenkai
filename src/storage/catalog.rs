use super::*;

impl SqliteStore {
    pub(super) fn publish_release_sqlite(&self, release: &ReleaseRecord) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT product, version, content_digest, descriptor_json FROM releases WHERE id=?1",
                [&release.id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    release.product.clone(),
                    release.version.clone(),
                    release.content_digest.clone(),
                    release.descriptor_json.clone(),
                )
            {
                return Err(StoreError::ImmutableConflict {
                    kind: "release",
                    id: release.id.clone(),
                });
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO releases(id,product,version,content_digest,descriptor_json) VALUES(?1,?2,?3,?4,?5)",
            params![release.id, release.product, release.version, release.content_digest, release.descriptor_json],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn promote_channel_sqlite(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE (object_kind='release' AND object_id=?1)
                   OR (object_kind='channel' AND object_id=?2)
             )",
            params![channel.release_id, channel.id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture releases and channels cannot be promoted".into(),
            });
        }
        let release_product: String = tx
            .query_row(
                "SELECT product FROM releases WHERE id=?1",
                [&channel.release_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound {
                kind: "release",
                id: channel.release_id.clone(),
            })?;
        if release_product != channel.product {
            return Err(StoreError::InvalidData {
                kind: "channel",
                detail: format!(
                    "release {} belongs to product {release_product}, not {}",
                    channel.release_id, channel.product
                ),
            });
        }
        let existing: Option<(String, String, u64)> = tx
            .query_row(
                "SELECT product,name,revision FROM channels WHERE id=?1",
                [&channel.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let next = match existing {
            Some((product, name, revision)) => {
                if product != channel.product || name != channel.name {
                    return Err(StoreError::ImmutableConflict {
                        kind: "channel",
                        id: channel.id.clone(),
                    });
                }
                if revision != channel.revision {
                    return Err(StoreError::RevisionConflict {
                        kind: "channel",
                        id: channel.id.clone(),
                        expected: channel.revision,
                        actual: revision,
                    });
                }
                revision + 1
            }
            None if channel.revision == 0 => 1,
            None => {
                return Err(StoreError::RevisionConflict {
                    kind: "channel",
                    id: channel.id.clone(),
                    expected: channel.revision,
                    actual: 0,
                });
            }
        };
        tx.execute(
            "INSERT INTO channels(id,product,name,release_id,revision) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(id) DO UPDATE SET release_id=excluded.release_id, revision=excluded.revision",
            params![channel.id, channel.product, channel.name, channel.release_id, next],
        )?;
        tx.commit()?;
        Ok(ChannelRecord {
            revision: next,
            ..channel.clone()
        })
    }

    pub(super) fn put_environment_sqlite(
        &self,
        environment: &EnvironmentRecord,
    ) -> Result<EnvironmentRecord> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM development_fixture_objects
                WHERE object_kind='environment' AND object_id=?1
             )",
            [&environment.id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::InvalidData {
                kind: "development_fixture",
                detail: "fixture environments are immutable".into(),
            });
        }
        let existing: Option<(u64, String)> = tx
            .query_row(
                "SELECT revision,configuration_json FROM environments WHERE id=?1",
                [&environment.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if existing.as_ref().is_some_and(|(_, configuration)| {
            crate::environment::retirement_from_configuration_json(configuration).is_some()
        }) {
            return Err(StoreError::InvalidData {
                kind: "environment",
                detail: format!(
                    "environment {} is retired; registering it again requires a new environment name",
                    environment.id
                ),
            });
        }
        if crate::environment::retirement_from_configuration_json(&environment.configuration_json)
            .is_some()
        {
            let now = crate::now_millis();
            let active_claim: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM runtime_claims
                 WHERE environment_id=?1 AND expires_at>?2 AND completion_json IS NULL)",
                params![environment.id, now],
                |row| row.get(0),
            )?;
            let active_apply: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM leases WHERE environment_id=?1 AND expires_at>?2)",
                params![environment.id, now],
                |row| row.get(0),
            )?;
            if active_claim || active_apply {
                return Err(StoreError::InvalidData {
                    kind: "environment",
                    detail: format!("environment {} has active delivery work", environment.id),
                });
            }
        }
        let revision = existing.map(|(revision, _)| revision);
        let next = match revision {
            Some(revision) if revision == environment.revision => revision + 1,
            Some(revision) => {
                return Err(StoreError::RevisionConflict {
                    kind: "environment",
                    id: environment.id.clone(),
                    expected: environment.revision,
                    actual: revision,
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
        tx.execute(
            "INSERT INTO environments(id,revision,configuration_json,retired_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
               configuration_json=excluded.configuration_json, retired_at=excluded.retired_at",
            params![
                environment.id,
                next,
                environment.configuration_json,
                crate::environment::retirement_from_configuration_json(
                    &environment.configuration_json
                )
                .map(|retirement| retirement.retired_at)
            ],
        )?;
        tx.commit()?;
        Ok(EnvironmentRecord {
            revision: next,
            ..environment.clone()
        })
    }
}

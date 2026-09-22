use super::*;

impl SqliteStore {
    pub fn list_kind(&self, kind: &str) -> AnyResult<Vec<Object>> {
        match kind {
            KIND_PLAN => self.list_plans(),
            KIND_ENVIRONMENT => self.list_environments(),
            KIND_RELEASE => self.list_releases(),
            KIND_CHANNEL => self.list_channels(),
            _ => {
                let connection = self.connection()?;
                let mut statement = connection
                    .prepare("SELECT payload FROM catalog_objects WHERE kind=?1 ORDER BY id")?;
                let payloads = statement
                    .query_map([kind], |row| row.get::<_, Vec<u8>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                decode_many(payloads, "object")
            }
        }
    }

    pub fn list_kind_ids(&self, kind: &str) -> AnyResult<Vec<String>> {
        Ok(self
            .list_kind(kind)?
            .into_iter()
            .map(|object| object.id)
            .collect())
    }

    pub(super) fn list_plans(&self) -> AnyResult<Vec<Object>> {
        let rows = {
            let connection = self.connection()?;
            let mut statement = connection.prepare(
                "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail FROM plans ORDER BY id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.into_iter()
            .map(
                |(
                    id,
                    environment_id,
                    format_version,
                    content_digest,
                    plan_json,
                    status,
                    status_detail,
                )| {
                    if let Some(stored) = self.get_catalog_object(&id)? {
                        return Ok(stored);
                    }
                    plan_record_to_object(&PlanRecord {
                        id,
                        environment_id,
                        format_version,
                        content_digest,
                        plan_json,
                        status: PlanStatus::parse(&status).map_err(anyhow::Error::from)?,
                        status_detail,
                    })
                },
            )
            .collect()
    }

    pub(super) fn list_environments(&self) -> AnyResult<Vec<Object>> {
        let ids = self.list_environment_ids().map_err(anyhow::Error::from)?;
        ids.into_iter()
            .filter_map(|id| self.get_environment(&id).ok().flatten())
            .map(|record| environment_record_to_object(&record))
            .collect()
    }

    pub(super) fn list_releases(&self) -> AnyResult<Vec<Object>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id,product,version,content_digest,descriptor_json FROM releases ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(ReleaseRecord {
                    id: row.get(0)?,
                    product: row.get(1)?,
                    version: row.get(2)?,
                    content_digest: row.get(3)?,
                    descriptor_json: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|record| release_record_to_object(&record))
            .collect()
    }

    pub(super) fn list_channels(&self) -> AnyResult<Vec<Object>> {
        let rows = {
            let connection = self.connection()?;
            let mut statement = connection
                .prepare("SELECT id,product,name,release_id,revision FROM channels ORDER BY id")?;
            statement
                .query_map([], |row| {
                    Ok(ChannelRecord {
                        id: row.get(0)?,
                        product: row.get(1)?,
                        name: row.get(2)?,
                        release_id: row.get(3)?,
                        revision: row.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut objects = rows
            .into_iter()
            .map(|record| self.channel_to_object(&record))
            .collect::<AnyResult<Vec<_>>>()?;
        let mut seen = objects
            .iter()
            .map(|object| object.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for object in self.list_catalog_kind(KIND_CHANNEL)? {
            if seen.insert(object.id.clone()) {
                objects.push(object);
            }
        }
        objects.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(objects)
    }

    pub(super) fn list_catalog_kind(&self, kind: &str) -> AnyResult<Vec<Object>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT payload FROM catalog_objects WHERE kind=?1 ORDER BY id")?;
        let payloads = statement
            .query_map([kind], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object")
    }

    pub(super) fn channel_record(&self, id: &str) -> Result<Option<ChannelRecord>> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT id,product,name,release_id,revision FROM channels WHERE id=?1",
                [id],
                |row| {
                    Ok(ChannelRecord {
                        id: row.get(0)?,
                        product: row.get(1)?,
                        name: row.get(2)?,
                        release_id: row.get(3)?,
                        revision: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub(super) fn channel_to_object(&self, record: &ChannelRecord) -> AnyResult<Object> {
        if let Some(stored) = self.get_catalog_object(&record.id)? {
            return Ok(stored);
        }
        Ok(Object {
            id: record.id.clone(),
            kind: KIND_CHANNEL.into(),
            name: record.name.clone(),
            namespace: NS.into(),
            properties: BTreeMap::from([
                ("product".into(), record.product.clone()),
                ("name".into(), record.name.clone()),
                ("current_release".into(), record.release_id.clone()),
            ])
            .into_iter()
            .collect(),
            ..Object::default()
        })
    }

    pub(super) fn get_catalog_object(&self, id: &str) -> AnyResult<Option<Object>> {
        let connection = self.connection()?;
        decode_optional(
            connection
                .query_row(
                    "SELECT payload FROM catalog_objects WHERE id=?1",
                    [id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            "object",
        )
    }
}

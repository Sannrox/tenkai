use super::*;

impl SqliteStore {
    pub fn create_link(
        &self,
        link: Link,
        fail_if_exists: bool,
    ) -> std::result::Result<(), tonic::Status> {
        let connection = self
            .connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        let changed = connection
            .execute(
                "INSERT OR IGNORE INTO catalog_links(id,from_id,to_id,relation,payload)
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    link.id,
                    link.from_id,
                    link.to_id,
                    link.relation,
                    link.encode_to_vec()
                ],
            )
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        if fail_if_exists && changed == 0 {
            return Err(tonic::Status::already_exists(format!(
                "link {} already exists",
                link.id
            )));
        }
        Ok(())
    }

    pub fn unlink(&self, id: &str) -> AnyResult<()> {
        self.connection()?
            .execute("DELETE FROM catalog_links WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn links(&self, object_id: &str, relation: &str, direction: &str) -> AnyResult<Vec<Link>> {
        let sql = match direction {
            "out" => {
                "SELECT payload FROM catalog_links WHERE from_id=?1 AND relation=?2 ORDER BY id"
            }
            "in" => "SELECT payload FROM catalog_links WHERE to_id=?1 AND relation=?2 ORDER BY id",
            other => bail!("unsupported embedded link direction {other:?}"),
        };
        let connection = self.connection()?;
        let mut statement = connection.prepare(sql)?;
        let payloads = statement
            .query_map(params![object_id, relation], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "link")
    }

    pub fn linked(
        &self,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> AnyResult<Vec<Object>> {
        let links = self.links(object_id, relation, direction)?;
        links
            .into_iter()
            .map(|link| {
                let id = if direction == "in" {
                    link.from_id
                } else {
                    link.to_id
                };
                self.get_object(&id)?
                    .with_context(|| format!("linked object {id} is missing"))
            })
            .collect()
    }

    pub fn find_by_property(&self, kind: &str, key: &str, value: &str) -> AnyResult<Vec<Object>> {
        self.find_by_property_matching(PropertyIndexQuery::new(kind, key, value))
    }

    pub fn find_by_property_matching(
        &self,
        query: PropertyIndexQuery<'_>,
    ) -> AnyResult<Vec<Object>> {
        let mut objects = self.find_catalog(query)?;
        if query.kind == KIND_PLAN {
            objects.retain(|object| {
                OperationalStore::get_plan(self, &object.id)
                    .ok()
                    .flatten()
                    .is_some()
            });
        }
        Ok(objects)
    }

    pub(super) fn find_catalog(&self, query: PropertyIndexQuery<'_>) -> AnyResult<Vec<Object>> {
        anyhow::ensure!(
            !query.kind.trim().is_empty() && !query.key.trim().is_empty(),
            "find_by_property requires non-empty kind and key"
        );
        let mut sql = String::from(
            "SELECT o.payload FROM catalog_objects o
             INNER JOIN catalog_object_properties p
               ON p.object_id = o.id AND p.kind = ? AND p.key = ? AND p.value = ?",
        );
        let mut bind = vec![
            Value::Text(query.kind.to_string()),
            Value::Text(query.key.to_string()),
            Value::Text(query.value.to_string()),
        ];
        if let Some(filter_key) = query.matching_key {
            if query.matching_values.is_empty() {
                return Ok(Vec::new());
            }
            sql.push_str(
                " INNER JOIN catalog_object_properties f
                    ON f.object_id = o.id AND f.kind = ? AND f.key = ? AND f.value IN (",
            );
            bind.push(Value::Text(query.kind.to_string()));
            bind.push(Value::Text(filter_key.to_string()));
            for (index, filter_value) in query.matching_values.iter().enumerate() {
                if index > 0 {
                    sql.push(',');
                }
                sql.push('?');
                bind.push(Value::Text((*filter_value).to_string()));
            }
            sql.push(')');
        }
        if let (Some(equals_key), Some(equals_value)) = (query.equals_key, query.equals_value) {
            sql.push_str(
                " INNER JOIN catalog_object_properties e
                    ON e.object_id = o.id AND e.kind = ? AND e.key = ? AND e.value = ?",
            );
            bind.push(Value::Text(query.kind.to_string()));
            bind.push(Value::Text(equals_key.to_string()));
            bind.push(Value::Text(equals_value.to_string()));
        }
        if let Some(order_key) = query.order_key {
            sql.push_str(
                " LEFT JOIN catalog_object_properties ord
                    ON ord.object_id = o.id AND ord.kind = ? AND ord.key = ?",
            );
            bind.push(Value::Text(query.kind.to_string()));
            bind.push(Value::Text(order_key.to_string()));
            let direction = if query.descending { "DESC" } else { "ASC" };
            sql.push_str(" ORDER BY CAST(ord.value AS INTEGER) ");
            sql.push_str(direction);
            sql.push_str(", o.id ");
            sql.push_str(direction);
        } else {
            sql.push_str(" ORDER BY o.id");
        }
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            bind.push(Value::Integer(i64::from(limit)));
        }
        if let Some(offset) = query.offset {
            anyhow::ensure!(
                query.limit.is_some(),
                "find_by_property offset requires a limit"
            );
            sql.push_str(" OFFSET ?");
            bind.push(Value::Integer(i64::from(offset)));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(&sql)?;
        let payloads = statement
            .query_map(params_from_iter(bind), |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object")
    }
}

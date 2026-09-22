use super::*;

impl SqliteStore {
    pub fn get_object(&self, id: &str) -> AnyResult<Option<Object>> {
        if let Some(record) = OperationalStore::get_plan(self, id).map_err(anyhow::Error::from)? {
            if let Some(stored) = self.get_catalog_object(id)? {
                return Ok(Some(stored));
            }
            return plan_record_to_object(&record).map(Some);
        }
        if let Some(record) = self.get_environment(id).map_err(anyhow::Error::from)? {
            return Ok(Some(environment_record_to_object(&record)?));
        }
        if let Some(record) =
            OperationalStore::get_release(self, id).map_err(anyhow::Error::from)?
        {
            return Ok(Some(release_record_to_object(&record)?));
        }
        if let Some(record) = self.channel_record(id).map_err(anyhow::Error::from)? {
            return Ok(Some(self.channel_to_object(&record)?));
        }
        let connection = self.connection()?;
        let catalog = decode_optional(
            connection
                .query_row(
                    "SELECT payload FROM catalog_objects WHERE id=?1",
                    [id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            "object",
        )?;
        Ok(catalog.filter(|object| !is_strict_authority(&object.kind)))
    }

    pub fn get(&self, id: &str) -> AnyResult<Option<Object>> {
        self.get_object(id)
    }

    pub fn create(&self, object: Object) -> std::result::Result<Object, tonic::Status> {
        self.create_object(object)
    }

    pub fn put(&self, object: Object) -> AnyResult<Object> {
        self.put_object(object)
    }

    pub fn delete(&self, id: &str) -> AnyResult<()> {
        self.delete_object(id)
    }

    pub fn create_object(&self, object: Object) -> std::result::Result<Object, tonic::Status> {
        if self
            .get_object(&object.id)
            .map_err(|error| tonic::Status::internal(error.to_string()))?
            .is_some()
        {
            return Err(tonic::Status::already_exists(format!(
                "object {} already exists",
                object.id
            )));
        }
        self.put_object(object.clone())
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        Ok(object)
    }

    pub fn put_object(&self, object: Object) -> AnyResult<Object> {
        let previous = self.get_object(&object.id)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        upsert_object_in(&tx, &object, &self.principal).map_err(anyhow::Error::from)?;
        if let Some(previous) = previous {
            record_changes(&tx, &previous, &object, &self.principal)?;
        }
        tx.commit()?;
        Ok(object)
    }

    pub fn delete_object(&self, id: &str) -> AnyResult<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute("DELETE FROM plans WHERE id=?1", [id])?;
        tx.execute("DELETE FROM environments WHERE id=?1", [id])?;
        tx.execute("DELETE FROM releases WHERE id=?1", [id])?;
        tx.execute("DELETE FROM channels WHERE id=?1", [id])?;
        tx.execute(
            "DELETE FROM catalog_links WHERE from_id=?1 OR to_id=?1",
            [id],
        )?;
        tx.execute(
            "DELETE FROM catalog_object_properties WHERE object_id=?1",
            [id],
        )?;
        tx.execute("DELETE FROM catalog_objects WHERE id=?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn put_objects_inner(
        &self,
        objects: &[Object],
        events: &[ProviderEventRecord],
        lease: Option<(&str, &str, &str)>,
    ) -> AnyResult<()> {
        anyhow::ensure!(!objects.is_empty(), "embedded object update is empty");
        let unique = objects
            .iter()
            .map(|object| object.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            unique.len() == objects.len(),
            "embedded object update contains duplicate identities"
        );
        let previous = objects
            .iter()
            .map(|object| self.get_object(&object.id))
            .collect::<AnyResult<Vec<_>>>()?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if let Some((namespace, key, token)) = lease {
            require_active_lease_in(&tx, namespace, key, token)?;
        }
        for (object, previous) in objects.iter().zip(previous) {
            anyhow::ensure!(
                previous.is_some(),
                "embedded object {} does not exist",
                object.id
            );
            upsert_object_in(&tx, object, &self.principal).map_err(anyhow::Error::from)?;
            if let Some(previous) = previous {
                record_changes(&tx, &previous, object, &self.principal)?;
            }
        }
        for event in events {
            enqueue_provider_event_in(&tx, event).map_err(anyhow::Error::from)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn put_with_provider_events(
        &self,
        object: Object,
        events: &[ProviderEventRecord],
    ) -> AnyResult<Object> {
        self.put_objects_inner(std::slice::from_ref(&object), events, None)?;
        Ok(object)
    }

    pub fn put_objects_with_provider_events(
        &self,
        objects: &[Object],
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        self.put_objects_inner(objects, events, None)
    }

    pub fn guarded_put_with_provider_events(
        &self,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
    ) -> AnyResult<Object> {
        self.put_objects_inner(
            std::slice::from_ref(&object),
            events,
            Some((namespace, key, fencing_token)),
        )?;
        Ok(object)
    }

    pub fn guarded_put_objects_with_provider_events(
        &self,
        objects: &[Object],
        namespace: &str,
        key: &str,
        fencing_token: &str,
        events: &[ProviderEventRecord],
    ) -> AnyResult<()> {
        self.put_objects_inner(objects, events, Some((namespace, key, fencing_token)))
    }

    pub fn guarded_put(
        &self,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> AnyResult<Object> {
        let previous = self.get_object(&object.id)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        require_active_lease_in(&tx, namespace, key, fencing_token)?;
        if create && previous.is_some() {
            return Err(anyhow::Error::new(tonic::Status::already_exists(format!(
                "object {} already exists",
                object.id
            ))));
        }
        if !create {
            anyhow::ensure!(
                previous.is_some(),
                "embedded object {} does not exist",
                object.id
            );
        }
        upsert_object_in(&tx, &object, &self.principal).map_err(anyhow::Error::from)?;
        if let Some(previous) = previous {
            record_changes(&tx, &previous, &object, &self.principal)?;
        }
        tx.commit()?;
        Ok(object)
    }
}

use super::*;
use tenkai::feedback_observation::FeedbackObservation;

/// The object `id` as [`SqliteStore::get_object`] returns it, read through
/// `connection`. Writers pass their open transaction, so the previous object
/// they diff against or check for is the one they replace.
pub(super) fn object_in(connection: &Connection, id: &str) -> AnyResult<Option<Object>> {
    if let Some(record) = crate::sqlite_operational_store::plan_record_in(connection, id)? {
        if let Some(stored) = super::listings::catalog_object_in(connection, id)? {
            return Ok(Some(stored));
        }
        return plan_record_to_object(&record).map(Some);
    }
    if let Some(record) = crate::sqlite_store::environment_record_in(connection, id)? {
        return Ok(Some(environment_record_to_object(&record)?));
    }
    if let Some(record) = crate::sqlite_operational_store::release_record_in(connection, id)? {
        return Ok(Some(release_record_to_object(&record)?));
    }
    if let Some(record) = super::listings::channel_record_in(connection, id)? {
        return Ok(Some(super::listings::channel_object_in(
            connection, &record,
        )?));
    }
    let catalog = super::listings::catalog_object_in(connection, id)?;
    Ok(catalog.filter(|object| !is_strict_authority(&object.kind)))
}

impl SqliteStore {
    pub fn get_object(&self, id: &str) -> AnyResult<Option<Object>> {
        object_in(&*self.connection()?, id)
    }

    pub fn get(&self, id: &str) -> AnyResult<Option<Object>> {
        self.get_object(id)
    }

    pub fn create(&self, object: Object) -> Result<Object> {
        self.create_object(object)
    }

    pub fn put(&self, object: Object) -> AnyResult<Object> {
        self.put_object(object)
    }

    pub fn delete(&self, id: &str) -> AnyResult<()> {
        self.delete_object(id)
    }

    /// Delete `id` only when property `key` still equals `value`.
    ///
    /// The check and the row deletes share one immediate transaction so a
    /// concurrent put cannot replace the object between the read and the
    /// delete.
    pub fn delete_if_property(&self, id: &str, key: &str, value: &str) -> AnyResult<bool> {
        self.delete_object_if_property(id, key, value)
    }

    /// Write `object`, copying `key` from the stored row when it is already set.
    pub fn put_keeping_property(&self, object: Object, key: &str) -> AnyResult<Object> {
        self.put_object_keeping_property(object, key)
    }

    pub fn create_object(&self, object: Object) -> Result<Object> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Database(error.to_string()))?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog_objects WHERE id=?1)
                 OR EXISTS(SELECT 1 FROM plans WHERE id=?1)
                 OR EXISTS(SELECT 1 FROM environments WHERE id=?1)
                 OR EXISTS(SELECT 1 FROM releases WHERE id=?1)
                 OR EXISTS(SELECT 1 FROM channels WHERE id=?1)",
                [&object.id],
                |row| row.get(0),
            )
            .map_err(|error| StoreError::Database(error.to_string()))?;
        if exists {
            return Err((StoreError::already_exists("object", object.id)).into());
        }
        upsert_object_in(&tx, &object, &self.principal)?;
        tx.commit()
            .map_err(|error| StoreError::Database(error.to_string()))?;
        Ok(object)
    }

    pub fn put_object(&self, object: Object) -> AnyResult<Object> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let previous = object_in(&tx, &object.id)?;
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
        delete_object_rows(&tx, id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_object_if_property(&self, id: &str, key: &str, value: &str) -> AnyResult<bool> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT value FROM catalog_object_properties WHERE object_id=?1 AND key=?2",
                rusqlite::params![id, key],
                |row| row.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(value) {
            return Ok(false);
        }
        delete_object_rows(&tx, id)?;
        tx.commit()?;
        Ok(true)
    }

    /// Upsert `object` while copying `key` from the stored row in the same
    /// immediate transaction, so a concurrent writer cannot drop that property.
    pub fn put_object_keeping_property(&self, mut object: Object, key: &str) -> AnyResult<Object> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT value FROM catalog_object_properties WHERE object_id=?1 AND key=?2",
                rusqlite::params![&object.id, key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(value) = current.filter(|value| !value.is_empty()) {
            object.properties.insert(key.to_string(), value);
        }
        let previous = decode_optional(
            tx.query_row(
                "SELECT payload FROM catalog_objects WHERE id=?1",
                [&object.id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
            "object",
        )?;
        upsert_object_in(&tx, &object, &self.principal).map_err(anyhow::Error::from)?;
        if let Some(previous) = previous {
            record_changes(&tx, &previous, &object, &self.principal)?;
        }
        tx.commit()?;
        Ok(object)
    }
}

fn delete_object_rows(tx: &rusqlite::Transaction<'_>, id: &str) -> AnyResult<()> {
    record_stored_write(tx, id)?;
    let links: Vec<String> = tx
        .prepare("SELECT id FROM catalog_links WHERE from_id=?1 OR to_id=?1")?
        .query_map([id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for link in links {
        record_link_write(tx, &link)?;
    }
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
    Ok(())
}

impl SqliteStore {
    pub(super) fn put_objects_inner(
        &self,
        objects: &[Object],
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
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
        let mut connection = self.connection()?;
        // Immediate (the store's default): the lease and previous objects are
        // read before the objects are written, so a concurrent writer waits on
        // the busy timeout instead of changing them in between.
        let tx = connection.transaction()?;
        let previous = objects
            .iter()
            .map(|object| object_in(&tx, &object.id))
            .collect::<AnyResult<Vec<_>>>()?;
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
        for observation in observations {
            // Usually a failed statement rolls back alone and the operation
            // still commits (#802). Some errors, such as a full disk, roll
            // back the whole transaction: then the operation is written
            // again without its observations.
            if let Err(error) = insert_feedback_observation_in(&tx, observation) {
                eprintln!(
                    "feedback observation {} was not stored: {error:#}",
                    observation.id
                );
                if tx.is_autocommit() {
                    drop(tx);
                    drop(connection);
                    return self.put_objects_inner(objects, events, &[], lease);
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Feedback observations of `environment`, oldest first. A record this
    /// version cannot read, such as one a newer version wrote with fields it
    /// does not know, is skipped and logged rather than failing the query.
    pub fn feedback_observations(&self, environment: &str) -> AnyResult<Vec<FeedbackObservation>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, body_json FROM feedback_observations
             WHERE environment_id=?1 ORDER BY observed_at, id",
        )?;
        let rows = statement.query_map([environment], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut observations = Vec::new();
        for row in rows {
            let (id, body) = row?;
            match serde_json::from_str(&body) {
                Ok(observation) => observations.push(observation),
                Err(error) => eprintln!("skipping unreadable feedback observation {id}: {error}"),
            }
        }
        Ok(observations)
    }

    /// Write `object` with `events` and `observations` in one transaction.
    pub fn put_with_provider_events(
        &self,
        object: Object,
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<Object> {
        self.put_objects_inner(std::slice::from_ref(&object), events, observations, None)?;
        Ok(object)
    }

    pub fn put_objects_with_provider_events(
        &self,
        objects: &[Object],
        events: &[ProviderEventRecord],
        observations: &[FeedbackObservation],
    ) -> AnyResult<()> {
        self.put_objects_inner(objects, events, observations, None)
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
            &[],
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
        observations: &[FeedbackObservation],
    ) -> AnyResult<()> {
        self.put_objects_inner(
            objects,
            events,
            observations,
            Some((namespace, key, fencing_token)),
        )
    }

    pub fn guarded_put(
        &self,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> AnyResult<Object> {
        let mut connection = self.connection()?;
        // Immediate: the lease and previous object are read before the object
        // is written, so a concurrent writer waits on the busy timeout instead
        // of changing them in between.
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous = object_in(&tx, &object.id)?;
        require_active_lease_in(&tx, namespace, key, fencing_token)?;
        if create && previous.is_some() {
            return Err((StoreError::already_exists("object", object.id.clone())).into());
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

/// Store `observation` unless one with its id exists. An identical replay
/// changes nothing; a conflicting one is refused and logged, and the
/// operation it rides with still commits: a capture never interrupts it.
fn insert_feedback_observation_in(
    tx: &rusqlite::Transaction<'_>,
    observation: &FeedbackObservation,
) -> AnyResult<()> {
    let body = serde_json::to_string(observation)?;
    let inserted = tx.execute(
        "INSERT INTO feedback_observations (id, schema, environment_id, observed_at, body_json)
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO NOTHING",
        rusqlite::params![
            observation.id,
            observation.schema,
            observation.environment,
            observation.observed_at_ms,
            body
        ],
    )?;
    if inserted == 0 {
        let stored: String = tx.query_row(
            "SELECT body_json FROM feedback_observations WHERE id=?1",
            [&observation.id],
            |row| row.get(0),
        )?;
        if stored != body {
            eprintln!(
                "feedback observation {} conflicts with the stored one; kept the stored observation",
                observation.id
            );
        }
    }
    Ok(())
}

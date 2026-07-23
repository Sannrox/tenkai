//! In-process persistence used by the single-user embedded host.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, bail};
use prost::Message;
use rusqlite::{Connection, DatabaseName, OptionalExtension, params};

use crate::pb::sekai::{
    ActionResult, ActionTypeDef, Decision, Lease, Link, Object, ObjectChange, ObjectType,
};

const SCHEMA_VERSION: u32 = 1;

pub struct EmbeddedStore {
    connection: Mutex<Connection>,
    principal: String,
}

impl EmbeddedStore {
    pub fn open(path: impl AsRef<Path>, principal: String) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("creating embedded state directory {}", parent.display())
            })?;
        }
        let mut connection =
            Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            principal,
        })
    }

    /// Create a transactionally consistent SQLite backup while the host is live.
    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<()> {
        let destination = destination.as_ref();
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating backup directory {}", parent.display()))?;
        }
        self.connection()?
            .backup(DatabaseName::Main, destination, None)
            .with_context(|| format!("backing up embedded state to {}", destination.display()))
    }

    /// Restore a verified SQLite backup into a closed embedded database.
    pub fn restore(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> Result<()> {
        let source = source.as_ref();
        let destination = destination.as_ref();
        anyhow::ensure!(
            source.is_file(),
            "backup {} does not exist",
            source.display()
        );
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state directory {}", parent.display()))?;
        }
        let source_connection =
            Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .with_context(|| format!("opening backup {}", source.display()))?;
        source_connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .context("checking backup integrity")
            .and_then(|result| {
                anyhow::ensure!(result == "ok", "backup integrity check failed: {result}");
                Ok(())
            })?;
        source_connection
            .backup(DatabaseName::Main, destination, None)
            .with_context(|| {
                format!(
                    "restoring backup {} to {}",
                    source.display(),
                    destination.display()
                )
            })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            principal: "tenkai".into(),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("embedded store mutex was poisoned"))
    }

    pub fn get(&self, id: &str) -> Result<Option<Object>> {
        let connection = self.connection()?;
        decode_optional(
            connection
                .query_row(
                    "SELECT payload FROM embedded_objects WHERE id=?1",
                    [id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            "object",
        )
    }

    pub fn create(&self, object: Object) -> std::result::Result<Object, tonic::Status> {
        let connection = self
            .connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        let changed = connection
            .execute(
                "INSERT OR IGNORE INTO embedded_objects(id,kind,payload) VALUES(?1,?2,?3)",
                params![object.id, object.kind, object.encode_to_vec()],
            )
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        if changed == 0 {
            return Err(tonic::Status::already_exists(format!(
                "object {} already exists",
                object.id
            )));
        }
        Ok(object)
    }

    pub fn put(&self, object: Object) -> Result<Object> {
        let previous = self.get(&object.id)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            "INSERT INTO embedded_objects(id,kind,payload) VALUES(?1,?2,?3)
             ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,payload=excluded.payload",
            params![object.id, object.kind, object.encode_to_vec()],
        )?;
        if let Some(previous) = previous {
            record_changes(&tx, &previous, &object, &self.principal)?;
        }
        tx.commit()?;
        Ok(object)
    }

    pub fn guarded_put(
        &self,
        object: Object,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        create: bool,
    ) -> Result<Object> {
        self.require_active_lease(namespace, key, fencing_token)?;
        if create {
            return self.create(object).map_err(anyhow::Error::from);
        }
        self.put(object)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            "DELETE FROM embedded_links WHERE from_id=?1 OR to_id=?1",
            [id],
        )?;
        tx.execute("DELETE FROM embedded_objects WHERE id=?1", [id])?;
        tx.commit()?;
        Ok(())
    }

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
                "INSERT OR IGNORE INTO embedded_links(id,from_id,to_id,relation,payload)
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

    pub fn unlink(&self, id: &str) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM embedded_links WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn links(&self, object_id: &str, relation: &str, direction: &str) -> Result<Vec<Link>> {
        let (column, sql) = match direction {
            "out" => (
                "from_id",
                "SELECT payload FROM embedded_links WHERE from_id=?1 AND relation=?2 ORDER BY id",
            ),
            "in" => (
                "to_id",
                "SELECT payload FROM embedded_links WHERE to_id=?1 AND relation=?2 ORDER BY id",
            ),
            other => bail!("unsupported embedded link direction {other:?}"),
        };
        let _ = column;
        let connection = self.connection()?;
        let mut statement = connection.prepare(sql)?;
        let payloads = statement
            .query_map(params![object_id, relation], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "link")
    }

    pub fn linked(&self, object_id: &str, relation: &str, direction: &str) -> Result<Vec<Object>> {
        let links = self.links(object_id, relation, direction)?;
        links
            .into_iter()
            .map(|link| {
                let id = if direction == "in" {
                    link.from_id
                } else {
                    link.to_id
                };
                self.get(&id)?.with_context(|| {
                    format!("embedded link {} references missing object {id}", link.id)
                })
            })
            .collect()
    }

    pub fn find_by_property(&self, kind: &str, key: &str, value: &str) -> Result<Vec<Object>> {
        Ok(self
            .list_kind(kind)?
            .into_iter()
            .filter(|object| {
                object
                    .properties
                    .get(key)
                    .is_some_and(|stored| stored == value)
            })
            .collect())
    }

    pub fn list_kind(&self, kind: &str) -> Result<Vec<Object>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT payload FROM embedded_objects WHERE kind=?1 ORDER BY id")?;
        let payloads = statement
            .query_map([kind], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object")
    }

    pub fn register_schema(&self, schema: ObjectType) -> std::result::Result<(), tonic::Status> {
        let connection = self
            .connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        insert_definition(
            &connection,
            "embedded_schema_types",
            &schema.kind,
            schema.encode_to_vec(),
        )
    }

    pub fn schemas(&self) -> Result<Vec<ObjectType>> {
        let connection = self.connection()?;
        definitions(&connection, "embedded_schema_types", "schema")
    }

    pub fn register_action(&self, action: ActionTypeDef) -> std::result::Result<(), tonic::Status> {
        let connection = self
            .connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        insert_definition(
            &connection,
            "embedded_action_types",
            &action.name,
            action.encode_to_vec(),
        )
    }

    pub fn execute_action(
        &self,
        action_name: &str,
        params: std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> Result<ActionResult> {
        let payload = self
            .connection()?
            .query_row(
                "SELECT payload FROM embedded_action_types WHERE name=?1",
                [action_name],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .with_context(|| {
                format!("embedded action {action_name} is not registered; run `tenkaictl init`")
            })?;
        let action = ActionTypeDef::decode(payload.as_slice())?;
        let target_id = params.get("id").with_context(|| {
            format!("embedded action {action_name} requires target parameter id")
        })?;
        let mut target = self
            .get(target_id)?
            .with_context(|| format!("embedded action target {target_id} does not exist"))?;
        let planned_ops = action
            .ops
            .iter()
            .map(|op| op.op.clone())
            .collect::<Vec<_>>();
        if !dry_run {
            for op in &action.ops {
                match op.op.as_str() {
                    "set_property" => {
                        let value = params.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        target.properties.insert(op.property.clone(), value.clone());
                    }
                    "create_link" => {
                        let to_id = params.get(&op.property).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.property)
                        })?;
                        self.create_link(
                            Link {
                                id: format!("{target_id}--{}--{to_id}", op.relation),
                                from_id: target_id.clone(),
                                to_id: to_id.clone(),
                                relation: op.relation.clone(),
                                created: crate::now_millis(),
                            },
                            false,
                        )
                        .map_err(anyhow::Error::from)?;
                    }
                    "delete_link" => {
                        let link_id = params.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        self.unlink(link_id)?;
                    }
                    other => bail!("unsupported embedded action operation {other:?}"),
                }
            }
            target.updated = crate::now_millis();
            self.put(target)?;
            self.record_decision(action_name, target_id, "allow", &params)?;
        }
        Ok(ActionResult {
            action: action_name.into(),
            message: "allowed by embedded host policy".into(),
            dry_run,
            planned_ops,
            decision: "allow".into(),
            approval_id: String::new(),
        })
    }

    pub fn decisions(&self, actor: &str, action: &str, after: i64) -> Result<Vec<Decision>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT payload FROM embedded_decisions
             WHERE (?1='' OR actor=?1) AND (?2='' OR action=?2) AND timestamp>?3
             ORDER BY timestamp,id",
        )?;
        let payloads = statement
            .query_map(params![actor, action, after], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "decision")
    }

    pub fn changes(&self, object_id: &str) -> Result<Vec<ObjectChange>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT payload FROM embedded_changes WHERE object_id=?1 ORDER BY timestamp,id",
        )?;
        let payloads = statement
            .query_map([object_id], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object change")
    }

    pub fn acquire_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        let now = crate::now_millis();
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current: Option<Lease> = decode_optional(
            tx.query_row(
                "SELECT payload FROM embedded_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
            "lease",
        )?;
        if let Some(current) = &current
            && current.status == "active"
            && current.expires_at_ms > now
        {
            return Err(anyhow::Error::new(tonic::Status::already_exists(format!(
                "embedded lease {namespace}/{key} is held by {}",
                current.owner
            ))));
        }
        let generation = current.map_or(1, |lease| lease.generation.saturating_add(1));
        let lease = Lease {
            namespace: namespace.into(),
            key: key.into(),
            generation,
            fencing_token: uuid::Uuid::new_v4().to_string(),
            owner: owner.into(),
            status: "active".into(),
            acquired_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            released_at_ms: 0,
        };
        tx.execute(
            "INSERT INTO embedded_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)
             ON CONFLICT(namespace,lease_key) DO UPDATE SET payload=excluded.payload",
            params![lease.namespace, lease.key, lease.encode_to_vec()],
        )?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>> {
        let connection = self.connection()?;
        decode_optional(
            connection
                .query_row(
                    "SELECT payload FROM embedded_leases WHERE namespace=?1 AND lease_key=?2",
                    params![namespace, key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            "lease",
        )
    }

    pub fn refresh_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut lease = require_active_lease_in(&tx, namespace, key, fencing_token)?;
        lease.refreshed_at_ms = crate::now_millis();
        lease.expires_at_ms = lease.refreshed_at_ms.saturating_add(ttl_ms);
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn release_lease(&self, namespace: &str, key: &str, fencing_token: &str) -> Result<Lease> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut lease = require_active_lease_in(&tx, namespace, key, fencing_token)?;
        lease.status = "released".into();
        lease.released_at_ms = crate::now_millis();
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn takeover_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> Result<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current: Option<Lease> = decode_optional(
            tx.query_row(
                "SELECT payload FROM embedded_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
            "lease",
        )?;
        let current =
            current.with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
        anyhow::ensure!(
            current.fencing_token == expected_token
                && current.expires_at_ms == expected_expires_at
                && current.expires_at_ms <= crate::now_millis(),
            "embedded lease takeover precondition failed"
        );
        let now = crate::now_millis();
        let lease = Lease {
            namespace: namespace.into(),
            key: key.into(),
            generation: current.generation.saturating_add(1),
            fencing_token: uuid::Uuid::new_v4().to_string(),
            owner: owner.into(),
            status: "active".into(),
            acquired_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            released_at_ms: 0,
        };
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    fn require_active_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<Lease> {
        let connection = self.connection()?;
        require_active_lease_in(&connection, namespace, key, fencing_token)
    }

    fn record_decision(
        &self,
        action: &str,
        target_id: &str,
        outcome: &str,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let timestamp = crate::now_millis();
        let mut evidence = params.clone();
        evidence.insert("decision".into(), outcome.into());
        let decision = Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            actor: self.principal.clone(),
            action: action.into(),
            reason: "execute_action".into(),
            evidence,
            target_id: target_id.into(),
            outcome: outcome.into(),
        };
        self.connection()?.execute(
            "INSERT INTO embedded_decisions(id,timestamp,actor,action,payload)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                decision.id,
                decision.timestamp,
                decision.actor,
                decision.action,
                decision.encode_to_vec()
            ],
        )?;
        Ok(())
    }
}

fn migrate(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS embedded_metadata (
             key TEXT PRIMARY KEY, value TEXT NOT NULL
         );",
    )?;
    let found = connection
        .query_row(
            "SELECT value FROM embedded_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| value.parse::<u32>())
        .transpose()
        .context("embedded schema version is not an integer")?
        .unwrap_or(0);
    anyhow::ensure!(
        found <= SCHEMA_VERSION,
        "embedded database schema version {found} is newer than supported version {SCHEMA_VERSION}"
    );
    if found == 0 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE embedded_objects (
                 id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE INDEX embedded_objects_kind ON embedded_objects(kind,id);
             CREATE TABLE embedded_links (
                 id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
                 relation TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE INDEX embedded_links_from ON embedded_links(from_id,relation,id);
             CREATE INDEX embedded_links_to ON embedded_links(to_id,relation,id);
             CREATE TABLE embedded_schema_types (
                 name TEXT PRIMARY KEY, payload BLOB NOT NULL
             );
             CREATE TABLE embedded_action_types (
                 name TEXT PRIMARY KEY, payload BLOB NOT NULL
             );
             CREATE TABLE embedded_leases (
                 namespace TEXT NOT NULL, lease_key TEXT NOT NULL, payload BLOB NOT NULL,
                 PRIMARY KEY(namespace,lease_key)
             );
             CREATE TABLE embedded_decisions (
                 id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, actor TEXT NOT NULL,
                 action TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE TABLE embedded_changes (
                 id TEXT PRIMARY KEY, object_id TEXT NOT NULL, timestamp INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE INDEX embedded_changes_object ON embedded_changes(object_id,timestamp,id);
             INSERT INTO embedded_metadata(key,value) VALUES('schema_version','1');
             COMMIT;",
        )?;
    }
    Ok(())
}

fn require_active_lease_in(
    connection: &Connection,
    namespace: &str,
    key: &str,
    fencing_token: &str,
) -> Result<Lease> {
    let lease: Option<Lease> = decode_optional(
        connection
            .query_row(
                "SELECT payload FROM embedded_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
        "lease",
    )?;
    let lease =
        lease.with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
    anyhow::ensure!(
        lease.status == "active"
            && lease.expires_at_ms > crate::now_millis()
            && lease.fencing_token == fencing_token,
        "embedded lease {namespace}/{key} is stale"
    );
    Ok(lease)
}

fn save_lease_in(connection: &Connection, lease: &Lease) -> Result<()> {
    connection.execute(
        "INSERT INTO embedded_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)
         ON CONFLICT(namespace,lease_key) DO UPDATE SET payload=excluded.payload",
        params![lease.namespace, lease.key, lease.encode_to_vec()],
    )?;
    Ok(())
}

fn insert_definition(
    connection: &Connection,
    table: &str,
    name: &str,
    payload: Vec<u8>,
) -> std::result::Result<(), tonic::Status> {
    let sql = format!("INSERT OR IGNORE INTO {table}(name,payload) VALUES(?1,?2)");
    let changed = connection
        .execute(&sql, params![name, payload])
        .map_err(|error| tonic::Status::internal(error.to_string()))?;
    if changed == 0 {
        return Err(tonic::Status::already_exists(format!(
            "definition {name} already exists"
        )));
    }
    Ok(())
}

fn definitions<T: Message + Default>(
    connection: &Connection,
    table: &str,
    kind: &str,
) -> Result<Vec<T>> {
    let mut statement =
        connection.prepare(&format!("SELECT payload FROM {table} ORDER BY name"))?;
    let payloads = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    decode_many(payloads, kind)
}

fn decode_optional<T: Message + Default>(
    payload: Option<Vec<u8>>,
    kind: &str,
) -> Result<Option<T>> {
    payload
        .map(|bytes| {
            T::decode(bytes.as_slice()).with_context(|| format!("decoding embedded {kind}"))
        })
        .transpose()
}

fn decode_many<T: Message + Default>(payloads: Vec<Vec<u8>>, kind: &str) -> Result<Vec<T>> {
    payloads
        .into_iter()
        .map(|bytes| {
            T::decode(bytes.as_slice()).with_context(|| format!("decoding embedded {kind}"))
        })
        .collect()
}

fn record_changes(
    tx: &rusqlite::Transaction<'_>,
    previous: &Object,
    next: &Object,
    principal: &str,
) -> Result<()> {
    let timestamp = crate::now_millis();
    for key in previous
        .properties
        .keys()
        .chain(next.properties.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let old = previous.properties.get(key).cloned().unwrap_or_default();
        let new = next.properties.get(key).cloned().unwrap_or_default();
        if old == new {
            continue;
        }
        let change = ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: next.id.clone(),
            field: format!("properties.{key}"),
            old_value: old,
            new_value: new,
            changed_by: principal.into(),
            timestamp,
        };
        tx.execute(
            "INSERT INTO embedded_changes(id,object_id,timestamp,payload) VALUES(?1,?2,?3,?4)",
            params![
                change.id,
                change.object_id,
                change.timestamp,
                change.encode_to_vec()
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_objects_links_actions_and_leases() {
        let store = EmbeddedStore::open_in_memory().unwrap();
        let object = Object {
            id: "tenkai:env:local".into(),
            kind: "tenkai.environment".into(),
            name: "local".into(),
            ..Default::default()
        };
        store.create(object.clone()).unwrap();
        assert_eq!(store.get(&object.id).unwrap(), Some(object));

        let lease = store
            .acquire_lease("tenkai.environment", "local", "test", 60_000)
            .unwrap();
        assert_eq!(lease.generation, 1);
        assert_eq!(
            store
                .get_lease("tenkai.environment", "local")
                .unwrap()
                .unwrap()
                .fencing_token,
            lease.fencing_token
        );
    }

    #[test]
    fn online_backup_restores_complete_embedded_state() {
        let root = std::env::temp_dir().join(format!("tenkai-embedded-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("tenkai.db");
        let backup = root.join("backup.db");
        let restored = root.join("restored.db");
        let store = EmbeddedStore::open(&database, "test".into()).unwrap();
        store
            .create(Object {
                id: "tenkai:env:local".into(),
                kind: "tenkai.environment".into(),
                name: "local".into(),
                ..Default::default()
            })
            .unwrap();
        store.backup(&backup).unwrap();
        drop(store);

        EmbeddedStore::restore(&backup, &restored).unwrap();
        let reopened = EmbeddedStore::open(&restored, "test".into()).unwrap();
        assert!(reopened.get("tenkai:env:local").unwrap().is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
}

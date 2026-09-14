//! Object/link/lease codec over typed schema 10 records plus a catalog sidecar.
//!
//! Plan, environment, release, channel, and apply-lease identities live in
//! typed tables. Leftover `embedded_*` graph rows are imported once and dropped
//! so they cannot authorize apply.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result as AnyResult, bail};
use prost::Message;
use rusqlite::{
    Connection, DatabaseName, OptionalExtension, Transaction, params, params_from_iter,
    types::Value,
};

use crate::embedded::PropertyIndexQuery;
use crate::ontology::{
    KIND_CHANNEL, KIND_ENVIRONMENT, KIND_PLAN, KIND_RELEASE, NS, env_id, release_id,
};
use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{Decision, Lease, Link, Object, ObjectChange, ObjectType};
use crate::plan::Plan;
use crate::storage::{
    ChannelRecord, EnvironmentRecord, OperationalStore, PlanRecord, PlanStatus,
    ProviderEventRecord, ReleaseRecord, Result, SqliteStore, StoreError, enqueue_provider_event_in,
};

const STRICT_AUTHORITY_KINDS: &[&str] = &[KIND_PLAN, KIND_ENVIRONMENT, KIND_RELEASE];

type DecisionRow = (String, i64, String, String, Vec<u8>);
type ChangeRow = (String, String, i64, Vec<u8>);

pub(super) fn ensure_typed_schema_tables(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS releases (
             id TEXT PRIMARY KEY, product TEXT NOT NULL, version TEXT NOT NULL,
             content_digest TEXT NOT NULL, descriptor_json TEXT NOT NULL,
             UNIQUE(product, version)
         );
         CREATE TABLE IF NOT EXISTS channels (
             id TEXT PRIMARY KEY, product TEXT NOT NULL, name TEXT NOT NULL,
             release_id TEXT NOT NULL REFERENCES releases(id), revision INTEGER NOT NULL,
             UNIQUE(product, name)
         );
         CREATE TABLE IF NOT EXISTS environments (
             id TEXT PRIMARY KEY, revision INTEGER NOT NULL, configuration_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS plans (
             id TEXT PRIMARY KEY,
             environment_id TEXT NOT NULL REFERENCES environments(id),
             format_version INTEGER NOT NULL, content_digest TEXT NOT NULL,
             plan_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS leases (
             environment_id TEXT PRIMARY KEY REFERENCES environments(id),
             owner TEXT NOT NULL, generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS receipts (
             id TEXT PRIMARY KEY,
             environment_id TEXT NOT NULL REFERENCES environments(id),
             plan_id TEXT NOT NULL REFERENCES plans(id), step_id TEXT NOT NULL,
             lease_generation INTEGER NOT NULL, payload_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS rollbacks (
             id TEXT PRIMARY KEY,
             environment_id TEXT NOT NULL REFERENCES environments(id),
             plan_id TEXT NOT NULL REFERENCES plans(id), lease_generation INTEGER NOT NULL,
             intent_digest TEXT NOT NULL,
             checkpoint_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS rollbacks_recovery ON rollbacks(status, environment_id);
         CREATE TABLE IF NOT EXISTS provider_events (
             id TEXT NOT NULL, provider_kind TEXT NOT NULL,
             binding_digest TEXT NOT NULL, payload_json TEXT NOT NULL,
             attempts INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL,
             delivered_at INTEGER, last_error TEXT NOT NULL,
             claim_token TEXT, claim_until INTEGER,
             environment_id TEXT NOT NULL DEFAULT '',
             observed_at INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY(provider_kind,id)
         );
         CREATE INDEX IF NOT EXISTS provider_events_delivery
             ON provider_events(delivered_at, next_attempt_at, id);
         CREATE TABLE IF NOT EXISTS audit_events (
             id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL,
             principal TEXT NOT NULL, operation TEXT NOT NULL,
             resource TEXT NOT NULL, outcome TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(occurred_at, id);
         CREATE TABLE IF NOT EXISTS runtime_claims (
             plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             owner TEXT NOT NULL, generation INTEGER NOT NULL,
             expires_at INTEGER NOT NULL, completion_json TEXT
         );
         CREATE INDEX IF NOT EXISTS runtime_claims_environment
             ON runtime_claims(environment_id, expires_at);
         CREATE TABLE IF NOT EXISTS offline_imports (
             bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS offline_step_receipts (
             receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
             plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
             attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
             succeeded INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS development_fixture_objects (
             fixture_id TEXT NOT NULL, fixture_digest TEXT NOT NULL,
             object_kind TEXT NOT NULL, object_id TEXT NOT NULL,
             object_order INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY(object_kind, object_id)
         );
         CREATE INDEX IF NOT EXISTS development_fixture_objects_fixture
             ON development_fixture_objects(fixture_id, object_kind);",
    )?;
    Ok(())
}

pub(super) fn ensure_catalog(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS catalog_objects (
             id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS catalog_objects_kind ON catalog_objects(kind,id);
         CREATE TABLE IF NOT EXISTS catalog_object_properties (
             object_id TEXT NOT NULL,
             kind TEXT NOT NULL,
             key TEXT NOT NULL,
             value TEXT NOT NULL,
             PRIMARY KEY (object_id, key),
             FOREIGN KEY (object_id) REFERENCES catalog_objects(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS catalog_object_properties_lookup
             ON catalog_object_properties(kind, key, value, object_id);
         CREATE TABLE IF NOT EXISTS catalog_links (
             id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
             relation TEXT NOT NULL, payload BLOB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS catalog_links_from ON catalog_links(from_id,relation,id);
         CREATE INDEX IF NOT EXISTS catalog_links_to ON catalog_links(to_id,relation,id);
         CREATE TABLE IF NOT EXISTS catalog_schema_types (
             name TEXT PRIMARY KEY, payload BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS catalog_action_types (
             name TEXT PRIMARY KEY, payload BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS catalog_leases (
             namespace TEXT NOT NULL, lease_key TEXT NOT NULL, payload BLOB NOT NULL,
             PRIMARY KEY(namespace,lease_key)
         );
         CREATE TABLE IF NOT EXISTS catalog_decisions (
             id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, actor TEXT NOT NULL,
             action TEXT NOT NULL, payload BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS catalog_changes (
             id TEXT PRIMARY KEY, object_id TEXT NOT NULL, timestamp INTEGER NOT NULL,
             payload BLOB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS catalog_changes_object
             ON catalog_changes(object_id,timestamp,id);",
    )?;
    Ok(())
}

pub(super) fn import_legacy_graph(connection: &mut Connection) -> Result<()> {
    let has_graph: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_objects')",
        [],
        |row| row.get(0),
    )?;
    if !has_graph {
        return Ok(());
    }
    let objects = load_embedded_objects(connection)?;
    let links = load_embedded_links(connection)?;
    let schemas = load_blob_rows(connection, "SELECT name,payload FROM embedded_schema_types")?;
    let actions = load_blob_rows(connection, "SELECT name,payload FROM embedded_action_types")?;
    let leases = load_lease_rows(connection)?;
    let decisions = load_named_blobs(
        connection,
        "SELECT id,timestamp,actor,action,payload FROM embedded_decisions",
    )?;
    let changes = load_change_rows(connection)?;
    {
        let tx = connection.transaction()?;
        import_objects_in(&tx, &objects)?;
        for link in &links {
            tx.execute(
                "INSERT OR IGNORE INTO catalog_links(id,from_id,to_id,relation,payload)
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    link.id,
                    link.from_id,
                    link.to_id,
                    link.relation,
                    link.encode_to_vec()
                ],
            )?;
        }
        for (name, payload) in &schemas {
            tx.execute(
                "INSERT OR REPLACE INTO catalog_schema_types(name,payload) VALUES(?1,?2)",
                params![name, payload],
            )?;
        }
        for (name, payload) in &actions {
            tx.execute(
                "INSERT OR REPLACE INTO catalog_action_types(name,payload) VALUES(?1,?2)",
                params![name, payload],
            )?;
        }
        for (namespace, key, payload) in &leases {
            tx.execute(
                "INSERT OR REPLACE INTO catalog_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)",
                params![namespace, key, payload],
            )?;
        }
        for (id, timestamp, actor, action, payload) in &decisions {
            tx.execute(
                "INSERT OR IGNORE INTO catalog_decisions(id,timestamp,actor,action,payload)
                 VALUES(?1,?2,?3,?4,?5)",
                params![id, timestamp, actor, action, payload],
            )?;
        }
        for (id, object_id, timestamp, payload) in &changes {
            tx.execute(
                "INSERT OR IGNORE INTO catalog_changes(id,object_id,timestamp,payload)
                 VALUES(?1,?2,?3,?4)",
                params![id, object_id, timestamp, payload],
            )?;
        }
        tx.execute_batch(
            "DROP TABLE IF EXISTS embedded_object_properties;
             DROP TABLE IF EXISTS embedded_links;
             DROP TABLE IF EXISTS embedded_schema_types;
             DROP TABLE IF EXISTS embedded_action_types;
             DROP TABLE IF EXISTS embedded_leases;
             DROP TABLE IF EXISTS embedded_decisions;
             DROP TABLE IF EXISTS embedded_changes;
             DROP TABLE IF EXISTS embedded_objects;
             DROP TABLE IF EXISTS embedded_metadata;",
        )?;
        tx.commit()?;
    }
    Ok(())
}

fn load_embedded_objects(connection: &Connection) -> Result<Vec<Object>> {
    let mut statement =
        connection.prepare("SELECT payload FROM embedded_objects ORDER BY kind,id")?;
    let payloads = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    decode_many(payloads, "object").map_err(|error| StoreError::InvalidData {
        kind: "legacy_object",
        detail: error.to_string(),
    })
}

fn load_embedded_links(connection: &Connection) -> Result<Vec<Link>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_links')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare("SELECT payload FROM embedded_links")?;
    let payloads = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    decode_many(payloads, "link").map_err(|error| StoreError::InvalidData {
        kind: "legacy_link",
        detail: error.to_string(),
    })
}

fn load_blob_rows(connection: &Connection, sql: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let table = sql
        .split_whitespace()
        .rev()
        .find(|part| part.starts_with("embedded_"))
        .unwrap_or("");
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn load_lease_rows(connection: &Connection) -> Result<Vec<(String, String, Vec<u8>)>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_leases')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement =
        connection.prepare("SELECT namespace,lease_key,payload FROM embedded_leases")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn load_named_blobs(connection: &Connection, sql: &str) -> Result<Vec<DecisionRow>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_decisions')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn load_change_rows(connection: &Connection) -> Result<Vec<ChangeRow>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_changes')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut statement =
        connection.prepare("SELECT id,object_id,timestamp,payload FROM embedded_changes")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn import_objects_in(tx: &Transaction<'_>, objects: &[Object]) -> Result<()> {
    let mut ordered = objects.to_vec();
    ordered.sort_by_key(|object| authority_rank(&object.kind));
    for object in &ordered {
        upsert_object_in(tx, object, "tenkai")?;
    }
    Ok(())
}

fn authority_rank(kind: &str) -> u8 {
    match kind {
        KIND_ENVIRONMENT => 0,
        KIND_RELEASE => 1,
        KIND_CHANNEL => 2,
        KIND_PLAN => 3,
        _ => 4,
    }
}

fn upsert_object_in(tx: &Transaction<'_>, object: &Object, _principal: &str) -> Result<()> {
    match object.kind.as_str() {
        KIND_ENVIRONMENT => upsert_environment_in(tx, object)?,
        KIND_RELEASE => upsert_release_in(tx, object)?,
        KIND_CHANNEL => upsert_channel_in(tx, object)?,
        KIND_PLAN => upsert_plan_in(tx, object)?,
        _ => upsert_catalog_in(tx, object)?,
    }
    Ok(())
}

fn upsert_environment_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let revision: Option<u64> = tx
        .query_row(
            "SELECT revision FROM environments WHERE id=?1",
            [&object.id],
            |row| row.get(0),
        )
        .optional()?;
    let next = revision.map(|value| value + 1).unwrap_or(1);
    tx.execute(
        "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,?2,?3)
         ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, configuration_json=excluded.configuration_json",
        params![object.id, next, encode_object(object)],
    )?;
    upsert_catalog_in(tx, object)?;
    Ok(())
}

fn upsert_release_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let version = object
        .properties
        .get("version")
        .cloned()
        .unwrap_or_default();
    let digest = object
        .properties
        .get("digest")
        .cloned()
        .or_else(|| object.properties.get("content_digest").cloned())
        .unwrap_or_default();
    let id = if object.id.is_empty() {
        release_id(&product, &version)
    } else {
        object.id.clone()
    };
    let existing: Option<String> = tx
        .query_row(
            "SELECT content_digest FROM releases WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing != digest {
            return Err(StoreError::ImmutableConflict {
                kind: "release",
                id,
            });
        }
        tx.execute(
            "UPDATE releases SET descriptor_json=?2 WHERE id=?1",
            params![id, encode_object(object)],
        )?;
        upsert_catalog_in(tx, object)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO releases(id,product,version,content_digest,descriptor_json)
         VALUES(?1,?2,?3,?4,?5)",
        params![id, product, version, digest, encode_object(object)],
    )?;
    upsert_catalog_in(tx, object)?;
    Ok(())
}

fn upsert_channel_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let name = object
        .properties
        .get("name")
        .cloned()
        .or_else(|| object.properties.get("channel").cloned())
        .unwrap_or_else(|| object.name.clone());
    let release = object
        .properties
        .get("current_release")
        .cloned()
        .unwrap_or_default();
    let revision: Option<u64> = tx
        .query_row(
            "SELECT revision FROM channels WHERE id=?1",
            [&object.id],
            |row| row.get(0),
        )
        .optional()?;
    let next = revision.map(|value| value + 1).unwrap_or(1);
    let release_exists = !release.is_empty()
        && tx
            .query_row("SELECT 1 FROM releases WHERE id=?1", [&release], |_| Ok(()))
            .optional()?
            .is_some();
    if !release_exists {
        upsert_catalog_in(tx, object)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO channels(id,product,name,release_id,revision) VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(id) DO UPDATE SET release_id=excluded.release_id, revision=excluded.revision",
        params![object.id, product, name, release, next],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO catalog_objects(id,kind,payload) VALUES(?1,?2,?3)",
        params![object.id, object.kind, object.encode_to_vec()],
    )?;
    replace_catalog_properties(tx, object)?;
    Ok(())
}

fn upsert_plan_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    let Some(raw) = object.properties.get("plan") else {
        upsert_catalog_in(tx, object)?;
        return Ok(());
    };
    let Ok(plan) = serde_json::from_str::<Plan>(raw) else {
        upsert_catalog_in(tx, object)?;
        return Ok(());
    };
    let environment_id = env_id(&plan.environment);
    if tx
        .query_row(
            "SELECT 1 FROM environments WHERE id=?1",
            [&environment_id],
            |_| Ok(()),
        )
        .optional()?
        .is_none()
    {
        tx.execute(
            "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,1,?2)",
            params![
                environment_id,
                encode_object(&Object {
                    id: environment_id.clone(),
                    kind: KIND_ENVIRONMENT.into(),
                    name: plan.environment.clone(),
                    namespace: NS.into(),
                    properties: BTreeMap::new().into_iter().collect(),
                    created: plan.created_at,
                    updated: plan.created_at,
                    ..Object::default()
                })
            ],
        )?;
    }
    let digest = object
        .properties
        .get("content_digest")
        .cloned()
        .unwrap_or_default();
    let status = object
        .properties
        .get("status")
        .and_then(|value| PlanStatus::parse(value).ok())
        .unwrap_or(PlanStatus::Computed);
    tx.execute(
        "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
         VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(id) DO UPDATE SET
            status=excluded.status,
            status_detail=excluded.status_detail,
            plan_json=excluded.plan_json",
        params![
            object.id,
            environment_id,
            plan.format_version,
            digest,
            object.properties.get("plan").cloned().unwrap_or_default(),
            status.as_str(),
            plan.status_detail
        ],
    )?;
    upsert_catalog_in(tx, object)?;
    Ok(())
}

fn upsert_catalog_in(tx: &Transaction<'_>, object: &Object) -> Result<()> {
    tx.execute(
        "INSERT INTO catalog_objects(id,kind,payload) VALUES(?1,?2,?3)
         ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,payload=excluded.payload",
        params![object.id, object.kind, object.encode_to_vec()],
    )?;
    replace_catalog_properties(tx, object)?;
    Ok(())
}

fn replace_catalog_properties(tx: &Transaction<'_>, object: &Object) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM catalog_object_properties WHERE object_id=?1",
        [&object.id],
    )?;
    for (key, value) in &object.properties {
        tx.execute(
            "INSERT INTO catalog_object_properties(object_id,kind,key,value) VALUES(?1,?2,?3,?4)",
            params![object.id, object.kind, key, value],
        )?;
    }
    Ok(())
}

fn encode_object(object: &Object) -> String {
    serde_json::to_string(&StoredObject::from_proto(object)).expect("object json")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredObject {
    id: String,
    kind: String,
    name: String,
    namespace: String,
    properties: BTreeMap<String, String>,
    created: i64,
    updated: i64,
}

impl StoredObject {
    fn from_proto(object: &Object) -> Self {
        Self {
            id: object.id.clone(),
            kind: object.kind.clone(),
            name: object.name.clone(),
            namespace: object.namespace.clone(),
            properties: object
                .properties
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            created: object.created,
            updated: object.updated,
        }
    }

    fn into_proto(self) -> Object {
        Object {
            id: self.id,
            kind: self.kind,
            name: self.name,
            namespace: self.namespace,
            properties: self.properties.into_iter().collect(),
            created: self.created,
            updated: self.updated,
            ..Object::default()
        }
    }
}

fn plan_record_to_object(record: &PlanRecord) -> AnyResult<Object> {
    let plan: Plan = serde_json::from_str(&record.plan_json)?;
    plan.to_object()
}

fn environment_record_to_object(record: &EnvironmentRecord) -> AnyResult<Object> {
    if let Ok(stored) = serde_json::from_str::<StoredObject>(&record.configuration_json)
        && (stored.kind == KIND_ENVIRONMENT || stored.id == record.id)
    {
        return Ok(stored.into_proto());
    }
    let name = record
        .id
        .strip_prefix("tenkai:env:")
        .unwrap_or(&record.id)
        .to_string();
    Ok(Object {
        id: record.id.clone(),
        kind: KIND_ENVIRONMENT.into(),
        name,
        namespace: NS.into(),
        properties: std::collections::HashMap::from([(
            "configuration".into(),
            record.configuration_json.clone(),
        )]),
        ..Object::default()
    })
}

fn release_record_to_object(record: &ReleaseRecord) -> AnyResult<Object> {
    if let Ok(stored) = serde_json::from_str::<StoredObject>(&record.descriptor_json)
        && (stored.kind == KIND_RELEASE || stored.id == record.id)
    {
        return Ok(stored.into_proto());
    }
    Ok(Object {
        id: record.id.clone(),
        kind: KIND_RELEASE.into(),
        name: format!("{}@{}", record.product, record.version),
        namespace: NS.into(),
        properties: std::collections::HashMap::from([
            ("product".into(), record.product.clone()),
            ("version".into(), record.version.clone()),
            ("digest".into(), record.content_digest.clone()),
            ("content_digest".into(), record.content_digest.clone()),
        ]),
        ..Object::default()
    })
}

fn decode_optional(payload: Option<Vec<u8>>, kind: &str) -> AnyResult<Option<Object>> {
    payload
        .map(|bytes| Object::decode(bytes.as_slice()).with_context(|| format!("decoding {kind}")))
        .transpose()
}

fn decode_many<T: Message + Default>(payloads: Vec<Vec<u8>>, kind: &str) -> AnyResult<Vec<T>> {
    payloads
        .into_iter()
        .map(|bytes| T::decode(bytes.as_slice()).with_context(|| format!("decoding {kind}")))
        .collect()
}

fn is_strict_authority(kind: &str) -> bool {
    STRICT_AUTHORITY_KINDS.contains(&kind)
}

impl SqliteStore {
    pub fn backup(&self, destination: impl AsRef<Path>) -> AnyResult<()> {
        let destination = destination.as_ref();
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating backup directory {}", parent.display()))?;
        }
        self.connection()?
            .backup(DatabaseName::Main, destination, None)
            .with_context(|| format!("backing up operational state to {}", destination.display()))
    }

    pub fn restore(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> AnyResult<()> {
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
        let check: String = source_connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .context("checking backup integrity")?;
        anyhow::ensure!(check == "ok", "backup integrity check failed: {check}");
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

    pub fn leftover_graph_tables(&self) -> AnyResult<bool> {
        let connection = self.connection()?;
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_objects')",
            [],
            |row| row.get(0),
        )?;
        Ok(present)
    }

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

    fn put_objects_inner(
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

    fn find_catalog(&self, query: PropertyIndexQuery<'_>) -> AnyResult<Vec<Object>> {
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

    fn list_plans(&self) -> AnyResult<Vec<Object>> {
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

    fn list_environments(&self) -> AnyResult<Vec<Object>> {
        let ids = self.list_environment_ids().map_err(anyhow::Error::from)?;
        ids.into_iter()
            .filter_map(|id| self.get_environment(&id).ok().flatten())
            .map(|record| environment_record_to_object(&record))
            .collect()
    }

    fn list_releases(&self) -> AnyResult<Vec<Object>> {
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

    fn list_channels(&self) -> AnyResult<Vec<Object>> {
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

    fn list_catalog_kind(&self, kind: &str) -> AnyResult<Vec<Object>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT payload FROM catalog_objects WHERE kind=?1 ORDER BY id")?;
        let payloads = statement
            .query_map([kind], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object")
    }

    fn channel_record(&self, id: &str) -> Result<Option<ChannelRecord>> {
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

    fn channel_to_object(&self, record: &ChannelRecord) -> AnyResult<Object> {
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

    fn get_catalog_object(&self, id: &str) -> AnyResult<Option<Object>> {
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

    pub fn register_schema(&self, schema: ObjectType) -> std::result::Result<(), tonic::Status> {
        self.connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?
            .execute(
                "INSERT OR REPLACE INTO catalog_schema_types(name,payload) VALUES(?1,?2)",
                params![schema.kind, schema.encode_to_vec()],
            )
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        Ok(())
    }

    pub fn schemas(&self) -> AnyResult<Vec<ObjectType>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT payload FROM catalog_schema_types")?;
        let payloads = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "schema")
    }

    pub fn register_action(&self, action: ActionTypeDef) -> std::result::Result<(), tonic::Status> {
        self.connection()
            .map_err(|error| tonic::Status::internal(error.to_string()))?
            .execute(
                "INSERT OR REPLACE INTO catalog_action_types(name,payload) VALUES(?1,?2)",
                params![action.name, action.encode_to_vec()],
            )
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        Ok(())
    }

    pub fn execute_action(
        &self,
        action_name: &str,
        params_map: std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> AnyResult<ActionResult> {
        let payload = self
            .connection()?
            .query_row(
                "SELECT payload FROM catalog_action_types WHERE name=?1",
                [action_name],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .with_context(|| {
                format!("embedded action {action_name} is not registered; run `tenkaictl init`")
            })?;
        let action = ActionTypeDef::decode(payload.as_slice())?;
        let target_id = params_map.get("id").with_context(|| {
            format!("embedded action {action_name} requires target parameter id")
        })?;
        let mut target = self
            .get_object(target_id)?
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
                        let value = params_map.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        target.properties.insert(op.property.clone(), value.clone());
                    }
                    "create_link" => {
                        let to_id = params_map.get(&op.property).with_context(|| {
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
                        let link_id = params_map.get(&op.value_from).with_context(|| {
                            format!("embedded action {action_name} requires {}", op.value_from)
                        })?;
                        self.unlink(link_id)?;
                    }
                    other => bail!("unsupported embedded action operation {other:?}"),
                }
            }
            target.updated = crate::now_millis();
            self.put_object(target)?;
            self.record_decision(action_name, target_id, "allow", &params_map)?;
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

    pub fn decisions(&self, actor: &str, action: &str, after: i64) -> AnyResult<Vec<Decision>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT payload FROM catalog_decisions
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

    pub fn changes(&self, object_id: &str) -> AnyResult<Vec<ObjectChange>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT payload FROM catalog_changes WHERE object_id=?1 ORDER BY timestamp,id",
        )?;
        let payloads = statement
            .query_map([object_id], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode_many(payloads, "object change")
    }

    pub fn acquire_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let now = crate::now_millis();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current: Option<Lease> = decode_lease(
            tx.query_row(
                "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
        )?;
        if let Some(held) = current
            .as_ref()
            .filter(|lease| lease.status == "active" && lease.expires_at_ms > now)
        {
            return Err(anyhow::Error::new(tonic::Status::already_exists(format!(
                "embedded lease {namespace}/{key} is held by {}",
                held.owner
            ))));
        }
        let generation = current
            .as_ref()
            .map(|lease| lease.generation.saturating_add(1))
            .unwrap_or(1);
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
            site_id: String::new(),
        };
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn get_namespaced_lease(&self, namespace: &str, key: &str) -> AnyResult<Option<Lease>> {
        let connection = self.connection()?;
        decode_lease(
            connection
                .query_row(
                    "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
                    params![namespace, key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
        )
    }

    pub fn refresh_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut lease = require_active_lease_in(&tx, namespace, key, fencing_token)?;
        let now = crate::now_millis();
        lease.refreshed_at_ms = now;
        lease.expires_at_ms = now.saturating_add(ttl_ms);
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn release_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> AnyResult<Lease> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut lease = require_active_lease_in(&tx, namespace, key, fencing_token)?;
        lease.status = "released".into();
        lease.released_at_ms = crate::now_millis();
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    pub fn takeover_namespaced_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at: i64,
        ttl_ms: i64,
    ) -> AnyResult<Lease> {
        anyhow::ensure!(ttl_ms > 0, "embedded lease TTL must be positive");
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let current = decode_lease(
            tx.query_row(
                "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?,
        )?
        .with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
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
            site_id: String::new(),
        };
        save_lease_in(&tx, &lease)?;
        tx.commit()?;
        Ok(lease)
    }

    fn record_decision(
        &self,
        action: &str,
        target_id: &str,
        outcome: &str,
        params_map: &std::collections::HashMap<String, String>,
    ) -> AnyResult<()> {
        let timestamp = crate::now_millis();
        let mut evidence = params_map.clone();
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
            "INSERT INTO catalog_decisions(id,timestamp,actor,action,payload)
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

fn record_changes(
    tx: &Transaction<'_>,
    previous: &Object,
    next: &Object,
    principal: &str,
) -> AnyResult<()> {
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
        let change = crate::pb::sekai::ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: next.id.clone(),
            field: format!("properties.{key}"),
            old_value: old,
            new_value: new,
            changed_by: principal.into(),
            timestamp,
        };
        tx.execute(
            "INSERT INTO catalog_changes(id,object_id,timestamp,payload) VALUES(?1,?2,?3,?4)",
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

fn require_active_lease_in(
    tx: &Transaction<'_>,
    namespace: &str,
    key: &str,
    fencing_token: &str,
) -> AnyResult<Lease> {
    let lease = decode_lease(
        tx.query_row(
            "SELECT payload FROM catalog_leases WHERE namespace=?1 AND lease_key=?2",
            params![namespace, key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?,
    )?
    .with_context(|| format!("embedded lease {namespace}/{key} does not exist"))?;
    anyhow::ensure!(
        lease.status == "active"
            && lease.fencing_token == fencing_token
            && lease.expires_at_ms > crate::now_millis(),
        "embedded lease {namespace}/{key} is not the active fenced holder"
    );
    Ok(lease)
}

fn save_lease_in(tx: &Transaction<'_>, lease: &Lease) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO catalog_leases(namespace,lease_key,payload) VALUES(?1,?2,?3)
         ON CONFLICT(namespace,lease_key) DO UPDATE SET payload=excluded.payload",
        params![lease.namespace, lease.key, lease.encode_to_vec()],
    )?;
    Ok(())
}

fn decode_lease(payload: Option<Vec<u8>>) -> AnyResult<Option<Lease>> {
    payload
        .map(|bytes| Lease::decode(bytes.as_slice()).context("decoding lease"))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::EmbeddedStore;
    use crate::ontology::plan_id;
    use crate::plan::{Action, DesiredStateInput, PLAN_FORMAT_VERSION, PlanState, Step};
    use crate::storage::OperationalStore;

    #[test]
    fn leftover_graph_cannot_authorize_apply_after_migration() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-382-graph-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&path);
        let graph = EmbeddedStore::open(&path, "tenkai".into()).unwrap();
        let env = Object {
            id: env_id("lab"),
            kind: KIND_ENVIRONMENT.into(),
            name: "lab".into(),
            namespace: NS.into(),
            properties: [("description".into(), "fixture".into())]
                .into_iter()
                .collect(),
            created: 1,
            updated: 1,
            ..Object::default()
        };
        graph.put(env).unwrap();
        let plan = sample_plan("lab", 10);
        let object = plan.to_object().unwrap();
        graph.put(object).unwrap();
        drop(graph);

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 11);
        assert!(!store.leftover_graph_tables().unwrap());
        let record = store.get_plan(&plan.id).unwrap().expect("typed plan");
        assert_eq!(record.content_digest, plan.executable_digest().unwrap());
        assert_eq!(record.status, PlanStatus::Computed);
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO catalog_objects(id,kind,payload) VALUES(?1,?2,?3)",
                rusqlite::params![
                    "tenkai:plan:residual",
                    KIND_PLAN,
                    Object {
                        id: "tenkai:plan:residual".into(),
                        kind: KIND_PLAN.into(),
                        name: "residual".into(),
                        namespace: NS.into(),
                        properties: [("plan".into(), "{}".into())].into_iter().collect(),
                        ..Object::default()
                    }
                    .encode_to_vec()
                ],
            )
            .unwrap();
        assert!(
            store.get("tenkai:plan:residual").unwrap().is_none(),
            "catalog leftover must not grant plan authority"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn embedded_backup_restore_stays_on_typed_schema() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-382-backup-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::create_dir_all(&root);
        let database = root.join("tenkai.db");
        let backup = root.join("backup.db");
        let restored = root.join("restored.db");
        let store = SqliteStore::open_embedded(&database, "tenkai").unwrap();
        let env = Object {
            id: env_id("lab"),
            kind: KIND_ENVIRONMENT.into(),
            name: "lab".into(),
            namespace: NS.into(),
            properties: [("description".into(), "fixture".into())]
                .into_iter()
                .collect(),
            created: 1,
            updated: 1,
            ..Object::default()
        };
        store.put(env).unwrap();
        let plan = sample_plan("lab", 11);
        store.put(plan.to_object().unwrap()).unwrap();
        store.backup(&backup).unwrap();
        drop(store);
        SqliteStore::restore(&backup, &restored).unwrap();
        let restored_store = SqliteStore::open_embedded(&restored, "tenkai").unwrap();
        assert_eq!(restored_store.schema_version().unwrap(), 11);
        assert!(!restored_store.leftover_graph_tables().unwrap());
        assert!(restored_store.get_plan(&plan.id).unwrap().is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn postgres_url_fails_closed_on_embedded_open() {
        let previous = std::env::var_os("TENKAI_POSTGRES_URL");
        unsafe {
            std::env::set_var("TENKAI_POSTGRES_URL", "postgres://hub.example/tenkai");
        }
        let error = match SqliteStore::open_embedded(
            std::env::temp_dir().join("tenkai-382-pg-refuse.db"),
            "tenkai",
        ) {
            Ok(_) => panic!("embedded open must refuse TENKAI_POSTGRES_URL"),
            Err(error) => error,
        };
        match previous {
            Some(value) => unsafe { std::env::set_var("TENKAI_POSTGRES_URL", value) },
            None => unsafe { std::env::remove_var("TENKAI_POSTGRES_URL") },
        }
        assert!(error.to_string().contains("TENKAI_POSTGRES_URL"), "{error}");
    }

    fn sample_plan(env: &str, created_at: i64) -> Plan {
        let content_id = String::from("digest-a");
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: plan_id(env, created_at, &content_id),
            content_id,
            environment: env.into(),
            created_at,
            inputs: vec![DesiredStateInput {
                product: "api".into(),
                channel: "stable".into(),
                channel_id: "tenkai:channel:api/stable".into(),
                desired_version: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                deployed_version: None,
            }],
            steps: vec![Step {
                id: format!("{}:step:0", plan_id(env, created_at, "digest-a")),
                order: 0,
                product: "api".into(),
                action: Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                workdir: ".".into(),
                restore: None,
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
        }
    }
}

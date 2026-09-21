use super::*;

pub(in crate::storage) fn ensure_typed_schema_tables(connection: &Connection) -> Result<()> {
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

pub(in crate::storage) fn ensure_catalog(connection: &Connection) -> Result<()> {
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

use super::*;

pub(crate) fn migrate(connection: &mut Connection) -> Result<()> {
    let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found == 0 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE releases (
                id TEXT PRIMARY KEY, product TEXT NOT NULL, version TEXT NOT NULL,
                content_digest TEXT NOT NULL, descriptor_json TEXT NOT NULL,
                UNIQUE(product, version)
             );
             CREATE TABLE channels (
                id TEXT PRIMARY KEY, product TEXT NOT NULL, name TEXT NOT NULL,
                release_id TEXT NOT NULL REFERENCES releases(id), revision INTEGER NOT NULL,
                UNIQUE(product, name)
             );
             CREATE TABLE environments (
                id TEXT PRIMARY KEY, revision INTEGER NOT NULL, configuration_json TEXT NOT NULL
             );
             CREATE TABLE plans (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id),
                format_version INTEGER NOT NULL, content_digest TEXT NOT NULL,
                plan_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
             );
             CREATE TABLE leases (
                environment_id TEXT PRIMARY KEY REFERENCES environments(id),
                owner TEXT NOT NULL, generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
             );
             CREATE TABLE receipts (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id),
                plan_id TEXT NOT NULL REFERENCES plans(id), step_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL, payload_json TEXT NOT NULL
             );
             CREATE TABLE rollbacks (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id),
                plan_id TEXT NOT NULL REFERENCES plans(id), lease_generation INTEGER NOT NULL,
                intent_digest TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
             );
             CREATE INDEX rollbacks_recovery ON rollbacks(status, environment_id);
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
             CREATE TABLE audit_events (
                id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL,
                principal TEXT NOT NULL, operation TEXT NOT NULL,
                resource TEXT NOT NULL, outcome TEXT NOT NULL
             );
             CREATE INDEX audit_events_time ON audit_events(occurred_at, id);
             CREATE TABLE runtime_claims (
                plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                owner TEXT NOT NULL, generation INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, completion_json TEXT
             );
             CREATE INDEX runtime_claims_environment
                ON runtime_claims(environment_id, expires_at);
             CREATE TABLE offline_imports (
                bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
             );
             CREATE TABLE offline_step_receipts (
                receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
                succeeded INTEGER NOT NULL
             );
             CREATE TABLE development_fixture_objects (
                fixture_id TEXT NOT NULL, fixture_digest TEXT NOT NULL,
                object_kind TEXT NOT NULL, object_id TEXT NOT NULL,
                object_order INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(object_kind, object_id)
             );
             CREATE INDEX development_fixture_objects_fixture
                ON development_fixture_objects(fixture_id, object_kind);
             PRAGMA user_version = 10;",
        )?;
        tx.commit()?;
    }
    if found == 1 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS provider_events (
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
             CREATE TABLE audit_events (
                id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL,
                principal TEXT NOT NULL, operation TEXT NOT NULL,
                resource TEXT NOT NULL, outcome TEXT NOT NULL
             );
             CREATE INDEX audit_events_time ON audit_events(occurred_at, id);
             CREATE TABLE runtime_claims (
                plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                owner TEXT NOT NULL, generation INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, completion_json TEXT
             );
             CREATE INDEX runtime_claims_environment
                ON runtime_claims(environment_id, expires_at);
             CREATE TABLE offline_imports (
                bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
             );
             CREATE TABLE offline_step_receipts (
                receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
                succeeded INTEGER NOT NULL
             );
             PRAGMA user_version = 6;",
        )?;
        tx.commit()?;
    }
    if found == 2 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE audit_events (
                id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL,
                principal TEXT NOT NULL, operation TEXT NOT NULL,
                resource TEXT NOT NULL, outcome TEXT NOT NULL
             );
             CREATE INDEX audit_events_time ON audit_events(occurred_at, id);
             CREATE TABLE runtime_claims (
                plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                owner TEXT NOT NULL, generation INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, completion_json TEXT
             );
             CREATE INDEX runtime_claims_environment
                ON runtime_claims(environment_id, expires_at);
             CREATE TABLE offline_imports (
                bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
             );
             CREATE TABLE offline_step_receipts (
                receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
                succeeded INTEGER NOT NULL
             );
             PRAGMA user_version = 6;",
        )?;
        tx.commit()?;
    }
    if found == 3 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE runtime_claims (
                plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                owner TEXT NOT NULL, generation INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, completion_json TEXT
             );
             CREATE INDEX runtime_claims_environment
                ON runtime_claims(environment_id, expires_at);
             CREATE TABLE offline_imports (
                bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
             );
             CREATE TABLE offline_step_receipts (
                receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
                succeeded INTEGER NOT NULL
             );
             PRAGMA user_version = 6;",
        )?;
        tx.commit()?;
    }
    if found == 4 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "ALTER TABLE runtime_claims ADD COLUMN completion_json TEXT;
             CREATE TABLE offline_imports (
                bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
             );
             CREATE TABLE offline_step_receipts (
                receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
                succeeded INTEGER NOT NULL
             );
             PRAGMA user_version = 6;",
        )?;
        tx.commit()?;
    }
    if found == 5 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE offline_imports (
                bundle_digest TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, receipt_json TEXT NOT NULL
             );
             CREATE TABLE offline_step_receipts (
                receipt_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt INTEGER NOT NULL, result_digest TEXT NOT NULL,
                succeeded INTEGER NOT NULL
             );
             PRAGMA user_version = 6;",
        )?;
        tx.commit()?;
    }
    if found <= 6 && found != 0 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE development_fixture_objects (
                fixture_id TEXT NOT NULL, fixture_digest TEXT NOT NULL,
                object_kind TEXT NOT NULL, object_id TEXT NOT NULL,
                object_order INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(object_kind, object_id)
             );
             CREATE INDEX development_fixture_objects_fixture
                ON development_fixture_objects(fixture_id, object_kind);
             PRAGMA user_version = 9;",
        )?;
        tx.commit()?;
    }
    if found == 7 {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "DELETE FROM plans WHERE id IN
                (SELECT object_id FROM development_fixture_objects WHERE object_kind='plan');
             DELETE FROM channels WHERE id IN
                (SELECT object_id FROM development_fixture_objects WHERE object_kind='channel');
             DELETE FROM environments WHERE id IN
                (SELECT object_id FROM development_fixture_objects WHERE object_kind='environment');
             DELETE FROM releases WHERE id IN
                (SELECT object_id FROM development_fixture_objects WHERE object_kind='release');
             DELETE FROM development_fixture_objects;
             ALTER TABLE development_fixture_objects
                ADD COLUMN object_order INTEGER NOT NULL DEFAULT 0;
             PRAGMA user_version = 9;",
        )?;
        tx.commit()?;
    }
    if found == 8 {
        let tx = connection.transaction()?;
        tx.execute_batch("PRAGMA user_version = 9;")?;
        tx.commit()?;
    }
    ensure_provider_event_environment_column(connection)?;
    ensure_provider_event_sequence_table(connection)?;
    let current: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current < 10 {
        let tx = connection.transaction()?;
        tx.execute_batch("PRAGMA user_version = 10;")?;
        tx.commit()?;
    }
    sqlite_objects::ensure_typed_schema_tables(connection)?;
    sqlite_objects::ensure_catalog(connection)?;
    sqlite_objects::import_legacy_graph(connection)?;
    let current: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current < SCHEMA_VERSION {
        let tx = connection.transaction()?;
        tx.execute_batch("PRAGMA user_version = 11;")?;
        tx.commit()?;
    }
    Ok(())
}

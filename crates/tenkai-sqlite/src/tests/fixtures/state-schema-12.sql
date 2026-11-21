-- State database written by tenkai v0.5.0 (state schema 12), the release before
-- schema 13. Generated with SqliteStore::open at that tag plus four sample rows,
-- then `sqlite3 .dump`. Do not edit: it stands for data an operator already has.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE releases (
                id TEXT PRIMARY KEY, product TEXT NOT NULL, version TEXT NOT NULL,
                content_digest TEXT NOT NULL, descriptor_json TEXT NOT NULL,
                UNIQUE(product, version)
             );
INSERT INTO releases VALUES('rel-kako-0.1.0','kako','0.1.0','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}');
CREATE TABLE channels (
                id TEXT PRIMARY KEY, product TEXT NOT NULL, name TEXT NOT NULL,
                release_id TEXT NOT NULL REFERENCES releases(id), revision INTEGER NOT NULL,
                UNIQUE(product, name)
             );
INSERT INTO channels VALUES('chan-kako-stable','kako','stable','rel-kako-0.1.0',1);
CREATE TABLE environments (
                id TEXT PRIMARY KEY, revision INTEGER NOT NULL, configuration_json TEXT NOT NULL,
                retired_at INTEGER
             );
INSERT INTO environments VALUES('env-prod',3,'{"name":"prod"}',NULL);
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
CREATE TABLE provider_events (
                id TEXT NOT NULL, provider_kind TEXT NOT NULL,
                binding_digest TEXT NOT NULL, payload_json TEXT NOT NULL,
                attempts INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL,
                delivered_at INTEGER, last_error TEXT NOT NULL,
                claim_token TEXT, claim_until INTEGER,
                environment_id TEXT NOT NULL DEFAULT '',
                observed_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(provider_kind,id)
             );
CREATE TABLE audit_events (
                id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL,
                principal TEXT NOT NULL, operation TEXT NOT NULL,
                resource TEXT NOT NULL, outcome TEXT NOT NULL
             );
INSERT INTO audit_events VALUES('audit-1',1760000000000,'svc','promote','kako/stable','allowed');
CREATE TABLE runtime_claims (
                plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
                owner TEXT NOT NULL, generation INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, completion_json TEXT
             );
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
CREATE TABLE provider_event_sequences (
             provider_kind TEXT PRIMARY KEY,
             next_sequence INTEGER NOT NULL
         );
CREATE TABLE catalog_objects (
             id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL
         );
CREATE TABLE catalog_object_properties (
             object_id TEXT NOT NULL,
             kind TEXT NOT NULL,
             key TEXT NOT NULL,
             value TEXT NOT NULL,
             PRIMARY KEY (object_id, key),
             FOREIGN KEY (object_id) REFERENCES catalog_objects(id) ON DELETE CASCADE
         );
CREATE TABLE catalog_links (
             id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
             relation TEXT NOT NULL, payload BLOB NOT NULL
         );
CREATE TABLE catalog_schema_types (
             name TEXT PRIMARY KEY, payload BLOB NOT NULL
         );
CREATE TABLE catalog_action_types (
             name TEXT PRIMARY KEY, payload BLOB NOT NULL
         );
CREATE TABLE catalog_leases (
             namespace TEXT NOT NULL, lease_key TEXT NOT NULL, payload BLOB NOT NULL,
             PRIMARY KEY(namespace,lease_key)
         );
CREATE TABLE catalog_decisions (
             id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, actor TEXT NOT NULL,
             action TEXT NOT NULL, payload BLOB NOT NULL
         );
CREATE TABLE catalog_changes (
             id TEXT PRIMARY KEY, object_id TEXT NOT NULL, timestamp INTEGER NOT NULL,
             payload BLOB NOT NULL
         );
CREATE INDEX rollbacks_recovery ON rollbacks(status, environment_id);
CREATE INDEX provider_events_delivery
                ON provider_events(delivered_at, next_attempt_at, id);
CREATE INDEX audit_events_time ON audit_events(occurred_at, id);
CREATE INDEX runtime_claims_environment
                ON runtime_claims(environment_id, expires_at);
CREATE INDEX development_fixture_objects_fixture
                ON development_fixture_objects(fixture_id, object_kind);
CREATE INDEX provider_events_environment
         ON provider_events(provider_kind, environment_id, next_attempt_at, id);
CREATE INDEX provider_events_environment_observed
         ON provider_events(provider_kind, environment_id, observed_at, id);
CREATE INDEX environments_active ON environments(id) WHERE retired_at IS NULL;
CREATE INDEX catalog_objects_kind ON catalog_objects(kind,id);
CREATE INDEX catalog_object_properties_lookup
             ON catalog_object_properties(kind, key, value, object_id);
CREATE INDEX catalog_links_from ON catalog_links(from_id,relation,id);
CREATE INDEX catalog_links_to ON catalog_links(to_id,relation,id);
CREATE INDEX catalog_changes_object
             ON catalog_changes(object_id,timestamp,id);
COMMIT;
PRAGMA user_version=12;

use super::pg;
use super::*;
use postgres::Transaction;

pub(crate) fn migrate_tenant_schema(tx: &mut Transaction<'_>) -> Result<()> {
    tx.batch_execute(
        "
        CREATE TABLE IF NOT EXISTS releases (
            id TEXT PRIMARY KEY, product TEXT NOT NULL, version TEXT NOT NULL,
            content_digest TEXT NOT NULL, descriptor_json TEXT NOT NULL,
            UNIQUE(product, version)
        );
        CREATE TABLE IF NOT EXISTS channels (
            id TEXT PRIMARY KEY, product TEXT NOT NULL, name TEXT NOT NULL,
            release_id TEXT NOT NULL REFERENCES releases(id), revision BIGINT NOT NULL,
            UNIQUE(product, name)
        );
        CREATE TABLE IF NOT EXISTS environments (
            id TEXT PRIMARY KEY, revision BIGINT NOT NULL, configuration_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY,
            environment_id TEXT NOT NULL REFERENCES environments(id),
            format_version INTEGER NOT NULL, content_digest TEXT NOT NULL,
            plan_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS leases (
            environment_id TEXT PRIMARY KEY REFERENCES environments(id),
            owner TEXT NOT NULL, generation BIGINT NOT NULL, expires_at BIGINT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS receipts (
            id TEXT PRIMARY KEY,
            environment_id TEXT NOT NULL REFERENCES environments(id),
            plan_id TEXT NOT NULL REFERENCES plans(id), step_id TEXT NOT NULL,
            lease_generation BIGINT NOT NULL, payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rollbacks (
            id TEXT PRIMARY KEY,
            environment_id TEXT NOT NULL REFERENCES environments(id),
            plan_id TEXT NOT NULL REFERENCES plans(id), lease_generation BIGINT NOT NULL,
            intent_digest TEXT NOT NULL,
            checkpoint_json TEXT NOT NULL, status TEXT NOT NULL, status_detail TEXT NOT NULL
        );
        ALTER TABLE rollbacks
            ADD COLUMN IF NOT EXISTS intent_lease_generation BIGINT;
        ALTER TABLE rollbacks
            ADD COLUMN IF NOT EXISTS creation_checkpoint_json TEXT;
        ALTER TABLE rollbacks
            ADD COLUMN IF NOT EXISTS creation_status_detail TEXT;
        UPDATE rollbacks
           SET intent_lease_generation = lease_generation,
               creation_checkpoint_json = checkpoint_json,
               creation_status_detail = status_detail
         WHERE intent_lease_generation IS NULL
           AND status = 'pending'
           AND intent_digest =
               environment_id || ':' || plan_id || ':' || lease_generation::text;
        CREATE INDEX IF NOT EXISTS rollbacks_recovery ON rollbacks(status, environment_id);
        CREATE TABLE IF NOT EXISTS provider_events (
            id TEXT NOT NULL, provider_kind TEXT NOT NULL,
            binding_digest TEXT NOT NULL, payload_json TEXT NOT NULL,
            attempts INTEGER NOT NULL, next_attempt_at BIGINT NOT NULL,
            delivered_at BIGINT, last_error TEXT NOT NULL,
            claim_token TEXT, claim_until BIGINT,
            environment_id TEXT NOT NULL DEFAULT '',
            observed_at BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY(provider_kind,id)
        );
        ALTER TABLE provider_events
            ADD COLUMN IF NOT EXISTS environment_id TEXT NOT NULL DEFAULT '';
        ALTER TABLE provider_events
            ADD COLUMN IF NOT EXISTS observed_at BIGINT NOT NULL DEFAULT 0;
        CREATE INDEX IF NOT EXISTS provider_events_delivery
            ON provider_events(delivered_at, next_attempt_at, id);
        CREATE INDEX IF NOT EXISTS provider_events_environment
            ON provider_events(provider_kind, environment_id, next_attempt_at, id);
        CREATE INDEX IF NOT EXISTS provider_events_environment_observed
            ON provider_events(provider_kind, environment_id, observed_at, id);
        CREATE TABLE IF NOT EXISTS provider_event_sequences (
            provider_kind TEXT PRIMARY KEY,
            next_sequence BIGINT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY, occurred_at BIGINT NOT NULL,
            principal TEXT NOT NULL, operation TEXT NOT NULL,
            resource TEXT NOT NULL, outcome TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(occurred_at, id);
        CREATE TABLE IF NOT EXISTS runtime_claims (
            plan_id TEXT PRIMARY KEY, environment_id TEXT NOT NULL,
            owner TEXT NOT NULL, generation BIGINT NOT NULL,
            expires_at BIGINT NOT NULL, completion_json TEXT
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
            succeeded BOOLEAN NOT NULL
        );
        CREATE TABLE IF NOT EXISTS development_fixture_objects (
            fixture_id TEXT NOT NULL, fixture_digest TEXT NOT NULL,
            object_kind TEXT NOT NULL, object_id TEXT NOT NULL,
            object_order BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY(object_kind, object_id)
        );
        DO $fixture_migration$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'development_fixture_objects'
                  AND column_name = 'object_order'
            ) THEN
                DELETE FROM plans WHERE id IN
                    (SELECT object_id FROM development_fixture_objects WHERE object_kind='plan');
                DELETE FROM channels WHERE id IN
                    (SELECT object_id FROM development_fixture_objects WHERE object_kind='channel');
                DELETE FROM environments WHERE id IN
                    (SELECT object_id FROM development_fixture_objects WHERE object_kind='environment');
                DELETE FROM releases WHERE id IN
                    (SELECT object_id FROM development_fixture_objects WHERE object_kind='release');
                DELETE FROM development_fixture_objects;
                ALTER TABLE development_fixture_objects
                    ADD COLUMN object_order BIGINT NOT NULL DEFAULT 0;
            END IF;
        END
        $fixture_migration$;
        CREATE INDEX IF NOT EXISTS development_fixture_objects_fixture
            ON development_fixture_objects(fixture_id, object_kind);
        ",
    )
    .map_err(pg)?;
    let legacy_events = tx
        .query(
            "SELECT provider_kind,id,payload_json FROM provider_events
             WHERE environment_id = ''",
            &[],
        )
        .map_err(pg)?;
    for row in legacy_events {
        let provider_kind: String = row.get(0);
        let id: String = row.get(1);
        let payload_json: String = row.get(2);
        if let Some(environment_id) = crate::storage::provider_event_environment_id(&payload_json) {
            tx.execute(
                "UPDATE provider_events SET environment_id = $1
                 WHERE provider_kind = $2 AND id = $3 AND environment_id = ''",
                &[&environment_id, &provider_kind, &id],
            )
            .map_err(pg)?;
        }
    }
    let legacy_observations = tx
        .query(
            "SELECT provider_kind,id,payload_json,next_attempt_at FROM provider_events
             WHERE observed_at = 0",
            &[],
        )
        .map_err(pg)?;
    for row in legacy_observations {
        let provider_kind: String = row.get(0);
        let id: String = row.get(1);
        let payload_json: String = row.get(2);
        let next_attempt_at: i64 = row.get(3);
        tx.execute(
            "UPDATE provider_events SET observed_at = $1
             WHERE provider_kind = $2 AND id = $3 AND observed_at = 0",
            &[
                &crate::storage::provider_event_observed_at(&payload_json, next_attempt_at),
                &provider_kind,
                &id,
            ],
        )
        .map_err(pg)?;
    }
    Ok(())
}

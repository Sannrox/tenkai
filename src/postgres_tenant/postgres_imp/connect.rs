use super::*;
use super::{Inner, migrate_tenant_schema, pg};
use postgres::{Client, NoTls};
use std::sync::Mutex;

impl Inner {
    pub fn connect(url: &str) -> Result<Self> {
        let mut client = Client::connect(url, NoTls).map_err(pg)?;
        // PostgreSQL's IF NOT EXISTS DDL can still race in the system
        // catalogs when several replicas initialize a fresh database at
        // once. Serialize only the global adapter migration; the
        // session-scoped lock is released automatically if setup fails.
        client
            .query_one(
                "SELECT pg_advisory_lock(hashtextextended('tenkai_global_schema_migration', 0))",
                &[],
            )
            .map_err(pg)?;
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS tenkai_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                 );",
            )
            .map_err(pg)?;
        // Global adapter schema version (refuse newer).
        let found: Option<String> = client
            .query_opt(
                "SELECT value FROM tenkai_meta WHERE key = 'schema_version'",
                &[],
            )
            .map_err(pg)?
            .map(|row| row.get(0));
        match found {
            Some(value) => {
                let version: u32 = value.parse().map_err(|_| StoreError::InvalidData {
                    kind: "schema",
                    detail: format!("invalid schema_version {value}"),
                })?;
                if version > SCHEMA_VERSION {
                    return Err(StoreError::UnsupportedSchema {
                        found: version,
                        supported: SCHEMA_VERSION,
                    });
                }
                if version < SCHEMA_VERSION {
                    client
                        .execute(
                            "UPDATE tenkai_meta SET value = $1 WHERE key = 'schema_version'",
                            &[&SCHEMA_VERSION.to_string()],
                        )
                        .map_err(pg)?;
                }
            }
            None => {
                client
                    .execute(
                        "INSERT INTO tenkai_meta(key,value) VALUES('schema_version',$1)",
                        &[&SCHEMA_VERSION.to_string()],
                    )
                    .map_err(pg)?;
            }
        }
        // Hub-wide durable tick fence claims (#135). Not per-tenant: reconcile
        // environments are coordinated across the control plane.
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS tenkai_reconcile_tick_claims (
                    environment TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    generation BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL
                 );",
            )
            .map_err(pg)?;
        client
            .query_one(
                "SELECT pg_advisory_unlock(hashtextextended('tenkai_global_schema_migration', 0))",
                &[],
            )
            .map_err(pg)?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }
}

impl Inner {
    pub fn ensure_tenant_schema(&self, schema: &str) -> Result<()> {
        let mut client = self.client.lock().map_err(|_| StoreError::Poisoned)?;
        let mut tx = client.transaction().map_err(pg)?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(
                hashtextextended('tenkai_tenant_schema:' || $1, 0)
             )",
            &[&schema],
        )
        .map_err(pg)?;
        tx.batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
            .map_err(pg)?;
        tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
            .map_err(pg)?;
        migrate_tenant_schema(&mut tx)?;
        tx.commit().map_err(pg)?;
        Ok(())
    }
}

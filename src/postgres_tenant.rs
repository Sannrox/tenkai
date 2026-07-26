//! Optional PostgreSQL multi-tenant operational store for the **control-plane hub**.
//!
//! Community hosts keep SQLite (`SqliteStore`). Enterprise hubs that need durable
//! multi-tenant recovery can enable this adapter behind Cargo feature `postgres`.
//!
//! Model: **schema-per-tenant** inside one Tenkai-owned database (never co-located
//! with the identity plane). Does **not** claim `shared_replica_state` or
//! `high_availability` until multi-replica fencing is proven (ADR 0009).
//!
//! Connection strings come from env/config only — never argv secrets.
//!
//! Enable:
//! ```text
//! cargo build --features postgres
//! export TENKAI_POSTGRES_URL=postgres://tenkai:tenkai@127.0.0.1:5432/tenkai
//! ```

use crate::auth_context::AuthenticatedRequestContext;
use crate::runtime_capabilities::{
    Capability, CapabilityName, ComponentCapabilities, RUNTIME_CAPABILITY_CONTRACT_VERSION,
};
#[cfg(feature = "postgres")]
use crate::storage::{
    AuditRecord, ChannelRecord, LeaseRecord, OfflineImportRecord, OfflineStepImportRecord,
    OperationalStore, PlanRecord, PlanStatus, ProviderEventRecord, ReceiptRecord, ReleaseRecord,
    RollbackRecord, RollbackStatus, RuntimeClaim,
};
use crate::storage::{EnvironmentRecord, Result, SCHEMA_VERSION, StoreError};
use crate::tenant_isolation::IsolationError;
use crate::tenant_store::TenantOperationalStore;

/// Capability advertisement for the optional Postgres tenant store.
///
/// Advertises `tenant_isolation` and migration level only — not HA/shared replica.
pub fn tenant_postgres_store_capabilities() -> ComponentCapabilities {
    ComponentCapabilities::new(
        "store.tenant_postgres",
        [
            Capability::named(
                CapabilityName::TenantIsolation,
                RUNTIME_CAPABILITY_CONTRACT_VERSION,
            ),
            Capability::migration(SCHEMA_VERSION),
        ],
    )
}

/// Whether this binary was compiled with the `postgres` feature.
pub fn postgres_feature_enabled() -> bool {
    cfg!(feature = "postgres")
}

/// Hub connection configuration (no secrets in process arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTenantConfig {
    /// `postgres://` URL (user/password from env-backed URL only).
    pub url: String,
}

impl PostgresTenantConfig {
    /// Load from `TENKAI_POSTGRES_URL`. Missing/empty → configuration error.
    pub fn from_env() -> Result<Self> {
        let url = std::env::var("TENKAI_POSTGRES_URL").map_err(|_| {
            StoreError::AdapterUnavailable(
                "TENKAI_POSTGRES_URL is not set (postgres://user:pass@host/db)".into(),
            )
        })?;
        Self::new(url)
    }

    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        if url.trim().is_empty() {
            return Err(StoreError::AdapterUnavailable(
                "postgres URL must not be empty".into(),
            ));
        }
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err(StoreError::AdapterUnavailable(
                "postgres URL must use postgres:// or postgresql://".into(),
            ));
        }
        Ok(Self { url })
    }

    /// Open the multi-tenant factory. Requires `--features postgres`.
    pub fn open(&self) -> Result<PostgresTenantOperationalStore> {
        #[cfg(feature = "postgres")]
        {
            PostgresTenantOperationalStore::connect(self)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = self;
            Err(StoreError::AdapterUnavailable(
                "rebuild tenkai with --features postgres to use the PostgreSQL tenant store".into(),
            ))
        }
    }
}

/// Resolve the durable hub tenant store for `tenkai-server` startup (#127).
///
/// - `tenant_mode == false` → `Ok(None)` (community path).
/// - `tenant_mode == true` → requires `TENKAI_POSTGRES_URL` and feature `postgres`,
///   then returns a wired [`PostgresTenantOperationalStore`].
pub fn resolve_server_tenant_store(
    tenant_mode: bool,
) -> Result<Option<std::sync::Arc<dyn TenantOperationalStore>>> {
    if !tenant_mode {
        return Ok(None);
    }
    if !postgres_feature_enabled() {
        return Err(StoreError::AdapterUnavailable(
            "tenant mode requires a binary built with --features postgres and TENKAI_POSTGRES_URL"
                .into(),
        ));
    }
    let config = PostgresTenantConfig::from_env()?;
    let store = config.open()?;
    Ok(Some(std::sync::Arc::new(store)))
}

/// Sanitize tenant id into a safe Postgres schema name (`tenkai_t_*`).
pub fn tenant_schema_name(tenant_id: &str) -> Result<String> {
    if tenant_id.trim().is_empty() || tenant_id.len() > 64 {
        return Err(StoreError::InvalidData {
            kind: "tenant",
            detail: "tenant id must be 1..=64 characters".into(),
        });
    }
    let mut out = String::from("tenkai_t_");
    for ch in tenant_id.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            out.push('_');
        } else {
            return Err(StoreError::InvalidData {
                kind: "tenant",
                detail: format!("tenant id contains unsupported character {ch:?}"),
            });
        }
    }
    if out == "tenkai_t_" {
        return Err(StoreError::InvalidData {
            kind: "tenant",
            detail: "tenant id produced an empty schema suffix".into(),
        });
    }
    Ok(out)
}

/// Multi-tenant Postgres operational store factory (hub).
///
/// Each authenticated tenant gets an isolated schema with the full Tenkai
/// operational table set. Cross-tenant access is non-disclosing.
#[derive(Clone)]
pub struct PostgresTenantOperationalStore {
    #[cfg(feature = "postgres")]
    inner: std::sync::Arc<postgres_imp::Inner>,
    #[cfg(not(feature = "postgres"))]
    _private: (),
}

impl PostgresTenantOperationalStore {
    pub fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_postgres_store_capabilities()
    }

    #[cfg(feature = "postgres")]
    fn connect(config: &PostgresTenantConfig) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(postgres_imp::Inner::connect(&config.url)?),
        })
    }

    pub fn partition_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<PostgresTenantPartition, IsolationError> {
        context
            .validate()
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        let tenant_id = context
            .tenant()
            .map(|tenant| tenant.tenant_id().to_string())
            .ok_or(IsolationError::Unauthenticated)?;
        self.partition_by_id(&tenant_id)
    }

    fn partition_by_id(
        &self,
        tenant_id: &str,
    ) -> std::result::Result<PostgresTenantPartition, IsolationError> {
        let schema = tenant_schema_name(tenant_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))?;
        #[cfg(feature = "postgres")]
        {
            self.inner
                .ensure_tenant_schema(&schema)
                .map_err(|error| IsolationError::Contract(error.to_string()))?;
            Ok(PostgresTenantPartition {
                tenant_id: tenant_id.to_string(),
                schema,
                inner: self.inner.clone(),
            })
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = schema;
            Err(IsolationError::Contract(
                "postgres feature is not enabled in this binary".into(),
            ))
        }
    }

    pub fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        let partition = self.partition_for(context)?;
        match partition.get_environment(environment_id) {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(IsolationError::NotFound),
            Err(error) => Err(IsolationError::Contract(error.to_string())),
        }
    }

    pub fn put_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &EnvironmentRecord,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .put_environment_record(environment)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .list_environment_ids()
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }
}

impl TenantOperationalStore for PostgresTenantOperationalStore {
    fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_postgres_store_capabilities()
    }

    fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        PostgresTenantOperationalStore::get_environment_for(self, context, environment_id)
    }

    fn put_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &EnvironmentRecord,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        PostgresTenantOperationalStore::put_environment_for(self, context, environment)
    }

    fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError> {
        PostgresTenantOperationalStore::list_environment_ids_for(self, context)
    }
}

impl PostgresTenantOperationalStore {
    /// Isolation checks when a live Postgres is available; no-op structure when feature off.
    pub fn run_partition_isolation_check(
        &self,
        ctx_a: &AuthenticatedRequestContext,
        ctx_b: &AuthenticatedRequestContext,
        env_a: &str,
        env_b: &str,
    ) -> std::result::Result<(), IsolationError> {
        self.put_environment_for(
            ctx_a,
            &EnvironmentRecord {
                id: env_a.into(),
                revision: 0,
                configuration_json: r#"{"tenant":"a"}"#.into(),
            },
        )?;
        self.put_environment_for(
            ctx_b,
            &EnvironmentRecord {
                id: env_b.into(),
                revision: 0,
                configuration_json: r#"{"tenant":"b"}"#.into(),
            },
        )?;
        let listed = self.list_environment_ids_for(ctx_a)?;
        if listed != vec![env_a.to_string()] {
            return Err(IsolationError::Contract(
                "postgres tenant list leaked or missed environments".into(),
            ));
        }
        match self.get_environment_for(ctx_a, env_b) {
            Err(IsolationError::NotFound) => Ok(()),
            Ok(_) => Err(IsolationError::Contract(
                "cross-tenant environment get succeeded".into(),
            )),
            Err(other) => Err(other),
        }
    }
}

/// One tenant's Postgres schema partition implementing [`OperationalStore`].
#[derive(Clone)]
pub struct PostgresTenantPartition {
    tenant_id: String,
    schema: String,
    #[cfg(feature = "postgres")]
    inner: std::sync::Arc<postgres_imp::Inner>,
    #[cfg(not(feature = "postgres"))]
    _private: (),
}

impl PostgresTenantPartition {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn get_environment(&self, id: &str) -> Result<Option<EnvironmentRecord>> {
        #[cfg(feature = "postgres")]
        {
            self.inner.get_environment(&self.schema, id)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = id;
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn put_environment_record(
        &self,
        environment: &EnvironmentRecord,
    ) -> Result<EnvironmentRecord> {
        #[cfg(feature = "postgres")]
        {
            self.inner.put_environment(&self.schema, environment)
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = environment;
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }

    pub fn list_environment_ids(&self) -> Result<Vec<String>> {
        #[cfg(feature = "postgres")]
        {
            self.inner.list_environment_ids(&self.schema)
        }
        #[cfg(not(feature = "postgres"))]
        {
            Err(StoreError::AdapterUnavailable(
                "postgres feature disabled".into(),
            ))
        }
    }
}

#[cfg(feature = "postgres")]
impl OperationalStore for PostgresTenantPartition {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()> {
        self.inner.publish_release(&self.schema, release)
    }
    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>> {
        self.inner.get_release(&self.schema, id)
    }
    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        self.inner.promote_channel(&self.schema, channel)
    }
    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord> {
        self.inner.put_environment(&self.schema, environment)
    }
    fn create_plan(&self, plan: &PlanRecord) -> Result<()> {
        self.inner.create_plan(&self.schema, plan)
    }
    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>> {
        self.inner.get_plan(&self.schema, id)
    }
    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        self.inner
            .transition_plan(&self.schema, id, owner, generation, status, detail)
    }
    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        self.inner
            .acquire_lease(&self.schema, environment, owner, expires_at)
    }
    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>> {
        self.inner.current_lease(&self.schema, environment)
    }
    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        self.inner.record_receipt(&self.schema, owner, receipt)
    }
    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>> {
        self.inner.get_receipt(&self.schema, id)
    }
    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        self.inner
            .record_offline_import(&self.schema, receipt, steps)
    }
    fn get_offline_import(&self, bundle_digest: &str) -> Result<Option<OfflineImportRecord>> {
        self.inner.get_offline_import(&self.schema, bundle_digest)
    }
    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()> {
        self.inner.create_rollback(&self.schema, owner, rollback)
    }
    fn transition_rollback(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord> {
        self.inner.transition_rollback(
            &self.schema,
            id,
            owner,
            generation,
            status,
            checkpoint_json,
            detail,
        )
    }
    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>> {
        self.inner.pending_rollbacks(&self.schema)
    }
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()> {
        self.inner.enqueue_provider_event(&self.schema, event)
    }
    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.inner
            .claim_provider_events(&self.schema, now, limit, claim_token, claim_until)
    }
    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        self.inner.record_provider_failure(
            &self.schema,
            provider_kind,
            id,
            claim_token,
            next_attempt_at,
            error,
        )
    }
    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        self.inner.mark_provider_event_delivered(
            &self.schema,
            provider_kind,
            id,
            claim_token,
            delivered_at,
        )
    }
    fn append_audit(&self, event: &AuditRecord) -> Result<()> {
        self.inner.append_audit(&self.schema, event)
    }
    fn audit_events(&self) -> Result<Vec<AuditRecord>> {
        self.inner.audit_events(&self.schema)
    }
    fn check_health(&self) -> Result<()> {
        self.inner.check_health()
    }
    fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_postgres_store_capabilities()
    }
    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.inner
            .claim_runtime_plan(&self.schema, environment, plan_id, owner, expires_at)
    }
    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.inner
            .renew_runtime_plan(&self.schema, plan_id, owner, generation, expires_at)
    }
    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        self.inner
            .complete_runtime_plan(&self.schema, plan_id, owner, generation, completion_json)
    }
}

#[cfg(feature = "postgres")]
mod postgres_imp {
    use super::*;
    use postgres::{Client, NoTls, Transaction};
    use std::sync::Mutex;

    pub struct Inner {
        client: Mutex<Client>,
    }

    fn pg(err: postgres::Error) -> StoreError {
        StoreError::Postgres(err.to_string())
    }

    impl Inner {
        pub fn connect(url: &str) -> Result<Self> {
            let mut client = Client::connect(url, NoTls).map_err(pg)?;
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
            Ok(Self {
                client: Mutex::new(client),
            })
        }

        fn with_schema<T>(
            &self,
            schema: &str,
            f: impl FnOnce(&mut Transaction<'_>) -> Result<T>,
        ) -> Result<T> {
            let mut client = self.client.lock().map_err(|_| StoreError::Poisoned)?;
            let mut tx = client.transaction().map_err(pg)?;
            // Identifier is sanitized by tenant_schema_name (alnum + underscore only).
            tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
                .map_err(pg)?;
            let out = f(&mut tx)?;
            tx.commit().map_err(pg)?;
            Ok(out)
        }

        pub fn ensure_tenant_schema(&self, schema: &str) -> Result<()> {
            let mut client = self.client.lock().map_err(|_| StoreError::Poisoned)?;
            client
                .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
                .map_err(pg)?;
            let mut tx = client.transaction().map_err(pg)?;
            tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
                .map_err(pg)?;
            migrate_tenant_schema(&mut tx)?;
            tx.commit().map_err(pg)?;
            Ok(())
        }

        pub fn check_health(&self) -> Result<()> {
            let mut client = self.client.lock().map_err(|_| StoreError::Poisoned)?;
            client.query_one("SELECT 1", &[]).map_err(pg)?;
            Ok(())
        }

        pub fn get_environment(&self, schema: &str, id: &str) -> Result<Option<EnvironmentRecord>> {
            self.with_schema(schema, |tx| {
                let row = tx
                    .query_opt(
                        "SELECT id, revision, configuration_json FROM environments WHERE id = $1",
                        &[&id],
                    )
                    .map_err(pg)?;
                Ok(row.map(|row| EnvironmentRecord {
                    id: row.get(0),
                    revision: row.get::<_, i64>(1) as u64,
                    configuration_json: row.get(2),
                }))
            })
        }

        pub fn list_environment_ids(&self, schema: &str) -> Result<Vec<String>> {
            self.with_schema(schema, |tx| {
                let rows = tx
                    .query("SELECT id FROM environments ORDER BY id ASC", &[])
                    .map_err(pg)?;
                Ok(rows.into_iter().map(|row| row.get(0)).collect())
            })
        }

        pub fn put_environment(
            &self,
            schema: &str,
            environment: &EnvironmentRecord,
        ) -> Result<EnvironmentRecord> {
            self.with_schema(schema, |tx| {
                let revision: Option<i64> = tx
                    .query_opt(
                        "SELECT revision FROM environments WHERE id = $1",
                        &[&environment.id],
                    )
                    .map_err(pg)?
                    .map(|row| row.get(0));
                let next = match revision {
                    Some(revision) if revision as u64 == environment.revision => {
                        revision as u64 + 1
                    }
                    Some(revision) => {
                        return Err(StoreError::RevisionConflict {
                            kind: "environment",
                            id: environment.id.clone(),
                            expected: environment.revision,
                            actual: revision as u64,
                        });
                    }
                    None if environment.revision == 0 => 1,
                    None => {
                        return Err(StoreError::RevisionConflict {
                            kind: "environment",
                            id: environment.id.clone(),
                            expected: environment.revision,
                            actual: 0,
                        });
                    }
                };
                let next_i = next as i64;
                tx.execute(
                    "INSERT INTO environments(id,revision,configuration_json) VALUES($1,$2,$3)
                     ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,
                       configuration_json=EXCLUDED.configuration_json",
                    &[&environment.id, &next_i, &environment.configuration_json],
                )
                .map_err(pg)?;
                Ok(EnvironmentRecord {
                    revision: next,
                    ..environment.clone()
                })
            })
        }

        pub fn publish_release(&self, schema: &str, release: &ReleaseRecord) -> Result<()> {
            self.with_schema(schema, |tx| {
                let existing = tx
                    .query_opt(
                        "SELECT product, version, content_digest, descriptor_json
                         FROM releases WHERE id = $1",
                        &[&release.id],
                    )
                    .map_err(pg)?;
                if let Some(row) = existing {
                    let product: String = row.get(0);
                    let version: String = row.get(1);
                    let digest: String = row.get(2);
                    let descriptor: String = row.get(3);
                    if product != release.product
                        || version != release.version
                        || digest != release.content_digest
                        || descriptor != release.descriptor_json
                    {
                        return Err(StoreError::ImmutableConflict {
                            kind: "release",
                            id: release.id.clone(),
                        });
                    }
                    return Ok(());
                }
                tx.execute(
                    "INSERT INTO releases(id,product,version,content_digest,descriptor_json)
                     VALUES($1,$2,$3,$4,$5)",
                    &[
                        &release.id,
                        &release.product,
                        &release.version,
                        &release.content_digest,
                        &release.descriptor_json,
                    ],
                )
                .map_err(pg)?;
                Ok(())
            })
        }

        pub fn get_release(&self, schema: &str, id: &str) -> Result<Option<ReleaseRecord>> {
            self.with_schema(schema, |tx| {
                let row = tx
                    .query_opt(
                        "SELECT id,product,version,content_digest,descriptor_json FROM releases WHERE id=$1",
                        &[&id],
                    )
                    .map_err(pg)?;
                Ok(row.map(|row| ReleaseRecord {
                    id: row.get(0),
                    product: row.get(1),
                    version: row.get(2),
                    content_digest: row.get(3),
                    descriptor_json: row.get(4),
                }))
            })
        }

        pub fn promote_channel(
            &self,
            schema: &str,
            channel: &ChannelRecord,
        ) -> Result<ChannelRecord> {
            self.with_schema(schema, |tx| {
                let release_product: String = tx
                    .query_opt(
                        "SELECT product FROM releases WHERE id = $1",
                        &[&channel.release_id],
                    )
                    .map_err(pg)?
                    .map(|row| row.get(0))
                    .ok_or_else(|| StoreError::NotFound {
                        kind: "release",
                        id: channel.release_id.clone(),
                    })?;
                if release_product != channel.product {
                    return Err(StoreError::InvalidData {
                        kind: "channel",
                        detail: format!(
                            "release {} belongs to product {release_product}, not {}",
                            channel.release_id, channel.product
                        ),
                    });
                }
                let existing = tx
                    .query_opt(
                        "SELECT product,name,revision FROM channels WHERE id = $1",
                        &[&channel.id],
                    )
                    .map_err(pg)?;
                let next = match existing {
                    Some(row) => {
                        let product: String = row.get(0);
                        let name: String = row.get(1);
                        let revision: i64 = row.get(2);
                        if product != channel.product || name != channel.name {
                            return Err(StoreError::ImmutableConflict {
                                kind: "channel",
                                id: channel.id.clone(),
                            });
                        }
                        if revision as u64 != channel.revision {
                            return Err(StoreError::RevisionConflict {
                                kind: "channel",
                                id: channel.id.clone(),
                                expected: channel.revision,
                                actual: revision as u64,
                            });
                        }
                        revision as u64 + 1
                    }
                    None if channel.revision == 0 => 1,
                    None => {
                        return Err(StoreError::RevisionConflict {
                            kind: "channel",
                            id: channel.id.clone(),
                            expected: channel.revision,
                            actual: 0,
                        });
                    }
                };
                let next_i = next as i64;
                tx.execute(
                    "INSERT INTO channels(id,product,name,release_id,revision)
                     VALUES($1,$2,$3,$4,$5)
                     ON CONFLICT(id) DO UPDATE SET release_id=EXCLUDED.release_id,
                       revision=EXCLUDED.revision",
                    &[
                        &channel.id,
                        &channel.product,
                        &channel.name,
                        &channel.release_id,
                        &next_i,
                    ],
                )
                .map_err(pg)?;
                Ok(ChannelRecord {
                    revision: next,
                    ..channel.clone()
                })
            })
        }

        pub fn create_plan(&self, schema: &str, plan: &PlanRecord) -> Result<()> {
            self.with_schema(schema, |tx| {
                let existing = tx
                    .query_opt(
                        "SELECT environment_id,format_version,content_digest,plan_json
                         FROM plans WHERE id = $1",
                        &[&plan.id],
                    )
                    .map_err(pg)?;
                if let Some(row) = existing {
                    let env: String = row.get(0);
                    let format: i32 = row.get(1);
                    let digest: String = row.get(2);
                    let json: String = row.get(3);
                    if env != plan.environment_id
                        || format as u32 != plan.format_version
                        || digest != plan.content_digest
                        || json != plan.plan_json
                    {
                        return Err(StoreError::ImmutableConflict {
                            kind: "plan",
                            id: plan.id.clone(),
                        });
                    }
                    return Ok(());
                }
                if plan.status != PlanStatus::Computed {
                    return Err(StoreError::InvalidPlanTransition {
                        id: plan.id.clone(),
                        from: PlanStatus::Computed,
                        to: plan.status,
                    });
                }
                let format = plan.format_version as i32;
                tx.execute(
                    "INSERT INTO plans(id,environment_id,format_version,content_digest,plan_json,status,status_detail)
                     VALUES($1,$2,$3,$4,$5,$6,$7)",
                    &[
                        &plan.id,
                        &plan.environment_id,
                        &format,
                        &plan.content_digest,
                        &plan.plan_json,
                        &plan.status.as_str(),
                        &plan.status_detail,
                    ],
                )
                .map_err(pg)?;
                Ok(())
            })
        }

        pub fn get_plan(&self, schema: &str, id: &str) -> Result<Option<PlanRecord>> {
            self.with_schema(schema, |tx| {
                let row = tx
                    .query_opt(
                        "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                         FROM plans WHERE id = $1",
                        &[&id],
                    )
                    .map_err(pg)?;
                row.map(|row| {
                    let status: String = row.get(5);
                    Ok(PlanRecord {
                        id: row.get(0),
                        environment_id: row.get(1),
                        format_version: row.get::<_, i32>(2) as u32,
                        content_digest: row.get(3),
                        plan_json: row.get(4),
                        status: PlanStatus::parse(&status)?,
                        status_detail: row.get(6),
                    })
                })
                .transpose()
            })
        }

        pub fn transition_plan(
            &self,
            schema: &str,
            id: &str,
            owner: &str,
            generation: u64,
            status: PlanStatus,
            detail: &str,
        ) -> Result<PlanRecord> {
            self.with_schema(schema, |tx| {
                let current: String = tx
                    .query_opt("SELECT status FROM plans WHERE id = $1", &[&id])
                    .map_err(pg)?
                    .map(|row| row.get(0))
                    .ok_or_else(|| StoreError::NotFound {
                        kind: "plan",
                        id: id.into(),
                    })?;
                let current = PlanStatus::parse(&current)?;
                let environment: String = tx
                    .query_one("SELECT environment_id FROM plans WHERE id = $1", &[&id])
                    .map_err(pg)?
                    .get(0);
                require_lease(tx, &environment, owner, generation, crate::now_millis())?;
                if !current.allows(status) {
                    return Err(StoreError::InvalidPlanTransition {
                        id: id.into(),
                        from: current,
                        to: status,
                    });
                }
                tx.execute(
                    "UPDATE plans SET status = $2, status_detail = $3 WHERE id = $1",
                    &[&id, &status.as_str(), &detail],
                )
                .map_err(pg)?;
                let row = tx
                    .query_one(
                        "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail
                         FROM plans WHERE id = $1",
                        &[&id],
                    )
                    .map_err(pg)?;
                let status_s: String = row.get(5);
                Ok(PlanRecord {
                    id: row.get(0),
                    environment_id: row.get(1),
                    format_version: row.get::<_, i32>(2) as u32,
                    content_digest: row.get(3),
                    plan_json: row.get(4),
                    status: PlanStatus::parse(&status_s)?,
                    status_detail: row.get(6),
                })
            })
        }

        pub fn acquire_lease(
            &self,
            schema: &str,
            environment: &str,
            owner: &str,
            expires_at: i64,
        ) -> Result<LeaseRecord> {
            let now = crate::now_millis();
            if expires_at <= now {
                return Err(StoreError::LeaseExpired {
                    environment: environment.into(),
                    generation: 0,
                });
            }
            self.with_schema(schema, |tx| {
                let current = lease_in(tx, environment)?;
                let generation = match current {
                    Some(current) if current.expires_at > now && current.owner != owner => {
                        return Err(StoreError::LeaseHeld {
                            environment: environment.into(),
                            owner: current.owner,
                            expires_at: current.expires_at,
                        });
                    }
                    Some(current) if current.expires_at > now => current.generation,
                    Some(current) => current.generation + 1,
                    None => 1,
                };
                let gen_i = generation as i64;
                tx.execute(
                    "INSERT INTO leases(environment_id,owner,generation,expires_at)
                     VALUES($1,$2,$3,$4)
                     ON CONFLICT(environment_id) DO UPDATE SET owner=EXCLUDED.owner,
                       generation=EXCLUDED.generation,expires_at=EXCLUDED.expires_at",
                    &[&environment, &owner, &gen_i, &expires_at],
                )
                .map_err(pg)?;
                Ok(LeaseRecord {
                    environment_id: environment.into(),
                    owner: owner.into(),
                    generation,
                    expires_at,
                })
            })
        }

        pub fn current_lease(
            &self,
            schema: &str,
            environment: &str,
        ) -> Result<Option<LeaseRecord>> {
            self.with_schema(schema, |tx| lease_in(tx, environment))
        }

        pub fn record_receipt(
            &self,
            schema: &str,
            owner: &str,
            receipt: &ReceiptRecord,
        ) -> Result<()> {
            self.with_schema(schema, |tx| {
                let existing = tx
                    .query_opt(
                        "SELECT environment_id,plan_id,step_id,lease_generation,payload_json
                         FROM receipts WHERE id = $1",
                        &[&receipt.id],
                    )
                    .map_err(pg)?;
                if let Some(row) = existing {
                    let env: String = row.get(0);
                    let plan: String = row.get(1);
                    let step: String = row.get(2);
                    let lease_gen: i64 = row.get(3);
                    let payload: String = row.get(4);
                    if env != receipt.environment_id
                        || plan != receipt.plan_id
                        || step != receipt.step_id
                        || lease_gen as u64 != receipt.lease_generation
                        || payload != receipt.payload_json
                    {
                        return Err(StoreError::ImmutableConflict {
                            kind: "receipt",
                            id: receipt.id.clone(),
                        });
                    }
                    return Ok(());
                }
                require_plan_environment(tx, &receipt.plan_id, &receipt.environment_id)?;
                require_lease(
                    tx,
                    &receipt.environment_id,
                    owner,
                    receipt.lease_generation,
                    crate::now_millis(),
                )?;
                let lease_gen = receipt.lease_generation as i64;
                tx.execute(
                    "INSERT INTO receipts(id,environment_id,plan_id,step_id,lease_generation,payload_json)
                     VALUES($1,$2,$3,$4,$5,$6)",
                    &[
                        &receipt.id,
                        &receipt.environment_id,
                        &receipt.plan_id,
                        &receipt.step_id,
                        &lease_gen,
                        &receipt.payload_json,
                    ],
                )
                .map_err(pg)?;
                Ok(())
            })
        }

        pub fn get_receipt(&self, schema: &str, id: &str) -> Result<Option<ReceiptRecord>> {
            self.with_schema(schema, |tx| {
                let row = tx
                    .query_opt(
                        "SELECT id,environment_id,plan_id,step_id,lease_generation,payload_json
                         FROM receipts WHERE id = $1",
                        &[&id],
                    )
                    .map_err(pg)?;
                Ok(row.map(|row| ReceiptRecord {
                    id: row.get(0),
                    environment_id: row.get(1),
                    plan_id: row.get(2),
                    step_id: row.get(3),
                    lease_generation: row.get::<_, i64>(4) as u64,
                    payload_json: row.get(5),
                }))
            })
        }

        pub fn record_offline_import(
            &self,
            schema: &str,
            receipt: &OfflineImportRecord,
            steps: &[OfflineStepImportRecord],
        ) -> Result<()> {
            self.with_schema(schema, |tx| {
                let existing = tx
                    .query_opt(
                        "SELECT environment_id,plan_id,receipt_json FROM offline_imports
                         WHERE bundle_digest = $1",
                        &[&receipt.bundle_digest],
                    )
                    .map_err(pg)?;
                if let Some(row) = existing {
                    let env: String = row.get(0);
                    let plan: String = row.get(1);
                    let json: String = row.get(2);
                    if env != receipt.environment_id
                        || plan != receipt.plan_id
                        || json != receipt.receipt_json
                    {
                        return Err(StoreError::ImmutableConflict {
                            kind: "offline import",
                            id: receipt.bundle_digest.clone(),
                        });
                    }
                }
                require_plan_environment(tx, &receipt.plan_id, &receipt.environment_id)?;
                tx.execute(
                    "INSERT INTO offline_imports(bundle_digest,environment_id,plan_id,receipt_json)
                     VALUES($1,$2,$3,$4) ON CONFLICT(bundle_digest) DO NOTHING",
                    &[
                        &receipt.bundle_digest,
                        &receipt.environment_id,
                        &receipt.plan_id,
                        &receipt.receipt_json,
                    ],
                )
                .map_err(pg)?;
                for step in steps {
                    let attempt = step.attempt as i32;
                    tx.execute(
                        "INSERT INTO offline_step_receipts(
                            receipt_id,environment_id,plan_id,step_id,attempt,result_digest,succeeded
                         ) VALUES($1,$2,$3,$4,$5,$6,$7)
                         ON CONFLICT(receipt_id) DO NOTHING",
                        &[
                            &step.receipt_id,
                            &step.environment_id,
                            &step.plan_id,
                            &step.step_id,
                            &attempt,
                            &step.result_digest,
                            &step.succeeded,
                        ],
                    )
                    .map_err(pg)?;
                }
                Ok(())
            })
        }

        pub fn get_offline_import(
            &self,
            schema: &str,
            bundle_digest: &str,
        ) -> Result<Option<OfflineImportRecord>> {
            self.with_schema(schema, |tx| {
                let row = tx
                    .query_opt(
                        "SELECT bundle_digest,environment_id,plan_id,receipt_json
                         FROM offline_imports WHERE bundle_digest = $1",
                        &[&bundle_digest],
                    )
                    .map_err(pg)?;
                Ok(row.map(|row| OfflineImportRecord {
                    bundle_digest: row.get(0),
                    environment_id: row.get(1),
                    plan_id: row.get(2),
                    receipt_json: row.get(3),
                }))
            })
        }

        pub fn create_rollback(
            &self,
            schema: &str,
            owner: &str,
            rollback: &RollbackRecord,
        ) -> Result<()> {
            if rollback.status != RollbackStatus::Pending {
                return Err(StoreError::InvalidRollbackTransition {
                    id: rollback.id.clone(),
                    from: RollbackStatus::Pending,
                    to: rollback.status,
                });
            }
            self.with_schema(schema, |tx| {
                if let Some(existing) = rollback_in(tx, &rollback.id)? {
                    if existing.environment_id != rollback.environment_id
                        || existing.plan_id != rollback.plan_id
                        || existing.lease_generation != rollback.lease_generation
                    {
                        return Err(StoreError::ImmutableConflict {
                            kind: "rollback",
                            id: rollback.id.clone(),
                        });
                    }
                    return Ok(());
                }
                require_plan_environment(tx, &rollback.plan_id, &rollback.environment_id)?;
                require_lease(
                    tx,
                    &rollback.environment_id,
                    owner,
                    rollback.lease_generation,
                    crate::now_millis(),
                )?;
                let lease_gen = rollback.lease_generation as i64;
                let intent = format!(
                    "{}:{}:{}",
                    rollback.environment_id, rollback.plan_id, rollback.lease_generation
                );
                tx.execute(
                    "INSERT INTO rollbacks(id,environment_id,plan_id,lease_generation,intent_digest,checkpoint_json,status,status_detail)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                    &[
                        &rollback.id,
                        &rollback.environment_id,
                        &rollback.plan_id,
                        &lease_gen,
                        &intent,
                        &rollback.checkpoint_json,
                        &rollback.status.as_str(),
                        &rollback.status_detail,
                    ],
                )
                .map_err(pg)?;
                Ok(())
            })
        }

        #[allow(clippy::too_many_arguments)]
        pub fn transition_rollback(
            &self,
            schema: &str,
            id: &str,
            owner: &str,
            generation: u64,
            status: RollbackStatus,
            checkpoint_json: &str,
            detail: &str,
        ) -> Result<RollbackRecord> {
            self.with_schema(schema, |tx| {
                let current = rollback_in(tx, id)?.ok_or_else(|| StoreError::NotFound {
                    kind: "rollback",
                    id: id.into(),
                })?;
                require_plan_environment(tx, &current.plan_id, &current.environment_id)?;
                require_lease(
                    tx,
                    &current.environment_id,
                    owner,
                    generation,
                    crate::now_millis(),
                )?;
                if !current.status.allows(status) {
                    return Err(StoreError::InvalidRollbackTransition {
                        id: id.into(),
                        from: current.status,
                        to: status,
                    });
                }
                let lease_gen = generation as i64;
                tx.execute(
                    "UPDATE rollbacks SET lease_generation=$2,checkpoint_json=$3,status=$4,status_detail=$5
                     WHERE id=$1",
                    &[&id, &lease_gen, &checkpoint_json, &status.as_str(), &detail],
                )
                .map_err(pg)?;
                rollback_in(tx, id)?.ok_or_else(|| StoreError::NotFound {
                    kind: "rollback",
                    id: id.into(),
                })
            })
        }

        pub fn pending_rollbacks(&self, schema: &str) -> Result<Vec<RollbackRecord>> {
            self.with_schema(schema, |tx| {
                let rows = tx
                    .query(
                        "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail
                         FROM rollbacks WHERE status IN ('pending','running') ORDER BY id",
                        &[],
                    )
                    .map_err(pg)?;
                rows.into_iter()
                    .map(|row| {
                        let status: String = row.get(5);
                        Ok(RollbackRecord {
                            id: row.get(0),
                            environment_id: row.get(1),
                            plan_id: row.get(2),
                            lease_generation: row.get::<_, i64>(3) as u64,
                            checkpoint_json: row.get(4),
                            status: RollbackStatus::parse(&status)?,
                            status_detail: row.get(6),
                        })
                    })
                    .collect()
            })
        }

        pub fn enqueue_provider_event(
            &self,
            schema: &str,
            event: &ProviderEventRecord,
        ) -> Result<()> {
            if event.attempts != 0
                || event.delivered_at.is_some()
                || !event.last_error.is_empty()
                || event.claim_token.is_some()
                || event.claim_until.is_some()
            {
                return Err(StoreError::InvalidData {
                    kind: "provider event",
                    detail: "new events must have pristine delivery state".into(),
                });
            }
            self.with_schema(schema, |tx| {
                let existing = tx
                    .query_opt(
                        "SELECT provider_kind,binding_digest,payload_json FROM provider_events
                         WHERE provider_kind = $1 AND id = $2",
                        &[&event.provider_kind, &event.id],
                    )
                    .map_err(pg)?;
                if let Some(row) = existing {
                    let kind: String = row.get(0);
                    let digest: String = row.get(1);
                    let payload: String = row.get(2);
                    if kind != event.provider_kind
                        || digest != event.binding_digest
                        || payload != event.payload_json
                    {
                        return Err(StoreError::ImmutableConflict {
                            kind: "provider event",
                            id: event.id.clone(),
                        });
                    }
                    return Ok(());
                }
                let attempts = event.attempts as i32;
                tx.execute(
                    "INSERT INTO provider_events(id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    &[
                        &event.id,
                        &event.provider_kind,
                        &event.binding_digest,
                        &event.payload_json,
                        &attempts,
                        &event.next_attempt_at,
                        &event.delivered_at,
                        &event.last_error,
                        &event.claim_token,
                        &event.claim_until,
                    ],
                )
                .map_err(pg)?;
                Ok(())
            })
        }

        pub fn claim_provider_events(
            &self,
            schema: &str,
            now: i64,
            limit: usize,
            claim_token: &str,
            claim_until: i64,
        ) -> Result<Vec<ProviderEventRecord>> {
            if claim_token.is_empty() || claim_until <= now {
                return Err(StoreError::InvalidData {
                    kind: "provider event claim",
                    detail: "claim token must be non-empty and expiry must be in the future".into(),
                });
            }
            self.with_schema(schema, |tx| {
                tx.execute(
                    "UPDATE provider_events SET claim_token=NULL,claim_until=NULL
                     WHERE delivered_at IS NULL AND claim_until <= $1",
                    &[&now],
                )
                .map_err(pg)?;
                let token_in_use: bool = tx
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM provider_events
                         WHERE delivered_at IS NULL AND claim_token = $1)",
                        &[&claim_token],
                    )
                    .map_err(pg)?
                    .get(0);
                if token_in_use {
                    return Err(StoreError::InvalidData {
                        kind: "provider event claim",
                        detail: "claim token is already active; every claim operation requires a fresh token"
                            .into(),
                    });
                }
                let limit_i = limit as i64;
                tx.execute(
                    "UPDATE provider_events SET claim_token=$3,claim_until=$4
                     WHERE (provider_kind,id) IN (
                       SELECT provider_kind,id FROM provider_events
                       WHERE delivered_at IS NULL AND next_attempt_at <= $1
                         AND (claim_until IS NULL OR claim_until <= $1)
                       ORDER BY next_attempt_at,provider_kind,id LIMIT $2
                     )",
                    &[&now, &limit_i, &claim_token, &claim_until],
                )
                .map_err(pg)?;
                let rows = tx
                    .query(
                        "SELECT id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,delivered_at,last_error,claim_token,claim_until
                         FROM provider_events WHERE delivered_at IS NULL AND claim_token = $1
                         ORDER BY next_attempt_at,provider_kind,id",
                        &[&claim_token],
                    )
                    .map_err(pg)?;
                Ok(rows
                    .into_iter()
                    .map(|row| ProviderEventRecord {
                        id: row.get(0),
                        provider_kind: row.get(1),
                        binding_digest: row.get(2),
                        payload_json: row.get(3),
                        attempts: row.get::<_, i32>(4) as u32,
                        next_attempt_at: row.get(5),
                        delivered_at: row.get(6),
                        last_error: row.get(7),
                        claim_token: row.get(8),
                        claim_until: row.get(9),
                    })
                    .collect())
            })
        }

        pub fn record_provider_failure(
            &self,
            schema: &str,
            provider_kind: &str,
            id: &str,
            claim_token: &str,
            next_attempt_at: i64,
            error: &str,
        ) -> Result<()> {
            self.with_schema(schema, |tx| {
                let changed = tx
                    .execute(
                        "UPDATE provider_events SET attempts=attempts+1,next_attempt_at=$4,last_error=$5,
                           claim_token=NULL,claim_until=NULL
                         WHERE provider_kind=$1 AND id=$2 AND claim_token=$3 AND delivered_at IS NULL",
                        &[&provider_kind, &id, &claim_token, &next_attempt_at, &error],
                    )
                    .map_err(pg)?;
                if changed == 0 {
                    return Err(StoreError::NotFound {
                        kind: "pending provider event",
                        id: id.into(),
                    });
                }
                Ok(())
            })
        }

        pub fn mark_provider_event_delivered(
            &self,
            schema: &str,
            provider_kind: &str,
            id: &str,
            claim_token: &str,
            delivered_at: i64,
        ) -> Result<()> {
            self.with_schema(schema, |tx| {
                let changed = tx
                    .execute(
                        "UPDATE provider_events SET delivered_at=$4,last_error='',claim_token=NULL,claim_until=NULL
                         WHERE provider_kind=$1 AND id=$2 AND claim_token=$3 AND delivered_at IS NULL",
                        &[&provider_kind, &id, &claim_token, &delivered_at],
                    )
                    .map_err(pg)?;
                if changed == 0 {
                    return Err(StoreError::NotFound {
                        kind: "provider event",
                        id: id.into(),
                    });
                }
                Ok(())
            })
        }

        pub fn append_audit(&self, schema: &str, event: &AuditRecord) -> Result<()> {
            if event.id.is_empty()
                || event.principal.is_empty()
                || event.operation.is_empty()
                || event.outcome.is_empty()
            {
                return Err(StoreError::InvalidData {
                    kind: "audit event",
                    detail: "id, principal, operation, and outcome must be non-empty".into(),
                });
            }
            self.with_schema(schema, |tx| {
                tx.execute(
                    "INSERT INTO audit_events(id,occurred_at,principal,operation,resource,outcome)
                     VALUES($1,$2,$3,$4,$5,$6)",
                    &[
                        &event.id,
                        &event.occurred_at,
                        &event.principal,
                        &event.operation,
                        &event.resource,
                        &event.outcome,
                    ],
                )
                .map_err(pg)?;
                Ok(())
            })
        }

        pub fn audit_events(&self, schema: &str) -> Result<Vec<AuditRecord>> {
            self.with_schema(schema, |tx| {
                let rows = tx
                    .query(
                        "SELECT id,occurred_at,principal,operation,resource,outcome
                         FROM audit_events ORDER BY occurred_at,id",
                        &[],
                    )
                    .map_err(pg)?;
                Ok(rows
                    .into_iter()
                    .map(|row| AuditRecord {
                        id: row.get(0),
                        occurred_at: row.get(1),
                        principal: row.get(2),
                        operation: row.get(3),
                        resource: row.get(4),
                        outcome: row.get(5),
                    })
                    .collect())
            })
        }

        pub fn claim_runtime_plan(
            &self,
            schema: &str,
            environment: &str,
            plan_id: &str,
            owner: &str,
            expires_at: i64,
        ) -> Result<Option<RuntimeClaim>> {
            let now = crate::now_millis();
            if environment.is_empty() || plan_id.is_empty() || owner.is_empty() || expires_at <= now
            {
                return Err(StoreError::InvalidData {
                    kind: "runtime claim",
                    detail: "environment, plan, owner, and future expiry are required".into(),
                });
            }
            self.with_schema(schema, |tx| {
                let current = tx
                    .query_opt(
                        "SELECT environment_id,owner,generation,expires_at,completion_json
                         FROM runtime_claims WHERE plan_id = $1",
                        &[&plan_id],
                    )
                    .map_err(pg)?;
                let generation = match current {
                    Some(row) => {
                        let stored_env: String = row.get(0);
                        let stored_owner: String = row.get(1);
                        let generation: i64 = row.get(2);
                        let stored_expiry: i64 = row.get(3);
                        let completion: Option<String> = row.get(4);
                        if stored_env != environment {
                            return Err(StoreError::EnvironmentMismatch {
                                kind: "runtime claim",
                                id: plan_id.into(),
                                expected: stored_env,
                                actual: environment.into(),
                            });
                        }
                        if stored_owner == owner && completion.is_some() {
                            return Ok(Some(RuntimeClaim {
                                plan_id: plan_id.into(),
                                environment_id: stored_env,
                                owner: stored_owner,
                                generation: generation as u64,
                                expires_at: stored_expiry,
                                completion_json: completion,
                            }));
                        }
                        if completion.is_some() {
                            return Ok(None);
                        }
                        if stored_expiry > now && stored_owner == owner {
                            tx.execute(
                                "UPDATE runtime_claims SET expires_at = $2 WHERE plan_id = $1",
                                &[&plan_id, &expires_at],
                            )
                            .map_err(pg)?;
                            return Ok(Some(RuntimeClaim {
                                plan_id: plan_id.into(),
                                environment_id: stored_env,
                                owner: stored_owner,
                                generation: generation as u64,
                                expires_at,
                                completion_json: None,
                            }));
                        }
                        if stored_expiry > now {
                            return Ok(None);
                        }
                        (generation as u64).saturating_add(1)
                    }
                    None => 1,
                };
                let gen_i = generation as i64;
                tx.execute(
                    "INSERT INTO runtime_claims(plan_id,environment_id,owner,generation,expires_at)
                     VALUES($1,$2,$3,$4,$5)
                     ON CONFLICT(plan_id) DO UPDATE SET owner=EXCLUDED.owner,
                       generation=EXCLUDED.generation,expires_at=EXCLUDED.expires_at",
                    &[&plan_id, &environment, &owner, &gen_i, &expires_at],
                )
                .map_err(pg)?;
                Ok(Some(RuntimeClaim {
                    plan_id: plan_id.into(),
                    environment_id: environment.into(),
                    owner: owner.into(),
                    generation,
                    expires_at,
                    completion_json: None,
                }))
            })
        }

        pub fn renew_runtime_plan(
            &self,
            schema: &str,
            plan_id: &str,
            owner: &str,
            generation: u64,
            expires_at: i64,
        ) -> Result<Option<RuntimeClaim>> {
            let now = crate::now_millis();
            if plan_id.is_empty() || owner.is_empty() || generation == 0 || expires_at <= now {
                return Err(StoreError::InvalidData {
                    kind: "runtime heartbeat",
                    detail: "plan, owner, generation, and future expiry are required".into(),
                });
            }
            self.with_schema(schema, |tx| {
                let lease_gen = generation as i64;
                let changed = tx
                    .execute(
                        "UPDATE runtime_claims SET expires_at = $4
                         WHERE plan_id = $1 AND owner = $2 AND generation = $3
                           AND expires_at > $5 AND completion_json IS NULL",
                        &[&plan_id, &owner, &lease_gen, &expires_at, &now],
                    )
                    .map_err(pg)?;
                if changed == 0 {
                    return Ok(None);
                }
                let row = tx
                    .query_one(
                        "SELECT plan_id,environment_id,owner,generation,expires_at,completion_json
                         FROM runtime_claims WHERE plan_id = $1",
                        &[&plan_id],
                    )
                    .map_err(pg)?;
                Ok(Some(RuntimeClaim {
                    plan_id: row.get(0),
                    environment_id: row.get(1),
                    owner: row.get(2),
                    generation: row.get::<_, i64>(3) as u64,
                    expires_at: row.get(4),
                    completion_json: row.get(5),
                }))
            })
        }

        pub fn complete_runtime_plan(
            &self,
            schema: &str,
            plan_id: &str,
            owner: &str,
            generation: u64,
            completion_json: &str,
        ) -> Result<()> {
            self.with_schema(schema, |tx| {
                let row = tx
                    .query_opt(
                        "SELECT owner,generation,expires_at,completion_json FROM runtime_claims
                         WHERE plan_id = $1",
                        &[&plan_id],
                    )
                    .map_err(pg)?
                    .ok_or_else(|| StoreError::NotFound {
                        kind: "runtime claim",
                        id: plan_id.into(),
                    })?;
                let stored_owner: String = row.get(0);
                let stored_gen: i64 = row.get(1);
                let expiry: i64 = row.get(2);
                let completion: Option<String> = row.get(3);
                if stored_owner != owner {
                    return Err(StoreError::LeaseOwnerMismatch {
                        environment: plan_id.into(),
                        expected: stored_owner,
                        actual: owner.into(),
                    });
                }
                if stored_gen as u64 != generation {
                    return Err(StoreError::StaleLease {
                        environment: plan_id.into(),
                        expected: generation,
                        actual: stored_gen as u64,
                    });
                }
                if let Some(existing) = completion {
                    if existing != completion_json {
                        return Err(StoreError::ImmutableConflict {
                            kind: "runtime completion",
                            id: plan_id.into(),
                        });
                    }
                    return Ok(());
                }
                if expiry <= crate::now_millis() {
                    return Err(StoreError::LeaseExpired {
                        environment: plan_id.into(),
                        generation,
                    });
                }
                let lease_gen = generation as i64;
                tx.execute(
                    "UPDATE runtime_claims SET completion_json = $4
                     WHERE plan_id = $1 AND owner = $2 AND generation = $3 AND completion_json IS NULL",
                    &[&plan_id, &owner, &lease_gen, &completion_json],
                )
                .map_err(pg)?;
                Ok(())
            })
        }
    }

    fn migrate_tenant_schema(tx: &mut Transaction<'_>) -> Result<()> {
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
            CREATE INDEX IF NOT EXISTS rollbacks_recovery ON rollbacks(status, environment_id);
            CREATE TABLE IF NOT EXISTS provider_events (
                id TEXT NOT NULL, provider_kind TEXT NOT NULL,
                binding_digest TEXT NOT NULL, payload_json TEXT NOT NULL,
                attempts INTEGER NOT NULL, next_attempt_at BIGINT NOT NULL,
                delivered_at BIGINT, last_error TEXT NOT NULL,
                claim_token TEXT, claim_until BIGINT,
                PRIMARY KEY(provider_kind,id)
            );
            CREATE INDEX IF NOT EXISTS provider_events_delivery
                ON provider_events(delivered_at, next_attempt_at, id);
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
            ",
        )
        .map_err(pg)?;
        Ok(())
    }

    fn lease_in(tx: &mut Transaction<'_>, environment: &str) -> Result<Option<LeaseRecord>> {
        let row = tx
            .query_opt(
                "SELECT environment_id,owner,generation,expires_at FROM leases WHERE environment_id = $1",
                &[&environment],
            )
            .map_err(pg)?;
        Ok(row.map(|row| LeaseRecord {
            environment_id: row.get(0),
            owner: row.get(1),
            generation: row.get::<_, i64>(2) as u64,
            expires_at: row.get(3),
        }))
    }

    fn require_lease(
        tx: &mut Transaction<'_>,
        environment: &str,
        owner: &str,
        generation: u64,
        now: i64,
    ) -> Result<()> {
        let lease = lease_in(tx, environment)?.ok_or_else(|| StoreError::LeaseExpired {
            environment: environment.into(),
            generation,
        })?;
        if lease.expires_at <= now {
            return Err(StoreError::LeaseExpired {
                environment: environment.into(),
                generation: lease.generation,
            });
        }
        if lease.owner != owner {
            return Err(StoreError::LeaseOwnerMismatch {
                environment: environment.into(),
                expected: lease.owner,
                actual: owner.into(),
            });
        }
        if lease.generation != generation {
            return Err(StoreError::StaleLease {
                environment: environment.into(),
                expected: generation,
                actual: lease.generation,
            });
        }
        Ok(())
    }

    fn require_plan_environment(
        tx: &mut Transaction<'_>,
        plan_id: &str,
        environment: &str,
    ) -> Result<()> {
        let stored: String = tx
            .query_opt(
                "SELECT environment_id FROM plans WHERE id = $1",
                &[&plan_id],
            )
            .map_err(pg)?
            .map(|row| row.get(0))
            .ok_or_else(|| StoreError::NotFound {
                kind: "plan",
                id: plan_id.into(),
            })?;
        if stored != environment {
            return Err(StoreError::EnvironmentMismatch {
                kind: "plan",
                id: plan_id.into(),
                expected: stored,
                actual: environment.into(),
            });
        }
        Ok(())
    }

    fn rollback_in(tx: &mut Transaction<'_>, id: &str) -> Result<Option<RollbackRecord>> {
        let row = tx
            .query_opt(
                "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail
                 FROM rollbacks WHERE id = $1",
                &[&id],
            )
            .map_err(pg)?;
        row.map(|row| {
            let status: String = row.get(5);
            Ok(RollbackRecord {
                id: row.get(0),
                environment_id: row.get(1),
                plan_id: row.get(2),
                lease_generation: row.get::<_, i64>(3) as u64,
                checkpoint_json: row.get(4),
                status: RollbackStatus::parse(&status)?,
                status_detail: row.get(6),
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_are_safe() {
        assert_eq!(tenant_schema_name("tenant-a").unwrap(), "tenkai_t_tenant_a");
        assert!(tenant_schema_name("").is_err());
        assert!(tenant_schema_name("evil;drop").is_err());
        assert!(tenant_schema_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn config_rejects_non_postgres_urls() {
        assert!(PostgresTenantConfig::new("postgres://localhost/tenkai").is_ok());
        assert!(PostgresTenantConfig::new("postgresql://localhost/tenkai").is_ok());
        assert!(PostgresTenantConfig::new("mysql://localhost/tenkai").is_err());
        assert!(PostgresTenantConfig::new("").is_err());
    }

    #[test]
    fn open_without_feature_fails_closed() {
        if postgres_feature_enabled() {
            return;
        }
        let config = PostgresTenantConfig::new("postgres://localhost/tenkai").unwrap();
        let err = match config.open() {
            Ok(_) => panic!("open should fail without postgres feature"),
            Err(error) => error.to_string(),
        };
        assert!(err.contains("features postgres") || err.contains("postgres"));
    }

    #[test]
    fn capabilities_advertise_tenant_not_ha() {
        let caps = tenant_postgres_store_capabilities();
        let names = caps.names().join(",");
        assert!(names.contains("tenant_isolation"));
        assert!(names.contains("operational_store_migration"));
        assert!(!names.contains("high_availability"));
        assert!(!names.contains("shared_replica_state"));
    }

    #[test]
    fn resolve_server_tenant_store_community_is_none() {
        let resolved = resolve_server_tenant_store(false).unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_server_tenant_store_fails_closed_without_feature_or_url() {
        let err = match resolve_server_tenant_store(true) {
            Ok(_) => panic!("tenant mode without config must fail closed"),
            Err(error) => error.to_string(),
        };
        assert!(
            err.contains("features postgres")
                || err.contains("TENKAI_POSTGRES_URL")
                || err.contains("postgres"),
            "{err}"
        );
    }

    /// Live isolation drill. Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
    #[cfg(feature = "postgres")]
    #[test]
    #[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
    fn live_postgres_tenant_isolation() {
        use crate::auth_context::{
            AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
            TenantDerivationAuthority,
        };
        use crate::storage::{OperationalStore as _, ReleaseRecord};

        let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
        let store = config.open().expect("connect");
        let authority = TenantDerivationAuthority::new("test");
        let ctx_a = AuthenticatedRequestContextBuilder::new(
            "r-a",
            PrincipalIdentity {
                id: "user-a".into(),
                kind: PrincipalKind::Human,
            },
            "test",
        )
        .with_tenant("tenant-a", &authority)
        .unwrap()
        .build()
        .unwrap();
        let ctx_b = AuthenticatedRequestContextBuilder::new(
            "r-b",
            PrincipalIdentity {
                id: "user-b".into(),
                kind: PrincipalKind::Human,
            },
            "test",
        )
        .with_tenant("tenant-b", &authority)
        .unwrap()
        .build()
        .unwrap();
        store
            .run_partition_isolation_check(&ctx_a, &ctx_b, "env-a", "env-b")
            .unwrap();
        let part = store.partition_for(&ctx_a).unwrap();
        part.check_health().unwrap();
        part.publish_release(&ReleaseRecord {
            id: "rel-1".into(),
            product: "api".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:a".into(),
            descriptor_json: "{}".into(),
        })
        .unwrap();
        assert!(part.get_release("rel-1").unwrap().is_some());
    }
}

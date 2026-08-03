//! Tenant-isolating operational store port and in-memory adapter.
//!
//! Community hosts keep using [`crate::storage::SqliteStore`] (tenant-free).
//! Enterprise hosts that enable tenant mode use a store that advertises
//! `tenant_isolation` and enforces tenant-scoped reads/writes.
//!
//! - In-memory partitions: this module (`InMemoryTenantOperationalStore`).
//! - Production hub Postgres: optional [`crate::postgres_tenant`] (feature
//!   `postgres`, schema-per-tenant, never identity-plane co-location).
//!
//! The adapter never shares a database with an identity plane (ADR 0005).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::auth_context::AuthenticatedRequestContext;
use crate::runtime_capabilities::{
    Capability, CapabilityName, ComponentCapabilities, RUNTIME_CAPABILITY_CONTRACT_VERSION,
};
use crate::storage::{
    AuditRecord, ChannelRecord, EnvironmentRecord, LeaseRecord, OfflineImportRecord,
    OfflineStepImportRecord, OperationalStore, PlanRecord, PlanStatus, ProviderEventRecord,
    ReceiptRecord, ReleaseRecord, Result, RollbackRecord, RollbackStatus, RuntimeClaim,
    SCHEMA_VERSION, SqliteStore,
};
use crate::tenant_isolation::{
    IsolationError, TenantIsolationHarness, TenantResources, TwoTenantFixture,
};

/// Application port for multi-tenant operational access used by the server host.
///
/// Community hosts leave this unset. Enterprise tenant mode requires an
/// implementation (in-memory for tests, Postgres for durable hub recovery).
pub trait TenantOperationalStore: Send + Sync {
    fn runtime_capabilities(&self) -> ComponentCapabilities;

    fn check_health(&self) -> Result<()> {
        Ok(())
    }

    fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError>;

    fn put_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &EnvironmentRecord,
    ) -> std::result::Result<EnvironmentRecord, IsolationError>;

    fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError>;

    fn import_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
    ) -> std::result::Result<crate::development_fixtures::FixtureMap, IsolationError>;

    fn reset_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture_id: &str,
    ) -> std::result::Result<crate::development_fixtures::FixtureResetResult, IsolationError>;

    fn development_fixture_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<
        Option<crate::development_fixtures::FixtureEnvironmentProjection>,
        IsolationError,
    >;
}

/// Capability advertisement for the in-memory tenant-isolating store adapter.
pub fn tenant_memory_store_capabilities() -> ComponentCapabilities {
    ComponentCapabilities::new(
        "store.tenant_memory",
        [
            Capability::named(
                CapabilityName::TenantIsolation,
                RUNTIME_CAPABILITY_CONTRACT_VERSION,
            ),
            Capability::migration(SCHEMA_VERSION),
        ],
    )
}

/// Enterprise multi-tenant operational store factory (in-memory partitions).
///
/// Each authenticated tenant receives an isolated [`SqliteStore`] partition.
/// Cross-tenant access is denied with a non-disclosing error. This is a
/// conformance and wiring adapter, not a commercial multi-tenant database.
#[derive(Clone)]
pub struct InMemoryTenantOperationalStore {
    partitions: Arc<Mutex<BTreeMap<String, Arc<SqliteStore>>>>,
    #[cfg(test)]
    healthy: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for InMemoryTenantOperationalStore {
    fn default() -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(test)]
            healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

impl InMemoryTenantOperationalStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_memory_store_capabilities()
    }

    #[cfg(test)]
    pub(crate) fn set_healthy(&self, healthy: bool) {
        self.healthy
            .store(healthy, std::sync::atomic::Ordering::SeqCst);
    }

    /// Open (or return) the operational partition for the authenticated tenant.
    pub fn partition_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<TenantPartition, IsolationError> {
        context
            .validate()
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        let tenant_id = context
            .tenant()
            .map(|tenant| tenant.tenant_id().to_string())
            .ok_or(IsolationError::Unauthenticated)?;
        if tenant_id.trim().is_empty() {
            return Err(IsolationError::Unauthenticated);
        }
        self.partition_by_id(&tenant_id)
    }

    fn partition_by_id(
        &self,
        tenant_id: &str,
    ) -> std::result::Result<TenantPartition, IsolationError> {
        let mut partitions = self
            .partitions
            .lock()
            .map_err(|_| IsolationError::Contract("tenant store mutex poisoned".into()))?;
        if let Some(store) = partitions.get(tenant_id) {
            return Ok(TenantPartition {
                tenant_id: tenant_id.to_string(),
                store: store.clone(),
            });
        }
        let store = Arc::new(SqliteStore::open_in_memory().map_err(|error| {
            IsolationError::Contract(format!("opening tenant partition: {error}"))
        })?);
        partitions.insert(tenant_id.to_string(), store.clone());
        Ok(TenantPartition {
            tenant_id: tenant_id.to_string(),
            store,
        })
    }

    /// Deny cross-tenant environment access with the harness non-disclosing posture.
    pub fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        let partition = self.partition_for(context)?;
        match partition.store.get_environment(environment_id) {
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
            .store
            .put_environment(environment)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .store
            .list_environment_ids()
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn import_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
    ) -> std::result::Result<crate::development_fixtures::FixtureMap, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .import_development_fixture(fixture, context.principal_id(), &context.request_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn reset_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture_id: &str,
    ) -> std::result::Result<crate::development_fixtures::FixtureResetResult, IsolationError> {
        let partition = self.partition_for(context)?;
        partition
            .reset_development_fixture(fixture_id, context.principal_id(), &context.request_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    pub fn development_fixture_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<
        Option<crate::development_fixtures::FixtureEnvironmentProjection>,
        IsolationError,
    > {
        self.partition_for(context)?
            .development_fixture_environment(environment_id)
            .map_err(|error| IsolationError::Contract(error.to_string()))
    }

    /// Run the isolation harness plus store-partition isolation checks.
    pub fn run_conformance(&self) -> std::result::Result<(), IsolationError> {
        let harness = TenantIsolationHarness::new()
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        harness.run_conformance()?;
        let fixture = TwoTenantFixture::new();
        let ctx_a = context_for(&harness, &fixture.tenant_a)?;
        let ctx_b = context_for(&harness, &fixture.tenant_b)?;
        self.put_environment_for(
            &ctx_a,
            &EnvironmentRecord {
                id: fixture.tenant_a.environment_id.clone(),
                revision: 0,
                configuration_json: r#"{"tenant":"a"}"#.into(),
            },
        )?;
        self.put_environment_for(
            &ctx_b,
            &EnvironmentRecord {
                id: fixture.tenant_b.environment_id.clone(),
                revision: 0,
                configuration_json: r#"{"tenant":"b"}"#.into(),
            },
        )?;
        let listed_a = self.list_environment_ids_for(&ctx_a)?;
        if listed_a != vec![fixture.tenant_a.environment_id.clone()] {
            return Err(IsolationError::Contract(
                "tenant partition list leaked or missed environments".into(),
            ));
        }
        if listed_a
            .iter()
            .any(|id| id == &fixture.tenant_b.environment_id)
        {
            return Err(IsolationError::Contract(
                "tenant partition list leaked foreign environment".into(),
            ));
        }
        match self.get_environment_for(&ctx_a, &fixture.tenant_b.environment_id) {
            Err(IsolationError::NotFound) => Ok(()),
            Ok(_) => Err(IsolationError::Contract(
                "cross-tenant environment get succeeded".into(),
            )),
            Err(other) => Err(other),
        }
    }
}

impl TenantOperationalStore for InMemoryTenantOperationalStore {
    fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_memory_store_capabilities()
    }

    fn check_health(&self) -> Result<()> {
        #[cfg(test)]
        if !self.healthy.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::storage::StoreError::AdapterUnavailable(
                "synthetic tenant store outage".into(),
            ));
        }
        Ok(())
    }

    fn get_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        InMemoryTenantOperationalStore::get_environment_for(self, context, environment_id)
    }

    fn put_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment: &EnvironmentRecord,
    ) -> std::result::Result<EnvironmentRecord, IsolationError> {
        InMemoryTenantOperationalStore::put_environment_for(self, context, environment)
    }

    fn list_environment_ids_for(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> std::result::Result<Vec<String>, IsolationError> {
        InMemoryTenantOperationalStore::list_environment_ids_for(self, context)
    }

    fn import_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
    ) -> std::result::Result<crate::development_fixtures::FixtureMap, IsolationError> {
        InMemoryTenantOperationalStore::import_development_fixture_for(self, context, fixture)
    }

    fn reset_development_fixture_for(
        &self,
        context: &AuthenticatedRequestContext,
        fixture_id: &str,
    ) -> std::result::Result<crate::development_fixtures::FixtureResetResult, IsolationError> {
        InMemoryTenantOperationalStore::reset_development_fixture_for(self, context, fixture_id)
    }

    fn development_fixture_environment_for(
        &self,
        context: &AuthenticatedRequestContext,
        environment_id: &str,
    ) -> std::result::Result<
        Option<crate::development_fixtures::FixtureEnvironmentProjection>,
        IsolationError,
    > {
        InMemoryTenantOperationalStore::development_fixture_environment_for(
            self,
            context,
            environment_id,
        )
    }
}

fn context_for(
    harness: &TenantIsolationHarness,
    tenant: &TenantResources,
) -> std::result::Result<AuthenticatedRequestContext, IsolationError> {
    harness
        .valid_context(tenant)
        .map_err(|error| IsolationError::InvalidCredential(error.to_string()))
}

/// One tenant's operational partition. Implements [`OperationalStore`].
#[derive(Clone)]
pub struct TenantPartition {
    tenant_id: String,
    store: Arc<SqliteStore>,
}

impl TenantPartition {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

impl OperationalStore for TenantPartition {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()> {
        self.store.publish_release(release)
    }
    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>> {
        self.store.get_release(id)
    }
    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        self.store.promote_channel(channel)
    }
    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord> {
        self.store.put_environment(environment)
    }
    fn create_plan(&self, plan: &PlanRecord) -> Result<()> {
        self.store.create_plan(plan)
    }
    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>> {
        self.store.get_plan(id)
    }
    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        self.store
            .transition_plan(id, owner, generation, status, detail)
    }
    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        self.store.acquire_lease(environment, owner, expires_at)
    }
    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>> {
        self.store.current_lease(environment)
    }
    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        self.store.record_receipt(owner, receipt)
    }
    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>> {
        self.store.get_receipt(id)
    }
    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        self.store.record_offline_import(receipt, steps)
    }
    fn get_offline_import(&self, bundle_digest: &str) -> Result<Option<OfflineImportRecord>> {
        self.store.get_offline_import(bundle_digest)
    }
    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()> {
        self.store.create_rollback(owner, rollback)
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
        self.store
            .transition_rollback(id, owner, generation, status, checkpoint_json, detail)
    }
    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>> {
        self.store.pending_rollbacks()
    }
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()> {
        self.store.enqueue_provider_event(event)
    }
    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.store
            .list_provider_events(provider_kind, environment_id, limit)
    }
    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.store
            .claim_provider_events(now, limit, claim_token, claim_until)
    }
    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.store.claim_provider_events_for_kind(
            provider_kind,
            now,
            limit,
            claim_token,
            claim_until,
        )
    }
    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        self.store
            .record_provider_failure(provider_kind, id, claim_token, next_attempt_at, error)
    }
    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        self.store
            .mark_provider_event_delivered(provider_kind, id, claim_token, delivered_at)
    }
    fn append_audit(&self, event: &AuditRecord) -> Result<()> {
        self.store.append_audit(event)
    }
    fn audit_events(&self) -> Result<Vec<AuditRecord>> {
        self.store.audit_events()
    }
    fn check_health(&self) -> Result<()> {
        self.store.check_health()
    }
    fn import_development_fixture(
        &self,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        self.store
            .import_development_fixture(fixture, actor, request_id)
    }
    fn reset_development_fixture(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        self.store
            .reset_development_fixture(fixture_id, actor, request_id)
    }
    fn development_fixture_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        self.store.development_fixture_environment(environment_id)
    }
    fn runtime_capabilities(&self) -> ComponentCapabilities {
        // Partition claims the multi-tenant adapter identity so hosts never
        // advertise a tenant-free store under tenant mode.
        tenant_memory_store_capabilities()
    }
    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.store
            .claim_runtime_plan(environment, plan_id, owner, expires_at)
    }
    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.store
            .renew_runtime_plan(plan_id, owner, generation, expires_at)
    }
    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        self.store
            .complete_runtime_plan(plan_id, owner, generation, completion_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_capabilities::{
        RuntimeRequirements, community_auth_capabilities, community_sqlite_profile,
        validate_runtime_capabilities,
    };
    use crate::tenant_isolation::NON_DISCLOSING_DENY;

    #[test]
    fn advertises_tenant_isolation_and_migration_level() {
        let store = InMemoryTenantOperationalStore::new();
        let capabilities = store.runtime_capabilities();
        assert_eq!(capabilities.component_id, "store.tenant_memory");
        let names = capabilities.names();
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("tenant_isolation")),
            "{names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.contains("operational_store_migration")),
            "{names:?}"
        );
    }

    #[test]
    fn community_sqlite_remains_tenant_free() {
        let community = community_sqlite_profile(community_auth_capabilities());
        assert!(
            !community
                .diagnostic_names()
                .iter()
                .any(|name| name.contains("tenant_isolation"))
        );
        let store = SqliteStore::open_in_memory().unwrap();
        let names = store.runtime_capabilities().names();
        assert!(!names.iter().any(|name| name.contains("tenant_isolation")));
    }

    #[test]
    fn tenant_mode_accepts_tenant_memory_capability() {
        let mut provided = community_sqlite_profile(community_auth_capabilities());
        provided.components = vec![
            tenant_memory_store_capabilities(),
            community_auth_capabilities(),
        ];
        provided.profile = "enterprise-tenant-memory".into();
        validate_runtime_capabilities(
            &provided,
            &RuntimeRequirements {
                tenant_mode: true,
                ..RuntimeRequirements::community()
            },
        )
        .unwrap();
    }

    #[test]
    fn cross_tenant_environment_access_is_non_disclosing() {
        let store = InMemoryTenantOperationalStore::new();
        let harness = TenantIsolationHarness::new().unwrap();
        let fixture = &harness.fixture;
        let ctx_a = harness.valid_context(&fixture.tenant_a).unwrap();
        let ctx_b = harness.valid_context(&fixture.tenant_b).unwrap();
        store
            .put_environment_for(
                &ctx_a,
                &EnvironmentRecord {
                    id: "env-a".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();
        store
            .put_environment_for(
                &ctx_b,
                &EnvironmentRecord {
                    id: "env-b".into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();

        let listed = store.list_environment_ids_for(&ctx_a).unwrap();
        assert_eq!(listed, vec!["env-a".to_string()]);
        assert!(!listed.contains(&"env-b".to_string()));

        let err = store.get_environment_for(&ctx_a, "env-b").unwrap_err();
        assert!(matches!(err, IsolationError::NotFound));
        assert_eq!(err.to_string(), NON_DISCLOSING_DENY);
        assert!(!err.to_string().contains("tenant-b"));
        assert!(!err.public_message().contains("env-b"));
    }

    #[test]
    fn harness_and_store_conformance_pass() {
        let store = InMemoryTenantOperationalStore::new();
        store.run_conformance().unwrap();
    }

    #[test]
    fn partition_implements_operational_store_with_tenant_capability() {
        let store = InMemoryTenantOperationalStore::new();
        let harness = TenantIsolationHarness::new().unwrap();
        let ctx = harness.valid_context(&harness.fixture.tenant_a).unwrap();
        let partition = store.partition_for(&ctx).unwrap();
        partition
            .put_environment(&EnvironmentRecord {
                id: "prod".into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
        let names = partition.runtime_capabilities().names();
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("tenant_isolation"))
        );
        assert_eq!(partition.tenant_id(), harness.fixture.tenant_a.tenant_id);
    }
}

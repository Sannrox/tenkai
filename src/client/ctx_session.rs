//! Embedded construction, outcome inspection, and Plan retarget ticks.

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::OnceCell;

use super::{
    Backend, Ctx, PlanKindListSnapshot, PlanKindListTick, PlanRetargetTickGuard, block_operational,
};
use crate::pb::record::Object;
use crate::storage::OperationalStore;
#[cfg(any(test, feature = "test-support"))]
use crate::storage::StoreBackup;

impl Ctx {
    /// Configure host-owned release roots for deployment re-verification.
    pub fn with_release_trust_roots(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.release_trust_roots = path;
        self.require_host_release_trust = true;
        self
    }
    /// Open a throwaway in-memory session for tests. Path-keyed so a reopen
    /// of the same path sees the same maps. Community hosts that persist a
    /// SQLite file use `tenkai_sqlite::embedded_ctx`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn embedded(path: impl AsRef<Path>) -> Result<Self> {
        crate::storage::refuse_postgres_on_embedded().map_err(anyhow::Error::from)?;
        Self::memory_application_state(path)
    }

    /// Test helper matching the former hub constructor (Postgres URL allowed).
    #[cfg(any(test, feature = "test-support"))]
    pub fn embedded_hub(path: impl AsRef<Path>) -> Result<Self> {
        Self::memory_application_state(path)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn memory_application_state(path: impl AsRef<Path>) -> Result<Self> {
        let store = std::sync::Arc::new(crate::storage::MemoryCatalogGraph::open(path)?);
        let backup = std::sync::Arc::clone(&store);
        Ok(Self::from_embedded(
            std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::storage::CatalogGraph>,
            store as std::sync::Arc<dyn crate::storage::OperationalStore>,
            move |destination: &Path| backup.backup(destination),
        ))
    }

    /// Open an in-process session from store ports. Hosts that open a SQLite
    /// file construct the adapter in `tenkai-sqlite` and pass it here.
    pub fn from_embedded(
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        operational: Arc<dyn crate::storage::OperationalStore>,
        backup: impl Fn(&Path) -> anyhow::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            backend: Backend::Embedded {
                catalog,
                operational,
                backup: Arc::new(backup),
            },
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_inspection_enabled: true,
            release_trust_roots: None,
            require_host_release_trust: false,
            plan_kind_list: Arc::new(PlanKindListTick::default()),
            health_metrics: None,
            trust_sources: None,
            execution_capabilities: None,
            held_execution_leases: Vec::new(),
            plan_proposer: None,
            release_reads: std::sync::Weak::new(),
        }
    }

    /// Enterprise hub catalog port. PostgreSQL owns authority; this context
    /// does not open SQLite. Writes fail closed until a catalog and tenant
    /// are bound.
    pub fn tenant_hub() -> Self {
        Self::tenant_hub_backend(None, None)
    }

    /// Tenant-mode hub with a catalog adapter. Bind the tenant from the
    /// authenticated request before catalog writes.
    pub fn tenant_hub_catalog(catalog: Arc<dyn crate::storage::CatalogGraph>) -> Self {
        Self::tenant_hub_backend(Some(catalog), None)
    }

    fn tenant_hub_backend(
        catalog: Option<Arc<dyn crate::storage::CatalogGraph>>,
        tenant: Option<String>,
    ) -> Self {
        Self {
            backend: Backend::TenantHub { catalog, tenant },
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_inspection_enabled: true,
            release_trust_roots: None,
            require_host_release_trust: false,
            plan_kind_list: Arc::new(PlanKindListTick::default()),
            health_metrics: None,
            trust_sources: None,
            execution_capabilities: None,
            held_execution_leases: Vec::new(),
            plan_proposer: None,
            release_reads: std::sync::Weak::new(),
        }
    }

    /// Bind catalog writes and reads to one tenant schema.
    pub fn with_catalog_tenant(mut self, tenant: impl Into<String>) -> Self {
        if let Backend::TenantHub { tenant: bound, .. } = &mut self.backend {
            *bound = Some(tenant.into());
        }
        self
    }

    /// Certificates this host serves and trusts, so plans can flag one that
    /// lapses before the next maintenance window (#778).
    pub fn with_trust_sources(mut self, sources: Arc<crate::trust_posture::TrustSources>) -> Self {
        self.trust_sources = Some(sources);
        self
    }

    pub(crate) fn trust_sources(&self) -> Option<&crate::trust_posture::TrustSources> {
        self.trust_sources.as_deref()
    }

    /// Where planning reads the executor sets of the replicas and runtimes
    /// that run steps (ADR 0057). Without one, the planning process's own
    /// executors are the set.
    pub fn with_execution_capabilities(
        mut self,
        source: Arc<dyn crate::execution_capabilities::ExecutionCapabilitySource>,
    ) -> Self {
        self.execution_capabilities = Some(source);
        self
    }

    pub fn execution_capabilities(
        &self,
    ) -> Option<Arc<dyn crate::execution_capabilities::ExecutionCapabilitySource>> {
        self.execution_capabilities.clone()
    }

    /// Inject a Prometheus-compatible instant-query source for SLO gates (#590).
    pub fn with_health_metrics(
        mut self,
        source: Arc<dyn crate::health_gate::HealthMetricsSource>,
    ) -> Self {
        self.health_metrics = Some(source);
        self
    }

    pub fn health_metrics(&self) -> Option<Arc<dyn crate::health_gate::HealthMetricsSource>> {
        self.health_metrics.clone()
    }

    pub fn set_health_metrics(&mut self, source: Arc<dyn crate::health_gate::HealthMetricsSource>) {
        self.health_metrics = Some(source);
    }

    /// Record who requested this plan so the approval brief can name them.
    pub fn set_plan_proposer(&mut self, proposer: crate::plan::PlanProposer) {
        self.plan_proposer = Some(proposer);
    }

    pub(crate) fn plan_proposer(&self) -> crate::plan::PlanProposer {
        self.plan_proposer.clone().unwrap_or_default()
    }

    pub fn is_embedded(&self) -> bool {
        matches!(self.backend, Backend::Embedded { .. })
    }

    pub(crate) fn is_tenant_hub(&self) -> bool {
        matches!(self.backend, Backend::TenantHub { .. })
    }

    pub(crate) fn has_catalog(&self) -> bool {
        matches!(
            self.backend,
            Backend::TenantHub {
                catalog: Some(_),
                ..
            }
        )
    }

    /// A tenant hub with a catalog but no bound tenant: the process-level
    /// context. Its catalog reads fail with "tenant not bound".
    pub(crate) fn tenant_unbound(&self) -> bool {
        matches!(
            self.backend,
            Backend::TenantHub {
                catalog: Some(_),
                tenant: None,
            }
        )
    }

    /// Bound catalog for this session: community embedded (tenant `None`) or a
    /// hub tenant. Unbound and remote sessions return `None`.
    pub(crate) fn catalog_port(
        &self,
    ) -> Option<(Arc<dyn crate::storage::CatalogGraph>, Option<String>)> {
        match &self.backend {
            Backend::Embedded { catalog, .. } => Some((Arc::clone(catalog), None)),
            Backend::TenantHub {
                catalog: Some(catalog),
                tenant: Some(tenant),
            } => Some((Arc::clone(catalog), Some(tenant.clone()))),
            _ => None,
        }
    }

    pub(crate) fn operational_store(&self) -> Option<Arc<dyn OperationalStore>> {
        match &self.backend {
            Backend::Embedded { operational, .. } => Some(Arc::clone(operational)),
            _ => None,
        }
    }

    /// Whether this context is already bound to a reconcile-tick Plan kind-list
    /// cell. Inspect and other one-shot paths stay unbound and list once per call.
    pub(crate) fn shares_plan_retarget_tick(&self) -> bool {
        self.plan_kind_list.tick_cell().is_some()
    }

    /// Clone a tick-local context that shares one Plan kind-list among the
    /// tick's environment workers, embedded or remote. The original context is unchanged, so
    /// inspect and other one-shot paths still list once per call.
    ///
    /// Dropping the returned guard ends the tick even if the caller is
    /// cancelled.
    pub(crate) fn with_shared_plan_retarget_tick(&self) -> (Self, PlanRetargetTickGuard) {
        let scan = Arc::new(PlanKindListTick::default());
        scan.begin();
        let mut ctx = self.clone();
        ctx.plan_kind_list = Arc::clone(&scan);
        (ctx, PlanRetargetTickGuard::new(scan))
    }

    /// Kind-list plans for environment-index retarget detection.
    ///
    /// During a reconcile tick this reuses one kind-list. Outside
    /// a tick it lists once per call so inspect is not served a stale catalog.
    pub(crate) async fn list_plans_for_retarget(&mut self) -> Result<Arc<Vec<Object>>> {
        Ok(Arc::clone(&self.list_plan_kind_snapshot().await?.objects))
    }

    pub(crate) async fn list_plan_kind_snapshot(&mut self) -> Result<Arc<PlanKindListSnapshot>> {
        let Some(cell) = self.plan_kind_list.tick_cell() else {
            return Ok(PlanKindListSnapshot::from_objects(
                self.list_kind(crate::ontology::KIND_PLAN).await?,
            ));
        };
        if let Some(snapshot) = cell.get() {
            return Ok(Arc::clone(snapshot));
        }
        let list = Arc::clone(&self.plan_kind_list);
        let _fill = list.fill.lock().await;
        if let Some(snapshot) = cell.get() {
            return Ok(Arc::clone(snapshot));
        }
        let snapshot =
            PlanKindListSnapshot::from_objects(self.list_kind(crate::ontology::KIND_PLAN).await?);
        let _ = cell.set(Arc::clone(&snapshot));
        Ok(snapshot)
    }

    /// Read the bounded Tenkai-owned terminal-outcome projection for one
    /// environment.
    pub(crate) async fn terminal_outcomes(
        &self,
        environment: &str,
        as_of: i64,
    ) -> Result<Vec<crate::providers::TerminalOutcomeProjection>> {
        if !self.outcome_inspection_enabled {
            return Ok(Vec::new());
        }
        let Some(store) = self.operational_store() else {
            return Ok(Vec::new());
        };
        let environment = environment.to_string();
        block_operational(store, move |store| {
            let records = store.list_provider_events(
                crate::providers::OUTCOME_PROVIDER_KIND,
                &environment,
                128,
            )?;
            crate::providers::project_terminal_outcomes(&records, &environment, as_of)
                .map_err(anyhow::Error::from)
        })
        .await
    }

    pub async fn backup_embedded(&self, destination: impl AsRef<Path>) -> Result<()> {
        let backup = match &self.backend {
            Backend::Embedded { backup, .. } => Arc::clone(backup),
            _ => anyhow::bail!("backup is available only in embedded mode"),
        };
        let destination = destination.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || backup(&destination))
            .await
            .unwrap_or_else(|error| Err(anyhow::anyhow!("embedded backup task failed: {error}")))
    }
}

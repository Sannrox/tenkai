//! Embedded construction, outcome inspection, and Plan retarget ticks.

use anyhow::{Context as _, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::OnceCell;

use super::{
    Backend, Ctx, PlanKindListSnapshot, PlanKindListTick, PlanRetargetTickGuard, block_embedded,
};
use crate::pb::sekai::Object;
use crate::storage::OperationalStore;

impl Ctx {
    /// Open the complete in-process backend used by the solo CLI.
    pub fn embedded(path: impl AsRef<Path>) -> Result<Self> {
        Self::embedded_with_outcome_export(path, false)
    }

    /// Open embedded application state and optionally enable atomic terminal
    /// outcome enqueueing into the Tenkai-owned provider outbox.
    pub fn embedded_with_outcome_export(
        path: impl AsRef<Path>,
        outcome_export_enabled: bool,
    ) -> Result<Self> {
        let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
        Ok(Self {
            backend: Backend::Embedded(Arc::new(crate::storage::SqliteStore::open_embedded(
                path, principal,
            )?)),
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_export_enabled,
            outcome_inspection_enabled: true,
            plan_kind_list: Arc::new(PlanKindListTick::default()),
        })
    }

    pub fn is_embedded(&self) -> bool {
        matches!(self.backend, Backend::Embedded(_))
    }

    /// Whether this context is already bound to a reconcile-tick Plan kind-list
    /// cell. Inspect and other one-shot paths stay unbound and list once per call.
    pub(crate) fn shares_plan_retarget_tick(&self) -> bool {
        self.plan_kind_list.tick_cell().is_some()
    }

    /// Clone a tick-local context that shares one remote Plan kind-list among
    /// concurrent environment workers. The original context is unchanged, so
    /// inspect and other one-shot paths still list once per call.
    ///
    /// Dropping the returned guard ends the tick even if the caller is
    /// cancelled.
    pub(crate) fn with_shared_plan_retarget_tick(&self) -> (Self, PlanRetargetTickGuard) {
        let scan = Arc::new(PlanKindListTick::default());
        if !self.is_embedded() {
            scan.begin();
        }
        let mut ctx = self.clone();
        ctx.plan_kind_list = Arc::clone(&scan);
        (ctx, PlanRetargetTickGuard::new(scan))
    }

    /// Kind-list plans for environment-index retarget detection.
    ///
    /// During a reconcile tick this reuses one `ListObjects` transfer. Outside
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

    pub(crate) fn outcome_export_enabled(&self) -> bool {
        self.outcome_export_enabled
    }

    pub(crate) fn without_outcome_export(&self) -> Self {
        let mut context = self.clone();
        context.outcome_export_enabled = false;
        context.outcome_inspection_enabled = false;
        context
    }

    /// Read the bounded Tenkai-owned terminal-outcome projection for one
    /// environment. Remote provider mode has no local outbox to inspect; its
    /// authenticated server host supplies the same projection from its local
    /// operational store.
    pub(crate) async fn terminal_outcomes(
        &self,
        environment: &str,
        as_of: i64,
    ) -> Result<Vec<crate::providers::TerminalOutcomeProjection>> {
        if !self.outcome_inspection_enabled {
            return Ok(Vec::new());
        }
        let Some(store) = self.embedded_arc() else {
            return Ok(Vec::new());
        };
        let environment = environment.to_string();
        block_embedded(store, move |store| {
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
        let store = self
            .embedded_arc()
            .context("backup is available only in embedded mode")?;
        let destination = destination.as_ref().to_path_buf();
        block_embedded(store, move |store| store.backup(destination)).await
    }
}

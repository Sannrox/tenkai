//! Tick-scoped remote Plan kind-list sharing for retarget detection.

#[cfg(test)]
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use tokio::sync::OnceCell;

use crate::pb::sekai::Object;

/// Tick-scoped remote `ListObjects` of `KIND_PLAN` for retarget detection.
///
/// Reconcile environments run concurrently and must share one catalog
/// transfer. Inspect and other one-shot paths leave the cell empty and list
/// once per call.
type PlanKindListCell = Arc<OnceCell<Arc<PlanKindListSnapshot>>>;

/// One tick-local Plan kind-list plus a lazily built env→id omit index.
pub(crate) struct PlanKindListSnapshot {
    pub(crate) objects: Arc<Vec<Object>>,
    omit_index: OnceLock<HashMap<String, HashSet<String>>>,
}

impl PlanKindListSnapshot {
    pub(super) fn from_objects(objects: Vec<Object>) -> Arc<Self> {
        Arc::new(Self {
            objects: Arc::new(objects),
            omit_index: OnceLock::new(),
        })
    }

    pub(crate) fn omit_ids(
        &self,
        build: impl FnOnce(&[Object]) -> HashMap<String, HashSet<String>>,
    ) -> &HashMap<String, HashSet<String>> {
        self.omit_index.get_or_init(|| build(&self.objects))
    }
}

pub(crate) struct PlanKindListTick {
    cell: std::sync::Mutex<Option<PlanKindListCell>>,
    pub(super) fill: tokio::sync::Mutex<()>,
}

impl Default for PlanKindListTick {
    fn default() -> Self {
        Self {
            cell: std::sync::Mutex::new(None),
            fill: tokio::sync::Mutex::new(()),
        }
    }
}

impl PlanKindListTick {
    pub(super) fn begin(&self) {
        *self.cell.lock().expect("plan kind-list tick lock") = Some(Arc::new(OnceCell::new()));
    }

    pub(super) fn end(&self) {
        *self.cell.lock().expect("plan kind-list tick lock") = None;
    }

    pub(super) fn tick_cell(&self) -> Option<PlanKindListCell> {
        self.cell.lock().expect("plan kind-list tick lock").clone()
    }

    #[cfg(test)]
    pub(super) async fn get_or_load<F, Fut>(&self, load: F) -> Result<Arc<Vec<Object>>>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Object>>>,
    {
        let Some(cell) = self.tick_cell() else {
            return Ok(Arc::new(load().await?));
        };
        if let Some(snapshot) = cell.get() {
            return Ok(Arc::clone(&snapshot.objects));
        }
        let _fill = self.fill.lock().await;
        if let Some(snapshot) = cell.get() {
            return Ok(Arc::clone(&snapshot.objects));
        }
        let snapshot = PlanKindListSnapshot::from_objects(load().await?);
        let objects = Arc::clone(&snapshot.objects);
        let _ = cell.set(snapshot);
        Ok(objects)
    }
}

/// Ends a shared Plan kind-list tick when dropped.
pub(crate) struct PlanRetargetTickGuard {
    scan: Arc<PlanKindListTick>,
}

impl PlanRetargetTickGuard {
    pub(super) fn new(scan: Arc<PlanKindListTick>) -> Self {
        Self { scan }
    }
}

impl Drop for PlanRetargetTickGuard {
    fn drop(&mut self) {
        self.scan.end();
    }
}

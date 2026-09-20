use crate::storage::{Result, StoreError};

#[cfg(feature = "postgres")]
use super::PostgresTenantConfig;
use super::postgres_feature_enabled;
#[cfg(feature = "postgres")]
use super::postgres_imp;

/// Durable [`crate::reconcile_fence::ReconcileTickFence`] on hub Postgres (#135).
///
/// Claims live in `public.tenkai_reconcile_tick_claims` (hub-wide, not
/// schema-per-tenant). Does not advertise product `high_availability`.
#[cfg(feature = "postgres")]
pub struct PostgresReconcileFence {
    pub(crate) inner: std::sync::Arc<postgres_imp::Inner>,
}

#[cfg(feature = "postgres")]
impl crate::reconcile_fence::ReconcileTickFence for PostgresReconcileFence {
    fn try_begin(
        &self,
        environment: &str,
        owner: &str,
        now: i64,
        ttl_ms: i64,
    ) -> std::result::Result<
        crate::reconcile_fence::FenceAdmission,
        crate::reconcile_fence::FenceError,
    > {
        self.inner
            .try_begin_reconcile_claim(environment, owner, now, ttl_ms)
    }

    fn release(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        now: i64,
    ) -> std::result::Result<(), crate::reconcile_fence::FenceError> {
        self.inner
            .release_reconcile_claim(environment, owner, generation, now)
    }
}

/// Open a durable Postgres reconcile fence from `TENKAI_POSTGRES_URL` (#135).
///
/// Requires `--features postgres`. Used by multi-replica `tenkai-server` hosts
/// that share the hub database.
pub fn open_postgres_reconcile_fence()
-> Result<std::sync::Arc<dyn crate::reconcile_fence::ReconcileTickFence>> {
    if !postgres_feature_enabled() {
        return Err(StoreError::AdapterUnavailable(
            "durable reconcile fence requires --features postgres and TENKAI_POSTGRES_URL".into(),
        ));
    }
    #[cfg(feature = "postgres")]
    {
        let config = PostgresTenantConfig::from_env()?;
        let store = config.open()?;
        Ok(store.reconcile_tick_fence())
    }
    #[cfg(not(feature = "postgres"))]
    {
        Err(StoreError::AdapterUnavailable(
            "rebuild tenkai with --features postgres for durable reconcile fence".into(),
        ))
    }
}

/// Prefer durable Postgres fence when available; otherwise process-shared (#129).
///
/// Multi-process multi-replica hubs must set `TENKAI_POSTGRES_URL` and build with
/// `--features postgres` so claims survive process restart.
pub fn resolve_reconcile_fence_for_replicas(
    replica_count: u32,
) -> Result<Option<std::sync::Arc<dyn crate::reconcile_fence::ReconcileTickFence>>> {
    if replica_count <= 1 {
        return Ok(None);
    }
    match open_postgres_reconcile_fence() {
        Ok(fence) => Ok(Some(fence)),
        Err(_) => Ok(Some(
            crate::reconcile_fence::SharedReconcileFence::new().into_arc()
                as std::sync::Arc<dyn crate::reconcile_fence::ReconcileTickFence>,
        )),
    }
}

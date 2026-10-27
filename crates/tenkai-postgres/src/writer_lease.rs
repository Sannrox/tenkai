//! The hub writer lease (#748) for multi-replica tenant-mode hubs.
//!
//! [`PostgresHubWriterLease`] renews the lease on a connection of its own, so
//! a slow write never delays a renewal into a lapse, and publishes the result
//! to the shared [`WriterFence`] the store checks before every write.

use std::sync::Arc;

use tenkai::storage::Result;
#[cfg(not(feature = "postgres"))]
use tenkai::storage::StoreError;
use tenkai::writer_fence::WriterFence;
#[cfg(feature = "postgres")]
use tenkai::writer_fence::WriterRole;

#[cfg(feature = "postgres")]
use super::{PostgresTenantConfig, postgres_imp};

/// Acquires and renews the writer lease for one holder.
///
/// The connection is dropped on any failure and opened again on the next
/// renewal, so a database restart or a dropped connection costs leadership
/// only until the database answers again.
#[cfg(feature = "postgres")]
pub struct PostgresHubWriterLease {
    url: String,
    inner: std::sync::Mutex<Option<postgres_imp::Inner>>,
    holder: String,
    ttl_ms: i64,
    fence: Arc<WriterFence>,
}

#[cfg(feature = "postgres")]
impl PostgresHubWriterLease {
    pub fn open(
        config: &PostgresTenantConfig,
        holder: impl Into<String>,
        ttl_ms: i64,
        fence: Arc<WriterFence>,
    ) -> Result<Self> {
        Ok(Self {
            url: config.url.clone(),
            inner: std::sync::Mutex::new(Some(postgres_imp::Inner::connect(&config.url)?)),
            holder: holder.into(),
            ttl_ms,
            fence,
        })
    }

    /// Runs `work` on the lease connection, opening it if needed and
    /// dropping it on failure so the next call reconnects.
    fn on_connection<T>(&self, work: impl FnOnce(&postgres_imp::Inner) -> Result<T>) -> Result<T> {
        let mut slot = self
            .inner
            .lock()
            .map_err(|_| tenkai::storage::StoreError::Poisoned)?;
        if slot.is_none() {
            *slot = Some(postgres_imp::Inner::connect(&self.url)?);
        }
        let result = work(slot.as_ref().expect("connected above"));
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// Takes or renews the lease and publishes the role. A failed renewal
    /// fails closed: the fence becomes standby until a renewal succeeds.
    pub fn renew(&self) -> Result<WriterRole> {
        // Taken before the request: the database's expiry is at least this
        // plus the lifetime, so the local deadline never outlives the lease.
        let requested = std::time::Instant::now();
        match self.on_connection(|inner| inner.acquire_writer_lease(&self.holder, self.ttl_ms)) {
            Ok(role) => {
                let lifetime = std::time::Duration::from_millis(self.ttl_ms.max(0) as u64);
                self.fence.set_until(role.clone(), requested + lifetime);
                Ok(role)
            }
            Err(error) => {
                self.fence.set(WriterRole::Standby);
                Err(error)
            }
        }
    }

    /// Steps down: standby now, and the lease lapses for a quick takeover.
    pub fn release(&self) -> Result<()> {
        self.fence.set(WriterRole::Standby);
        self.on_connection(|inner| inner.release_writer_lease(&self.holder))
    }

    pub fn holder(&self) -> &str {
        &self.holder
    }
}

/// Opens the writer lease from `TENKAI_POSTGRES_URL`; refused without the
/// `postgres` feature.
pub fn open_hub_writer_lease(
    holder: impl Into<String>,
    ttl_ms: i64,
    fence: Arc<WriterFence>,
) -> Result<HubWriterLease> {
    #[cfg(feature = "postgres")]
    {
        let config = PostgresTenantConfig::from_env()?;
        PostgresHubWriterLease::open(&config, holder, ttl_ms, fence)
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = (holder.into(), ttl_ms, fence);
        Err(StoreError::AdapterUnavailable(
            "the hub writer lease requires --features postgres and TENKAI_POSTGRES_URL".into(),
        ))
    }
}

#[cfg(feature = "postgres")]
pub type HubWriterLease = PostgresHubWriterLease;
/// Uninhabited without the `postgres` feature: [`open_hub_writer_lease`]
/// refuses, so no value exists and these methods never run.
#[cfg(not(feature = "postgres"))]
pub enum HubWriterLease {}

#[cfg(not(feature = "postgres"))]
impl HubWriterLease {
    pub fn renew(&self) -> Result<tenkai::writer_fence::WriterRole> {
        match *self {}
    }

    pub fn release(&self) -> Result<()> {
        match *self {}
    }

    pub fn holder(&self) -> &str {
        match *self {}
    }
}

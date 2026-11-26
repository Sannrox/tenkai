//! Blocking adapters that run catalog and operational store calls off the async runtime.

use anyhow::{Result, anyhow};
use std::sync::Arc;

pub(crate) async fn block_operational<T, F>(
    store: Arc<dyn crate::storage::OperationalStore>,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn crate::storage::OperationalStore) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(store.as_ref()))
        .await
        .unwrap_or_else(|error| Err(anyhow!("operational store blocking task failed: {error}")))
}

pub(crate) async fn block_catalog<T, F>(
    catalog: Arc<dyn crate::storage::CatalogGraph>,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn crate::storage::CatalogGraph) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(catalog.as_ref()))
        .await
        .unwrap_or_else(|error| Err(anyhow!("catalog blocking task failed: {error}")))
}

pub(crate) async fn block_catalog_status<T, F>(
    catalog: Arc<dyn crate::storage::CatalogGraph>,
    operation: F,
) -> std::result::Result<T, super::ClientError>
where
    T: Send + 'static,
    F: FnOnce(&dyn crate::storage::CatalogGraph) -> crate::storage::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(catalog.as_ref()))
        .await
        .unwrap_or_else(|error| {
            Err(crate::storage::StoreError::Database(format!(
                "catalog blocking task failed: {error}"
            )))
        })
        .map_err(super::ClientError::from)
}

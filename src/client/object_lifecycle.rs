//! Object lifecycle semantics across the embedded and tenant catalogs.

use anyhow::Result;
use std::sync::Arc;

use crate::pb::record::Object;

pub(super) enum ObjectLifecycle {
    Catalog {
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        tenant: Option<String>,
    },
    /// A tenant hub without a usable catalog binding. `tenant_unbound` is a
    /// hub that has a catalog but no tenant yet: its reads fail with
    /// [`super::TENANT_NOT_BOUND`] instead of looking like an empty catalog.
    Unavailable { tenant_unbound: bool },
}

impl ObjectLifecycle {
    pub(super) async fn get(&self, id: &str) -> Result<Option<Object>> {
        match self {
            Self::Unavailable {
                tenant_unbound: true,
            } => anyhow::bail!(super::TENANT_NOT_BOUND),
            Self::Unavailable { .. } => Ok(None),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let id = id.to_string();
                super::block_catalog(catalog, move |catalog| catalog.get(tenant.as_deref(), &id))
                    .await
            }
        }
    }

    pub(super) async fn create_once(
        &self,
        object: Object,
    ) -> std::result::Result<Object, super::ClientError> {
        match self {
            Self::Unavailable { .. } => Err(super::ClientError::Failed(anyhow::anyhow!(
                super::TENANT_HUB_UNAVAILABLE
            ))),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog_status(catalog, move |catalog| {
                    catalog.create(tenant.as_deref(), object)
                })
                .await
            }
        }
    }

    pub(super) async fn delete(&self, id: &str) -> Result<()> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let id = id.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.delete(tenant.as_deref(), &id)
                })
                .await
            }
        }
    }

    pub(super) async fn put(&self, object: Object) -> Result<Object> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog(catalog, move |catalog| {
                    catalog.put(tenant.as_deref(), object)
                })
                .await
            }
        }
    }
}

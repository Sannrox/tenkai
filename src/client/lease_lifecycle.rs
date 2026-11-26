//! Lease lifecycle semantics across the embedded and tenant catalogs.

use anyhow::Result;
use std::sync::Arc;

use crate::pb::record::Lease;

pub(super) enum LeaseLifecycle {
    Catalog {
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        tenant: Option<String>,
    },
    /// A tenant hub without a usable catalog binding. `tenant_unbound` is a
    /// hub that has a catalog but no tenant yet: its reads fail with
    /// [`super::TENANT_NOT_BOUND`] instead of looking like an empty catalog.
    Unavailable { tenant_unbound: bool },
}

impl LeaseLifecycle {
    pub(super) async fn acquire(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> std::result::Result<Lease, super::LeaseError> {
        match self {
            Self::Unavailable { .. } => Err(super::LeaseError::Failed(anyhow::anyhow!(
                super::TENANT_HUB_UNAVAILABLE
            ))),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let namespace = namespace.to_string();
                let key = key.to_string();
                let owner = owner.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.acquire_lease(tenant.as_deref(), &namespace, &key, &owner, ttl_ms)
                })
                .await
                .map_err(super::LeaseError::from_anyhow)
            }
        }
    }

    pub(super) async fn get(&self, namespace: &str, key: &str) -> Result<Option<Lease>> {
        match self {
            Self::Unavailable {
                tenant_unbound: true,
            } => anyhow::bail!(super::TENANT_NOT_BOUND),
            Self::Unavailable { .. } => Ok(None),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let namespace = namespace.to_string();
                let key = key.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.get_lease(tenant.as_deref(), &namespace, &key)
                })
                .await
            }
        }
    }

    pub(super) async fn refresh(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let namespace = namespace.to_string();
                let key = key.to_string();
                let fencing_token = fencing_token.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.refresh_lease(
                        tenant.as_deref(),
                        &namespace,
                        &key,
                        &fencing_token,
                        ttl_ms,
                    )
                })
                .await
            }
        }
    }

    pub(super) async fn release(
        &self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<Lease> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let namespace = namespace.to_string();
                let key = key.to_string();
                let fencing_token = fencing_token.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.release_lease(tenant.as_deref(), &namespace, &key, &fencing_token)
                })
                .await
            }
        }
    }

    pub(super) async fn takeover(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_fencing_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
    ) -> Result<Lease> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let namespace = namespace.to_string();
                let key = key.to_string();
                let owner = owner.to_string();
                let expected_fencing_token = expected_fencing_token.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.takeover_lease(
                        tenant.as_deref(),
                        &namespace,
                        &key,
                        &owner,
                        &expected_fencing_token,
                        expected_expires_at_ms,
                        ttl_ms,
                    )
                })
                .await
            }
        }
    }
}

//! Relation lifecycle semantics across the embedded and tenant catalogs.

use anyhow::Result;
use std::sync::Arc;

use crate::pb::record::{Link, Object};

pub(super) enum RelationLifecycle {
    Catalog {
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        tenant: Option<String>,
    },
    /// A tenant hub without a usable catalog binding. `tenant_unbound` is a
    /// hub that has a catalog but no tenant yet: its reads fail with
    /// [`super::TENANT_NOT_BOUND`] instead of looking like an empty catalog.
    Unavailable { tenant_unbound: bool },
}

impl RelationLifecycle {
    pub(super) async fn link(&self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let link = Link {
            id: format!("{from_id}--{relation}--{to_id}"),
            from_id: from_id.into(),
            to_id: to_id.into(),
            relation: relation.into(),
            created: crate::now_millis(),
        };
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog(catalog, move |catalog| {
                    catalog
                        .create_link(tenant.as_deref(), link, false)
                        .map_err(anyhow::Error::from)
                })
                .await
            }
        }
    }

    pub(super) async fn create_link_once(
        &self,
        link: Link,
    ) -> std::result::Result<(), super::ClientError> {
        match self {
            Self::Unavailable { .. } => Err(super::ClientError::Failed(anyhow::anyhow!(
                super::TENANT_HUB_UNAVAILABLE
            ))),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog_status(catalog, move |catalog| {
                    catalog.create_link(tenant.as_deref(), link, true)
                })
                .await
            }
        }
    }

    pub(super) async fn unlink(&self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let id = format!("{from_id}--{relation}--{to_id}");
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog(catalog, move |catalog| {
                    catalog.unlink(tenant.as_deref(), &id)
                })
                .await
            }
        }
    }

    pub(super) async fn linked(
        &self,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> Result<Vec<Object>> {
        match self {
            Self::Unavailable {
                tenant_unbound: true,
            } => anyhow::bail!(super::TENANT_NOT_BOUND),
            Self::Unavailable { .. } => Ok(Vec::new()),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let object_id = object_id.to_string();
                let relation = relation.to_string();
                let direction = direction.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.linked(tenant.as_deref(), &object_id, &relation, &direction)
                })
                .await
            }
        }
    }

    pub(super) async fn links(&self, object_id: &str, relation: &str) -> Result<Vec<Link>> {
        match self {
            Self::Unavailable {
                tenant_unbound: true,
            } => anyhow::bail!(super::TENANT_NOT_BOUND),
            Self::Unavailable { .. } => Ok(Vec::new()),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let object_id = object_id.to_string();
                let relation = relation.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.links(tenant.as_deref(), &object_id, &relation, "out")
                })
                .await
            }
        }
    }
}

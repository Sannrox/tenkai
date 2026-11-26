//! Graph action lifecycle on the embedded and tenant catalogs.
//!
//! Tenkai keeps a local graph-action definition store and applies the
//! Tenkai-owned mutation DSL in-process. Missing, disabled, denied, or
//! unauthorized definitions fail closed.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;

use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::record::Decision;

pub(super) enum ActionLifecycle {
    Catalog {
        catalog: Arc<dyn crate::storage::CatalogGraph>,
        tenant: Option<String>,
    },
    /// A tenant hub without a usable catalog binding. `tenant_unbound` is a
    /// hub that has a catalog but no tenant yet: its reads fail with
    /// [`super::TENANT_NOT_BOUND`] instead of looking like an empty catalog.
    Unavailable { tenant_unbound: bool },
}

impl ActionLifecycle {
    pub(super) async fn register(
        &self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), super::ClientError> {
        match self {
            Self::Unavailable { .. } => Err(super::ClientError::Failed(anyhow!(
                super::TENANT_HUB_UNAVAILABLE
            ))),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                super::block_catalog_status(catalog, move |catalog| {
                    catalog.register_action(tenant.as_deref(), action)
                })
                .await
            }
        }
    }

    pub(super) async fn execute(
        &self,
        action: &str,
        params: HashMap<String, String>,
        dry_run: bool,
    ) -> Result<ActionResult> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let action = action.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.execute_action(tenant.as_deref(), &action, params, dry_run)
                })
                .await
            }
        }
    }

    pub(super) async fn deny(&self, approval_id: &str, _reason: &str) -> Result<()> {
        match self {
            Self::Unavailable { .. } => anyhow::bail!(super::TENANT_HUB_UNAVAILABLE),
            Self::Catalog { .. } => anyhow::bail!(
                "embedded mode has no deferred approvals; action {approval_id} cannot be denied"
            ),
        }
    }

    pub(super) async fn decisions(
        &self,
        actor: &str,
        action: &str,
        after: i64,
    ) -> Result<Vec<Decision>> {
        match self {
            Self::Unavailable {
                tenant_unbound: true,
            } => anyhow::bail!(super::TENANT_NOT_BOUND),
            Self::Unavailable { .. } => Ok(Vec::new()),
            Self::Catalog { catalog, tenant } => {
                let catalog = Arc::clone(catalog);
                let tenant = tenant.clone();
                let actor = actor.to_string();
                let action = action.to_string();
                super::block_catalog(catalog, move |catalog| {
                    catalog.decisions(tenant.as_deref(), &actor, &action, after)
                })
                .await
            }
        }
    }
}

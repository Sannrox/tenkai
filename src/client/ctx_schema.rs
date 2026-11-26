//! Schema and lease methods on `Ctx`.

use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::OnceCell;

use super::Ctx;
use crate::pb::graph_action::ActionTypeDef;
use crate::pb::record::{Lease, ObjectType};

impl Ctx {
    pub(crate) async fn register_schema(
        &mut self,
        schema: ObjectType,
    ) -> std::result::Result<(), super::ClientError> {
        if let Some((catalog, tenant)) = self.catalog_port() {
            return super::block_catalog_status(catalog, move |catalog| {
                catalog.register_schema(tenant.as_deref(), schema)
            })
            .await;
        }
        Err(super::ClientError::Failed(anyhow!(
            super::TENANT_HUB_UNAVAILABLE
        )))
    }

    pub(crate) async fn schemas(&mut self) -> Result<Vec<ObjectType>> {
        if let Some((catalog, tenant)) = self.catalog_port() {
            return super::block_catalog(catalog, move |catalog| {
                catalog.schemas(tenant.as_deref())
            })
            .await;
        }
        anyhow::ensure!(!self.has_catalog(), super::TENANT_NOT_BOUND);
        Ok(Vec::new())
    }

    pub(crate) async fn register_action(
        &mut self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), super::ClientError> {
        self.backend.action_lifecycle().register(action).await
    }

    pub(crate) async fn acquire_lease(
        &mut self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> std::result::Result<Lease, super::LeaseError> {
        self.backend
            .lease_lifecycle()
            .acquire(namespace, key, owner, ttl_ms)
            .await
    }

    pub(crate) async fn get_lease(&mut self, namespace: &str, key: &str) -> Result<Option<Lease>> {
        self.backend.lease_lifecycle().get(namespace, key).await
    }

    pub(crate) async fn refresh_lease(
        &mut self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        self.backend
            .lease_lifecycle()
            .refresh(namespace, key, fencing_token, ttl_ms)
            .await
    }

    pub(crate) async fn release_lease(
        &mut self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<Lease> {
        self.backend
            .lease_lifecycle()
            .release(namespace, key, fencing_token)
            .await
    }

    pub(crate) async fn takeover_expired_lease(
        &mut self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_fencing_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
    ) -> Result<Lease> {
        self.backend
            .lease_lifecycle()
            .takeover(
                namespace,
                key,
                owner,
                expected_fencing_token,
                expected_expires_at_ms,
                ttl_ms,
            )
            .await
    }

    pub(crate) fn canary_schema_preflight(&self) -> Arc<OnceCell<()>> {
        Arc::clone(&self.canary_schema_preflight)
    }
}

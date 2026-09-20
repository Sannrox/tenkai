//! Schema, lease, and remote-dispatch methods on `Ctx`.

use anyhow::Result;
use prost::Message;
use std::sync::Arc;
use tokio::sync::OnceCell;

use sekai_client::CallOptions;

use super::{
    Backend, Ctx, RemoteClient, block_embedded, block_embedded_status, remote_unary_with_options,
};
use crate::pb::chisei::{GetEvaluationGateEvidenceRequest, GetEvaluationGateEvidenceResponse};
use crate::pb::graph_action::ActionTypeDef;
use crate::pb::sekai::{
    CreateSchemaTypeRequest, CreateSchemaTypeResponse, Lease, ListSchemaTypesRequest,
    ListSchemaTypesResponse, ObjectType,
};

impl Ctx {
    pub(super) fn remote(&self) -> Result<&RemoteClient> {
        match &self.backend {
            Backend::Remote { client, .. } => Ok(client.as_ref()),
            Backend::Embedded(_) => {
                anyhow::bail!("operation requires a configured remote provider")
            }
        }
    }

    pub(super) async fn remote_unary<Req, Resp>(
        &self,
        path: &str,
        request: Req,
        options: CallOptions,
    ) -> std::result::Result<Resp, tonic::Status>
    where
        Req: Message + Default + Clone + Send + 'static,
        Resp: Message + Default + Send + 'static,
    {
        let client = self
            .remote()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        remote_unary_with_options(client, path, request, options).await
    }

    async fn remote_schema_exists(&self, kind: &str) -> bool {
        let response: std::result::Result<ListSchemaTypesResponse, tonic::Status> = self
            .remote_unary(
                "/sekai.SekaiService/ListSchemaTypes",
                ListSchemaTypesRequest {},
                CallOptions::default(),
            )
            .await;
        response.is_ok_and(|response| response.types.iter().any(|schema| schema.kind == kind))
    }

    pub(crate) fn embedded_arc(&self) -> Option<Arc<crate::storage::SqliteStore>> {
        match &self.backend {
            Backend::Embedded(store) => Some(Arc::clone(store)),
            Backend::Remote { .. } => None,
        }
    }

    pub(crate) async fn register_schema(
        &mut self,
        schema: ObjectType,
    ) -> std::result::Result<(), tonic::Status> {
        if let Some(store) = self.embedded_arc() {
            return block_embedded_status(store, move |store| store.register_schema(schema)).await;
        }
        let kind = schema.kind.clone();
        let response: std::result::Result<CreateSchemaTypeResponse, tonic::Status> = self
            .remote_unary(
                "/sekai.SekaiService/CreateSchemaType",
                CreateSchemaTypeRequest {
                    r#type: Some(schema),
                },
                CallOptions::default(),
            )
            .await;
        match response {
            Ok(_) => Ok(()),
            Err(status)
                if status.code() == tonic::Code::Internal
                    && self.remote_schema_exists(&kind).await =>
            {
                Err(tonic::Status::already_exists("schema type already exists"))
            }
            Err(status) => Err(status),
        }
    }

    pub(crate) async fn schemas(&mut self) -> Result<Vec<ObjectType>> {
        if let Some(store) = self.embedded_arc() {
            return block_embedded(store, |store| store.schemas()).await;
        }
        let response: ListSchemaTypesResponse = self
            .remote_unary(
                "/sekai.SekaiService/ListSchemaTypes",
                ListSchemaTypesRequest {},
                CallOptions::default(),
            )
            .await?;
        Ok(response.types)
    }

    pub(crate) async fn register_action(
        &mut self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), tonic::Status> {
        self.backend.action_lifecycle().register(action).await
    }

    pub(crate) async fn evaluation_gate_evidence(
        &mut self,
        request: GetEvaluationGateEvidenceRequest,
    ) -> Result<GetEvaluationGateEvidenceResponse> {
        if self.is_embedded() {
            anyhow::bail!(
                "embedded mode has no governance provider; configure remote provider mode for evaluation gate evidence"
            );
        }
        Ok(self
            .remote_unary(
                "/chisei.ChiseiService/GetEvaluationGateEvidence",
                request,
                CallOptions::default(),
            )
            .await?)
    }

    pub(crate) async fn acquire_lease(
        &mut self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
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

//! Connection to a local sekai-chisei server, plus thin object/link helpers.

mod action_lifecycle;
mod lease_lifecycle;
mod object_lifecycle;
mod relation_lifecycle;

use anyhow::{Context as _, Result};
use prost::Message;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tonic::Status;

use crate::pb::chisei::{GetEvaluationGateEvidenceRequest, GetEvaluationGateEvidenceResponse};
use crate::pb::graph_action::{ActionResult, ActionTypeDef};
use crate::pb::sekai::{
    CreateObjectRequest, CreateObjectResponse, CreateSchemaTypeRequest, CreateSchemaTypeResponse,
    Decision, FindByPropertyRequest, Lease, LeasePrecondition, Link, ListFilter,
    ListObjectChangesRequest, ListObjectChangesResponse, ListObjectsRequest, ListObjectsResponse,
    ListSchemaTypesRequest, ListSchemaTypesResponse, Object, ObjectChange, ObjectType,
    UpdateObjectRequest, UpdateObjectResponse,
};
use sekai_client::{
    CallOptions, ClientConfig, CoreLoopClient, GrpcTransport, RetryPolicy, SdkError, SdkErrorCode,
};

fn action_actor_from_changes(
    changes: &[ObjectChange],
    field: &str,
    correlation: &str,
) -> Option<String> {
    changes.iter().find_map(|change| {
        (change.field == field
            && change.new_value == correlation
            && !change.changed_by.trim().is_empty())
        .then(|| change.changed_by.clone())
    })
}

fn lease_precondition(
    lease_namespace: &str,
    lease_key: &str,
    fencing_token: &str,
) -> LeasePrecondition {
    LeasePrecondition {
        namespace: lease_namespace.into(),
        key: lease_key.into(),
        fencing_token: fencing_token.into(),
        request_id: uuid::Uuid::new_v4().to_string(),
    }
}

fn canonical_create_request(
    object: Object,
    precondition: Option<LeasePrecondition>,
) -> CreateObjectRequest {
    CreateObjectRequest {
        object: Some(object),
        lease_precondition: precondition,
    }
}

fn canonical_update_request(
    object: Object,
    precondition: Option<LeasePrecondition>,
) -> UpdateObjectRequest {
    UpdateObjectRequest {
        object: Some(object),
        lease_precondition: precondition,
    }
}

type RemoteClient = CoreLoopClient<GrpcTransport>;

#[derive(Clone)]
pub struct Ctx {
    backend: Backend,
    canary_schema_preflight: Arc<OnceCell<()>>,
    outcome_export_enabled: bool,
    outcome_inspection_enabled: bool,
}

#[derive(Clone)]
enum Backend {
    Remote {
        client: Arc<RemoteClient>,
        action_defs: action_lifecycle::RemoteActionDefs,
    },
    Embedded(Arc<crate::embedded::EmbeddedStore>),
}

impl Backend {
    fn object_lifecycle(&self) -> object_lifecycle::ObjectLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => object_lifecycle::ObjectLifecycle::Remote(client),
            Self::Embedded(store) => object_lifecycle::ObjectLifecycle::Embedded(store),
        }
    }

    fn relation_lifecycle(&self) -> relation_lifecycle::RelationLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => relation_lifecycle::RelationLifecycle::Remote(client),
            Self::Embedded(store) => relation_lifecycle::RelationLifecycle::Embedded(store),
        }
    }

    fn lease_lifecycle(&self) -> lease_lifecycle::LeaseLifecycle<'_> {
        match self {
            Self::Remote { client, .. } => lease_lifecycle::LeaseLifecycle::Remote(client),
            Self::Embedded(store) => lease_lifecycle::LeaseLifecycle::Embedded(store),
        }
    }

    fn action_lifecycle(&self) -> action_lifecycle::ActionLifecycle<'_> {
        match self {
            Self::Remote {
                client,
                action_defs,
            } => action_lifecycle::ActionLifecycle::Remote {
                client,
                action_defs,
            },
            Self::Embedded(store) => action_lifecycle::ActionLifecycle::Embedded(store),
        }
    }
}

fn sdk_error_status(error: SdkError) -> tonic::Status {
    let code = match error.code {
        SdkErrorCode::Cancelled => tonic::Code::Cancelled,
        SdkErrorCode::Unknown => tonic::Code::Unknown,
        SdkErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        SdkErrorCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        SdkErrorCode::NotFound => tonic::Code::NotFound,
        SdkErrorCode::AlreadyExists => tonic::Code::AlreadyExists,
        SdkErrorCode::PermissionDenied => tonic::Code::PermissionDenied,
        SdkErrorCode::ResourceExhausted => tonic::Code::ResourceExhausted,
        SdkErrorCode::FailedPrecondition => tonic::Code::FailedPrecondition,
        SdkErrorCode::Aborted => tonic::Code::Aborted,
        SdkErrorCode::Unavailable => tonic::Code::Unavailable,
        SdkErrorCode::Unimplemented => tonic::Code::Unimplemented,
        SdkErrorCode::Internal => tonic::Code::Internal,
        SdkErrorCode::Unauthenticated => tonic::Code::Unauthenticated,
    };
    Status::new(code, error.to_string())
}

fn token_transport_is_safe(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    if parsed.scheme() == "https" {
        return true;
    }
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    }
}

/// Connect to sekai-chisei. Honors `TENKAI_SEKAI_URL`, `GRPC_PORT`,
/// `SEKAI_AUTH_TOKEN`, and `TENKAI_PRINCIPAL` (default `tenkai`).
pub async fn connect() -> Result<Ctx> {
    let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".into());
    let url =
        std::env::var("TENKAI_SEKAI_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
    let token = std::env::var("SEKAI_AUTH_TOKEN").ok();
    if token.is_some() && !token_transport_is_safe(&url) {
        anyhow::bail!(
            "refusing to send SEKAI_AUTH_TOKEN to non-loopback plaintext endpoint {url}; use HTTPS"
        );
    }
    let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
    let mut config = ClientConfig::new(url.clone(), principal).with_retry_policy(RetryPolicy {
        max_attempts: 2,
        initial_backoff: Duration::from_millis(0),
        max_backoff: Duration::from_millis(0),
        retryable_codes: vec![SdkErrorCode::Unavailable, SdkErrorCode::DeadlineExceeded],
    });
    if let Some(token) = token {
        config = config.with_token(token).map_err(anyhow::Error::new)?;
    }
    let client = RemoteClient::connect(config)
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| {
            format!(
                "connecting to sekai-chisei at {url} — is the server running? (SEKAI_INSECURE=1 cargo run)"
            )
        })?;
    Ok(Ctx {
        backend: Backend::Remote {
            client: Arc::new(client),
            action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
        outcome_export_enabled: false,
        outcome_inspection_enabled: false,
    })
}

impl Ctx {
    /// Open the complete in-process backend used by the solo CLI.
    pub fn embedded(path: impl AsRef<Path>) -> Result<Self> {
        Self::embedded_with_outcome_export(path, false)
    }

    /// Open embedded application state and optionally enable atomic terminal
    /// outcome enqueueing into the Tenkai-owned provider outbox.
    pub fn embedded_with_outcome_export(
        path: impl AsRef<Path>,
        outcome_export_enabled: bool,
    ) -> Result<Self> {
        let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
        Ok(Self {
            backend: Backend::Embedded(Arc::new(crate::embedded::EmbeddedStore::open(
                path, principal,
            )?)),
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_export_enabled,
            outcome_inspection_enabled: true,
        })
    }

    pub fn is_embedded(&self) -> bool {
        matches!(self.backend, Backend::Embedded(_))
    }

    pub(crate) fn outcome_export_enabled(&self) -> bool {
        self.outcome_export_enabled
    }

    pub(crate) fn without_outcome_export(&self) -> Self {
        let mut context = self.clone();
        context.outcome_export_enabled = false;
        context.outcome_inspection_enabled = false;
        context
    }

    /// Read the bounded Tenkai-owned terminal-outcome projection for one
    /// environment. Remote provider mode has no local outbox to inspect; its
    /// authenticated server host supplies the same projection from its local
    /// operational store.
    pub(crate) fn terminal_outcomes(
        &self,
        environment: &str,
        as_of: i64,
    ) -> Result<Vec<crate::providers::TerminalOutcomeProjection>> {
        if !self.outcome_inspection_enabled {
            return Ok(Vec::new());
        }
        let Some(store) = self.embedded_store() else {
            return Ok(Vec::new());
        };
        let records = store.list_provider_events(
            crate::providers::OUTCOME_PROVIDER_KIND,
            environment,
            128,
        )?;
        crate::providers::project_terminal_outcomes(&records, environment, as_of)
            .map_err(anyhow::Error::from)
    }

    pub fn backup_embedded(&self, destination: impl AsRef<Path>) -> Result<()> {
        self.embedded_store()
            .context("backup is available only in embedded mode")?
            .backup(destination)
    }

    fn remote(&self) -> Result<&RemoteClient> {
        match &self.backend {
            Backend::Remote { client, .. } => Ok(client.as_ref()),
            Backend::Embedded(_) => {
                anyhow::bail!("operation requires a configured remote provider")
            }
        }
    }

    async fn remote_unary<Req, Resp>(
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
        client
            .raw()
            .unary(path, request, options)
            .await
            .map_err(sdk_error_status)
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

    fn embedded_store(&self) -> Option<&crate::embedded::EmbeddedStore> {
        match &self.backend {
            Backend::Embedded(store) => Some(store),
            Backend::Remote { .. } => None,
        }
    }

    pub(crate) async fn register_schema(
        &mut self,
        schema: ObjectType,
    ) -> std::result::Result<(), tonic::Status> {
        if let Some(store) = self.embedded_store() {
            return store.register_schema(schema);
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
        if let Some(store) = self.embedded_store() {
            return store.schemas();
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

    /// Get an object by id; `None` on not-found.
    pub async fn get(&mut self, id: &str) -> Result<Option<Object>> {
        self.backend.object_lifecycle().get(id).await
    }

    /// Create an object without falling back to update when its id exists.
    pub async fn create_once(
        &mut self,
        object: Object,
    ) -> std::result::Result<Object, tonic::Status> {
        self.backend.object_lifecycle().create_once(object).await
    }

    pub async fn delete(&mut self, id: &str) -> Result<()> {
        self.backend.object_lifecycle().delete(id).await
    }

    /// Create the object, or update it if the id already exists.
    pub async fn put(&mut self, object: Object) -> Result<Object> {
        self.backend.object_lifecycle().put(object).await
    }

    pub(crate) async fn put_with_provider_events(
        &mut self,
        object: Object,
        events: &[crate::storage::ProviderEventRecord],
    ) -> Result<Object> {
        if events.is_empty() {
            return self.put(object).await;
        }
        let Some(store) = self.embedded_store() else {
            anyhow::bail!(
                "remote application state cannot atomically enqueue Tenkai provider events"
            );
        };
        store.put_with_provider_events(object, events)
    }

    pub(crate) async fn put_objects_with_provider_events(
        &mut self,
        objects: &[Object],
        events: &[crate::storage::ProviderEventRecord],
    ) -> Result<()> {
        let Some(store) = self.embedded_store() else {
            anyhow::bail!(
                "remote application state cannot atomically update objects and enqueue Tenkai provider events"
            );
        };
        store.put_objects_with_provider_events(objects, events)
    }

    pub(crate) async fn guarded_create(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<Object> {
        if let Some(store) = self.embedded_store() {
            return store.guarded_put(object, lease_namespace, lease_key, fencing_token, true);
        }
        let request = canonical_create_request(
            object,
            Some(lease_precondition(
                lease_namespace,
                lease_key,
                fencing_token,
            )),
        );
        let request_id = request
            .lease_precondition
            .as_ref()
            .map(|precondition| precondition.request_id.clone());
        let mut options = CallOptions::default().retryable(true);
        if let Some(request_id) = request_id {
            options = options.with_request_id(request_id);
        }
        let response: CreateObjectResponse = self
            .remote_unary("/sekai.SekaiService/CreateObject", request, options)
            .await?;
        response
            .object
            .context("Sekai returned an empty canonical create result")
    }

    pub(crate) async fn guarded_update(
        &mut self,
        object: Object,
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
    ) -> Result<Object> {
        if let Some(store) = self.embedded_store() {
            return store.guarded_put(object, lease_namespace, lease_key, fencing_token, false);
        }
        let request = canonical_update_request(
            object,
            Some(lease_precondition(
                lease_namespace,
                lease_key,
                fencing_token,
            )),
        );
        let request_id = request
            .lease_precondition
            .as_ref()
            .map(|precondition| precondition.request_id.clone());
        let mut options = CallOptions::default().retryable(true);
        if let Some(request_id) = request_id {
            options = options.with_request_id(request_id);
        }
        let response: UpdateObjectResponse = self
            .remote_unary("/sekai.SekaiService/UpdateObject", request, options)
            .await?;
        response
            .object
            .context("Sekai returned an empty canonical update result")
    }

    pub(crate) async fn guarded_update_objects_with_provider_events(
        &mut self,
        objects: &[Object],
        lease_namespace: &str,
        lease_key: &str,
        fencing_token: &str,
        events: &[crate::storage::ProviderEventRecord],
    ) -> Result<()> {
        let Some(store) = self.embedded_store() else {
            anyhow::bail!(
                "remote application state cannot atomically update objects and enqueue Tenkai provider events"
            );
        };
        store.guarded_put_objects_with_provider_events(
            objects,
            lease_namespace,
            lease_key,
            fencing_token,
            events,
        )
    }

    /// Create a link with a deterministic id; already-exists is treated as success.
    pub async fn link(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        self.backend
            .relation_lifecycle()
            .link(from_id, to_id, relation)
            .await
    }

    /// Create one exact link and preserve duplicate errors for lock acquisition.
    pub(crate) async fn create_link_once(
        &mut self,
        link: Link,
    ) -> std::result::Result<(), tonic::Status> {
        self.backend
            .relation_lifecycle()
            .create_link_once(link)
            .await
    }

    pub async fn unlink(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        self.backend
            .relation_lifecycle()
            .unlink(from_id, to_id, relation)
            .await
    }

    pub async fn linked(
        &mut self,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> Result<Vec<Object>> {
        self.backend
            .relation_lifecycle()
            .linked(object_id, relation, direction)
            .await
    }

    pub async fn find_by_property(
        &mut self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>> {
        anyhow::ensure!(
            !kind.trim().is_empty() && !key.trim().is_empty(),
            "find_by_property requires non-empty kind and key"
        );
        if let Some(store) = self.embedded_store() {
            return store.find_by_property(kind, key, value);
        }
        let response: ListObjectsResponse = self
            .remote_unary(
                "/sekai.SekaiService/FindByProperty",
                FindByPropertyRequest {
                    kind: kind.into(),
                    key: key.into(),
                    value: value.into(),
                },
                CallOptions::default(),
            )
            .await?;
        Ok(response.objects)
    }

    pub async fn links(&mut self, object_id: &str, relation: &str) -> Result<Vec<Link>> {
        self.backend
            .relation_lifecycle()
            .links(object_id, relation)
            .await
    }

    pub async fn list_kind(&mut self, kind: &str) -> Result<Vec<Object>> {
        if let Some(store) = self.embedded_store() {
            return store.list_kind(kind);
        }
        const PAGE_SIZE: i32 = 100;
        let mut objects = Vec::new();
        loop {
            let response: ListObjectsResponse = self
                .remote_unary(
                    "/sekai.SekaiService/ListObjects",
                    ListObjectsRequest {
                        filter: Some(ListFilter {
                            kind: kind.into(),
                            limit: PAGE_SIZE,
                            offset: objects.len() as i32,
                            ..Default::default()
                        }),
                    },
                    CallOptions::default(),
                )
                .await?;
            let received = response.objects.len();
            objects.extend(response.objects);
            if received < PAGE_SIZE as usize {
                return Ok(objects);
            }
        }
    }

    pub async fn execute_action_result(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<ActionResult> {
        self.backend
            .action_lifecycle()
            .execute(action, params, false)
            .await
    }

    pub async fn preview_action_result(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<ActionResult> {
        self.backend
            .action_lifecycle()
            .execute(action, params, true)
            .await
    }

    pub async fn execute_action(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let result = self.execute_action_result(action, params).await?;
        if result.decision != "allow" {
            anyhow::bail!("action {action} was not allowed: {}", result.decision);
        }
        Ok(())
    }

    pub async fn deny_action(&mut self, approval_id: &str, reason: &str) -> Result<()> {
        self.backend
            .action_lifecycle()
            .deny(approval_id, reason)
            .await
    }

    pub async fn action_decisions(
        &mut self,
        actor: &str,
        action: &str,
        after: i64,
    ) -> Result<Vec<Decision>> {
        self.backend
            .action_lifecycle()
            .decisions(actor, action, after)
            .await
    }

    pub async fn object_changes(&mut self, object_id: &str) -> Result<Vec<ObjectChange>> {
        if let Some(store) = self.embedded_store() {
            return store.changes(object_id);
        }
        let mut offset = 0;
        let mut all = Vec::new();
        loop {
            let response: ListObjectChangesResponse = self
                .remote_unary(
                    "/sekai.SekaiService/ListObjectChanges",
                    ListObjectChangesRequest {
                        object_id: object_id.into(),
                        limit: 100,
                        offset,
                    },
                    CallOptions::default(),
                )
                .await?;
            let changes = response.changes;
            let received = changes.len();
            all.extend(changes);
            if received < 100 {
                return Ok(all);
            }
            offset += received as i32;
        }
    }

    pub async fn authorize_emergency_override(
        &mut self,
        plan_id: &str,
        reason: &str,
    ) -> Result<String> {
        let correlation = uuid::Uuid::new_v4().to_string();
        let result = self
            .execute_action_result(
                crate::ontology::ACTION_EMERGENCY_OVERRIDE,
                std::collections::HashMap::from([
                    ("id".into(), plan_id.into()),
                    ("reason".into(), reason.into()),
                    ("correlation".into(), correlation.clone()),
                ]),
            )
            .await?;
        match result.decision.as_str() {
            "allow" => self
                .emergency_override_actor(plan_id, &correlation)
                .await?
                .context("governed emergency override has no authenticated actor evidence"),
            "require_approval" => {
                anyhow::bail!(
                    "emergency maintenance override requires approval {}; governed ActionInstance admission denies require_approval and Tenkai does not resume deferred overrides",
                    result.approval_id,
                )
            }
            decision => {
                anyhow::bail!("emergency maintenance override was not allowed: {decision}")
            }
        }
    }

    async fn emergency_override_actor(
        &mut self,
        plan_id: &str,
        correlation: &str,
    ) -> Result<Option<String>> {
        let Some(plan) = self.get(plan_id).await? else {
            return Ok(None);
        };
        if plan
            .properties
            .get("last_emergency_override_correlation")
            .is_none_or(|stored| stored != correlation)
        {
            return Ok(None);
        }
        self.action_actor(
            plan_id,
            "properties.last_emergency_override_correlation",
            correlation,
        )
        .await
    }

    async fn action_actor(
        &mut self,
        object_id: &str,
        field: &str,
        correlation: &str,
    ) -> Result<Option<String>> {
        Ok(action_actor_from_changes(
            &self.object_changes(object_id).await?,
            field,
            correlation,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Backend, Ctx, action_actor_from_changes, canonical_create_request,
        canonical_update_request, lease_precondition, token_transport_is_safe,
    };
    use crate::pb::graph_action::{ActionOp, ActionTypeDef};
    use crate::pb::sekai::{
        AcquireLeaseRequest, AcquireLeaseResponse, ActionInstance, CreateLinkRequest,
        CreateLinkResponse, CreateObjectRequest, CreateObjectResponse, Decision, DeleteLinkRequest,
        DeleteLinkResponse, DeleteObjectRequest, DeleteObjectResponse,
        GetGovernedActionTypeRequest, GetGovernedActionTypeResponse, GetLeaseRequest,
        GetLeaseResponse, GetLinkedObjectsRequest, GetLinkedObjectsResponse, GetLinksRequest,
        GetLinksResponse, GetObjectRequest, GetObjectResponse, GovernedActionType, Lease, Link,
        ListActionPoliciesRequest, ListActionPoliciesResponse, ListDecisionsRequest,
        ListDecisionsResponse, Object, ObjectChange, PutGovernedActionTypeRequest,
        PutGovernedActionTypeResponse, RecordDecisionRequest, RecordDecisionResponse,
        RefreshLeaseRequest, RefreshLeaseResponse, ReleaseLeaseRequest, ReleaseLeaseResponse,
        SubmitActionInstanceRequest, SubmitActionInstanceResponse, TakeoverExpiredLeaseRequest,
        TakeoverExpiredLeaseResponse, UpdateObjectRequest, UpdateObjectResponse,
    };
    use sekai_client::{ClientConfig, RetryPolicy, SdkErrorCode};
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context as TaskContext, Poll};
    use tokio::net::TcpListener;
    use tokio::sync::OnceCell;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    type CapturedMetadata = (Option<String>, Option<String>);

    #[derive(Clone)]
    struct MockSekaiState {
        creates: Arc<Mutex<Vec<CreateObjectRequest>>>,
        updates: Arc<Mutex<Vec<UpdateObjectRequest>>>,
        governed_actions: Arc<Mutex<Vec<GovernedActionType>>>,
        metadata: Arc<Mutex<Vec<CapturedMetadata>>>,
        objects: Arc<Mutex<BTreeMap<String, Object>>>,
        links: Arc<Mutex<BTreeMap<String, Link>>>,
        leases: Arc<Mutex<BTreeMap<(String, String), Lease>>>,
        decisions: Arc<Mutex<Vec<Decision>>>,
        create_failures: Arc<AtomicUsize>,
        create_internal_failures: Arc<AtomicUsize>,
        update_failures: Arc<AtomicUsize>,
    }

    impl Default for MockSekaiState {
        fn default() -> Self {
            Self {
                creates: Arc::new(Mutex::new(Vec::new())),
                updates: Arc::new(Mutex::new(Vec::new())),
                governed_actions: Arc::new(Mutex::new(Vec::new())),
                metadata: Arc::new(Mutex::new(Vec::new())),
                objects: Arc::new(Mutex::new(BTreeMap::new())),
                links: Arc::new(Mutex::new(BTreeMap::new())),
                leases: Arc::new(Mutex::new(BTreeMap::new())),
                decisions: Arc::new(Mutex::new(Vec::new())),
                create_failures: Arc::new(AtomicUsize::new(0)),
                create_internal_failures: Arc::new(AtomicUsize::new(0)),
                update_failures: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    fn mock_now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn mock_lease_key(namespace: &str, key: &str) -> (String, String) {
        (namespace.to_owned(), key.to_owned())
    }

    fn consume_failure(counter: &AtomicUsize) -> bool {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    struct CreateObjectRpc(MockSekaiState);

    impl tonic::server::UnaryService<CreateObjectRequest> for CreateObjectRpc {
        type Response = CreateObjectResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<CreateObjectRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let object = request.object.clone().unwrap_or_default();
                state.creates.lock().unwrap().push(request);
                if consume_failure(&state.create_failures) {
                    return Err(tonic::Status::unavailable("transient create failure"));
                }
                if consume_failure(&state.create_internal_failures) {
                    state
                        .objects
                        .lock()
                        .unwrap()
                        .insert(object.id.clone(), object.clone());
                    return Err(tonic::Status::internal("UNIQUE constraint failed"));
                }
                let mut objects = state.objects.lock().unwrap();
                if objects.contains_key(&object.id) {
                    return Err(tonic::Status::already_exists("object already exists"));
                }
                objects.insert(object.id.clone(), object.clone());
                Ok(tonic::Response::new(CreateObjectResponse {
                    object: Some(object),
                }))
            })
        }
    }

    struct GetObjectRpc(MockSekaiState);

    impl tonic::server::UnaryService<GetObjectRequest> for GetObjectRpc {
        type Response = GetObjectResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<GetObjectRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let id = request.into_inner().id;
                let object = state.objects.lock().unwrap().get(&id).cloned();
                match object {
                    Some(object) => Ok(tonic::Response::new(GetObjectResponse {
                        object: Some(object),
                    })),
                    None => Err(tonic::Status::not_found("object not found")),
                }
            })
        }
    }

    struct UpdateObjectRpc(MockSekaiState);

    impl tonic::server::UnaryService<UpdateObjectRequest> for UpdateObjectRpc {
        type Response = UpdateObjectResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<UpdateObjectRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let object = request.object.clone().unwrap_or_default();
                state.updates.lock().unwrap().push(request);
                if consume_failure(&state.update_failures) {
                    return Err(tonic::Status::unavailable("transient update failure"));
                }
                let mut objects = state.objects.lock().unwrap();
                if !objects.contains_key(&object.id) {
                    return Err(tonic::Status::not_found("object not found"));
                }
                objects.insert(object.id.clone(), object.clone());
                Ok(tonic::Response::new(UpdateObjectResponse {
                    object: Some(object),
                }))
            })
        }
    }

    struct DeleteObjectRpc(MockSekaiState);

    impl tonic::server::UnaryService<DeleteObjectRequest> for DeleteObjectRpc {
        type Response = DeleteObjectResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<DeleteObjectRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                state
                    .objects
                    .lock()
                    .unwrap()
                    .remove(&request.into_inner().id);
                Ok(tonic::Response::new(DeleteObjectResponse {}))
            })
        }
    }

    struct CreateLinkRpc(MockSekaiState);

    impl tonic::server::UnaryService<CreateLinkRequest> for CreateLinkRpc {
        type Response = CreateLinkResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<CreateLinkRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let link = request.link.unwrap_or_default();
                let mut links = state.links.lock().unwrap();
                if links.contains_key(&link.id) {
                    return Err(tonic::Status::already_exists("link already exists"));
                }
                links.insert(link.id.clone(), link.clone());
                Ok(tonic::Response::new(CreateLinkResponse {
                    link: Some(link),
                }))
            })
        }
    }

    struct DeleteLinkRpc(MockSekaiState);

    impl tonic::server::UnaryService<DeleteLinkRequest> for DeleteLinkRpc {
        type Response = DeleteLinkResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<DeleteLinkRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let removed = state.links.lock().unwrap().remove(&request.into_inner().id);
                match removed {
                    Some(_) => Ok(tonic::Response::new(DeleteLinkResponse {})),
                    None => Err(tonic::Status::not_found("link not found")),
                }
            })
        }
    }

    struct GetLinksRpc(MockSekaiState);

    impl tonic::server::UnaryService<GetLinksRequest> for GetLinksRpc {
        type Response = GetLinksResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<GetLinksRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let links = state
                    .links
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|link| {
                        link.relation == request.relation
                            && match request.direction.as_str() {
                                "out" => link.from_id == request.object_id,
                                "in" => link.to_id == request.object_id,
                                _ => false,
                            }
                    })
                    .cloned()
                    .collect();
                Ok(tonic::Response::new(GetLinksResponse { links }))
            })
        }
    }

    struct GetLinkedObjectsRpc(MockSekaiState);

    impl tonic::server::UnaryService<GetLinkedObjectsRequest> for GetLinkedObjectsRpc {
        type Response = GetLinkedObjectsResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<GetLinkedObjectsRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let linked_ids = state
                    .links
                    .lock()
                    .unwrap()
                    .values()
                    .filter_map(|link| {
                        if link.relation != request.relation {
                            return None;
                        }
                        match request.direction.as_str() {
                            "out" if link.from_id == request.object_id => Some(link.to_id.clone()),
                            "in" if link.to_id == request.object_id => Some(link.from_id.clone()),
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>();
                let objects = state.objects.lock().unwrap();
                let objects = linked_ids
                    .into_iter()
                    .filter_map(|id| objects.get(&id).cloned())
                    .collect();
                Ok(tonic::Response::new(GetLinkedObjectsResponse { objects }))
            })
        }
    }

    struct AcquireLeaseRpc(MockSekaiState);

    impl tonic::server::UnaryService<AcquireLeaseRequest> for AcquireLeaseRpc {
        type Response = AcquireLeaseResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<AcquireLeaseRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                if request.ttl_ms <= 0 {
                    return Err(tonic::Status::invalid_argument("ttl_ms must be positive"));
                }
                let now = mock_now_ms();
                let key = mock_lease_key(&request.namespace, &request.key);
                let mut leases = state.leases.lock().unwrap();
                if let Some(current) = leases.get(&key)
                    && current.status == "active"
                    && current.expires_at_ms > now
                {
                    return Err(tonic::Status::already_exists(format!(
                        "lease {}/{} is held by {}",
                        request.namespace, request.key, current.owner
                    )));
                }
                let generation = leases
                    .get(&key)
                    .map_or(1, |lease| lease.generation.saturating_add(1));
                let lease = Lease {
                    namespace: request.namespace,
                    key: request.key,
                    generation,
                    fencing_token: uuid::Uuid::new_v4().to_string(),
                    owner: request.owner,
                    status: "active".into(),
                    acquired_at_ms: now,
                    refreshed_at_ms: now,
                    expires_at_ms: now.saturating_add(request.ttl_ms),
                    released_at_ms: 0,
                    site_id: String::new(),
                };
                leases.insert(key, lease.clone());
                Ok(tonic::Response::new(AcquireLeaseResponse {
                    lease: Some(lease),
                }))
            })
        }
    }

    struct GetLeaseRpc(MockSekaiState);

    impl tonic::server::UnaryService<GetLeaseRequest> for GetLeaseRpc {
        type Response = GetLeaseResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<GetLeaseRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let key = mock_lease_key(&request.namespace, &request.key);
                match state.leases.lock().unwrap().get(&key).cloned() {
                    Some(lease) => Ok(tonic::Response::new(GetLeaseResponse {
                        lease: Some(lease),
                    })),
                    None => Err(tonic::Status::not_found("lease not found")),
                }
            })
        }
    }

    struct RefreshLeaseRpc(MockSekaiState);

    impl tonic::server::UnaryService<RefreshLeaseRequest> for RefreshLeaseRpc {
        type Response = RefreshLeaseResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<RefreshLeaseRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let key = mock_lease_key(&request.namespace, &request.key);
                let mut leases = state.leases.lock().unwrap();
                let Some(lease) = leases.get_mut(&key) else {
                    return Err(tonic::Status::not_found("lease not found"));
                };
                if lease.status != "active" || lease.fencing_token != request.fencing_token {
                    return Err(tonic::Status::failed_precondition("lease refresh rejected"));
                }
                let now = mock_now_ms();
                lease.refreshed_at_ms = now;
                lease.expires_at_ms = now.saturating_add(request.ttl_ms);
                Ok(tonic::Response::new(RefreshLeaseResponse {
                    lease: Some(lease.clone()),
                }))
            })
        }
    }

    struct ReleaseLeaseRpc(MockSekaiState);

    impl tonic::server::UnaryService<ReleaseLeaseRequest> for ReleaseLeaseRpc {
        type Response = ReleaseLeaseResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<ReleaseLeaseRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let key = mock_lease_key(&request.namespace, &request.key);
                let mut leases = state.leases.lock().unwrap();
                let Some(lease) = leases.get_mut(&key) else {
                    return Err(tonic::Status::not_found("lease not found"));
                };
                if lease.status != "active" || lease.fencing_token != request.fencing_token {
                    return Err(tonic::Status::failed_precondition("lease release rejected"));
                }
                lease.status = "released".into();
                lease.released_at_ms = mock_now_ms();
                Ok(tonic::Response::new(ReleaseLeaseResponse {
                    lease: Some(lease.clone()),
                }))
            })
        }
    }

    struct TakeoverExpiredLeaseRpc(MockSekaiState);

    impl tonic::server::UnaryService<TakeoverExpiredLeaseRequest> for TakeoverExpiredLeaseRpc {
        type Response = TakeoverExpiredLeaseResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<TakeoverExpiredLeaseRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                if request.ttl_ms <= 0 {
                    return Err(tonic::Status::invalid_argument("ttl_ms must be positive"));
                }
                let key = mock_lease_key(&request.namespace, &request.key);
                let mut leases = state.leases.lock().unwrap();
                let Some(current) = leases.get(&key).cloned() else {
                    return Err(tonic::Status::not_found("lease not found"));
                };
                let now = mock_now_ms();
                if current.fencing_token != request.expected_fencing_token
                    || current.expires_at_ms != request.expected_expires_at_ms
                    || current.expires_at_ms > now
                {
                    return Err(tonic::Status::failed_precondition(
                        "lease takeover precondition failed",
                    ));
                }
                let lease = Lease {
                    namespace: request.namespace,
                    key: request.key,
                    generation: current.generation.saturating_add(1),
                    fencing_token: uuid::Uuid::new_v4().to_string(),
                    owner: request.owner,
                    status: "active".into(),
                    acquired_at_ms: now,
                    refreshed_at_ms: now,
                    expires_at_ms: now.saturating_add(request.ttl_ms),
                    released_at_ms: 0,
                    site_id: String::new(),
                };
                leases.insert(key, lease.clone());
                Ok(tonic::Response::new(TakeoverExpiredLeaseResponse {
                    lease: Some(lease),
                }))
            })
        }
    }

    struct PutGovernedActionTypeRpc(MockSekaiState);

    impl tonic::server::UnaryService<PutGovernedActionTypeRequest> for PutGovernedActionTypeRpc {
        type Response = PutGovernedActionTypeResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<PutGovernedActionTypeRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let principal = request
                    .metadata()
                    .get("x-principal")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let authorization = request
                    .metadata()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                state
                    .metadata
                    .lock()
                    .unwrap()
                    .push((principal, authorization));
                let mut action = request.into_inner().r#type.unwrap_or_default();
                if action.created_at_ms == 0 {
                    action.created_at_ms = mock_now_ms();
                }
                action.enabled = true;
                state.governed_actions.lock().unwrap().push(action.clone());
                Ok(tonic::Response::new(PutGovernedActionTypeResponse {
                    r#type: Some(action),
                }))
            })
        }
    }

    struct GetGovernedActionTypeRpc(MockSekaiState);

    impl tonic::server::UnaryService<GetGovernedActionTypeRequest> for GetGovernedActionTypeRpc {
        type Response = GetGovernedActionTypeResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<GetGovernedActionTypeRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let action = state
                    .governed_actions
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|candidate| {
                        candidate.namespace == request.namespace
                            && candidate.type_id == request.type_id
                            && candidate.version == request.version
                    })
                    .cloned()
                    .ok_or_else(|| tonic::Status::not_found("governed action type not found"))?;
                Ok(tonic::Response::new(GetGovernedActionTypeResponse {
                    r#type: Some(action),
                }))
            })
        }
    }

    struct ListActionPoliciesRpc;

    impl tonic::server::UnaryService<ListActionPoliciesRequest> for ListActionPoliciesRpc {
        type Response = ListActionPoliciesResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<ListActionPoliciesRequest>) -> Self::Future {
            Box::pin(async move {
                let _ = request;
                Ok(tonic::Response::new(ListActionPoliciesResponse {
                    policies: Vec::new(),
                }))
            })
        }
    }

    struct SubmitActionInstanceRpc(MockSekaiState);

    impl tonic::server::UnaryService<SubmitActionInstanceRequest> for SubmitActionInstanceRpc {
        type Response = SubmitActionInstanceResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<SubmitActionInstanceRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let exists = state.governed_actions.lock().unwrap().iter().any(|action| {
                    action.namespace == request.namespace
                        && action.type_id == request.type_id
                        && action.version == request.version
                        && action.enabled
                });
                if !exists {
                    return Err(tonic::Status::failed_precondition(
                        "governed action type missing or disabled",
                    ));
                }
                let now = mock_now_ms();
                Ok(tonic::Response::new(SubmitActionInstanceResponse {
                    instance: Some(ActionInstance {
                        instance_id: uuid::Uuid::new_v4().to_string(),
                        namespace: request.namespace,
                        type_id: request.type_id,
                        version: request.version,
                        principal: "remote-mock".into(),
                        parameters_json: request.parameters_json,
                        request_digest: "sha256:mock".into(),
                        idempotency_key: request.idempotency_key,
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        status: "admitted".into(),
                        deny_reason: String::new(),
                        evidence_submission_ids: request.evidence_submission_ids,
                        policy_decision: "allow".into(),
                        budget_decision: "not_configured".into(),
                        created_at_ms: now,
                        decided_at_ms: now,
                    }),
                    replay: false,
                }))
            })
        }
    }

    struct RecordDecisionRpc(MockSekaiState);

    impl tonic::server::UnaryService<RecordDecisionRequest> for RecordDecisionRpc {
        type Response = RecordDecisionResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<RecordDecisionRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let principal = request
                    .metadata()
                    .get("x-principal")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("remote-mock")
                    .to_owned();
                let mut decision = request
                    .into_inner()
                    .decision
                    .ok_or_else(|| tonic::Status::invalid_argument("decision required"))?;
                decision.actor = principal;
                if decision.timestamp <= 0 {
                    decision.timestamp = mock_now_ms();
                }
                state.decisions.lock().unwrap().push(decision.clone());
                Ok(tonic::Response::new(RecordDecisionResponse {
                    decision: Some(decision),
                }))
            })
        }
    }

    struct ListDecisionsRpc(MockSekaiState);

    impl tonic::server::UnaryService<ListDecisionsRequest> for ListDecisionsRpc {
        type Response = ListDecisionsResponse;
        type Future = Pin<
            Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
        >;

        fn call(&mut self, request: tonic::Request<ListDecisionsRequest>) -> Self::Future {
            let state = self.0.clone();
            Box::pin(async move {
                let request = request.into_inner();
                let decisions = state
                    .decisions
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|decision| {
                        (request.actor.is_empty() || decision.actor == request.actor)
                            && (request.action.is_empty() || decision.action == request.action)
                            && decision.timestamp > request.after
                    })
                    .cloned()
                    .collect();
                Ok(tonic::Response::new(ListDecisionsResponse { decisions }))
            })
        }
    }

    impl tower::Service<tonic::codegen::http::Request<tonic::body::Body>> for MockSekaiState {
        type Response = tonic::codegen::http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(
            &mut self,
            request: tonic::codegen::http::Request<tonic::body::Body>,
        ) -> Self::Future {
            let state = self.clone();
            Box::pin(async move {
                let response = match request.uri().path() {
                    "/sekai.SekaiService/CreateObject" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(CreateObjectRpc(state), request).await
                    }
                    "/sekai.SekaiService/GetObject" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(GetObjectRpc(state), request).await
                    }
                    "/sekai.SekaiService/UpdateObject" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(UpdateObjectRpc(state), request).await
                    }
                    "/sekai.SekaiService/DeleteObject" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(DeleteObjectRpc(state), request).await
                    }
                    "/sekai.SekaiService/CreateLink" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(CreateLinkRpc(state), request).await
                    }
                    "/sekai.SekaiService/DeleteLink" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(DeleteLinkRpc(state), request).await
                    }
                    "/sekai.SekaiService/GetLinks" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(GetLinksRpc(state), request).await
                    }
                    "/sekai.SekaiService/GetLinkedObjects" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(GetLinkedObjectsRpc(state), request).await
                    }
                    "/sekai.SekaiService/AcquireLease" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(AcquireLeaseRpc(state), request).await
                    }
                    "/sekai.SekaiService/GetLease" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(GetLeaseRpc(state), request).await
                    }
                    "/sekai.SekaiService/RefreshLease" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(RefreshLeaseRpc(state), request).await
                    }
                    "/sekai.SekaiService/ReleaseLease" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(ReleaseLeaseRpc(state), request).await
                    }
                    "/sekai.SekaiService/TakeoverExpiredLease" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(TakeoverExpiredLeaseRpc(state), request).await
                    }
                    "/sekai.SekaiService/PutGovernedActionType" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(PutGovernedActionTypeRpc(state), request).await
                    }
                    "/sekai.SekaiService/GetGovernedActionType" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(GetGovernedActionTypeRpc(state), request).await
                    }
                    "/sekai.SekaiService/ListActionPolicies" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(ListActionPoliciesRpc, request).await
                    }
                    "/sekai.SekaiService/SubmitActionInstance" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(SubmitActionInstanceRpc(state), request).await
                    }
                    "/sekai.SekaiService/RecordDecision" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(RecordDecisionRpc(state), request).await
                    }
                    "/sekai.SekaiService/ListDecisions" => {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        grpc.unary(ListDecisionsRpc(state), request).await
                    }
                    _ => {
                        let mut response =
                            tonic::codegen::http::Response::new(tonic::body::Body::default());
                        response.headers_mut().insert(
                            tonic::Status::GRPC_STATUS,
                            (tonic::Code::Unimplemented as i32).into(),
                        );
                        response.headers_mut().insert(
                            tonic::codegen::http::header::CONTENT_TYPE,
                            tonic::metadata::GRPC_CONTENT_TYPE,
                        );
                        response
                    }
                };
                Ok(response)
            })
        }
    }

    impl tonic::server::NamedService for MockSekaiState {
        const NAME: &'static str = "sekai.SekaiService";
    }

    async fn remote_ctx(state: MockSekaiState) -> (Ctx, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(server_state)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = super::RemoteClient::connect(ClientConfig::new(
            format!("http://{address}"),
            "tenkai.conformance",
        ))
        .await
        .unwrap();
        (
            Ctx {
                backend: Backend::Remote {
                    client: Arc::new(client),
                    action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
                },
                canary_schema_preflight: Arc::new(OnceCell::new()),
                outcome_export_enabled: false,
                outcome_inspection_enabled: false,
            },
            server,
        )
    }

    async fn assert_object_lifecycle(mut ctx: Ctx) {
        let id = "tenkai:conformance:object";
        assert_eq!(ctx.get(id).await.unwrap(), None);

        let original = Object {
            id: id.into(),
            kind: "tenkai.conformance".into(),
            name: "original".into(),
            properties: [("environment".into(), "test".into())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        assert_eq!(ctx.create_once(original.clone()).await.unwrap(), original);
        assert_eq!(ctx.get(id).await.unwrap(), Some(original.clone()));

        let mut conflicting = original.clone();
        conflicting.name = "must-not-replace".into();
        let error = ctx.create_once(conflicting).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::AlreadyExists);
        assert_eq!(ctx.get(id).await.unwrap(), Some(original.clone()));

        let mut updated = original;
        updated.name = "updated".into();
        updated.properties.insert("status".into(), "ready".into());
        assert_eq!(ctx.put(updated.clone()).await.unwrap(), updated);
        assert_eq!(ctx.get(id).await.unwrap(), Some(updated));

        ctx.delete(id).await.unwrap();
        assert_eq!(ctx.get(id).await.unwrap(), None);
    }

    async fn assert_relation_lifecycle(mut ctx: Ctx) {
        let source = Object {
            id: "tenkai:conformance:source".into(),
            kind: "tenkai.conformance".into(),
            name: "source".into(),
            ..Default::default()
        };
        let target = Object {
            id: "tenkai:conformance:target".into(),
            kind: "tenkai.conformance".into(),
            name: "target".into(),
            ..Default::default()
        };
        ctx.create_once(source.clone()).await.unwrap();
        ctx.create_once(target.clone()).await.unwrap();

        assert!(
            ctx.links(&source.id, "depends_on")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            ctx.linked(&source.id, "depends_on", "out")
                .await
                .unwrap()
                .is_empty()
        );

        ctx.link(&source.id, &target.id, "depends_on")
            .await
            .unwrap();
        ctx.link(&source.id, &target.id, "depends_on")
            .await
            .unwrap();
        let links = ctx.links(&source.id, "depends_on").await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].id,
            format!("{}--depends_on--{}", source.id, target.id)
        );
        assert_eq!(links[0].from_id, source.id);
        assert_eq!(links[0].to_id, target.id);
        assert_eq!(links[0].relation, "depends_on");
        assert!(links[0].created > 0);
        assert_eq!(
            ctx.linked(&source.id, "depends_on", "out").await.unwrap(),
            vec![target.clone()]
        );
        assert_eq!(
            ctx.linked(&target.id, "depends_on", "in").await.unwrap(),
            vec![source.clone()]
        );

        let strict = Link {
            id: "tenkai:conformance:strict-link".into(),
            from_id: source.id.clone(),
            to_id: target.id.clone(),
            relation: "locked_by".into(),
            created: 42,
        };
        ctx.create_link_once(strict.clone()).await.unwrap();
        let error = ctx.create_link_once(strict).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::AlreadyExists);

        ctx.unlink(&source.id, &target.id, "depends_on")
            .await
            .unwrap();
        ctx.unlink(&source.id, &target.id, "depends_on")
            .await
            .unwrap();
        assert!(
            ctx.links(&source.id, "depends_on")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            ctx.linked(&source.id, "depends_on", "out")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            ctx.linked(&target.id, "depends_on", "in")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn embedded_ctx_conforms_to_object_lifecycle() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-ctx-conformance-{}.db",
            uuid::Uuid::new_v4()
        ));
        let ctx = Ctx::embedded(&path).unwrap();
        assert_object_lifecycle(ctx).await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn remote_ctx_conforms_to_object_lifecycle() {
        let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
        assert_object_lifecycle(ctx).await;
        server.abort();
    }

    #[tokio::test]
    async fn embedded_ctx_conforms_to_relation_lifecycle() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-ctx-relation-conformance-{}.db",
            uuid::Uuid::new_v4()
        ));
        let ctx = Ctx::embedded(&path).unwrap();
        assert_relation_lifecycle(ctx).await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn remote_ctx_conforms_to_relation_lifecycle() {
        let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
        assert_relation_lifecycle(ctx).await;
        server.abort();
    }

    async fn assert_lease_lifecycle(mut ctx: Ctx) {
        let namespace = "tenkai";
        let key = "environment/conformance";
        assert_eq!(ctx.get_lease(namespace, key).await.unwrap(), None);

        let acquired = ctx
            .acquire_lease(namespace, key, "owner-a", 5_000)
            .await
            .unwrap();
        assert_eq!(acquired.namespace, namespace);
        assert_eq!(acquired.key, key);
        assert_eq!(acquired.owner, "owner-a");
        assert_eq!(acquired.status, "active");
        assert!(!acquired.fencing_token.is_empty());
        assert_eq!(
            ctx.get_lease(namespace, key).await.unwrap(),
            Some(acquired.clone())
        );

        let conflict = ctx
            .acquire_lease(namespace, key, "owner-b", 5_000)
            .await
            .unwrap_err();
        let status = conflict
            .downcast_ref::<tonic::Status>()
            .expect("lease conflict should surface as tonic Status");
        assert_eq!(status.code(), tonic::Code::AlreadyExists);

        let refreshed = ctx
            .refresh_lease(namespace, key, &acquired.fencing_token, 8_000)
            .await
            .unwrap();
        assert_eq!(refreshed.fencing_token, acquired.fencing_token);
        assert!(refreshed.expires_at_ms >= acquired.expires_at_ms);
        assert_eq!(refreshed.status, "active");

        let released = ctx
            .release_lease(namespace, key, &acquired.fencing_token)
            .await
            .unwrap();
        assert_eq!(released.status, "released");
        assert!(released.released_at_ms > 0);

        let reacquired = ctx
            .acquire_lease(namespace, key, "owner-c", 1)
            .await
            .unwrap();
        assert_eq!(reacquired.owner, "owner-c");
        assert_eq!(reacquired.status, "active");
        assert_ne!(reacquired.fencing_token, acquired.fencing_token);
        assert!(reacquired.generation > acquired.generation);

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let takeover = ctx
            .takeover_expired_lease(
                namespace,
                key,
                "owner-d",
                &reacquired.fencing_token,
                reacquired.expires_at_ms,
                5_000,
            )
            .await
            .unwrap();
        assert_eq!(takeover.owner, "owner-d");
        assert_eq!(takeover.status, "active");
        assert_ne!(takeover.fencing_token, reacquired.fencing_token);
        assert!(takeover.generation > reacquired.generation);
    }

    #[tokio::test]
    async fn embedded_ctx_conforms_to_lease_lifecycle() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-ctx-lease-conformance-{}.db",
            uuid::Uuid::new_v4()
        ));
        let ctx = Ctx::embedded(&path).unwrap();
        assert_lease_lifecycle(ctx).await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn remote_ctx_conforms_to_lease_lifecycle() {
        let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
        assert_lease_lifecycle(ctx).await;
        server.abort();
    }

    async fn assert_action_lifecycle(mut ctx: Ctx) {
        let target = Object {
            id: "tenkai:conformance:action-target".into(),
            kind: "tenkai.conformance".into(),
            name: "action-target".into(),
            ..Default::default()
        };
        ctx.create_once(target.clone()).await.unwrap();

        let action = ActionTypeDef {
            name: "tenkai.conformance.set_status".into(),
            description: "set status".into(),
            params: vec![],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "status".into(),
                value_from: "status".into(),
                relation: String::new(),
            }],
            target_kind: "tenkai.conformance".into(),
            created: 1,
            required_purpose: "delivery".into(),
        };
        ctx.register_action(action).await.unwrap();

        let params = std::collections::HashMap::from([
            ("id".into(), target.id.clone()),
            ("status".into(), "ready".into()),
        ]);
        let preview = ctx
            .preview_action_result("tenkai.conformance.set_status", params.clone())
            .await
            .unwrap();
        assert_eq!(preview.decision, "allow");
        assert!(preview.dry_run);
        assert_eq!(
            ctx.get(&target.id)
                .await
                .unwrap()
                .unwrap()
                .properties
                .get("status"),
            None
        );

        let executed = ctx
            .execute_action_result("tenkai.conformance.set_status", params)
            .await
            .unwrap();
        assert_eq!(executed.decision, "allow");
        assert!(!executed.dry_run);
        assert_eq!(
            ctx.get(&target.id)
                .await
                .unwrap()
                .unwrap()
                .properties
                .get("status")
                .map(String::as_str),
            Some("ready")
        );

        let decisions = ctx
            .action_decisions("", "tenkai.conformance.set_status", 0)
            .await
            .unwrap();
        assert!(!decisions.is_empty());
        assert!(
            decisions
                .iter()
                .any(|decision| decision.target_id == target.id)
        );

        let deny = ctx.deny_action("approval-conformance", "blocked").await;
        if ctx.is_embedded() {
            assert!(deny.is_err());
        } else {
            deny.unwrap();
        }
    }

    #[tokio::test]
    async fn embedded_ctx_conforms_to_action_lifecycle() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-ctx-action-conformance-{}.db",
            uuid::Uuid::new_v4()
        ));
        let ctx = Ctx::embedded(&path).unwrap();
        assert_action_lifecycle(ctx).await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn remote_ctx_conforms_to_action_lifecycle() {
        let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
        assert_action_lifecycle(ctx).await;
        server.abort();
    }

    #[test]
    fn bearer_tokens_require_tls_or_loopback() {
        assert!(token_transport_is_safe("https://sekai.example.com"));
        assert!(token_transport_is_safe("http://127.0.0.1:50051"));
        assert!(token_transport_is_safe("http://[::1]:50051"));
        assert!(!token_transport_is_safe("http://sekai.example.com"));
        assert!(!token_transport_is_safe("http://127.0.0.1.evil.test"));
        assert!(!token_transport_is_safe(
            "http://localhost:80@attacker.example:50051"
        ));
    }

    #[test]
    fn remote_client_config_redacts_credentials_and_preserves_principal() {
        let config = ClientConfig::new("http://127.0.0.1:50051", "tenkai.operator")
            .with_token("provider-token")
            .unwrap();

        assert_eq!(config.principal, "tenkai.operator");
        assert_eq!(
            format!("{:?}", config.credential.as_ref().unwrap()),
            "Credential(REDACTED)"
        );
    }

    #[test]
    fn canonical_fenced_requests_preserve_lease_identity_and_request_id() {
        let precondition = lease_precondition("tenkai", "environment/prod", "fence-7");
        let create = canonical_create_request(
            Object {
                id: "object-1".into(),
                ..Default::default()
            },
            Some(precondition.clone()),
        );
        let update = canonical_update_request(
            Object {
                id: "object-1".into(),
                ..Default::default()
            },
            Some(precondition),
        );

        let create_lease = create.lease_precondition.as_ref().unwrap();
        let update_lease = update.lease_precondition.as_ref().unwrap();
        assert_eq!(create_lease.namespace, "tenkai");
        assert_eq!(create_lease.key, "environment/prod");
        assert_eq!(create_lease.fencing_token, "fence-7");
        assert!(!create_lease.request_id.is_empty());
        assert_eq!(create_lease, update_lease);
    }

    #[test]
    fn emergency_override_actor_uses_property_change_field() {
        let changes = vec![ObjectChange {
            field: "properties.last_emergency_override_correlation".into(),
            new_value: "correlation-1".into(),
            changed_by: "authenticated-operator".into(),
            ..Default::default()
        }];

        assert_eq!(
            action_actor_from_changes(
                &changes,
                "properties.last_emergency_override_correlation",
                "correlation-1"
            )
            .as_deref(),
            Some("authenticated-operator")
        );
        assert_eq!(
            action_actor_from_changes(
                &changes,
                "properties.last_emergency_override_correlation",
                "correlation-2"
            ),
            None
        );
    }

    #[tokio::test]
    async fn embedded_gate_evidence_lookup_fails_locally_without_networking() {
        let path =
            std::env::temp_dir().join(format!("tenkai-embedded-gate-{}.db", uuid::Uuid::new_v4()));
        let mut ctx = Ctx::embedded(&path).unwrap();
        let error = ctx
            .evaluation_gate_evidence(crate::pb::chisei::GetEvaluationGateEvidenceRequest {
                suite_id: "required-suite".into(),
                release_digest: "release".into(),
                artifact_digest: "artifact".into(),
                max_timestamp_ms: 1,
            })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("embedded mode has no governance provider")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn remote_fenced_writes_use_canonical_rpc_and_reuse_request_id_on_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = MockSekaiState {
            create_failures: Arc::new(AtomicUsize::new(1)),
            update_failures: Arc::new(AtomicUsize::new(1)),
            ..Default::default()
        };
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(server_state)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = super::RemoteClient::connect(
            ClientConfig::new(format!("http://{address}"), "tenkai.test").with_retry_policy(
                RetryPolicy {
                    max_attempts: 2,
                    initial_backoff: std::time::Duration::ZERO,
                    max_backoff: std::time::Duration::ZERO,
                    retryable_codes: vec![
                        SdkErrorCode::Unavailable,
                        SdkErrorCode::DeadlineExceeded,
                    ],
                },
            ),
        )
        .await
        .unwrap();
        let mut ctx = Ctx {
            backend: Backend::Remote {
                client: Arc::new(client),
                action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            },
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_export_enabled: false,
            outcome_inspection_enabled: false,
        };
        let object = Object {
            id: "tenkai:object:remote".into(),
            ..Default::default()
        };

        ctx.guarded_create(object.clone(), "tenkai", "environment/prod", "fence-7")
            .await
            .unwrap();
        ctx.guarded_update(object, "tenkai", "environment/prod", "fence-7")
            .await
            .unwrap();

        let creates = state.creates.lock().unwrap().clone();
        assert_eq!(creates.len(), 2);
        assert_eq!(creates[0].lease_precondition, creates[1].lease_precondition);
        assert_eq!(
            creates[0]
                .lease_precondition
                .as_ref()
                .unwrap()
                .fencing_token,
            "fence-7"
        );
        let updates = state.updates.lock().unwrap().clone();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].lease_precondition, updates[1].lease_precondition);
        assert_eq!(
            updates[0]
                .lease_precondition
                .as_ref()
                .unwrap()
                .fencing_token,
            "fence-7"
        );

        server.abort();
    }

    #[tokio::test]
    async fn remote_create_reclassifies_existing_object_after_sanitized_internal_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = MockSekaiState {
            create_internal_failures: Arc::new(AtomicUsize::new(1)),
            ..Default::default()
        };
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(server_state)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = super::RemoteClient::connect(ClientConfig::new(
            format!("http://{address}"),
            "tenkai.test",
        ))
        .await
        .unwrap();
        let mut ctx = Ctx {
            backend: Backend::Remote {
                client: Arc::new(client),
                action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            },
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_export_enabled: false,
            outcome_inspection_enabled: false,
        };

        let object = Object {
            id: "tenkai:object:conflict".into(),
            ..Default::default()
        };
        let error = ctx.create_once(object.clone()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::AlreadyExists);
        assert_eq!(ctx.get(&object.id).await.unwrap().unwrap(), object);

        server.abort();
    }

    #[tokio::test]
    async fn remote_graph_action_registration_uses_governed_rpc() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = MockSekaiState::default();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(server_state)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = super::RemoteClient::connect(
            ClientConfig::new(format!("http://{address}"), "tenkai.test")
                .with_token("provider-token")
                .unwrap()
                .with_retry_policy(RetryPolicy {
                    max_attempts: 2,
                    initial_backoff: std::time::Duration::ZERO,
                    max_backoff: std::time::Duration::ZERO,
                    retryable_codes: vec![
                        SdkErrorCode::Unavailable,
                        SdkErrorCode::DeadlineExceeded,
                    ],
                }),
        )
        .await
        .unwrap();
        let mut ctx = Ctx {
            backend: Backend::Remote {
                client: Arc::new(client),
                action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            },
            canary_schema_preflight: Arc::new(OnceCell::new()),
            outcome_export_enabled: false,
            outcome_inspection_enabled: false,
        };
        let action = ActionTypeDef {
            name: "tenkai.replace_subscription".into(),
            description: "replace a subscription".into(),
            params: vec![],
            ops: vec![ActionOp {
                op: "create_link".into(),
                property: "channel_id".into(),
                value_from: String::new(),
                relation: "subscribes".into(),
            }],
            target_kind: "tenkai.environment".into(),
            created: 42,
            required_purpose: "delivery".into(),
        };

        ctx.register_action(action.clone()).await.unwrap();

        let registered = state.governed_actions.lock().unwrap().clone();
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].namespace, "tenkai");
        assert_eq!(registered[0].type_id, action.name);
        assert_eq!(registered[0].version, "1");
        assert!(registered[0].enabled);
        assert!(registered[0].parameter_schema_json.contains("\"id\""));
        assert_eq!(
            state.metadata.lock().unwrap().as_slice(),
            [(
                Some("tenkai.test".into()),
                Some("Bearer provider-token".into())
            )]
        );
        server.abort();
    }
}

//! Connection to a local sekai-chisei server, plus thin object/link helpers.

use anyhow::{Context as _, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

use crate::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::pb::chisei::{
    EvalRun, EvalSuite, GetEvalRunRequest, GetEvalSuiteRequest, ListEvalRunsRequest,
};
use crate::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::pb::sekai::{
    ActionRequest, ActionResult, ActionTypeDef, CreateLinkRequest, CreateObjectRequest, Decision,
    DeleteLinkRequest, DeleteObjectRequest, DenyActionRequest, ExecuteActionRequest,
    FindByPropertyRequest, GetLinkedObjectsRequest, GetLinksRequest, GetObjectRequest,
    GuardedCreateObjectRequest, GuardedUpdateObjectRequest, Lease, LeasePrecondition, Link,
    ListDecisionsRequest, ListFilter, ListObjectChangesRequest, ListObjectsRequest, Object,
    ObjectChange, ObjectType, UpdateObjectRequest,
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

/// Attaches auth + caller identity metadata to every request.
#[derive(Clone)]
pub struct Meta {
    token: Option<String>,
    principal: String,
}

impl Interceptor for Meta {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = &self.token {
            let value: MetadataValue<_> = format!("Bearer {token}")
                .parse()
                .map_err(|_| Status::internal("invalid auth token"))?;
            req.metadata_mut().insert("authorization", value);
        }
        let principal: MetadataValue<_> = self
            .principal
            .parse()
            .map_err(|_| Status::internal("invalid principal"))?;
        req.metadata_mut().insert("x-principal", principal);
        Ok(req)
    }
}

pub type Sekai = SekaiServiceClient<InterceptedService<Channel, Meta>>;
pub type Chisei = ChiseiServiceClient<InterceptedService<Channel, Meta>>;

#[derive(Clone)]
pub struct Ctx {
    backend: Backend,
    canary_schema_preflight: Arc<OnceCell<()>>,
}

#[derive(Clone)]
enum Backend {
    Remote {
        sekai: Box<Sekai>,
        chisei: Box<Chisei>,
    },
    Embedded(Arc<crate::embedded::EmbeddedStore>),
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
    let channel = Endpoint::from_shared(url.clone())?
        .connect()
        .await
        .with_context(|| {
            format!(
                "connecting to sekai-chisei at {url} — is the server running? (SEKAI_INSECURE=1 cargo run)"
            )
        })?;
    let meta = Meta {
        token,
        principal: std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into()),
    };
    Ok(Ctx {
        backend: Backend::Remote {
            sekai: Box::new(SekaiServiceClient::with_interceptor(
                channel.clone(),
                meta.clone(),
            )),
            chisei: Box::new(ChiseiServiceClient::with_interceptor(channel, meta)),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
    })
}

impl Ctx {
    /// Open the complete in-process backend used by the solo CLI.
    pub fn embedded(path: impl AsRef<Path>) -> Result<Self> {
        let principal = std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into());
        Ok(Self {
            backend: Backend::Embedded(Arc::new(crate::embedded::EmbeddedStore::open(
                path, principal,
            )?)),
            canary_schema_preflight: Arc::new(OnceCell::new()),
        })
    }

    pub fn is_embedded(&self) -> bool {
        matches!(self.backend, Backend::Embedded(_))
    }

    pub fn backup_embedded(&self, destination: impl AsRef<Path>) -> Result<()> {
        self.embedded_store()
            .context("backup is available only in embedded mode")?
            .backup(destination)
    }

    fn remote(&mut self) -> Result<(&mut Sekai, &mut Chisei)> {
        match &mut self.backend {
            Backend::Remote { sekai, chisei } => Ok((sekai.as_mut(), chisei.as_mut())),
            Backend::Embedded(_) => {
                anyhow::bail!("operation requires a configured remote provider")
            }
        }
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
        let (sekai, _) = self
            .remote()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        sekai
            .create_schema_type(crate::pb::sekai::CreateSchemaTypeRequest {
                r#type: Some(schema),
            })
            .await?;
        Ok(())
    }

    pub(crate) async fn schemas(&mut self) -> Result<Vec<ObjectType>> {
        if let Some(store) = self.embedded_store() {
            return store.schemas();
        }
        let (sekai, _) = self.remote()?;
        Ok(sekai
            .list_schema_types(crate::pb::sekai::ListSchemaTypesRequest {})
            .await?
            .into_inner()
            .types)
    }

    pub(crate) async fn register_action(
        &mut self,
        action: ActionTypeDef,
    ) -> std::result::Result<(), tonic::Status> {
        if let Some(store) = self.embedded_store() {
            return store.register_action(action);
        }
        let (sekai, _) = self
            .remote()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        sekai
            .create_action_type(crate::pb::sekai::CreateActionTypeRequest {
                action_type: Some(action),
            })
            .await?;
        Ok(())
    }

    pub(crate) async fn eval_suite(&mut self, id: &str) -> Result<Option<EvalSuite>> {
        if self.is_embedded() {
            anyhow::bail!(
                "embedded mode has no governance provider; configure remote provider mode for eval suite {id}"
            );
        }
        let (_, chisei) = self.remote()?;
        match chisei
            .get_eval_suite(GetEvalSuiteRequest { id: id.into() })
            .await
        {
            Ok(response) => Ok(response.into_inner().suite),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status.into()),
        }
    }

    pub(crate) async fn eval_runs(&mut self, suite_id: &str) -> Result<Vec<EvalRun>> {
        if self.is_embedded() {
            anyhow::bail!(
                "embedded mode has no governance provider; configure remote provider mode for eval suite {suite_id}"
            );
        }
        let (_, chisei) = self.remote()?;
        Ok(chisei
            .list_eval_runs(ListEvalRunsRequest {
                suite_id: suite_id.into(),
            })
            .await?
            .into_inner()
            .runs)
    }

    pub(crate) async fn eval_run(&mut self, id: &str) -> Result<Option<EvalRun>> {
        if self.is_embedded() {
            anyhow::bail!("embedded mode has no governance provider; cannot load eval run {id}");
        }
        let (_, chisei) = self.remote()?;
        match chisei
            .get_eval_run(GetEvalRunRequest { id: id.into() })
            .await
        {
            Ok(response) => Ok(response.into_inner().run),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status.into()),
        }
    }

    pub(crate) async fn acquire_lease(
        &mut self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        if let Some(store) = self.embedded_store() {
            return store.acquire_lease(namespace, key, owner, ttl_ms);
        }
        let (sekai, _) = self.remote()?;
        sekai
            .acquire_lease(crate::pb::sekai::AcquireLeaseRequest {
                namespace: namespace.into(),
                key: key.into(),
                owner: owner.into(),
                ttl_ms,
                request_id: uuid::Uuid::new_v4().to_string(),
            })
            .await?
            .into_inner()
            .lease
            .context("provider returned an empty lease")
    }

    pub(crate) async fn get_lease(&mut self, namespace: &str, key: &str) -> Result<Option<Lease>> {
        if let Some(store) = self.embedded_store() {
            return store.get_lease(namespace, key);
        }
        let (sekai, _) = self.remote()?;
        match sekai
            .get_lease(crate::pb::sekai::GetLeaseRequest {
                namespace: namespace.into(),
                key: key.into(),
            })
            .await
        {
            Ok(response) => Ok(response.into_inner().lease),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status.into()),
        }
    }

    pub(crate) async fn refresh_lease(
        &mut self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
        ttl_ms: i64,
    ) -> Result<Lease> {
        if let Some(store) = self.embedded_store() {
            return store.refresh_lease(namespace, key, fencing_token, ttl_ms);
        }
        let (sekai, _) = self.remote()?;
        sekai
            .refresh_lease(crate::pb::sekai::RefreshLeaseRequest {
                namespace: namespace.into(),
                key: key.into(),
                fencing_token: fencing_token.into(),
                ttl_ms,
                request_id: uuid::Uuid::new_v4().to_string(),
            })
            .await?
            .into_inner()
            .lease
            .context("provider returned an empty refreshed lease")
    }

    pub(crate) async fn release_lease(
        &mut self,
        namespace: &str,
        key: &str,
        fencing_token: &str,
    ) -> Result<Lease> {
        if let Some(store) = self.embedded_store() {
            return store.release_lease(namespace, key, fencing_token);
        }
        let (sekai, _) = self.remote()?;
        sekai
            .release_lease(crate::pb::sekai::ReleaseLeaseRequest {
                namespace: namespace.into(),
                key: key.into(),
                fencing_token: fencing_token.into(),
                request_id: uuid::Uuid::new_v4().to_string(),
            })
            .await?
            .into_inner()
            .lease
            .context("provider returned an empty released lease")
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
        if let Some(store) = self.embedded_store() {
            return store.takeover_lease(
                namespace,
                key,
                owner,
                expected_fencing_token,
                expected_expires_at_ms,
                ttl_ms,
            );
        }
        let (sekai, _) = self.remote()?;
        sekai
            .takeover_expired_lease(crate::pb::sekai::TakeoverExpiredLeaseRequest {
                namespace: namespace.into(),
                key: key.into(),
                owner: owner.into(),
                expected_fencing_token: expected_fencing_token.into(),
                expected_expires_at_ms,
                ttl_ms,
                request_id: uuid::Uuid::new_v4().to_string(),
            })
            .await?
            .into_inner()
            .lease
            .context("provider returned an empty takeover lease")
    }

    pub(crate) fn canary_schema_preflight(&self) -> Arc<OnceCell<()>> {
        Arc::clone(&self.canary_schema_preflight)
    }

    /// Get an object by id; `None` on not-found.
    pub async fn get(&mut self, id: &str) -> Result<Option<Object>> {
        let Some(store) = self.embedded_store() else {
            let (sekai, _) = self.remote()?;
            return match sekai.get_object(GetObjectRequest { id: id.into() }).await {
                Ok(resp) => Ok(resp.into_inner().object),
                Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
                Err(status) => Err(status.into()),
            };
        };
        store.get(id)
    }

    /// Create an object without falling back to update when its id exists.
    pub async fn create_once(
        &mut self,
        object: Object,
    ) -> std::result::Result<Object, tonic::Status> {
        if let Some(store) = self.embedded_store() {
            return store.create(object);
        }
        let (sekai, _) = self
            .remote()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        Ok(sekai
            .create_object(CreateObjectRequest {
                object: Some(object),
            })
            .await?
            .into_inner()
            .object
            .unwrap_or_default())
    }

    pub async fn delete(&mut self, id: &str) -> Result<()> {
        if let Some(store) = self.embedded_store() {
            return store.delete(id);
        }
        let (sekai, _) = self.remote()?;
        sekai
            .delete_object(DeleteObjectRequest { id: id.into() })
            .await?;
        Ok(())
    }

    /// Create the object, or update it if the id already exists.
    pub async fn put(&mut self, object: Object) -> Result<Object> {
        if let Some(store) = self.embedded_store() {
            return store.put(object);
        }
        let existing = self.get(&object.id).await?;
        let (sekai, _) = self.remote()?;
        let resp = if existing.is_some() {
            sekai
                .update_object(UpdateObjectRequest {
                    object: Some(object),
                })
                .await?
                .into_inner()
                .object
        } else {
            sekai
                .create_object(CreateObjectRequest {
                    object: Some(object),
                })
                .await?
                .into_inner()
                .object
        };
        Ok(resp.unwrap_or_default())
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
        let request = GuardedCreateObjectRequest {
            object: Some(object),
            lease_precondition: Some(LeasePrecondition {
                namespace: lease_namespace.into(),
                key: lease_key.into(),
                fencing_token: fencing_token.into(),
                request_id: uuid::Uuid::new_v4().to_string(),
            }),
        };
        let (sekai, _) = self.remote()?;
        let response = match sekai.guarded_create_object(request.clone()).await {
            Ok(response) => response,
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                ) =>
            {
                sekai.guarded_create_object(request).await?
            }
            Err(status) => return Err(status.into()),
        };
        response
            .into_inner()
            .object
            .context("Sekai returned an empty guarded create result")
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
        let request = GuardedUpdateObjectRequest {
            object: Some(object),
            lease_precondition: Some(LeasePrecondition {
                namespace: lease_namespace.into(),
                key: lease_key.into(),
                fencing_token: fencing_token.into(),
                request_id: uuid::Uuid::new_v4().to_string(),
            }),
        };
        let (sekai, _) = self.remote()?;
        let response = match sekai.guarded_update_object(request.clone()).await {
            Ok(response) => response,
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                ) =>
            {
                sekai.guarded_update_object(request).await?
            }
            Err(status) => return Err(status.into()),
        };
        response
            .into_inner()
            .object
            .context("Sekai returned an empty guarded update result")
    }

    /// Create a link with a deterministic id; already-exists is treated as success.
    pub async fn link(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let link = Link {
            id: format!("{from_id}--{relation}--{to_id}"),
            from_id: from_id.into(),
            to_id: to_id.into(),
            relation: relation.into(),
            created: crate::now_millis(),
        };
        if let Some(store) = self.embedded_store() {
            return store.create_link(link, false).map_err(anyhow::Error::from);
        }
        let (sekai, _) = self.remote()?;
        match sekai
            .create_link(CreateLinkRequest {
                link: Some(link),
                fail_if_exists: false,
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(status) if status.code() == tonic::Code::AlreadyExists => Ok(()),
            // The server surfaces duplicate-key inserts as internal errors; a
            // deterministic link id makes retrying the same link idempotent.
            Err(status)
                if status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE") =>
            {
                Ok(())
            }
            Err(status) => Err(status.into()),
        }
    }

    /// Create one exact link and preserve duplicate errors for lock acquisition.
    pub(crate) async fn create_link_once(
        &mut self,
        link: Link,
    ) -> std::result::Result<(), tonic::Status> {
        if let Some(store) = self.embedded_store() {
            return store.create_link(link, true);
        }
        let (sekai, _) = self
            .remote()
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        sekai
            .create_link(CreateLinkRequest {
                link: Some(link),
                fail_if_exists: true,
            })
            .await?;
        Ok(())
    }

    pub async fn unlink(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let id = format!("{from_id}--{relation}--{to_id}");
        if let Some(store) = self.embedded_store() {
            return store.unlink(&id);
        }
        let (sekai, _) = self.remote()?;
        match sekai.delete_link(DeleteLinkRequest { id }).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(()),
            Err(status) => Err(status.into()),
        }
    }

    pub async fn linked(
        &mut self,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> Result<Vec<Object>> {
        if let Some(store) = self.embedded_store() {
            return store.linked(object_id, relation, direction);
        }
        let (sekai, _) = self.remote()?;
        Ok(sekai
            .get_linked_objects(GetLinkedObjectsRequest {
                object_id: object_id.into(),
                relation: relation.into(),
                direction: direction.into(),
            })
            .await?
            .into_inner()
            .objects)
    }

    pub async fn find_by_property(
        &mut self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>> {
        if let Some(store) = self.embedded_store() {
            return store.find_by_property(kind, key, value);
        }
        let (sekai, _) = self.remote()?;
        Ok(sekai
            .find_by_property(FindByPropertyRequest {
                kind: kind.into(),
                key: key.into(),
                value: value.into(),
            })
            .await?
            .into_inner()
            .objects)
    }

    pub async fn links(&mut self, object_id: &str, relation: &str) -> Result<Vec<Link>> {
        if let Some(store) = self.embedded_store() {
            return store.links(object_id, relation, "out");
        }
        let (sekai, _) = self.remote()?;
        Ok(sekai
            .get_links(GetLinksRequest {
                object_id: object_id.into(),
                relation: relation.into(),
                direction: "out".into(),
            })
            .await?
            .into_inner()
            .links)
    }

    pub async fn list_kind(&mut self, kind: &str) -> Result<Vec<Object>> {
        if let Some(store) = self.embedded_store() {
            return store.list_kind(kind);
        }
        const PAGE_SIZE: i32 = 100;
        let mut objects = Vec::new();
        let (sekai, _) = self.remote()?;
        loop {
            let response = sekai
                .list_objects(ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: kind.into(),
                        limit: PAGE_SIZE,
                        offset: objects.len() as i32,
                        ..Default::default()
                    }),
                })
                .await?
                .into_inner();
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
        self.action_result_with_mode(action, params, false).await
    }

    pub async fn preview_action_result(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<ActionResult> {
        self.action_result_with_mode(action, params, true).await
    }

    async fn action_result_with_mode(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
        dry_run: bool,
    ) -> Result<ActionResult> {
        if let Some(store) = self.embedded_store() {
            return store.execute_action(action, params, dry_run);
        }
        let (sekai, _) = self.remote()?;
        sekai
            .execute_action(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: action.into(),
                    params,
                    actor: String::new(),
                }),
                dry_run,
            })
            .await?
            .into_inner()
            .result
            .context("governed action returned no result")
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
        if self.is_embedded() {
            anyhow::bail!(
                "embedded mode has no deferred approvals; action {approval_id} cannot be denied"
            );
        }
        let (sekai, _) = self.remote()?;
        sekai
            .deny_action(DenyActionRequest {
                approval_id: approval_id.into(),
                reason: reason.into(),
            })
            .await?;
        Ok(())
    }

    pub async fn action_decisions(
        &mut self,
        actor: &str,
        action: &str,
        after: i64,
    ) -> Result<Vec<Decision>> {
        if let Some(store) = self.embedded_store() {
            return store.decisions(actor, action, after);
        }
        let (sekai, _) = self.remote()?;
        Ok(sekai
            .list_decisions(ListDecisionsRequest {
                actor: actor.into(),
                action: action.into(),
                after,
                limit: i32::MAX,
            })
            .await?
            .into_inner()
            .decisions)
    }

    pub async fn object_changes(&mut self, object_id: &str) -> Result<Vec<ObjectChange>> {
        if let Some(store) = self.embedded_store() {
            return store.changes(object_id);
        }
        let mut offset = 0;
        let mut all = Vec::new();
        let (sekai, _) = self.remote()?;
        loop {
            let changes = sekai
                .list_object_changes(ListObjectChangesRequest {
                    object_id: object_id.into(),
                    limit: 100,
                    offset,
                })
                .await?
                .into_inner()
                .changes;
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
                    "emergency maintenance override requires approval {}; the pinned Sekai API cannot safely resume approved actions, so this apply remains blocked",
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
    use super::{Ctx, action_actor_from_changes, token_transport_is_safe};
    use crate::pb::sekai::ObjectChange;

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
    async fn embedded_gate_lookup_fails_locally_without_networking() {
        let path =
            std::env::temp_dir().join(format!("tenkai-embedded-gate-{}.db", uuid::Uuid::new_v4()));
        let mut ctx = Ctx::embedded(&path).unwrap();
        let error = ctx.eval_suite("required-suite").await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("embedded mode has no governance provider")
        );
        std::fs::remove_file(path).unwrap();
    }
}

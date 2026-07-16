//! Connection to a local sekai-chisei server, plus thin object/link helpers.

use anyhow::{Context as _, Result};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

use crate::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::pb::sekai::{
    CreateLinkRequest, CreateObjectRequest, GetLinkedObjectsRequest, GetObjectRequest, Link,
    Object, UpdateObjectRequest,
};

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

pub struct Ctx {
    pub sekai: Sekai,
    pub chisei: Chisei,
}

/// Connect to sekai-chisei. Honors `TENKAI_SEKAI_URL`, `GRPC_PORT`,
/// `SEKAI_AUTH_TOKEN`, and `TENKAI_PRINCIPAL` (default `tenkai`).
pub async fn connect() -> Result<Ctx> {
    let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".into());
    let url =
        std::env::var("TENKAI_SEKAI_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
    let channel = Endpoint::from_shared(url.clone())?
        .connect()
        .await
        .with_context(|| {
            format!(
                "connecting to sekai-chisei at {url} — is the server running? (SEKAI_INSECURE=1 cargo run)"
            )
        })?;
    let meta = Meta {
        token: std::env::var("SEKAI_AUTH_TOKEN").ok(),
        principal: std::env::var("TENKAI_PRINCIPAL").unwrap_or_else(|_| "tenkai".into()),
    };
    Ok(Ctx {
        sekai: SekaiServiceClient::with_interceptor(channel.clone(), meta.clone()),
        chisei: ChiseiServiceClient::with_interceptor(channel, meta),
    })
}

impl Ctx {
    /// Get an object by id; `None` on not-found.
    pub async fn get(&mut self, id: &str) -> Result<Option<Object>> {
        match self
            .sekai
            .get_object(GetObjectRequest { id: id.into() })
            .await
        {
            Ok(resp) => Ok(resp.into_inner().object),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status.into()),
        }
    }

    /// Create the object, or update it if the id already exists.
    pub async fn put(&mut self, object: Object) -> Result<Object> {
        let existing = self.get(&object.id).await?;
        let resp = if existing.is_some() {
            self.sekai
                .update_object(UpdateObjectRequest {
                    object: Some(object),
                })
                .await?
                .into_inner()
                .object
        } else {
            self.sekai
                .create_object(CreateObjectRequest {
                    object: Some(object),
                })
                .await?
                .into_inner()
                .object
        };
        Ok(resp.unwrap_or_default())
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
        match self
            .sekai
            .create_link(CreateLinkRequest { link: Some(link) })
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

    pub async fn linked(
        &mut self,
        object_id: &str,
        relation: &str,
        direction: &str,
    ) -> Result<Vec<Object>> {
        Ok(self
            .sekai
            .get_linked_objects(GetLinkedObjectsRequest {
                object_id: object_id.into(),
                relation: relation.into(),
                direction: direction.into(),
            })
            .await?
            .into_inner()
            .objects)
    }
}

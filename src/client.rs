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
    ActionRequest, CreateLinkRequest, CreateObjectRequest, DeleteLinkRequest, DeleteObjectRequest,
    ExecuteActionRequest, FindByPropertyRequest, GetLinkedObjectsRequest, GetLinksRequest,
    GetObjectRequest, Link, ListFilter, ListObjectsRequest, Object, UpdateObjectRequest,
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

pub(crate) const CONTROL_PLANE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone)]
pub struct Ctx {
    pub sekai: Sekai,
    pub chisei: Chisei,
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
        .timeout(CONTROL_PLANE_TIMEOUT)
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
        sekai: SekaiServiceClient::with_interceptor(channel.clone(), meta.clone()),
        chisei: ChiseiServiceClient::with_interceptor(channel, meta),
    })
}

impl Ctx {
    /// List every object of a kind in a namespace, following offset pages.
    pub async fn list_kind(&mut self, kind: &str, namespace: &str) -> Result<Vec<Object>> {
        const PAGE_SIZE: i32 = 100;
        let mut objects = Vec::new();
        loop {
            let response = self
                .sekai
                .list_objects(ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: kind.into(),
                        namespace: namespace.into(),
                        limit: PAGE_SIZE,
                        offset: objects.len() as i32,
                        ..Default::default()
                    }),
                })
                .await?
                .into_inner();
            let page_len = response.objects.len();
            objects.extend(response.objects);
            if page_len < PAGE_SIZE as usize
                || (response.total > 0 && objects.len() >= response.total as usize)
            {
                break;
            }
        }
        Ok(objects)
    }

    pub async fn find_by_property(
        &mut self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>> {
        Ok(self
            .sekai
            .find_by_property(FindByPropertyRequest {
                kind: kind.into(),
                key: key.into(),
                value: value.into(),
            })
            .await?
            .into_inner()
            .objects)
    }

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

    /// Create an object without falling back to update when its id exists.
    pub async fn create_once(
        &mut self,
        object: Object,
    ) -> std::result::Result<Object, tonic::Status> {
        Ok(self
            .sekai
            .create_object(CreateObjectRequest {
                object: Some(object),
            })
            .await?
            .into_inner()
            .object
            .unwrap_or_default())
    }

    pub async fn delete(&mut self, id: &str) -> Result<()> {
        self.sekai
            .delete_object(DeleteObjectRequest { id: id.into() })
            .await?;
        Ok(())
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

    pub async fn unlink(&mut self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let id = format!("{from_id}--{relation}--{to_id}");
        match self.sekai.delete_link(DeleteLinkRequest { id }).await {
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

    pub async fn links(&mut self, object_id: &str, relation: &str) -> Result<Vec<Link>> {
        Ok(self
            .sekai
            .get_links(GetLinksRequest {
                object_id: object_id.into(),
                relation: relation.into(),
                direction: "out".into(),
            })
            .await?
            .into_inner()
            .links)
    }

    pub async fn execute_action(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let result = self
            .sekai
            .execute_action(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: action.into(),
                    params,
                    actor: String::new(),
                }),
                dry_run: false,
            })
            .await?
            .into_inner()
            .result
            .context("governed action returned no result")?;
        if result.decision != "allow" {
            anyhow::bail!("action {action} was not allowed: {}", result.decision);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::token_transport_is_safe;

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
}

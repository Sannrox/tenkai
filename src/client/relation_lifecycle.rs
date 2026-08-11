//! Relation lifecycle semantics across embedded and remote adapters.

use anyhow::Result;
use prost::Message;
use sekai_client::CallOptions;

use super::{RemoteClient, sdk_error_status};
use crate::pb::sekai::{
    CreateLinkRequest, CreateLinkResponse, DeleteLinkRequest, DeleteLinkResponse,
    GetLinkedObjectsRequest, GetLinkedObjectsResponse, GetLinksRequest, GetLinksResponse, Link,
    Object,
};

pub(super) enum RelationLifecycle<'a> {
    Remote(&'a RemoteClient),
    Embedded(&'a crate::embedded::EmbeddedStore),
}

impl RelationLifecycle<'_> {
    pub(super) async fn link(&self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let link = Link {
            id: format!("{from_id}--{relation}--{to_id}"),
            from_id: from_id.into(),
            to_id: to_id.into(),
            relation: relation.into(),
            created: crate::now_millis(),
        };
        match self {
            Self::Embedded(store) => store.create_link(link, false).map_err(anyhow::Error::from),
            Self::Remote(client) => {
                let link_id = link.id.clone();
                let from_id = link.from_id.clone();
                let relation_name = link.relation.clone();
                let response: std::result::Result<CreateLinkResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/CreateLink",
                        CreateLinkRequest {
                            link: Some(link),
                            fail_if_exists: true,
                        },
                    )
                    .await;
                match response {
                    Ok(_) => Ok(()),
                    Err(status) if status.code() == tonic::Code::AlreadyExists => Ok(()),
                    Err(status)
                        if status.code() == tonic::Code::Internal
                            && remote_link_exists(client, &from_id, &relation_name, &link_id)
                                .await =>
                    {
                        Ok(())
                    }
                    Err(status) => Err(status.into()),
                }
            }
        }
    }

    pub(super) async fn create_link_once(
        &self,
        link: Link,
    ) -> std::result::Result<(), tonic::Status> {
        match self {
            Self::Embedded(store) => store.create_link(link, true),
            Self::Remote(client) => {
                let link_id = link.id.clone();
                let from_id = link.from_id.clone();
                let relation_name = link.relation.clone();
                let response: std::result::Result<CreateLinkResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/CreateLink",
                        CreateLinkRequest {
                            link: Some(link),
                            fail_if_exists: true,
                        },
                    )
                    .await;
                match response {
                    Ok(_) => Ok(()),
                    Err(status)
                        if status.code() == tonic::Code::Internal
                            && remote_link_exists(client, &from_id, &relation_name, &link_id)
                                .await =>
                    {
                        Err(tonic::Status::already_exists("link already exists"))
                    }
                    Err(status) => Err(status),
                }
            }
        }
    }

    pub(super) async fn unlink(&self, from_id: &str, to_id: &str, relation: &str) -> Result<()> {
        let id = format!("{from_id}--{relation}--{to_id}");
        match self {
            Self::Embedded(store) => store.unlink(&id),
            Self::Remote(client) => {
                let response: std::result::Result<DeleteLinkResponse, tonic::Status> =
                    remote_unary(
                        client,
                        "/sekai.SekaiService/DeleteLink",
                        DeleteLinkRequest { id },
                    )
                    .await;
                match response {
                    Ok(_) => Ok(()),
                    Err(status) if status.code() == tonic::Code::NotFound => Ok(()),
                    Err(status) => Err(status.into()),
                }
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
            Self::Embedded(store) => store.linked(object_id, relation, direction),
            Self::Remote(client) => {
                let response: GetLinkedObjectsResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/GetLinkedObjects",
                    GetLinkedObjectsRequest {
                        object_id: object_id.into(),
                        relation: relation.into(),
                        direction: direction.into(),
                    },
                )
                .await?;
                Ok(response.objects)
            }
        }
    }

    pub(super) async fn links(&self, object_id: &str, relation: &str) -> Result<Vec<Link>> {
        match self {
            Self::Embedded(store) => store.links(object_id, relation, "out"),
            Self::Remote(client) => {
                let response: GetLinksResponse = remote_unary(
                    client,
                    "/sekai.SekaiService/GetLinks",
                    GetLinksRequest {
                        object_id: object_id.into(),
                        relation: relation.into(),
                        direction: "out".into(),
                    },
                )
                .await?;
                Ok(response.links)
            }
        }
    }
}

async fn remote_link_exists(
    client: &RemoteClient,
    from_id: &str,
    relation: &str,
    link_id: &str,
) -> bool {
    let response: std::result::Result<GetLinksResponse, tonic::Status> = remote_unary(
        client,
        "/sekai.SekaiService/GetLinks",
        GetLinksRequest {
            object_id: from_id.into(),
            relation: relation.into(),
            direction: "out".into(),
        },
    )
    .await;
    response.is_ok_and(|response| response.links.iter().any(|link| link.id == link_id))
}

async fn remote_unary<Req, Resp>(
    client: &RemoteClient,
    path: &str,
    request: Req,
) -> std::result::Result<Resp, tonic::Status>
where
    Req: Message + Default + Clone + Send + 'static,
    Resp: Message + Default + Send + 'static,
{
    client
        .raw()
        .unary(path, request, CallOptions::default())
        .await
        .map_err(sdk_error_status)
}

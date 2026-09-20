use std::future::Future;
use std::pin::Pin;

use super::mock_state::MockSekaiState;
use crate::pb::sekai::{
    CreateLinkRequest, CreateLinkResponse, DeleteLinkRequest, DeleteLinkResponse,
    GetLinkedObjectsRequest, GetLinkedObjectsResponse, GetLinksRequest, GetLinksResponse,
};

pub(super) struct CreateLinkRpc(pub(super) MockSekaiState);

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

pub(super) struct DeleteLinkRpc(pub(super) MockSekaiState);

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

pub(super) struct GetLinksRpc(pub(super) MockSekaiState);

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

pub(super) struct GetLinkedObjectsRpc(pub(super) MockSekaiState);

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

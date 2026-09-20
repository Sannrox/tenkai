use std::future::Future;
use std::pin::Pin;

use super::mock_state::{MockSekaiState, consume_failure};
use crate::pb::sekai::{
    CreateObjectRequest, CreateObjectResponse, DeleteObjectRequest, DeleteObjectResponse,
    FindByPropertyRequest, GetObjectRequest, GetObjectResponse, ListObjectsRequest,
    ListObjectsResponse, UpdateObjectRequest, UpdateObjectResponse,
};

pub(super) struct CreateObjectRpc(pub(super) MockSekaiState);

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

pub(super) struct GetObjectRpc(pub(super) MockSekaiState);

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

pub(super) struct FindByPropertyRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<FindByPropertyRequest> for FindByPropertyRpc {
    type Response = ListObjectsResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<FindByPropertyRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let request = request.into_inner();
            let objects = state
                .objects
                .lock()
                .unwrap()
                .values()
                .filter(|object| {
                    object.kind == request.kind
                        && object
                            .properties
                            .get(&request.key)
                            .is_some_and(|value| value == &request.value)
                })
                .cloned()
                .collect::<Vec<_>>();
            let total = objects.len() as i32;
            Ok(tonic::Response::new(ListObjectsResponse { objects, total }))
        })
    }
}

pub(super) struct ListObjectsRpc(pub(super) MockSekaiState);

impl tonic::server::UnaryService<ListObjectsRequest> for ListObjectsRpc {
    type Response = ListObjectsResponse;
    type Future = Pin<
        Box<dyn Future<Output = Result<tonic::Response<Self::Response>, tonic::Status>> + Send>,
    >;

    fn call(&mut self, request: tonic::Request<ListObjectsRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let filter = request.into_inner().filter.unwrap_or_default();
            let mut objects = state
                .objects
                .lock()
                .unwrap()
                .values()
                .filter(|object| filter.kind.is_empty() || object.kind == filter.kind)
                .cloned()
                .collect::<Vec<_>>();
            objects.sort_by(|left, right| left.id.cmp(&right.id));
            let total = objects.len() as i32;
            let offset = filter.offset.max(0) as usize;
            let limit = if filter.limit > 0 {
                filter.limit as usize
            } else {
                objects.len()
            };
            let objects = objects.into_iter().skip(offset).take(limit).collect();
            Ok(tonic::Response::new(ListObjectsResponse { objects, total }))
        })
    }
}

pub(super) struct UpdateObjectRpc(pub(super) MockSekaiState);

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

pub(super) struct DeleteObjectRpc(pub(super) MockSekaiState);

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

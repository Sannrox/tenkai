use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use sekai_client::ClientConfig;
use tokio::net::TcpListener;
use tokio::sync::OnceCell;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::mock_action_rpc::{
    GetGovernedActionTypeRpc, ListActionPoliciesRpc, ListDecisionsRpc, PutGovernedActionTypeRpc,
    RecordDecisionRpc, SubmitActionInstanceRpc,
};
use super::mock_lease_rpc::{
    AcquireLeaseRpc, GetLeaseRpc, RefreshLeaseRpc, ReleaseLeaseRpc, TakeoverExpiredLeaseRpc,
};
use super::mock_object_rpc::{
    CreateObjectRpc, DeleteObjectRpc, FindByPropertyRpc, GetObjectRpc, ListObjectsRpc,
    UpdateObjectRpc,
};
use super::mock_relation_rpc::{CreateLinkRpc, DeleteLinkRpc, GetLinkedObjectsRpc, GetLinksRpc};
use super::mock_state::MockSekaiState;
use crate::client::{Backend, Ctx, PlanKindListTick, RemoteClient};

impl tower::Service<tonic::codegen::http::Request<tonic::body::Body>> for MockSekaiState {
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
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
                "/sekai.SekaiService/FindByProperty" => {
                    let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                    grpc.unary(FindByPropertyRpc(state), request).await
                }
                "/sekai.SekaiService/ListObjects" => {
                    let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                    grpc.unary(ListObjectsRpc(state), request).await
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

pub(super) async fn remote_ctx(state: MockSekaiState) -> (Ctx, tokio::task::JoinHandle<()>) {
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
    let client = RemoteClient::connect(ClientConfig::new(
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
            plan_kind_list: Arc::new(PlanKindListTick::default()),
        },
        server,
    )
}

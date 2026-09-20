//! Embedded blocking and remote unary transport helpers.

use anyhow::{Result, anyhow};
use prost::Message;
use std::sync::Arc;
use tonic::Status;

use sekai_client::{CallOptions, CoreLoopClient, GrpcTransport, SdkError, SdkErrorCode};

pub(crate) type RemoteClient = CoreLoopClient<GrpcTransport>;

pub(crate) async fn block_embedded<T, F>(
    store: Arc<crate::storage::SqliteStore>,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&crate::storage::SqliteStore) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(&store))
        .await
        .unwrap_or_else(|error| Err(anyhow!("embedded store blocking task failed: {error}")))
}

pub(crate) async fn block_embedded_status<T, F>(
    store: Arc<crate::storage::SqliteStore>,
    operation: F,
) -> std::result::Result<T, tonic::Status>
where
    T: Send + 'static,
    F: FnOnce(&crate::storage::SqliteStore) -> std::result::Result<T, tonic::Status>
        + Send
        + 'static,
{
    tokio::task::spawn_blocking(move || operation(&store))
        .await
        .unwrap_or_else(|error| {
            Err(tonic::Status::unavailable(format!(
                "embedded store blocking task failed: {error}"
            )))
        })
}

pub(crate) async fn remote_unary<Req, Resp>(
    client: &RemoteClient,
    path: &str,
    request: Req,
) -> std::result::Result<Resp, tonic::Status>
where
    Req: Message + Default + Clone + Send + 'static,
    Resp: Message + Default + Send + 'static,
{
    remote_unary_with_options(client, path, request, CallOptions::default()).await
}

pub(crate) async fn remote_unary_with_options<Req, Resp>(
    client: &RemoteClient,
    path: &str,
    request: Req,
    options: CallOptions,
) -> std::result::Result<Resp, tonic::Status>
where
    Req: Message + Default + Clone + Send + 'static,
    Resp: Message + Default + Send + 'static,
{
    client
        .raw()
        .unary(path, request, options)
        .await
        .map_err(sdk_error_status)
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

pub(crate) fn token_transport_is_safe(url: &str) -> bool {
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

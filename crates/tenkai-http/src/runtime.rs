use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use tenkai::management_operations::ManagementError;
use tenkai::runner_attestation::{AttestationChallenge, AttestationRefusal};
use tenkai::runtime_delivery::{RuntimeDeliveryError, RuntimeHeartbeat, RuntimeInventoryReport};

use super::router::{AppState, ErrorBody};

pub(super) async fn runtime_work(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
) -> Response {
    match state
        .runtime_delivery
        .claim_work(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
        )
        .await
    {
        Ok(work) => Json(work).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

pub(super) async fn runtime_complete(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(completion): Json<tenkai::runtime_delivery::RuntimeCompletion>,
) -> Response {
    match state
        .runtime_delivery
        .complete(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            completion,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

pub(super) async fn runtime_heartbeat(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(heartbeat): Json<RuntimeHeartbeat>,
) -> Response {
    match state
        .runtime_delivery
        .renew(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            &heartbeat,
        )
        .await
    {
        Ok(claim) => Json(claim).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// One binary of the runtime agent's own release, for the claimed runtime
/// (#685). The body is the file; `x-tenkai-file-mode` its octal mode.
pub(super) async fn runtime_self_release(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(request): Json<tenkai::runtime_delivery::RuntimeSelfReleaseFile>,
) -> Response {
    match state
        .runtime_delivery
        .self_release_file(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            &request,
        )
        .await
    {
        Ok((bytes, mode)) => (
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/octet-stream".to_string(),
                ),
                (
                    axum::http::HeaderName::from_static("x-tenkai-file-mode"),
                    format!("{mode:o}"),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// The signed release of a step of the claimed plan, for a runtime that
/// applies it with a built-in executor (ADR 0048 §3).
pub(super) async fn runtime_release(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(request): Json<tenkai::runtime_delivery::RuntimeReleaseRequest>,
) -> Response {
    match state
        .runtime_delivery
        .release(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            &request,
        )
        .await
    {
        Ok(release) => Json(release).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// Renew a runner certificate (#674): admitted by the current one, or by
/// the enrolled bearer once it has expired.
pub(super) async fn runtime_certificate(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(request): Json<tenkai::runtime_delivery::RuntimeCertificateRequest>,
) -> Response {
    match state
        .runtime_delivery
        .renew_certificate(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            &request,
        )
        .await
    {
        Ok(renewed) => Json(renewed).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// Runtime inventory report: write admitted capability facts for the assigned env (#136).
pub(super) async fn runtime_inventory(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(report): Json<RuntimeInventoryReport>,
) -> Response {
    match state
        .runtime_delivery
        .report_inventory(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            report,
        )
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// A runtime's identity issuer candidate (ADR 0046 §2). Answers with the
/// candidate the server keeps, which is another runtime's if that came first.
pub(super) async fn runtime_issuer_candidate(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(candidate): Json<tenkai::identity_issuer::IssuerKey>,
) -> Response {
    match state
        .runtime_delivery
        .upload_issuer_candidate(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            candidate,
        )
        .await
    {
        Ok(kept) => Json(kept).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// The host applier's records a runtime reports (ADR 0048 §2).
pub(super) async fn runtime_host_records(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(report): Json<tenkai::runtime_delivery::RuntimeHostRecordsReport>,
) -> Response {
    match state
        .runtime_delivery
        .report_host_records(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            &report,
        )
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// The workload certificates a runtime reports (ADR 0046 §3).
pub(super) async fn runtime_certificates(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    certificate: Option<axum::Extension<crate::tls::ClientCertificate>>,
    Json(report): Json<tenkai::runtime_delivery::RuntimeCertificatesReport>,
) -> Response {
    match state
        .runtime_delivery
        .report_certificates(
            bearer(&headers),
            runtime_caller(&headers, certificate.as_ref()),
            &environment,
            &report,
        )
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// The calling instance, the agent's version when sent (#673), and the
/// connection's verified client certificate (#674).
fn runtime_caller<'a>(
    headers: &'a HeaderMap,
    certificate: Option<&'a axum::Extension<crate::tls::ClientCertificate>>,
) -> tenkai::runtime_delivery::RuntimeCaller<'a> {
    tenkai::runtime_delivery::RuntimeCaller {
        instance: runtime_instance(headers),
        version: headers
            .get("x-tenkai-runtime-version")
            .and_then(|value| value.to_str().ok()),
        certificate: certificate.and_then(|certificate| certificate.0.0.as_deref()),
        workload_identity: names_capability(
            headers,
            tenkai::runtime_delivery::WORKLOAD_IDENTITY_CAPABILITY,
        ),
        peer_grants: names_capability(headers, tenkai::runtime_delivery::PEER_GRANTS_CAPABILITY),
    }
}

/// Whether `x-tenkai-runtime-capabilities` names `capability`.
fn names_capability(headers: &HeaderMap, capability: &str) -> bool {
    headers
        .get("x-tenkai-runtime-capabilities")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|capabilities| {
            capabilities
                .split(',')
                .any(|named| named.trim() == capability)
        })
}

fn runtime_instance(headers: &HeaderMap) -> Option<&str> {
    let instance = headers.get("x-tenkai-runtime-instance")?.to_str().ok()?;
    (!instance.is_empty() && instance.len() <= 128 && instance.is_ascii()).then_some(instance)
}

pub(super) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

pub(crate) fn error_response(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
        }),
    )
        .into_response()
}

fn runtime_delivery_error(error: RuntimeDeliveryError) -> Response {
    let status = match error {
        RuntimeDeliveryError::MissingCredential => StatusCode::UNAUTHORIZED,
        RuntimeDeliveryError::InvalidCredential | RuntimeDeliveryError::ForeignEnvironment => {
            StatusCode::FORBIDDEN
        }
        RuntimeDeliveryError::InvalidInstance | RuntimeDeliveryError::InvalidRequest(_) => {
            StatusCode::BAD_REQUEST
        }
        RuntimeDeliveryError::Conflict(_) => StatusCode::CONFLICT,
        // Distinct from 400 and 422, which a request-shape mismatch between
        // versions also yields: only this fails the runtime's step.
        RuntimeDeliveryError::ReleaseRefused(_) => StatusCode::PRECONDITION_FAILED,
        RuntimeDeliveryError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        RuntimeDeliveryError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        // 428 advertises the runner attestation policy (#675): the agent
        // then sends evidence in one of the schemas named with it (#849).
        // Every other refusal is final for the request.
        RuntimeDeliveryError::Attestation(ref refusal) => {
            let status = match refusal {
                AttestationRefusal::Missing => StatusCode::PRECONDITION_REQUIRED,
                AttestationRefusal::InventoryContradictsDeclaredFact { .. } => StatusCode::CONFLICT,
                _ => StatusCode::FORBIDDEN,
            };
            if refusal.names_schemas() {
                return (status, Json(AttestationChallenge::new(refusal))).into_response();
            }
            status
        }
    };
    error_response(status, error.to_string())
}

pub(super) fn management_error(error: ManagementError) -> Response {
    match error {
        ManagementError::Unauthorized(message) => {
            // RFC 6750 §3: name the scheme, and flag a presented token as invalid.
            let challenge = if message == tenkai::management_operations::MISSING_CREDENTIAL {
                "Bearer"
            } else {
                "Bearer error=\"invalid_token\""
            };
            let mut response = error_response(StatusCode::UNAUTHORIZED, message);
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(challenge),
            );
            response
        }
        ManagementError::Forbidden(message) => error_response(StatusCode::FORBIDDEN, message),
        ManagementError::NotFound(message) => error_response(StatusCode::NOT_FOUND, message),
        ManagementError::BadRequest(message) => error_response(StatusCode::BAD_REQUEST, message),
        ManagementError::Conflict(message) => error_response(StatusCode::CONFLICT, message),
        ManagementError::ExecutionFailed(message)
        | ManagementError::StepsFailed { message, .. } => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, message)
        }
        ManagementError::Unavailable(message) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, message)
        }
        ManagementError::Internal(message) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

pub(super) fn encode_plan_path(plan_id: &str) -> String {
    plan_id
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// A runtime agent exchanges its single-use enrollment token for its own
/// credential (#630). The token is the only credential this route takes.
pub(super) async fn runtime_enroll(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    Json(request): Json<tenkai::runtime_delivery::RuntimeEnrollRequest>,
) -> Response {
    match state.runtime_delivery.enroll(&environment, &request).await {
        Ok(enrolled) => (StatusCode::CREATED, Json(enrolled)).into_response(),
        Err(error) => runtime_delivery_error(error),
    }
}

/// Issue a single-use enrollment token for an environment's runtime agent.
pub(super) async fn create_runtime_enrollment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match super::auth::require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match super::auth::parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    super::auth::manage_result(
        state
            .management
            .create_runtime_enrollment(&credential, &environment, request)
            .await,
    )
}

/// Revoke a runtime credential by its id; the body carries the reason.
pub(super) async fn revoke_runtime_credential(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match super::auth::require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match super::auth::parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    super::auth::manage_result(
        state
            .management
            .revoke_runtime_credential(&credential, &credential_id, request)
            .await,
    )
}

/// The #630 revoke route, kept bodyless for released clients; it records a
/// fixed reason. `/v1/runners/{id}/revoke` requires one.
pub(super) async fn revoke_runtime_credential_legacy(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match super::auth::require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    super::auth::manage_result(
        state
            .management
            .revoke_runtime_credential(
                &credential,
                &credential_id,
                tenkai::management_operations::RuntimeRevokeRequest {
                    reason: "revoked through /v1/runtime-credentials (no reason given)".into(),
                },
            )
            .await,
    )
}

/// The runner registry (#673): enrolled credentials and static tokens.
pub(super) async fn list_runtime_runners(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let credential = match super::auth::require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    super::auth::manage_result(state.management.list_runtime_runners(&credential).await)
}

/// Unrevoked sealing keys of an environment (ADR 0045).
pub(super) async fn list_environment_recipients(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match super::auth::require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    super::auth::manage_result(
        state
            .management
            .list_environment_recipients(&credential, &environment)
            .await,
    )
}

/// One runner of the registry.
pub(super) async fn inspect_runtime_runner(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match super::auth::require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    super::auth::manage_result(
        state
            .management
            .inspect_runtime_runner(&credential, &credential_id)
            .await,
    )
}

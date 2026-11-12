use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse as _, Response};

use super::auth::{manage_result, parse_management_json, require_management};
use super::router::AppState;

pub(super) async fn publish_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(state.management.publish_release(&credential, request).await)
}

pub(super) async fn promote_release(
    State(state): State<Arc<AppState>>,
    Path(channel): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request =
        match parse_management_json::<tenkai::management_lifecycle::PromoteHttpRequest>(&body) {
            Ok(request) => request,
            Err(error) => return *error,
        };
    let (request, expected_head) = request.into_promote();
    manage_result(
        state
            .management
            .promote_release_expecting(&credential, &channel, request, expected_head.as_deref())
            .await,
    )
}

pub(super) async fn recall_release(
    State(state): State<Arc<AppState>>,
    Path(release): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .recall_release(&credential, &release, request)
            .await,
    )
}

pub(super) async fn record_recall_range(
    State(state): State<Arc<AppState>>,
    Path(product): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .record_recall_range(&credential, &product, request)
            .await,
    )
}

pub(super) async fn close_recall_range(
    State(state): State<Arc<AppState>>,
    Path(product): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .close_recall_range(&credential, &product, request)
            .await,
    )
}

pub(super) async fn subscribe_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .subscribe_environment(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn unsubscribe_environment(
    State(state): State<Arc<AppState>>,
    Path((environment, product)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .unsubscribe_environment(&credential, &environment, &product, request)
            .await,
    )
}

pub(super) async fn retire_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .retire_environment(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn plan_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .plan_environment(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn approve_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .approve_plan(&credential, &plan_id, request)
            .await,
    )
}

/// Query of `POST /v1/plans/{plan}/apply`. `steps=true` asks for one
/// result per step (#1076); a server that predates it ignores the query and
/// answers with the message alone.
#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct ApplyQuery {
    #[serde(default)]
    steps: bool,
}

pub(super) async fn apply_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ApplyQuery>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    let applied = state
        .management
        .apply_plan(&credential, &plan_id, request)
        .await;
    match applied {
        Err(tenkai::management_operations::ManagementError::StepsFailed { message, steps })
            if query.steps =>
        {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(tenkai::management_lifecycle::ApplyFailedBody {
                    error: message,
                    steps,
                }),
            )
                .into_response()
        }
        Ok(mut result) => {
            if !query.steps {
                result.steps.clear();
            }
            Json(result).into_response()
        }
        Err(error) => manage_result::<()>(Err(error)),
    }
}

pub(super) async fn rollback_environment(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .rollback_environment(&credential, &environment, request)
            .await,
    )
}

/// A plan that re-wraps an environment's sealed values for one more
/// recipient key (ADR 0045 §5).
pub(super) async fn rewrap_sealed_secrets(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .rewrap_sealed_secrets(&credential, &environment, request)
            .await,
    )
}

/// Ask an environment's runtimes for an identity issuer candidate of the
/// next generation (ADR 0046 §2).
pub(super) async fn prepare_identity_issuer(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .prepare_identity_issuer(&credential, &environment, request)
            .await,
    )
}

/// A plan that activates an environment's uploaded identity issuer
/// candidate (ADR 0046 §2).
pub(super) async fn plan_identity_issuer(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .plan_identity_issuer(&credential, &environment, request)
            .await,
    )
}

/// A plan that wraps an environment's identity issuer key for one more
/// recipient (ADR 0046 §2).
pub(super) async fn rewrap_identity_issuer(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .rewrap_identity_issuer(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn record_software_compatibility_evidence(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let evidence = match parse_management_json(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .record_software_compatibility_evidence(&credential, &environment, evidence)
            .await,
    )
}

pub(super) async fn install_model_evaluation_trust(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let roots = match parse_management_json(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .install_model_evaluation_trust(&credential, roots)
            .await,
    )
}

pub(super) async fn record_model_evaluation_evidence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let evidence = match parse_management_json(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .record_model_evaluation_evidence(&credential, evidence)
            .await,
    )
}

pub(super) async fn environment_hold(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .environment_hold(&credential, &environment)
            .await,
    )
}

pub(super) async fn set_environment_hold(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .set_environment_hold(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn release_environment_hold(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .release_environment_hold(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn schedule_environment_freeze(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .schedule_environment_freeze(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn cancel_environment_freeze(
    State(state): State<Arc<AppState>>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .cancel_environment_freeze(&credential, &environment, request)
            .await,
    )
}

pub(super) async fn retry_failed_target(
    State(state): State<Arc<AppState>>,
    Path((environment, product)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .retry_failed_target(&credential, &environment, &product, request)
            .await,
    )
}

pub(super) async fn channel_hold(
    State(state): State<Arc<AppState>>,
    Path((product, channel)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .channel_hold(&credential, &product, &channel)
            .await,
    )
}

pub(super) async fn set_channel_hold(
    State(state): State<Arc<AppState>>,
    Path((product, channel)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .set_channel_hold(&credential, &product, &channel, request)
            .await,
    )
}

pub(super) async fn release_channel_hold(
    State(state): State<Arc<AppState>>,
    Path((product, channel)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .release_channel_hold(&credential, &product, &channel, request)
            .await,
    )
}

/// Removes a product's head from one channel (#1174).
pub(super) async fn remove_channel_head(
    State(state): State<Arc<AppState>>,
    Path((product, channel)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .remove_channel_head(&credential, &product, &channel, request)
            .await,
    )
}

pub(super) async fn set_product_criticality(
    State(state): State<Arc<AppState>>,
    Path(product): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    let request = match parse_management_json(&body) {
        Ok(request) => request,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .set_product_criticality(&credential, &product, request)
            .await,
    )
}

pub(super) async fn clear_product_criticality(
    State(state): State<Arc<AppState>>,
    Path(product): Path<String>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .clear_product_criticality(&credential, &product)
            .await,
    )
}

pub(super) async fn import_derived_criticality(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(credential) => credential,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .import_derived_criticality(&credential, &body)
            .await,
    )
}

pub(super) async fn software_compatibility_report(
    State(state): State<Arc<AppState>>,
    Path((environment, release)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let credential = match require_management(&headers) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    manage_result(
        state
            .management
            .software_compatibility_outcome(&credential, &environment, &release)
            .await,
    )
}

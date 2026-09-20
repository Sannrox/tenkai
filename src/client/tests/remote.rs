use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use sekai_client::{ClientConfig, RetryPolicy, SdkErrorCode};
use tokio::net::TcpListener;
use tokio::sync::OnceCell;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::client::{Backend, Ctx, PlanKindListTick, RemoteClient};
use crate::pb::graph_action::{ActionOp, ActionTypeDef};
use crate::pb::sekai::Object;

use super::mock_state::MockSekaiState;

#[tokio::test]
async fn embedded_gate_evidence_lookup_fails_locally_without_networking() {
    let path =
        std::env::temp_dir().join(format!("tenkai-embedded-gate-{}.db", uuid::Uuid::new_v4()));
    let mut ctx = Ctx::embedded(&path).unwrap();
    let error = ctx
        .evaluation_gate_evidence(crate::pb::chisei::GetEvaluationGateEvidenceRequest {
            suite_id: "required-suite".into(),
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: 1,
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("embedded mode has no governance provider")
    );
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn remote_fenced_writes_use_canonical_rpc_and_reuse_request_id_on_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = MockSekaiState {
        create_failures: Arc::new(AtomicUsize::new(1)),
        update_failures: Arc::new(AtomicUsize::new(1)),
        ..Default::default()
    };
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(server_state)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let client = RemoteClient::connect(
        ClientConfig::new(format!("http://{address}"), "tenkai.test").with_retry_policy(
            RetryPolicy {
                max_attempts: 2,
                initial_backoff: std::time::Duration::ZERO,
                max_backoff: std::time::Duration::ZERO,
                retryable_codes: vec![SdkErrorCode::Unavailable, SdkErrorCode::DeadlineExceeded],
            },
        ),
    )
    .await
    .unwrap();
    let mut ctx = Ctx {
        backend: Backend::Remote {
            client: Arc::new(client),
            action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
        outcome_export_enabled: false,
        outcome_inspection_enabled: false,
        plan_kind_list: Arc::new(PlanKindListTick::default()),
    };
    let object = Object {
        id: "tenkai:object:remote".into(),
        ..Default::default()
    };

    ctx.guarded_create(object.clone(), "tenkai", "environment/prod", "fence-7")
        .await
        .unwrap();
    ctx.guarded_update(object, "tenkai", "environment/prod", "fence-7")
        .await
        .unwrap();

    let creates = state.creates.lock().unwrap().clone();
    assert_eq!(creates.len(), 2);
    assert_eq!(creates[0].lease_precondition, creates[1].lease_precondition);
    assert_eq!(
        creates[0]
            .lease_precondition
            .as_ref()
            .unwrap()
            .fencing_token,
        "fence-7"
    );
    let updates = state.updates.lock().unwrap().clone();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].lease_precondition, updates[1].lease_precondition);
    assert_eq!(
        updates[0]
            .lease_precondition
            .as_ref()
            .unwrap()
            .fencing_token,
        "fence-7"
    );

    server.abort();
}

#[tokio::test]
async fn remote_create_reclassifies_existing_object_after_sanitized_internal_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = MockSekaiState {
        create_internal_failures: Arc::new(AtomicUsize::new(1)),
        ..Default::default()
    };
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
        "tenkai.test",
    ))
    .await
    .unwrap();
    let mut ctx = Ctx {
        backend: Backend::Remote {
            client: Arc::new(client),
            action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
        outcome_export_enabled: false,
        outcome_inspection_enabled: false,
        plan_kind_list: Arc::new(PlanKindListTick::default()),
    };

    let object = Object {
        id: "tenkai:object:conflict".into(),
        ..Default::default()
    };
    let error = ctx.create_once(object.clone()).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::AlreadyExists);
    assert_eq!(ctx.get(&object.id).await.unwrap().unwrap(), object);

    server.abort();
}

#[tokio::test]
async fn remote_graph_action_registration_uses_governed_rpc() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = MockSekaiState::default();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(server_state)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let client = RemoteClient::connect(
        ClientConfig::new(format!("http://{address}"), "tenkai.test")
            .with_token("provider-token")
            .unwrap()
            .with_retry_policy(RetryPolicy {
                max_attempts: 2,
                initial_backoff: std::time::Duration::ZERO,
                max_backoff: std::time::Duration::ZERO,
                retryable_codes: vec![SdkErrorCode::Unavailable, SdkErrorCode::DeadlineExceeded],
            }),
    )
    .await
    .unwrap();
    let mut ctx = Ctx {
        backend: Backend::Remote {
            client: Arc::new(client),
            action_defs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        },
        canary_schema_preflight: Arc::new(OnceCell::new()),
        outcome_export_enabled: false,
        outcome_inspection_enabled: false,
        plan_kind_list: Arc::new(PlanKindListTick::default()),
    };
    let action = ActionTypeDef {
        name: "tenkai.replace_subscription".into(),
        description: "replace a subscription".into(),
        params: vec![],
        ops: vec![ActionOp {
            op: "create_link".into(),
            property: "channel_id".into(),
            value_from: String::new(),
            relation: "subscribes".into(),
        }],
        target_kind: "tenkai.environment".into(),
        created: 42,
        required_purpose: "delivery".into(),
    };

    ctx.register_action(action.clone()).await.unwrap();

    let registered = state.governed_actions.lock().unwrap().clone();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].namespace, "tenkai");
    assert_eq!(registered[0].type_id, action.name);
    assert_eq!(registered[0].version, "1");
    assert!(registered[0].enabled);
    assert!(registered[0].parameter_schema_json.contains("\"id\""));
    assert_eq!(
        state.metadata.lock().unwrap().as_slice(),
        [(
            Some("tenkai.test".into()),
            Some("Bearer provider-token".into())
        )]
    );
    server.abort();
}

use super::support::{FixedReconciler, app_with_reconciler};
use super::*;

use tenkai::telemetry::{CompletedSpan, MemoryTelemetry, TraceContext};

const PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

/// Plan `prod` through the hub with `traceparent`, capturing the hub's spans.
async fn plan_with_traceparent(traceparent: &str) -> (StatusCode, Vec<CompletedSpan>) {
    let mut ctx = tenkai_sqlite::embedded_ctx(":memory:").unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    tenkai::environment::env_add(&mut ctx, "prod", "prod")
        .await
        .unwrap();
    let (app, _) = app_with_reconciler(FixedReconciler::with_ctx(ctx));
    let memory = Arc::new(MemoryTelemetry::new());
    let request = Request::post("/v1/environments/prod/plans")
        .header("authorization", "Bearer management-secret")
        .header("content-type", "application/json")
        .header("traceparent", traceparent)
        .body(Body::from(
            serde_json::json!({
                "version": 1,
                "operation": "plan",
                "environment": "prod",
                "expected_generation": 1
            })
            .to_string(),
        ))
        .unwrap();
    let response =
        tenkai::telemetry::scope(memory.clone(), "corr-1443-hub", app.oneshot(request)).await;
    (response.unwrap().status(), memory.spans())
}

fn plan_span(spans: &[CompletedSpan]) -> &CompletedSpan {
    spans
        .iter()
        .find(|span| span.name == "tenkai.plan")
        .unwrap_or_else(|| panic!("no tenkai.plan span in {spans:?}"))
}

#[tokio::test]
async fn hub_spans_continue_a_valid_inbound_traceparent() {
    let (status, spans) = plan_with_traceparent(PARENT).await;
    assert!(status.is_success(), "{status}");
    let parent = TraceContext::from_traceparent(PARENT).unwrap();
    let span = plan_span(&spans);
    assert_eq!(span.ids.context.trace_id, parent.trace_id);
    assert_eq!(span.ids.parent_span_id, Some(parent.span_id));
}

#[tokio::test]
async fn a_malformed_traceparent_starts_a_fresh_trace_and_is_not_refused() {
    let malformed = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01";
    let (status, spans) = plan_with_traceparent(malformed).await;
    assert!(status.is_success(), "{status}");
    let span = plan_span(&spans);
    assert_eq!(span.ids.parent_span_id, None);
    let encoded = serde_json::to_string(&spans).unwrap();
    assert!(!encoded.contains("4BF92F"), "{encoded}");
}

/// The request head the client sends for one call, read off a bare socket.
async fn sent_request_head(trace: Option<TraceContext>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        let read = socket.read(&mut buffer).await.unwrap();
        String::from_utf8_lossy(&buffer[..read]).to_ascii_lowercase()
    });
    let client = RemoteClient::new(format!("http://{addr}"), "token").unwrap();
    // The bare socket never answers; only the request matters.
    let call = client.fleet_status();
    let _ = match trace {
        Some(trace) => tenkai::telemetry::in_trace(trace, call).await,
        None => call.await,
    };
    captured.await.unwrap()
}

#[tokio::test]
async fn remote_client_forwards_its_trace_context_only_when_it_has_one() {
    let parent = TraceContext::from_traceparent(PARENT).unwrap();
    let head = sent_request_head(Some(parent)).await;
    assert!(head.contains(&format!("traceparent: {PARENT}")), "{head}");
    let head = sent_request_head(None).await;
    assert!(!head.contains("traceparent"), "{head}");
}

//! Delivery telemetry keyed by the inbound operation identity (#380).
//!
//! Hub and spoke emit the same allowlisted span and metric attributes. Export
//! is off by default. Cached files and payload contents cannot appear on a
//! span: only versioned delivery identities are admitted. Transport is not a
//! domain boundary — the same port is used from embedded `tenkaictl` and the
//! server host.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::Result;

use serde::Serialize;

pub const ATTR_OPERATION: &str = "tenkai.operation";
pub const ATTR_OPERATION_ID: &str = "tenkai.operation_id";
pub const ATTR_PLAN_ID: &str = "tenkai.plan_id";
pub const ATTR_RELEASE_DIGEST: &str = "tenkai.release_digest";
pub const ATTR_ENVIRONMENT: &str = "tenkai.environment";
pub const ATTR_FENCING_GENERATION: &str = "tenkai.fencing_generation";
pub const ATTR_OUTCOME: &str = "tenkai.outcome";

pub const METRIC_RECONCILE_LATENCY_MS: &str = "tenkai.reconcile.latency_ms";
pub const METRIC_APPLY_OUTCOME: &str = "tenkai.apply.outcomes";
pub const METRIC_LEASE_ACQUIRED: &str = "tenkai.lease.acquired";
pub const METRIC_LEASE_RELEASED: &str = "tenkai.lease.released";
pub const METRIC_HEALTH_GATE_OUTCOME: &str = "tenkai.health_gate.outcomes";

const ENDPOINT_ENV: &str = "TENKAI_OTEL_ENDPOINT";
const OPERATION_ENV: &str = "TENKAI_OPERATION_ID";

const ALLOWED_KEYS: &[&str] = &[
    ATTR_OPERATION,
    ATTR_OPERATION_ID,
    ATTR_PLAN_ID,
    ATTR_RELEASE_DIGEST,
    ATTR_ENVIRONMENT,
    ATTR_FENCING_GENERATION,
    ATTR_OUTCOME,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Plan,
    Apply,
    Health,
    Rollback,
    Reconcile,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Health => "health",
            Self::Rollback => "rollback",
            Self::Reconcile => "reconcile",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    Ok,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DeliveryAttributes {
    pub operation: Option<Operation>,
    pub operation_id: Option<String>,
    pub plan_id: Option<String>,
    pub release_digest: Option<String>,
    pub environment: Option<String>,
    pub fencing_generation: Option<u64>,
    pub outcome: Option<String>,
}

impl DeliveryAttributes {
    pub fn new(operation: Operation) -> Self {
        Self {
            operation: Some(operation),
            operation_id: current_operation_id(),
            ..Self::default()
        }
    }

    pub fn plan_id(mut self, plan_id: impl Into<String>) -> Self {
        self.plan_id = Some(plan_id.into());
        self
    }

    pub fn release_digest(mut self, digest: impl Into<String>) -> Self {
        self.release_digest = Some(digest.into());
        self
    }

    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    pub fn fencing_generation(mut self, generation: u64) -> Self {
        self.fencing_generation = Some(generation);
        self
    }

    pub fn from_plan(operation: Operation, plan: &crate::plan::Plan) -> Self {
        let mut attrs = Self::new(operation)
            .plan_id(plan.id.clone())
            .environment(plan.environment.clone());
        if let Some(step) = plan.steps.first() {
            attrs = attrs.release_digest(step.release_digest.clone());
        }
        attrs
    }

    pub fn allowlisted_pairs(&self) -> BTreeMap<String, String> {
        let mut pairs = BTreeMap::new();
        insert_allowed(
            &mut pairs,
            ATTR_OPERATION,
            self.operation.map(Operation::as_str),
        );
        insert_allowed(&mut pairs, ATTR_OPERATION_ID, self.operation_id.as_deref());
        insert_allowed(&mut pairs, ATTR_PLAN_ID, self.plan_id.as_deref());
        insert_allowed(
            &mut pairs,
            ATTR_RELEASE_DIGEST,
            self.release_digest.as_deref(),
        );
        insert_allowed(&mut pairs, ATTR_ENVIRONMENT, self.environment.as_deref());
        insert_allowed(
            &mut pairs,
            ATTR_FENCING_GENERATION,
            self.fencing_generation
                .map(|value| value.to_string())
                .as_deref(),
        );
        insert_allowed(&mut pairs, ATTR_OUTCOME, self.outcome.as_deref());
        pairs
    }
}

fn insert_allowed(pairs: &mut BTreeMap<String, String>, key: &str, value: Option<&str>) {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return;
    };
    if !ALLOWED_KEYS.contains(&key) || looks_like_secret(key, value) {
        return;
    }
    pairs.insert(key.into(), value.into());
}

fn looks_like_secret(key: &str, value: &str) -> bool {
    let compact = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    for fragment in [
        "password",
        "secret",
        "token",
        "bearer",
        "credential",
        "privatekey",
        "kubeconfig",
        "authorization",
    ] {
        if compact.contains(fragment) {
            return true;
        }
    }
    let lower = value.to_ascii_lowercase();
    for needle in [
        "bearer ",
        "-----begin ",
        "password=",
        "token=",
        "secret=",
        "authorization:",
    ] {
        if lower.contains(needle) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanToken(u64);

pub trait Telemetry: Send + Sync {
    fn start_span(&self, name: &str, attrs: &DeliveryAttributes) -> SpanToken;
    fn end_span(&self, token: SpanToken, attrs: &DeliveryAttributes, status: SpanStatus);
    fn record_metric(&self, name: &str, value: f64, attrs: &DeliveryAttributes);
}

#[derive(Debug, Default)]
pub struct NoopTelemetry;

impl Telemetry for NoopTelemetry {
    fn start_span(&self, _name: &str, _attrs: &DeliveryAttributes) -> SpanToken {
        SpanToken(0)
    }

    fn end_span(&self, _token: SpanToken, _attrs: &DeliveryAttributes, _status: SpanStatus) {}

    fn record_metric(&self, _name: &str, _value: f64, _attrs: &DeliveryAttributes) {}
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompletedSpan {
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub status: SpanStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecordedMetric {
    pub name: String,
    pub value: f64,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
pub struct MemoryTelemetry {
    next: AtomicU64,
    open: Mutex<BTreeMap<u64, String>>,
    spans: Mutex<Vec<CompletedSpan>>,
    metrics: Mutex<Vec<RecordedMetric>>,
}

impl MemoryTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn spans(&self) -> Vec<CompletedSpan> {
        self.spans.lock().expect("telemetry mutex").clone()
    }

    pub fn metrics(&self) -> Vec<RecordedMetric> {
        self.metrics.lock().expect("telemetry mutex").clone()
    }
}

impl Telemetry for MemoryTelemetry {
    fn start_span(&self, name: &str, _attrs: &DeliveryAttributes) -> SpanToken {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.open
            .lock()
            .expect("telemetry mutex")
            .insert(id, name.into());
        SpanToken(id)
    }

    fn end_span(&self, token: SpanToken, attrs: &DeliveryAttributes, status: SpanStatus) {
        let name = self
            .open
            .lock()
            .expect("telemetry mutex")
            .remove(&token.0)
            .unwrap_or_else(|| "tenkai.unknown".into());
        self.spans
            .lock()
            .expect("telemetry mutex")
            .push(CompletedSpan {
                name,
                attributes: attrs.allowlisted_pairs(),
                status,
            });
    }

    fn record_metric(&self, name: &str, value: f64, attrs: &DeliveryAttributes) {
        self.metrics
            .lock()
            .expect("telemetry mutex")
            .push(RecordedMetric {
                name: name.into(),
                value,
                attributes: attrs.allowlisted_pairs(),
            });
    }
}

/// Connect and whole-request bounds on one OTLP export, so a stalled
/// collector holds an export for at most this long (#1311).
const EXPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const EXPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// Export clients shared by every exporter in the process. They keep no idle
/// connections, so a connection never outlives the runtime that opened it.
static ASYNC_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
static BLOCKING_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

/// The client in `cell`, built on first use. A build failure is not cached:
/// the next export tries again.
fn shared_client<T: Clone>(cell: &OnceLock<T>, build: impl FnOnce() -> Result<T>) -> Option<T> {
    if let Some(client) = cell.get() {
        return Some(client.clone());
    }
    let client = build().ok()?;
    Some(cell.get_or_init(|| client).clone())
}

fn async_export_client() -> Result<reqwest::Client> {
    Ok(crate::outbound_tls::client()?
        .connect_timeout(EXPORT_CONNECT_TIMEOUT)
        .timeout(EXPORT_TIMEOUT)
        .pool_max_idle_per_host(0)
        .build()?)
}

fn blocking_export_client() -> Result<reqwest::blocking::Client> {
    Ok(crate::outbound_tls::blocking_client()?
        .connect_timeout(EXPORT_CONNECT_TIMEOUT)
        .timeout(EXPORT_TIMEOUT)
        .pool_max_idle_per_host(0)
        .build()?)
}

/// One finished span as exported: its identity and wall-clock bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanRecord {
    pub name: String,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub start_unix_nanos: u64,
    pub end_unix_nanos: u64,
}

impl SpanRecord {
    /// A span opened now, in a trace of its own.
    fn open(name: impl Into<String>) -> Self {
        let span = uuid::Uuid::new_v4();
        let mut span_id = [0; 8];
        span_id.copy_from_slice(&span.as_bytes()[..8]);
        let now = unix_nanos();
        Self {
            name: name.into(),
            // Random v4 bytes carry a version nibble, so neither id is all zero.
            trace_id: *uuid::Uuid::new_v4().as_bytes(),
            span_id,
            start_unix_nanos: now,
            end_unix_nanos: now,
        }
    }
}

fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// OTLP/HTTP JSON exporter. Export failures never fail a delivery operation.
pub struct OtlpHttpTelemetry {
    endpoint: String,
    next: AtomicU64,
    open: Mutex<BTreeMap<u64, SpanRecord>>,
}

impl OtlpHttpTelemetry {
    pub fn from_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            next: AtomicU64::new(0),
            open: Mutex::new(BTreeMap::new()),
        }
    }

    /// Fire and forget inside a runtime; synchronous, within the export
    /// timeout, outside one.
    fn export(&self, path: &str, body: serde_json::Value) {
        let url = format!("{}{path}", self.endpoint);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let Some(client) = shared_client(&ASYNC_CLIENT, async_export_client) else {
                return;
            };
            handle.spawn(async move {
                let _ = client.post(url).json(&body).send().await;
            });
        } else if let Some(client) = shared_client(&BLOCKING_CLIENT, blocking_export_client) {
            let _ = client.post(url).json(&body).send();
        }
    }
}

impl Telemetry for OtlpHttpTelemetry {
    fn start_span(&self, name: &str, _attrs: &DeliveryAttributes) -> SpanToken {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.open
            .lock()
            .expect("telemetry mutex")
            .insert(id, SpanRecord::open(name));
        SpanToken(id)
    }

    fn end_span(&self, token: SpanToken, attrs: &DeliveryAttributes, status: SpanStatus) {
        let mut span = self
            .open
            .lock()
            .expect("telemetry mutex")
            .remove(&token.0)
            .unwrap_or_else(|| SpanRecord::open("tenkai.unknown"));
        span.end_unix_nanos = unix_nanos().max(span.start_unix_nanos);
        self.export("/v1/traces", otlp_trace_payload(&span, attrs, status));
    }

    fn record_metric(&self, name: &str, value: f64, attrs: &DeliveryAttributes) {
        self.export("/v1/metrics", otlp_metric_payload(name, value, attrs));
    }
}

/// OTLP/JSON encodes ids as lowercase hex and 64-bit times as decimal strings.
pub fn otlp_trace_payload(
    span: &SpanRecord,
    attrs: &DeliveryAttributes,
    status: SpanStatus,
) -> serde_json::Value {
    serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "tenkai"}}
                ]
            },
            "scopeSpans": [{
                "spans": [{
                    "traceId": hex(&span.trace_id),
                    "spanId": hex(&span.span_id),
                    "name": span.name,
                    "kind": 1,
                    "startTimeUnixNano": span.start_unix_nanos.to_string(),
                    "endTimeUnixNano": span.end_unix_nanos.to_string(),
                    "attributes": otlp_attributes(attrs),
                    "status": {
                        "code": match status {
                            SpanStatus::Ok => 1,
                            SpanStatus::Error => 2,
                        }
                    }
                }]
            }]
        }]
    })
}

pub fn otlp_metric_payload(
    name: &str,
    value: f64,
    attrs: &DeliveryAttributes,
) -> serde_json::Value {
    serde_json::json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "tenkai"}}
                ]
            },
            "scopeMetrics": [{
                "metrics": [{
                    "name": name,
                    "gauge": {
                        "dataPoints": [{
                            "timeUnixNano": unix_nanos().to_string(),
                            "asDouble": value,
                            "attributes": otlp_attributes(attrs)
                        }]
                    }
                }]
            }]
        }]
    })
}

fn otlp_attributes(attrs: &DeliveryAttributes) -> Vec<serde_json::Value> {
    attrs
        .allowlisted_pairs()
        .into_iter()
        .map(|(key, value)| serde_json::json!({"key": key, "value": {"stringValue": value}}))
        .collect()
}

#[derive(Clone)]
enum Installed {
    None,
    Shared(Arc<dyn Telemetry>),
}

static INSTALLED: RwLock<Installed> = RwLock::new(Installed::None);
static PROCESS_OPERATION: Mutex<Option<String>> = Mutex::new(None);

tokio::task_local! {
    static TASK_TELEMETRY: Arc<dyn Telemetry>;
    static TASK_OPERATION: String;
}

pub fn bind_process_operation_id(operation_id: impl Into<String>) {
    *PROCESS_OPERATION.lock().expect("telemetry mutex") = Some(operation_id.into());
}

pub fn current_operation_id() -> Option<String> {
    if let Ok(id) = TASK_OPERATION.try_with(Clone::clone) {
        return Some(id);
    }
    if let Some(id) = PROCESS_OPERATION.lock().expect("telemetry mutex").clone() {
        return Some(id);
    }
    std::env::var(OPERATION_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub fn selected() -> Arc<dyn Telemetry> {
    if let Ok(telemetry) = TASK_TELEMETRY.try_with(Clone::clone) {
        return telemetry;
    }
    if let Installed::Shared(telemetry) = INSTALLED.read().expect("telemetry lock").clone() {
        return telemetry;
    }
    if let Ok(endpoint) = std::env::var(ENDPOINT_ENV)
        && !endpoint.trim().is_empty()
    {
        return Arc::new(OtlpHttpTelemetry::from_endpoint(endpoint));
    }
    Arc::new(NoopTelemetry)
}

pub fn install(telemetry: Arc<dyn Telemetry>) -> InstallGuard {
    let mut slot = INSTALLED.write().expect("telemetry lock");
    let previous = std::mem::replace(&mut *slot, Installed::Shared(telemetry));
    InstallGuard { previous }
}

pub struct InstallGuard {
    previous: Installed,
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        *INSTALLED.write().expect("telemetry lock") = self.previous.clone();
    }
}

pub async fn scope<F, T>(
    telemetry: Arc<dyn Telemetry>,
    operation_id: impl Into<String>,
    fut: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    let operation_id = operation_id.into();
    TASK_TELEMETRY
        .scope(telemetry, TASK_OPERATION.scope(operation_id, fut))
        .await
}

pub async fn scope_operation<F, T>(operation_id: impl Into<String>, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    TASK_OPERATION.scope(operation_id.into(), fut).await
}

pub fn start_span(name: &str, attrs: &DeliveryAttributes) -> SpanGuard {
    let telemetry = selected();
    let token = telemetry.start_span(name, attrs);
    SpanGuard {
        telemetry,
        token: Some(token),
        attrs: attrs.clone(),
        status: SpanStatus::Ok,
    }
}

pub struct SpanGuard {
    telemetry: Arc<dyn Telemetry>,
    token: Option<SpanToken>,
    attrs: DeliveryAttributes,
    status: SpanStatus,
}

impl SpanGuard {
    pub fn fail(&mut self) {
        self.status = SpanStatus::Error;
        self.attrs.outcome = Some("error".into());
    }

    pub fn succeed(&mut self) {
        self.status = SpanStatus::Ok;
        self.attrs.outcome = Some("ok".into());
    }

    pub fn set_plan(&mut self, plan: &crate::plan::Plan) {
        self.attrs.plan_id = Some(plan.id.clone());
        self.attrs.environment = Some(plan.environment.clone());
        if let Some(step) = plan.steps.first() {
            self.attrs.release_digest = Some(step.release_digest.clone());
        }
    }

    pub fn set_fencing_generation(&mut self, generation: u64) {
        self.attrs.fencing_generation = Some(generation);
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        if self.attrs.outcome.is_none() {
            self.attrs.outcome = Some(
                match self.status {
                    SpanStatus::Ok => "ok",
                    SpanStatus::Error => "error",
                }
                .into(),
            );
        }
        if let Some(token) = self.token.take() {
            self.telemetry.end_span(token, &self.attrs, self.status);
        }
    }
}

pub fn record_metric(name: &str, value: f64, attrs: &DeliveryAttributes) {
    selected().record_metric(name, value, attrs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::test_management_context;
    use crate::catalog::{PublishOptions, publish};
    use crate::client::Ctx;
    use crate::plan::{self, Action};
    use crate::software_executor::FakeSoftwareExecutor;

    #[test]
    fn allowlist_drops_secret_material_and_unknown_keys() {
        let attrs = DeliveryAttributes {
            operation: Some(Operation::Apply),
            operation_id: Some("corr-1".into()),
            plan_id: Some("tenkai:plan:local:1".into()),
            release_digest: Some("abc".into()),
            environment: Some("local".into()),
            fencing_generation: Some(3),
            outcome: Some("bearer secret-token".into()),
        };
        let pairs = attrs.allowlisted_pairs();
        assert_eq!(
            pairs.get(ATTR_OPERATION_ID).map(String::as_str),
            Some("corr-1")
        );
        assert_eq!(
            pairs.get(ATTR_ENVIRONMENT).map(String::as_str),
            Some("local")
        );
        assert!(!pairs.contains_key(ATTR_OUTCOME));
        assert!(!pairs.values().any(|value| value.contains("bearer")));
    }

    #[test]
    fn otlp_payload_carries_allowlisted_identities_only() {
        let attrs = DeliveryAttributes::new(Operation::Apply)
            .plan_id("tenkai:plan:lab:1")
            .environment("lab")
            .release_digest("deadbeef")
            .fencing_generation(9);
        let payload = otlp_trace_payload(&SpanRecord::open("tenkai.apply"), &attrs, SpanStatus::Ok);
        let encoded = payload.to_string();
        assert!(encoded.contains(ATTR_PLAN_ID));
        assert!(encoded.contains("deadbeef"));
        assert!(encoded.contains("lab"));
        assert!(!encoded.contains("token="));
        assert!(!encoded.contains("bearer"));
        assert!(!encoded.contains("kubeconfig"));
    }

    #[test]
    fn otlp_payloads_carry_the_fields_a_collector_requires() {
        let attrs = DeliveryAttributes::new(Operation::Apply);
        let mut opened = SpanRecord::open("tenkai.apply");
        opened.end_unix_nanos = opened.start_unix_nanos + 5;
        let trace = otlp_trace_payload(&opened, &attrs, SpanStatus::Ok);
        let span = &trace["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        let id = |key: &str, len: usize| {
            let value = span[key].as_str().expect("id is a string");
            assert_eq!(value.len(), len, "{key}");
            assert!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
            assert!(value.bytes().any(|b| b != b'0'), "{key} is all zero");
        };
        id("traceId", 32);
        id("spanId", 16);
        let time = |key: &str| -> u64 { span[key].as_str().expect("time").parse().expect("u64") };
        assert!(time("startTimeUnixNano") > 0);
        assert_eq!(time("endTimeUnixNano"), time("startTimeUnixNano") + 5);

        let metric = otlp_metric_payload(METRIC_APPLY_OUTCOME, 1.0, &attrs);
        let point = &metric["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"]
            [0];
        let at: u64 = point["timeUnixNano"]
            .as_str()
            .expect("time")
            .parse()
            .expect("u64");
        assert!(at > 0);
    }

    #[test]
    fn export_to_a_stalled_collector_gives_up_within_the_timeout() {
        // Accepts into the backlog and never answers.
        let collector = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let exporter =
            OtlpHttpTelemetry::from_endpoint(format!("http://{}", collector.local_addr().unwrap()));
        let started = std::time::Instant::now();
        exporter.record_metric(
            METRIC_APPLY_OUTCOME,
            1.0,
            &DeliveryAttributes::new(Operation::Apply),
        );
        let waited = started.elapsed();
        assert!(
            waited >= EXPORT_TIMEOUT / 2,
            "export returned before reaching the collector"
        );
        assert!(
            waited < EXPORT_TIMEOUT + Duration::from_secs(2),
            "export waited {waited:?}"
        );
    }

    #[tokio::test]
    async fn delivery_drill_carries_external_operation_id_on_plan_apply_health_rollback() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-otel-drill-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_shell_product(&root, "1.0.0");
        write_shell_product(&root, "1.1.0");
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        publish(&mut ctx, &root.join("1.0.0").join("tenkai.toml"), &options)
            .await
            .unwrap();
        publish(&mut ctx, &root.join("1.1.0").join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = test_management_context("otel-drill");
        crate::catalog::promote(&mut ctx, &actor, "edge-app@1.0.0", "stable")
            .await
            .unwrap();
        plan::env_add(&mut ctx, "local", "fixture").await.unwrap();
        plan::subscribe(&mut ctx, "local", "edge-app", "stable")
            .await
            .unwrap();
        let software = Arc::new(FakeSoftwareExecutor::new());
        let memory = Arc::new(MemoryTelemetry::new());
        let operation_id = "corr-380-delivery";
        scope(memory.clone(), operation_id, async {
            let first = plan::create(&mut ctx, "local").await.unwrap();
            assert_apply_succeeded(
                crate::apply::execute_with_options(
                    &mut ctx,
                    &first.id,
                    crate::apply::ExecutionOptions {
                        rollback_hold: true,
                        skip_gates: false,
                        emergency_reason: None,
                        authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                            reason: "otel delivery drill",
                        },
                        software_executors:
                            crate::software_executor::SoftwareExecutors::with_default(
                                software.clone(),
                            ),
                        model_runtime_executor: None,
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
                    },
                )
                .await
                .unwrap(),
            );
            crate::catalog::promote(&mut ctx, &actor, "edge-app@1.1.0", "stable")
                .await
                .unwrap();
            let upgrade = plan::create(&mut ctx, "local").await.unwrap();
            assert_apply_succeeded(
                crate::apply::execute_with_options(
                    &mut ctx,
                    &upgrade.id,
                    crate::apply::ExecutionOptions {
                        rollback_hold: true,
                        skip_gates: false,
                        emergency_reason: None,
                        authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                            reason: "otel delivery drill",
                        },
                        software_executors:
                            crate::software_executor::SoftwareExecutors::with_default(
                                software.clone(),
                            ),
                        model_runtime_executor: None,
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
                    },
                )
                .await
                .unwrap(),
            );
            let step = plan::rollback_step(&mut ctx, "local", "edge-app")
                .await
                .unwrap();
            assert_eq!(step.action, Action::Rollback);
            let rollback = plan::create_from_steps(&mut ctx, "local", vec![step])
                .await
                .unwrap();
            assert_apply_succeeded(
                crate::apply::execute_with_options(
                    &mut ctx,
                    &rollback.id,
                    crate::apply::ExecutionOptions {
                        rollback_hold: true,
                        skip_gates: false,
                        emergency_reason: None,
                        authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                            reason: "otel delivery drill",
                        },
                        software_executors:
                            crate::software_executor::SoftwareExecutors::with_default(software),
                        model_runtime_executor: None,
                        worker_lifecycle: None,
                        artifact_registry: None,
                        delivery_adapter: None,
                    },
                )
                .await
                .unwrap(),
            );
        })
        .await;

        let spans = memory.spans();
        let names: Vec<_> = spans.iter().map(|span| span.name.as_str()).collect();
        assert!(names.contains(&"tenkai.plan"), "{names:?}");
        assert!(names.contains(&"tenkai.apply"), "{names:?}");
        assert!(names.contains(&"tenkai.health"), "{names:?}");
        assert!(names.contains(&"tenkai.rollback"), "{names:?}");
        for span in &spans {
            assert_eq!(
                span.attributes.get(ATTR_OPERATION_ID).map(String::as_str),
                Some(operation_id),
                "{span:?}"
            );
            assert!(span.attributes.contains_key(ATTR_ENVIRONMENT), "{span:?}");
            for value in span.attributes.values() {
                assert!(!value.to_ascii_lowercase().contains("bearer"), "{span:?}");
                assert!(!value.contains("token="), "{span:?}");
            }
        }
        let metrics = memory.metrics();
        assert!(
            metrics
                .iter()
                .any(|metric| metric.name == METRIC_APPLY_OUTCOME),
            "{metrics:?}"
        );
        assert!(
            metrics
                .iter()
                .any(|metric| metric.name == METRIC_LEASE_ACQUIRED),
            "{metrics:?}"
        );
        assert!(
            metrics
                .iter()
                .any(|metric| metric.name == METRIC_LEASE_RELEASED),
            "{metrics:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn noop_reconcile_tick_records_latency_without_exporter() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-otel-reconcile-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        let mut register = ctx.clone();
        crate::ontology::register(&mut register).await.unwrap();
        plan::env_add(&mut register, "local", "fixture")
            .await
            .unwrap();
        let memory = Arc::new(MemoryTelemetry::new());
        scope(memory.clone(), "corr-380-reconcile", async {
            let reconciler = crate::reconciler::Reconciler::new(
                ctx,
                crate::reconciler::Config {
                    initial_backoff: std::time::Duration::from_millis(100),
                    max_backoff: std::time::Duration::from_millis(250),
                    max_concurrency: 2,
                    skip_gates: false,
                    unapproved_development_reason: Some("otel reconcile drill".into()),
                    approval_directory: None,
                    approval_trust_roots: None,
                    channel_promotion_policies: true,
                },
            )
            .unwrap();
            reconciler.run_once().await.unwrap();
        })
        .await;
        let metrics = memory.metrics();
        assert!(
            metrics
                .iter()
                .any(|metric| metric.name == METRIC_RECONCILE_LATENCY_MS),
            "{metrics:?}"
        );
        let spans = memory.spans();
        assert!(
            spans.iter().any(|span| span.name == "tenkai.reconcile"),
            "{spans:?}"
        );
        for span in &spans {
            assert_eq!(
                span.attributes.get(ATTR_OPERATION_ID).map(String::as_str),
                Some("corr-380-reconcile"),
                "{span:?}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_shell_product(root: &std::path::Path, version: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "edge-app"
version = "{version}"
kind = "software"

[deploy]
workdir = "."
install = "true"
uninstall = "true"
"#
            ),
        )
        .unwrap();
    }

    fn assert_apply_succeeded(outcomes: Vec<crate::apply::Outcome>) {
        assert!(
            !outcomes.is_empty() && outcomes.iter().all(|outcome| outcome.status == "succeeded"),
            "{outcomes:?}"
        );
    }
}

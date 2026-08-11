//! Optional governance and intelligence provider contracts.
//!
//! Providers return or consume evidence; they never own releases, plans,
//! execution state, leases, receipts, or rollback recovery.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

use crate::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::pb::sekai::{EvidenceEnvelope, Object, SubmitEvidenceRequest};
use crate::storage::{ProviderEventRecord, StoreError};

pub use crate::provider_event::{
    DeliveryStatus, deliver_optional_event, deliver_outcome_batch, enqueue_optional_event,
    provider_event_record,
};

pub const PROVIDER_CONTRACT_VERSION: u32 = 1;
pub const TERMINAL_OUTCOME_SCHEMA: &str = "tenkai.terminal_outcome.v1";
const TERMINAL_OUTCOME_SCHEMA_VERSION: &str = "1.0.0";
pub const OUTCOME_PROVIDER_KIND: &str = "outcome";
pub const OUTCOME_PROVIDER_REGISTRATION_ENV: &str = "TENKAI_OUTCOME_PROVIDER_REGISTRATION";
const MAX_PROVIDER_EVENT_ID_BYTES: usize = 512;
const MAX_PROVIDER_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;

fn evidence_submission_succeeded(result: &crate::pb::sekai::EvidenceSubmissionResult) -> bool {
    let Some(submission) = result.submission.as_ref() else {
        return false;
    };
    let lifecycle = submission.lifecycle_state.trim();
    if lifecycle.is_empty()
        || matches!(
            lifecycle,
            "received" | "validated" | "deduplicated" | "rejected"
        )
    {
        return false;
    }
    // A rejection code contradicts admission unless Sekai explicitly retained
    // an admitted submission in quarantine because projection failed.
    let rejection_is_projection_quarantine =
        lifecycle == "quarantined" && submission.rejection_code.starts_with("projection_");
    if !submission.rejection_code.is_empty() && !rejection_is_projection_quarantine {
        return false;
    }
    result.admitted || result.deduplicated
}

/// Exact operational inputs to which a decision or exported event applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBinding {
    pub contract_version: u32,
    pub release_digest: String,
    pub plan_digest: String,
    pub configuration_digest: String,
    pub environment_id: String,
}

impl EvidenceBinding {
    pub fn digest(&self) -> String {
        let mut digest = Sha256::new();
        for value in [
            PROVIDER_CONTRACT_VERSION.to_string().as_bytes(),
            self.release_digest.as_bytes(),
            self.plan_digest.as_bytes(),
            self.configuration_digest.as_bytes(),
            self.environment_id.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value);
        }
        format!("sha256:{:x}", digest.finalize())
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.contract_version != PROVIDER_CONTRACT_VERSION {
            return Err(ProviderError::InvalidEvidence(format!(
                "unsupported provider contract version {}",
                self.contract_version
            )));
        }
        for (name, value) in [
            ("release digest", &self.release_digest),
            ("plan digest", &self.plan_digest),
            ("configuration digest", &self.configuration_digest),
            ("environment", &self.environment_id),
        ] {
            if value.trim().is_empty() {
                return Err(ProviderError::InvalidEvidence(format!("{name} is empty")));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub request_id: String,
    pub action: String,
    pub principal: String,
    pub binding: EvidenceBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDecision {
    pub allowed: bool,
    pub reason: String,
    pub evidence_id: String,
    pub binding_digest: String,
    pub request_id: String,
    pub action: String,
    pub principal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEvent {
    pub id: String,
    pub binding: EvidenceBinding,
    pub payload_json: String,
    /// Set atomically on the first delivery attempt and retained across
    /// retries. `None` is valid only before the event enters delivery.
    #[serde(default)]
    pub collected_at_ms: Option<i64>,
    /// Source-instance ordering allocated durably on first delivery.
    #[serde(default)]
    pub source_sequence: Option<i64>,
}

impl ProviderEvent {
    pub fn validate(&self) -> Result<(), ProviderError> {
        self.binding.validate()?;
        if self.id.trim().is_empty() || self.id.len() > MAX_PROVIDER_EVENT_ID_BYTES {
            return Err(ProviderError::InvalidEvidence(
                "provider event id is empty or exceeds the bounded contract".into(),
            ));
        }
        if self.payload_json.is_empty()
            || self.payload_json.len() > MAX_PROVIDER_EVENT_PAYLOAD_BYTES
            || serde_json::from_str::<serde_json::Value>(&self.payload_json).is_err()
        {
            return Err(ProviderError::InvalidEvidence(
                "provider event payload is empty, oversized, or not valid JSON".into(),
            ));
        }
        if self.collected_at_ms.is_some_and(|timestamp| timestamp <= 0) {
            return Err(ProviderError::InvalidEvidence(
                "provider event collection timestamp must be positive".into(),
            ));
        }
        if self.source_sequence.is_some_and(|sequence| sequence <= 0) {
            return Err(ProviderError::InvalidEvidence(
                "provider event source sequence must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcomeState {
    DeploymentSucceeded,
    DeploymentFailed,
    AutomaticRollbackSucceeded,
    RollbackSucceeded,
    RollbackFailed,
    ExecutionCancelled,
    UnknownReconciled,
}

impl TerminalOutcomeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentSucceeded => "deployment_succeeded",
            Self::DeploymentFailed => "deployment_failed",
            Self::AutomaticRollbackSucceeded => "automatic_rollback_succeeded",
            Self::RollbackSucceeded => "rollback_succeeded",
            Self::RollbackFailed => "rollback_failed",
            Self::ExecutionCancelled => "execution_cancelled",
            Self::UnknownReconciled => "unknown_reconciled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalOutcomePayload {
    pub schema: String,
    pub deployment_id: String,
    pub plan_id: String,
    pub release_id: String,
    pub product: String,
    pub environment_id: String,
    pub configuration_id: String,
    pub terminal_state: TerminalOutcomeState,
    pub observed_at: i64,
}

impl TerminalOutcomePayload {
    fn validate_for_event(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        if self.schema != TERMINAL_OUTCOME_SCHEMA || self.observed_at <= 0 {
            return Err(ProviderError::InvalidEvidence(
                "terminal outcome schema or observation time is invalid".into(),
            ));
        }
        for (name, value) in [
            ("deployment", &self.deployment_id),
            ("plan", &self.plan_id),
            ("release", &self.release_id),
            ("product", &self.product),
            ("environment", &self.environment_id),
            ("configuration", &self.configuration_id),
        ] {
            if value.trim().is_empty() || value.len() > MAX_PROVIDER_EVENT_ID_BYTES {
                return Err(ProviderError::InvalidEvidence(format!(
                    "terminal outcome {name} identity is empty or oversized"
                )));
            }
        }
        if self.environment_id != event.binding.environment_id {
            return Err(ProviderError::InvalidEvidence(
                "terminal outcome environment does not match its evidence binding".into(),
            ));
        }
        Ok(())
    }
}

/// Bounded, authenticated read projection of one Tenkai-owned terminal
/// outcome and its optional-provider delivery state. The projection contains
/// identities and digests only; the original event payload and retry error are
/// never returned to an operator or integration client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalOutcomeProjection {
    pub event_id: String,
    pub schema: String,
    pub deployment_id: String,
    pub plan_id: String,
    pub release_id: String,
    pub product: String,
    pub environment_id: String,
    pub configuration_id: String,
    pub terminal_state: String,
    pub observed_at: i64,
    pub binding_digest: String,
    pub release_digest: String,
    pub plan_digest: String,
    pub configuration_digest: String,
    pub delivery_state: String,
    pub attempts: u32,
    pub next_attempt_at: i64,
    pub delivered_at: Option<i64>,
    pub claim_until: Option<i64>,
    pub delivery_lag_ms: i64,
}

/// Project a durable outcome row without exposing its bounded event payload.
/// Invalid rows fail closed so a corrupt or forged outbox record cannot be
/// presented as authoritative evidence.
pub fn project_terminal_outcome(
    record: &ProviderEventRecord,
    as_of: i64,
) -> Result<Option<TerminalOutcomeProjection>, ProviderError> {
    if record.provider_kind != OUTCOME_PROVIDER_KIND {
        return Ok(None);
    }
    let event: ProviderEvent = serde_json::from_str(&record.payload_json)?;
    event.validate()?;
    if event.id != record.id || event.binding.digest() != record.binding_digest {
        return Err(ProviderError::InvalidEvidence(
            "terminal outcome row does not match its event envelope".into(),
        ));
    }
    let payload_value: serde_json::Value = serde_json::from_str(&event.payload_json)?;
    if payload_value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        != Some(TERMINAL_OUTCOME_SCHEMA)
    {
        return Ok(None);
    }
    let payload: TerminalOutcomePayload = serde_json::from_value(payload_value)?;
    payload.validate_for_event(&event)?;
    let expected_event_id = terminal_outcome_event_id(&event.binding, &payload)?;
    let legacy_event_id = legacy_terminal_outcome_event_id(&event.binding, &payload);
    if event.id != expected_event_id && event.id != legacy_event_id {
        return Err(ProviderError::InvalidEvidence(
            "terminal outcome event identity does not bind its payload".into(),
        ));
    }
    // The pre-v2 identity did not include every projected field. Keep those
    // durable rows for delivery and historical storage, but do not present
    // them as authoritative readback evidence.
    if event.id == legacy_event_id {
        return Ok(None);
    }
    let delivery_state = if record.delivered_at.is_some() {
        "delivered"
    } else if record.claim_token.is_some()
        && record
            .claim_until
            .is_some_and(|claim_until| claim_until > as_of)
    {
        "in_flight"
    } else if record.attempts > 0 {
        "retrying"
    } else {
        "pending"
    };
    let delivery_end = record
        .delivered_at
        .unwrap_or(as_of)
        .max(payload.observed_at);
    Ok(Some(TerminalOutcomeProjection {
        event_id: event.id,
        schema: payload.schema,
        deployment_id: payload.deployment_id,
        plan_id: payload.plan_id,
        release_id: payload.release_id,
        product: payload.product,
        environment_id: payload.environment_id,
        configuration_id: payload.configuration_id,
        terminal_state: payload.terminal_state.as_str().into(),
        observed_at: payload.observed_at,
        binding_digest: event.binding.digest(),
        release_digest: event.binding.release_digest,
        plan_digest: event.binding.plan_digest,
        configuration_digest: event.binding.configuration_digest,
        delivery_state: delivery_state.into(),
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        delivered_at: record.delivered_at,
        claim_until: record.claim_until,
        delivery_lag_ms: delivery_end.saturating_sub(payload.observed_at),
    }))
}

/// Project a bounded, authenticated set of terminal outcomes for one
/// environment. Callers own storage lookup and authorization; this helper
/// owns provider-record validation, environment filtering, and ordering.
pub(crate) fn project_terminal_outcomes(
    records: &[ProviderEventRecord],
    environment: &str,
    as_of: i64,
) -> Result<Vec<TerminalOutcomeProjection>, ProviderError> {
    let mut outcomes = Vec::new();
    for record in records {
        let Some(outcome) = project_terminal_outcome(record, as_of)? else {
            continue;
        };
        if outcome.environment_id == environment {
            outcomes.push(outcome);
        }
    }
    outcomes.sort_by(|left, right| {
        left.observed_at
            .cmp(&right.observed_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    Ok(outcomes)
}

fn legacy_terminal_outcome_event_id(
    binding: &EvidenceBinding,
    payload: &TerminalOutcomePayload,
) -> String {
    let observed_at = payload.observed_at.to_string();
    let binding_digest = binding.digest();
    let mut identity = Sha256::new();
    for value in [
        payload.deployment_id.as_str(),
        payload.plan_id.as_str(),
        payload.release_id.as_str(),
        payload.terminal_state.as_str(),
        binding_digest.as_str(),
        observed_at.as_str(),
    ] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    format!("tenkai:outcome:v1:{:x}", identity.finalize())
}

fn terminal_outcome_event_id(
    binding: &EvidenceBinding,
    payload: &TerminalOutcomePayload,
) -> Result<String, ProviderError> {
    let payload_json = serde_json::to_string(payload)?;
    let binding_digest = binding.digest();
    let mut identity = Sha256::new();
    for value in [&binding_digest, &payload_json] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    Ok(format!("tenkai:outcome:v2:{:x}", identity.finalize()))
}

pub fn environment_configuration_digest(environment: &Object) -> String {
    let mut digest = Sha256::new();
    for value in [&environment.id, &environment.namespace] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    let mut configuration = environment
        .properties
        .iter()
        .filter(|(key, _)| {
            ![
                "deployed.",
                "deployed_prev.",
                "deployed_release.",
                "deployment_health.",
                "deployment_error.",
                "deployment_unknown_",
            ]
            .iter()
            .any(|prefix| key.starts_with(prefix))
        })
        .collect::<Vec<_>>();
    configuration.sort_by(|left, right| left.0.cmp(right.0));
    for (key, value) in configuration {
        for part in [key.as_bytes(), value.as_bytes()] {
            digest.update((part.len() as u64).to_le_bytes());
            digest.update(part);
        }
    }
    format!("sha256:{:x}", digest.finalize())
}

#[allow(clippy::too_many_arguments)]
pub fn terminal_outcome_event(
    deployment_id: &str,
    plan_id: &str,
    plan_digest: &str,
    release_id: &str,
    release_digest: &str,
    product: &str,
    environment_id: &str,
    configuration_id: &str,
    configuration_digest: &str,
    terminal_state: TerminalOutcomeState,
    observed_at: i64,
) -> Result<ProviderEvent, ProviderError> {
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest: release_digest.into(),
        plan_digest: plan_digest.into(),
        configuration_digest: configuration_digest.into(),
        environment_id: environment_id.into(),
    };
    binding.validate()?;
    let payload = TerminalOutcomePayload {
        schema: TERMINAL_OUTCOME_SCHEMA.into(),
        deployment_id: deployment_id.into(),
        plan_id: plan_id.into(),
        release_id: release_id.into(),
        product: product.into(),
        environment_id: environment_id.into(),
        configuration_id: configuration_id.into(),
        terminal_state,
        observed_at,
    };
    let event = ProviderEvent {
        id: terminal_outcome_event_id(&binding, &payload)?,
        binding,
        payload_json: serde_json::to_string(&payload)?,
        collected_at_ms: None,
        source_sequence: None,
    };
    event.validate()?;
    payload.validate_for_event(&event)?;
    Ok(event)
}

pub fn terminal_outcome_record(
    plan: &crate::plan::Plan,
    step: &crate::plan::Step,
    deployment_id: &str,
    terminal_state: TerminalOutcomeState,
    environment: &Object,
    observed_at: i64,
) -> Result<ProviderEventRecord, ProviderError> {
    if environment.id.trim().is_empty() {
        return Err(ProviderError::InvalidEvidence(
            "terminal outcome environment object is missing its identity".into(),
        ));
    }
    let plan_digest = plan.executable_digest().map_err(|error| {
        ProviderError::InvalidEvidence(format!(
            "terminal outcome plan digest could not be computed: {error}"
        ))
    })?;
    let event = terminal_outcome_event(
        deployment_id,
        &plan.id,
        &plan_digest,
        &step.release_id,
        &step.release_digest,
        &step.product,
        &plan.environment,
        &environment.id,
        &environment_configuration_digest(environment),
        terminal_state,
        observed_at,
    )?;
    provider_event_record(OUTCOME_PROVIDER_KIND, &event, observed_at)
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("provider timed out after {0:?}")]
    Timeout(Duration),
    #[error("provider returned invalid evidence: {0}")]
    InvalidEvidence(String),
    #[error("required provider blocked {action}: {reason}")]
    Blocked { action: String, reason: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("provider event serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub trait GateProvider: Send + Sync {
    fn evaluate<'a>(
        &'a self,
        request: &'a DecisionRequest,
    ) -> impl Future<Output = Result<ProviderDecision, ProviderError>> + Send + 'a;
}

pub trait PolicyProvider: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: &'a DecisionRequest,
    ) -> impl Future<Output = Result<ProviderDecision, ProviderError>> + Send + 'a;
}

pub trait AuditExporter: Send + Sync {
    fn export<'a>(
        &'a self,
        event: &'a ProviderEvent,
    ) -> impl Future<Output = Result<(), ProviderError>> + Send + 'a;
}

pub trait OutcomeProvider: Send + Sync {
    fn record<'a>(
        &'a self,
        event: &'a ProviderEvent,
    ) -> impl Future<Output = Result<(), ProviderError>> + Send + 'a;
}

/// Standalone gate implementation. Configured evidence IDs are immutable input
/// to the local host, so retries return the same decision.
#[derive(Debug, Clone)]
pub struct LocalGateProvider {
    pub passing_evidence_id: Option<String>,
}

/// Remote gate provider over the generic HTTP JSON decision contract.
///
/// POSTs a [`DecisionRequest`] to `endpoint` and expects a [`ProviderDecision`]
/// body. Used for chisei-compatible (or other) evaluation hosts. Community
/// ungated deploys never construct this adapter, so they never open a network
/// connection.
///
/// Auth: optional bearer from constructor (host loads from env/file — never
/// commit tokens). Timeouts fail closed when used with [`required_decision`].
#[derive(Debug, Clone)]
pub struct HttpRemoteGateProvider {
    /// Absolute URL of the decision endpoint (e.g. `https://eval.example/v1/gate/decide`).
    pub endpoint: String,
    /// Per-request timeout for the HTTP call (not including outer required_decision).
    pub timeout: Duration,
    /// Optional `Authorization: Bearer` token (opaque; never logged by this type).
    pub bearer_token: Option<String>,
    client: reqwest::Client,
}

impl HttpRemoteGateProvider {
    pub fn new(
        endpoint: impl Into<String>,
        timeout: Duration,
        bearer_token: Option<String>,
    ) -> Result<Self, ProviderError> {
        let endpoint = endpoint.into();
        if endpoint.trim().is_empty() {
            return Err(ProviderError::InvalidEvidence(
                "remote gate endpoint must not be empty".into(),
            ));
        }
        if timeout.is_zero() {
            return Err(ProviderError::InvalidEvidence(
                "remote gate timeout must be positive".into(),
            ));
        }
        if bearer_token.as_ref().is_some_and(|t| t.trim().is_empty()) {
            return Err(ProviderError::InvalidEvidence(
                "remote gate bearer token must not be empty when set".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("tenkai-gate-provider/1")
            .build()
            .map_err(|error| {
                ProviderError::Unavailable(format!("failed to build HTTP client: {error}"))
            })?;
        Ok(Self {
            endpoint,
            timeout,
            bearer_token,
            client,
        })
    }
}

impl GateProvider for HttpRemoteGateProvider {
    async fn evaluate(&self, request: &DecisionRequest) -> Result<ProviderDecision, ProviderError> {
        request.binding.validate()?;
        let mut builder = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(request);
        if let Some(token) = &self.bearer_token {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                ProviderError::Timeout(self.timeout)
            } else {
                ProviderError::Unavailable(format!("remote gate transport failed: {error}"))
            }
        })?;
        let status = response.status();
        if !status.is_success() {
            // Do not include response body (may contain secrets); status only.
            return Err(ProviderError::Unavailable(format!(
                "remote gate returned HTTP {status}"
            )));
        }
        let decision: ProviderDecision = response.json().await.map_err(|error| {
            ProviderError::InvalidEvidence(format!(
                "remote gate response is not valid JSON: {error}"
            ))
        })?;
        if decision.evidence_id.trim().is_empty() {
            return Err(ProviderError::InvalidEvidence(
                "remote gate decision is missing evidence_id".into(),
            ));
        }
        // Full binding/request checks live in required_decision; surface clear
        // errors early for obvious mismatches.
        if decision.request_id != request.request_id {
            return Err(ProviderError::InvalidEvidence(
                "remote gate decision request_id does not match".into(),
            ));
        }
        Ok(decision)
    }
}

/// Reference adapter for Sekai's authenticated, namespace-scoped
/// `SubmitEvidence` admission path.
#[derive(Clone)]
pub struct ChiseiOutcomeProvider {
    namespace: String,
    principal: String,
    bearer_token: Option<String>,
    registration_attested: bool,
    client: SekaiServiceClient<Channel>,
}

impl std::fmt::Debug for ChiseiOutcomeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChiseiOutcomeProvider")
            .field("namespace", &self.namespace)
            .field("principal", &self.principal)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[redacted]"),
            )
            .field("registration_attested", &self.registration_attested)
            .finish_non_exhaustive()
    }
}

fn outcome_transport_is_safe(endpoint: &str) -> bool {
    let Ok(parsed) = url::Url::parse(endpoint) else {
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

/// Return the exact, non-secret registration contract expected by the
/// terminal-outcome adapter. Sekai administrators register the corresponding
/// producer capability and schema out of band; Tenkai compares this value at
/// startup before enabling delivery.
pub fn outcome_provider_registration_attestation(principal: &str, namespace: &str) -> String {
    format!(
        "producer={principal};source_type={OUTCOME_PROVIDER_KIND};source_instance={namespace}:{OUTCOME_PROVIDER_KIND};namespace={namespace};evidence_type=operations.terminal_outcome;schema={TERMINAL_OUTCOME_SCHEMA}@{TERMINAL_OUTCOME_SCHEMA_VERSION};target_kind=tenkai.deployment;classification=internal;intent=upsert"
    )
}

impl ChiseiOutcomeProvider {
    /// Build an adapter for evidence mapping and local inspection.
    ///
    /// This constructor deliberately leaves delivery disabled. The server
    /// host must use [`Self::new_for_export`] so the operator has explicitly
    /// confirmed the producer and schema registrations required by Sekai.
    pub fn new(
        endpoint: impl Into<String>,
        namespace: impl Into<String>,
        principal: impl Into<String>,
        bearer_token: Option<String>,
    ) -> Result<Self, ProviderError> {
        let endpoint = endpoint.into();
        let namespace = namespace.into();
        let principal = principal.into();
        if namespace.trim().is_empty()
            || principal.trim().is_empty()
            || namespace.len() > MAX_PROVIDER_EVENT_ID_BYTES
            || principal.len() > MAX_PROVIDER_EVENT_ID_BYTES
        {
            return Err(ProviderError::InvalidEvidence(
                "outcome namespace and principal must be non-empty and bounded".into(),
            ));
        }
        if bearer_token.as_ref().is_some_and(|token| token.is_empty()) {
            return Err(ProviderError::InvalidEvidence(
                "outcome bearer token must not be empty when configured".into(),
            ));
        }
        if !outcome_transport_is_safe(&endpoint) {
            return Err(ProviderError::InvalidEvidence(
                "outcome provider endpoints require HTTPS or loopback HTTP".into(),
            ));
        }
        let channel = Endpoint::from_shared(endpoint)
            .map_err(|_| {
                ProviderError::InvalidEvidence(
                    "outcome provider endpoint is not a valid absolute URL".into(),
                )
            })?
            .connect_lazy();
        Ok(Self {
            namespace,
            principal,
            bearer_token,
            registration_attested: false,
            client: SekaiServiceClient::new(channel),
        })
    }

    /// Build an adapter that is allowed to submit terminal outcome evidence.
    ///
    /// Sekai 1.0 does not expose producer-capability provisioning through the
    /// client RPC surface. The registration attestation therefore binds the
    /// configured principal, namespace, source identity, evidence type, and
    /// schema to the administrator-side registration that must already exist.
    pub fn new_for_export(
        endpoint: impl Into<String>,
        namespace: impl Into<String>,
        principal: impl Into<String>,
        bearer_token: Option<String>,
        registration_attestation: impl AsRef<str>,
    ) -> Result<Self, ProviderError> {
        let provider = Self::new(endpoint, namespace, principal, bearer_token)?;
        let expected =
            outcome_provider_registration_attestation(&provider.principal, &provider.namespace);
        if registration_attestation.as_ref() != expected {
            return Err(ProviderError::InvalidEvidence(format!(
                "{OUTCOME_PROVIDER_REGISTRATION_ENV} must exactly confirm the configured Sekai producer and schema registration"
            )));
        }
        Ok(Self {
            registration_attested: true,
            ..provider
        })
    }

    fn evidence(&self, event: &ProviderEvent) -> Result<EvidenceEnvelope, ProviderError> {
        event.validate()?;
        let payload: TerminalOutcomePayload = serde_json::from_str(&event.payload_json)?;
        payload.validate_for_event(event)?;
        let content_value: serde_json::Value = serde_json::from_str(&event.payload_json)?;
        let content_json = serde_json::to_vec(&content_value)?;
        let content_digest = format!("{:x}", Sha256::digest(&content_json));
        Ok(EvidenceEnvelope {
            contract_version: "sekai.evidence/v1".into(),
            source_type: OUTCOME_PROVIDER_KIND.into(),
            source_instance: format!("{}:{OUTCOME_PROVIDER_KIND}", self.namespace),
            source_record_id: event.id.clone(),
            source_version: PROVIDER_CONTRACT_VERSION.to_string(),
            source_sequence: event.source_sequence.ok_or_else(|| {
                ProviderError::InvalidEvidence(
                    "terminal outcome delivery is missing its durable source sequence".into(),
                )
            })?,
            namespace: self.namespace.clone(),
            target_external_id: payload.deployment_id,
            target_kind: "tenkai.deployment".into(),
            evidence_type: "operations.terminal_outcome".into(),
            signal: "other".into(),
            schema_id: TERMINAL_OUTCOME_SCHEMA.into(),
            schema_version: TERMINAL_OUTCOME_SCHEMA_VERSION.into(),
            schema_compatibility: "exact".into(),
            observed_at_ms: payload.observed_at,
            collected_at_ms: event.collected_at_ms.ok_or_else(|| {
                ProviderError::InvalidEvidence(
                    "terminal outcome delivery is missing its durable collection timestamp".into(),
                )
            })?,
            expires_at_ms: None,
            content_json,
            relationships: Vec::new(),
            producer_identity: self.principal.clone(),
            confidence_bps: 10_000,
            classification: "internal".into(),
            provenance: HashMap::from([
                (
                    "environment_id".into(),
                    event.binding.environment_id.clone(),
                ),
                (
                    "release_digest".into(),
                    event.binding.release_digest.clone(),
                ),
                ("plan_digest".into(), event.binding.plan_digest.clone()),
                (
                    "configuration_digest".into(),
                    event.binding.configuration_digest.clone(),
                ),
                (
                    "provider_contract_version".into(),
                    PROVIDER_CONTRACT_VERSION.to_string(),
                ),
            ]),
            idempotency_key: event.id.clone(),
            content_digest,
            intent: "upsert".into(),
            causality: None,
        })
    }
}

impl OutcomeProvider for ChiseiOutcomeProvider {
    async fn record(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        if !self.registration_attested {
            return Err(ProviderError::InvalidEvidence(
                "Sekai outcome export requires administrator-confirmed producer and schema registration".into(),
            ));
        }
        let evidence = self.evidence(event)?;
        let mut request = tonic::Request::new(SubmitEvidenceRequest {
            envelope: Some(evidence),
        });
        let principal = MetadataValue::try_from(self.principal.as_str()).map_err(|_| {
            ProviderError::InvalidEvidence("outcome principal is not valid metadata".into())
        })?;
        request.metadata_mut().insert("x-principal", principal);
        if let Some(token) = &self.bearer_token {
            let authorization =
                MetadataValue::try_from(format!("Bearer {token}")).map_err(|_| {
                    ProviderError::InvalidEvidence(
                        "outcome bearer token is not valid metadata".into(),
                    )
                })?;
            request
                .metadata_mut()
                .insert("authorization", authorization);
        }
        let mut client = self.client.clone();
        let result = client
            .submit_evidence(request)
            .await
            .map_err(|status| {
                ProviderError::Unavailable(format!(
                    "Sekai outcome evidence admission returned gRPC {}",
                    status.code()
                ))
            })?
            .into_inner()
            .result
            .ok_or_else(|| {
                ProviderError::Unavailable(
                    "Sekai outcome evidence admission returned no result".into(),
                )
            })?;
        if !evidence_submission_succeeded(&result) {
            return Err(ProviderError::Unavailable(
                "Sekai rejected terminal outcome evidence".into(),
            ));
        }
        Ok(())
    }
}

impl GateProvider for LocalGateProvider {
    async fn evaluate(&self, request: &DecisionRequest) -> Result<ProviderDecision, ProviderError> {
        request.binding.validate()?;
        let binding_digest = request.binding.digest();
        Ok(match &self.passing_evidence_id {
            Some(evidence_id) => ProviderDecision {
                allowed: true,
                reason: "local gate evidence passed".into(),
                evidence_id: evidence_id.clone(),
                binding_digest,
                request_id: request.request_id.clone(),
                action: request.action.clone(),
                principal: request.principal.clone(),
            },
            None => ProviderDecision {
                allowed: false,
                reason: "no passing local gate evidence is configured".into(),
                evidence_id: format!("local-gate:{}", request.request_id),
                binding_digest,
                request_id: request.request_id.clone(),
                action: request.action.clone(),
                principal: request.principal.clone(),
            },
        })
    }
}

/// Standalone policy implementation with an explicit allow list.
#[derive(Debug, Clone, Default)]
pub struct LocalPolicyProvider {
    pub allowed_actions: std::collections::BTreeSet<String>,
}

impl PolicyProvider for LocalPolicyProvider {
    async fn authorize(
        &self,
        request: &DecisionRequest,
    ) -> Result<ProviderDecision, ProviderError> {
        request.binding.validate()?;
        let allowed = self.allowed_actions.contains(&request.action);
        Ok(ProviderDecision {
            allowed,
            reason: if allowed {
                "allowed by local policy".into()
            } else {
                format!("action {} is not allowed by local policy", request.action)
            },
            evidence_id: format!("local-policy:{}", request.request_id),
            binding_digest: request.binding.digest(),
            request_id: request.request_id.clone(),
            action: request.action.clone(),
            principal: request.principal.clone(),
        })
    }
}

/// Standalone optional sink. Durable truth remains in the operational store;
/// retaining the received events is only a convenient local projection.
#[derive(Debug, Default)]
pub struct LocalEventSink {
    received: std::sync::Mutex<Vec<ProviderEvent>>,
}

impl LocalEventSink {
    pub fn received(&self) -> Vec<ProviderEvent> {
        self.received.lock().expect("local sink mutex").clone()
    }

    async fn receive(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        event.validate()?;
        let mut received = self.received.lock().expect("local sink mutex");
        if !received.iter().any(|stored| stored.id == event.id) {
            received.push(event.clone());
        }
        Ok(())
    }
}

impl AuditExporter for LocalEventSink {
    async fn export(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        self.receive(event).await
    }
}

impl OutcomeProvider for LocalEventSink {
    async fn record(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        self.receive(event).await
    }
}

/// Fail closed for a required decision. Timeout, transport failure, denial,
/// malformed evidence, or evidence for different operational inputs all block.
pub async fn required_decision<F>(
    request: &DecisionRequest,
    timeout: Duration,
    decision: F,
) -> Result<ProviderDecision, ProviderError>
where
    F: Future<Output = Result<ProviderDecision, ProviderError>>,
{
    request.binding.validate()?;
    let result = tokio::time::timeout(timeout, decision)
        .await
        .map_err(|_| ProviderError::Timeout(timeout))??;
    if result.binding_digest != request.binding.digest()
        || result.request_id != request.request_id
        || result.action != request.action
        || result.principal != request.principal
    {
        return Err(ProviderError::InvalidEvidence(
            "decision is bound to a different request, action, principal, or operational input"
                .into(),
        ));
    }
    if !result.allowed {
        return Err(ProviderError::Blocked {
            action: request.action.clone(),
            reason: result.reason,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{OperationalStore, SqliteStore};

    fn binding() -> EvidenceBinding {
        EvidenceBinding {
            contract_version: PROVIDER_CONTRACT_VERSION,
            release_digest: "sha256:release".into(),
            plan_digest: "sha256:plan".into(),
            configuration_digest: "sha256:config".into(),
            environment_id: "prod".into(),
        }
    }

    fn request() -> DecisionRequest {
        DecisionRequest {
            request_id: "request-1".into(),
            action: "deploy".into(),
            principal: "operator".into(),
            binding: binding(),
        }
    }

    fn terminal_event() -> ProviderEvent {
        terminal_outcome_event(
            "tenkai:deployment:prod:api:1",
            "tenkai:plan:prod:1",
            "sha256:plan",
            "tenkai:release:api@2.0.0",
            "sha256:release",
            "api",
            "prod",
            "tenkai:environment:prod",
            "sha256:config",
            TerminalOutcomeState::AutomaticRollbackSucceeded,
            1_000,
        )
        .unwrap()
    }

    fn terminal_event_for(
        environment: &str,
        deployment_id: &str,
        observed_at: i64,
    ) -> ProviderEvent {
        terminal_outcome_event(
            deployment_id,
            "tenkai:plan:shared",
            "sha256:plan",
            "tenkai:release:api@2.0.0",
            "sha256:release",
            "api",
            environment,
            &format!("tenkai:environment:{environment}"),
            "sha256:config",
            TerminalOutcomeState::DeploymentSucceeded,
            observed_at,
        )
        .unwrap()
    }

    #[test]
    fn terminal_outcome_projections_filter_and_order_records() {
        let first = terminal_event_for("prod", "tenkai:deployment:prod:first", 1_000);
        let second = terminal_event_for("prod", "tenkai:deployment:prod:second", 1_000);
        let wrong_environment = terminal_event_for("stage", "tenkai:deployment:stage:wrong", 500);
        let generic = provider_event_record("audit", &first, 2_000).unwrap();
        let records = [
            provider_event_record(OUTCOME_PROVIDER_KIND, &first, 2_000).unwrap(),
            generic,
            provider_event_record(OUTCOME_PROVIDER_KIND, &wrong_environment, 500).unwrap(),
            provider_event_record(OUTCOME_PROVIDER_KIND, &second, 1_000).unwrap(),
        ];

        let projections = project_terminal_outcomes(&records, "prod", 3_000).unwrap();
        let mut expected_ids = vec![first.id.as_str(), second.id.as_str()];
        expected_ids.sort_unstable();

        assert_eq!(
            projections
                .iter()
                .map(|projection| projection.event_id.as_str())
                .collect::<Vec<_>>(),
            expected_ids
        );
        assert!(
            projections
                .iter()
                .all(|projection| projection.environment_id == "prod")
        );
    }

    #[test]
    fn terminal_outcome_projections_reject_invalid_evidence() {
        let event = terminal_event();
        let mut invalid = provider_event_record(OUTCOME_PROVIDER_KIND, &event, 1_000).unwrap();
        invalid.binding_digest = "sha256:tampered".into();

        assert!(project_terminal_outcomes(&[invalid], "prod", 4_000).is_err());
    }

    #[test]
    fn deduplicated_evidence_must_reference_an_admitted_submission() {
        let rejected = crate::pb::sekai::EvidenceSubmissionResult {
            deduplicated: true,
            submission: Some(crate::pb::sekai::EvidenceSubmissionRecord {
                lifecycle_state: "rejected".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!evidence_submission_succeeded(&rejected));

        let admitted = crate::pb::sekai::EvidenceSubmissionResult {
            deduplicated: true,
            submission: Some(crate::pb::sekai::EvidenceSubmissionRecord {
                lifecycle_state: "available".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(evidence_submission_succeeded(&admitted));
        assert!(evidence_submission_succeeded(
            &crate::pb::sekai::EvidenceSubmissionResult {
                deduplicated: true,
                submission: Some(crate::pb::sekai::EvidenceSubmissionRecord {
                    lifecycle_state: "future_admitted_state".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ));
        assert!(!evidence_submission_succeeded(
            &crate::pb::sekai::EvidenceSubmissionResult {
                admitted: true,
                ..Default::default()
            }
        ));
        assert!(!evidence_submission_succeeded(
            &crate::pb::sekai::EvidenceSubmissionResult {
                admitted: true,
                submission: Some(crate::pb::sekai::EvidenceSubmissionRecord {
                    lifecycle_state: "rejected".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ));
        assert!(evidence_submission_succeeded(
            &crate::pb::sekai::EvidenceSubmissionResult {
                deduplicated: true,
                submission: Some(crate::pb::sekai::EvidenceSubmissionRecord {
                    lifecycle_state: "quarantined".into(),
                    rejection_code: "projection_unavailable".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ));
        assert!(!evidence_submission_succeeded(
            &crate::pb::sekai::EvidenceSubmissionResult {
                deduplicated: true,
                submission: Some(crate::pb::sekai::EvidenceSubmissionRecord {
                    lifecycle_state: "quarantined".into(),
                    rejection_code: "producer_unregistered".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn terminal_outcome_projection_is_bounded_and_reports_delivery_lag() {
        let event = terminal_event();
        let mut record = provider_event_record(OUTCOME_PROVIDER_KIND, &event, 1_000).unwrap();
        let pending = project_terminal_outcome(&record, 4_000).unwrap().unwrap();
        assert_eq!(pending.delivery_state, "pending");
        assert_eq!(pending.delivery_lag_ms, 3_000);
        assert_eq!(pending.binding_digest, event.binding.digest());
        let encoded = serde_json::to_string(&pending).unwrap();
        assert!(!encoded.contains("payload_json"));
        assert!(!encoded.contains("private-claim"));

        let mut tampered_record = record.clone();
        let mut tampered_event: ProviderEvent =
            serde_json::from_str(&tampered_record.payload_json).unwrap();
        let mut tampered_payload: TerminalOutcomePayload =
            serde_json::from_str(&tampered_event.payload_json).unwrap();
        tampered_payload.product = "tampered".into();
        tampered_event.payload_json = serde_json::to_string(&tampered_payload).unwrap();
        tampered_record.payload_json = serde_json::to_string(&tampered_event).unwrap();
        assert!(project_terminal_outcome(&tampered_record, 4_000).is_err());

        let generic_event = ProviderEvent {
            id: "generic-outcome-destination-event".into(),
            binding: event.binding.clone(),
            payload_json: "{}".into(),
            collected_at_ms: None,
            source_sequence: None,
        };
        let generic_record =
            provider_event_record(OUTCOME_PROVIDER_KIND, &generic_event, 1_000).unwrap();
        assert!(
            project_terminal_outcome(&generic_record, 4_000)
                .unwrap()
                .is_none()
        );

        let payload: TerminalOutcomePayload = serde_json::from_str(&event.payload_json).unwrap();
        let mut legacy_event = event.clone();
        legacy_event.id = legacy_terminal_outcome_event_id(&event.binding, &payload);
        let mut legacy_record = record.clone();
        legacy_record.id = legacy_event.id.clone();
        legacy_record.payload_json = serde_json::to_string(&legacy_event).unwrap();
        assert!(
            project_terminal_outcome(&legacy_record, 4_000)
                .unwrap()
                .is_none()
        );

        record.attempts = 1;
        record.claim_token = Some("private-claim".into());
        record.claim_until = Some(5_000);
        let in_flight = project_terminal_outcome(&record, 4_000).unwrap().unwrap();
        assert_eq!(in_flight.delivery_state, "in_flight");
        assert_eq!(in_flight.claim_until, Some(5_000));

        let expired_claim = project_terminal_outcome(&record, 5_000).unwrap().unwrap();
        assert_eq!(expired_claim.delivery_state, "retrying");

        record.claim_token = None;
        record.claim_until = None;
        record.delivered_at = Some(4_500);
        let delivered = project_terminal_outcome(&record, 5_000).unwrap().unwrap();
        assert_eq!(delivered.delivery_state, "delivered");
        assert_eq!(delivered.delivery_lag_ms, 3_500);
        assert_eq!(delivered.delivered_at, Some(4_500));
    }

    #[tokio::test]
    async fn terminal_outcome_is_bounded_content_bound_and_sekai_evidence_mapped() {
        let event = terminal_event();
        let repeated_transition = terminal_event();
        let later_transition = terminal_outcome_event(
            "tenkai:deployment:prod:api:1",
            "tenkai:plan:prod:1",
            "sha256:plan",
            "tenkai:release:api@2.0.0",
            "sha256:release",
            "api",
            "prod",
            "tenkai:environment:prod",
            "sha256:config",
            TerminalOutcomeState::AutomaticRollbackSucceeded,
            2_000,
        )
        .unwrap();
        assert_eq!(event, repeated_transition);
        assert_ne!(event.id, later_transition.id);
        let payload: TerminalOutcomePayload = serde_json::from_str(&event.payload_json).unwrap();
        assert_eq!(
            payload.terminal_state,
            TerminalOutcomeState::AutomaticRollbackSucceeded
        );
        assert_eq!(event.binding.environment_id, payload.environment_id);

        let provider = ChiseiOutcomeProvider::new(
            "http://127.0.0.1:50051",
            "tenkai-prod",
            "tenkai.outcome",
            Some("secret-token".into()),
        )
        .unwrap();
        let mut collected_event = event.clone();
        collected_event.collected_at_ms = Some(1_000);
        collected_event.source_sequence = Some(1);
        let evidence = provider.evidence(&collected_event).unwrap();
        assert_eq!(evidence, provider.evidence(&collected_event).unwrap());
        assert_eq!(evidence.source_record_id, event.id);
        assert_eq!(evidence.namespace, "tenkai-prod");
        assert_eq!(evidence.target_external_id, "tenkai:deployment:prod:api:1");
        assert_eq!(evidence.schema_id, TERMINAL_OUTCOME_SCHEMA);
        assert_eq!(evidence.collected_at_ms, 1_000);
        assert_eq!(evidence.source_sequence, 1);
        let canonical_content = serde_json::to_vec(
            &serde_json::from_str::<serde_json::Value>(&event.payload_json).unwrap(),
        )
        .unwrap();
        assert_eq!(evidence.content_json, canonical_content);
        assert_eq!(evidence.idempotency_key, event.id);
        assert_eq!(evidence.confidence_bps, 10_000);
        assert_eq!(evidence.intent, "upsert");
        assert!(!format!("{provider:?}").contains("secret-token"));
        assert!(provider.record(&event).await.is_err());

        let registration =
            outcome_provider_registration_attestation("tenkai.outcome", "tenkai-prod");
        let export_provider = ChiseiOutcomeProvider::new_for_export(
            "http://127.0.0.1:50051",
            "tenkai-prod",
            "tenkai.outcome",
            Some("secret-token".into()),
            registration,
        )
        .unwrap();
        assert!(export_provider.registration_attested);
        assert!(
            ChiseiOutcomeProvider::new_for_export(
                "http://127.0.0.1:50051",
                "tenkai-prod",
                "tenkai.outcome",
                None,
                "producer=tenkai.outcome;schema=wrong",
            )
            .is_err()
        );

        assert!(
            ChiseiOutcomeProvider::new(
                "http://provider.example.test:50051",
                "tenkai-prod",
                "tenkai.outcome",
                Some("secret-token".into()),
            )
            .is_err()
        );
        assert!(
            ChiseiOutcomeProvider::new(
                "http://provider.example.test:50051",
                "tenkai-prod",
                "tenkai.outcome",
                None,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn outcome_worker_claims_only_outcomes_and_acknowledges_idempotently() {
        let store = SqliteStore::open_in_memory().unwrap();
        let event = terminal_event();
        enqueue_optional_event(&store, "audit", &event, 100).unwrap();
        enqueue_optional_event(&store, OUTCOME_PROVIDER_KIND, &event, 100).unwrap();
        let sink = LocalEventSink::default();

        let (delivered, deferred) =
            deliver_outcome_batch(&store, &sink, Duration::from_secs(1), 100, 10)
                .await
                .unwrap();
        assert_eq!((delivered, deferred), (1, 0));
        let mut collected_event = event.clone();
        collected_event.collected_at_ms = Some(100);
        collected_event.source_sequence = Some(1);
        assert_eq!(sink.received(), vec![collected_event]);
        assert!(
            store
                .claim_provider_events_for_kind(
                    OUTCOME_PROVIDER_KIND,
                    101,
                    10,
                    "outcome-retry",
                    1_101,
                )
                .unwrap()
                .is_empty()
        );
        let audit = store
            .claim_provider_events_for_kind("audit", 101, 10, "audit-worker", 1_101)
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].id, event.id);
    }

    #[tokio::test]
    async fn outcome_sequences_are_durable_and_monotonic_across_events() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = terminal_event();
        let second = terminal_outcome_event(
            "tenkai:deployment:prod:web:2",
            "tenkai:plan:prod:2",
            "sha256:plan-2",
            "tenkai:release:web@2.0.0",
            "sha256:release-2",
            "web",
            "prod",
            "tenkai:environment:prod",
            "sha256:config-2",
            TerminalOutcomeState::DeploymentSucceeded,
            1_001,
        )
        .unwrap();
        enqueue_optional_event(&store, OUTCOME_PROVIDER_KIND, &first, 100).unwrap();
        enqueue_optional_event(&store, OUTCOME_PROVIDER_KIND, &second, 100).unwrap();
        let claimed = store
            .claim_provider_events_for_kind(
                OUTCOME_PROVIDER_KIND,
                100,
                10,
                "sequence-worker",
                1_100,
            )
            .unwrap();
        assert_eq!(claimed.len(), 2);
        let sink = std::sync::Arc::new(LocalEventSink::default());
        for record in &claimed {
            let delivery_sink = std::sync::Arc::clone(&sink);
            deliver_optional_event(
                &store,
                record,
                Duration::from_secs(1),
                100,
                move |event, kind| async move {
                    assert_eq!(kind, OUTCOME_PROVIDER_KIND);
                    delivery_sink.export(&event).await
                },
            )
            .await
            .unwrap();
        }
        let mut sequences = sink
            .received()
            .into_iter()
            .map(|event| event.source_sequence.unwrap())
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert_eq!(sequences, vec![1, 2]);

        let durable = store
            .list_provider_events(OUTCOME_PROVIDER_KIND, "prod", 128)
            .unwrap();
        assert_eq!(durable.len(), 2);
        for record in durable {
            let event: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
            assert!(event.collected_at_ms.is_some());
            assert!(event.source_sequence.is_some());
        }
    }

    #[tokio::test]
    async fn local_providers_support_bound_standalone_decisions() {
        let request = request();
        let gate = LocalGateProvider {
            passing_evidence_id: Some("eval-1".into()),
        };
        let decision = required_decision(&request, Duration::from_secs(1), gate.evaluate(&request))
            .await
            .unwrap();
        assert_eq!(decision.binding_digest, request.binding.digest());

        let policy = LocalPolicyProvider {
            allowed_actions: ["deploy".into()].into_iter().collect(),
        };
        assert!(policy.authorize(&request).await.unwrap().allowed);
    }

    #[tokio::test]
    async fn remote_gate_provider_accepts_valid_http_decision() {
        use axum::{Json, Router, routing::post};
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/gate/decide",
            post(|Json(req): Json<DecisionRequest>| async move {
                let binding_digest = req.binding.digest();
                Json(ProviderDecision {
                    allowed: true,
                    reason: "suite passed".into(),
                    evidence_id: format!("remote-eval:{}", req.request_id),
                    binding_digest,
                    request_id: req.request_id,
                    action: req.action,
                    principal: req.principal,
                })
            }),
        );
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let endpoint = format!("http://{addr}/v1/gate/decide");
        let gate = HttpRemoteGateProvider::new(endpoint, Duration::from_secs(2), None).unwrap();
        let request = request();
        let decision = required_decision(&request, Duration::from_secs(3), gate.evaluate(&request))
            .await
            .unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.binding_digest, request.binding.digest());
        assert!(decision.evidence_id.starts_with("remote-eval:"));
        assert!(!format!("{decision:?}").contains("Bearer"));
    }

    #[tokio::test]
    async fn remote_gate_provider_fails_closed_on_5xx_and_invalid_binding() {
        use axum::{Json, Router, http::StatusCode, routing::post};
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/fail",
                post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/bad-binding",
                post(|Json(req): Json<DecisionRequest>| async move {
                    Json(ProviderDecision {
                        allowed: true,
                        reason: "forged".into(),
                        evidence_id: "e".into(),
                        binding_digest: "sha256:not-the-binding".into(),
                        request_id: req.request_id,
                        action: req.action,
                        principal: req.principal,
                    })
                }),
            );
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let request = request();
        let fail = HttpRemoteGateProvider::new(
            format!("http://{addr}/fail"),
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        let err = required_decision(&request, Duration::from_secs(3), fail.evaluate(&request))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unavailable") || err.contains("HTTP 500"),
            "{err}"
        );

        let forged = HttpRemoteGateProvider::new(
            format!("http://{addr}/bad-binding"),
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        let forged_err =
            required_decision(&request, Duration::from_secs(3), forged.evaluate(&request))
                .await
                .unwrap_err();
        assert!(
            matches!(forged_err, ProviderError::InvalidEvidence(_)),
            "{forged_err}"
        );
    }

    #[tokio::test]
    async fn remote_gate_provider_times_out() {
        use axum::{Router, routing::post};
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/slow",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "ok"
            }),
        );
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let request = request();
        let gate = HttpRemoteGateProvider::new(
            format!("http://{addr}/slow"),
            Duration::from_millis(50),
            None,
        )
        .unwrap();
        let err = required_decision(
            &request,
            Duration::from_millis(200),
            gate.evaluate(&request),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ProviderError::Timeout(_)) || err.to_string().contains("timed out"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn required_decisions_fail_closed_with_actionable_errors() {
        let request = request();
        let policy = LocalPolicyProvider::default();
        let error = required_decision(&request, Duration::from_secs(1), policy.authorize(&request))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("required provider blocked deploy")
        );

        let mut wrong = request.binding.clone();
        wrong.environment_id = "other".into();
        let forged = async {
            Ok(ProviderDecision {
                allowed: true,
                reason: "ok".into(),
                evidence_id: "evidence".into(),
                binding_digest: wrong.digest(),
                request_id: request.request_id.clone(),
                action: request.action.clone(),
                principal: request.principal.clone(),
            })
        };
        assert!(matches!(
            required_decision(&request, Duration::from_secs(1), forged).await,
            Err(ProviderError::InvalidEvidence(_))
        ));
    }

    #[tokio::test]
    async fn optional_failures_remain_durable_and_retry_idempotently() {
        let store = SqliteStore::open_in_memory().unwrap();
        let event = ProviderEvent {
            id: "audit-1".into(),
            binding: binding(),
            payload_json: "{\"result\":\"ok\"}".into(),
            collected_at_ms: None,
            source_sequence: None,
        };
        enqueue_optional_event(&store, "audit", &event, 100).unwrap();
        enqueue_optional_event(&store, "audit", &event, 100).unwrap();
        let pending = store
            .claim_provider_events(100, 10, "worker-1", 10_100)
            .unwrap();
        assert_eq!(pending.len(), 1);
        deliver_optional_event(
            &store,
            &pending[0],
            Duration::from_secs(1),
            100,
            |_, _| async { Err(ProviderError::Unavailable("offline".into())) },
        )
        .await
        .unwrap();
        assert!(
            store
                .claim_provider_events(100, 10, "worker-2", 10_100)
                .unwrap()
                .is_empty()
        );
        let retry = store
            .claim_provider_events(1_100, 10, "worker-2", 11_100)
            .unwrap();
        assert_eq!(retry[0].attempts, 1);

        let sink = std::sync::Arc::new(LocalEventSink::default());
        let delivery_sink = std::sync::Arc::clone(&sink);
        deliver_optional_event(
            &store,
            &retry[0],
            Duration::from_secs(1),
            1_100,
            |delivered, kind| async move {
                assert_eq!(kind, "audit");
                delivery_sink.export(&delivered).await
            },
        )
        .await
        .unwrap();
        assert!(
            store
                .claim_provider_events(i64::MAX - 1, 10, "worker-3", i64::MAX)
                .unwrap()
                .is_empty()
        );
        let mut collected_event = event;
        collected_event.collected_at_ms = Some(100);
        collected_event.source_sequence = Some(1);
        assert_eq!(sink.received(), vec![collected_event]);
    }

    #[tokio::test]
    async fn destinations_claims_and_poison_events_are_isolated() {
        let store = SqliteStore::open_in_memory().unwrap();
        let event = ProviderEvent {
            id: "shared-1".into(),
            binding: binding(),
            payload_json: "{}".into(),
            collected_at_ms: None,
            source_sequence: None,
        };
        enqueue_optional_event(&store, "audit", &event, 10).unwrap();
        enqueue_optional_event(&store, "outcome", &event, 10).unwrap();
        let first = store
            .claim_provider_events(10, 1, "worker-a", 1_010)
            .unwrap();
        assert_eq!(first.len(), 1);
        assert!(matches!(
            store.claim_provider_events(10, 1, "worker-a", 1_010),
            Err(StoreError::InvalidData { .. })
        ));
        let second = store
            .claim_provider_events(10, 10, "worker-b", 1_010)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_ne!(first[0].provider_kind, second[0].provider_kind);

        store
            .enqueue_provider_event(&ProviderEventRecord {
                id: "poison-1".into(),
                provider_kind: "audit".into(),
                binding_digest: binding().digest(),
                payload_json: "not-json".into(),
                attempts: 0,
                next_attempt_at: 20,
                delivered_at: None,
                last_error: String::new(),
                claim_token: None,
                claim_until: None,
            })
            .unwrap();
        let poison = store
            .claim_provider_events(20, 1, "worker-c", 1_020)
            .unwrap();
        deliver_optional_event(
            &store,
            &poison[0],
            Duration::from_secs(1),
            20,
            |_, _| async { panic!("invalid event must not reach adapter") },
        )
        .await
        .unwrap();
        assert!(
            store
                .claim_provider_events(20, 10, "worker-d", 1_020)
                .unwrap()
                .is_empty()
        );
        let retried = store
            .claim_provider_events(60_020, 10, "worker-d", 61_020)
            .unwrap();
        let poison = retried
            .iter()
            .find(|record| record.id == "poison-1")
            .unwrap();
        assert_eq!(poison.attempts, 1);
        assert!(poison.last_error.contains("serialization"));

        let mut invalid_new = poison.clone();
        invalid_new.id = "pre-delivered".into();
        invalid_new.provider_kind = "outcome".into();
        invalid_new.delivered_at = Some(60_020);
        invalid_new.claim_token = None;
        invalid_new.claim_until = None;
        assert!(matches!(
            store.enqueue_provider_event(&invalid_new),
            Err(StoreError::InvalidData { .. })
        ));
    }
}

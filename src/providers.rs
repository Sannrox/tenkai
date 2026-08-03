//! Optional governance and intelligence provider contracts.
//!
//! Providers return or consume evidence; they never own releases, plans,
//! execution state, leases, receipts, or rollback recovery.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

use crate::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::pb::chisei::{RecordSampleObservationRequest, SampleObservation};
use crate::pb::sekai::Object;
use crate::storage::{OperationalStore, ProviderEventRecord, StoreError};

pub const PROVIDER_CONTRACT_VERSION: u32 = 1;
pub const TERMINAL_OUTCOME_SCHEMA: &str = "tenkai.terminal_outcome.v1";
pub const OUTCOME_PROVIDER_KIND: &str = "outcome";
const MAX_PROVIDER_EVENT_ID_BYTES: usize = 512;
const MAX_PROVIDER_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;

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

/// Reference adapter for Chisei's authenticated, namespace-scoped
/// `RecordSampleObservation` admission path.
#[derive(Clone)]
pub struct ChiseiOutcomeProvider {
    namespace: String,
    principal: String,
    bearer_token: Option<String>,
    client: ChiseiServiceClient<Channel>,
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

impl ChiseiOutcomeProvider {
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
            client: ChiseiServiceClient::new(channel),
        })
    }

    fn observation(&self, event: &ProviderEvent) -> Result<SampleObservation, ProviderError> {
        event.validate()?;
        let payload: TerminalOutcomePayload = serde_json::from_str(&event.payload_json)?;
        payload.validate_for_event(event)?;
        Ok(SampleObservation {
            request_id: event.id.clone(),
            namespace: self.namespace.clone(),
            spec: TERMINAL_OUTCOME_SCHEMA.into(),
            resolved_model: String::new(),
            output_content: event.payload_json.clone(),
            sample_reason: payload.terminal_state.as_str().into(),
            input_tokens: 0,
            output_tokens: 0,
            stop_reason: "terminal".into(),
            timestamp: payload.observed_at,
        })
    }
}

impl OutcomeProvider for ChiseiOutcomeProvider {
    async fn record(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        let observation = self.observation(event)?;
        let mut request = tonic::Request::new(RecordSampleObservationRequest {
            observation: Some(observation),
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
        let recorded = client
            .record_sample_observation(request)
            .await
            .map_err(|status| {
                ProviderError::Unavailable(format!(
                    "Chisei outcome admission returned gRPC {}",
                    status.code()
                ))
            })?
            .into_inner()
            .recorded;
        if !recorded {
            return Err(ProviderError::Unavailable(
                "Chisei outcome admission is not enabled".into(),
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

pub fn enqueue_optional_event(
    store: &impl OperationalStore,
    kind: &str,
    event: &ProviderEvent,
    now: i64,
) -> Result<(), ProviderError> {
    store.enqueue_provider_event(&provider_event_record(kind, event, now)?)?;
    Ok(())
}

pub fn provider_event_record(
    kind: &str,
    event: &ProviderEvent,
    now: i64,
) -> Result<ProviderEventRecord, ProviderError> {
    event.validate()?;
    if kind.trim().is_empty() || kind.len() > 64 {
        return Err(ProviderError::InvalidEvidence(
            "provider event kind is empty or oversized".into(),
        ));
    }
    Ok(ProviderEventRecord {
        id: event.id.clone(),
        provider_kind: kind.into(),
        binding_digest: event.binding.digest(),
        payload_json: serde_json::to_string(event)?,
        attempts: 0,
        next_attempt_at: now,
        delivered_at: None,
        last_error: String::new(),
        claim_token: None,
        claim_until: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Delivered,
    Deferred,
}

/// Retry one durable optional event. The event is acknowledged only after the
/// adapter succeeds. Backoff is bounded and the stable event ID is the
/// provider's idempotency key.
pub async fn deliver_optional_event<S, F, Fut>(
    store: &S,
    record: &ProviderEventRecord,
    timeout: Duration,
    now: i64,
    delivery: F,
) -> Result<DeliveryStatus, ProviderError>
where
    S: OperationalStore + ?Sized,
    F: FnOnce(ProviderEvent, String) -> Fut,
    Fut: Future<Output = Result<(), ProviderError>>,
{
    let claim_token = record.claim_token.as_deref().ok_or_else(|| {
        ProviderError::InvalidEvidence("durable event is not claimed for delivery".into())
    })?;
    let parsed = serde_json::from_str::<ProviderEvent>(&record.payload_json)
        .map_err(ProviderError::from)
        .and_then(|event| {
            event.validate()?;
            if event.binding.digest() != record.binding_digest || event.id != record.id {
                return Err(ProviderError::InvalidEvidence(
                    "durable event binding or identity does not match its envelope".into(),
                ));
            }
            Ok(event)
        });
    let event = match parsed {
        Ok(event) => event,
        Err(error) => {
            store.record_provider_failure(
                &record.provider_kind,
                &record.id,
                claim_token,
                now + 60_000,
                &error.to_string(),
            )?;
            return Ok(DeliveryStatus::Deferred);
        }
    };
    let result = tokio::time::timeout(timeout, delivery(event, record.provider_kind.clone())).await;
    let delivered = matches!(&result, Ok(Ok(())));
    match result {
        Ok(Ok(())) => store.mark_provider_event_delivered(
            &record.provider_kind,
            &record.id,
            claim_token,
            now,
        )?,
        Ok(Err(error)) => {
            let delay_seconds = 1_i64 << record.attempts.min(10);
            store.record_provider_failure(
                &record.provider_kind,
                &record.id,
                claim_token,
                now + delay_seconds * 1_000,
                &error.to_string(),
            )?;
        }
        Err(_) => {
            let delay_seconds = 1_i64 << record.attempts.min(10);
            store.record_provider_failure(
                &record.provider_kind,
                &record.id,
                claim_token,
                now + delay_seconds * 1_000,
                &ProviderError::Timeout(timeout).to_string(),
            )?;
        }
    }
    Ok(if delivered {
        DeliveryStatus::Delivered
    } else {
        DeliveryStatus::Deferred
    })
}

pub async fn deliver_outcome_batch<S, P>(
    store: &S,
    provider: &P,
    timeout: Duration,
    now: i64,
    limit: usize,
) -> Result<(usize, usize), ProviderError>
where
    S: OperationalStore + ?Sized,
    P: OutcomeProvider + ?Sized,
{
    let claim_token = format!("outcome-worker:{}", uuid::Uuid::new_v4());
    let claim_until = now.saturating_add(
        i64::try_from(timeout.saturating_mul(limit.max(1) as u32).as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(30_000),
    );
    let records = store.claim_provider_events_for_kind(
        OUTCOME_PROVIDER_KIND,
        now,
        limit,
        &claim_token,
        claim_until,
    )?;
    let mut delivered = 0;
    let mut deferred = 0;
    for record in &records {
        match deliver_optional_event(store, record, timeout, now, |event, kind| async move {
            if kind != OUTCOME_PROVIDER_KIND {
                return Err(ProviderError::InvalidEvidence(
                    "outcome worker claimed a different provider destination".into(),
                ));
            }
            provider.record(&event).await
        })
        .await?
        {
            DeliveryStatus::Delivered => delivered += 1,
            DeliveryStatus::Deferred => deferred += 1,
        }
    }
    Ok((delivered, deferred))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;

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
    async fn terminal_outcome_is_bounded_content_bound_and_chisei_mapped() {
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
        let observation = provider.observation(&event).unwrap();
        assert_eq!(observation.request_id, event.id);
        assert_eq!(observation.namespace, "tenkai-prod");
        assert_eq!(observation.output_content, event.payload_json);
        assert_eq!(observation.sample_reason, "automatic_rollback_succeeded");
        assert!(!format!("{provider:?}").contains("secret-token"));

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
        assert_eq!(sink.received(), vec![event.clone()]);
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
        assert_eq!(sink.received(), vec![event]);
    }

    #[tokio::test]
    async fn destinations_claims_and_poison_events_are_isolated() {
        let store = SqliteStore::open_in_memory().unwrap();
        let event = ProviderEvent {
            id: "shared-1".into(),
            binding: binding(),
            payload_json: "{}".into(),
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

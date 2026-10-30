//! Opt-in delivery of captured feedback observations to Sekai (#783).
//!
//! Capture stays local and always-on. When this adapter is enabled, each
//! stored observation is also enqueued on the provider outbox and delivered
//! as `feedback.observation` evidence, then recorded with
//! `SubmitActionInstance` (`feedback.observation.record`). Delivery uses the
//! existing evidence and governed-action RPCs; it never opens a new core
//! contract. Disabled or unavailable export cannot interrupt deployment.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tonic::metadata::MetadataValue;

use crate::feedback_observation::{FEEDBACK_OBSERVATION_SCHEMA, FeedbackObservation, Reason};
use crate::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::pb::sekai::{EvidenceEnvelope, SubmitActionInstanceRequest, SubmitEvidenceRequest};
use crate::provider_event::{
    DeliveryStatus, ProviderEventStore, deliver_optional_event, provider_event_record,
};
use crate::providers::{
    EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderError, ProviderEvent,
    evidence_submission_succeeded, provider_transport_is_safe,
};
use crate::storage::ProviderEventRecord;

pub const FEEDBACK_PROVIDER_KIND: &str = "feedback";
pub const FEEDBACK_PROVIDER_REGISTRATION_ENV: &str = "TENKAI_FEEDBACK_PROVIDER_REGISTRATION";
pub const FEEDBACK_EVIDENCE_TYPE: &str = "feedback.observation";
pub const FEEDBACK_EVIDENCE_SCHEMA_VERSION: &str = "1.0.0";
pub const FEEDBACK_OBJECT_KIND: &str = "feedback_observation";
pub const FEEDBACK_ACTION_TYPE: &str = "feedback.observation.record";
pub const FEEDBACK_ACTION_VERSION: &str = "1";
pub const FEEDBACK_PACKAGE_ID: &str = "pkg:feedback.evidence-finding/v1";

const MAX_PROVIDER_EVENT_ID_BYTES: usize = 512;

/// Outbox envelope around one captured observation. `tenant_id` is delivery
/// metadata for tenant-mode identity; evidence content is only `observation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackExportPayload {
    pub observation: FeedbackObservation,
    pub observed_at: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
}

/// Action parameters required by `feedback.observation.record`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackActionParameters {
    pub object_id: String,
    pub source_evidence: String,
    pub problem_signature: String,
    pub occurrence_ids: String,
    pub classification: String,
    pub disposition: String,
}

pub trait FeedbackProvider: Send + Sync {
    fn deliver<'a>(
        &'a self,
        event: &'a ProviderEvent,
    ) -> impl Future<Output = Result<(), ProviderError>> + Send + 'a;
}

/// Exact, non-secret registration an operator must attest after registering
/// the producer, evidence schema, and observation Action in Sekai.
pub fn feedback_provider_registration_attestation(principal: &str, namespace: &str) -> String {
    format!(
        "producer={principal};source_type={FEEDBACK_PROVIDER_KIND};source_instance={namespace}:{FEEDBACK_PROVIDER_KIND};namespace={namespace};evidence_type={FEEDBACK_EVIDENCE_TYPE};schema={FEEDBACK_EVIDENCE_TYPE}@{FEEDBACK_EVIDENCE_SCHEMA_VERSION};target_kind={FEEDBACK_OBJECT_KIND};classification=internal;intent=upsert;action={FEEDBACK_ACTION_TYPE}"
    )
}

/// Build durable outbox records for captured observations. A record that
/// cannot be built is skipped so export never interrupts the operation.
pub fn records_for_observations(observations: &[FeedbackObservation]) -> Vec<ProviderEventRecord> {
    observations
        .iter()
        .filter_map(|observation| match record(observation) {
            Ok(record) => Some(record),
            Err(error) => {
                eprintln!(
                    "feedback observation {} was not exported: {error}",
                    observation.id
                );
                None
            }
        })
        .collect()
}

pub fn record(observation: &FeedbackObservation) -> Result<ProviderEventRecord, ProviderError> {
    event_record(observation, "")
}

fn event_record(
    observation: &FeedbackObservation,
    tenant_id: &str,
) -> Result<ProviderEventRecord, ProviderError> {
    let event = export_event(observation, tenant_id)?;
    provider_event_record(
        FEEDBACK_PROVIDER_KIND,
        &event,
        observation.observed_at_ms.max(1),
    )
}

fn export_event(
    observation: &FeedbackObservation,
    tenant_id: &str,
) -> Result<ProviderEvent, ProviderError> {
    if observation.schema != FEEDBACK_OBSERVATION_SCHEMA {
        return Err(ProviderError::InvalidEvidence(
            "feedback export requires tenkai.feedback_observation.v1".into(),
        ));
    }
    let payload = FeedbackExportPayload {
        observation: observation.clone(),
        observed_at: observation.observed_at_ms,
        tenant_id: tenant_id.to_owned(),
    };
    let binding = binding_for(observation)?;
    let event = ProviderEvent {
        id: feedback_event_id(&binding, &payload)?,
        binding,
        payload_json: serde_json::to_string(&payload)?,
        collected_at_ms: None,
        source_sequence: None,
    };
    event.validate()?;
    Ok(event)
}

fn binding_for(observation: &FeedbackObservation) -> Result<EvidenceBinding, ProviderError> {
    let environment_id = if observation.environment.trim().is_empty() {
        observation.id.clone()
    } else {
        observation.environment.clone()
    };
    let release_digest = if observation.release_id.trim().is_empty() {
        format!("observation:{}", observation.id)
    } else {
        observation.release_id.clone()
    };
    let plan_digest = if observation.plan_id.trim().is_empty() {
        format!("observation:{}", observation.id)
    } else {
        observation.plan_id.clone()
    };
    let configuration_digest = if observation.controller_version.trim().is_empty() {
        format!("observation:{}", observation.id)
    } else {
        format!("tenkai:{}", observation.controller_version)
    };
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest,
        plan_digest,
        configuration_digest,
        environment_id,
    };
    binding.validate()?;
    Ok(binding)
}

fn feedback_event_id(
    binding: &EvidenceBinding,
    payload: &FeedbackExportPayload,
) -> Result<String, ProviderError> {
    let payload_json = serde_json::to_string(payload)?;
    let binding_digest = binding.digest();
    let mut identity = Sha256::new();
    for value in [&binding_digest, &payload_json] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    Ok(format!("tenkai:feedback:v1:{:x}", identity.finalize()))
}

pub fn parse_payload(event: &ProviderEvent) -> Result<FeedbackExportPayload, ProviderError> {
    event.validate()?;
    let payload: FeedbackExportPayload = serde_json::from_str(&event.payload_json)?;
    if payload.observation.schema != FEEDBACK_OBSERVATION_SCHEMA {
        return Err(ProviderError::InvalidEvidence(
            "feedback export payload is not a captured observation".into(),
        ));
    }
    if payload.tenant_id.len() > MAX_PROVIDER_EVENT_ID_BYTES {
        return Err(ProviderError::InvalidEvidence(
            "feedback export tenant identity exceeds the bounded contract".into(),
        ));
    }
    let expected = feedback_event_id(&event.binding, &payload)?;
    if event.id != expected {
        return Err(ProviderError::InvalidEvidence(
            "feedback export event identity does not bind its payload".into(),
        ));
    }
    Ok(payload)
}

/// Bind `tenant` into feedback records so two tenants cannot share a
/// producer identity. Other outbox kinds are left unchanged.
pub fn bind_tenant_to_feedback_event(
    record: &ProviderEventRecord,
    tenant: &str,
) -> Result<ProviderEventRecord, ProviderError> {
    if record.provider_kind != FEEDBACK_PROVIDER_KIND {
        return Ok(record.clone());
    }
    let Ok(mut event) = serde_json::from_str::<ProviderEvent>(&record.payload_json) else {
        return Ok(record.clone());
    };
    if event.validate().is_err() {
        return Ok(record.clone());
    }
    let Ok(mut payload) = serde_json::from_str::<FeedbackExportPayload>(&event.payload_json) else {
        return Ok(record.clone());
    };
    if payload.tenant_id.is_empty() {
        payload.tenant_id = tenant.to_owned();
    } else if payload.tenant_id != tenant {
        return Err(ProviderError::InvalidEvidence(
            "feedback export tenant does not match the catalog tenant".into(),
        ));
    }
    event.payload_json = serde_json::to_string(&payload)?;
    event.id = feedback_event_id(&event.binding, &payload)?;
    event.validate()?;
    Ok(ProviderEventRecord {
        id: event.id.clone(),
        provider_kind: record.provider_kind.clone(),
        binding_digest: record.binding_digest.clone(),
        payload_json: serde_json::to_string(&event)?,
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        delivered_at: record.delivered_at,
        last_error: record.last_error.clone(),
        claim_token: record.claim_token.clone(),
        claim_until: record.claim_until,
    })
}

pub fn action_parameters(
    observation: &FeedbackObservation,
    source_evidence: &str,
) -> FeedbackActionParameters {
    FeedbackActionParameters {
        object_id: observation.id.clone(),
        source_evidence: source_evidence.into(),
        problem_signature: problem_signature(observation),
        occurrence_ids: observation.id.clone(),
        classification: classification(observation.reason).into(),
        disposition: disposition(observation.reason).into(),
    }
}

fn problem_signature(observation: &FeedbackObservation) -> String {
    let reason = snake_case(observation.reason);
    if observation.product.is_empty() {
        format!("{}:{reason}", snake_case(observation.operation))
    } else {
        format!("{}:{reason}", observation.product)
    }
}

fn classification(reason: Reason) -> &'static str {
    match reason {
        Reason::None => "ok",
        Reason::Reconciled => "reconciled",
        Reason::Blocked | Reason::MaintenanceBlocked | Reason::GateBlocked => "blocked",
        Reason::Cancelled => "cancelled",
        Reason::Degraded => "degraded",
        Reason::ProductFailed
        | Reason::ProductFailedRestored
        | Reason::TenkaiFailed
        | Reason::TenkaiFailedRestored
        | Reason::StateUnknown
        | Reason::PlanFailed
        | Reason::Abandoned => "defect",
    }
}

fn disposition(reason: Reason) -> &'static str {
    match reason {
        Reason::None | Reason::Reconciled => "closed",
        _ => "open",
    }
}

fn snake_case<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub async fn deliver_feedback_batch<S, P>(
    store: &S,
    provider: &P,
    timeout: Duration,
    now: i64,
    limit: usize,
) -> Result<(usize, usize), ProviderError>
where
    S: ProviderEventStore + ?Sized,
    P: FeedbackProvider + ?Sized,
{
    let claim_token = format!("feedback-worker:{}", uuid::Uuid::new_v4());
    let claim_until = now.saturating_add(
        i64::try_from(timeout.saturating_mul(limit.max(1) as u32).as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(30_000),
    );
    let records = store.claim_provider_events_for_kind(
        FEEDBACK_PROVIDER_KIND,
        now,
        limit,
        &claim_token,
        claim_until,
    )?;
    let mut delivered = 0;
    let mut deferred = 0;
    for record in &records {
        match deliver_optional_event(store, record, timeout, now, |event, kind| async move {
            if kind != FEEDBACK_PROVIDER_KIND {
                return Err(ProviderError::InvalidEvidence(
                    "feedback worker claimed a different provider destination".into(),
                ));
            }
            provider.deliver(&event).await
        })
        .await?
        {
            DeliveryStatus::Delivered => delivered += 1,
            DeliveryStatus::Deferred => deferred += 1,
        }
    }
    Ok((delivered, deferred))
}

/// Reference adapter: authenticated `SubmitEvidence` then
/// `SubmitActionInstance` for the evidence-and-finding package.
#[derive(Clone)]
pub struct ChiseiFeedbackProvider {
    namespace: String,
    principal: String,
    bearer_token: Option<String>,
    registration_attested: bool,
    client: SekaiServiceClient<tonic::transport::Channel>,
}

impl std::fmt::Debug for ChiseiFeedbackProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChiseiFeedbackProvider")
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

impl ChiseiFeedbackProvider {
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
                "feedback namespace and principal must be non-empty and bounded".into(),
            ));
        }
        if bearer_token.as_ref().is_some_and(|token| token.is_empty()) {
            return Err(ProviderError::InvalidEvidence(
                "feedback bearer token must not be empty when configured".into(),
            ));
        }
        if !provider_transport_is_safe(&endpoint) {
            return Err(ProviderError::InvalidEvidence(
                "feedback provider endpoints require HTTPS or loopback HTTP".into(),
            ));
        }
        let secure = crate::outbound_tls::is_tls_url(&endpoint);
        let mut channel = tonic::transport::Endpoint::from_shared(endpoint).map_err(|_| {
            ProviderError::InvalidEvidence(
                "feedback provider endpoint is not a valid absolute URL".into(),
            )
        })?;
        if secure {
            let trust = crate::outbound_tls::OutboundTrust::from_env().map_err(|error| {
                ProviderError::Unavailable(format!("feedback provider TLS: {error:#}"))
            })?;
            channel = channel.tls_config(trust.tonic()).map_err(|error| {
                ProviderError::Unavailable(format!("feedback provider TLS: {error}"))
            })?;
        }
        Ok(Self {
            namespace,
            principal,
            bearer_token,
            registration_attested: false,
            client: SekaiServiceClient::new(channel.connect_lazy()),
        })
    }

    pub fn new_for_export(
        endpoint: impl Into<String>,
        namespace: impl Into<String>,
        principal: impl Into<String>,
        bearer_token: Option<String>,
        registration_attestation: impl AsRef<str>,
    ) -> Result<Self, ProviderError> {
        let provider = Self::new(endpoint, namespace, principal, bearer_token)?;
        let expected =
            feedback_provider_registration_attestation(&provider.principal, &provider.namespace);
        if registration_attestation.as_ref() != expected {
            return Err(ProviderError::InvalidEvidence(format!(
                "{FEEDBACK_PROVIDER_REGISTRATION_ENV} must exactly confirm the configured Sekai producer, schema, and observation Action registration"
            )));
        }
        Ok(Self {
            registration_attested: true,
            ..provider
        })
    }

    pub(crate) fn evidence(
        &self,
        event: &ProviderEvent,
    ) -> Result<(EvidenceEnvelope, FeedbackActionParameters), ProviderError> {
        let payload = parse_payload(event)?;
        let content_value = serde_json::to_value(&payload.observation)?;
        let content_json = serde_json::to_vec(&content_value)?;
        let content_digest = format!("{:x}", Sha256::digest(&content_json));
        let target_external_id = if payload.tenant_id.is_empty() {
            payload.observation.id.clone()
        } else {
            format!("{}:{}", payload.tenant_id, payload.observation.id)
        };
        let mut provenance = HashMap::from([
            (
                "environment".into(),
                payload.observation.environment.clone(),
            ),
            ("product".into(), payload.observation.product.clone()),
            ("plan_id".into(), payload.observation.plan_id.clone()),
            (
                "operation".into(),
                snake_case(payload.observation.operation),
            ),
            ("reason".into(), snake_case(payload.observation.reason)),
            (
                "lease_generation".into(),
                payload.observation.lease_generation.to_string(),
            ),
            (
                "controller_version".into(),
                payload.observation.controller_version.clone(),
            ),
            ("observation_id".into(), payload.observation.id.clone()),
            ("package_id".into(), FEEDBACK_PACKAGE_ID.into()),
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
        ]);
        if !payload.tenant_id.is_empty() {
            provenance.insert("tenant_id".into(), payload.tenant_id.clone());
        }
        let envelope = EvidenceEnvelope {
            contract_version: "sekai.evidence/v1".into(),
            source_type: FEEDBACK_PROVIDER_KIND.into(),
            source_instance: format!("{}:{FEEDBACK_PROVIDER_KIND}", self.namespace),
            source_record_id: event.id.clone(),
            source_version: PROVIDER_CONTRACT_VERSION.to_string(),
            source_sequence: event.source_sequence.ok_or_else(|| {
                ProviderError::InvalidEvidence(
                    "feedback delivery is missing its durable source sequence".into(),
                )
            })?,
            namespace: self.namespace.clone(),
            target_external_id,
            target_kind: FEEDBACK_OBJECT_KIND.into(),
            evidence_type: FEEDBACK_EVIDENCE_TYPE.into(),
            signal: "other".into(),
            schema_id: FEEDBACK_EVIDENCE_TYPE.into(),
            schema_version: FEEDBACK_EVIDENCE_SCHEMA_VERSION.into(),
            schema_compatibility: "exact".into(),
            observed_at_ms: payload.observation.observed_at_ms,
            collected_at_ms: event.collected_at_ms.ok_or_else(|| {
                ProviderError::InvalidEvidence(
                    "feedback delivery is missing its durable collection timestamp".into(),
                )
            })?,
            expires_at_ms: None,
            content_json,
            relationships: Vec::new(),
            producer_identity: self.principal.clone(),
            confidence_bps: 10_000,
            classification: "internal".into(),
            provenance,
            idempotency_key: event.id.clone(),
            content_digest,
            intent: "upsert".into(),
            causality: None,
        };
        Ok((envelope, action_parameters(&payload.observation, "")))
    }

    fn authenticate<T>(
        &self,
        mut request: tonic::Request<T>,
    ) -> Result<tonic::Request<T>, ProviderError> {
        let principal = MetadataValue::try_from(self.principal.as_str()).map_err(|_| {
            ProviderError::InvalidEvidence("feedback principal is not valid metadata".into())
        })?;
        request.metadata_mut().insert("x-principal", principal);
        if let Some(token) = &self.bearer_token {
            let authorization =
                MetadataValue::try_from(format!("Bearer {token}")).map_err(|_| {
                    ProviderError::InvalidEvidence(
                        "feedback bearer token is not valid metadata".into(),
                    )
                })?;
            request
                .metadata_mut()
                .insert("authorization", authorization);
        }
        Ok(request)
    }
}

impl FeedbackProvider for ChiseiFeedbackProvider {
    async fn deliver(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        if !self.registration_attested {
            return Err(ProviderError::InvalidEvidence(
                "Sekai feedback export requires administrator-confirmed producer, schema, and Action registration".into(),
            ));
        }
        let (evidence, mut parameters) = self.evidence(event)?;
        let request = self.authenticate(tonic::Request::new(SubmitEvidenceRequest {
            envelope: Some(evidence),
        }))?;
        let mut client = self.client.clone();
        let result = client
            .submit_evidence(request)
            .await
            .map_err(|status| {
                ProviderError::Unavailable(format!(
                    "Sekai feedback evidence admission returned gRPC {}",
                    status.code()
                ))
            })?
            .into_inner()
            .result
            .ok_or_else(|| {
                ProviderError::Unavailable(
                    "Sekai feedback evidence admission returned no result".into(),
                )
            })?;
        if !evidence_submission_succeeded(&result) {
            return Err(ProviderError::Unavailable(
                "Sekai rejected feedback observation evidence".into(),
            ));
        }
        let submission_id = result
            .submission
            .as_ref()
            .map(|submission| submission.id.clone())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ProviderError::Unavailable(
                    "Sekai admitted feedback evidence without a submission id".into(),
                )
            })?;
        parameters.source_evidence = submission_id.clone();
        let parameters_json = serde_json::to_string(&parameters)?;
        let request = self.authenticate(tonic::Request::new(SubmitActionInstanceRequest {
            namespace: self.namespace.clone(),
            type_id: FEEDBACK_ACTION_TYPE.into(),
            version: FEEDBACK_ACTION_VERSION.into(),
            parameters_json,
            idempotency_key: event.id.clone(),
            evidence_submission_ids: vec![submission_id],
            request_id: uuid::Uuid::new_v4().to_string(),
        }))?;
        let response = match client.submit_action_instance(request).await {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::AlreadyExists => return Ok(()),
            Err(status) => {
                return Err(ProviderError::Unavailable(format!(
                    "Sekai feedback observation Action returned gRPC {}",
                    status.code()
                )));
            }
        };
        if response.replay {
            return Ok(());
        }
        let instance = response.instance.ok_or_else(|| {
            ProviderError::Unavailable("Sekai SubmitActionInstance returned no instance".into())
        })?;
        if instance.status == "admitted" || instance.policy_decision == "allow" {
            return Ok(());
        }
        Err(ProviderError::Unavailable(
            if instance.deny_reason.is_empty() {
                format!(
                    "Sekai feedback observation Action status {}",
                    instance.status
                )
            } else {
                instance.deny_reason
            },
        ))
    }
}

impl FeedbackProvider for crate::providers::LocalEventSink {
    async fn deliver(&self, event: &ProviderEvent) -> Result<(), ProviderError> {
        crate::providers::OutcomeProvider::record(self, event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback_observation::{Capture, Operation, RetryContext};
    use crate::plan::Action;
    use crate::providers::{LocalEventSink, enqueue_optional_event};
    use crate::storage::{OperationalStore, SqliteStore};

    fn observation(status: &str, reason: Reason) -> FeedbackObservation {
        FeedbackObservation::capture(Capture {
            id: "deployment:prod:api:2000",
            operation: Operation::ApplyStep,
            environment: "prod",
            product: "api",
            plan_id: "plan-1",
            step_id: "step-1",
            action: Some(Action::Upgrade),
            release_id: "release:api:1.1.0",
            status,
            reason,
            started_at_ms: Some(1_000),
            lease_generation: 3,
            observed_at_ms: 2_000,
            context: RetryContext::default(),
        })
    }

    #[test]
    fn export_payload_is_only_the_captured_observation() {
        let captured = observation("failed", Reason::ProductFailed);
        let record = record(&captured).unwrap();
        let event: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
        let payload = parse_payload(&event).unwrap();
        assert_eq!(payload.observation, captured);
        let encoded = serde_json::to_string(&payload.observation).unwrap();
        assert!(!encoded.contains("detail"), "{encoded}");
        assert!(!encoded.contains("secret"), "{encoded}");
        assert!(!encoded.contains("token"), "{encoded}");
        assert_eq!(record.provider_kind, FEEDBACK_PROVIDER_KIND);
        assert_eq!(event.binding.environment_id, "prod");
    }

    #[test]
    fn action_parameters_are_derived_from_captured_fields() {
        let captured = observation("failed", Reason::TenkaiFailed);
        let parameters = action_parameters(&captured, "evidence-1");
        assert_eq!(parameters.object_id, captured.id);
        assert_eq!(parameters.occurrence_ids, captured.id);
        assert_eq!(parameters.problem_signature, "api:tenkai_failed");
        assert_eq!(parameters.classification, "defect");
        assert_eq!(parameters.disposition, "open");
        assert_eq!(parameters.source_evidence, "evidence-1");

        let blocked = observation("blocked", Reason::GateBlocked);
        assert_eq!(action_parameters(&blocked, "e").classification, "blocked");
        let ok = observation("succeeded", Reason::None);
        assert_eq!(action_parameters(&ok, "e").disposition, "closed");
        assert_eq!(action_parameters(&ok, "e").classification, "ok");
    }

    #[test]
    fn identical_observations_share_an_outbox_identity() {
        let captured = observation("succeeded", Reason::None);
        let first = record(&captured).unwrap();
        let second = record(&captured).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.payload_json, second.payload_json);
    }

    #[test]
    fn tenant_binding_separates_identical_observations() {
        let captured = observation("succeeded", Reason::None);
        let record = record(&captured).unwrap();
        let tenant_a = bind_tenant_to_feedback_event(&record, "tenant-a").unwrap();
        let tenant_b = bind_tenant_to_feedback_event(&record, "tenant-b").unwrap();
        assert_ne!(tenant_a.id, tenant_b.id);
        assert_ne!(tenant_a.id, record.id);
        assert_eq!(
            bind_tenant_to_feedback_event(&tenant_a, "tenant-a")
                .unwrap()
                .id,
            tenant_a.id
        );
        assert!(bind_tenant_to_feedback_event(&tenant_a, "tenant-b").is_err());
        assert_eq!(
            crate::providers::bind_tenant_to_provider_events(
                Some("tenant-a"),
                std::slice::from_ref(&record)
            )
            .unwrap()[0]
                .id,
            tenant_a.id
        );
        let leftover = ProviderEventRecord {
            provider_kind: "deploy_webhook".into(),
            ..record.clone()
        };
        assert_eq!(
            bind_tenant_to_feedback_event(&leftover, "tenant-a")
                .unwrap()
                .id,
            leftover.id
        );
    }

    #[tokio::test]
    async fn evidence_envelope_carries_observation_fields_and_provenance() {
        let captured = observation("failed", Reason::ProductFailed);
        let mut event: ProviderEvent =
            serde_json::from_str(&record(&captured).unwrap().payload_json).unwrap();
        event.collected_at_ms = Some(2_100);
        event.source_sequence = Some(4);
        let provider = ChiseiFeedbackProvider::new(
            "http://127.0.0.1:50051",
            "delivery-learning",
            "tenkai.feedback",
            None,
        )
        .unwrap();
        let (envelope, parameters) = provider.evidence(&event).unwrap();
        assert_eq!(envelope.evidence_type, FEEDBACK_EVIDENCE_TYPE);
        assert_eq!(envelope.target_kind, FEEDBACK_OBJECT_KIND);
        assert_eq!(envelope.target_external_id, captured.id);
        assert_eq!(envelope.schema_id, FEEDBACK_EVIDENCE_TYPE);
        assert_eq!(envelope.idempotency_key, event.id);
        let content: FeedbackObservation = serde_json::from_slice(&envelope.content_json).unwrap();
        assert_eq!(content, captured);
        assert_eq!(
            envelope.provenance.get("package_id").map(String::as_str),
            Some(FEEDBACK_PACKAGE_ID)
        );
        assert_eq!(
            envelope.provenance.get("reason").map(String::as_str),
            Some("product_failed")
        );
        assert_eq!(parameters.object_id, captured.id);
        let content_json = String::from_utf8(envelope.content_json).unwrap();
        assert!(!content_json.contains("detail"), "{content_json}");
        assert!(!content_json.contains("tenant_id"), "{content_json}");
    }

    #[tokio::test]
    async fn registration_attestation_is_exact() {
        let expected =
            feedback_provider_registration_attestation("tenkai.feedback", "delivery-learning");
        ChiseiFeedbackProvider::new_for_export(
            "http://127.0.0.1:50051",
            "delivery-learning",
            "tenkai.feedback",
            None,
            &expected,
        )
        .unwrap();
        assert!(
            ChiseiFeedbackProvider::new_for_export(
                "http://127.0.0.1:50051",
                "delivery-learning",
                "tenkai.feedback",
                None,
                "wrong",
            )
            .is_err()
        );
        assert!(
            ChiseiFeedbackProvider::new("http://example.invalid/sekai", "ns", "p", None).is_err()
        );
    }

    #[tokio::test]
    async fn outbox_delivery_survives_restart_and_duplicate_ack_loss() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-feedback-export-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tenkai.db");
        let captured = observation("failed", Reason::ProductFailed);
        let event = {
            let store = SqliteStore::open(&path).unwrap();
            let record = record(&captured).unwrap();
            let parsed: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
            enqueue_optional_event(&store, FEEDBACK_PROVIDER_KIND, &parsed, 100).unwrap();
            enqueue_optional_event(&store, FEEDBACK_PROVIDER_KIND, &parsed, 100).unwrap();
            parsed
        };
        let store = SqliteStore::open(&path).unwrap();
        let pending =
            OperationalStore::list_provider_events(&store, FEEDBACK_PROVIDER_KIND, "prod", 8)
                .unwrap();
        assert_eq!(pending.len(), 1);
        let sink = LocalEventSink::default();
        assert_eq!(
            deliver_feedback_batch(&store, &sink, Duration::from_secs(1), 200, 10)
                .await
                .unwrap(),
            (1, 0)
        );
        assert_eq!(
            deliver_feedback_batch(&store, &sink, Duration::from_secs(1), 300, 10)
                .await
                .unwrap(),
            (0, 0)
        );
        let received = sink.received();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].id, event.id);
        let payload = parse_payload(&received[0]).unwrap();
        assert_eq!(payload.observation, captured);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    struct UnavailableFeedback;

    impl FeedbackProvider for UnavailableFeedback {
        async fn deliver(&self, _event: &ProviderEvent) -> Result<(), ProviderError> {
            Err(ProviderError::Unavailable("sekai is unavailable".into()))
        }
    }

    #[tokio::test]
    async fn unavailable_export_defers_without_interrupting_capture() {
        use crate::client::Ctx;

        let dir = std::env::temp_dir().join(format!(
            "tenkai-feedback-unavailable-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let database = dir.join("tenkai.db");
        let captured = observation("failed", Reason::ProductFailed);
        let object = crate::pb::sekai::Object {
            id: "note-1".into(),
            kind: "note".into(),
            name: "a".into(),
            namespace: "test".into(),
            ..Default::default()
        };
        let mut ctx = Ctx::embedded(&database).unwrap().with_feedback_export(true);
        ctx.put(object.clone()).await.unwrap();
        let mut updated = object;
        updated.name = "b".into();
        ctx.put_with_provider_events(updated, &[], std::slice::from_ref(&captured))
            .await
            .unwrap();
        let store = ctx.embedded_arc().unwrap();
        assert_eq!(
            store.feedback_observations("prod").unwrap(),
            vec![captured.clone()]
        );
        assert_eq!(
            deliver_feedback_batch(
                store.as_ref(),
                &UnavailableFeedback,
                Duration::from_secs(1),
                3_000,
                10
            )
            .await
            .unwrap(),
            (0, 1)
        );
        assert_eq!(
            OperationalStore::list_provider_events(
                store.as_ref(),
                FEEDBACK_PROVIDER_KIND,
                "prod",
                8
            )
            .unwrap()
            .len(),
            1
        );
        drop(ctx);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn plan_level_observations_group_by_operation_when_product_is_absent() {
        let captured = FeedbackObservation::capture(Capture {
            id: "tenkai:plan:plan-1:plan_failed:2",
            operation: Operation::PlanFailed,
            environment: "prod",
            product: "",
            plan_id: "plan-1",
            step_id: "",
            action: None,
            release_id: "",
            status: "failed",
            reason: Reason::PlanFailed,
            started_at_ms: None,
            lease_generation: 2,
            observed_at_ms: 4_000,
            context: RetryContext::default(),
        });
        let parameters = action_parameters(&captured, "e");
        assert_eq!(parameters.problem_signature, "plan_failed:plan_failed");
        let record = record(&captured).unwrap();
        let event: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
        assert_eq!(event.binding.environment_id, "prod");
        assert!(event.binding.release_digest.starts_with("observation:"));
    }

    #[tokio::test]
    async fn capture_write_enqueues_only_when_export_is_enabled() {
        use crate::client::Ctx;
        use crate::pb::sekai::Object;

        let dir = std::env::temp_dir().join(format!(
            "tenkai-feedback-ctx-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let database = dir.join("tenkai.db");
        let captured = observation("failed", Reason::ProductFailed);
        let object = |name: &str| Object {
            id: "note-1".into(),
            kind: "note".into(),
            name: name.into(),
            namespace: "test".into(),
            ..Default::default()
        };

        {
            let mut ctx = Ctx::embedded(&database).unwrap();
            ctx.put(object("a")).await.unwrap();
            ctx.put_with_provider_events(object("b"), &[], std::slice::from_ref(&captured))
                .await
                .unwrap();
            let store = ctx.embedded_arc().unwrap();
            assert!(
                OperationalStore::list_provider_events(
                    store.as_ref(),
                    FEEDBACK_PROVIDER_KIND,
                    "prod",
                    8
                )
                .unwrap()
                .is_empty()
            );
            assert_eq!(
                store.feedback_observations("prod").unwrap(),
                vec![captured.clone()]
            );
        }
        {
            let mut ctx = Ctx::embedded(&database).unwrap().with_feedback_export(true);
            ctx.put_with_provider_events(object("c"), &[], std::slice::from_ref(&captured))
                .await
                .unwrap();
            let events = OperationalStore::list_provider_events(
                ctx.embedded_arc().unwrap().as_ref(),
                FEEDBACK_PROVIDER_KIND,
                "prod",
                8,
            )
            .unwrap();
            assert_eq!(events.len(), 1);
            let event: ProviderEvent = serde_json::from_str(&events[0].payload_json).unwrap();
            assert_eq!(parse_payload(&event).unwrap().observation, captured);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

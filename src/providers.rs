//! Optional governance and intelligence provider contracts.
//!
//! Providers return or consume evidence; they never own releases, plans,
//! execution state, leases, receipts, or rollback recovery.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::storage::{OperationalStore, ProviderEventRecord, StoreError};

pub const PROVIDER_CONTRACT_VERSION: u32 = 1;

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
        event.binding.validate()?;
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
    event.binding.validate()?;
    store.enqueue_provider_event(&ProviderEventRecord {
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
    })?;
    Ok(())
}

/// Retry one durable optional event. The event is acknowledged only after the
/// adapter succeeds. Backoff is bounded and the stable event ID is the
/// provider's idempotency key.
pub async fn deliver_optional_event<F, Fut>(
    store: &impl OperationalStore,
    record: &ProviderEventRecord,
    timeout: Duration,
    now: i64,
    delivery: F,
) -> Result<(), ProviderError>
where
    F: FnOnce(ProviderEvent, String) -> Fut,
    Fut: Future<Output = Result<(), ProviderError>>,
{
    let claim_token = record.claim_token.as_deref().ok_or_else(|| {
        ProviderError::InvalidEvidence("durable event is not claimed for delivery".into())
    })?;
    let parsed = serde_json::from_str::<ProviderEvent>(&record.payload_json)
        .map_err(ProviderError::from)
        .and_then(|event| {
            event.binding.validate()?;
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
            return Ok(());
        }
    };
    let result = tokio::time::timeout(timeout, delivery(event, record.provider_kind.clone())).await;
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
    Ok(())
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

//! Signed `feedback.observation` webhooks (#1102).
//!
//! Captured observations stay local and always-on. An endpoint that lists
//! `feedback.observation` also receives the observation as a signed HTTPS
//! POST on the durable provider-event outbox, using its own outbox kind so a
//! version that does not know it never claims the row. Delivery is opt-in
//! per endpoint, retried in the background, and never interrupts capture.
//! The Sekai export in [`crate::feedback_export`] stays until a receiver
//! exists on that side; both paths may run together.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::deploy_webhook::{FeedbackEvent, WebhookEndpoint, WebhookSecrets};
use crate::feedback_observation::{FEEDBACK_OBSERVATION_SCHEMA, FeedbackObservation};
use crate::provider_event::{ProviderEventStore, deliver_optional_event, provider_event_record};
use crate::providers::{
    DeliveryStatus, EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderError, ProviderEvent,
};
use crate::storage::ProviderEventRecord;

pub const FEEDBACK_WEBHOOK_KIND: &str = "feedback_webhook";
const ENVELOPE_SCHEMA: &str = "tenkai.feedback_webhook.envelope.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Envelope {
    schema: String,
    url: String,
    secret_env: String,
    event: String,
    body: FeedbackObservation,
}

/// Outbox records announcing `observation` to every endpoint that lists
/// [`FeedbackEvent::Observation`]. Invalid endpoints are skipped so capture
/// never fails closed on delivery configuration.
pub fn records_for_observation(
    endpoints: &[WebhookEndpoint],
    observation: &FeedbackObservation,
) -> Vec<ProviderEventRecord> {
    if observation.schema != FEEDBACK_OBSERVATION_SCHEMA || observation.id.trim().is_empty() {
        return Vec::new();
    }
    endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.validate().is_ok() && endpoint.notifies_feedback(FeedbackEvent::Observation)
        })
        .filter_map(|endpoint| record(endpoint, observation).ok())
        .collect()
}

fn record(
    endpoint: &WebhookEndpoint,
    observation: &FeedbackObservation,
) -> Result<ProviderEventRecord, ProviderError> {
    let envelope = Envelope {
        schema: ENVELOPE_SCHEMA.into(),
        url: endpoint.url.clone(),
        secret_env: endpoint.secret_env.clone(),
        event: FeedbackEvent::Observation.as_str().into(),
        body: observation.clone(),
    };
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
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest,
        plan_digest,
        configuration_digest: format!("sha256:{:x}", Sha256::digest(endpoint.url.as_bytes())),
        environment_id,
    };
    provider_event_record(
        FEEDBACK_WEBHOOK_KIND,
        &ProviderEvent {
            id: event_id(&endpoint.url, &observation.id),
            binding,
            payload_json: serde_json::to_string(&envelope)?,
            collected_at_ms: None,
            source_sequence: None,
        },
        observation.observed_at_ms.max(1),
    )
}

fn event_id(url: &str, observation_id: &str) -> String {
    let mut identity = Sha256::new();
    for value in [url, observation_id, FeedbackEvent::Observation.as_str()] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    format!("tenkai:feedback-webhook:v1:{:x}", identity.finalize())
}

/// Deliver claimed feedback webhooks, as
/// [`crate::deploy_webhook::deliver_webhook_batch`] does for apply outcomes.
pub async fn deliver_batch<S, K>(
    store: &S,
    secrets: &K,
    timeout: Duration,
    now: i64,
    limit: usize,
) -> Result<(usize, usize), ProviderError>
where
    S: ProviderEventStore + ?Sized,
    K: WebhookSecrets,
{
    let claim_token = format!("feedback-webhook-worker:{}", uuid::Uuid::new_v4());
    let claim_until = now.saturating_add(
        i64::try_from(timeout.saturating_mul(limit.max(1) as u32).as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(30_000),
    );
    let records = store.claim_provider_events_for_kind(
        FEEDBACK_WEBHOOK_KIND,
        now,
        limit,
        &claim_token,
        claim_until,
    )?;
    if records.is_empty() {
        return Ok((0, 0));
    }
    let client = crate::outbound_tls::client()
        .map_err(|error| ProviderError::Unavailable(format!("webhook client: {error:#}")))?
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("tenkai-webhook/1")
        .build()
        .map_err(|error| ProviderError::Unavailable(format!("webhook client: {error}")))?;
    let mut delivered = 0;
    let mut deferred = 0;
    for record in &records {
        let client = client.clone();
        match deliver_optional_event(store, record, timeout, now, |event, kind| async move {
            if kind != FEEDBACK_WEBHOOK_KIND {
                return Err(ProviderError::InvalidEvidence(
                    "feedback webhook worker claimed a different provider destination".into(),
                ));
            }
            let envelope: Envelope = serde_json::from_str(&event.payload_json)?;
            if envelope.schema != ENVELOPE_SCHEMA {
                return Err(ProviderError::InvalidEvidence(
                    "feedback webhook envelope schema is unsupported".into(),
                ));
            }
            crate::deploy_webhook::post_signed(
                &client,
                secrets,
                &envelope.url,
                &envelope.secret_env,
                &envelope.event,
                &event.id,
                serde_json::to_vec(&envelope.body)?,
            )
            .await
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
    use crate::client::Ctx;
    use crate::deploy_webhook::{
        HEADER_EVENT, HEADER_IDEMPOTENCY, HEADER_SIGNATURE, HEADER_SIGNATURE_ALG, SIGNATURE_ALG,
        WebhookEvent, set_environment_webhook, signature_matches,
    };
    use crate::feedback_observation::{Capture, Operation, Reason, RetryContext};
    use crate::plan::Action;
    use crate::storage::OperationalStore;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct MapSecrets(HashMap<String, String>);

    impl WebhookSecrets for MapSecrets {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    fn observation() -> FeedbackObservation {
        FeedbackObservation::capture(Capture {
            id: "deployment:prod:api:2000",
            operation: Operation::ApplyStep,
            environment: "prod",
            product: "api",
            plan_id: "plan-1",
            step_id: "step-1",
            action: Some(Action::Upgrade),
            release_id: "release:api:1.1.0",
            status: "failed",
            reason: Reason::ProductFailed,
            started_at_ms: Some(1_000),
            lease_generation: 3,
            observed_at_ms: 2_000,
            context: RetryContext::default(),
        })
    }

    fn endpoint(feedback: Vec<FeedbackEvent>) -> WebhookEndpoint {
        WebhookEndpoint {
            url: "https://hooks.example/feedback".into(),
            secret_env: "FEEDBACK_HOOK_SECRET".into(),
            events: Vec::new(),
            operational: Vec::new(),
            feedback,
        }
    }

    fn required_schema_keys() -> Vec<String> {
        crate::feedback_observation::feedback_observation_schema()["required"]
            .as_array()
            .expect("published schema lists required keys")
            .iter()
            .map(|value| value.as_str().expect("required key").to_owned())
            .collect()
    }

    #[test]
    fn subscribed_endpoint_enqueues_one_event_and_unsubscribed_enqueues_none() {
        let captured = observation();
        let listing =
            records_for_observation(&[endpoint(vec![FeedbackEvent::Observation])], &captured);
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].provider_kind, FEEDBACK_WEBHOOK_KIND);
        let event: ProviderEvent = serde_json::from_str(&listing[0].payload_json).unwrap();
        let envelope: Envelope = serde_json::from_str(&event.payload_json).unwrap();
        assert_eq!(envelope.event, "feedback.observation");
        assert_eq!(envelope.body, captured);
        let apply_only = WebhookEndpoint {
            url: "https://hooks.example/apply".into(),
            secret_env: "APPLY_HOOK_SECRET".into(),
            events: vec![WebhookEvent::ApplySucceeded],
            operational: Vec::new(),
            feedback: Vec::new(),
        };
        assert!(records_for_observation(&[apply_only], &captured).is_empty());
        assert!(records_for_observation(&[endpoint(Vec::new())], &captured).is_empty());
    }

    #[test]
    fn replayed_observation_reuses_the_outbox_identity() {
        let captured = observation();
        let listing = [endpoint(vec![FeedbackEvent::Observation])];
        let first = records_for_observation(&listing, &captured);
        let replay = records_for_observation(&listing, &captured);
        assert_eq!(first[0].id, replay[0].id);
        assert_eq!(first[0].payload_json, replay[0].payload_json);
        let other = FeedbackObservation::capture(Capture {
            id: "deployment:prod:api:3000",
            operation: Operation::ApplyStep,
            environment: "prod",
            product: "api",
            plan_id: "plan-1",
            step_id: "step-1",
            action: Some(Action::Upgrade),
            release_id: "release:api:1.1.0",
            status: "failed",
            reason: Reason::ProductFailed,
            started_at_ms: Some(1_000),
            lease_generation: 3,
            observed_at_ms: 2_000,
            context: RetryContext::default(),
        });
        let second = records_for_observation(&listing, &other);
        assert_ne!(first[0].id, second[0].id);
    }

    #[test]
    fn posted_body_matches_the_published_observation_schema() {
        let captured = observation();
        let record =
            &records_for_observation(&[endpoint(vec![FeedbackEvent::Observation])], &captured)[0];
        let event: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
        let envelope: Envelope = serde_json::from_str(&event.payload_json).unwrap();
        let body = serde_json::to_value(&envelope.body).unwrap();
        for key in required_schema_keys() {
            assert!(body.get(&key).is_some(), "missing {key} in {body}");
        }
        assert_eq!(body["schema"], FEEDBACK_OBSERVATION_SCHEMA);
        let encoded = serde_json::to_string(&envelope.body).unwrap();
        assert!(!encoded.contains("detail"), "{encoded}");
        assert!(!encoded.contains("secret"), "{encoded}");
    }

    #[tokio::test]
    async fn conflicting_replay_keeps_the_first_webhook_and_still_commits() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-feedback-webhook-conflict-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "feedback-webhooks")
            .await
            .unwrap();
        set_environment_webhook(&mut ctx, "prod", endpoint(vec![FeedbackEvent::Observation]))
            .await
            .unwrap();
        let first = observation();
        let object = crate::pb::sekai::Object {
            id: "note-1".into(),
            kind: "note".into(),
            name: "a".into(),
            namespace: "test".into(),
            ..Default::default()
        };
        ctx.put(object.clone()).await.unwrap();
        let mut updated = object;
        updated.name = "b".into();
        ctx.put_with_provider_events(updated.clone(), &[], std::slice::from_ref(&first))
            .await
            .unwrap();
        let conflicting = FeedbackObservation::capture(Capture {
            id: "deployment:prod:api:2000",
            operation: Operation::ApplyStep,
            environment: "prod",
            product: "api",
            plan_id: "plan-1",
            step_id: "step-1",
            action: Some(Action::Upgrade),
            release_id: "release:api:1.1.0",
            status: "failed",
            reason: Reason::ProductFailed,
            started_at_ms: Some(1_000),
            lease_generation: 3,
            observed_at_ms: 3_000,
            context: RetryContext::default(),
        });
        updated.name = "c".into();
        ctx.put_with_provider_events(updated.clone(), &[], std::slice::from_ref(&conflicting))
            .await
            .unwrap();
        assert_eq!(ctx.get("note-1").await.unwrap().unwrap().name, "c");
        let store = ctx.embedded_arc().unwrap();
        let queued = OperationalStore::list_provider_events(
            store.as_ref(),
            FEEDBACK_WEBHOOK_KIND,
            "prod",
            8,
        )
        .unwrap();
        assert_eq!(queued.len(), 1, "{queued:?}");
        let inner: ProviderEvent = serde_json::from_str(&queued[0].payload_json).unwrap();
        let envelope: Envelope = serde_json::from_str(&inner.payload_json).unwrap();
        assert_eq!(envelope.body, first);
        assert_eq!(store.feedback_observations("prod").unwrap(), vec![first]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn capture_enqueues_one_signed_event_per_subscribed_endpoint() {
        let fixture = Fixture::start(StatusCode::NO_CONTENT).await;
        let mut ctx = fixture.ctx();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "feedback-webhooks")
            .await
            .unwrap();
        set_environment_webhook(
            &mut ctx,
            "prod",
            WebhookEndpoint {
                url: fixture.url.clone(),
                secret_env: "FEEDBACK_HOOK_SECRET".into(),
                events: Vec::new(),
                operational: Vec::new(),
                feedback: vec![FeedbackEvent::Observation],
            },
        )
        .await
        .unwrap();
        set_environment_webhook(
            &mut ctx,
            "prod",
            WebhookEndpoint {
                url: "https://hooks.example/unsubscribed".into(),
                secret_env: "OTHER_HOOK_SECRET".into(),
                events: vec![WebhookEvent::ApplySucceeded],
                operational: Vec::new(),
                feedback: Vec::new(),
            },
        )
        .await
        .unwrap();
        let captured = observation();
        let object = crate::pb::sekai::Object {
            id: "note-1".into(),
            kind: "note".into(),
            name: "a".into(),
            namespace: "test".into(),
            ..Default::default()
        };
        ctx.put(object.clone()).await.unwrap();
        let mut updated = object;
        updated.name = "b".into();
        ctx.put_with_provider_events(updated.clone(), &[], std::slice::from_ref(&captured))
            .await
            .unwrap();
        ctx.put_with_provider_events(updated, &[], std::slice::from_ref(&captured))
            .await
            .unwrap();
        let store = ctx.embedded_arc().unwrap();
        let queued = OperationalStore::list_provider_events(
            store.as_ref(),
            FEEDBACK_WEBHOOK_KIND,
            "prod",
            8,
        )
        .unwrap();
        assert_eq!(queued.len(), 1, "{queued:?}");
        let inner: ProviderEvent = serde_json::from_str(&queued[0].payload_json).unwrap();
        let secrets = MapSecrets(HashMap::from([(
            "FEEDBACK_HOOK_SECRET".into(),
            "test-secret".into(),
        )]));
        let (delivered, deferred) = deliver_batch(
            store.as_ref(),
            &secrets,
            Duration::from_secs(2),
            crate::now_millis(),
            8,
        )
        .await
        .unwrap();
        assert_eq!((delivered, deferred), (1, 0));
        let received = fixture.received();
        assert_eq!(received.len(), 1, "{received:?}");
        let (headers, body) = &received[0];
        let signature = headers.get(HEADER_SIGNATURE).unwrap().to_str().unwrap();
        assert!(signature_matches(
            b"test-secret",
            body.as_bytes(),
            signature
        ));
        assert_eq!(
            headers.get(HEADER_SIGNATURE_ALG).unwrap().to_str().unwrap(),
            SIGNATURE_ALG
        );
        assert_eq!(
            headers.get(HEADER_EVENT).unwrap().to_str().unwrap(),
            "feedback.observation"
        );
        assert_eq!(
            headers.get(HEADER_IDEMPOTENCY).unwrap().to_str().unwrap(),
            inner.id
        );
        let posted: FeedbackObservation = serde_json::from_str(body).unwrap();
        assert_eq!(posted, captured);
        let posted_value: serde_json::Value = serde_json::from_str(body).unwrap();
        for key in required_schema_keys() {
            assert!(
                posted_value.get(&key).is_some(),
                "missing {key} in {posted_value}"
            );
        }
        let (delivered, deferred) = deliver_batch(
            store.as_ref(),
            &secrets,
            Duration::from_secs(2),
            crate::now_millis(),
            8,
        )
        .await
        .unwrap();
        assert_eq!((delivered, deferred), (0, 0));
        assert_eq!(fixture.received().len(), 1);
        let _ = std::fs::remove_dir_all(&fixture.root);
    }

    struct Fixture {
        root: std::path::PathBuf,
        url: String,
        received: Arc<Mutex<Vec<(HeaderMap, String)>>>,
    }

    impl Fixture {
        async fn start(status: StatusCode) -> Self {
            let root = std::env::temp_dir().join(format!(
                "tenkai-feedback-webhook-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let received = Arc::new(Mutex::new(Vec::new()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let captured = received.clone();
            tokio::spawn(async move {
                let app = axum::Router::new().route(
                    "/hooks",
                    post(move |headers: HeaderMap, body: String| {
                        let captured = captured.clone();
                        async move {
                            captured.lock().unwrap().push((headers, body));
                            status
                        }
                    }),
                );
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                root,
                url: format!("http://127.0.0.1:{}/hooks", addr.port()),
                received,
            }
        }

        fn ctx(&self) -> Ctx {
            Ctx::embedded(self.root.join("tenkai.db")).unwrap()
        }

        fn received(&self) -> Vec<(HeaderMap, String)> {
            self.received.lock().unwrap().clone()
        }
    }
}

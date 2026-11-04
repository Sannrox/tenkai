use super::super::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;
use tenkai::feedback_export::{
    FEEDBACK_PROVIDER_KIND, FeedbackProvider, deliver_feedback_batch, observation_admission, record,
};
use tenkai::feedback_observation::{Capture, FeedbackObservation, Operation, Reason, RetryContext};
use tenkai::pb::sekai::{ActionInstance, SubmitActionInstanceResponse};
use tenkai::providers::{ProviderError, ProviderEvent};
use tenkai::storage::OperationalStore as _;

/// Plays back `SubmitActionInstance` replies, one per delivery.
struct ScriptedPlane(Mutex<VecDeque<SubmitActionInstanceResponse>>);

impl FeedbackProvider for ScriptedPlane {
    async fn deliver(&self, _event: &ProviderEvent) -> Result<(), ProviderError> {
        let reply = self.0.lock().unwrap().pop_front().expect("scripted reply");
        observation_admission(reply)
    }
}

fn reply(status: &str, replay: bool) -> SubmitActionInstanceResponse {
    SubmitActionInstanceResponse {
        instance: Some(ActionInstance {
            status: status.into(),
            policy_decision: "allow".into(),
            deny_reason: "budget exhausted".into(),
            ..Default::default()
        }),
        replay,
    }
}

/// A denied feedback observation, and its same-key replay, stay undelivered
/// and visible in a tenant partition's outbox until the plane admits it (#880).
#[tokio::test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
async fn live_postgres_denied_feedback_replay_stays_retryable() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let partition = store.partition_by_id(&format!("fd{suffix}")).unwrap();
    let observation = FeedbackObservation::capture(Capture {
        id: &format!("deployment:prod:api:{suffix}"),
        operation: Operation::ApplyStep,
        environment: "prod",
        product: "api",
        plan_id: "plan-1",
        step_id: "step-1",
        action: None,
        release_id: "release:api:1.1.0",
        status: "failed",
        reason: Reason::ProductFailed,
        started_at_ms: Some(1_000),
        lease_generation: 1,
        observed_at_ms: 2_000,
        context: RetryContext::default(),
    });
    partition
        .enqueue_provider_event(&record(&observation).unwrap())
        .unwrap();
    let plane = ScriptedPlane(Mutex::new(
        [
            reply("denied", false),
            reply("denied", true),
            reply("admitted", true),
        ]
        .into(),
    ));
    let pending = || {
        partition
            .list_provider_events(FEEDBACK_PROVIDER_KIND, "prod", 8)
            .unwrap()
            .remove(0)
    };
    for now in [3_000, 60_000] {
        assert_eq!(
            deliver_feedback_batch(&partition, &plane, Duration::from_secs(1), now, 10)
                .await
                .unwrap(),
            (0, 1)
        );
        let pending = pending();
        assert_eq!(pending.delivered_at, None);
        assert!(pending.last_error.contains("budget exhausted"));
    }
    assert_eq!(
        deliver_feedback_batch(&partition, &plane, Duration::from_secs(1), 120_000, 10)
            .await
            .unwrap(),
        (1, 0)
    );
    assert_eq!(pending().delivered_at, Some(120_000));
}

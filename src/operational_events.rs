//! Operational events over signed webhooks (#724).
//!
//! Besides apply outcomes, webhook endpoints may subscribe to operational
//! events. Environment-scoped events go to that environment's webhooks:
//! `plan.held`, `plan.awaiting_approval` and `import.failed`. Host-scoped
//! events go to the host webhook list in `TENKAI_HOST_WEBHOOKS` (the same
//! JSON shape as environment webhooks): `backup.stale` and `clock.drift`. An
//! endpoint receives an operational event only when it lists it.
//!
//! Each event fires once per transition. Its outbox id is derived from the
//! endpoint, the event, its scope and a transition key (for example the plan
//! id and hold scope), and enqueueing an id that already exists is a no-op, so
//! producers that see the same state on every reconcile tick enqueue once.
//! Delivery uses its own outbox kind and envelope, signed and retried like
//! deploy webhooks; a version that does not know the kind never claims it.
//! Payloads carry identities and codes only, never free text such as a hold
//! reason or an error message.

use std::time::Duration;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::deploy_webhook::{OperationalEvent, WebhookEndpoint, WebhookSecrets};
use crate::provider_event::{ProviderEventStore, deliver_optional_event, provider_event_record};
use crate::providers::{
    DeliveryStatus, EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderError, ProviderEvent,
};
use crate::storage::{OperationalStore, ProviderEventRecord};

pub const OPERATIONAL_WEBHOOK_KIND: &str = "operational_webhook";
pub const OPERATIONAL_EVENT_SCHEMA: &str = "tenkai.operational_event.v1";
const ENVELOPE_SCHEMA: &str = "tenkai.operational_event.envelope.v1";
pub const HOST_WEBHOOKS_ENV: &str = "TENKAI_HOST_WEBHOOKS";
/// Outbox scope of host events; not a valid environment name.
pub const HOST_SCOPE: &str = "_host";

/// The JSON posted to an endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalPayload {
    pub schema: String,
    pub event: String,
    /// Empty for a host event.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
    /// What the event is about: a plan id, an import id, a backup or `clock`.
    pub resource: String,
    /// A short code, for example a hold scope or a clock state.
    pub code: String,
    /// Bound from the outbox on first delivery, so retries keep one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Envelope {
    schema: String,
    url: String,
    secret_env: String,
    event: String,
    body: OperationalPayload,
}

/// One transition to announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition<'a> {
    pub event: OperationalEvent,
    /// The environment, or [`HOST_SCOPE`].
    pub scope: &'a str,
    pub resource: &'a str,
    pub code: &'a str,
    /// Distinguishes this transition from a later one of the same resource.
    pub key: &'a str,
}

/// Outbox records announcing `transition` to every endpoint that lists it.
/// Invalid endpoints are skipped: announcing must never fail the caller.
pub fn records(
    endpoints: &[WebhookEndpoint],
    transition: &Transition<'_>,
    now: i64,
) -> Vec<ProviderEventRecord> {
    endpoints
        .iter()
        .filter(|endpoint| endpoint.validate().is_ok() && endpoint.notifies(transition.event))
        .filter_map(|endpoint| record(endpoint, transition, now).ok())
        .collect()
}

fn record(
    endpoint: &WebhookEndpoint,
    transition: &Transition<'_>,
    now: i64,
) -> Result<ProviderEventRecord, ProviderError> {
    let body = OperationalPayload {
        schema: OPERATIONAL_EVENT_SCHEMA.into(),
        event: transition.event.as_str().into(),
        environment: if transition.scope == HOST_SCOPE {
            String::new()
        } else {
            transition.scope.into()
        },
        resource: transition.resource.into(),
        code: transition.code.into(),
        observed_at: None,
    };
    let envelope = Envelope {
        schema: ENVELOPE_SCHEMA.into(),
        url: endpoint.url.clone(),
        secret_env: endpoint.secret_env.clone(),
        event: transition.event.as_str().into(),
        body,
    };
    let mut identity = Sha256::new();
    for value in [
        endpoint.url.as_str(),
        transition.event.as_str(),
        transition.scope,
        transition.resource,
        transition.key,
    ] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    let id = format!("tenkai:operational-event:v1:{:x}", identity.finalize());
    // The outbox binds every event to digests; an operational event binds to
    // its own identity, which is all it has.
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest: format!("sha256:{:x}", Sha256::digest(transition.event.as_str())),
        plan_digest: format!("sha256:{:x}", Sha256::digest(&id)),
        configuration_digest: format!("sha256:{:x}", Sha256::digest(endpoint.url.as_bytes())),
        environment_id: transition.scope.into(),
    };
    provider_event_record(
        OPERATIONAL_WEBHOOK_KIND,
        &ProviderEvent {
            id,
            binding,
            payload_json: serde_json::to_string(&envelope)?,
            collected_at_ms: None,
            source_sequence: None,
        },
        now,
    )
}

/// Enqueue `transition` for `endpoints`. Failures are logged, never returned:
/// a sink, or the outbox, must not block reconcile, apply or import.
/// Returns whether every record was enqueued, so a caller tracking
/// transitions can try again.
pub fn announce(
    store: &dyn OperationalStore,
    endpoints: &[WebhookEndpoint],
    transition: &Transition<'_>,
    now: i64,
) -> bool {
    let mut enqueued = true;
    let digests = crate::smtp_digest::records(crate::smtp_digest::installed(), transition, now);
    for record in records(endpoints, transition, now)
        .into_iter()
        .chain(digests)
    {
        if let Err(error) = store.enqueue_provider_event(&record) {
            eprintln!(
                "tenkai.operational_event outcome=enqueue_failed event={} detail={error}",
                transition.event.as_str()
            );
            enqueued = false;
        }
    }
    enqueued
}

/// Host webhooks from `TENKAI_HOST_WEBHOOKS` (a JSON list of endpoints).
pub fn host_endpoints_from_env() -> Result<Vec<WebhookEndpoint>> {
    match std::env::var(HOST_WEBHOOKS_ENV) {
        Ok(raw) if !raw.trim().is_empty() => crate::deploy_webhook::parse_endpoints_json(&raw)
            .with_context(|| format!("parsing {HOST_WEBHOOKS_ENV}")),
        _ => Ok(Vec::new()),
    }
}

/// When the hold behind a held plan's scope key (`environment:<env>` or
/// `channel:<product>/<channel>`) was set.
async fn hold_set_at(ctx: &mut crate::client::Ctx, scope: &str) -> Option<i64> {
    use crate::delivery_hold::HoldScope;
    let scope = if let Some(environment) = scope.strip_prefix("environment:") {
        HoldScope::environment(environment)
    } else {
        let (product, channel) = scope.strip_prefix("channel:")?.split_once('/')?;
        HoldScope::channel(product, channel)
    };
    crate::delivery_hold::get(ctx, &scope)
        .await
        .ok()
        .flatten()
        .map(|hold| hold.held_at)
}

/// Announce every failed import in `staging` not yet announced, to its
/// environment's webhooks, and mark it once the outbox has it. Called after a
/// failed import and on a schedule, so a crash or a full outbox only delays it.
pub async fn announce_failed_imports(
    ctx: &mut crate::client::Ctx,
    store: &dyn OperationalStore,
    staging: &std::path::Path,
    now: i64,
) {
    let Ok(failures) = crate::offline_import::unannounced_failures(staging) else {
        return;
    };
    for job in failures {
        let Ok(endpoints) =
            crate::deploy_webhook::list_environment_webhooks(ctx, &job.environment).await
        else {
            continue;
        };
        // A moved-aside attempt carries `<id>@<started>`; announce it under
        // its job id, keyed by the attempt, as when it was current.
        let resource = job.id.split('@').next().unwrap_or(&job.id).to_string();
        let key = format!("{resource}|{}", job.started_at_ms);
        let announced = announce(
            store,
            &endpoints,
            &Transition {
                event: OperationalEvent::ImportFailed,
                scope: &job.environment,
                resource: &resource,
                code: "failed",
                key: &key,
            },
            now,
        );
        // Not marked (an import holds the lock, or an error): the next pass
        // announces again with the same key, which the outbox deduplicates.
        if announced && let Err(error) = crate::offline_import::mark_announced(staging, &job) {
            eprintln!("tenkai.operational_event outcome=mark_failed detail={error:#}");
        }
    }
}

/// Announce the held and approval-waiting plans of one reconcile tick to
/// each environment's webhooks.
pub async fn announce_tick(
    ctx: &mut crate::client::Ctx,
    store: &dyn OperationalStore,
    report: &crate::reconciler::TickReport,
    now: i64,
) {
    use crate::reconciler::EnvironmentStatus;
    for result in &report.environments {
        let (event, plan_id, code) = match &result.status {
            EnvironmentStatus::Held { plan_id, scope, .. } => {
                (OperationalEvent::PlanHeld, plan_id, scope.as_str())
            }
            EnvironmentStatus::AwaitingApproval { plan_id, .. } => {
                (OperationalEvent::PlanAwaitingApproval, plan_id, "approval")
            }
            _ => continue,
        };
        let Ok(endpoints) =
            crate::deploy_webhook::list_environment_webhooks(ctx, &result.environment).await
        else {
            continue;
        };
        // Nothing to tell when no webhook and no SMTP sink listens.
        if endpoints.is_empty() && crate::smtp_digest::installed().is_empty() {
            continue;
        }
        // A hold cleared and set again is a new occurrence: key it by when
        // the hold was set, so a repeated tick dedups and a new hold does not.
        let occurrence = match &result.status {
            EnvironmentStatus::Held { scope, .. } => hold_set_at(ctx, scope).await,
            _ => None,
        };
        let key = format!("{plan_id}|{code}|{}", occurrence.unwrap_or_default());
        announce(
            store,
            &endpoints,
            &Transition {
                event,
                scope: &result.environment,
                resource: plan_id,
                code,
                key: &key,
            },
            now,
        );
    }
}

/// Edge detection for host events: announces when backup age turns `stale`
/// or `missing`, and when the clock turns `warn` or `refuse`, once per turn.
/// A process that starts in a bad state announces it once. An announcement
/// the outbox did not fully take is retried with the same key, so endpoints
/// that already have it see no duplicate.
#[derive(Debug, Default)]
pub struct HostWatch {
    backup: Condition,
    clock: Condition,
    /// Where announcements still waiting for the outbox are kept, so a
    /// restart retries them; `None` keeps them in memory only.
    state: Option<std::path::PathBuf>,
}

/// One host announcement the outbox has not taken yet, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingHostAlert {
    event: OperationalEvent,
    state: String,
    key: String,
}

#[derive(Debug, Default)]
struct Condition {
    /// The bad state last announced, or `None` while healthy.
    announced: Option<&'static str>,
    /// Announcements the outbox has not fully taken, with their keys. They
    /// are retried until it does, whatever the condition is by then.
    pending: Vec<(String, String)>,
}

impl Condition {
    fn observe(
        &mut self,
        store: &dyn OperationalStore,
        endpoints: &[WebhookEndpoint],
        event: OperationalEvent,
        resource: &str,
        // `None` when this condition is not monitored (pending alerts are
        // still retried); otherwise the state when bad, `None` when healthy.
        health: Option<Option<&'static str>>,
        now: i64,
    ) -> Vec<String> {
        let mut delivered = Vec::new();
        let announce_one = |state: &str, key: &str| {
            announce(
                store,
                endpoints,
                &Transition {
                    event,
                    scope: HOST_SCOPE,
                    resource,
                    code: state,
                    key,
                },
                now,
            )
        };
        self.pending.retain(|(state, key)| {
            let sent = announce_one(state, key);
            if sent {
                delivered.push(key.clone());
            }
            !sent
        });
        let Some(bad) = health else {
            return delivered;
        };
        let Some(state) = bad else {
            self.announced = None;
            return delivered;
        };
        if self.announced == Some(state) {
            return delivered;
        }
        self.announced = Some(state);
        let key = format!("{state}|{now}");
        if announce_one(state, &key) {
            delivered.push(key);
        } else {
            self.pending.push((state.to_string(), key));
        }
        delivered
    }
}

impl HostWatch {
    /// A watch that keeps announcements waiting for the outbox in `path`
    /// (JSON), and retries any left there by an earlier process.
    pub fn with_state_file(path: std::path::PathBuf) -> Self {
        let mut watch = Self {
            state: Some(path.clone()),
            ..Self::default()
        };
        let pending: Vec<PendingHostAlert> = std::fs::read(&path)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        watch.adopt(pending);
        watch
    }

    /// Merge this watch's pending alerts into the state file under a lock,
    /// then adopt the merged list. A server sharing the file (an overlapping
    /// restart) keeps its alerts, and an alert leaves the file only once some
    /// process delivered it. Retrying another's alert is safe: the outbox
    /// takes each key once.
    fn save(&mut self, delivered: &[String]) {
        let Some(path) = self.state.clone() else {
            return;
        };
        let saved = (|| -> Result<Vec<PendingHostAlert>> {
            let lock = std::fs::File::create(path.with_extension("lock"))?;
            lock.lock()?;
            let mut pending: Vec<PendingHostAlert> = std::fs::read(&path)
                .ok()
                .and_then(|raw| serde_json::from_slice(&raw).ok())
                .unwrap_or_default();
            for alert in self.alerts() {
                if !pending.contains(&alert) {
                    pending.push(alert);
                }
            }
            pending.retain(|alert| !delivered.contains(&alert.key));
            if pending.is_empty() {
                match std::fs::remove_file(&path) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error.into());
                    }
                    _ => {}
                }
            } else {
                crate::atomic_state::write_json_verified(
                    &path,
                    &pending,
                    |_: &Vec<PendingHostAlert>| Ok(()),
                )?;
            }
            Ok(pending)
        })();
        match saved {
            Ok(pending) => self.adopt(pending),
            Err(error) => {
                eprintln!("tenkai.operational_event outcome=state_unsaved detail={error:#}")
            }
        }
    }

    fn alerts(&self) -> Vec<PendingHostAlert> {
        [
            (OperationalEvent::BackupStale, &self.backup),
            (OperationalEvent::ClockDrift, &self.clock),
        ]
        .into_iter()
        .flat_map(|(event, condition)| {
            condition
                .pending
                .iter()
                .map(move |(state, key)| PendingHostAlert {
                    event,
                    state: state.clone(),
                    key: key.clone(),
                })
        })
        .collect()
    }

    fn adopt(&mut self, pending: Vec<PendingHostAlert>) {
        self.backup.pending.clear();
        self.clock.pending.clear();
        for alert in pending {
            let condition = match alert.event {
                OperationalEvent::ClockDrift => &mut self.clock,
                _ => &mut self.backup,
            };
            condition.pending.push((alert.state, alert.key));
        }
    }

    pub fn observe(
        &mut self,
        store: &dyn OperationalStore,
        endpoints: &[WebhookEndpoint],
        backup: Option<&crate::backup::BackupHealth>,
        clock: Option<&crate::clock_guard::ClockHealth>,
        now: i64,
    ) {
        let backup = backup.map(|backup| {
            matches!(backup.state, "stale" | "missing" | "unreadable").then_some(backup.state)
        });
        let clock =
            clock.map(|clock| matches!(clock.state, "warn" | "refuse").then_some(clock.state));
        let mut delivered = self.backup.observe(
            store,
            endpoints,
            OperationalEvent::BackupStale,
            "backup",
            backup,
            now,
        );
        delivered.extend(self.clock.observe(
            store,
            endpoints,
            OperationalEvent::ClockDrift,
            "clock",
            clock,
            now,
        ));
        self.save(&delivered);
    }
}

/// Deliver claimed operational events, as [`crate::deploy_webhook::deliver_webhook_batch`]
/// does for apply outcomes.
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
    let claim_token = format!("operational-worker:{}", uuid::Uuid::new_v4());
    let claim_until = now.saturating_add(
        i64::try_from(timeout.saturating_mul(limit.max(1) as u32).as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(30_000),
    );
    let records = store.claim_provider_events_for_kind(
        OPERATIONAL_WEBHOOK_KIND,
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
            if kind != OPERATIONAL_WEBHOOK_KIND {
                return Err(ProviderError::InvalidEvidence(
                    "operational worker claimed a different provider destination".into(),
                ));
            }
            let envelope: Envelope = serde_json::from_str(&event.payload_json)?;
            if envelope.schema != ENVELOPE_SCHEMA {
                return Err(ProviderError::InvalidEvidence(
                    "operational event envelope schema is unsupported".into(),
                ));
            }
            let mut body = envelope.body;
            body.observed_at = event.collected_at_ms.filter(|timestamp| *timestamp > 0);
            crate::deploy_webhook::post_signed(
                &client,
                secrets,
                &envelope.url,
                &envelope.secret_env,
                &envelope.event,
                &event.id,
                serde_json::to_vec(&body)?,
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

/// One webhook delivery as `GET .../webhooks/deliveries` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebhookDelivery {
    pub id: String,
    pub event: String,
    pub url: String,
    /// `pending`, `retrying` or `delivered`.
    pub state: String,
    pub attempts: u32,
    pub next_attempt_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub delivered_at: Option<i64>,
    /// The last failure, as the worker recorded it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

/// Apply-outcome and operational deliveries for `scope` (an environment, or
/// [`HOST_SCOPE`]), at most `limit` of each kind: apply outcomes, then
/// operational events, each newest recorded first.
pub fn deliveries(
    store: &dyn OperationalStore,
    scope: &str,
    limit: usize,
) -> Result<Vec<WebhookDelivery>> {
    let mut deliveries = Vec::new();
    let kinds = [
        crate::deploy_webhook::DEPLOY_WEBHOOK_KIND.to_string(),
        OPERATIONAL_WEBHOOK_KIND.to_string(),
    ]
    .into_iter()
    .chain(
        crate::smtp_digest::installed()
            .iter()
            .map(|sink| crate::smtp_digest::digest_kind(&sink.id)),
    );
    for kind in kinds {
        for record in store.list_provider_events(&kind, scope, limit)? {
            #[derive(Deserialize)]
            struct Addressed {
                url: String,
                event: String,
            }
            let addressed = serde_json::from_str::<ProviderEvent>(&record.payload_json)
                .ok()
                .and_then(|event| serde_json::from_str::<Addressed>(&event.payload_json).ok());
            let Some(addressed) = addressed else {
                continue;
            };
            deliveries.push(WebhookDelivery {
                id: record.id,
                event: addressed.event,
                url: addressed.url,
                state: if record.delivered_at.is_some() {
                    "delivered"
                } else if record.attempts > 0 {
                    "retrying"
                } else {
                    "pending"
                }
                .into(),
                attempts: record.attempts,
                next_attempt_at: record.next_attempt_at,
                delivered_at: record.delivered_at,
                last_error: record.last_error,
            });
        }
    }
    Ok(deliveries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;

    fn endpoint(operational: Vec<OperationalEvent>) -> WebhookEndpoint {
        WebhookEndpoint {
            url: "https://hooks.example/ops".into(),
            secret_env: "OPS_HOOK_SECRET".into(),
            events: Vec::new(),
            operational,
        }
    }

    #[test]
    fn a_transition_is_enqueued_once_and_only_for_listing_endpoints() {
        let store = SqliteStore::open_in_memory().unwrap();
        let held = Transition {
            event: OperationalEvent::PlanHeld,
            scope: HOST_SCOPE,
            resource: "plan-1",
            code: "environment",
            key: "plan-1|environment",
        };
        // An endpoint that lists no operational event receives none.
        assert!(records(&[endpoint(Vec::new())], &held, 1).is_empty());
        let listing = [endpoint(vec![OperationalEvent::PlanHeld])];
        // The same state seen on every tick enqueues one event.
        for tick in 1..=3 {
            announce(&store, &listing, &held, tick);
        }
        let queued = deliveries(&store, HOST_SCOPE, 10).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(
            (queued[0].event.as_str(), queued[0].state.as_str()),
            ("plan.held", "pending")
        );
        // A later transition of the same resource is a new event.
        announce(
            &store,
            &listing,
            &Transition {
                key: "plan-1|channel",
                code: "channel",
                ..held.clone()
            },
            4,
        );
        assert_eq!(deliveries(&store, HOST_SCOPE, 10).unwrap().len(), 2);
    }

    #[test]
    fn payloads_carry_identities_and_codes_only() {
        let record = &records(
            &[endpoint(vec![OperationalEvent::ImportFailed])],
            &Transition {
                event: OperationalEvent::ImportFailed,
                scope: "prod",
                resource: "imp-0123",
                code: "failed",
                key: "imp-0123|1",
            },
            1,
        )[0];
        let event: ProviderEvent = serde_json::from_str(&record.payload_json).unwrap();
        let envelope: Envelope = serde_json::from_str(&event.payload_json).unwrap();
        assert_eq!(
            serde_json::to_value(&envelope.body).unwrap(),
            serde_json::json!({
                "schema": OPERATIONAL_EVENT_SCHEMA,
                "event": "import.failed",
                "environment": "prod",
                "resource": "imp-0123",
                "code": "failed",
            })
        );
    }

    #[test]
    fn host_watch_announces_each_turn_once() {
        let store = SqliteStore::open_in_memory().unwrap();
        let hosts = [endpoint(vec![
            OperationalEvent::BackupStale,
            OperationalEvent::ClockDrift,
        ])];
        let backup = |state| crate::backup::BackupHealth {
            state,
            age_seconds: None,
            max_age_seconds: 60,
        };
        let clock = |state| crate::clock_guard::ClockHealth {
            state,
            skew_ms: None,
            measured_at_ms: None,
            warn_ms: 1,
            refuse_ms: 2,
        };
        let mut watch = HostWatch::default();
        // Stale for three checks: one event. Clock fine.
        for now in 1..=3 {
            watch.observe(
                &store,
                &hosts,
                Some(&backup("stale")),
                Some(&clock("ok")),
                now,
            );
        }
        assert_eq!(deliveries(&store, HOST_SCOPE, 10).unwrap().len(), 1);
        // Recovers, then turns stale again: a second event. Clock warns, then refuses.
        watch.observe(&store, &hosts, Some(&backup("ok")), Some(&clock("warn")), 4);
        watch.observe(
            &store,
            &hosts,
            Some(&backup("stale")),
            Some(&clock("refuse")),
            5,
        );
        watch.observe(
            &store,
            &hosts,
            Some(&backup("stale")),
            Some(&clock("refuse")),
            6,
        );
        let events: Vec<String> = deliveries(&store, HOST_SCOPE, 10)
            .unwrap()
            .into_iter()
            .map(|delivery| delivery.event)
            .collect();
        assert_eq!(events.iter().filter(|e| *e == "backup.stale").count(), 2);
        assert_eq!(events.iter().filter(|e| *e == "clock.drift").count(), 2);
    }

    #[test]
    fn host_alert_state_is_shared_by_overlapping_servers() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-host-alerts-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut first = HostWatch::with_state_file(path.clone());
        first
            .backup
            .pending
            .push(("stale".into(), "stale|1".into()));
        first.save(&[]);
        // A second server with nothing pending keeps, and adopts, the alert.
        let mut second = HostWatch::with_state_file(path.clone());
        second.backup.pending.clear();
        second.save(&[]);
        assert_eq!(second.backup.pending.len(), 1);
        assert!(path.exists());
        // Once either delivers it, it leaves the file.
        second.save(&["stale|1".into()]);
        assert!(!path.exists());
        let _ = std::fs::remove_file(path.with_extension("lock"));
    }

    #[tokio::test]
    async fn failed_imports_are_announced_once_and_marked() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-op-import-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let mut ctx = crate::client::Ctx::embedded(dir.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "site-c", "site")
            .await
            .unwrap();
        crate::deploy_webhook::set_environment_webhook(
            &mut ctx,
            "site-c",
            endpoint(vec![OperationalEvent::ImportFailed]),
        )
        .await
        .unwrap();
        // A refused import, as the import job records it.
        let request = crate::offline_import::ImportRequest {
            version: 1,
            operation: "import".into(),
            bundle: "../escape.json".into(),
            upgrade: "fleet-1".into(),
            environment: "site-c".into(),
            dry_run: false,
        };
        let roots = crate::release_signing::TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: Vec::new(),
        };
        let job = crate::offline_import::run(&mut ctx, &staging, &request, &roots, "operator")
            .await
            .unwrap();
        assert_eq!(job.state, crate::offline_import::ImportState::Failed);

        // A retry before the failure was announced keeps it, moved aside.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let retried = crate::offline_import::run(&mut ctx, &staging, &request, &roots, "operator")
            .await
            .unwrap();
        assert_ne!(retried.started_at_ms, job.started_at_ms);

        let store = SqliteStore::open_in_memory().unwrap();
        for now in [1, 2] {
            announce_failed_imports(&mut ctx, &store, &staging, now).await;
        }
        let queued = deliveries(&store, "site-c", 10).unwrap();
        // Both attempts, each once.
        assert_eq!(queued.len(), 2);
        assert!(
            crate::offline_import::unannounced_failures(&staging)
                .unwrap()
                .is_empty()
        );
        assert_eq!(queued[0].event, "import.failed");
        // The job file keeps the format earlier versions read.
        let raw = std::fs::read_to_string(staging.join("imports").join(format!("{}.json", job.id)))
            .unwrap();
        assert!(!raw.contains("announced"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_down_sink_defers_and_records_its_failure() {
        let store = SqliteStore::open_in_memory().unwrap();
        // A closed port: the delivery fails and stays queued for retry.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", closed.local_addr().unwrap());
        drop(closed);
        let sink = WebhookEndpoint {
            url,
            secret_env: "OPS_HOOK_SECRET".into(),
            events: Vec::new(),
            operational: vec![OperationalEvent::ClockDrift],
        };
        announce(
            &store,
            &[sink],
            &Transition {
                event: OperationalEvent::ClockDrift,
                scope: HOST_SCOPE,
                resource: "clock",
                code: "refuse",
                key: "refuse|1",
            },
            crate::now_millis(),
        );
        struct Secret;
        impl WebhookSecrets for Secret {
            fn get(&self, _: &str) -> Option<String> {
                Some("secret".into())
            }
        }
        let (delivered, deferred) = deliver_batch(
            &store,
            &Secret,
            Duration::from_secs(2),
            crate::now_millis(),
            10,
        )
        .await
        .unwrap();
        assert_eq!((delivered, deferred), (0, 1));
        let status = &deliveries(&store, HOST_SCOPE, 10).unwrap()[0];
        assert_eq!((status.state.as_str(), status.attempts), ("retrying", 1));
        assert!(!status.last_error.is_empty());
    }
}

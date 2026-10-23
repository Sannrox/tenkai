//! Per-environment post-deploy webhook notifications (#546).
//!
//! Terminal apply observations enqueue signed HTTPS deliveries on the durable
//! provider-event outbox. Endpoint downtime retries in the background and does
//! not change apply, rollback, or recovery authority.

use std::time::Duration;

use anyhow::{Result, bail};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::client::Ctx;
use crate::ontology::validate_identifier;
use crate::pb::sekai::Object;
use crate::plan::{Plan, Step};
use crate::provider_event::{ProviderEventStore, deliver_optional_event, provider_event_record};
use crate::providers::{
    DeliveryStatus, EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderError, ProviderEvent,
};

pub const DEPLOY_WEBHOOK_KIND: &str = "deploy_webhook";
pub const DEPLOY_WEBHOOK_SCHEMA: &str = "tenkai.deploy_webhook.v1";
pub const DEPLOY_WEBHOOK_ENVELOPE_SCHEMA: &str = "tenkai.deploy_webhook.envelope.v1";
pub const WEBHOOKS_PROPERTY: &str = "webhooks";
pub const SIGNATURE_ALG: &str = "hmac-sha256";
pub const HEADER_SIGNATURE: &str = "x-tenkai-signature";
pub const HEADER_SIGNATURE_ALG: &str = "x-tenkai-signature-alg";
pub const HEADER_EVENT: &str = "x-tenkai-event";
pub const HEADER_IDEMPOTENCY: &str = "x-tenkai-idempotency-key";

const MAX_ENDPOINTS: usize = 8;
const MAX_SECRET_BYTES: usize = 256;

/// Stable apply-lifecycle events a webhook endpoint may subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum WebhookEvent {
    #[serde(rename = "apply.succeeded")]
    ApplySucceeded,
    #[serde(rename = "apply.failed")]
    ApplyFailed,
    #[serde(rename = "apply.rolled_back")]
    ApplyRolledBack,
}

impl WebhookEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApplySucceeded => "apply.succeeded",
            Self::ApplyFailed => "apply.failed",
            Self::ApplyRolledBack => "apply.rolled_back",
        }
    }

    fn is_alert(self) -> bool {
        matches!(self, Self::ApplyRolledBack)
    }

    fn from_status(status: &str) -> Option<Self> {
        match status {
            "succeeded" => Some(Self::ApplySucceeded),
            "failed" => Some(Self::ApplyFailed),
            "rolled_back" => Some(Self::ApplyRolledBack),
            _ => None,
        }
    }
}

/// Operator-facing endpoint configuration. The HMAC secret is never stored;
/// `secret_env` names a process environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub url: String,
    pub secret_env: String,
    #[serde(default)]
    pub events: Vec<WebhookEvent>,
}

impl WebhookEndpoint {
    pub fn validate(&self) -> Result<()> {
        validate_webhook_url(&self.url)?;
        validate_secret_env(&self.secret_env)?;
        if self.events.len() > 8 {
            bail!("webhook event list is oversized");
        }
        Ok(())
    }

    fn subscribed(&self, event: WebhookEvent) -> bool {
        self.events.is_empty() || self.events.contains(&event)
    }
}

/// Public JSON posted to the endpoint. No secrets, command output, or paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployWebhookPayload {
    pub schema: String,
    pub event: String,
    pub alert: bool,
    pub environment: String,
    pub product: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    pub release_id: String,
    pub release_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_revision: String,
    pub artifact_digests: Vec<String>,
    pub plan_id: String,
    pub outcome: String,
    /// Bound from outbox `collected_at_ms` on first delivery so replayed
    /// observations keep a stable enqueue payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<i64>,
    /// Durable plan-step identity. This is not the per-call deployment attempt
    /// id: that value is minted from the clock on every observation and would
    /// duplicate notifications if it were part of the payload or outbox key.
    pub step_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeployWebhookEnvelope {
    schema: String,
    url: String,
    secret_env: String,
    event: String,
    body: DeployWebhookPayload,
}

/// Resolves HMAC secrets by environment-variable name.
pub trait WebhookSecrets: Send + Sync {
    fn get(&self, name: &str) -> Option<String>;
}

/// Process-environment secret source used by `tenkai-server`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessWebhookSecrets;

impl WebhookSecrets for ProcessWebhookSecrets {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }
}

/// Parse and validate the environment `webhooks` property.
pub fn parse_endpoints(environment: &Object) -> Result<Vec<WebhookEndpoint>> {
    let Some(raw) = environment.properties.get(WEBHOOKS_PROPERTY) else {
        return Ok(Vec::new());
    };
    parse_endpoints_json(raw)
}

pub fn parse_endpoints_json(raw: &str) -> Result<Vec<WebhookEndpoint>> {
    let endpoints: Vec<WebhookEndpoint> = serde_json::from_str(raw)
        .map_err(|error| anyhow::anyhow!("parsing {WEBHOOKS_PROPERTY}: {error}"))?;
    validate_endpoints(&endpoints)?;
    Ok(endpoints)
}

fn validate_endpoints(endpoints: &[WebhookEndpoint]) -> Result<()> {
    if endpoints.len() > MAX_ENDPOINTS {
        bail!("at most {MAX_ENDPOINTS} webhook endpoints may be configured");
    }
    let mut urls = std::collections::BTreeSet::new();
    for endpoint in endpoints {
        endpoint.validate()?;
        if !urls.insert(endpoint.url.as_str()) {
            bail!("webhook URL is configured more than once");
        }
    }
    Ok(())
}

pub fn configured_endpoints(environment: &Object) -> Vec<WebhookEndpoint> {
    parse_endpoints(environment).unwrap_or_default()
}

/// Upsert one endpoint on the environment, keyed by URL. Never stores secret bytes.
pub async fn set_environment_webhook(
    ctx: &mut Ctx,
    env: &str,
    endpoint: WebhookEndpoint,
) -> Result<String> {
    validate_identifier("environment", env)?;
    endpoint.validate()?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    let mut endpoints = configured_endpoints(&env_obj);
    if let Some(existing) = endpoints.iter_mut().find(|item| item.url == endpoint.url) {
        *existing = endpoint.clone();
    } else {
        endpoints.push(endpoint.clone());
    }
    validate_endpoints(&endpoints)?;
    env_obj
        .properties
        .insert(WEBHOOKS_PROPERTY.into(), serde_json::to_string(&endpoints)?);
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} webhook {}", endpoint.url))
}

pub async fn list_environment_webhooks(ctx: &mut Ctx, env: &str) -> Result<Vec<WebhookEndpoint>> {
    validate_identifier("environment", env)?;
    let env_obj = crate::environment::environment(ctx, env).await?;
    parse_endpoints(&env_obj)
}

pub async fn clear_environment_webhooks(
    ctx: &mut Ctx,
    env: &str,
    url: Option<&str>,
) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    let Some(raw) = env_obj.properties.get(WEBHOOKS_PROPERTY).cloned() else {
        bail!("environment {env} has no webhooks");
    };
    match url {
        None => {
            env_obj.properties.remove(WEBHOOKS_PROPERTY);
            env_obj.updated = crate::now_millis();
            ctx.put(env_obj).await?;
            Ok(format!("cleared {env} webhooks"))
        }
        Some(url) => {
            let mut endpoints = parse_endpoints_json(&raw)?;
            let before = endpoints.len();
            endpoints.retain(|endpoint| endpoint.url != url);
            if endpoints.len() == before {
                bail!("environment {env} has no webhook {url}");
            }
            if endpoints.is_empty() {
                env_obj.properties.remove(WEBHOOKS_PROPERTY);
            } else {
                env_obj
                    .properties
                    .insert(WEBHOOKS_PROPERTY.into(), serde_json::to_string(&endpoints)?);
            }
            env_obj.updated = crate::now_millis();
            ctx.put(env_obj).await?;
            Ok(format!("cleared {env} webhook {url}"))
        }
    }
}

pub async fn source_revision(ctx: &mut Ctx, release_id: &str) -> String {
    let Ok(Some(release)) = ctx.get(release_id).await else {
        return String::new();
    };
    let Some(raw) = release.properties.get("provenance") else {
        return String::new();
    };
    serde_json::from_str::<crate::release_signing::Provenance>(raw)
        .ok()
        .map(|provenance| provenance.revision)
        .filter(|revision| !revision.trim().is_empty())
        .unwrap_or_default()
}

/// Build durable outbox records for one terminal observation. Invalid or
/// unsubscribed endpoints are skipped so apply cannot fail closed on delivery
/// configuration.
pub fn records_for_observation(
    endpoints: &[WebhookEndpoint],
    plan: &Plan,
    step: &Step,
    status: &str,
    observed_at: i64,
    source_revision: &str,
) -> Vec<crate::storage::ProviderEventRecord> {
    let Some(event) = WebhookEvent::from_status(status) else {
        return Vec::new();
    };
    let Ok(plan_digest) = plan.executable_digest() else {
        return Vec::new();
    };
    let mut artifact_digests = Vec::new();
    if !step.artifact_digest.trim().is_empty() {
        artifact_digests.push(step.artifact_digest.clone());
    }
    if event == WebhookEvent::ApplyRolledBack
        && let Some(restore) = step.restore.as_ref()
        && !restore.artifact_digest.trim().is_empty()
        && !artifact_digests.contains(&restore.artifact_digest)
    {
        artifact_digests.push(restore.artifact_digest.clone());
    }
    let mut records = Vec::new();
    for endpoint in endpoints {
        if !endpoint.subscribed(event) {
            continue;
        }
        let Ok(record) = webhook_record(
            endpoint,
            plan,
            &plan_digest,
            step,
            event,
            observed_at,
            source_revision,
            &artifact_digests,
        ) else {
            continue;
        };
        records.push(record);
    }
    records
}

#[allow(clippy::too_many_arguments)]
fn webhook_record(
    endpoint: &WebhookEndpoint,
    plan: &Plan,
    plan_digest: &str,
    step: &Step,
    event: WebhookEvent,
    observed_at: i64,
    source_revision: &str,
    artifact_digests: &[String],
) -> Result<crate::storage::ProviderEventRecord, ProviderError> {
    if step.id.trim().is_empty() || observed_at <= 0 {
        return Err(ProviderError::InvalidEvidence(
            "deploy webhook payload is missing required identities".into(),
        ));
    }
    let body = DeployWebhookPayload {
        schema: DEPLOY_WEBHOOK_SCHEMA.into(),
        event: event.as_str().into(),
        alert: event.is_alert(),
        environment: plan.environment.clone(),
        product: step.product.clone(),
        version: step.to.clone(),
        previous_version: step.from.clone().filter(|value| !value.is_empty()),
        release_id: step.release_id.clone(),
        release_digest: step.release_digest.clone(),
        source_revision: source_revision.to_string(),
        artifact_digests: artifact_digests.to_vec(),
        plan_id: plan.id.clone(),
        outcome: match event {
            WebhookEvent::ApplySucceeded => "succeeded".into(),
            WebhookEvent::ApplyFailed => "failed".into(),
            WebhookEvent::ApplyRolledBack => "rolled_back".into(),
        },
        observed_at: None,
        step_id: step.id.clone(),
    };
    if body.environment.trim().is_empty()
        || body.product.trim().is_empty()
        || body.release_id.trim().is_empty()
        || body.release_digest.trim().is_empty()
        || body.plan_id.trim().is_empty()
        || body.step_id.trim().is_empty()
    {
        return Err(ProviderError::InvalidEvidence(
            "deploy webhook payload is missing required identities".into(),
        ));
    }
    let envelope = DeployWebhookEnvelope {
        schema: DEPLOY_WEBHOOK_ENVELOPE_SCHEMA.into(),
        url: endpoint.url.clone(),
        secret_env: endpoint.secret_env.clone(),
        event: event.as_str().into(),
        body,
    };
    let payload_json = serde_json::to_string(&envelope)?;
    let configuration_digest = digest_bytes(endpoint.url.as_bytes());
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest: step.release_digest.clone(),
        plan_digest: plan_digest.into(),
        configuration_digest,
        environment_id: plan.environment.clone(),
    };
    let provider_event = ProviderEvent {
        id: webhook_event_id(&endpoint.url, &plan.id, &step.id, event),
        binding,
        payload_json,
        collected_at_ms: None,
        source_sequence: None,
    };
    provider_event_record(DEPLOY_WEBHOOK_KIND, &provider_event, observed_at)
}

fn webhook_event_id(url: &str, plan_id: &str, step_id: &str, event: WebhookEvent) -> String {
    let mut identity = Sha256::new();
    for value in [url, plan_id, step_id, event.as_str()] {
        identity.update((value.len() as u64).to_le_bytes());
        identity.update(value.as_bytes());
    }
    format!("tenkai:deploy-webhook:v1:{:x}", identity.finalize())
}

/// HMAC-SHA256 over the posted JSON body. Header value is `sha256=<hex>`.
pub fn sign_payload(secret: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    format!("sha256={}", hex_encode(tag.as_ref()))
}

pub fn signature_matches(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(tag) = decode_hex(hex) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, body, &tag).is_ok()
}

pub async fn deliver_webhook_batch<S, K>(
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
    let claim_token = format!("webhook-worker:{}", uuid::Uuid::new_v4());
    let claim_until = now.saturating_add(
        i64::try_from(timeout.saturating_mul(limit.max(1) as u32).as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(30_000),
    );
    let records = store.claim_provider_events_for_kind(
        DEPLOY_WEBHOOK_KIND,
        now,
        limit,
        &claim_token,
        claim_until,
    )?;
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
        match deliver_optional_event(store, record, timeout, now, |event, kind| {
            let client = client.clone();
            async move {
                if kind != DEPLOY_WEBHOOK_KIND {
                    return Err(ProviderError::InvalidEvidence(
                        "webhook worker claimed a different provider destination".into(),
                    ));
                }
                deliver_one(&client, secrets, &event).await
            }
        })
        .await?
        {
            DeliveryStatus::Delivered => delivered += 1,
            DeliveryStatus::Deferred => deferred += 1,
        }
    }
    Ok((delivered, deferred))
}

async fn deliver_one<K: WebhookSecrets>(
    client: &reqwest::Client,
    secrets: &K,
    event: &ProviderEvent,
) -> Result<(), ProviderError> {
    let envelope: DeployWebhookEnvelope = serde_json::from_str(&event.payload_json)?;
    if envelope.schema != DEPLOY_WEBHOOK_ENVELOPE_SCHEMA {
        return Err(ProviderError::InvalidEvidence(
            "deploy webhook envelope schema is unsupported".into(),
        ));
    }
    validate_webhook_url(&envelope.url).map_err(|error| {
        ProviderError::InvalidEvidence(format!("deploy webhook URL is not deliverable: {error}"))
    })?;
    validate_secret_env(&envelope.secret_env).map_err(|error| {
        ProviderError::InvalidEvidence(format!("deploy webhook secret_env is invalid: {error}"))
    })?;
    let secret = secrets.get(&envelope.secret_env).ok_or_else(|| {
        ProviderError::Unavailable("webhook signing secret is not configured".into())
    })?;
    if secret.len() > MAX_SECRET_BYTES {
        return Err(ProviderError::Unavailable(
            "webhook signing secret exceeds the bounded contract".into(),
        ));
    }
    let mut body = envelope.body.clone();
    body.observed_at = event.collected_at_ms.filter(|timestamp| *timestamp > 0);
    let body = serde_json::to_vec(&body)?;
    let signature = sign_payload(secret.as_bytes(), &body);
    let response = client
        .post(&envelope.url)
        .header("content-type", "application/json")
        .header(HEADER_SIGNATURE, &signature)
        .header(HEADER_SIGNATURE_ALG, SIGNATURE_ALG)
        .header(HEADER_EVENT, &envelope.event)
        .header(HEADER_IDEMPOTENCY, &event.id)
        .body(body)
        .send()
        .await
        .map_err(|_| ProviderError::Unavailable("webhook endpoint unreachable".into()))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(ProviderError::Unavailable(format!(
            "webhook endpoint returned {}",
            response.status()
        )))
    }
}

pub fn validate_webhook_url(raw: &str) -> Result<()> {
    let parsed = Url::parse(raw).map_err(|_| anyhow::anyhow!("webhook URL is not a valid URL"))?;
    if parsed.username() != "" || parsed.password().is_some() {
        bail!("webhook URL must not embed credentials");
    }
    match parsed.scheme() {
        "https" => {}
        "http" if is_loopback(&parsed) => {}
        "http" => bail!("webhook URL must use HTTPS"),
        other => bail!("webhook URL scheme {other:?} is not supported"),
    }
    if parsed.host_str().is_none() {
        bail!("webhook URL is missing a host");
    }
    Ok(())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn validate_secret_env(name: &str) -> Result<()> {
    if name.len() < 3 || name.len() > 128 {
        bail!("secret_env is empty or oversized");
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        bail!("secret_env is empty or oversized");
    };
    if !first.is_ascii_alphabetic() || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        bail!("secret_env must be an environment variable name");
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, ()> {
    if !hex.len().is_multiple_of(2) || hex.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{ExecutionAuthorization, ExecutionOptions, StepOutcomeStatus};
    use crate::client::Ctx;
    use crate::provider_event::ProviderEventStore;
    use crate::software_executor::FakeSoftwareExecutor;
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

    #[test]
    fn https_and_loopback_http_are_admitted() {
        validate_webhook_url("https://hooks.example.test/tenkai").unwrap();
        validate_webhook_url("http://127.0.0.1:8080/hooks").unwrap();
        validate_webhook_url("http://localhost:9/hooks").unwrap();
        let https_user = validate_webhook_url("https://user:pass@hooks.example.test/tenkai")
            .unwrap_err()
            .to_string();
        assert!(https_user.contains("credentials"), "{https_user}");
        let cleartext = validate_webhook_url("http://hooks.example.test/tenkai")
            .unwrap_err()
            .to_string();
        assert!(cleartext.contains("HTTPS"), "{cleartext}");
    }

    #[test]
    fn replayed_step_keeps_a_stable_outbox_identity() {
        let first = webhook_event_id(
            "https://hooks.example.test/tenkai",
            "plan-a",
            "step-1",
            WebhookEvent::ApplySucceeded,
        );
        let replay = webhook_event_id(
            "https://hooks.example.test/tenkai",
            "plan-a",
            "step-1",
            WebhookEvent::ApplySucceeded,
        );
        assert_eq!(first, replay);
        assert_ne!(
            first,
            webhook_event_id(
                "https://hooks.example.test/tenkai",
                "plan-a",
                "step-2",
                WebhookEvent::ApplySucceeded,
            )
        );
    }

    #[test]
    fn hmac_header_matches_sample_verifier() {
        let body = br#"{"schema":"tenkai.deploy_webhook.v1"}"#;
        let header = sign_payload(b"test-secret", body);
        assert!(header.starts_with("sha256="), "{header}");
        assert!(signature_matches(b"test-secret", body, &header));
        assert!(!signature_matches(b"other-secret", body, &header));
    }

    #[test]
    fn default_events_subscribe_to_every_apply_outcome() {
        let endpoint = WebhookEndpoint {
            url: "https://hooks.example.test/tenkai".into(),
            secret_env: "TENKAI_WEBHOOK_SECRET".into(),
            events: Vec::new(),
        };
        endpoint.validate().unwrap();
        assert!(endpoint.subscribed(WebhookEvent::ApplySucceeded));
        assert!(endpoint.subscribed(WebhookEvent::ApplyFailed));
        assert!(endpoint.subscribed(WebhookEvent::ApplyRolledBack));
    }

    #[tokio::test]
    async fn successful_apply_delivers_one_signed_succeeded_event() {
        let fixture = Fixture::start(StatusCode::NO_CONTENT).await;
        let mut ctx = fixture.ctx();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "webhooks")
            .await
            .unwrap();
        set_environment_webhook(
            &mut ctx,
            "local",
            WebhookEndpoint {
                url: fixture.url.clone(),
                secret_env: "TENKAI_WEBHOOK_SECRET".into(),
                events: vec![WebhookEvent::ApplySucceeded],
            },
        )
        .await
        .unwrap();
        publish_and_apply(&mut ctx, &fixture.root, "1.0.0", "").await;
        let records = listed(&ctx);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].provider_kind, DEPLOY_WEBHOOK_KIND);
        let inner: ProviderEvent = serde_json::from_str(&records[0].payload_json).unwrap();
        let envelope: DeployWebhookEnvelope = serde_json::from_str(&inner.payload_json).unwrap();
        assert_eq!(envelope.body.event, "apply.succeeded");
        assert!(!envelope.body.alert);
        assert_eq!(envelope.body.version, "1.0.0");
        assert!(envelope.body.previous_version.is_none());
        assert!(!envelope.body.release_digest.is_empty());
        let encoded = serde_json::to_string(&envelope.body).unwrap();
        assert!(!encoded.contains("workdir"));
        assert!(!encoded.contains("detail"));

        let secrets = MapSecrets(HashMap::from([(
            "TENKAI_WEBHOOK_SECRET".into(),
            "test-secret".into(),
        )]));
        let store = ctx.embedded_arc().unwrap();
        let (delivered, deferred) = deliver_webhook_batch(
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
            "apply.succeeded"
        );
        assert_eq!(
            headers.get(HEADER_IDEMPOTENCY).unwrap().to_str().unwrap(),
            inner.id
        );
        let posted: DeployWebhookPayload = serde_json::from_str(body).unwrap();
        assert_eq!(posted.event, "apply.succeeded");
        assert_eq!(posted.environment, "local");
        assert_eq!(posted.product, "hook-demo");
        assert!(posted.observed_at.is_some_and(|timestamp| timestamp > 0));
        assert_eq!(posted.step_id, envelope.body.step_id);
        assert!(!posted.step_id.is_empty());

        let (delivered, deferred) = deliver_webhook_batch(
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

    #[tokio::test]
    async fn endpoint_downtime_does_not_fail_apply_and_retries() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-webhook-down-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "webhooks")
            .await
            .unwrap();
        set_environment_webhook(
            &mut ctx,
            "local",
            WebhookEndpoint {
                url: "http://127.0.0.1:1/missing".into(),
                secret_env: "TENKAI_WEBHOOK_SECRET".into(),
                events: vec![WebhookEvent::ApplySucceeded],
            },
        )
        .await
        .unwrap();
        let outcomes = publish_and_apply(&mut ctx, &root, "1.0.0", "").await;
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.classified_status().unwrap() == StepOutcomeStatus::Succeeded),
            "{outcomes:?}"
        );
        let secrets = MapSecrets(HashMap::from([(
            "TENKAI_WEBHOOK_SECRET".into(),
            "test-secret".into(),
        )]));
        let store = ctx.embedded_arc().unwrap();
        let (delivered, deferred) = deliver_webhook_batch(
            store.as_ref(),
            &secrets,
            Duration::from_millis(200),
            crate::now_millis(),
            8,
        )
        .await
        .unwrap();
        assert_eq!(delivered, 0);
        assert_eq!(deferred, 1);
        let records = listed(&ctx);
        assert_eq!(records.len(), 1);
        assert!(records[0].delivered_at.is_none());
        assert!(records[0].attempts >= 1);
        assert!(
            records[0].last_error.contains("unreachable")
                || records[0].last_error.contains("returned"),
            "{}",
            records[0].last_error
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn health_gate_rollback_emits_alert_with_both_versions() {
        let fixture = Fixture::start(StatusCode::NO_CONTENT).await;
        let mut ctx = fixture.ctx();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "webhooks")
            .await
            .unwrap();
        set_environment_webhook(
            &mut ctx,
            "local",
            WebhookEndpoint {
                url: fixture.url.clone(),
                secret_env: "TENKAI_WEBHOOK_SECRET".into(),
                events: vec![WebhookEvent::ApplySucceeded, WebhookEvent::ApplyRolledBack],
            },
        )
        .await
        .unwrap();
        publish_and_apply(&mut ctx, &fixture.root, "1.0.0", "").await;
        publish_software(
            &mut ctx,
            &fixture.root,
            "1.1.0",
            "[gate]\nbake_window_seconds = 0\non_fail = \"rollback\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nthreshold = 0.01\n",
        )
        .await;
        let actor = crate::auth_context::test_management_context("webhook-rollback");
        crate::catalog::promote(&mut ctx, &actor, "hook-demo@1.1.0", "stable")
            .await
            .unwrap();
        ctx.set_health_metrics(std::sync::Arc::new(
            crate::health_gate::FakeMetricsSource::new().with_value("error_rate", 1.0),
        ));
        let outcomes = apply_current(&mut ctx).await;
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            StepOutcomeStatus::RolledBack,
            "{outcomes:?}"
        );

        let secrets = MapSecrets(HashMap::from([(
            "TENKAI_WEBHOOK_SECRET".into(),
            "test-secret".into(),
        )]));
        let store = ctx.embedded_arc().unwrap();
        let _ = deliver_webhook_batch(
            store.as_ref(),
            &secrets,
            Duration::from_secs(2),
            crate::now_millis(),
            8,
        )
        .await
        .unwrap();
        let received = fixture.received();
        let bodies: Vec<DeployWebhookPayload> = received
            .iter()
            .map(|(_, body)| serde_json::from_str(body).unwrap())
            .collect();
        let rolled = bodies
            .iter()
            .find(|payload| payload.event == "apply.rolled_back")
            .expect("rollback webhook");
        assert!(rolled.alert);
        assert_eq!(rolled.version, "1.1.0");
        assert_eq!(rolled.previous_version.as_deref(), Some("1.0.0"));
        assert_eq!(rolled.outcome, "rolled_back");
        let _ = std::fs::remove_dir_all(&fixture.root);
    }

    #[tokio::test]
    async fn set_list_clear_never_store_secret_bytes() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-webhook-cfg-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "webhooks")
            .await
            .unwrap();
        set_environment_webhook(
            &mut ctx,
            "local",
            WebhookEndpoint {
                url: "https://hooks.example.test/tenkai".into(),
                secret_env: "TENKAI_WEBHOOK_SECRET".into(),
                events: vec![WebhookEvent::ApplySucceeded],
            },
        )
        .await
        .unwrap();
        let listed = list_environment_webhooks(&mut ctx, "local").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].secret_env, "TENKAI_WEBHOOK_SECRET");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let raw = env.properties.get(WEBHOOKS_PROPERTY).unwrap();
        assert!(!raw.contains("test-secret"));
        assert!(!raw.to_ascii_lowercase().contains("password"));
        clear_environment_webhooks(&mut ctx, "local", Some("https://hooks.example.test/tenkai"))
            .await
            .unwrap();
        assert!(
            list_environment_webhooks(&mut ctx, "local")
                .await
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    struct Fixture {
        root: std::path::PathBuf,
        url: String,
        received: Arc<Mutex<Vec<(HeaderMap, String)>>>,
    }

    impl Fixture {
        async fn start(status: StatusCode) -> Self {
            let root = std::env::temp_dir().join(format!(
                "tenkai-webhook-{}-{}",
                std::process::id(),
                crate::now_millis()
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

    fn listed(ctx: &Ctx) -> Vec<crate::storage::ProviderEventRecord> {
        ctx.embedded_arc()
            .unwrap()
            .list_provider_events(DEPLOY_WEBHOOK_KIND, "local", 32)
            .unwrap()
    }

    async fn publish_and_apply(
        ctx: &mut Ctx,
        root: &std::path::Path,
        version: &str,
        gate: &str,
    ) -> Vec<crate::apply::Outcome> {
        publish_software(ctx, root, version, gate).await;
        let actor = crate::auth_context::test_management_context("webhook-apply");
        crate::catalog::promote(ctx, &actor, &format!("hook-demo@{version}"), "stable")
            .await
            .unwrap();
        crate::plan::subscribe(ctx, "local", "hook-demo", "stable")
            .await
            .ok();
        apply_current(ctx).await
    }

    async fn publish_software(ctx: &mut Ctx, root: &std::path::Path, version: &str, gate: &str) {
        std::fs::write(
            root.join("tenkai.toml"),
            format!(
                "[product]\nname = \"hook-demo\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n{gate}"
            ),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    fn apply_options() -> ExecutionOptions<'static> {
        ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: ExecutionAuthorization::LocalDevelopment {
                reason: "webhook fixture",
            },
            software_executor: Some(std::sync::Arc::new(FakeSoftwareExecutor::new())),
            model_runtime_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
            delivery_fence: None,
        }
    }

    async fn apply_current(ctx: &mut Ctx) -> Vec<crate::apply::Outcome> {
        let plan = crate::plan::create(ctx, "local").await.unwrap();
        crate::apply::execute_with_options(ctx, &plan.id, apply_options())
            .await
            .unwrap()
    }
}

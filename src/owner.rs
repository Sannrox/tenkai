//! Product and environment owners with notification routing (#1066).
//!
//! An owner is a contact string for display and audit, plus the same
//! [`WebhookEndpoint`] list environments already store as `webhooks`. There is
//! no team directory. HMAC secrets stay in process variables named by
//! `secret_env`. Apply, recall, automatic hold, and stale-health events fan
//! out to the product and environment endpoints, once per URL.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::criticality_store::{
    claim_product_mutation, finish_product_mutation, persist_product_object,
};
use crate::deploy_webhook::{WebhookEndpoint, parse_endpoints, parse_endpoints_json};
use crate::ontology::{KIND_PRODUCT, NS, product_id, validate_identifier};
use crate::pb::sekai::Object;

pub const OWNER_PROPERTY: &str = "owner";
const MAX_CONTACT_BYTES: usize = 256;

/// Contact and notification URLs as inspect, status, and history show them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerView {
    /// Display and audit contact. Not an identity.
    pub contact: String,
    /// Configured notification URLs. Empty means no reachable endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Whether notifications reach this owner, from recorded deliveries.
    /// Present where delivery records are readable (environment inspect).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub reachability: Option<OwnerReachability>,
}

/// Failed attempts on one outstanding delivery at which its endpoint
/// counts as unreachable.
pub const UNREACHABLE_AFTER_FAILURES: u32 = 3;

/// Whether an owner or one endpoint receives notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityVerdict {
    /// The owner has no notification endpoint.
    Unconfigured,
    /// An outstanding delivery failed [`UNREACHABLE_AFTER_FAILURES`] times
    /// or more. For an owner: every endpoint is unreachable.
    Unreachable,
    /// No outstanding delivery has failed past the threshold.
    Reachable,
    /// More failing deliveries are outstanding than one read returns, and
    /// the ones not read may have failed past the threshold for this URL.
    /// For an owner: no endpoint is reachable and some are unknown.
    Unknown,
}

/// Owner verdict plus one row per notification endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerReachability {
    pub verdict: ReachabilityVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<EndpointReachability>,
}

/// Delivery health of one notification URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EndpointReachability {
    pub url: String,
    pub verdict: ReachabilityVerdict,
    /// Failed attempts on this URL's longest-retrying outstanding delivery.
    pub consecutive_failures: u32,
    /// Latest successful delivery to this URL among the recorded ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_success_at: Option<i64>,
}

/// Query of `DELETE /v1/products/{product}/webhooks`: one endpoint by `url`,
/// or every endpoint when omitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearProductWebhooksQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub url: Option<String>,
}

/// Body of `PUT /v1/products/{product}/owner` and environment `set_owner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetOwnerRequest {
    pub contact: String,
}

impl SetOwnerRequest {
    pub fn validate(&self) -> Result<()> {
        validate_contact(&self.contact)
    }
}

pub fn validate_contact(contact: &str) -> Result<()> {
    if contact.chars().any(char::is_control) {
        bail!("owner contact must not contain control characters");
    }
    let contact = contact.trim();
    if contact.is_empty() {
        bail!("owner contact is required");
    }
    if contact.len() > MAX_CONTACT_BYTES {
        bail!("owner contact exceeds {MAX_CONTACT_BYTES} bytes");
    }
    Ok(())
}

pub fn contact_from_object(object: &Object) -> Option<String> {
    object
        .properties
        .get(OWNER_PROPERTY)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn view_from_object(object: &Object) -> Option<OwnerView> {
    let contact = contact_from_object(object)?;
    let endpoints = parse_endpoints(object)
        .unwrap_or_default()
        .into_iter()
        .map(|endpoint| endpoint.url)
        .collect();
    Some(OwnerView {
        contact,
        endpoints,
        reachability: None,
    })
}

impl OwnerView {
    /// Replace stored URLs with the reachable notification set (env first).
    pub fn with_reachable(mut self, endpoints: &[WebhookEndpoint]) -> Self {
        self.endpoints = endpoints
            .iter()
            .map(|endpoint| endpoint.url.clone())
            .collect();
        self
    }

    /// Attach reachability of `endpoints` judged from recent and failing
    /// deliveries.
    pub fn with_reachability(
        mut self,
        recent: &[crate::operational_events::WebhookDelivery],
        failing: &crate::operational_events::FailingDeliveries,
    ) -> Self {
        self.reachability = Some(reachability(&self.endpoints, recent, failing));
        self
    }
}

/// Judge each URL from its deliveries. The owner is reachable when any
/// endpoint is, unreachable when every endpoint is, and unconfigured without
/// endpoints.
pub fn reachability(
    endpoints: &[String],
    recent: &[crate::operational_events::WebhookDelivery],
    failing: &crate::operational_events::FailingDeliveries,
) -> OwnerReachability {
    let endpoints = endpoints
        .iter()
        .map(|url| {
            let to_url = recent
                .iter()
                .chain(&failing.deliveries)
                .filter(|delivery| &delivery.url == url);
            let last_success_at = to_url
                .clone()
                .filter_map(|delivery| delivery.delivered_at)
                .max();
            let consecutive_failures = to_url
                .filter(|delivery| delivery.delivered_at.is_none())
                .map(|delivery| delivery.attempts)
                .max()
                .unwrap_or(0);
            EndpointReachability {
                url: url.clone(),
                verdict: if consecutive_failures >= UNREACHABLE_AFTER_FAILURES {
                    ReachabilityVerdict::Unreachable
                } else if failing.hidden_max_attempts >= UNREACHABLE_AFTER_FAILURES {
                    ReachabilityVerdict::Unknown
                } else {
                    ReachabilityVerdict::Reachable
                },
                consecutive_failures,
                last_success_at,
            }
        })
        .collect::<Vec<_>>();
    let has = |verdict| endpoints.iter().any(|endpoint| endpoint.verdict == verdict);
    let verdict = if endpoints.is_empty() {
        ReachabilityVerdict::Unconfigured
    } else if has(ReachabilityVerdict::Reachable) {
        ReachabilityVerdict::Reachable
    } else if has(ReachabilityVerdict::Unknown) {
        ReachabilityVerdict::Unknown
    } else {
        ReachabilityVerdict::Unreachable
    };
    OwnerReachability { verdict, endpoints }
}

/// One record per URL, environment first. A repeated product URL keeps the
/// environment `secret_env` and unions `events`, `operational`, and `feedback`.
pub fn union_endpoints(
    environment: Vec<WebhookEndpoint>,
    product: Vec<WebhookEndpoint>,
) -> Vec<WebhookEndpoint> {
    let mut out: Vec<WebhookEndpoint> = Vec::new();
    for endpoint in environment.into_iter().chain(product) {
        if let Some(existing) = out.iter_mut().find(|item| item.url == endpoint.url) {
            merge_subscriptions(existing, endpoint);
        } else {
            out.push(endpoint);
        }
    }
    out
}

fn all_apply_outcomes(endpoint: &WebhookEndpoint) -> bool {
    endpoint.events.is_empty() && endpoint.operational.is_empty() && endpoint.feedback.is_empty()
}

fn merge_subscriptions(existing: &mut WebhookEndpoint, other: WebhookEndpoint) {
    let keep_all_apply = all_apply_outcomes(existing) || all_apply_outcomes(&other);
    extend_unique(&mut existing.events, other.events);
    extend_unique(&mut existing.operational, other.operational);
    extend_unique(&mut existing.feedback, other.feedback);
    if keep_all_apply {
        if existing.operational.is_empty() && existing.feedback.is_empty() {
            existing.events.clear();
        } else {
            existing.events = vec![
                crate::deploy_webhook::WebhookEvent::ApplySucceeded,
                crate::deploy_webhook::WebhookEvent::ApplyFailed,
                crate::deploy_webhook::WebhookEvent::ApplyRolledBack,
            ];
        }
    }
}

fn extend_unique<T: PartialEq>(dst: &mut Vec<T>, src: Vec<T>) {
    for item in src {
        if !dst.contains(&item) {
            dst.push(item);
        }
    }
}

pub async fn set_environment_owner(ctx: &mut Ctx, env: &str, contact: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    validate_contact(contact)?;
    let mut object = crate::environment::environment(ctx, env).await?;
    object
        .properties
        .insert(OWNER_PROPERTY.into(), contact.trim().into());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("set {env} owner {}", contact.trim()))
}

pub async fn clear_environment_owner(ctx: &mut Ctx, env: &str) -> Result<String> {
    validate_identifier("environment", env)?;
    let mut object = crate::environment::environment(ctx, env).await?;
    if object.properties.remove(OWNER_PROPERTY).is_none() {
        bail!("environment {env} has no owner");
    }
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("cleared {env} owner"))
}

pub async fn environment_owner(ctx: &mut Ctx, env: &str) -> Result<Option<OwnerView>> {
    validate_identifier("environment", env)?;
    let object = crate::environment::environment(ctx, env).await?;
    let Some(view) = view_from_object(&object) else {
        return Ok(None);
    };
    let reachable = environment_notification_endpoints(ctx, env)
        .await
        .unwrap_or_default();
    Ok(Some(view.with_reachable(&reachable)))
}

pub async fn set_product_owner(ctx: &mut Ctx, product: &str, contact: &str) -> Result<String> {
    validate_identifier("product", product)?;
    validate_contact(contact)?;
    let lease = claim_product_mutation(ctx, product).await?;
    let result = async {
        let mut object = load_product(ctx, product).await?;
        object
            .properties
            .insert(OWNER_PROPERTY.into(), contact.trim().into());
        object.updated = crate::now_millis();
        persist_product_object(ctx, object, &lease, false).await?;
        Ok(format!("set {product} owner {}", contact.trim()))
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

pub async fn clear_product_owner(ctx: &mut Ctx, product: &str) -> Result<String> {
    validate_identifier("product", product)?;
    let lease = claim_product_mutation(ctx, product).await?;
    let result = async {
        let mut object = load_product(ctx, product).await?;
        if object.properties.remove(OWNER_PROPERTY).is_none() {
            bail!("product {product} has no owner");
        }
        object.updated = crate::now_millis();
        persist_product_object(ctx, object, &lease, false).await?;
        Ok(format!("cleared {product} owner"))
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

pub async fn product_owner(ctx: &mut Ctx, product: &str) -> Result<Option<OwnerView>> {
    validate_identifier("product", product)?;
    match ctx.get(&product_id(product)).await? {
        Some(object) if object.kind == KIND_PRODUCT => Ok(view_from_object(&object)),
        Some(_) => bail!("product {product} is not a product"),
        None => Ok(None),
    }
}

pub async fn list_product_webhooks(ctx: &mut Ctx, product: &str) -> Result<Vec<WebhookEndpoint>> {
    validate_identifier("product", product)?;
    match ctx.get(&product_id(product)).await? {
        Some(object) if object.kind == KIND_PRODUCT => parse_endpoints(&object),
        Some(_) => bail!("product {product} is not a product"),
        None => Ok(Vec::new()),
    }
}

pub async fn set_product_webhook(
    ctx: &mut Ctx,
    product: &str,
    endpoint: WebhookEndpoint,
) -> Result<String> {
    validate_identifier("product", product)?;
    endpoint.validate()?;
    let lease = claim_product_mutation(ctx, product).await?;
    let result = async {
        let mut object = load_product(ctx, product).await?;
        let mut endpoints = parse_endpoints(&object).unwrap_or_default();
        if let Some(existing) = endpoints.iter_mut().find(|item| item.url == endpoint.url) {
            *existing = endpoint.clone();
        } else {
            endpoints.push(endpoint.clone());
        }
        crate::deploy_webhook::validate_endpoint_list(&endpoints)?;
        object.properties.insert(
            crate::deploy_webhook::WEBHOOKS_PROPERTY.into(),
            serde_json::to_string(&endpoints)?,
        );
        object.updated = crate::now_millis();
        persist_product_object(ctx, object, &lease, false).await?;
        Ok(format!("set {product} webhook {}", endpoint.url))
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

pub async fn clear_product_webhooks(
    ctx: &mut Ctx,
    product: &str,
    url: Option<&str>,
) -> Result<String> {
    validate_identifier("product", product)?;
    let lease = claim_product_mutation(ctx, product).await?;
    let result = async {
        let mut object = load_product(ctx, product).await?;
        let Some(raw) = object
            .properties
            .get(crate::deploy_webhook::WEBHOOKS_PROPERTY)
            .cloned()
        else {
            bail!("product {product} has no webhooks");
        };
        match url {
            None => {
                object
                    .properties
                    .remove(crate::deploy_webhook::WEBHOOKS_PROPERTY);
                object.updated = crate::now_millis();
                persist_product_object(ctx, object, &lease, false).await?;
                Ok(format!("cleared {product} webhooks"))
            }
            Some(url) => {
                let mut endpoints = parse_endpoints_json(&raw)?;
                let before = endpoints.len();
                endpoints.retain(|endpoint| endpoint.url != url);
                if endpoints.len() == before {
                    bail!("product {product} has no webhook {url}");
                }
                if endpoints.is_empty() {
                    object
                        .properties
                        .remove(crate::deploy_webhook::WEBHOOKS_PROPERTY);
                } else {
                    object.properties.insert(
                        crate::deploy_webhook::WEBHOOKS_PROPERTY.into(),
                        serde_json::to_string(&endpoints)?,
                    );
                }
                object.updated = crate::now_millis();
                persist_product_object(ctx, object, &lease, false).await?;
                Ok(format!("cleared {product} webhook {url}"))
            }
        }
    }
    .await;
    finish_product_mutation(ctx, &lease, result).await
}

/// Environment endpoints first, then each subscribed product's, one URL once.
pub async fn environment_notification_endpoints(
    ctx: &mut Ctx,
    env: &str,
) -> Result<Vec<WebhookEndpoint>> {
    let env_obj = crate::environment::environment(ctx, env).await?;
    let mut endpoints = parse_endpoints(&env_obj).unwrap_or_default();
    let Ok(subscriptions) = crate::environment::list_subscriptions(ctx, &env_obj).await else {
        return Ok(endpoints);
    };
    for sub in subscriptions {
        let product = list_product_webhooks(ctx, &sub.product)
            .await
            .unwrap_or_default();
        endpoints = union_endpoints(endpoints, product);
    }
    Ok(endpoints)
}

async fn load_product(ctx: &mut Ctx, product: &str) -> Result<Object> {
    match ctx.get(&product_id(product)).await? {
        Some(object) if object.kind == KIND_PRODUCT && object.namespace == NS => Ok(object),
        Some(_) => bail!("product {product} is not a product"),
        None => bail!("product {product} is not in the catalog"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy_webhook::WebhookEvent;
    use crate::operational_events::WebhookDelivery;

    fn endpoint(url: &str, event: WebhookEvent) -> WebhookEndpoint {
        WebhookEndpoint {
            url: url.into(),
            secret_env: "HOOK_SECRET".into(),
            events: vec![event],
            operational: Vec::new(),
            feedback: Vec::new(),
        }
    }

    fn delivery(url: &str, attempts: u32, delivered_at: Option<i64>) -> WebhookDelivery {
        WebhookDelivery {
            id: format!("{url}-{attempts}"),
            event: "apply_failed".into(),
            url: url.into(),
            state: String::new(),
            attempts,
            next_attempt_at: 0,
            delivered_at,
            last_error: String::new(),
        }
    }

    #[test]
    fn reachability_judges_each_endpoint_from_its_deliveries() {
        use crate::operational_events::FailingDeliveries;
        let none = FailingDeliveries::default();
        assert_eq!(
            reachability(&[], &[], &none).verdict,
            ReachabilityVerdict::Unconfigured
        );
        let failing = "https://hooks.example/failing";
        let healthy = "https://hooks.example/healthy";
        let deliveries = [
            delivery(failing, 1, Some(10)),
            delivery(failing, UNREACHABLE_AFTER_FAILURES, None),
            delivery(healthy, 2, None),
            delivery(healthy, 1, Some(20)),
        ];
        let both = reachability(&[failing.into(), healthy.into()], &deliveries, &none);
        assert_eq!(both.verdict, ReachabilityVerdict::Reachable);
        assert_eq!(
            both.endpoints,
            vec![
                EndpointReachability {
                    url: failing.into(),
                    verdict: ReachabilityVerdict::Unreachable,
                    consecutive_failures: UNREACHABLE_AFTER_FAILURES,
                    last_success_at: Some(10),
                },
                EndpointReachability {
                    url: healthy.into(),
                    verdict: ReachabilityVerdict::Reachable,
                    consecutive_failures: 2,
                    last_success_at: Some(20),
                },
            ]
        );
        let only_failing = reachability(&[failing.into()], &deliveries, &none);
        assert_eq!(only_failing.verdict, ReachabilityVerdict::Unreachable);
        // Deliveries cut off by the read bound may have failed past the
        // threshold, so an endpoint without a known failure is unknown.
        let truncated = FailingDeliveries {
            deliveries: Vec::new(),
            hidden_max_attempts: UNREACHABLE_AFTER_FAILURES,
        };
        let cut_off = reachability(&[failing.into(), healthy.into()], &deliveries, &truncated);
        assert_eq!(
            cut_off.endpoints[0].verdict,
            ReachabilityVerdict::Unreachable
        );
        assert_eq!(cut_off.endpoints[1].verdict, ReachabilityVerdict::Unknown);
        assert_eq!(cut_off.verdict, ReachabilityVerdict::Unknown);
    }

    #[test]
    fn union_keeps_one_url_and_merges_subscriptions() {
        let env = vec![endpoint(
            "https://hooks.example/shared",
            WebhookEvent::ApplyFailed,
        )];
        let product = vec![
            endpoint(
                "https://hooks.example/shared",
                WebhookEvent::ApplyRolledBack,
            ),
            endpoint(
                "https://hooks.example/product",
                WebhookEvent::ApplyRolledBack,
            ),
        ];
        let unioned = union_endpoints(env, product);
        assert_eq!(
            unioned
                .iter()
                .map(|endpoint| endpoint.url.as_str())
                .collect::<Vec<_>>(),
            [
                "https://hooks.example/shared",
                "https://hooks.example/product"
            ]
        );
        assert_eq!(
            unioned[0].events,
            [WebhookEvent::ApplyFailed, WebhookEvent::ApplyRolledBack]
        );
        assert_eq!(unioned[0].secret_env, "HOOK_SECRET");
    }

    #[test]
    fn contact_rejects_empty_and_control_bytes() {
        assert!(validate_contact("").is_err());
        assert!(validate_contact("   ").is_err());
        assert!(validate_contact("oncall\n").is_err());
        assert!(validate_contact("oncall@example").is_ok());
    }
}

//! Stored endpoint lists (#1306). An environment's or product's `webhooks`
//! property may hold event names a newer version wrote during a rolling
//! deploy. Readers ignore those names; writers keep every entry they did not
//! change byte for byte, so the newer version still sees its subscriptions.

use anyhow::{Context as _, Result, bail};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    FeedbackEvent, MAX_ENDPOINTS, OperationalEvent, WEBHOOKS_PROPERTY, WebhookEndpoint,
    WebhookEvent, validate_endpoint_list,
};

/// Parse a stored list, ignoring event names this version does not know.
///
/// An endpoint left with no known subscription is skipped: with empty lists
/// it would otherwise mean "every apply outcome", which it never asked for.
pub fn parse_stored_endpoints_json(raw: &str) -> Result<Vec<WebhookEndpoint>> {
    let mut endpoints = Vec::new();
    for entry in stored_entries(raw)? {
        if let Some(endpoint) = known_subscription(entry)? {
            endpoints.push(endpoint);
        }
    }
    validate_endpoint_list(&endpoints)?;
    Ok(endpoints)
}

/// The stored list with `endpoint` replacing the entry for its URL, or
/// appended. Fails, and the caller writes nothing, when the stored list does
/// not parse.
pub(crate) fn upsert_endpoint_json(
    stored: Option<&str>,
    endpoint: &WebhookEndpoint,
) -> Result<String> {
    let mut entries = match stored {
        Some(raw) => stored_entries(raw)?,
        None => Vec::new(),
    };
    let value = serde_json::to_value(endpoint)?;
    match entries
        .iter_mut()
        .find(|entry| entry_url(entry) == Some(endpoint.url.as_str()))
    {
        Some(existing) => *existing = value,
        None => entries.push(value),
    }
    if entries.len() > MAX_ENDPOINTS {
        bail!("at most {MAX_ENDPOINTS} webhook endpoints may be configured");
    }
    let rewritten = serde_json::to_string(&entries)?;
    parse_stored_endpoints_json(&rewritten)?;
    Ok(rewritten)
}

/// What is left after removing one URL from a stored list.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    /// The list has no entry for the URL.
    Absent,
    /// The URL was the last entry.
    Empty,
    /// The remaining list, other entries unchanged.
    Remaining(String),
}

/// Remove the entry for `url`. Fails when the stored list does not parse.
pub(crate) fn remove_endpoint_json(stored: &str, url: &str) -> Result<Removal> {
    let mut entries = stored_entries(stored)?;
    let before = entries.len();
    entries.retain(|entry| entry_url(entry) != Some(url));
    Ok(if entries.len() == before {
        Removal::Absent
    } else if entries.is_empty() {
        Removal::Empty
    } else {
        Removal::Remaining(serde_json::to_string(&entries)?)
    })
}

fn stored_entries(raw: &str) -> Result<Vec<Value>> {
    let entries: Vec<Value> =
        serde_json::from_str(raw).with_context(|| format!("parsing stored {WEBHOOKS_PROPERTY}"))?;
    if let Some(index) = entries.iter().position(|entry| entry_url(entry).is_none()) {
        bail!("parsing stored {WEBHOOKS_PROPERTY}: entry {index} has no url");
    }
    Ok(entries)
}

fn entry_url(entry: &Value) -> Option<&str> {
    entry.get("url")?.as_str()
}

/// `entry` with unknown event names removed, or `None` when it listed events
/// and none of them is known here.
fn known_subscription(mut entry: Value) -> Result<Option<WebhookEndpoint>> {
    let listed = keep_known::<WebhookEvent>(&mut entry, "events")
        | keep_known::<OperationalEvent>(&mut entry, "operational")
        | keep_known::<FeedbackEvent>(&mut entry, "feedback");
    let endpoint: WebhookEndpoint = serde_json::from_value(entry)
        .with_context(|| format!("parsing stored {WEBHOOKS_PROPERTY}"))?;
    let subscribes_to_nothing_known = listed
        && endpoint.events.is_empty()
        && endpoint.operational.is_empty()
        && endpoint.feedback.is_empty();
    Ok((!subscribes_to_nothing_known).then_some(endpoint))
}

/// Drop names in `entry[field]` that do not parse as `T`. True when the
/// field listed any name before.
fn keep_known<T: DeserializeOwned>(entry: &mut Value, field: &str) -> bool {
    let Some(Value::Array(names)) = entry.get_mut(field) else {
        return false;
    };
    let listed = !names.is_empty();
    names.retain(|name| serde_json::from_value::<T>(name.clone()).is_ok());
    listed
}

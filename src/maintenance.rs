//! Timezone-aware recurring maintenance windows and environment configuration.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context as _, Result, bail};
use chrono::{
    DateTime, Datelike as _, Duration, LocalResult, NaiveDate, NaiveTime, TimeZone as _, Utc,
    Weekday,
};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::{
    ACTION_CONFIGURE_MAINTENANCE, KIND_MAINTENANCE_CONFIG, NS, env_id, validate_identifier,
};
use crate::pb::sekai::Object;
use crate::pb::sekai::{Decision, ObjectChange};

const WINDOWS_PROPERTY: &str = "windows";
fn config_id(environment: &str) -> String {
    format!("tenkai:maintenance:{environment}")
}

fn revision(windows: &str) -> String {
    format!("{:x}", Sha256::digest(windows.as_bytes()))
}

enum Occurrence {
    Absent,
    Valid {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    Invalid {
        starts: Vec<DateTime<Utc>>,
        sort_at: DateTime<Utc>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub identity: String,
    pub timezone: String,
    /// ISO weekday numbers: Monday is 1 and Sunday is 7.
    pub weekdays: Vec<u32>,
    /// Local wall-clock time in HH:MM form.
    pub start: String,
    pub duration_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    Open { window: String, closes_at: i64 },
    Closed { next_opens_at: Option<i64> },
    Invalid { detail: String },
}

impl Window {
    pub fn new(
        identity: impl Into<String>,
        timezone: impl Into<String>,
        weekdays: Vec<u32>,
        start: impl Into<String>,
        duration_minutes: u32,
    ) -> Result<Self> {
        let window = Self {
            identity: identity.into(),
            timezone: timezone.into(),
            weekdays,
            start: start.into(),
            duration_minutes,
        };
        window.validate()?;
        Ok(window)
    }

    fn validate(&self) -> Result<()> {
        validate_identifier("maintenance-window identity", &self.identity)?;
        self.timezone
            .parse::<Tz>()
            .map_err(|_| anyhow::anyhow!("unknown IANA timezone {:?}", self.timezone))?;
        parse_time(&self.start)?;
        if self.weekdays.is_empty() {
            bail!("maintenance window must include at least one weekday");
        }
        let unique = self.weekdays.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != self.weekdays.len() || unique.iter().any(|day| !(1..=7).contains(day)) {
            bail!("maintenance-window weekdays must be unique ISO values from 1 through 7");
        }
        if self.duration_minutes == 0 || self.duration_minutes > 7 * 24 * 60 {
            bail!("maintenance-window duration must be between 1 and 10080 minutes");
        }
        Ok(())
    }
}

fn parse_time(value: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .with_context(|| format!("maintenance-window start {value:?} must use HH:MM"))
}

fn weekday_number(day: Weekday) -> u32 {
    day.number_from_monday()
}

fn occurrence(window: &Window, date: NaiveDate) -> Result<Occurrence, String> {
    if !window.weekdays.contains(&weekday_number(date.weekday())) {
        return Ok(Occurrence::Absent);
    }
    let tz = window
        .timezone
        .parse::<Tz>()
        .map_err(|_| format!("unknown IANA timezone {:?}", window.timezone))?;
    let start_time = parse_time(&window.start).map_err(|error| error.to_string())?;
    let local_start = date.and_time(start_time);
    match tz.from_local_datetime(&local_start) {
        LocalResult::Single(value) => {
            let start = value.with_timezone(&Utc);
            let end = start
                .checked_add_signed(Duration::minutes(i64::from(window.duration_minutes)))
                .ok_or_else(|| {
                    "maintenance window end overflows supported time range".to_string()
                })?;
            Ok(Occurrence::Valid { start, end })
        }
        LocalResult::Ambiguous(first, second) => {
            let mut starts = vec![first.with_timezone(&Utc), second.with_timezone(&Utc)];
            starts.sort();
            Ok(Occurrence::Invalid {
                sort_at: starts[0],
                starts,
                detail: format!("maintenance window start is ambiguous in {tz} on {date}"),
            })
        }
        LocalResult::None => {
            let sort_at = (1..=24 * 60)
                .find_map(|minutes| {
                    let candidate = local_start.checked_add_signed(Duration::minutes(minutes))?;
                    match tz.from_local_datetime(&candidate) {
                        LocalResult::Single(value) => Some(value.with_timezone(&Utc)),
                        LocalResult::Ambiguous(first, second) => {
                            Some(first.min(second).with_timezone(&Utc))
                        }
                        LocalResult::None => None,
                    }
                })
                .ok_or_else(|| {
                    format!("could not resolve timezone {tz} after {date} {start_time}")
                })?;
            Ok(Occurrence::Invalid {
                starts: Vec::new(),
                sort_at,
                detail: format!("maintenance window start does not exist in {tz} on {date}"),
            })
        }
    }
}

/// Evaluate all configured windows at an exact UTC instant.
///
/// An empty set means unrestricted execution. Any invalid rule fails closed.
pub fn evaluate(windows: &[Window], now: DateTime<Utc>) -> Eligibility {
    if windows.is_empty() {
        return Eligibility::Open {
            window: "unrestricted".into(),
            closes_at: i64::MAX,
        };
    }
    for window in windows {
        if let Err(error) = window.validate() {
            return Eligibility::Invalid {
                detail: error.to_string(),
            };
        }
    }

    let mut open = Vec::new();
    let mut current_invalid = None;
    for window in windows {
        let tz = window.timezone.parse::<Tz>().expect("window validated");
        let local_date = now.with_timezone(&tz).date_naive();
        for offset in -7_i64..=0 {
            let Some(date) = local_date.checked_add_signed(Duration::days(offset)) else {
                return Eligibility::Invalid {
                    detail: "maintenance window date overflows supported time range".into(),
                };
            };
            match occurrence(window, date) {
                Ok(Occurrence::Valid { start, end }) if start <= now && now < end => {
                    open.push((end, window.identity.clone()));
                }
                Ok(Occurrence::Invalid {
                    starts,
                    sort_at,
                    detail,
                }) if starts.iter().any(|start| {
                    start <= &now
                        && start
                            .checked_add_signed(Duration::minutes(i64::from(
                                window.duration_minutes,
                            )))
                            .is_some_and(|end| now < end)
                }) || (starts.is_empty()
                    && sort_at <= now
                    && sort_at
                        .checked_add_signed(Duration::minutes(i64::from(window.duration_minutes)))
                        .is_some_and(|end| now < end)) =>
                {
                    current_invalid = Some(detail);
                }
                Ok(_) => {}
                Err(detail) => return Eligibility::Invalid { detail },
            }
        }
    }
    if let Some(detail) = current_invalid {
        Eligibility::Invalid { detail }
    } else if let Some((end, identity)) = open.into_iter().max_by_key(|(end, _)| *end) {
        Eligibility::Open {
            window: identity,
            closes_at: end.timestamp_millis(),
        }
    } else {
        let mut next = Vec::new();
        for window in windows {
            let tz = window.timezone.parse::<Tz>().expect("window validated");
            let local_date = now.with_timezone(&tz).date_naive();
            for offset in 0_i64..=7 {
                let Some(date) = local_date.checked_add_signed(Duration::days(offset)) else {
                    return Eligibility::Invalid {
                        detail: "maintenance window date overflows supported time range".into(),
                    };
                };
                match occurrence(window, date) {
                    Ok(Occurrence::Valid { start, .. }) if start > now => next.push((start, None)),
                    Ok(Occurrence::Invalid {
                        starts,
                        sort_at,
                        detail,
                    }) => {
                        let candidate = starts
                            .into_iter()
                            .filter(|start| *start > now)
                            .min()
                            .or_else(|| (sort_at > now).then_some(sort_at));
                        if let Some(candidate) = candidate {
                            // A known invalid next recurrence makes the rule
                            // invalid now; fail closed until it is corrected.
                            next.push((candidate, Some(detail)));
                        }
                    }
                    Ok(_) => {}
                    Err(detail) => return Eligibility::Invalid { detail },
                }
            }
        }
        match next.into_iter().min_by_key(|(start, _)| *start) {
            Some((_, Some(detail))) => Eligibility::Invalid { detail },
            Some((start, None)) => Eligibility::Closed {
                next_opens_at: Some(start.timestamp_millis()),
            },
            None => Eligibility::Closed {
                next_opens_at: None,
            },
        }
    }
}

fn decode_configuration(object: &Object, environment: &str) -> Result<Vec<Window>> {
    if object.kind != KIND_MAINTENANCE_CONFIG {
        bail!(
            "object {} is {}, not {KIND_MAINTENANCE_CONFIG}",
            object.id,
            object.kind
        );
    }
    if object.properties.get("environment").map(String::as_str) != Some(environment) {
        bail!(
            "maintenance configuration {} has the wrong environment",
            object.id
        );
    }
    let raw = object
        .properties
        .get(WINDOWS_PROPERTY)
        .context("maintenance configuration has no windows")?;
    if object.properties.get("revision") != Some(&revision(raw)) {
        bail!(
            "maintenance configuration {} has an invalid revision",
            object.id
        );
    }
    let windows: Vec<Window> = serde_json::from_str(raw).with_context(|| {
        format!(
            "configuration {} has invalid maintenance-window JSON",
            object.id
        )
    })?;
    for window in &windows {
        window.validate().with_context(|| {
            format!(
                "configuration {} has invalid maintenance window {}",
                object.id, window.identity
            )
        })?;
    }
    Ok(windows)
}

fn has_governed_evidence(
    object: &Object,
    decisions: &[Decision],
    changes: &[ObjectChange],
) -> bool {
    let Some(correlation) = object.properties.get("last_update_correlation") else {
        return false;
    };
    let Some(decision) = decisions.iter().find(|decision| {
        decision.action == ACTION_CONFIGURE_MAINTENANCE
            && decision.reason == "execute_action"
            && decision.target_id == object.id
            && decision.evidence.get("decision").map(String::as_str) == Some("allow")
            && decision.evidence.get("correlation") == Some(correlation)
            && decision.evidence.get("environment") == object.properties.get("environment")
            && decision.evidence.get(WINDOWS_PROPERTY) == object.properties.get(WINDOWS_PROPERTY)
            && decision.evidence.get("revision") == object.properties.get("revision")
    }) else {
        return false;
    };
    let Some(correlation_change) = changes
        .iter()
        .filter(|change| {
            change.field == "properties.last_update_correlation" && change.new_value == *correlation
        })
        .max_by_key(|change| change.timestamp)
    else {
        return false;
    };
    correlation_change.new_value == *correlation
        && correlation_change.changed_by == decision.actor
        && correlation_change.timestamp <= decision.timestamp
        && decision
            .timestamp
            .saturating_sub(correlation_change.timestamp)
            <= 60_000
        && !changes.iter().any(|change| {
            matches!(
                change.field.as_str(),
                "properties.windows" | "properties.revision"
            ) && change.timestamp > correlation_change.timestamp
        })
}

async fn decode_governed_configuration(
    ctx: &mut Ctx,
    object: &Object,
    environment: &str,
) -> Result<Vec<Window>> {
    let windows = decode_configuration(object, environment)?;
    let changes = ctx
        .object_changes(&object.id)
        .await
        .context("loading maintenance-window change evidence")?;
    let correlation_change =
        object
            .properties
            .get("last_update_correlation")
            .and_then(|correlation| {
                changes
                    .iter()
                    .filter(|change| {
                        change.field == "properties.last_update_correlation"
                            && change.new_value == *correlation
                    })
                    .max_by_key(|change| change.timestamp)
            });
    let decisions = if let Some(change) = correlation_change {
        ctx.action_decisions(
            &change.changed_by,
            ACTION_CONFIGURE_MAINTENANCE,
            change.timestamp.saturating_sub(1),
        )
        .await
        .context("loading maintenance-window authorization decisions")?
    } else {
        Vec::new()
    };
    if !has_governed_evidence(object, &decisions, &changes) {
        bail!(
            "maintenance configuration {} has no matching governed-action evidence",
            object.id
        );
    }
    Ok(windows)
}

async fn replace_governed_configuration(
    ctx: &mut Ctx,
    environment: &str,
    config_id: &str,
    windows: &[Window],
) -> Result<()> {
    let encoded = serde_json::to_string(windows)?;
    let new_revision = revision(&encoded);
    let correlation = uuid::Uuid::new_v4().to_string();
    let params = HashMap::from([
        ("id".into(), config_id.into()),
        ("environment".into(), environment.into()),
        (WINDOWS_PROPERTY.into(), encoded.clone()),
        ("revision".into(), new_revision.clone()),
        ("correlation".into(), correlation.clone()),
    ]);
    match ctx
        .preview_action_result(ACTION_CONFIGURE_MAINTENANCE, params.clone())
        .await
        .context("checking maintenance-window update policy")?
    {
        result if result.decision == "allow" => {}
        result if result.decision == "require_approval" => {
            bail!(
                "maintenance-window update requires approval; deferred schedule updates are not supported"
            );
        }
        result => {
            bail!(
                "maintenance-window update was not allowed: {}",
                result.decision
            );
        }
    }
    let action_error = match ctx
        .execute_action_result(ACTION_CONFIGURE_MAINTENANCE, params)
        .await
    {
        Ok(result) if result.decision == "allow" => None,
        Ok(result) if result.decision == "require_approval" => {
            let approval_id = result.approval_id;
            ctx.deny_action(
                &approval_id,
                "Tenkai does not support deferred maintenance-window updates",
            )
            .await
            .with_context(|| {
                format!(
                    "maintenance-window update requires approval {approval_id}, and cancelling the stale update failed; do not approve it"
                )
            })?;
            bail!(
                "maintenance-window update requires approval {approval_id}; the pending update was cancelled"
            );
        }
        Ok(result) => {
            bail!(
                "maintenance-window update was not allowed: {}",
                result.decision
            );
        }
        Err(error) => Some(error.context("updating maintenance windows")),
    };
    let persisted = ctx
        .get(config_id)
        .await?
        .context("maintenance configuration disappeared during governed update")?;
    let persisted_windows = decode_governed_configuration(ctx, &persisted, environment).await;
    let persisted_matches = matches!(&persisted_windows, Ok(stored) if stored == windows);
    if persisted.properties.get("last_update_correlation") != Some(&correlation)
        || persisted.properties.get(WINDOWS_PROPERTY) != Some(&encoded)
        || persisted.properties.get("revision") != Some(&new_revision)
        || !persisted_matches
    {
        if let Some(error) = action_error {
            return match persisted_windows {
                Ok(_) => Err(error.context("the requested configuration was not committed")),
                Err(evidence) => Err(error.context(format!(
                    "the requested configuration lacks valid commit evidence: {evidence}"
                ))),
            };
        }
        persisted_windows?;
        bail!("maintenance-window configuration was not persisted as requested");
    }
    persisted_windows?;
    Ok(())
}

pub async fn ensure_configuration(ctx: &mut Ctx, environment: &str) -> Result<()> {
    validate_identifier("environment", environment)?;
    let owner = format!("maintenance-initialize:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        let id = config_id(environment);
        if let Some(existing) = ctx.get(&id).await? {
            if existing.properties.contains_key("last_update_correlation") {
                decode_governed_configuration(ctx, &existing, environment).await?;
                return Ok(());
            }
            let windows = decode_configuration(&existing, environment)?;
            if !windows.is_empty() {
                bail!("unaudited maintenance configuration {id} is not empty");
            }
            return replace_governed_configuration(ctx, environment, &id, &windows).await;
        }
        let encoded = "[]".to_string();
        let now = crate::now_millis();
        let object = Object {
            id: id.clone(),
            kind: KIND_MAINTENANCE_CONFIG.into(),
            name: format!("{environment} maintenance windows"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), environment.into()),
                (WINDOWS_PROPERTY.into(), encoded.clone()),
                ("revision".into(), revision(&encoded)),
            ]),
            created: now,
            updated: now,
        };
        match ctx.create_once(object).await {
            Ok(_) => {}
            Err(status) if status.code() == tonic::Code::AlreadyExists => {}
            Err(status)
                if status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE") => {}
            Err(status) => return Err(status.into()),
        }
        let existing = ctx
            .get(&id)
            .await?
            .context("maintenance configuration disappeared during initialization")?;
        let windows = decode_configuration(&existing, environment)?;
        if !windows.is_empty() {
            bail!("unaudited maintenance configuration {id} is not empty");
        }
        replace_governed_configuration(ctx, environment, &id, &windows).await
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing maintenance initialization lease also failed: {unlock}"
        ))),
        (Ok(()), Err(error)) => Err(error.context("releasing maintenance initialization lease")),
    }
}

pub async fn migrate_all(ctx: &mut Ctx) -> Result<usize> {
    let environments = ctx.list_kind(crate::ontology::KIND_ENVIRONMENT).await?;
    for environment in &environments {
        ensure_configuration(ctx, &environment.name).await?;
    }
    Ok(environments.len())
}

/// Explicitly replace an invalid or incomplete configuration with an empty,
/// governed schedule. Existing window data is deliberately not trusted.
pub async fn repair(ctx: &mut Ctx, environment: &str) -> Result<String> {
    validate_identifier("environment", environment)?;
    let owner = format!("maintenance-repair:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        let id = config_id(environment);
        ctx.get(&env_id(environment))
            .await?
            .with_context(|| format!("environment {environment} is not registered"))?;
        ctx.get(&id)
            .await?
            .with_context(|| format!("maintenance configuration for {environment} is missing"))?;
        replace_governed_configuration(ctx, environment, &id, &[]).await?;
        Ok(format!(
            "maintenance configuration for {environment} repaired with an empty schedule"
        ))
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing maintenance repair lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing maintenance repair lease")),
    }
}

pub async fn list(ctx: &mut Ctx, environment: &str) -> Result<Vec<Window>> {
    validate_identifier("environment", environment)?;
    ctx.get(&env_id(environment))
        .await?
        .with_context(|| format!("environment {environment} is not registered"))?;
    match ctx.get(&config_id(environment)).await? {
        Some(object) => decode_governed_configuration(ctx, &object, environment).await,
        None => bail!(
            "maintenance configuration for {environment} is missing; run `tenkaictl env add {environment}` to initialize it"
        ),
    }
}

pub async fn set(ctx: &mut Ctx, environment: &str, window: Window) -> Result<String> {
    window.validate()?;
    update(ctx, environment, |windows| {
        windows.retain(|current| current.identity != window.identity);
        windows.push(window.clone());
        windows.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(format!(
            "maintenance window {} configured for {environment}",
            window.identity
        ))
    })
    .await
}

pub async fn remove(ctx: &mut Ctx, environment: &str, identity: &str) -> Result<String> {
    validate_identifier("maintenance-window identity", identity)?;
    update(ctx, environment, |windows| {
        let before = windows.len();
        windows.retain(|window| window.identity != identity);
        if windows.len() == before {
            bail!("maintenance window {identity} is not configured for {environment}");
        }
        Ok(format!(
            "maintenance window {identity} removed from {environment}"
        ))
    })
    .await
}

async fn update(
    ctx: &mut Ctx,
    environment: &str,
    change: impl FnOnce(&mut Vec<Window>) -> Result<String>,
) -> Result<String> {
    validate_identifier("environment", environment)?;
    let owner = format!("maintenance-update:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let result = async {
        let config_id = config_id(environment);
        let object = ctx
            .get(&config_id)
            .await?
            .with_context(|| {
                format!(
                    "maintenance configuration for {environment} is not initialized; rerun `tenkaictl env add {environment}`"
                )
            })?;
        let mut windows = decode_governed_configuration(ctx, &object, environment).await?;
        let message = change(&mut windows)?;
        replace_governed_configuration(ctx, environment, &config_id, &windows).await?;
        Ok::<_, anyhow::Error>(message)
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing environment maintenance update lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing environment maintenance update lease")),
    }
}

pub fn weekday_values(value: &str) -> Result<Vec<u32>> {
    let aliases = HashMap::from([
        ("mon", 1),
        ("tue", 2),
        ("wed", 3),
        ("thu", 4),
        ("fri", 5),
        ("sat", 6),
        ("sun", 7),
    ]);
    let mut days = Vec::new();
    for raw in value.split(',') {
        let day = raw.trim().to_ascii_lowercase();
        let Some(number) = aliases.get(day.as_str()) else {
            bail!("unknown weekday {raw:?}; use mon,tue,wed,thu,fri,sat,sun");
        };
        days.push(*number);
    }
    let unique = days.iter().copied().collect::<BTreeSet<_>>();
    if days.is_empty() || unique.len() != days.len() {
        bail!("maintenance-window weekdays must be non-empty and unique");
    }
    Ok(days)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }

    #[test]
    fn evaluates_recurring_window_in_its_timezone() {
        let windows = [Window::new("weekday", "Europe/Berlin", vec![1], "09:00", 120).unwrap()];
        assert!(matches!(
            evaluate(&windows, at("2026-07-20T08:30:00Z")),
            Eligibility::Open { ref window, .. } if window == "weekday"
        ));
        assert!(matches!(
            evaluate(&windows, at("2026-07-20T06:30:00Z")),
            Eligibility::Closed { .. }
        ));
    }

    #[test]
    fn supports_windows_crossing_midnight() {
        let windows = [Window::new("overnight", "UTC", vec![5], "23:00", 180).unwrap()];
        assert!(matches!(
            evaluate(&windows, at("2026-07-18T01:00:00Z")),
            Eligibility::Open { .. }
        ));
    }

    #[test]
    fn ambiguous_dst_boundary_fails_closed() {
        let windows = [Window::new("dst", "Europe/Berlin", vec![7], "02:30", 30).unwrap()];
        assert!(matches!(
            evaluate(&windows, at("2026-10-25T01:00:00Z")),
            Eligibility::Invalid { ref detail } if detail.contains("ambiguous")
        ));
    }

    #[test]
    fn future_invalid_recurrence_fails_closed_when_no_window_is_open() {
        let windows = [Window::new("dst", "Europe/Berlin", vec![7], "02:30", 30).unwrap()];
        assert!(matches!(
            evaluate(&windows, at("2026-03-23T00:00:00Z")),
            Eligibility::Invalid { ref detail } if detail.contains("does not exist")
        ));
    }

    #[test]
    fn future_dst_ambiguity_does_not_close_current_valid_occurrence() {
        let windows = [Window::new("dst", "Europe/Berlin", vec![7], "02:30", 60).unwrap()];
        assert!(matches!(
            evaluate(&windows, at("2026-10-18T00:45:00Z")),
            Eligibility::Open { .. }
        ));
    }

    #[test]
    fn active_dst_ambiguity_overrides_another_open_window() {
        let windows = [
            Window::new("always-open", "UTC", vec![7], "00:00", 24 * 60).unwrap(),
            Window::new("dst", "Europe/Berlin", vec![7], "02:30", 60).unwrap(),
        ];
        assert!(matches!(
            evaluate(&windows, at("2026-10-25T00:45:00Z")),
            Eligibility::Invalid { ref detail } if detail.contains("ambiguous")
        ));
    }

    #[test]
    fn active_skipped_dst_start_overrides_another_open_window() {
        let windows = [
            Window::new("always-open", "UTC", vec![7], "00:00", 24 * 60).unwrap(),
            Window::new("dst", "Europe/Berlin", vec![7], "02:30", 60).unwrap(),
        ];
        assert!(matches!(
            evaluate(&windows, at("2026-03-29T01:15:00Z")),
            Eligibility::Invalid { ref detail } if detail.contains("does not exist")
        ));
    }

    #[test]
    fn duration_is_elapsed_time_across_dst_changes() {
        let windows = [Window::new("spring", "Europe/Berlin", vec![7], "01:00", 120).unwrap()];
        assert!(matches!(
            evaluate(&windows, at("2026-03-29T01:30:00Z")),
            Eligibility::Open { closes_at, .. } if closes_at == at("2026-03-29T02:00:00Z").timestamp_millis()
        ));
    }

    #[test]
    fn rejects_invalid_rules() {
        assert!(Window::new("bad", "Mars/Olympus", vec![1], "09:00", 60).is_err());
        assert!(Window::new("bad", "UTC", vec![1, 1], "09:00", 60).is_err());
        assert!(weekday_values("mon,funday").is_err());
    }

    #[test]
    fn maintenance_configuration_decodes() {
        let configuration = Object {
            id: config_id("prod"),
            kind: KIND_MAINTENANCE_CONFIG.into(),
            properties: HashMap::from([
                ("environment".into(), "prod".into()),
                (WINDOWS_PROPERTY.into(), "[]".into()),
                ("revision".into(), revision("[]")),
            ]),
            ..Default::default()
        };
        assert_eq!(
            decode_configuration(&configuration, "prod").unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn initial_unrestricted_configuration_requires_governed_bootstrap() {
        let configuration = Object {
            id: config_id("prod"),
            kind: KIND_MAINTENANCE_CONFIG.into(),
            properties: HashMap::from([
                ("environment".into(), "prod".into()),
                (WINDOWS_PROPERTY.into(), "[]".into()),
                ("revision".into(), revision("[]")),
            ]),
            ..Default::default()
        };
        assert!(!has_governed_evidence(&configuration, &[], &[]));
        assert!(!has_governed_evidence(
            &configuration,
            &[],
            &[ObjectChange {
                field: "properties.windows".into(),
                new_value: "[]".into(),
                ..Default::default()
            }]
        ));
    }

    #[test]
    fn governed_configuration_rejects_later_direct_mutation() {
        let encoded =
            serde_json::to_string(&[Window::new("weekday", "UTC", vec![1], "09:00", 60).unwrap()])
                .unwrap();
        let correlation = "update-1";
        let configuration = Object {
            id: config_id("prod"),
            kind: KIND_MAINTENANCE_CONFIG.into(),
            properties: HashMap::from([
                ("environment".into(), "prod".into()),
                (WINDOWS_PROPERTY.into(), encoded.clone()),
                ("revision".into(), revision(&encoded)),
                ("last_update_correlation".into(), correlation.into()),
            ]),
            ..Default::default()
        };
        let decision = Decision {
            actor: "operator".into(),
            action: ACTION_CONFIGURE_MAINTENANCE.into(),
            reason: "execute_action".into(),
            evidence: HashMap::from([
                ("decision".into(), "allow".into()),
                ("correlation".into(), correlation.into()),
                ("environment".into(), "prod".into()),
                (WINDOWS_PROPERTY.into(), encoded.clone()),
                ("revision".into(), revision(&encoded)),
            ]),
            target_id: configuration.id.clone(),
            timestamp: 100,
            ..Default::default()
        };
        let action_change = ObjectChange {
            field: "properties.last_update_correlation".into(),
            new_value: correlation.into(),
            changed_by: "operator".into(),
            timestamp: 90,
            ..Default::default()
        };
        let older_change = ObjectChange {
            field: "properties.last_update_correlation".into(),
            new_value: "update-0".into(),
            changed_by: "operator".into(),
            timestamp: 50,
            ..Default::default()
        };
        assert!(has_governed_evidence(
            &configuration,
            std::slice::from_ref(&decision),
            &[older_change.clone(), action_change.clone()]
        ));

        let direct_change = ObjectChange {
            field: "properties.windows".into(),
            changed_by: "operator".into(),
            timestamp: 101,
            ..Default::default()
        };
        assert!(!has_governed_evidence(
            &configuration,
            &[decision],
            &[older_change, direct_change, action_change]
        ));
    }
}

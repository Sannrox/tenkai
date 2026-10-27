//! Typed, cursor-resumable change events for fleet, plan, and release updates (#610).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default page size for `GET /v1/events`.
pub const DEFAULT_PAGE_SIZE: usize = 50;
/// Hard cap so a slow consumer cannot pull an unbounded buffer.
pub const MAX_PAGE_SIZE: usize = 100;

/// Closed set of change-event kinds advertised on the HTTP contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeEventKind {
    PlanCreated,
    PlanApproved,
    PlanApplied,
    TargetFailed,
    TargetHeld,
    TargetRetried,
    HoldSet,
    HoldReleased,
    ReleasePublished,
    ReleasePromoted,
    ReleaseRecalled,
    CompatibilityResultRecorded,
}

impl ChangeEventKind {
    /// Wire names of every kind this version reads; stores skip the rest.
    pub fn names() -> Vec<&'static str> {
        Self::ALL.iter().map(|kind| kind.as_str()).collect()
    }

    /// Every kind the stream may emit. Contract tests iterate this list.
    pub const ALL: &[Self] = &[
        Self::PlanCreated,
        Self::PlanApproved,
        Self::PlanApplied,
        Self::TargetFailed,
        Self::TargetHeld,
        Self::TargetRetried,
        Self::HoldSet,
        Self::HoldReleased,
        Self::ReleasePublished,
        Self::ReleasePromoted,
        Self::ReleaseRecalled,
        Self::CompatibilityResultRecorded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlanCreated => "plan_created",
            Self::PlanApproved => "plan_approved",
            Self::PlanApplied => "plan_applied",
            Self::TargetFailed => "target_failed",
            Self::TargetHeld => "target_held",
            Self::TargetRetried => "target_retried",
            Self::HoldSet => "hold_set",
            Self::HoldReleased => "hold_released",
            Self::ReleasePublished => "release_published",
            Self::ReleasePromoted => "release_promoted",
            Self::ReleaseRecalled => "release_recalled",
            Self::CompatibilityResultRecorded => "compatibility_result_recorded",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ChangeStreamError> {
        match value {
            "plan_created" => Ok(Self::PlanCreated),
            "plan_approved" => Ok(Self::PlanApproved),
            "plan_applied" => Ok(Self::PlanApplied),
            "target_failed" => Ok(Self::TargetFailed),
            "target_held" => Ok(Self::TargetHeld),
            "target_retried" => Ok(Self::TargetRetried),
            "hold_set" => Ok(Self::HoldSet),
            "hold_released" => Ok(Self::HoldReleased),
            "release_published" => Ok(Self::ReleasePublished),
            "release_promoted" => Ok(Self::ReleasePromoted),
            "release_recalled" => Ok(Self::ReleaseRecalled),
            "compatibility_result_recorded" => Ok(Self::CompatibilityResultRecorded),
            other => Err(ChangeStreamError::UnknownKind(other.into())),
        }
    }
}

/// One durable change. `cursor` is the opaque resume token (monotonic sequence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChangeEvent {
    pub cursor: String,
    pub occurred_at: i64,
    pub kind: ChangeEventKind,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub environment: Option<String>,
}

impl ChangeEvent {
    pub fn new(
        seq: i64,
        occurred_at: i64,
        kind: ChangeEventKind,
        resource: impl Into<String>,
        environment_id: &str,
    ) -> Self {
        let environment = environment_id.trim();
        Self {
            cursor: seq.to_string(),
            occurred_at,
            kind,
            resource: resource.into(),
            environment: if environment.is_empty() {
                None
            } else {
                Some(environment.to_string())
            },
        }
    }
}

/// Bounded page of change events plus the cursor to resume from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChangeEventPage {
    pub events: Vec<ChangeEvent>,
    pub next_cursor: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChangeStreamError {
    #[error("change-event cursor is invalid")]
    InvalidCursor,
    #[error("change-event page limit is invalid")]
    InvalidLimit,
    #[error("unknown change-event kind {0:?}")]
    UnknownKind(String),
}

/// Parse `cursor` query (`None` or empty starts at the beginning).
pub fn parse_cursor(raw: Option<&str>) -> Result<i64, ChangeStreamError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(0),
        Some(raw) => raw
            .parse::<i64>()
            .map_err(|_| ChangeStreamError::InvalidCursor),
    }
    .and_then(|cursor| {
        if cursor < 0 {
            Err(ChangeStreamError::InvalidCursor)
        } else {
            Ok(cursor)
        }
    })
}

/// Parse `limit` query, defaulting and clamping for backpressure.
pub fn parse_limit(raw: Option<&str>) -> Result<usize, ChangeStreamError> {
    let limit = match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => DEFAULT_PAGE_SIZE,
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| ChangeStreamError::InvalidLimit)?,
    };
    if limit == 0 {
        return Err(ChangeStreamError::InvalidLimit);
    }
    Ok(limit.min(MAX_PAGE_SIZE))
}

/// High-water cursor after a page: last event, else the request cursor.
pub fn next_cursor(events: &[ChangeEvent], request_cursor: i64) -> String {
    events
        .last()
        .map(|event| event.cursor.clone())
        .unwrap_or_else(|| request_cursor.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_round_trips() {
        for kind in ChangeEventKind::ALL {
            assert_eq!(ChangeEventKind::parse(kind.as_str()).unwrap(), *kind);
        }
        assert_eq!(ChangeEventKind::ALL.len(), 12);
        assert!(ChangeEventKind::parse("webhook").is_err());
    }

    #[test]
    fn cursor_and_limit_parse_for_resume_and_backpressure() {
        assert_eq!(parse_cursor(None).unwrap(), 0);
        assert_eq!(parse_cursor(Some("7")).unwrap(), 7);
        assert!(parse_cursor(Some("-1")).is_err());
        assert!(parse_cursor(Some("nope")).is_err());
        assert_eq!(parse_limit(None).unwrap(), DEFAULT_PAGE_SIZE);
        assert_eq!(parse_limit(Some("3")).unwrap(), 3);
        assert_eq!(parse_limit(Some("9999")).unwrap(), MAX_PAGE_SIZE);
        assert!(parse_limit(Some("0")).is_err());
        let event = ChangeEvent::new(9, 1, ChangeEventKind::PlanCreated, "plan", "prod");
        assert_eq!(next_cursor(&[], 4), "4");
        assert_eq!(next_cursor(&[event], 4), "9");
    }
}

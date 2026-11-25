//! Debug session records (ADR 0061 §1, §6).
//!
//! A session is a durable catalog object of kind
//! [`crate::ontology::KIND_DEBUG_SESSION`], so every replica and both stores
//! (SQLite and the Postgres hub partition) read the same record. The JSON
//! record in property `record` is the source of truth; `environment`,
//! `instance` and `state` are copied out for lookup.
//!
//! The server never extends a session past `not_after`. A session still
//! `open` once its bound has passed is reported `expired`; the first read
//! that sees it records the expiry (see [`DebugSession::expire_if_due`]).
//!
//! A runtime that names the `debug_session` capability picks an open session
//! up with its work (#1557). The first runtime instance to do so owns it:
//! the attachment, and later that runtime's close report, are create-once
//! objects of kind [`crate::ontology::KIND_DEBUG_SESSION_RUNTIME`], joined
//! into [`DebugSession::runtime`] on read and never stored in the record.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::{KIND_DEBUG_SESSION, KIND_DEBUG_SESSION_RUNTIME, NS};
use crate::pb::sekai::Object;

/// Record format written into property `record`.
const RECORD_FORMAT: u32 = 1;

/// Access a session grants. Write needs a live elevation (#1560).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebugSessionMode {
    Read,
}

/// Lifecycle of a session. `closed` and `expired` are final.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebugSessionState {
    Open,
    Closed,
    Expired,
}

impl DebugSessionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }
}

/// A debug session as stored and as returned by the management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DebugSession {
    pub id: String,
    pub environment: String,
    pub instance: String,
    /// The human principal that opened the session.
    pub subject: String,
    /// The audit principal: subject and every delegating actor.
    pub opened_by: String,
    pub mode: DebugSessionMode,
    pub reason: String,
    pub opened_at: i64,
    /// Unix ms after which the session is over, whoever notices first.
    pub not_after: i64,
    pub state: DebugSessionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub closed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub closed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub close_reason: Option<String>,
    /// The runtime holding the session; absent until one picks it up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub runtime: Option<DebugSessionRuntime>,
}

/// The runtime instance a session reached, and when it closed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DebugSessionRuntime {
    pub instance: String,
    pub attached_at: i64,
    /// When the runtime reported closing the session on its own clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub closed_at: Option<i64>,
}

/// What a runtime did with a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeEvent {
    Attached,
    Closed,
}

impl RuntimeEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Closed => "closed",
        }
    }
}

/// Stored envelope around [`DebugSession`]; a newer format is refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u32,
    session: DebugSession,
}

/// Catalog object id of session `id`.
pub fn object_id(id: &str) -> String {
    format!("tenkai:debug-session:{id}")
}

impl DebugSession {
    /// Whether the bound has passed for a session still marked open.
    pub fn is_due(&self, now: i64) -> bool {
        self.state == DebugSessionState::Open && now >= self.not_after
    }

    /// Mark a due session expired at its bound. Returns whether it changed.
    pub fn expire_if_due(&mut self, now: i64) -> bool {
        if !self.is_due(now) {
            return false;
        }
        self.state = DebugSessionState::Expired;
        self.closed_at = Some(self.not_after);
        self.close_reason = Some("bound reached".into());
        true
    }

    fn to_object(&self) -> Result<Object> {
        // The runtime view lives in its own objects; the record never holds it.
        let session = DebugSession {
            runtime: None,
            ..self.clone()
        };
        let record = serde_json::to_string(&Record {
            format: RECORD_FORMAT,
            session,
        })
        .context("encoding debug session")?;
        Ok(Object {
            id: object_id(&self.id),
            kind: KIND_DEBUG_SESSION.into(),
            name: format!("debug session {}", self.id),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), self.environment.clone()),
                ("instance".into(), self.instance.clone()),
                ("state".into(), self.state.as_str().into()),
                ("record".into(), record),
            ]),
            created: self.opened_at,
            updated: crate::now_millis(),
        })
    }

    fn from_object(object: &Object) -> Result<Self> {
        let raw = object
            .properties
            .get("record")
            .with_context(|| format!("debug session {} has no record", object.id))?;
        let record: Record = serde_json::from_str(raw)
            .with_context(|| format!("debug session {} record is unreadable", object.id))?;
        anyhow::ensure!(
            record.format == RECORD_FORMAT,
            "debug session {} has record format {}, this release reads {RECORD_FORMAT}",
            object.id,
            record.format
        );
        Ok(record.session)
    }
}

/// Create `session`; fails when its id already exists.
pub async fn create(ctx: &mut Ctx, session: &DebugSession) -> Result<()> {
    ctx.create_once(session.to_object()?)
        .await
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

/// Overwrite `session` (state changes only; the id stays).
pub async fn save(ctx: &mut Ctx, session: &DebugSession) -> Result<()> {
    ctx.put(session.to_object()?).await.map(|_| ())
}

/// Session `id` with its runtime view, if it exists.
pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Option<DebugSession>> {
    let Some(object) = ctx.get(&object_id(id)).await? else {
        return Ok(None);
    };
    let mut session = DebugSession::from_object(&object)?;
    let mut markers = Vec::new();
    for event in [RuntimeEvent::Attached, RuntimeEvent::Closed] {
        markers.extend(ctx.get(&marker_id(id, event)).await?);
    }
    join_runtime(std::slice::from_mut(&mut session), &markers);
    Ok(Some(session))
}

/// Sessions of `environment`, or of every environment, newest first.
pub async fn list(ctx: &mut Ctx, environment: Option<&str>) -> Result<Vec<DebugSession>> {
    let (objects, markers) = match environment {
        Some(environment) => (
            ctx.find_by_property(KIND_DEBUG_SESSION, "environment", environment)
                .await?,
            ctx.find_by_property(KIND_DEBUG_SESSION_RUNTIME, "environment", environment)
                .await?,
        ),
        None => (
            ctx.list_kind(KIND_DEBUG_SESSION).await?,
            ctx.list_kind(KIND_DEBUG_SESSION_RUNTIME).await?,
        ),
    };
    let mut sessions = objects
        .iter()
        .map(DebugSession::from_object)
        .collect::<Result<Vec<_>>>()?;
    join_runtime(&mut sessions, &markers);
    sessions.sort_by(|a, b| b.opened_at.cmp(&a.opened_at).then(a.id.cmp(&b.id)));
    Ok(sessions)
}

/// Attach `session` to runtime `instance` unless another instance attached
/// it first. Returns the instance that owns the session.
pub async fn attach(ctx: &mut Ctx, session: &DebugSession, instance: &str) -> Result<String> {
    let marker = runtime_marker(
        session,
        RuntimeEvent::Attached,
        instance,
        crate::now_millis(),
    );
    match ctx.create_once(marker).await {
        Ok(_) => Ok(instance.to_owned()),
        Err(error) if crate::client::is_unique_conflict(&error) => {
            let owner = ctx
                .get(&marker_id(&session.id, RuntimeEvent::Attached))
                .await?
                .and_then(|object| object.properties.get("runtime_instance").cloned())
                .with_context(|| format!("debug session {} lost its attachment", session.id))?;
            Ok(owner)
        }
        Err(error) => Err(error.into()),
    }
}

/// Record that runtime `instance` closed `session` at `closed_at` on its
/// clock. Returns false when a close was already recorded.
pub async fn record_runtime_close(
    ctx: &mut Ctx,
    session: &DebugSession,
    instance: &str,
    closed_at: i64,
) -> Result<bool> {
    let marker = runtime_marker(session, RuntimeEvent::Closed, instance, closed_at);
    match ctx.create_once(marker).await {
        Ok(_) => Ok(true),
        Err(error) if crate::client::is_unique_conflict(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn marker_id(id: &str, event: RuntimeEvent) -> String {
    format!("{}:{}", object_id(id), event.as_str())
}

/// The marker of `event`; `at` is when it happened, on the clock of
/// whoever saw it (the runtime's, for a close).
fn runtime_marker(session: &DebugSession, event: RuntimeEvent, instance: &str, at: i64) -> Object {
    let now = crate::now_millis();
    Object {
        id: marker_id(&session.id, event),
        kind: KIND_DEBUG_SESSION_RUNTIME.into(),
        name: format!("debug session {} {}", session.id, event.as_str()),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("session".into(), session.id.clone()),
            ("environment".into(), session.environment.clone()),
            ("event".into(), event.as_str().into()),
            ("runtime_instance".into(), instance.into()),
            ("at".into(), at.to_string()),
        ]),
        created: now,
        updated: now,
    }
}

/// Fill each session's runtime view from its markers. A close marker
/// without an attachment cannot be written, so it is ignored.
fn join_runtime(sessions: &mut [DebugSession], markers: &[Object]) {
    let field = |object: &Object, name: &str| object.properties.get(name).cloned();
    for session in sessions {
        let event_of = |event: RuntimeEvent| {
            markers.iter().find(|object| {
                field(object, "session").as_deref() == Some(session.id.as_str())
                    && field(object, "event").as_deref() == Some(event.as_str())
            })
        };
        let at = |object: &Object| field(object, "at").and_then(|at| at.parse().ok());
        session.runtime = event_of(RuntimeEvent::Attached).map(|attached| DebugSessionRuntime {
            instance: field(attached, "runtime_instance").unwrap_or_default(),
            attached_at: at(attached).unwrap_or(attached.created),
            closed_at: event_of(RuntimeEvent::Closed).and_then(at),
        });
    }
}

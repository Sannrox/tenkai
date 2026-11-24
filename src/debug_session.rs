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

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::ontology::{KIND_DEBUG_SESSION, NS};
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
        let record = serde_json::to_string(&Record {
            format: RECORD_FORMAT,
            session: self.clone(),
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

pub async fn load(ctx: &mut Ctx, id: &str) -> Result<Option<DebugSession>> {
    ctx.get(&object_id(id))
        .await?
        .map(|object| DebugSession::from_object(&object))
        .transpose()
}

/// Sessions of `environment`, or of every environment, newest first.
pub async fn list(ctx: &mut Ctx, environment: Option<&str>) -> Result<Vec<DebugSession>> {
    let objects = match environment {
        Some(environment) => {
            ctx.find_by_property(KIND_DEBUG_SESSION, "environment", environment)
                .await?
        }
        None => ctx.list_kind(KIND_DEBUG_SESSION).await?,
    };
    let mut sessions = objects
        .iter()
        .map(DebugSession::from_object)
        .collect::<Result<Vec<_>>>()?;
    sessions.sort_by(|a, b| b.opened_at.cmp(&a.opened_at).then(a.id.cmp(&b.id)));
    Ok(sessions)
}

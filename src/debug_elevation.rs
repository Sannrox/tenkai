//! Quorum-approved write access in a debug session (ADR 0061 §3, §4, #1560).
//!
//! A human with `debug` requests elevation of an open session with a reason.
//! Other humans approve it by signing a [`DebugElevationStatement`] with a
//! plan-approval key; the environment's `debug_elevate` quorum counts those
//! approvals, never the requester's own. Once the quorum is met the
//! elevation is live until its own bound, the session's bound, a revocation,
//! or the session's end, whichever comes first.
//!
//! Every fact is a create-once catalog object of kind
//! [`crate::ontology::KIND_DEBUG_ELEVATION`]: the request, one approval per
//! signing key, the activation, and the revocation. Concurrent approvers and
//! a racing close never overwrite each other, and the first activation wins.
//! The session record itself never changes, so a release that predates
//! elevation reads every session as read-only.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::debug_session::{DebugSession, DebugSessionState};
use crate::ontology::{KIND_DEBUG_ELEVATION, NS};
use crate::pb::record::Object;
use crate::plan_approval::{
    ApprovalEnvelope, CountedApproval, QuorumTally, SignedApproval, count_quorum,
};
use crate::signature_verification::{self, TrustRootKind, TrustRoots, TrustedSigner};

/// Envelope schema of an elevation approval.
pub const APPROVAL_SCHEMA: &str = "tenkai.debug-elevation-approval.v1";
/// Signing domain; a plan approval's signature never verifies as this.
const APPROVAL_DOMAIN: &[u8] = b"TENKAI-DEBUG-ELEVATION-APPROVAL-V1\0";
/// The only purpose an elevation approval carries.
pub const APPROVAL_PURPOSE: &str = "debug_elevate";
/// Elevation length when the request names none: 30 minutes.
pub const DEFAULT_ELEVATION_MS: i64 = 30 * 60 * 1_000;
/// Record format written into property `record`.
const RECORD_FORMAT: u32 = 1;

/// What an approver signs: one elevation of one session in one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugElevationStatement {
    pub session: String,
    pub elevation: String,
    pub environment: String,
    /// Always [`APPROVAL_PURPOSE`].
    pub purpose: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// A signed elevation approval.
pub type DebugElevationEnvelope = ApprovalEnvelope<DebugElevationStatement>;

impl SignedApproval for DebugElevationStatement {
    const SCHEMA: &'static str = APPROVAL_SCHEMA;
    const KIND: TrustRootKind = TrustRootKind::PlanApproval;

    /// Frozen: stored approvals were signed over exactly these bytes.
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.purpose != APPROVAL_PURPOSE {
            bail!("debug elevation approval purpose must be {APPROVAL_PURPOSE}");
        }
        crate::ontology::validate_opaque_identifier("debug session", &self.session)?;
        crate::ontology::validate_opaque_identifier("debug elevation", &self.elevation)?;
        crate::ontology::validate_identifier("approval environment", &self.environment)?;
        if self.expires_at <= self.issued_at {
            bail!("debug elevation approval expiry must be after its issue time");
        }
        let mut bytes = APPROVAL_DOMAIN.to_vec();
        for value in [
            self.session.as_bytes(),
            self.elevation.as_bytes(),
            self.environment.as_bytes(),
            self.purpose.as_bytes(),
        ] {
            signature_verification::push_len_prefixed(&mut bytes, value);
        }
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(bytes)
    }

    fn issued_at(&self) -> i64 {
        self.issued_at
    }

    fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Where an elevation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebugElevationState {
    /// Waiting for its quorum.
    Pending,
    /// Write commands run.
    Active,
    /// Over: revoked, bound reached, or the session ended. Final.
    Ended,
}

/// One counted or collected approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DebugElevationApproval {
    pub identity: String,
    pub key_id: String,
    pub approved_at: i64,
}

/// An elevation as returned by the management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DebugElevation {
    pub id: String,
    pub session: String,
    pub environment: String,
    /// The human principal that asked; its own approval never counts.
    pub requested_by: String,
    /// The audit principal of the request.
    pub requester: String,
    pub reason: String,
    pub requested_at: i64,
    /// Requested length, counted from activation.
    pub duration_ms: i64,
    pub state: DebugElevationState,
    /// Approvals collected so far, whether or not they still count.
    pub approvals: Vec<DebugElevationApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub active_from: Option<i64>,
    /// When write access ends, once active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub not_after: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub ended_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub end_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub revoked_by: Option<String>,
}

/// The stored request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationRequest {
    pub id: String,
    pub session: String,
    pub environment: String,
    pub requested_by: String,
    pub requester: String,
    pub reason: String,
    pub requested_at: i64,
    pub duration_ms: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u32,
    request: ElevationRequest,
}

/// A request with every fact recorded against it.
#[derive(Debug, Clone)]
pub struct StoredElevation {
    pub request: ElevationRequest,
    /// Collected envelopes and when each was collected.
    pub approvals: Vec<(DebugElevationEnvelope, i64)>,
    /// When the quorum was met, and the bound it set.
    pub active: Option<(i64, i64)>,
    /// Who revoked it, why, and when.
    pub revoked: Option<(String, String, i64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Requested,
    Approval,
    Active,
    Revoked,
}

impl Event {
    fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approval => "approval",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

fn object_id(elevation: &str) -> String {
    format!("tenkai:debug-elevation:{elevation}")
}

fn fact(request: &ElevationRequest, id: String, event: Event, at: i64) -> Object {
    Object {
        id,
        kind: KIND_DEBUG_ELEVATION.into(),
        name: format!("debug elevation {} {}", request.id, event.as_str()),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("session".into(), request.session.clone()),
            ("environment".into(), request.environment.clone()),
            ("elevation".into(), request.id.clone()),
            ("event".into(), event.as_str().into()),
            ("at".into(), at.to_string()),
        ]),
        created: at,
        updated: at,
    }
}

/// Create-once; true when this call wrote it.
async fn create_fact(ctx: &mut Ctx, object: Object) -> Result<bool> {
    match ctx.create_once(object).await {
        Ok(_) => Ok(true),
        Err(error) if crate::client::is_unique_conflict(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Store a new request.
pub async fn create_request(ctx: &mut Ctx, request: &ElevationRequest) -> Result<()> {
    let mut object = fact(
        request,
        object_id(&request.id),
        Event::Requested,
        request.requested_at,
    );
    let record = serde_json::to_string(&Record {
        format: RECORD_FORMAT,
        request: request.clone(),
    })
    .context("encoding debug elevation")?;
    object.properties.insert("record".into(), record);
    ctx.create_once(object)
        .await
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

/// Collect `envelope`, once per signing key. True when it is new.
pub async fn add_approval(
    ctx: &mut Ctx,
    request: &ElevationRequest,
    envelope: &DebugElevationEnvelope,
    at: i64,
) -> Result<bool> {
    let mut object = fact(
        request,
        format!("{}:approval:{}", object_id(&request.id), envelope.key_id),
        Event::Approval,
        at,
    );
    object.properties.insert(
        "envelope".into(),
        serde_json::to_string(envelope).context("encoding debug elevation approval")?,
    );
    create_fact(ctx, object).await
}

/// Record that the quorum was met at `at`, live until `not_after`. False
/// when an activation was already recorded; the first one stands.
pub async fn activate(
    ctx: &mut Ctx,
    request: &ElevationRequest,
    at: i64,
    not_after: i64,
) -> Result<bool> {
    let mut object = fact(
        request,
        format!("{}:active", object_id(&request.id)),
        Event::Active,
        at,
    );
    object
        .properties
        .insert("not_after".into(), not_after.to_string());
    create_fact(ctx, object).await
}

/// Record a revocation. False when one was already recorded.
pub async fn revoke(
    ctx: &mut Ctx,
    request: &ElevationRequest,
    by: &str,
    reason: &str,
    at: i64,
) -> Result<bool> {
    let mut object = fact(
        request,
        format!("{}:revoked", object_id(&request.id)),
        Event::Revoked,
        at,
    );
    object.properties.insert("by".into(), by.into());
    object.properties.insert("reason".into(), reason.into());
    create_fact(ctx, object).await
}

/// Every elevation of `session`, oldest first.
pub async fn load_for_session(ctx: &mut Ctx, session: &str) -> Result<Vec<StoredElevation>> {
    let objects = ctx
        .find_by_property(KIND_DEBUG_ELEVATION, "session", session)
        .await?;
    assemble(&objects)
}

/// Group the facts of one session's elevations. A fact without its request
/// cannot be written first, so it is ignored.
fn assemble(objects: &[Object]) -> Result<Vec<StoredElevation>> {
    let field = |object: &Object, name: &str| object.properties.get(name).cloned();
    let at = |object: &Object| {
        field(object, "at")
            .and_then(|at| at.parse().ok())
            .unwrap_or(object.created)
    };
    let mut stored = Vec::new();
    for object in objects {
        if field(object, "event").as_deref() != Some(Event::Requested.as_str()) {
            continue;
        }
        let raw = field(object, "record")
            .with_context(|| format!("debug elevation {} has no record", object.id))?;
        let record: Record = serde_json::from_str(&raw)
            .with_context(|| format!("debug elevation {} record is unreadable", object.id))?;
        anyhow::ensure!(
            record.format == RECORD_FORMAT,
            "debug elevation {} has record format {}, this release reads {RECORD_FORMAT}",
            object.id,
            record.format
        );
        stored.push(StoredElevation {
            request: record.request,
            approvals: Vec::new(),
            active: None,
            revoked: None,
        });
    }
    for object in objects {
        let Some(elevation) = stored.iter_mut().find(|stored| {
            field(object, "elevation").as_deref() == Some(stored.request.id.as_str())
        }) else {
            continue;
        };
        match field(object, "event").as_deref() {
            Some("approval") => {
                let raw = field(object, "envelope").with_context(|| {
                    format!("debug elevation approval {} has no envelope", object.id)
                })?;
                let envelope = serde_json::from_str(&raw).with_context(|| {
                    format!("debug elevation approval {} is unreadable", object.id)
                })?;
                elevation.approvals.push((envelope, at(object)));
            }
            Some("active") => {
                let not_after = field(object, "not_after")
                    .and_then(|value| value.parse().ok())
                    .with_context(|| format!("debug elevation {} has no bound", object.id))?;
                elevation.active = Some((at(object), not_after));
            }
            Some("revoked") => {
                elevation.revoked = Some((
                    field(object, "by").unwrap_or_default(),
                    field(object, "reason").unwrap_or_default(),
                    at(object),
                ));
            }
            _ => {}
        }
    }
    stored.sort_by(|a, b| {
        a.request
            .requested_at
            .cmp(&b.request.requested_at)
            .then(a.request.id.cmp(&b.request.id))
    });
    Ok(stored)
}

/// Whether `signer` may approve elevations in `environment` by hand: in
/// scope there, and not only an automatic or preflight signer.
fn human_signer_for(signer: &TrustedSigner, environment: &str) -> bool {
    (signer.environments.is_empty() || signer.environments.iter().any(|e| e == environment))
        && (signer.providers.is_empty()
            || signer.providers.iter().any(|provider| {
                provider != "builtin-auto" && provider != crate::host_preflight::PREFLIGHT_PROVIDER
            }))
}

/// Check `envelope` approves `request` at `now`, and return its signer.
pub fn verify_approval<'r>(
    request: &ElevationRequest,
    envelope: &DebugElevationEnvelope,
    roots: &'r TrustRoots,
    now: i64,
) -> Result<&'r TrustedSigner> {
    let statement = &envelope.statement;
    if statement.elevation != request.id
        || statement.session != request.session
        || statement.environment != request.environment
    {
        bail!("the approval is bound to a different elevation, session or environment");
    }
    let signer = envelope.verify_signature(roots, now)?;
    if !human_signer_for(signer, &request.environment) {
        bail!("the approval signer may not approve debug elevation in this environment");
    }
    Ok(signer)
}

/// Count the approvals of `elevation` that still verify at `now` toward
/// `rule`. The requester never counts, whatever the rule says.
pub(crate) fn tally(
    elevation: &StoredElevation,
    roots: &TrustRoots,
    rule: &crate::approval_policy::QuorumRule,
    now: i64,
) -> QuorumTally {
    let rule = crate::approval_policy::QuorumRule {
        exclude_requester: true,
        ..rule.clone()
    };
    let candidates: Vec<CountedApproval> = elevation
        .approvals
        .iter()
        .filter_map(|(envelope, _)| {
            let signer = verify_approval(&elevation.request, envelope, roots, now).ok()?;
            Some(CountedApproval {
                key_id: envelope.key_id.clone(),
                identity: signer.identity.clone(),
                groups: signer.groups.clone(),
                auto: false,
            })
        })
        .collect();
    count_quorum(&rule, &candidates, Some(&elevation.request.requested_by))
}

impl StoredElevation {
    /// The view of this elevation in `session` at `now`. `identity` names a
    /// collected approval's signer, when the trust roots still know it.
    pub fn view(
        &self,
        session: &DebugSession,
        now: i64,
        identity: impl Fn(&str) -> Option<String>,
    ) -> DebugElevation {
        let request = &self.request;
        let session_end = match session.state {
            DebugSessionState::Open if !session.is_due(now) => None,
            DebugSessionState::Open => Some(session.not_after),
            _ => Some(session.closed_at.unwrap_or(session.not_after)),
        };
        let mut ended: Option<(i64, String)> = None;
        if let Some((_, reason, at)) = &self.revoked {
            ended = Some((*at, format!("revoked: {reason}")));
        }
        if let Some((_, not_after)) = self.active
            && now >= not_after
        {
            ended = earliest(ended, (not_after, "bound reached".into()));
        }
        if let Some(at) = session_end {
            ended = earliest(ended, (at, "session ended".into()));
        }
        let state = match (&ended, self.active) {
            (Some(_), _) => DebugElevationState::Ended,
            (None, Some(_)) => DebugElevationState::Active,
            (None, None) => DebugElevationState::Pending,
        };
        DebugElevation {
            id: request.id.clone(),
            session: request.session.clone(),
            environment: request.environment.clone(),
            requested_by: request.requested_by.clone(),
            requester: request.requester.clone(),
            reason: request.reason.clone(),
            requested_at: request.requested_at,
            duration_ms: request.duration_ms,
            state,
            approvals: self
                .approvals
                .iter()
                .map(|(envelope, at)| DebugElevationApproval {
                    identity: identity(&envelope.key_id).unwrap_or_default(),
                    key_id: envelope.key_id.clone(),
                    approved_at: *at,
                })
                .collect(),
            active_from: self.active.map(|(at, _)| at),
            not_after: self.active.map(|(_, not_after)| not_after),
            ended_at: ended.as_ref().map(|(at, _)| *at),
            end_reason: ended.map(|(_, reason)| reason),
            revoked_by: self.revoked.as_ref().map(|(by, _, _)| by.clone()),
        }
    }
}

fn earliest(current: Option<(i64, String)>, next: (i64, String)) -> Option<(i64, String)> {
    match current {
        Some(current) if current.0 <= next.0 => Some(current),
        _ => Some(next),
    }
}

/// Until when write access is live in `session` at `now`: the latest bound
/// of its active elevations, or none.
pub fn live_until(elevations: &[StoredElevation], session: &DebugSession, now: i64) -> Option<i64> {
    elevations
        .iter()
        .map(|elevation| elevation.view(session, now, |_| None))
        .filter(|view| view.state == DebugElevationState::Active)
        .filter_map(|view| view.not_after)
        .max()
}

/// Until when `session` may run write commands at `now`: the latest bound
/// of its active elevations, while the environment's live policy still says
/// `elevate`. A policy tightened after approval, or unreadable, ends every
/// elevation at once (fail closed).
pub async fn elevated_until(
    ctx: &mut Ctx,
    session: &DebugSession,
    now: i64,
) -> Result<Option<i64>> {
    let record = crate::environment::environment(ctx, &session.environment).await?;
    let elevate = crate::approval_policy::load_live_policy(&record.properties)
        .ok()
        .flatten()
        .is_some_and(|policy| {
            policy.debug_sessions == crate::approval_policy::DebugSessions::Elevate
        });
    if !elevate {
        return Ok(None);
    }
    let elevations = load_for_session(ctx, &session.id).await?;
    Ok(live_until(&elevations, session, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug_session::DebugSessionMode;

    fn session(now: i64) -> DebugSession {
        DebugSession {
            id: "s1".into(),
            environment: "prod".into(),
            instance: "api".into(),
            subject: "alice".into(),
            opened_by: "alice".into(),
            mode: DebugSessionMode::Read,
            reason: "incident".into(),
            opened_at: now,
            not_after: now + 60_000,
            state: DebugSessionState::Open,
            closed_at: None,
            closed_by: None,
            close_reason: None,
            runtime: None,
        }
    }

    fn stored(now: i64) -> StoredElevation {
        StoredElevation {
            request: ElevationRequest {
                id: "e1".into(),
                session: "s1".into(),
                environment: "prod".into(),
                requested_by: "alice".into(),
                requester: "alice".into(),
                reason: "restart".into(),
                requested_at: now,
                duration_ms: 10_000,
            },
            approvals: Vec::new(),
            active: None,
            revoked: None,
        }
    }

    #[test]
    fn elevation_ends_at_the_first_of_its_bound_revocation_and_session_end() {
        let now = 1_000_000;
        let session = session(now);
        let mut elevation = stored(now);
        assert_eq!(
            elevation.view(&session, now, |_| None).state,
            DebugElevationState::Pending
        );
        elevation.active = Some((now, now + 10_000));
        assert_eq!(
            live_until(std::slice::from_ref(&elevation), &session, now + 1),
            Some(now + 10_000)
        );
        let bound = elevation.view(&session, now + 10_000, |_| None);
        assert_eq!(bound.state, DebugElevationState::Ended);
        assert_eq!(bound.end_reason.as_deref(), Some("bound reached"));

        elevation.revoked = Some(("bob".into(), "done".into(), now + 5));
        let revoked = elevation.view(&session, now + 6, |_| None);
        assert_eq!(revoked.state, DebugElevationState::Ended);
        assert_eq!(revoked.end_reason.as_deref(), Some("revoked: done"));
        assert_eq!(live_until(&[elevation.clone()], &session, now + 6), None);

        elevation.revoked = None;
        let mut closed = session.clone();
        closed.state = DebugSessionState::Closed;
        closed.closed_at = Some(now + 2);
        assert_eq!(live_until(&[elevation], &closed, now + 3), None);
    }

    #[test]
    fn a_plan_approval_signature_never_verifies_as_an_elevation_approval() {
        let statement = DebugElevationStatement {
            session: "s1".into(),
            elevation: "e1".into(),
            environment: "prod".into(),
            purpose: APPROVAL_PURPOSE.into(),
            issued_at: 1,
            expires_at: 2,
        };
        let bytes = statement.canonical_bytes().unwrap();
        assert!(bytes.starts_with(APPROVAL_DOMAIN));
        let wrong = DebugElevationStatement {
            purpose: "execute_plan".into(),
            ..statement
        };
        assert!(wrong.canonical_bytes().is_err());
    }
}

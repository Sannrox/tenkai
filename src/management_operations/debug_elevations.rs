//! Request, approve, revoke and list debug session elevations (ADR 0061
//! §3, #1560).
//!
//! Only a human holding `debug` requests or approves; an agent or a service
//! principal is refused. The environment's policy must be `elevate` at each
//! step. Approvals are signed envelopes verified against the server's
//! plan-approval trust roots the reconciler verifies plans with;
//! without them nothing elevates. Every step is audited before it is stored,
//! and nothing is stored when the audit cannot be written.

use serde::{Deserialize, Serialize};

use super::debug_sessions::checked_reason;
use super::*;
use crate::approval_policy::{DEBUG_SESSION_BOUND_MS, DebugSessions, QuorumPurpose, QuorumRule};
use crate::debug_elevation::{
    DEFAULT_ELEVATION_MS, DebugElevation, DebugElevationEnvelope, DebugElevationState,
    ElevationRequest, StoredElevation,
};
use crate::debug_session::{DebugSession, DebugSessionState};
use crate::signature_verification::{TrustRootKind, TrustRoots};

/// `POST /v1/debug-sessions/{session}/elevations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugElevationOpenRequest {
    /// Why write access is needed; recorded and audited.
    pub reason: String,
    /// Write access length from activation. Default 30 minutes; never past
    /// the session's bound.
    #[serde(default)]
    pub duration_ms: Option<i64>,
}

/// `POST /v1/debug-sessions/{session}/elevations/{elevation}/approvals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugElevationApproveRequest {
    pub approval: DebugElevationEnvelope,
}

/// `POST /v1/debug-sessions/{session}/elevations/{elevation}/revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugElevationRevokeRequest {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DebugElevationList {
    pub elevations: Vec<DebugElevation>,
}

/// The server's plan-approval trust roots; elevation fails closed without.
impl ManagementOperations {
    /// The plan-approval trust roots, which this host's reconciler also
    /// verifies plan approvals with. Without them nothing elevates.
    fn approval_roots(&self) -> Result<TrustRoots, ManagementError> {
        let path = self.reconciler.approval_trust_roots().ok_or_else(|| {
            ManagementError::Unavailable(format!(
                "debug elevation needs {} on the server",
                crate::plan_approval::TRUST_ROOTS_ENV
            ))
        })?;
        TrustRoots::load(&path, TrustRootKind::PlanApproval)
            .map_err(|error| ManagementError::Unavailable(format!("{error:#}")))
    }
}

fn view(
    elevation: &StoredElevation,
    session: &DebugSession,
    roots: Option<&TrustRoots>,
) -> DebugElevation {
    elevation.view(session, crate::now_millis(), |key_id| {
        roots
            .and_then(|roots| roots.signer(TrustRootKind::PlanApproval, key_id).ok())
            .map(|signer| signer.identity.clone())
    })
}

impl ManagementOperations {
    /// The `debug_elevate` rule of `environment`, refused unless its policy
    /// is `elevate`.
    async fn elevation_rule(
        &self,
        ctx: &mut Ctx,
        environment: &str,
    ) -> Result<QuorumRule, ManagementError> {
        let record = crate::environment::environment(ctx, environment)
            .await
            .map_err(map_catalog_error)?;
        let policy = crate::approval_policy::load_live_policy(&record.properties)
            .map_err(|_| ManagementError::Unavailable("approval policy is unreadable".into()))?;
        let Some(policy) = policy.filter(|policy| policy.debug_sessions == DebugSessions::Elevate)
        else {
            return Err(ManagementError::Forbidden(
                "debug elevation is not allowed in this environment".into(),
            ));
        };
        let criticality = crate::criticality_store::effective_for_targets(ctx, environment, &[])
            .await
            .map_err(|_| ManagementError::Unavailable("criticality is unreadable".into()))?;
        Ok(crate::approval_policy::quorum_rule(
            &policy,
            QuorumPurpose::DebugElevate,
            criticality,
        ))
    }

    /// The checks every elevation step shares: a human with `debug`, in
    /// scope, on a session that is still open.
    async fn elevation_session(
        &self,
        credential: &CredentialMaterial,
        context: &AuthenticatedRequestContext,
        operation: &str,
        id: &str,
    ) -> Result<(Ctx, DebugSession), ManagementError> {
        // ADR 0061 §5: an agent never elevates or approves.
        self.refuse_agent(context, operation)?;
        if !context.has_delivery_capability(DeliveryCapability::Debug) {
            return Err(ManagementError::Forbidden(
                "insufficient delivery capability".into(),
            ));
        }
        crate::clock_guard::require_trusted_time("debug elevation")
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        let mut ctx = self.catalog_ctx(context)?;
        let session = self
            .scoped_debug_session(credential, context, &mut ctx, id)
            .await?;
        let session = self.settle_debug_session(&mut ctx, session).await?;
        if session.state != DebugSessionState::Open {
            return Err(ManagementError::Conflict(
                "the debug session has ended".into(),
            ));
        }
        Ok((ctx, session))
    }

    /// Elevation `id` of `session`, or not found.
    async fn stored_elevation(
        ctx: &mut Ctx,
        session: &DebugSession,
        id: &str,
    ) -> Result<StoredElevation, ManagementError> {
        let missing = || ManagementError::NotFound("debug elevation not found".into());
        crate::ontology::validate_opaque_identifier("debug elevation", id)
            .map_err(|_| missing())?;
        crate::debug_elevation::load_for_session(ctx, &session.id)
            .await
            .map_err(internal)?
            .into_iter()
            .find(|elevation| elevation.request.id == id)
            .ok_or_else(missing)
    }

    /// Ask for write access in open session `id`.
    pub async fn request_debug_elevation(
        &self,
        credential: &CredentialMaterial,
        id: &str,
        request: DebugElevationOpenRequest,
    ) -> Result<DebugElevation, ManagementError> {
        let context = self.authenticate(credential)?;
        // Audits its own refusal.
        self.refuse_agent(&context, "debug_session.elevate")?;
        let actor = context.audit_principal();
        let checked = async {
            let reason = checked_reason(&request.reason)?.to_string();
            let (mut ctx, session) = self
                .elevation_session(credential, &context, "debug_session.elevate", id)
                .await?;
            self.elevation_rule(&mut ctx, &session.environment).await?;
            self.approval_roots()?;
            let duration = request.duration_ms.unwrap_or(DEFAULT_ELEVATION_MS);
            if duration <= 0 || duration > DEBUG_SESSION_BOUND_MS {
                return Err(ManagementError::BadRequest(format!(
                    "duration_ms must be 1..={DEBUG_SESSION_BOUND_MS}"
                )));
            }
            let elevation = ElevationRequest {
                id: uuid::Uuid::new_v4().to_string(),
                session: session.id.clone(),
                environment: session.environment.clone(),
                requested_by: context.principal_id().to_string(),
                requester: actor.clone(),
                reason,
                requested_at: crate::now_millis(),
                duration_ms: duration,
            };
            Ok((ctx, session, elevation))
        }
        .await;
        let (mut ctx, session, elevation) = checked.map_err(|error| {
            match self.audit_debug(
                &actor,
                "debug_session.elevate.refused",
                format!("debug-session/{id} refused={error}"),
            ) {
                Ok(()) => error,
                Err(audit) => audit,
            }
        })?;
        self.audit_debug(
            &actor,
            "debug_session.elevate.requested",
            format!(
                "debug-session/{} elevation={} duration_ms={} reason={}",
                session.id, elevation.id, elevation.duration_ms, elevation.reason
            ),
        )?;
        crate::debug_elevation::create_request(&mut ctx, &elevation)
            .await
            .map_err(internal)?;
        let stored = StoredElevation {
            request: elevation,
            approvals: Vec::new(),
            active: None,
            revoked: None,
        };
        Ok(view(&stored, &session, None))
    }

    /// Collect one signed approval of elevation `elevation`, and activate
    /// it once the quorum is met. The requester's own approval is stored
    /// but never counts.
    pub async fn approve_debug_elevation(
        &self,
        credential: &CredentialMaterial,
        id: &str,
        elevation: &str,
        request: DebugElevationApproveRequest,
    ) -> Result<DebugElevation, ManagementError> {
        let context = self.authenticate(credential)?;
        let actor = context.audit_principal();
        let (mut ctx, session) = self
            .elevation_session(credential, &context, "debug_session.elevate.approve", id)
            .await?;
        let rule = self.elevation_rule(&mut ctx, &session.environment).await?;
        let roots = self.approval_roots()?;
        let mut stored = Self::stored_elevation(&mut ctx, &session, elevation).await?;
        let now = crate::now_millis();
        if view(&stored, &session, Some(&roots)).state == DebugElevationState::Ended {
            return Err(ManagementError::Conflict(
                "the debug elevation has ended".into(),
            ));
        }
        let signer = crate::debug_elevation::verify_approval(
            &stored.request,
            &request.approval,
            &roots,
            now,
        )
        .map_err(|error| {
            let error = ManagementError::BadRequest(format!("{error:#}"));
            match self.audit_debug(
                &actor,
                "debug_session.elevate.refused",
                format!(
                    "debug-session/{} elevation={} key={} refused={error}",
                    session.id, stored.request.id, request.approval.key_id
                ),
            ) {
                Ok(()) => error,
                Err(audit) => audit,
            }
        })?;
        self.audit_debug(
            &actor,
            "debug_session.elevate.approval",
            format!(
                "debug-session/{} elevation={} signer={} key={}",
                session.id, stored.request.id, signer.identity, request.approval.key_id
            ),
        )?;
        if crate::debug_elevation::add_approval(&mut ctx, &stored.request, &request.approval, now)
            .await
            .map_err(internal)?
        {
            stored.approvals.push((request.approval, now));
        }
        if stored.active.is_none() {
            let tally = crate::debug_elevation::tally(&stored, &roots, &rule, now);
            if tally.missing == 0 {
                let not_after = (now + stored.request.duration_ms).min(session.not_after);
                self.audit_debug(
                    &actor,
                    "debug_session.elevate.completed",
                    format!(
                        "debug-session/{} elevation={} not_after={not_after} approvers={}",
                        session.id,
                        stored.request.id,
                        tally
                            .counted
                            .iter()
                            .map(|item| item.identity.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                )?;
                crate::debug_elevation::activate(&mut ctx, &stored.request, now, not_after)
                    .await
                    .map_err(internal)?;
            }
        }
        // Read back: a concurrent approval may have activated it first.
        let stored = Self::stored_elevation(&mut ctx, &session, elevation).await?;
        Ok(view(&stored, &session, Some(&roots)))
    }

    /// End elevation `elevation` now. A `debug` holder or a management
    /// principal may revoke; revoking an ended elevation returns it as is.
    pub async fn revoke_debug_elevation(
        &self,
        credential: &CredentialMaterial,
        id: &str,
        elevation: &str,
        request: DebugElevationRevokeRequest,
    ) -> Result<DebugElevation, ManagementError> {
        let context = self.authenticate(credential)?;
        self.refuse_agent(&context, "debug_session.elevate.revoke")?;
        if !context.has_delivery_capability(DeliveryCapability::Debug) {
            Self::require_capability(&context, DeliveryCapability::Management)?;
        }
        let reason = checked_reason(&request.reason)?.to_string();
        let mut ctx = self.catalog_ctx(&context)?;
        let session = self
            .scoped_debug_session(credential, &context, &mut ctx, id)
            .await?;
        let session = self.settle_debug_session(&mut ctx, session).await?;
        let stored = Self::stored_elevation(&mut ctx, &session, elevation).await?;
        if view(&stored, &session, None).state == DebugElevationState::Ended {
            return Ok(view(&stored, &session, None));
        }
        let actor = context.audit_principal();
        self.audit_debug(
            &actor,
            "debug_session.elevate.revoked",
            format!(
                "debug-session/{} elevation={} reason={reason}",
                session.id, stored.request.id
            ),
        )?;
        crate::debug_elevation::revoke(
            &mut ctx,
            &stored.request,
            &actor,
            &reason,
            crate::now_millis(),
        )
        .await
        .map_err(internal)?;
        let stored = Self::stored_elevation(&mut ctx, &session, elevation).await?;
        Ok(view(&stored, &session, None))
    }

    /// Every elevation of session `id`, oldest first.
    pub async fn list_debug_elevations(
        &self,
        credential: &CredentialMaterial,
        id: &str,
    ) -> Result<DebugElevationList, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        let mut ctx = self.catalog_ctx(&context)?;
        let session = self
            .scoped_debug_session(credential, &context, &mut ctx, id)
            .await?;
        let session = self.settle_debug_session(&mut ctx, session).await?;
        // Identities are filled in only while the trust roots are readable.
        let roots = self.approval_roots().ok();
        let elevations = crate::debug_elevation::load_for_session(&mut ctx, &session.id)
            .await
            .map_err(internal)?
            .iter()
            .map(|elevation| view(elevation, &session, roots.as_ref()))
            .collect();
        Ok(DebugElevationList { elevations })
    }
}

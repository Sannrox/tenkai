//! Open, list, inspect and close debug sessions (ADR 0061, #1556).
//!
//! Opening needs the `debug` capability (a human acting directly), an
//! environment grant, and an environment whose approval policy allows
//! sessions. Every refusal and every state change is audited; when the audit
//! cannot be written, nothing opens.

use serde::{Deserialize, Serialize};

use super::*;
use crate::approval_policy::{DEBUG_SESSION_BOUND_MS, DebugSessions};
use crate::debug_session::{DebugSession, DebugSessionMode, DebugSessionState};

/// Longest open or close reason accepted.
const MAX_DEBUG_REASON: usize = 1024;

/// `POST /v1/debug-sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionOpenRequest {
    pub environment: String,
    pub instance: String,
    /// Why the session is needed; recorded and audited.
    pub reason: String,
    /// Session length; default and maximum are the environment's
    /// `debug_session_max_ms` (four hours unless lower).
    #[serde(default)]
    pub duration_ms: Option<i64>,
}

/// `POST /v1/debug-sessions/{session}/close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionCloseRequest {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DebugSessionList {
    pub sessions: Vec<DebugSession>,
}

/// `GET /v1/debug-sessions` filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionQuery {
    #[serde(default)]
    pub environment: Option<String>,
}

fn checked_reason(reason: &str) -> Result<&str, ManagementError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_DEBUG_REASON {
        return Err(ManagementError::BadRequest(format!(
            "a reason of 1..={MAX_DEBUG_REASON} bytes is required"
        )));
    }
    Ok(reason)
}

impl ManagementOperations {
    /// Append one debug-session audit record. The resource names the
    /// session or the request, since audit records have no other fields.
    fn audit_debug(
        &self,
        principal: &str,
        operation: &str,
        resource: String,
    ) -> Result<(), ManagementError> {
        self.store
            .append_audit(&AuditRecord {
                id: uuid::Uuid::new_v4().to_string(),
                occurred_at: crate::now_millis(),
                principal: principal.into(),
                operation: operation.into(),
                resource,
                outcome: operation.rsplit('.').next().unwrap_or(operation).into(),
            })
            .map_err(|error| ManagementError::Unavailable(error.to_string()))
    }

    /// Audit a refused open, then return `error`. An audit that cannot be
    /// written surfaces instead, so the refusal is never silent.
    fn refuse_debug_open(
        &self,
        context: &AuthenticatedRequestContext,
        request: &DebugSessionOpenRequest,
        error: ManagementError,
    ) -> ManagementError {
        let resource = format!(
            "debug-session environment={} instance={} refused={error}",
            request.environment, request.instance
        );
        match self.audit_debug(
            &context.audit_principal(),
            "debug_session.open.refused",
            resource,
        ) {
            Ok(()) => error,
            Err(audit) => audit,
        }
    }

    /// Record the expiry of a session whose bound passed while it was open.
    async fn settle_debug_session(
        &self,
        ctx: &mut Ctx,
        mut session: DebugSession,
    ) -> Result<DebugSession, ManagementError> {
        if !session.expire_if_due(crate::now_millis()) {
            return Ok(session);
        }
        self.audit_debug(
            "tenkai",
            "debug_session.expire.completed",
            format!("debug-session/{}", session.id),
        )?;
        crate::debug_session::save(ctx, &session)
            .await
            .map_err(internal)?;
        Ok(session)
    }

    /// Open a read-only session on one instance.
    pub async fn open_debug_session(
        &self,
        credential: &CredentialMaterial,
        request: DebugSessionOpenRequest,
    ) -> Result<DebugSession, ManagementError> {
        let context = self.authenticate(credential)?;
        // ADR 0061 §5: an agent never opens a session.
        self.refuse_agent(&context, "debug_session.open")?;
        // Every refusal after authentication is audited, whatever refused.
        let (mut ctx, session) = self
            .checked_debug_open(credential, &context, &request)
            .await
            .map_err(|error| self.refuse_debug_open(&context, &request, error))?;
        let actor = session.opened_by.clone();
        // Audit first: a session whose opening is not on record never exists.
        self.audit_debug(
            &actor,
            "debug_session.open.completed",
            format!(
                "debug-session/{} environment={} instance={} not_after={} reason={}",
                session.id,
                session.environment,
                session.instance,
                session.not_after,
                session.reason
            ),
        )?;
        if let Err(error) = crate::debug_session::create(&mut ctx, &session).await {
            // Best effort: the open is already on record as completed.
            let _ = self.audit_debug(
                &actor,
                "debug_session.open.failed",
                format!("debug-session/{}", session.id),
            );
            return Err(internal(error));
        }
        Ok(session)
    }

    /// Every check an open must pass, then the session it would create.
    async fn checked_debug_open(
        &self,
        credential: &CredentialMaterial,
        context: &AuthenticatedRequestContext,
        request: &DebugSessionOpenRequest,
    ) -> Result<(Ctx, DebugSession), ManagementError> {
        if !context.has_delivery_capability(DeliveryCapability::Debug) {
            return Err(ManagementError::Forbidden(
                "insufficient delivery capability".into(),
            ));
        }
        self.require_environment_grant(
            credential,
            context,
            Some(&request.environment),
            "debug session",
        )?;
        crate::ontology::validate_identifier("environment", &request.environment)
            .and_then(|()| crate::ontology::validate_instance_name(&request.instance))
            .map_err(|error| ManagementError::BadRequest(error.to_string()))?;
        let reason = checked_reason(&request.reason)?.to_string();
        crate::clock_guard::require_trusted_time("debug session")
            .map_err(|error| ManagementError::Unavailable(error.to_string()))?;
        let mut ctx = self.catalog_ctx(context)?;
        self.require_environment_visible(context, &request.environment)
            .await?;
        let environment = crate::environment::environment(&mut ctx, &request.environment)
            .await
            .map_err(map_catalog_error)?;
        let policy = crate::approval_policy::effective_policy(&environment.properties)
            .map_err(|_| ManagementError::Unavailable("approval policy is unreadable".into()))?;
        if policy.debug_sessions == DebugSessions::Forbid {
            return Err(ManagementError::Forbidden(
                "debug sessions are forbidden in this environment".into(),
            ));
        }
        let max = policy
            .debug_session_max_ms
            .unwrap_or(DEBUG_SESSION_BOUND_MS)
            .min(DEBUG_SESSION_BOUND_MS);
        let duration = request.duration_ms.unwrap_or(max);
        if duration <= 0 || duration > max {
            return Err(ManagementError::BadRequest(format!(
                "duration_ms must be 1..={max} in this environment"
            )));
        }
        // A product's default instance has no object of its own: match the
        // environment's status rows the way `explain` does.
        let rows = crate::plan::status(&mut ctx, &request.environment)
            .await
            .map_err(map_catalog_error)?;
        let named = |row: &crate::plan::StatusRow| {
            let name = if row.instance.is_empty() {
                &row.product
            } else {
                &row.instance
            };
            *name == request.instance
        };
        if !rows.iter().any(named) {
            return Err(ManagementError::NotFound("instance not found".into()));
        }
        let now = crate::now_millis();
        let session = DebugSession {
            id: uuid::Uuid::new_v4().to_string(),
            environment: request.environment.clone(),
            instance: request.instance.clone(),
            subject: context.principal_id().to_string(),
            opened_by: context.audit_principal(),
            mode: DebugSessionMode::Read,
            reason,
            opened_at: now,
            not_after: now + duration,
            state: DebugSessionState::Open,
            closed_at: None,
            closed_by: None,
            close_reason: None,
            runtime: None,
        };
        Ok((ctx, session))
    }

    /// Sessions the caller may see: one environment, or all of them for a
    /// credential that is not confined to one.
    pub async fn list_debug_sessions(
        &self,
        credential: &CredentialMaterial,
        query: DebugSessionQuery,
    ) -> Result<DebugSessionList, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        self.require_environment_grant(
            credential,
            &context,
            query.environment.as_deref(),
            "debug session list",
        )?;
        let mut ctx = self.catalog_ctx(&context)?;
        if let Some(environment) = &query.environment {
            self.require_environment_visible(&context, environment)
                .await?;
        }
        let stored = crate::debug_session::list(&mut ctx, query.environment.as_deref())
            .await
            .map_err(internal)?;
        let mut sessions = Vec::with_capacity(stored.len());
        for session in stored {
            sessions.push(self.settle_debug_session(&mut ctx, session).await?);
        }
        Ok(DebugSessionList { sessions })
    }

    /// One session, after the same scope checks as the list.
    pub async fn inspect_debug_session(
        &self,
        credential: &CredentialMaterial,
        id: &str,
    ) -> Result<DebugSession, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Read)?;
        let mut ctx = self.catalog_ctx(&context)?;
        let session = self
            .scoped_debug_session(credential, &context, &mut ctx, id)
            .await?;
        self.settle_debug_session(&mut ctx, session).await
    }

    /// Close an open session. Closing a session that already ended returns
    /// it unchanged. A `debug` holder or a management principal may close.
    pub async fn close_debug_session(
        &self,
        credential: &CredentialMaterial,
        id: &str,
        request: DebugSessionCloseRequest,
    ) -> Result<DebugSession, ManagementError> {
        let context = self.authenticate(credential)?;
        self.refuse_agent(&context, "debug_session.close")?;
        if !context.has_delivery_capability(DeliveryCapability::Debug) {
            Self::require_capability(&context, DeliveryCapability::Management)?;
        }
        let reason = checked_reason(&request.reason)?.to_string();
        let mut ctx = self.catalog_ctx(&context)?;
        let session = self
            .scoped_debug_session(credential, &context, &mut ctx, id)
            .await?;
        let mut session = self.settle_debug_session(&mut ctx, session).await?;
        if session.state != DebugSessionState::Open {
            return Ok(session);
        }
        let actor = context.audit_principal();
        self.audit_debug(
            &actor,
            "debug_session.close.completed",
            format!("debug-session/{} reason={reason}", session.id),
        )?;
        session.state = DebugSessionState::Closed;
        session.closed_at = Some(crate::now_millis());
        session.closed_by = Some(actor);
        session.close_reason = Some(reason);
        crate::debug_session::save(&mut ctx, &session)
            .await
            .map_err(internal)?;
        Ok(session)
    }

    /// Admit an operator's terminal stream on session `id` (#1558): a human
    /// holding `debug`, in scope, on a session still open. The relay calls
    /// it at the upgrade (`first`, which audits the attach) and again on
    /// every recheck, so a revoked grant or an ended session ends the stream.
    /// An ended session is [`ManagementError::Conflict`].
    pub async fn authorize_debug_stream(
        &self,
        credential: &CredentialMaterial,
        id: &str,
        first: bool,
    ) -> Result<DebugSession, ManagementError> {
        let context = self.authenticate(credential)?;
        self.refuse_agent(&context, "debug_session.stream")?;
        if !context.has_delivery_capability(DeliveryCapability::Debug) {
            return Err(ManagementError::Forbidden(
                "insufficient delivery capability".into(),
            ));
        }
        let mut ctx = self.catalog_ctx(&context)?;
        let session = self
            .scoped_debug_session(credential, &context, &mut ctx, id)
            .await?;
        let session = self.settle_debug_session(&mut ctx, session).await?;
        if session.state != DebugSessionState::Open {
            return Err(ManagementError::Conflict(
                "the debug session has ended".into(),
            ));
        }
        if first {
            self.audit_debug(
                &context.audit_principal(),
                "debug_session.stream.attached",
                format!("debug-session/{} side=operator", session.id),
            )?;
        }
        Ok(session)
    }

    /// Load session `id` and confine it to the caller's environment grant.
    /// Not found and out of scope answer alike.
    async fn scoped_debug_session(
        &self,
        credential: &CredentialMaterial,
        context: &AuthenticatedRequestContext,
        ctx: &mut Ctx,
        id: &str,
    ) -> Result<DebugSession, ManagementError> {
        let missing = || ManagementError::NotFound("debug session not found".into());
        crate::ontology::validate_opaque_identifier("debug session", id).map_err(|_| missing())?;
        let session = crate::debug_session::load(ctx, id)
            .await
            .map_err(internal)?
            .ok_or_else(missing)?;
        self.require_environment_grant(
            credential,
            context,
            Some(&session.environment),
            "debug session",
        )
        .map_err(|_| missing())?;
        self.require_environment_visible(context, &session.environment)
            .await
            .map_err(|_| missing())?;
        Ok(session)
    }
}

//! Create, list and download exports over HTTP (#682). Management capability
//! only; an environment-scoped credential sees and creates only its own
//! environment's recovery bundles and offline receipts.

use serde::Deserialize;

use super::*;
use crate::exports::{ExportAction, ExportEntry, ExportEvent, ExportKind, ExportList, Exports};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub kind: ExportKind,
    /// Why the export is made; recorded with the creator.
    pub reason: String,
    /// Required for `recovery-bundle` and `offline-receipt`, refused otherwise.
    #[serde(default)]
    pub environment: Option<String>,
    /// The plan of a `recovery-bundle`.
    #[serde(default)]
    pub plan_id: Option<String>,
    /// The connectivity upgrade of an `offline-receipt`.
    #[serde(default)]
    pub upgrade: Option<String>,
}

impl ManagementOperations {
    /// The export directory is one host's, not partitioned by tenant, so a
    /// tenant-mode host never serves it, whatever its configuration says.
    fn refuse_tenant_exports(&self) -> Result<(), ManagementError> {
        if self.tenant_mode {
            return Err(ManagementError::Unavailable(
                "exports are not available in tenant mode".into(),
            ));
        }
        Ok(())
    }

    /// `POST /v1/exports`: produce one export and store it.
    pub async fn create_export(
        &self,
        credential: &CredentialMaterial,
        exports: Arc<Exports>,
        request: ExportRequest,
    ) -> Result<ExportEntry, ManagementError> {
        let context = self.authenticate(credential)?;
        self.refuse_agent(&context, "export.create")?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        self.refuse_tenant_exports()?;
        let reason = crate::exports::validate_reason(&request.reason)
            .map_err(|error| ManagementError::BadRequest(error.to_string()))?;
        let environment = match (request.kind.is_environment_scoped(), &request.environment) {
            (true, Some(environment)) => Some(environment.as_str()),
            (false, None) => None,
            (true, None) => {
                return Err(ManagementError::BadRequest(format!(
                    "a {} export needs an environment",
                    request.kind.as_str()
                )));
            }
            (false, Some(_)) => {
                return Err(ManagementError::BadRequest(format!(
                    "a {} export is hub-wide and takes no environment",
                    request.kind.as_str()
                )));
            }
        };
        self.require_environment_grant(credential, &context, environment, "export")?;
        let principal = context.audit_principal();
        let operation = format!("export.{}", request.kind.as_str());
        self.audit(&principal, &format!("{operation}.requested"))?;
        let now = crate::now_millis();
        let event = ExportEvent {
            at_ms: now,
            principal: principal.clone(),
            action: ExportAction::Created,
            reason: reason.into(),
        };
        let entry = if request.kind == ExportKind::AuditExport {
            // Advancing the chain and storing the export happen together.
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || exports.next_audit_export(store.as_ref(), &event))
                .await
                .map_err(|error| ManagementError::Internal(error.to_string()))?
                .map_err(|error| ManagementError::ExecutionFailed(format!("{error:#}")))?
        } else {
            let (file_name, artifact) = self
                .produce_export(&request, environment, &exports, now)
                .await?;
            let kind = request.kind;
            let environment = environment.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                exports.store(kind, environment.as_deref(), &file_name, &artifact, &event)
            })
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
            .map_err(internal)?
        };
        self.audit_export(
            &principal,
            &format!("{operation}.completed"),
            &entry.export.id,
        )?;
        Ok(entry)
    }

    /// `GET /v1/exports`: the exports this credential may read, newest first.
    pub async fn list_exports(
        &self,
        credential: &CredentialMaterial,
        exports: Arc<Exports>,
    ) -> Result<ExportList, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        self.refuse_tenant_exports()?;
        let mut list = tokio::task::spawn_blocking(move || exports.list())
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
            .map_err(internal)?;
        list.exports
            .retain(|entry| self.may_read_export(credential, &context, entry));
        Ok(list)
    }

    /// `GET /v1/exports/{id}`: one export and who created and downloaded it.
    pub async fn inspect_export(
        &self,
        credential: &CredentialMaterial,
        exports: Arc<Exports>,
        id: String,
    ) -> Result<ExportEntry, ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        self.refuse_tenant_exports()?;
        tokio::task::spawn_blocking(move || exports.get(&id))
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
            .map_err(internal)?
            .filter(|entry| self.may_read_export(credential, &context, entry))
            .ok_or_else(export_not_found)
    }

    /// `GET /v1/exports/{id}/download`: the artifact bytes, after the
    /// download and its reason are recorded.
    pub async fn download_export(
        &self,
        credential: &CredentialMaterial,
        exports: Arc<Exports>,
        id: String,
        reason: &str,
    ) -> Result<(crate::exports::ExportRecord, Vec<u8>), ManagementError> {
        let context = self.authenticate(credential)?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        self.refuse_tenant_exports()?;
        let reason = crate::exports::validate_reason(reason)
            .map_err(|error| ManagementError::BadRequest(error.to_string()))?;
        let readable = {
            let (exports, id) = (exports.clone(), id.clone());
            tokio::task::spawn_blocking(move || exports.get(&id))
                .await
                .map_err(|error| ManagementError::Internal(error.to_string()))?
                .map_err(internal)?
                .filter(|entry| self.may_read_export(credential, &context, entry))
        };
        let Some(entry) = readable else {
            return Err(export_not_found());
        };
        let principal = context.audit_principal();
        let operation = format!("export.{}.downloaded", entry.export.kind.as_str());
        let event = ExportEvent {
            at_ms: crate::now_millis(),
            principal: principal.clone(),
            action: ExportAction::Downloaded,
            reason: reason.into(),
        };
        let download = tokio::task::spawn_blocking(move || exports.download(&id, &event))
            .await
            .map_err(|error| ManagementError::Internal(error.to_string()))?
            .map_err(internal)?
            .ok_or_else(export_not_found)?;
        self.audit_export(&principal, &operation, &download.0.id)?;
        Ok(download)
    }

    /// An environment-scoped credential reads only its environment's exports;
    /// hub-wide exports carry no environment, so it never reads those.
    fn may_read_export(
        &self,
        credential: &CredentialMaterial,
        context: &AuthenticatedRequestContext,
        entry: &ExportEntry,
    ) -> bool {
        match self.granted_environment(credential, context) {
            None => true,
            Some(granted) => entry.export.environment.as_deref() == Some(granted),
        }
    }

    /// The artifact bytes and download name, exactly as the CLI writes them.
    async fn produce_export(
        &self,
        request: &ExportRequest,
        environment: Option<&str>,
        exports: &Arc<Exports>,
        now: i64,
    ) -> Result<(String, Vec<u8>), ManagementError> {
        match (request.kind, environment) {
            (ExportKind::SupportBundle, _) => {
                let mut ctx = self.application_ctx()?;
                let bundle = crate::support_bundle::export(
                    Some(&mut ctx),
                    Some(crate::storage::SCHEMA_VERSION),
                    None,
                    exports.seed(),
                    now,
                )
                .await
                .map_err(|error| ManagementError::ExecutionFailed(format!("{error:#}")))?;
                Ok((
                    format!("tenkai-support-bundle-{now}.json"),
                    pretty(&bundle)?,
                ))
            }
            (ExportKind::AuditExport, _) => Err(ManagementError::Internal(
                "audit exports are produced by Exports::next_audit_export".into(),
            )),
            (ExportKind::RecoveryBundle, Some(environment)) => {
                let plan_id = request.plan_id.as_deref().ok_or_else(|| {
                    ManagementError::BadRequest("a recovery-bundle export needs a plan_id".into())
                })?;
                let mut ctx = self.application_ctx()?;
                // A plan of another environment is not disclosed, even as a
                // diagnostic finding: answer as if it did not exist.
                let bound = crate::plan::load(&mut ctx, plan_id)
                    .await
                    .is_ok_and(|plan| plan.environment == environment);
                if !bound {
                    return Err(ManagementError::NotFound(format!(
                        "plan {plan_id} not found in environment {environment}"
                    )));
                }
                let bundle = crate::recovery_bundle::export(&mut ctx, environment, plan_id)
                    .await
                    .map_err(|error| ManagementError::BadRequest(format!("{error:#}")))?;
                crate::recovery_bundle::verify(&bundle).map_err(internal)?;
                Ok((
                    format!("recovery-{environment}-{plan_id}.json"),
                    pretty(&bundle)?,
                ))
            }
            (ExportKind::OfflineReceipt, Some(environment)) => {
                let upgrade = request.upgrade.as_deref().ok_or_else(|| {
                    ManagementError::BadRequest("an offline-receipt export needs an upgrade".into())
                })?;
                let mut ctx = self.application_ctx()?;
                let record = crate::connectivity::load_upgrade(&mut ctx, upgrade)
                    .await
                    .map_err(|error| ManagementError::NotFound(format!("{error:#}")))?;
                let receipt = record
                    .environments
                    .iter()
                    .find(|candidate| candidate.name == environment)
                    .and_then(|candidate| candidate.isolated.as_ref())
                    .and_then(|evidence| evidence.receipt.as_ref())
                    .ok_or_else(|| {
                        ManagementError::NotFound(format!(
                            "upgrade {upgrade} holds no accepted receipt for {environment}"
                        ))
                    })?;
                Ok((
                    format!("{upgrade}-{environment}.receipt.json"),
                    pretty(receipt)?,
                ))
            }
            (_, None) => Err(ManagementError::Internal(
                "environment-scoped export without an environment".into(),
            )),
        }
    }

    fn audit_export(
        &self,
        principal: &str,
        operation: &str,
        id: &str,
    ) -> Result<(), ManagementError> {
        self.store
            .append_audit(&AuditRecord {
                id: uuid::Uuid::new_v4().to_string(),
                occurred_at: crate::now_millis(),
                principal: principal.into(),
                operation: operation.into(),
                resource: format!("export/{id}"),
                outcome: operation.rsplit('.').next().unwrap_or(operation).into(),
            })
            .map_err(|error| ManagementError::Unavailable(error.to_string()))
    }
}

/// Pretty JSON, as the CLI writes every one of these artifacts.
fn pretty<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ManagementError> {
    serde_json::to_vec_pretty(value).map_err(|error| ManagementError::Internal(error.to_string()))
}

fn export_not_found() -> ManagementError {
    ManagementError::NotFound("export not found".into())
}

//! Versioned remote management-lifecycle contract (ADR 0030).
//!
//! Admission for publish, promote, subscribe, plan, approve, apply, rollback,
//! and recall lives here. HTTP adapters and later route implementations call
//! this module; they do not invent a second protocol or reuse spoke runtime
//! RPCs.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::auth_context::PrincipalKind;
use crate::release_signing::{SignatureEnvelope, TrustRoots};

/// Wire and Rust contract version for `tenkai.management-lifecycle.v1`.
pub const MANAGEMENT_LIFECYCLE_API_VERSION: u32 = 1;

/// Stable contract name recorded on the wire and in operator docs.
pub const MANAGEMENT_LIFECYCLE_CONTRACT: &str = "tenkai.management-lifecycle.v1";

/// Closed lifecycle vocabulary accepted by version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementLifecycleOperation {
    Publish,
    Promote,
    Subscribe,
    Plan,
    Approve,
    Apply,
    Rollback,
    Recall,
}

impl ManagementLifecycleOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Promote => "promote",
            Self::Subscribe => "subscribe",
            Self::Plan => "plan",
            Self::Approve => "approve",
            Self::Apply => "apply",
            Self::Rollback => "rollback",
            Self::Recall => "recall",
        }
    }

    /// Catalog-wide verbs have no request environment and cannot be called
    /// with an environment-scoped management credential.
    pub fn is_catalog_wide(self) -> bool {
        matches!(self, Self::Publish | Self::Promote | Self::Recall)
    }

    /// Environment-bound verbs require `environment` on the envelope.
    pub fn requires_environment(self) -> bool {
        !self.is_catalog_wide()
    }

    /// Mutating environment-bound verbs require `expected_generation`.
    pub fn requires_expected_generation(self) -> bool {
        matches!(
            self,
            Self::Subscribe | Self::Plan | Self::Approve | Self::Apply | Self::Rollback
        )
    }
}

/// Fail-closed request header shared by later lifecycle routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementLifecycleEnvelope {
    pub version: u32,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
}

/// Envelope that passed version, operation, field, and scope admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedManagementLifecycle {
    pub operation: ManagementLifecycleOperation,
    pub environment: Option<String>,
    pub expected_generation: Option<u64>,
}

pub fn require_management_lifecycle_api_version(version: u32) -> Result<()> {
    if version != MANAGEMENT_LIFECYCLE_API_VERSION {
        bail!(
            "unsupported management lifecycle API version {version}; expected {MANAGEMENT_LIFECYCLE_API_VERSION}"
        );
    }
    Ok(())
}

pub fn parse_management_lifecycle_operation(name: &str) -> Result<ManagementLifecycleOperation> {
    match name {
        "publish" => Ok(ManagementLifecycleOperation::Publish),
        "promote" => Ok(ManagementLifecycleOperation::Promote),
        "subscribe" => Ok(ManagementLifecycleOperation::Subscribe),
        "plan" => Ok(ManagementLifecycleOperation::Plan),
        "approve" => Ok(ManagementLifecycleOperation::Approve),
        "apply" => Ok(ManagementLifecycleOperation::Apply),
        "rollback" => Ok(ManagementLifecycleOperation::Rollback),
        "recall" => Ok(ManagementLifecycleOperation::Recall),
        other => bail!("unknown management lifecycle operation {other:?}"),
    }
}

/// Refuse runtime principals and environment-scoped credentials that cross
/// their grant. Fleet management (no environment binding) is admitted here;
/// tenant visibility is enforced by later host adapters.
pub fn authorize_management_lifecycle_scope(
    kind: PrincipalKind,
    granted_environment: Option<&str>,
    operation: ManagementLifecycleOperation,
    request_environment: Option<&str>,
) -> Result<()> {
    if kind == PrincipalKind::Runtime {
        bail!("runtime credentials cannot call management lifecycle operations");
    }
    if let Some(granted) = granted_environment {
        if operation.is_catalog_wide() {
            bail!(
                "environment-scoped credentials cannot call catalog-wide management operation {}",
                operation.as_str()
            );
        }
        match request_environment {
            Some(requested) if requested == granted => Ok(()),
            Some(_) => bail!("environment-scoped credentials cannot act on another environment"),
            None => bail!(
                "management operation {} requires environment {}",
                operation.as_str(),
                granted
            ),
        }
    } else {
        Ok(())
    }
}

pub fn admit_management_lifecycle(
    envelope: &ManagementLifecycleEnvelope,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    require_management_lifecycle_api_version(envelope.version)?;
    let operation = parse_management_lifecycle_operation(&envelope.operation)?;
    if operation.requires_environment() {
        match envelope.environment.as_deref() {
            Some(environment) if !environment.trim().is_empty() => {}
            _ => bail!(
                "management operation {} requires environment",
                operation.as_str()
            ),
        }
    } else if envelope.environment.is_some() {
        bail!(
            "management operation {} is catalog-wide and forbids environment",
            operation.as_str()
        );
    }
    if operation.requires_expected_generation() && envelope.expected_generation.is_none() {
        bail!(
            "management operation {} requires expected_generation",
            operation.as_str()
        );
    }
    if !operation.requires_expected_generation() && envelope.expected_generation.is_some() {
        bail!(
            "management operation {} forbids expected_generation",
            operation.as_str()
        );
    }
    authorize_management_lifecycle_scope(
        kind,
        granted_environment,
        operation,
        envelope.environment.as_deref(),
    )?;
    Ok(AdmittedManagementLifecycle {
        operation,
        environment: envelope.environment.clone(),
        expected_generation: envelope.expected_generation,
    })
}

pub fn parse_management_lifecycle_json(
    raw: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let envelope: ManagementLifecycleEnvelope = serde_json::from_str(raw)?;
    admit_management_lifecycle(&envelope, kind, granted_environment)
}

/// Versioned result shared by catalog lifecycle routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementLifecycleResult {
    pub version: u32,
    pub operation: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

impl ManagementLifecycleResult {
    pub fn new(
        operation: ManagementLifecycleOperation,
        message: impl Into<String>,
        resource: Option<String>,
    ) -> Self {
        Self {
            version: MANAGEMENT_LIFECYCLE_API_VERSION,
            operation: operation.as_str().into(),
            message: message.into(),
            resource,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub version: u32,
    pub operation: String,
    pub manifest: String,
    pub signature: SignatureEnvelope,
    pub trust_roots: TrustRoots,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteRequest {
    pub version: u32,
    pub operation: String,
    pub spec: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallRequest {
    pub version: u32,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest {
    pub version: u32,
    pub operation: String,
    pub environment: String,
    pub expected_generation: u64,
    pub spec: String,
}

#[derive(Debug)]
pub struct RemotePublishFiles {
    _dir: PathBuf,
    pub manifest: PathBuf,
    pub signature: PathBuf,
    pub trust_roots: PathBuf,
}

impl RemotePublishFiles {
    pub fn materialize(
        manifest: &str,
        signature: &SignatureEnvelope,
        trust_roots: &TrustRoots,
    ) -> Result<Self> {
        if manifest.trim().is_empty() {
            bail!("publish manifest must not be empty");
        }
        let dir = std::env::temp_dir().join(format!(
            "tenkai-remote-publish-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating publish staging directory {}", dir.display()))?;
        let manifest_path = dir.join("tenkai.toml");
        let signature_path = dir.join("signature.json");
        let trust_roots_path = dir.join("trust-roots.toml");
        std::fs::write(&manifest_path, manifest)
            .with_context(|| format!("writing staged manifest {}", manifest_path.display()))?;
        std::fs::write(&signature_path, serde_json::to_vec(signature)?)
            .with_context(|| format!("writing staged signature {}", signature_path.display()))?;
        std::fs::write(&trust_roots_path, toml::to_string(trust_roots)?).with_context(|| {
            format!("writing staged trust roots {}", trust_roots_path.display())
        })?;
        Ok(Self {
            _dir: dir,
            manifest: manifest_path,
            signature: signature_path,
            trust_roots: trust_roots_path,
        })
    }
}

impl Drop for RemotePublishFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

pub fn admit_publish(
    request: &PublishRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Publish)?;
    Ok(admitted)
}

pub fn admit_promote(
    request: &PromoteRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Promote)?;
    if request.spec.trim().is_empty() {
        bail!("promote requires <product>@<version>");
    }
    Ok(admitted)
}

pub fn admit_recall(
    request: &RecallRequest,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: None,
            expected_generation: None,
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Recall)?;
    Ok(admitted)
}

pub fn admit_subscribe(
    request: &SubscribeRequest,
    path_environment: &str,
    kind: PrincipalKind,
    granted_environment: Option<&str>,
) -> Result<AdmittedManagementLifecycle> {
    if request.environment != path_environment {
        bail!(
            "subscribe environment {} does not match path {path_environment}",
            request.environment
        );
    }
    let admitted = admit_management_lifecycle(
        &ManagementLifecycleEnvelope {
            version: request.version,
            operation: request.operation.clone(),
            environment: Some(request.environment.clone()),
            expected_generation: Some(request.expected_generation),
        },
        kind,
        granted_environment,
    )?;
    require_route_operation(admitted.operation, ManagementLifecycleOperation::Subscribe)?;
    if request.spec.split_once('=').is_none() {
        bail!("subscribe requires <product>=<channel>");
    }
    Ok(admitted)
}

fn require_route_operation(
    found: ManagementLifecycleOperation,
    expected: ManagementLifecycleOperation,
) -> Result<()> {
    if found != expected {
        bail!(
            "management operation {} is not valid on this route; expected {}",
            found.as_str(),
            expected.as_str()
        );
    }
    Ok(())
}

pub fn environment_fence_generation(lease_generation: Option<u64>) -> u64 {
    lease_generation.unwrap_or(0)
}

pub fn require_expected_generation(expected: u64, actual: u64) -> Result<()> {
    if expected != actual {
        bail!("stale fencing generation {expected} cannot subscribe; expected {actual}");
    }
    Ok(())
}

pub fn load_publish_request(
    manifest: &Path,
    signature: &Path,
    trust_roots: &Path,
) -> Result<PublishRequest> {
    Ok(PublishRequest {
        version: MANAGEMENT_LIFECYCLE_API_VERSION,
        operation: ManagementLifecycleOperation::Publish.as_str().into(),
        manifest: std::fs::read_to_string(manifest)
            .with_context(|| format!("reading publish manifest {}", manifest.display()))?,
        signature: SignatureEnvelope::load(signature)?,
        trust_roots: TrustRoots::load(trust_roots)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet_publish() -> &'static str {
        r#"{"version":1,"operation":"publish"}"#
    }

    fn env_apply() -> &'static str {
        r#"{"version":1,"operation":"apply","environment":"stage","expected_generation":7}"#
    }

    #[test]
    fn version_and_unknown_operation_fail_closed() {
        require_management_lifecycle_api_version(MANAGEMENT_LIFECYCLE_API_VERSION).unwrap();
        let err = require_management_lifecycle_api_version(99)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unsupported management lifecycle API version 99"),
            "{err}"
        );
        let err = parse_management_lifecycle_operation("deploy")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown management lifecycle operation \"deploy\""),
            "{err}"
        );
    }

    #[test]
    fn unknown_field_and_development_bypass_fail_closed() {
        let err = parse_management_lifecycle_json(
            r#"{"version":1,"operation":"publish","allow_unapproved_development":true}"#,
            PrincipalKind::Management,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn known_version_and_operation_admit() {
        let admitted =
            parse_management_lifecycle_json(fleet_publish(), PrincipalKind::Management, None)
                .unwrap();
        assert_eq!(admitted.operation, ManagementLifecycleOperation::Publish);
        assert_eq!(admitted.environment, None);

        let admitted =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Management, None).unwrap();
        assert_eq!(admitted.operation, ManagementLifecycleOperation::Apply);
        assert_eq!(admitted.environment.as_deref(), Some("stage"));
        assert_eq!(admitted.expected_generation, Some(7));
    }

    #[test]
    fn runtime_and_crossed_environment_scope_fail_closed() {
        let err =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Runtime, Some("stage"))
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("runtime credentials cannot call management lifecycle"),
            "{err}"
        );

        let err =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Management, Some("prod"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("cannot act on another environment"), "{err}");

        let err = parse_management_lifecycle_json(
            fleet_publish(),
            PrincipalKind::Management,
            Some("stage"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("cannot call catalog-wide management operation publish"),
            "{err}"
        );
    }

    #[test]
    fn environment_scoped_apply_on_granted_environment_admits() {
        let admitted =
            parse_management_lifecycle_json(env_apply(), PrincipalKind::Management, Some("stage"))
                .unwrap();
        assert_eq!(admitted.environment.as_deref(), Some("stage"));
    }

    #[test]
    fn publish_request_rejects_development_bypass_and_wrong_operation() {
        let err = serde_json::from_str::<PublishRequest>(
            r#"{"version":1,"operation":"publish","manifest":"[product]","signature":{"schema":"tenkai.release-signature.v1","key_id":"k","statement":{"manifest_digest":"sha256:aa","artifact_digest":"sha256:bb","provenance":{"source_uri":"src","revision":"1","builder":"test","built_at_unix_ms":1,"materials":{}}},"signature":"c2ln"},"trust_roots":{"version":1,"signers":[{"key_id":"k","identity":"dev","public_key":"cA=="}]},"allow_unsigned_development":true}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field"), "{err}");

        let err = admit_promote(
            &PromoteRequest {
                version: 1,
                operation: "publish".into(),
                spec: "api@1.0.0".into(),
            },
            PrincipalKind::Management,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not valid on this route"), "{err}");
    }

    #[test]
    fn subscribe_refuses_path_mismatch_and_stale_generation() {
        let request = SubscribeRequest {
            version: 1,
            operation: "subscribe".into(),
            environment: "stage".into(),
            expected_generation: 2,
            spec: "api=stable".into(),
        };
        let err = admit_subscribe(&request, "prod", PrincipalKind::Management, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match path"), "{err}");
        let err = require_expected_generation(2, 3).unwrap_err().to_string();
        assert!(err.contains("stale fencing generation 2"), "{err}");
        assert_eq!(environment_fence_generation(None), 0);
        assert_eq!(environment_fence_generation(Some(4)), 4);
    }
}

//! Versioned remote management-lifecycle contract (ADR 0030).
//!
//! Admission for publish, promote, subscribe, plan, approve, apply, rollback,
//! and recall lives here. HTTP adapters and later route implementations call
//! this module; they do not invent a second protocol or reuse spoke runtime
//! RPCs.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::auth_context::PrincipalKind;

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
}

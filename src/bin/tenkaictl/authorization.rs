use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use tenkai::auth_context::AuthenticatedRequestContext;
use tenkai::{apply, assertion_verifier, package_migration, wave};

pub(crate) const JWT_VERIFIER_CONFIG_ENV: &str = "TENKAI_JWT_VERIFIER_CONFIG";
pub(crate) const JWT_ASSERTION_ENV: &str = "TENKAI_JWT_ASSERTION";
pub(crate) fn embedded_management_actor() -> Result<AuthenticatedRequestContext> {
    let token = std::env::var("TENKAI_MANAGEMENT_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let assertion = std::env::var(JWT_ASSERTION_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(String::into_bytes);
    let jwt_path = std::env::var_os(JWT_VERIFIER_CONFIG_ENV).map(PathBuf::from);
    assertion_verifier::authenticate_process_management(
        uuid::Uuid::new_v4().to_string(),
        token,
        assertion,
        jwt_path.as_deref(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}
pub(crate) fn signed_or_local_development<'a, T>(
    evidence: Option<&'a Path>,
    trust_roots: Option<&'a Path>,
    allow_unapproved_development: bool,
    development_reason: Option<&'a str>,
    missing: &str,
    signed: impl FnOnce(&'a Path, &'a Path) -> T,
    local: impl FnOnce(&'a str) -> T,
) -> Result<T> {
    match (evidence, trust_roots, allow_unapproved_development) {
        (Some(evidence), Some(trust_roots), false) => Ok(signed(evidence, trust_roots)),
        (None, None, true) => Ok(local(
            development_reason.expect("clap requires a development reason"),
        )),
        (None, None, false) => bail!("{missing}"),
        _ => unreachable!("clap rejects partial or conflicting authorization modes"),
    }
}

pub(crate) fn execution_authorization<'a>(
    approval: Option<&'a Path>,
    approval_trust_roots: Option<&'a Path>,
    allow_unapproved_development: bool,
    development_reason: Option<&'a str>,
    missing: &str,
) -> Result<apply::ExecutionAuthorization<'a>> {
    signed_or_local_development(
        approval,
        approval_trust_roots,
        allow_unapproved_development,
        development_reason,
        missing,
        |approval, trust_roots| apply::ExecutionAuthorization::Signed {
            approval,
            trust_roots,
        },
        |reason| apply::ExecutionAuthorization::LocalDevelopment { reason },
    )
}
pub(crate) fn reject_remote_migration_bypass(allow_unapproved_development: bool) -> Result<()> {
    if allow_unapproved_development {
        bail!(
            "the local-development package-migration bypass is available only with --target embedded"
        );
    }
    Ok(())
}

pub(crate) fn load_remote_migration_authorization(
    approval: Option<PathBuf>,
    approval_trust_roots: Option<PathBuf>,
) -> Result<(
    package_migration::MigrationApprovalEnvelope,
    package_migration::ApprovalTrustRoots,
    std::collections::BTreeMap<String, tenkai::plan_approval::ApprovalEnvelope>,
)> {
    let approval = approval.ok_or_else(|| {
        anyhow::anyhow!("remote package migration requires --approval and --approval-trust-roots")
    })?;
    let trust_roots = approval_trust_roots.ok_or_else(|| {
        anyhow::anyhow!("remote package migration requires --approval and --approval-trust-roots")
    })?;
    let raw = std::fs::read(&approval)
        .with_context(|| format!("reading package migration approval {}", approval.display()))?;
    let envelope: package_migration::MigrationApprovalEnvelope =
        serde_json::from_slice(&raw).context("parsing package migration approval envelope")?;
    let roots = package_migration::load_trust_roots(&trust_roots)?;
    Ok((envelope, roots, sibling_plan_approvals(&approval)?))
}

pub(crate) fn approval_parent_dir(approval: &std::path::Path) -> &std::path::Path {
    approval
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
}

pub(crate) fn sibling_plan_approvals(
    approval: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, tenkai::plan_approval::ApprovalEnvelope>> {
    let mut plan_approvals = std::collections::BTreeMap::new();
    let dir = approval_parent_dir(approval);
    let approval_name = approval.file_name();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(plan_approvals),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "reading package migration approval directory {}",
                    dir.display()
                )
            });
        }
    };
    for entry in entries {
        let path = entry?.path();
        if path.file_name() == approval_name {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let raw = std::fs::read(&path)
            .with_context(|| format!("reading plan approval {}", path.display()))?;
        let envelope: tenkai::plan_approval::ApprovalEnvelope = match serde_json::from_slice(&raw) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        if envelope.schema != tenkai::plan_approval::APPROVAL_SCHEMA {
            continue;
        }
        plan_approvals.insert(stem.to_string(), envelope);
    }
    Ok(plan_approvals)
}

pub(crate) fn migration_authorization<'a>(
    approval: Option<&'a Path>,
    approval_trust_roots: Option<&'a Path>,
    allow_unapproved_development: bool,
    development_reason: Option<&'a str>,
) -> Result<package_migration::MigrationAuthorization<'a>> {
    signed_or_local_development(
        approval,
        approval_trust_roots,
        allow_unapproved_development,
        development_reason,
        "package migration requires --approval and --approval-trust-roots, or --allow-unapproved-development with --development-reason",
        |approval, trust_roots| package_migration::MigrationAuthorization::Signed {
            approval,
            trust_roots,
        },
        |reason| package_migration::MigrationAuthorization::LocalDevelopment { reason },
    )
}

pub(crate) fn wave_authorization<'a>(
    approval_dir: Option<&'a Path>,
    approval_trust_roots: Option<&'a Path>,
    allow_unapproved_development: bool,
    development_reason: Option<&'a str>,
) -> Result<wave::WaveAuthorization<'a>> {
    signed_or_local_development(
        approval_dir,
        approval_trust_roots,
        allow_unapproved_development,
        development_reason,
        "wave execution requires --approval-dir and --approval-trust-roots, or --allow-unapproved-development with --development-reason",
        |approval_dir, trust_roots| wave::WaveAuthorization::Signed {
            approval_dir,
            trust_roots,
        },
        |reason| wave::WaveAuthorization::LocalDevelopment { reason },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenkai::apply;

    #[test]
    fn sibling_plan_approvals_read_the_current_directory_for_bare_filenames() {
        assert_eq!(
            approval_parent_dir(std::path::Path::new("cutover.approval.json")),
            std::path::Path::new(".")
        );
        assert_eq!(
            approval_parent_dir(std::path::Path::new("./cutover.approval.json")),
            std::path::Path::new(".")
        );
        assert_eq!(
            approval_parent_dir(std::path::Path::new("approvals/cutover.approval.json")),
            std::path::Path::new("approvals")
        );
    }

    #[test]
    fn signed_or_local_development_preserves_fail_closed_messages() {
        let signed = execution_authorization(
            Some(Path::new("plan.approval.json")),
            Some(Path::new("approvers.toml")),
            false,
            None,
            "missing",
        )
        .unwrap();
        assert!(matches!(
            signed,
            apply::ExecutionAuthorization::Signed { .. }
        ));

        let local =
            execution_authorization(None, None, true, Some("local drill"), "missing").unwrap();
        assert!(matches!(
            local,
            apply::ExecutionAuthorization::LocalDevelopment {
                reason: "local drill"
            }
        ));

        let error =
            execution_authorization(None, None, false, None, "plan execution requires flags")
                .unwrap_err();
        assert_eq!(error.to_string(), "plan execution requires flags");
    }
}

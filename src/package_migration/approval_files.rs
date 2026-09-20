//! Trust-root loading and scratch approval files for remote execution.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use super::types::{
    ApprovalTrustRoots, MIGRATION_API_VERSION, MigrationApprovalEnvelope, TRUST_ROOT_VERSION,
};

pub fn require_migration_api_version(version: u32) -> Result<()> {
    if version != MIGRATION_API_VERSION {
        bail!(
            "unsupported package migration API version {version}; expected {MIGRATION_API_VERSION}"
        );
    }
    Ok(())
}

pub fn load_trust_roots(path: &Path) -> Result<ApprovalTrustRoots> {
    let roots_raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading package migration approval trust roots {}",
            path.display()
        )
    })?;
    let roots: ApprovalTrustRoots = toml::from_str(&roots_raw).with_context(|| {
        format!(
            "parsing package migration approval trust roots {}",
            path.display()
        )
    })?;
    if roots.version != TRUST_ROOT_VERSION || roots.signers.is_empty() {
        bail!(
            "package migration approval trust roots must use version {TRUST_ROOT_VERSION} and contain at least one signer"
        );
    }
    Ok(roots)
}

#[derive(Debug)]
pub struct RemoteApprovalFiles {
    dir: PathBuf,
    pub approval: PathBuf,
    pub trust_roots: PathBuf,
}

impl Drop for RemoteApprovalFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) fn validate_plan_approval_filename(plan_id: &str) -> Result<()> {
    anyhow::ensure!(
        !plan_id.is_empty(),
        "package migration plan approval id is empty"
    );
    anyhow::ensure!(
        !plan_id.contains('/')
            && !plan_id.contains('\\')
            && !plan_id.contains('\0')
            && !plan_id.contains(".."),
        "package migration plan approval id {plan_id} is not a safe file name"
    );
    Ok(())
}

impl RemoteApprovalFiles {
    pub fn materialize(
        approval: &MigrationApprovalEnvelope,
        trust_roots: &ApprovalTrustRoots,
        plan_approvals: &BTreeMap<String, crate::plan_approval::ApprovalEnvelope>,
    ) -> Result<Self> {
        if trust_roots.version != TRUST_ROOT_VERSION || trust_roots.signers.is_empty() {
            bail!(
                "package migration approval trust roots must use version {TRUST_ROOT_VERSION} and contain at least one signer"
            );
        }
        for plan_id in plan_approvals.keys() {
            validate_plan_approval_filename(plan_id)?;
        }
        let dir = std::env::temp_dir().join(format!(
            "tenkai-migration-auth-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).with_context(|| {
            format!(
                "creating package migration approval scratch {}",
                dir.display()
            )
        })?;
        let files = Self {
            approval: dir.join("approval.json"),
            trust_roots: dir.join("trust.toml"),
            dir,
        };
        std::fs::write(&files.approval, serde_json::to_vec(approval)?)
            .with_context(|| format!("writing {}", files.approval.display()))?;
        std::fs::write(&files.trust_roots, toml::to_string(trust_roots)?)
            .with_context(|| format!("writing {}", files.trust_roots.display()))?;
        for (plan_id, envelope) in plan_approvals {
            let path = files.dir.join(format!("{plan_id}.json"));
            std::fs::write(&path, serde_json::to_vec(envelope)?)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(files)
    }

    pub async fn materialize_async(
        approval: MigrationApprovalEnvelope,
        trust_roots: ApprovalTrustRoots,
        plan_approvals: BTreeMap<String, crate::plan_approval::ApprovalEnvelope>,
    ) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            Self::materialize(&approval, &trust_roots, &plan_approvals)
        })
        .await
        .map_err(|error| {
            anyhow::anyhow!("package migration approval materialize task failed: {error}")
        })?
    }
}

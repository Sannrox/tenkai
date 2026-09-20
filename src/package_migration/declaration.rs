//! Declaration validation, identity digest, and checkpoint effect names.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::ontology::validate_identifier;
use crate::signature_verification;

use super::types::{
    COMPATIBILITY_VERSION, CheckpointClass, MIGRATION_DOCUMENT_VERSION, MIGRATION_PROFILE,
    MigrationDeclaration, PackagePin,
};

pub(super) fn checkpoint_effect(class: CheckpointClass) -> &'static str {
    match class {
        CheckpointClass::Compensating => "apply_target",
        CheckpointClass::Reversible | CheckpointClass::Irreversible => "revalidate",
    }
}

impl PackagePin {
    pub(super) fn validate(&self, label: &str) -> Result<()> {
        validate_identifier(&format!("{label} product"), &self.product)?;
        validate_identifier(&format!("{label} version"), &self.version)?;
        signature_verification::validate_prefixed_digest(&format!("{label} digest"), &self.digest)?;
        Ok(())
    }
}

impl MigrationDeclaration {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading package migration {}", path.display()))?;
        let doc: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing package migration {}", path.display()))?;
        doc.validate()?;
        Ok(doc)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MIGRATION_DOCUMENT_VERSION {
            bail!(
                "unsupported package migration version {}; expected {MIGRATION_DOCUMENT_VERSION}",
                self.version
            );
        }
        if self.profile != MIGRATION_PROFILE {
            bail!(
                "unknown package migration profile {:?}; expected {MIGRATION_PROFILE}",
                self.profile
            );
        }
        self.source.validate("source")?;
        self.target.validate("target")?;
        if self.source == self.target {
            bail!("package migration source and target must differ");
        }
        if self.source.product != self.target.product {
            bail!("package migration source and target must name the same product");
        }
        if self.compatibility.version != COMPATIBILITY_VERSION {
            bail!(
                "unsupported compatibility evidence version {}; expected {COMPATIBILITY_VERSION}",
                self.compatibility.version
            );
        }
        signature_verification::validate_prefixed_digest(
            "compatibility evidence digest",
            &self.compatibility.evidence_digest,
        )?;
        if self.checkpoints.is_empty() {
            bail!("package migration must declare at least one checkpoint");
        }
        let mut seen = BTreeSet::new();
        for checkpoint in &self.checkpoints {
            validate_identifier("checkpoint id", &checkpoint.id)?;
            if !seen.insert(checkpoint.id.as_str()) {
                bail!("duplicate checkpoint id {}", checkpoint.id);
            }
            match checkpoint.class {
                CheckpointClass::Irreversible => {
                    let Some(handling) = checkpoint.pre_admission.as_deref() else {
                        bail!(
                            "irreversible checkpoint {} requires explicit pre-admission handling",
                            checkpoint.id
                        );
                    };
                    if handling != "require_backup_receipt" {
                        bail!(
                            "unknown irreversible pre-admission {handling:?} on checkpoint {}",
                            checkpoint.id
                        );
                    }
                }
                CheckpointClass::Reversible | CheckpointClass::Compensating => {
                    if checkpoint.pre_admission.is_some() {
                        bail!(
                            "checkpoint {} is not irreversible and cannot declare pre-admission handling",
                            checkpoint.id
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub fn identity_digest(
        &self,
        environment: &str,
        backup_receipt_digest: Option<&str>,
    ) -> Result<String> {
        self.validate()?;
        if let Some(digest) = backup_receipt_digest {
            signature_verification::validate_prefixed_digest("backup receipt digest", digest)?;
        }
        let canonical = serde_json::to_vec(self)?;
        let mut output = b"TENKAI-PACKAGE-MIGRATION-V1\0".to_vec();
        signature_verification::push_len_prefixed(&mut output, environment.as_bytes());
        signature_verification::push_len_prefixed(&mut output, &canonical);
        signature_verification::push_len_prefixed(
            &mut output,
            backup_receipt_digest.unwrap_or_default().as_bytes(),
        );
        Ok(format!("sha256:{:x}", Sha256::digest(output)))
    }
}

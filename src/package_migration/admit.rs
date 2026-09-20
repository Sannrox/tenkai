//! Admission of a new package migration record against published pins.

use anyhow::{Context as _, Result, bail};

use crate::catalog;
use crate::client::Ctx;
use crate::ontology::validate_identifier;
use crate::signature_verification;

use super::persist::persist_new;
use super::types::{
    CheckpointClass, CompatibilityStatus, MigrationDeclaration, MigrationRecord, MigrationStatus,
    PackagePin,
};

pub(super) async fn admit(
    ctx: &mut Ctx,
    name: &str,
    environment: &str,
    declaration: MigrationDeclaration,
    backup_receipt_digest: Option<&str>,
    preview_only: bool,
    partition: Option<&str>,
) -> Result<MigrationRecord> {
    validate_identifier("migration name", name)?;
    validate_identifier("environment", environment)?;
    if let Some(partition) = partition {
        validate_identifier("migration partition", partition)?;
    }
    declaration.validate()?;
    if declaration.compatibility.status != CompatibilityStatus::Compatible {
        bail!("package migration compatibility evidence is not compatible");
    }
    crate::environment::environment(ctx, environment).await?;
    require_package_pin(ctx, &declaration.source).await?;
    require_package_pin(ctx, &declaration.target).await?;
    if catalog::release_is_recalled(
        ctx,
        &crate::ontology::release_id(&declaration.source.product, &declaration.source.version),
    )
    .await?
        || catalog::release_is_recalled(
            ctx,
            &crate::ontology::release_id(&declaration.target.product, &declaration.target.version),
        )
        .await?
    {
        bail!("package migration cannot use a recalled source or target release");
    }
    let needs_backup = declaration
        .checkpoints
        .iter()
        .any(|checkpoint| checkpoint.class == CheckpointClass::Irreversible);
    let backup = match backup_receipt_digest {
        Some(digest) => {
            signature_verification::validate_prefixed_digest("backup receipt digest", digest)?;
            Some(digest.to_string())
        }
        None if needs_backup => {
            bail!(
                "irreversible package migration requires a backup receipt digest before admission"
            )
        }
        None => None,
    };
    let record = MigrationRecord {
        name: name.into(),
        environment: environment.into(),
        partition: partition
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        identity_digest: declaration.identity_digest(environment, backup.as_deref())?,
        declaration,
        approval_digest: String::new(),
        fence_generation: 0,
        status: MigrationStatus::Admitted,
        receipts: Vec::new(),
        backup_receipt_digest: backup,
        pending_plan_id: None,
        pending_rollback_plan_id: None,
    };
    if preview_only {
        return Ok(record);
    }
    persist_new(ctx, &record).await?;
    Ok(record)
}

pub(super) async fn require_package_pin(ctx: &mut Ctx, pin: &PackagePin) -> Result<()> {
    let release_id = crate::ontology::release_id(&pin.product, &pin.version);
    let object = ctx
        .get(&release_id)
        .await?
        .with_context(|| format!("release {}@{} is not published", pin.product, pin.version))?;
    let digest = catalog_digest(
        object
            .properties
            .get("digest")
            .map(String::as_str)
            .unwrap_or_default(),
    )?;
    if digest != pin.digest {
        bail!(
            "release {}@{} digest {digest} does not match migration pin {}",
            pin.product,
            pin.version,
            pin.digest
        );
    }
    Ok(())
}

pub(super) fn catalog_digest(stored: &str) -> Result<String> {
    let prefixed = if stored.starts_with("sha256:") {
        stored.to_string()
    } else {
        format!("sha256:{stored}")
    };
    signature_verification::validate_prefixed_digest("catalog release digest", &prefixed)?;
    Ok(prefixed)
}

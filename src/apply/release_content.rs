//! Immutable Release admission for Plan execution.
//!
//! This module owns the trust, snapshot, digest, filesystem, and runtime-path
//! invariants required before product execution can consume a pinned Release.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use super::*;

pub(super) struct ReleaseContent {
    pub(super) manifest: Manifest,
    pub(super) artifact_digest: String,
    pub(super) workdir: PathBuf,
    pub(super) environment: String,
    pub(super) product: String,
    pub(super) mutation_lock: PathBuf,
    pub(super) routing_state: PathBuf,
    pub(super) model_runtime_state: PathBuf,
}

pub(super) fn verify_integrity(content: &ReleaseContent) -> Result<()> {
    let actual = manifest::artifact_digest(&content.workdir, &content.manifest.immutable_inputs())?;
    if actual != content.artifact_digest {
        bail!("immutable deployment inputs changed while executing release");
    }
    Ok(())
}

pub(super) async fn admit(
    ctx: &mut Ctx,
    pin: &ReleasePin,
    environment: &str,
    product: &str,
) -> Result<ReleaseContent> {
    use crate::catalog::CatalogReader as _;

    let descriptor = crate::catalog::EmbeddedCatalog::new(ctx)
        .lookup_release(&pin.release_id, environment)
        .await?;
    let Some(object) = ctx.get(&pin.release_id).await? else {
        bail!("release object {} not found", pin.release_id);
    };
    if object.kind != KIND_RELEASE {
        bail!(
            "object {} is {}, not {KIND_RELEASE}",
            pin.release_id,
            object.kind
        );
    }
    if object
        .properties
        .get("recalled_at")
        .is_some_and(|value| !value.is_empty())
    {
        bail!("release {} is recalled", pin.release_id);
    }

    // Validate the exact snapshot consumed below as well as the Catalog
    // descriptor fetched above; the compatibility store does not yet provide
    // a transactional read spanning those records.
    crate::catalog::require_deployable_trust(ctx, &object, environment).await?;
    let raw = object
        .properties
        .get("manifest")
        .cloned()
        .unwrap_or_default();
    let stored_digest = object.properties.get("digest").cloned().unwrap_or_default();
    let actual_digest = manifest::digest(&raw);
    if descriptor.manifest_digest != pin.digest
        || stored_digest != pin.digest
        || actual_digest != pin.digest
    {
        bail!(
            "release {} content no longer matches pinned digest {}",
            pin.release_id,
            pin.digest
        );
    }
    let manifest = manifest::parse_raw(&raw)
        .with_context(|| format!("parsing stored manifest of {}", pin.release_id))?;
    if descriptor.artifact_digest != pin.artifact_digest || descriptor.content_path != pin.workdir {
        bail!(
            "release {} descriptor no longer matches its plan pin",
            pin.release_id
        );
    }
    let actual_artifact_digest = manifest::artifact_digest(
        Path::new(&descriptor.content_path),
        &manifest.immutable_inputs(),
    )?;
    if actual_artifact_digest != descriptor.artifact_digest {
        bail!(
            "release {} immutable deploy inputs no longer match pinned artifact digest {}",
            pin.release_id,
            pin.artifact_digest
        );
    }
    let workdir = manifest::execution_workdir(
        Path::new(&descriptor.content_path),
        &manifest.immutable_inputs(),
        &pin.artifact_digest,
        environment,
        product,
    )?;
    let state_dir = Path::new(&descriptor.content_path)
        .parent()
        .and_then(Path::parent)
        .context("release snapshot is not inside the Tenkai state directory")?;
    let runtime_dir = state_dir.join("runtime").join(environment);

    Ok(ReleaseContent {
        manifest,
        artifact_digest: pin.artifact_digest.clone(),
        workdir,
        environment: environment.to_string(),
        product: product.to_string(),
        mutation_lock: runtime_dir.join(".mutation.lock"),
        routing_state: runtime_dir.join("routing").join(format!("{product}.json")),
        model_runtime_state: runtime_dir
            .join("model_runtime")
            .join(format!("{product}.json")),
    })
}

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
    /// Environment-mirror refs admitted for this apply. Origin pull is refused.
    pub(super) artifact_pulls: Vec<crate::oci_artifact::OciArtifactRef>,
}

pub(super) fn verify_integrity(content: &ReleaseContent) -> Result<()> {
    let actual = manifest::identity_digest(
        &content.workdir,
        &content.manifest.immutable_inputs(),
        &content.manifest.artifacts,
    )?;
    if actual != content.artifact_digest {
        bail!("immutable deployment inputs changed while executing release");
    }
    if !content.manifest.artifacts.is_empty() && content.artifact_pulls.is_empty() {
        bail!("digest-bound artifacts have no admitted environment-mirror pull");
    }
    for (declared, pull) in content
        .manifest
        .artifacts
        .iter()
        .zip(content.artifact_pulls.iter())
    {
        if pull.digest != declared.digest {
            bail!(
                "admitted pull digest {} does not match declared {}",
                pull.digest,
                declared.digest
            );
        }
    }
    Ok(())
}

pub(super) async fn admit(
    ctx: &mut Ctx,
    pin: &ReleasePin,
    environment: &str,
    product: &str,
    recalled_recovery: bool,
) -> Result<ReleaseContent> {
    let snapshot = if recalled_recovery {
        crate::catalog::load_recoverable_snapshot(ctx, &pin.release_id, environment).await?
    } else {
        crate::catalog::load_deployable_snapshot(ctx, &pin.release_id, environment).await?
    };
    let descriptor = snapshot.descriptor;
    let object = snapshot.object;
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
    let file_digest = manifest::artifact_digest(
        Path::new(&descriptor.content_path),
        &manifest.immutable_inputs(),
    )?;
    let actual_artifact_digest = manifest::identity_digest(
        Path::new(&descriptor.content_path),
        &manifest.immutable_inputs(),
        &manifest.artifacts,
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
        &file_digest,
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
        artifact_pulls: Vec::new(),
    })
}

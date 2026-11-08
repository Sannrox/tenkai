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
    pub(super) manifest_digest: String,
    pub(super) workdir: PathBuf,
    pub(super) environment: String,
    pub(super) product: String,
    /// Instance this apply is for. Empty means the product.
    pub(super) instance: String,
    pub(super) mutation_lock: PathBuf,
    pub(super) routing_state: PathBuf,
    pub(super) model_runtime_state: PathBuf,
    /// Environment-mirror refs admitted for this apply. Origin pull is refused.
    pub(super) artifact_pulls: Vec<crate::oci_artifact::OciArtifactRef>,
    /// The manifest text exactly as signed; a host step hands it to the applier.
    pub(super) raw_manifest: String,
    /// Root the manifest's immutable inputs are relative to.
    pub(super) content_root: PathBuf,
    /// Sealed bindings the plan step named; the executed configuration
    /// digest covers these, not whatever the environment holds by then.
    pub(super) sealed: Vec<crate::plan::SealedStep>,
}

impl ReleaseContent {
    /// Instance this apply is for. Empty `instance` means the product.
    pub(super) fn instance_name(&self) -> &str {
        if self.instance.is_empty() {
            &self.product
        } else {
            &self.instance
        }
    }
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
    step: &Step,
    recalled_recovery: bool,
) -> Result<ReleaseContent> {
    let product = step.product.as_str();
    let instance = step.instance_name();
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
    // `pin.workdir` / `step.workdir` keep the signed plan identity, including
    // exporter-local locators. Isolated first-install snapshots the same
    // digest-bound content onto a host-local path; execution uses that snapshot
    // (`descriptor.content_path`) rather than rewriting the stored plan.
    if descriptor.artifact_digest != pin.artifact_digest {
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
        manifest_digest: pin.digest.clone(),
        workdir,
        environment: environment.to_string(),
        product: product.to_string(),
        instance: if instance.is_empty() || instance == product {
            String::new()
        } else {
            instance.to_string()
        },
        mutation_lock: runtime_dir.join(".mutation.lock"),
        routing_state: runtime_dir.join("routing").join(format!("{product}.json")),
        model_runtime_state: runtime_dir
            .join("model_runtime")
            .join(format!("{product}.json")),
        artifact_pulls: Vec::new(),
        content_root: PathBuf::from(&descriptor.content_path),
        raw_manifest: raw,
        sealed: step.sealed.clone(),
    })
}

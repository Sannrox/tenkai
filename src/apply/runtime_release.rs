//! The release package a claimed environment runtime applies itself
//! (ADR 0048 §3).
//!
//! The server admits the release exactly as it would before applying it, then
//! hands over the signed manifest, its signature, the deploy inputs, and the
//! executor request it computed. The runtime verifies all of it on its own.

use super::*;
use crate::runtime_delivery::{RuntimeRelease, RuntimeReleaseEntry, RuntimeSealedValue};
use anyhow::anyhow;
use base64::Engine as _;
use std::path::Path;

/// Why the server will not hand a step's release to a runtime: the step fails
/// with this reason. Admission and its compatibility, placement, and mirror
/// checks refuse, as any of them failing fails the plan when the server
/// applies it. Any other error may pass, so the runtime retries it.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct ReleaseRefused(String);

fn refused(error: anyhow::Error) -> anyhow::Error {
    ReleaseRefused(format!("{error:#}")).into()
}

/// Build the release package for `step` of `plan`: its target, or with
/// `restore` its restore pin. Refuses, with [`ReleaseRefused`], steps a
/// runtime cannot apply with a built-in executor (removals) and releases the
/// server would not apply itself. A host step's package is its release; the
/// runtime hands it to its own host applier.
pub(crate) async fn runtime_release(
    ctx: &mut Ctx,
    plan: &Plan,
    step: &Step,
    restore: bool,
) -> Result<RuntimeRelease> {
    if step.host.is_some() && restore {
        return Err(refused(anyhow!(
            "step {} is a host step; host releases are never restored automatically",
            step.id
        )));
    }
    if step.action == Action::Remove {
        return Err(refused(anyhow!(
            "step {} removes a release; removals do not run through a runtime's built-in executors",
            step.id
        )));
    }
    let recalled = plan
        .recalled_recovery_reason
        .as_deref()
        .is_some_and(|reason| !reason.trim().is_empty())
        && step.action == Action::Rollback;
    let pin = if restore {
        step.restore
            .clone()
            .ok_or_else(|| refused(anyhow!("step {} has no pinned restore release", step.id)))?
    } else {
        ReleasePin {
            release_id: step.release_id.clone(),
            digest: step.release_digest.clone(),
            artifact_digest: step.artifact_digest.clone(),
            workdir: step.workdir.clone(),
        }
    };
    let mut content = admit_release(ctx, &pin, &plan.environment, step, recalled)
        .await
        .map_err(refused)?;
    if content.manifest.product.kind.policy().target()
        != crate::product_kind::ProductTarget::Software
    {
        return Err(refused(anyhow!(
            "release {} is not a software product; the server applies it",
            pin.release_id
        )));
    }
    // The same checks the server runs before it applies a release itself.
    // A restore pin was compatible when it was installed; it is only placed.
    if !restore {
        crate::software_compatibility::require_manifest(
            ctx,
            &plan.environment,
            &content.manifest,
            &content.manifest_digest,
            content.instance_name(),
        )
        .await
        .map_err(refused)?;
    }
    crate::topology::require_manifest_placement(ctx, &plan.environment, &content.manifest)
        .await
        .map_err(refused)?;
    let environment = crate::environment::environment(ctx, &plan.environment).await?;
    let registry = crate::oci_artifact::selected_registry()?;
    content.artifact_pulls = crate::oci_artifact::verify_environment_pull(
        &content.manifest.artifacts,
        &environment.properties,
        registry.as_deref(),
    )
    .map_err(refused)?;
    let mut request =
        product_execution::software_request(ctx, &content, format!("plan-{}-{}", plan.id, step.id))
            .await?;
    // Host-local: the runtime sets these from its own configuration.
    request.workdir = std::path::PathBuf::new();
    request.cluster_config_path = None;
    request.secret_dir_path = None;
    let signature = crate::catalog::signature_envelope(ctx, &pin.release_id).await?;
    let entries = release_entries(&content.workdir, &content.manifest.immutable_inputs())?;
    let replaces = match step.from.as_deref() {
        Some(installed) if !restore && step.restore.is_none() && step.action != Action::Restart => {
            let installed = crate::ontology::release_id(&step.product, installed);
            let executor = crate::plan::stored_release_executor(ctx, &installed).await?;
            Some(crate::runtime_delivery::RuntimeReplacedRelease {
                executor: executor.map(|kind| kind.as_str().to_owned()),
            })
        }
        _ => None,
    };
    // The restore pin reads the same values: they are the instance's, not
    // the release's.
    let sealed = if step.sealed.is_empty() {
        Vec::new()
    } else {
        crate::sealed_secret::step_values(&environment, step.instance_name(), &step.sealed)
            .map_err(refused)?
            .into_iter()
            .map(|(binding, sealed)| RuntimeSealedValue {
                secret: binding.secret,
                key: binding.key,
                sealed,
            })
            .collect()
    };
    Ok(RuntimeRelease {
        manifest: content.raw_manifest,
        signature,
        request,
        entries,
        replaces,
        sealed,
    })
}

/// Every file and directory under `inputs`, relative to `root`, parents
/// before children and siblings sorted, so the runtime can rebuild the tree
/// and hash it the way [`manifest::artifact_digest`] does.
fn release_entries(root: &Path, inputs: &[String]) -> Result<Vec<RuntimeReleaseEntry>> {
    fn walk(root: &Path, path: &Path, entries: &mut Vec<RuntimeReleaseEntry>) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("reading deploy input {}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .context("deploy input outside the release root")?
            .to_str()
            .context("deploy input path is not UTF-8")?
            .to_string();
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.is_dir() {
            entries.push(RuntimeReleaseEntry {
                path: relative,
                mode,
                contents: None,
            });
            let mut children =
                std::fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                walk(root, &child.path(), entries)?;
            }
        } else if metadata.is_file() {
            let bytes = std::fs::read(path)?;
            entries.push(RuntimeReleaseEntry {
                path: relative,
                mode,
                contents: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            });
        } else {
            bail!("deploy input {relative} is not a regular file or directory");
        }
        Ok(())
    }
    let mut entries = Vec::new();
    for input in inputs {
        walk(root, &root.join(input), &mut entries)?;
    }
    // Inputs may overlap (a document inside an input directory): keep the
    // first copy, which comes with its parents.
    let mut seen = std::collections::HashSet::new();
    entries.retain(|entry| seen.insert(entry.path.clone()));
    Ok(entries)
}

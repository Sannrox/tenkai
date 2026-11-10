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
/// `restore` its restore pin. Refuses, with [`ReleaseRefused`], releases the
/// server would not apply itself. A host step's package is its release; the
/// runtime hands it to its own host applier. A removal's package is the
/// release to remove (ADR 0049).
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
    if step.issuer.is_some() {
        return Err(refused(anyhow!(
            "step {} is an identity issuer step and has no release",
            step.id
        )));
    }
    if step.rewrap.is_some() {
        if restore {
            return Err(refused(anyhow!(
                "step {} re-wraps sealed values and has no restore pin",
                step.id
            )));
        }
        return rewrap_package(ctx, plan, step).await;
    }
    // Subscribing does not wait for a runtime, so a removal claimed earlier
    // must not remove an instance that is desired again; the runtime asks
    // for the package right before it removes.
    if step.action == Action::Remove && !restore {
        let environment = crate::environment::environment(ctx, &plan.environment).await?;
        if crate::environment::list_subscriptions(ctx, &environment)
            .await?
            .iter()
            .any(|subscription| subscription.instance == step.instance_name())
        {
            return Err(refused(anyhow!(
                "{} subscribes to {} again",
                plan.environment,
                step.instance_name()
            )));
        }
    }
    let recovery = plan
        .recalled_recovery_reason
        .as_deref()
        .is_some_and(|reason| !reason.trim().is_empty());
    // Removing a recalled release deploys nothing, as on the server.
    let recalled = (recovery && step.action == Action::Rollback) || step.action == Action::Remove;
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
    // A removal deploys nothing, so it is neither checked nor placed.
    let removal = step.action == Action::Remove;
    if !restore && !removal {
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
    if !removal {
        crate::topology::require_manifest_placement(ctx, &plan.environment, &content.manifest)
            .await
            .map_err(refused)?;
    }
    let environment = crate::environment::environment(ctx, &plan.environment).await?;
    let registry = crate::oci_artifact::selected_registry()?;
    content.artifact_pulls = crate::oci_artifact::verify_environment_pull(
        &content.manifest.artifacts,
        &environment.properties,
        registry.as_deref(),
    )
    .map_err(refused)?;
    let attempt = format!("plan-{}-{}", plan.id, step.id);
    let mut request = if removal {
        product_execution::removal_request(ctx, &content, attempt).await?
    } else {
        product_execution::software_request(ctx, &content, attempt).await?
    };
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
    // The issuer as recorded now; the runtime refuses it unless it is the
    // generation and key the step grants.
    let identity_issuer = match step.identity_grants().next() {
        Some(_) => Some(
            crate::identity_issuer::current(&environment)?
                .context("the environment has no identity issuer")
                .map_err(refused)?,
        ),
        None => None,
    };
    Ok(RuntimeRelease {
        manifest: content.raw_manifest,
        signature,
        request,
        entries,
        replaces,
        sealed,
        rewrap_recipient: None,
        identity_issuer,
    })
}

/// The package of a re-wrap step (ADR 0045 §5): the sealed values it names,
/// in its order, and nothing a deployment needs. No release content is
/// admitted, no artifact pulled and no input packaged, so an unreachable
/// registry or a missing input never blocks re-wrapping. The runtime uses
/// only the sealed values and the recipient key the caller adds.
async fn rewrap_package(ctx: &mut Ctx, plan: &Plan, step: &Step) -> Result<RuntimeRelease> {
    let environment = crate::environment::environment(ctx, &plan.environment).await?;
    let sealed =
        crate::sealed_secret::step_values(&environment, step.instance_name(), &step.sealed)
            .map_err(refused)?
            .into_iter()
            .map(|(binding, sealed)| RuntimeSealedValue {
                secret: binding.secret,
                key: binding.key,
                sealed,
            })
            .collect();
    let mut request = crate::software_executor::request_from_parts(
        &step.product,
        &step.to,
        &plan.environment,
        Path::new(""),
        &step.release_id,
    );
    request.instance = step.instance.clone();
    Ok(RuntimeRelease {
        manifest: String::new(),
        signature: crate::catalog::signature_envelope(ctx, &step.release_id).await?,
        request,
        entries: Vec::new(),
        replaces: None,
        sealed,
        rewrap_recipient: None,
        identity_issuer: None,
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

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use tenkai::client::Ctx;
use tenkai::oci_artifact::{FilesystemArtifactRegistry, MemoryArtifactRegistry};
use tenkai::offline_bundle_build::{self, BundleBuildRequest};
use tenkai::offline_host_binaries::{HostBinaryInput, HostBinaryProvenance, HostBinaryRole};
use tenkai::ontology;
use tenkai::release_signing::TrustRoots;

use crate::bundle_args::BundleCommand;

pub(crate) async fn run(ctx: &mut Ctx, command: BundleCommand) -> Result<()> {
    match command {
        BundleCommand::Build {
            releases,
            env,
            out,
            signing_key,
            trust_roots,
            hosts_dir,
            host_tag,
            host_git_sha,
            host_workflow,
            issued_at_unix_ms,
            expires_at_unix_ms,
            base,
        } => {
            let signing = offline_bundle_build::load_exporter_key(&signing_key)?;
            let roots = TrustRoots::load(&trust_roots)?;
            let exporter_identity = offline_bundle_build::exporter_identity(&roots, &signing)?;
            let trust_toml = std::fs::read(&trust_roots)
                .with_context(|| format!("reading public trust roots {}", trust_roots.display()))?;
            let hosts = match hosts_dir {
                Some(dir) => load_hosts(
                    &dir,
                    HostBinaryProvenance {
                        tag: required_host_field("host-tag", host_tag)?,
                        git_sha: required_host_field("host-git-sha", host_git_sha)?,
                        workflow: required_host_field("host-workflow", host_workflow)?,
                    },
                )?,
                None => Vec::new(),
            };
            let issued_at = issued_at_unix_ms.unwrap_or_else(tenkai::now_millis);
            let expires_at = expires_at_unix_ms
                .unwrap_or_else(|| offline_bundle_build::default_expires_at(issued_at));
            let filesystem = FilesystemArtifactRegistry::from_env().ok();
            let empty = MemoryArtifactRegistry::new();
            let registry: &dyn tenkai::oci_artifact::ArtifactRegistry = match &filesystem {
                Some(registry) => registry,
                None => &empty,
            };
            let weight_cache =
                std::env::var_os("TENKAI_WEIGHT_CACHE").map(std::path::PathBuf::from);
            let envelope = offline_bundle_build::build(
                ctx,
                &BundleBuildRequest {
                    releases,
                    tenant_id: ontology::NS.into(),
                    environment_id: env,
                    archive: &out,
                    signing_key: &signing,
                    exporter_identity,
                    trust_roots: &trust_toml,
                    hosts,
                    issued_at_unix_ms: issued_at,
                    expires_at_unix_ms: expires_at,
                    registry,
                    weight_cache: weight_cache.as_deref(),
                    base,
                },
            )
            .await?;
            println!(
                "wrote offline bundle {} ({} entries, digest {})",
                out.display(),
                envelope.entries.len(),
                envelope.statement.digest()?
            );
            Ok(())
        }
        BundleCommand::Docs {
            bundle,
            trust_roots,
            env,
            out,
        } => extract_docs(&bundle, &trust_roots, &env, &out),
    }
}

/// Verify `bundle` and write its docs under `out`. Opens no store, so it
/// runs on a host that only holds the archive.
pub(crate) fn extract_docs(bundle: &Path, trust_roots: &Path, env: &str, out: &Path) -> Result<()> {
    let envelope = tenkai::offline_bundle::BundleEnvelope::load(bundle)?;
    let roots = TrustRoots::load(trust_roots)?;
    let verified = envelope.verify(&roots, ontology::NS, env, tenkai::now_millis())?;
    let written = tenkai::offline_docs::extract(&verified, out)?;
    println!("wrote offline docs to {}", written.display());
    Ok(())
}

fn required_host_field(flag: &str, value: Option<String>) -> Result<String> {
    value.ok_or_else(|| anyhow::anyhow!("--hosts-dir requires --{flag}"))
}

fn load_hosts(dir: &Path, provenance: HostBinaryProvenance) -> Result<Vec<HostBinaryInput>> {
    let mut inputs = Vec::new();
    let mut platforms: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading hosts directory {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    platforms.sort_by_key(|entry| entry.file_name());
    for entry in platforms {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let platform = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("host platform directory is not UTF-8"))?;
        for role in HostBinaryRole::all() {
            let path = entry.path().join(role.binary_name());
            let bytes = std::fs::read(&path).with_context(|| {
                format!("reading host binary {} for {platform}", role.binary_name())
            })?;
            inputs.push(HostBinaryInput {
                role,
                platform: platform.clone(),
                bytes,
                provenance: provenance.clone(),
            });
        }
    }
    if inputs.is_empty() {
        bail!(
            "hosts directory {} contains no packaged Tenkai host platforms",
            dir.display()
        );
    }
    Ok(inputs)
}

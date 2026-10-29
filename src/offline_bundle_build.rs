//! One command that assembles a signed full-stack offline bundle (#626).
//!
//! `tenkaictl bundle build` takes published releases and emits `tenkai.offline-bundle.v1`
//! plus the companion chunk store: images by digest, host binaries, configs,
//! public trust roots, model weights, a checksum manifest, and an SBOM per
//! component. Each image artifact's SBOM is the one its release declares
//! (#804): the build fetches it by digest, checks it, and carries it under
//! `sbom/artifacts/`; the component SBOM lists the files it packed and names
//! those declared documents. Host binaries and model weights have no declared
//! SBOM, so their component SBOM is the packed-file inventory alone. The
//! bundle also carries the docs of the Tenkai version that built it (#646).
//! The v1 archive schema is unchanged. An optional signed
//! `tenkai.advisory-feed.v1` travels as `advisories/feed.json` (#645). A
//! missing image, declared SBOM, weight or schema fails the build with the
//! item named. Private keys never enter the archive.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::manifest::{self, Manifest};
use crate::oci_artifact::{ArtifactRegistry, OciArtifactRef};
use crate::offline_bundle::{
    BundleEnvelope, BundleStatement, OfflineStackManifest, STACK_MANIFEST_SCHEMA,
};
use crate::offline_chunk_store::{self, OfflineChunkArtifact};
use crate::offline_host_binaries::{HostBinaryInput, HostBinaryRole};
use crate::ontology;
use crate::pb::sekai::Object;
use crate::release_signing::TrustRoots;

pub const CHECKSUM_MANIFEST_SCHEMA: &str = "tenkai.offline-checksum-manifest.v1";
pub const CHECKSUM_MANIFEST_PATH: &str = "checksums/manifest.json";
pub const CHECKSUM_MANIFEST_MEDIA: &str =
    "application/vnd.tenkai.offline-checksum-manifest.v1+json";
pub const SBOM_SCHEMA: &str = "tenkai.offline-sbom.v1";
pub const SBOM_MEDIA: &str = "application/vnd.tenkai.offline-sbom.v1+json";
pub const TRUST_ROOTS_PATH: &str = "trust-roots.toml";
pub const TRUST_ROOTS_MEDIA: &str = "application/toml";
/// v1 envelope identity for the packed release set. Not an executable Plan;
/// first-install through `upgrade install-bundle` is #623.
pub const PLAN_ID: &str = "content";
const DEFAULT_VALIDITY_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Inputs for a deterministic full-stack bundle build.
pub struct BundleBuildRequest<'a> {
    /// Catalog identities (`product@version`), order-independent.
    pub releases: Vec<String>,
    pub tenant_id: String,
    pub environment_id: String,
    /// Archive destination; companion chunks are written beside it.
    pub archive: &'a Path,
    pub signing_key: &'a SigningKey,
    pub exporter_identity: String,
    /// Public trust-root TOML copied into the archive. Never a seed.
    pub trust_roots: &'a [u8],
    pub hosts: Vec<HostBinaryInput>,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub registry: &'a dyn ArtifactRegistry,
    pub weight_cache: Option<&'a Path>,
    /// Build a delta against this release (`product@version`), which the
    /// site must already hold: its layers and weights are left out (#686).
    pub base: Option<String>,
    /// Optional `tenkai.advisory-feed.v1` JSON carried as `advisories/feed.json`.
    pub advisory_feed: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksumManifest {
    pub schema: String,
    pub entries: Vec<ChecksumEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksumEntry {
    pub path: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSbom {
    pub schema: String,
    pub component: String,
    pub kind: String,
    pub digest: String,
    pub files: Vec<SbomFile>,
    /// The SBOMs the release declares for its artifacts, carried as they
    /// were declared (#804).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared: Vec<DeclaredSbom>,
}

/// One artifact's declared SBOM as the bundle carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredSbom {
    /// The artifact it describes.
    pub artifact: String,
    /// Where the document sits in the bundle.
    pub path: String,
    pub digest: String,
    pub media_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomFile {
    pub path: String,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

/// Assemble, sign, and write one full-stack bundle for `request.releases`.
pub async fn build(ctx: &mut Ctx, request: &BundleBuildRequest<'_>) -> Result<BundleEnvelope> {
    validate_request(request)?;
    let archive = normalized_archive(request.archive);
    require_free_destination(&archive)?;
    parse_trust_roots(request.trust_roots)?;
    refuse_private_keys(TRUST_ROOTS_PATH, request.trust_roots)?;
    let mut specs = request.releases.clone();
    specs.sort();
    specs.dedup();
    if specs.len() != request.releases.len() {
        bail!("bundle build release set must not contain duplicates");
    }

    let mut payloads: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    payloads.insert(
        TRUST_ROOTS_PATH.into(),
        (TRUST_ROOTS_MEDIA.into(), request.trust_roots.to_vec()),
    );

    let plan_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "tenkai.offline-bundle-content.v1",
        "releases": specs,
    }))?;
    let approval_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "tenkai.offline-bundle-content.v1",
        "kind": "bundle-build",
        "releases": specs,
    }))?;
    payloads.insert(
        format!("plans/{PLAN_ID}.json"),
        ("application/json".into(), plan_bytes.clone()),
    );
    payloads.insert(
        format!("approvals/{PLAN_ID}.json"),
        ("application/json".into(), approval_bytes.clone()),
    );

    let chunk_dir = offline_chunk_store::chunk_dir_beside(&archive)?;
    std::fs::create_dir_all(&chunk_dir)
        .with_context(|| format!("creating chunk directory {}", chunk_dir.display()))?;

    let (mut base, held) = match &request.base {
        Some(spec) => {
            let (base, held) = delta_base(ctx, spec, request.registry).await?;
            (Some(base), held)
        }
        None => (None, BTreeSet::new()),
    };

    let mut images = Vec::new();
    let mut weights = Vec::new();
    let mut schemas = Vec::new();
    let mut sboms = Vec::new();
    let mut artifacts = Vec::new();
    let mut weight_chunks = Vec::new();

    for spec in &specs {
        let assembled = assemble_release(
            ctx,
            spec,
            request.registry,
            request.weight_cache,
            &chunk_dir,
            &mut payloads,
            Delta {
                base: base.as_ref(),
                held: &held,
            },
        )
        .await?;
        images.extend(assembled.images);
        weights.extend(assembled.weights);
        schemas.extend(assembled.schemas);
        artifacts.extend(assembled.artifacts);
        weight_chunks.extend(assembled.weight_chunks);
        sboms.push(assembled.sbom);
    }

    // A delta always declares its base, even with no images: its omitted
    // weights are checked against the base through it.
    if let Some(base) = base.as_mut() {
        // Blobs the target needs elsewhere than where the base put them. Each
        // image is expanded on its own, so a base blob this host lacks never
        // hides another image's references.
        let mut targets = Vec::new();
        for artifact in &artifacts {
            if held.contains(&blob_at(artifact)) {
                targets.push(artifact.clone());
            } else {
                let expanded = crate::oci_artifact::image_closure_except(
                    std::slice::from_ref(artifact),
                    request.registry,
                    |candidate| held.contains(&blob_at(candidate)),
                )
                // A carried image must expand here; guessing which blobs
                // travel could publish a delta the site cannot import.
                .with_context(|| format!("expanding image {} for the delta", artifact.digest))?;
                for blob in &expanded {
                    if held.contains(&blob_at(blob))
                        || crate::oci_artifact::is_manifest_media_type(&blob.media_type)
                    {
                        continue;
                    }
                    // Leaf blobs are not fetched during discovery; a carried
                    // one still has to be here, and the refusal names the image.
                    if request.registry.stored(blob)? != Some(true) {
                        bail!("missing image {}", artifact.digest);
                    }
                }
                targets.extend(expanded);
            }
        }
        narrow_to_held(base, &held, &targets);
    }
    if !artifacts.is_empty() || base.is_some() {
        let chunks = Some((
            chunk_dir.as_path(),
            offline_chunk_store::DEFAULT_CHUNK_BYTES,
        ));
        match &base {
            Some(base) => crate::offline_bundle::insert_artifact_layers_delta(
                &mut payloads,
                &artifacts,
                request.registry,
                chunks,
                base,
            ),
            None => crate::offline_bundle::insert_artifact_layers_chunked(
                &mut payloads,
                &artifacts,
                request.registry,
                chunks,
            ),
        }
        .map_err(|error| named_fetch_error(error, &artifacts))?;
        // An image manifest packs the blobs it references (#627), and a
        // first install requires the stack manifest to name each one.
        let packed = packed_layers(&payloads)?;
        images.extend(packed.iter().map(|layer| layer.digest.clone()));
        let chunked = chunked_images(&payloads)?;
        let mut image_files = Vec::new();
        for layer in &packed {
            // The base release brought it; a delta does not carry it.
            if layer.path == crate::offline_bundle::DELTA_BASE_PATH {
                continue;
            }
            // A chunked blob sits in the chunk store; its entry is the index.
            let (path, size) = if layer.path == crate::offline_bundle::IMAGE_CHUNKS_PATH {
                let artifact = chunked.get(&layer.digest).ok_or_else(|| {
                    anyhow::anyhow!("chunked image {} is missing from the index", layer.digest)
                })?;
                (format!("{}#{}", layer.path, layer.digest), artifact.size)
            } else {
                let size = payloads
                    .get(&layer.path)
                    .map(|(_, bytes)| bytes.len() as u64)
                    .ok_or_else(|| anyhow::anyhow!("packed image {} has no entry", layer.digest))?;
                (layer.path.clone(), size)
            };
            image_files.push(SbomFile {
                path,
                digest: layer.digest.clone(),
                size,
                media_type: layer.media_type.clone(),
            });
        }
        if !packed.is_empty() {
            sboms.push(component_sbom("images", "images", &image_files));
        }
    }
    offline_chunk_store::insert_chunk_manifest(&mut payloads, weight_chunks)?;

    let mut hub = Vec::new();
    if !request.hosts.is_empty() {
        let mut host_files = Vec::new();
        for host in &request.hosts {
            let path = format!("hosts/{}/{}", host.platform, host.role.binary_name());
            host_files.push(sbom_file(&path, "application/octet-stream", &host.bytes));
            if host.role == HostBinaryRole::Server {
                hub.push(path);
            }
        }
        crate::offline_host_binaries::insert(&mut payloads, request.hosts.clone())?;
        sboms.push(component_sbom("hosts", "hosts", &host_files));
    }

    images.sort();
    images.dedup();
    weights.sort();
    weights.dedup();
    schemas.sort();
    schemas.dedup();
    hub.sort();
    hub.dedup();
    if !images.is_empty() && !weights.is_empty() && !schemas.is_empty() && !hub.is_empty() {
        crate::offline_bundle::insert_stack_manifest(
            &mut payloads,
            OfflineStackManifest {
                schema: STACK_MANIFEST_SCHEMA.into(),
                images,
                weights,
                schemas,
                hub,
            },
        )?;
    }

    // The docs of the Tenkai that built this bundle, readable offline (#646).
    let version = env!("CARGO_PKG_VERSION");
    crate::offline_docs::insert(&mut payloads, version)?;
    let doc_files: Vec<SbomFile> = crate::offline_docs::embedded()
        .map(|(path, bytes)| {
            sbom_file(
                &crate::offline_docs::entry_path(version, path),
                "text/plain",
                bytes,
            )
        })
        .collect();
    sboms.push(component_sbom("docs", "docs", &doc_files));

    for sbom in sboms {
        let path = format!("sbom/{}.json", sbom_file_stem(&sbom.component));
        payloads.insert(path, (SBOM_MEDIA.into(), serde_json::to_vec(&sbom)?));
    }
    if let Some(bytes) = request.advisory_feed {
        let mut feed = crate::exposure::parse_advisory_feed(bytes)?;
        crate::exposure::refuse_generated_after_issued(
            feed.generated_at,
            request.issued_at_unix_ms,
        )?;
        if feed.generated_at <= 0 {
            feed.generated_at = request.issued_at_unix_ms;
        }
        let bytes = serde_json::to_vec(&feed)?;
        refuse_private_keys(crate::exposure::ADVISORY_FEED_PATH, &bytes)?;
        if payloads.contains_key(crate::exposure::ADVISORY_FEED_PATH) {
            bail!(
                "bundle already contains {}",
                crate::exposure::ADVISORY_FEED_PATH
            );
        }
        payloads.insert(
            crate::exposure::ADVISORY_FEED_PATH.into(),
            (crate::exposure::ADVISORY_FEED_MEDIA.into(), bytes),
        );
    }
    insert_checksum_manifest(&mut payloads, &chunk_dir)?;

    let envelope = BundleEnvelope::create(
        BundleStatement {
            tenant_id: request.tenant_id.clone(),
            environment_id: request.environment_id.clone(),
            plan_id: PLAN_ID.into(),
            plan_digest: sha256_digest(&plan_bytes),
            approval_digest: sha256_digest(&approval_bytes),
            release_ids: specs,
            exporter_identity: request.exporter_identity.clone(),
            issued_at_unix_ms: request.issued_at_unix_ms,
            expires_at_unix_ms: request.expires_at_unix_ms,
            entries: Vec::new(),
        },
        payloads,
        request.signing_key,
    )?;
    // The archive names these chunks; they are durable before it is.
    std::fs::File::open(&chunk_dir)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing chunk directory {}", chunk_dir.display()))?;
    publish_archive(&envelope, &archive)?;
    Ok(envelope)
}

/// Every OCI blob the layer insertion packed, from its instruction list.
fn packed_layers(
    payloads: &BTreeMap<String, (String, Vec<u8>)>,
) -> Result<Vec<crate::offline_bundle::OfflineArtifactLayer>> {
    let Some((_, raw)) = payloads.get(crate::offline_bundle::LAYER_INSTRUCTION_PATH) else {
        return Ok(Vec::new());
    };
    let manifest: crate::offline_bundle::OfflineArtifactLayerManifest =
        serde_json::from_slice(raw).context("parsing packed layer instructions")?;
    Ok(manifest.layers)
}

/// The chunked image blobs the layer insertion indexed, by digest.
fn chunked_images(
    payloads: &BTreeMap<String, (String, Vec<u8>)>,
) -> Result<BTreeMap<String, OfflineChunkArtifact>> {
    let Some((_, raw)) = payloads.get(crate::offline_bundle::IMAGE_CHUNKS_PATH) else {
        return Ok(BTreeMap::new());
    };
    let index: offline_chunk_store::OfflineChunkManifest =
        serde_json::from_slice(raw).context("parsing packed image chunk index")?;
    Ok(index
        .artifacts
        .into_iter()
        .map(|artifact| (artifact.digest.clone(), artifact))
        .collect())
}

/// A bare file name's directory is the working directory.
fn normalized_archive(path: &Path) -> std::path::PathBuf {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new(".").join(path),
        _ => path.to_path_buf(),
    }
}

/// Refuse an existing destination up front, without writing anything there,
/// so a failed build leaves nothing that blocks its retry.
fn require_free_destination(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("bundle destination {} already exists", path.display());
    }
    Ok(())
}

/// Writes the signed archive beside `path` and links it into place, which
/// fails if another build published there meanwhile; the temporary file is
/// removed either way, and a crash leaves at most that temporary file.
fn publish_archive(envelope: &BundleEnvelope, path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating bundle directory {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("bundle destination must have a UTF-8 file name")?;
    let temporary = parent.join(format!(".{name}.{}.building", uuid::Uuid::new_v4()));
    let published = envelope.save(&temporary).and_then(|()| {
        std::fs::hard_link(&temporary, path)
            .with_context(|| format!("bundle destination {} already exists", path.display()))
    });
    let _ = std::fs::remove_file(&temporary);
    published?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing bundle directory {}", parent.display()))
}

/// Refuses a packed text input that holds a private key block. Release inputs
/// and trust roots are copied verbatim into a portable archive; image layers,
/// weights and host binaries are digest-checked blobs and are not inspected.
fn refuse_private_keys(path: &str, bytes: &[u8]) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    let marked = text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ")
            && (line.contains("PRIVATE KEY") || line.contains("PRIVATE KEY BLOCK"))
    });
    if marked {
        bail!("{path} holds a private key; a bundle carries public material only");
    }
    Ok(())
}

/// Default validity interval when the caller does not pin expiry.
pub fn default_expires_at(issued_at_unix_ms: i64) -> i64 {
    issued_at_unix_ms.saturating_add(DEFAULT_VALIDITY_MS)
}

/// Resolve the exporter identity for `signing_key` from public trust roots.
pub fn exporter_identity(roots: &TrustRoots, signing_key: &SigningKey) -> Result<String> {
    let key_id = crate::release_signing::key_id(&signing_key.verifying_key().to_bytes());
    Ok(roots.resolve(&key_id)?.identity)
}

/// Load a 32-byte exporter seed. Refused when the file is not owner-only.
pub fn load_exporter_key(path: &Path) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(
        &crate::approval_policy::load_signer_seed(path)?,
    ))
}

struct AssembledRelease {
    images: Vec<String>,
    weights: Vec<String>,
    schemas: Vec<String>,
    artifacts: Vec<OciArtifactRef>,
    weight_chunks: Vec<OfflineChunkArtifact>,
    sbom: ComponentSbom,
}

async fn assemble_release(
    ctx: &mut Ctx,
    spec: &str,
    registry: &dyn ArtifactRegistry,
    weight_cache: Option<&Path>,
    chunk_dir: &Path,
    payloads: &mut BTreeMap<String, (String, Vec<u8>)>,
    delta: Delta<'_>,
) -> Result<AssembledRelease> {
    let Delta { base, held } = delta;
    let release = load_release(ctx, spec).await?;
    let raw = release
        .properties
        .get("manifest")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release {spec} has no stored manifest"))?;
    // The stored manifest is what the release was published as; the workdir
    // check below binds only its inputs and artifacts.
    if release.properties.get("digest") != Some(&manifest::digest(raw)) {
        bail!("release {spec} manifest does not match its published digest");
    }
    let parsed = manifest::parse_raw(raw)?;
    let workdir = release
        .properties
        .get("workdir")
        .filter(|value| !value.is_empty())
        .map(Path::new);
    let artifacts: Vec<OciArtifactRef> = release
        .properties
        .get("oci_artifacts")
        .map(|raw| serde_json::from_str(raw))
        .transpose()?
        .unwrap_or_else(|| parsed.artifacts.clone());

    let mut files = Vec::new();
    let toml_path = format!("releases/{spec}/tenkai.toml");
    insert_payload(
        payloads,
        &toml_path,
        "application/toml",
        raw.as_bytes(),
        &mut files,
    )?;

    let mut schemas = Vec::new();
    let mut packed = BTreeSet::new();
    for input in parsed.immutable_inputs() {
        let Some(workdir) = workdir else {
            if is_schema_path(&input) {
                bail!("missing schema {input}");
            }
            bail!("release {spec} is missing stored workdir for {input}");
        };
        let source = workdir.join(&input);
        if !source.exists() {
            if is_schema_path(&input) {
                bail!("missing schema {input}");
            }
            bail!("missing config {input}");
        }
        for (relative, bytes) in collect_input_files(workdir, &input)? {
            // Inputs may overlap (a directory and a file inside it); the
            // workdir digest check above already bound these bytes.
            if !packed.insert(relative.clone()) {
                continue;
            }
            let path = format!("releases/{spec}/{relative}");
            insert_payload(
                payloads,
                &path,
                media_type_for(&relative),
                &bytes,
                &mut files,
            )?;
            if is_schema_path(&relative) {
                schemas.push(path);
            }
        }
    }
    if let Some(workdir) = workdir {
        let expected = release
            .properties
            .get("artifact_digest")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("release {spec} has no stored artifact digest"))?;
        let actual = manifest::identity_digest(workdir, &parsed.immutable_inputs(), &artifacts)?;
        if actual != *expected {
            bail!("release {spec} workdir does not match published artifact digest {expected}");
        }
    }

    let mut images = Vec::new();
    let mut declared = Vec::new();
    for artifact in &artifacts {
        artifact.validate()?;
        // The base release brought it, and its SBOM, to the site: a delta
        // neither fetches nor packs it (#686).
        if held.contains(&blob_at(artifact)) {
            images.push(artifact.digest.clone());
            continue;
        }
        match registry.fetch(artifact) {
            Ok(bytes) => {
                let actual = sha256_digest(&bytes);
                if actual != artifact.digest {
                    bail!(
                        "artifact digest {} does not match fetched bytes {actual}",
                        artifact.digest
                    );
                }
                let path = if bytes.len() as u64 > crate::offline_bundle::MAX_ENTRY_BYTES {
                    // Chunked: one blob of the index, not the index itself.
                    format!(
                        "{}#{}",
                        crate::offline_bundle::IMAGE_CHUNKS_PATH,
                        artifact.digest
                    )
                } else {
                    artifact.layer_entry_path()?
                };
                files.push(sbom_file(&path, &artifact.media_type, &bytes));
            }
            Err(_) => bail!("missing image {}", artifact.digest),
        }
        declared.push(carry_declared_sbom(registry, artifact, payloads)?);
        images.push(artifact.digest.clone());
    }

    let mut weights = Vec::new();
    let mut weight_chunks = Vec::new();
    if let Some(digest) = parsed
        .model
        .as_ref()
        .map(|model| model.artifact_digest.clone())
    {
        // The base release brought it: the stack still names it, and a
        // delta carries no chunks for it.
        if base.is_some_and(|base| base.weights.contains(&digest)) {
            weights.push(digest.clone());
        } else {
            let cache = weight_cache.ok_or_else(|| anyhow::anyhow!("missing weight {digest}"))?;
            let blob = crate::model_runtime::WeightCache::new(cache).blob_path(&digest)?;
            if !blob.is_file() {
                bail!("missing weight {digest}");
            }
            let exported = offline_chunk_store::export_weight_chunks(
                &blob,
                chunk_dir,
                offline_chunk_store::DEFAULT_CHUNK_BYTES,
            )?;
            if exported.digest != digest {
                bail!("weight {digest} does not match cached bytes");
            }
            files.push(SbomFile {
                path: format!("weights/{digest}"),
                digest: exported.digest.clone(),
                size: exported.size,
                media_type: exported.media_type.clone(),
            });
            weight_chunks.push(exported);
            weights.push(digest);
        }
    }

    Ok(AssembledRelease {
        images,
        weights,
        schemas,
        artifacts,
        weight_chunks,
        sbom: ComponentSbom {
            declared,
            ..component_sbom(spec, product_kind_name(&parsed), &files)
        },
    })
}

/// Fetches `artifact`'s declared SBOM from the registry beside it, checks its
/// digest, and adds it to the bundle payloads, where the checksum manifest and
/// the signature cover it. An artifact without a declared SBOM fails the
/// build: a bundle is the trust unit for an isolated site.
fn carry_declared_sbom(
    registry: &dyn ArtifactRegistry,
    artifact: &OciArtifactRef,
    payloads: &mut BTreeMap<String, (String, Vec<u8>)>,
) -> Result<DeclaredSbom> {
    let Some(sbom) = &artifact.sbom else {
        bail!("artifact {} declares no SBOM", artifact.digest);
    };
    let document = OciArtifactRef {
        registry: artifact.registry.clone(),
        repository: artifact.repository.clone(),
        digest: sbom.digest.clone(),
        media_type: sbom.media_type.clone(),
        sbom: None,
    };
    let bytes = registry.fetch(&document).map_err(|_| {
        anyhow::anyhow!(
            "missing SBOM {} for artifact {}",
            sbom.digest,
            artifact.digest
        )
    })?;
    if sha256_digest(&bytes) != sbom.digest {
        bail!(
            "SBOM {} for artifact {} does not match fetched bytes",
            sbom.digest,
            artifact.digest
        );
    }
    let path = format!("sbom/artifacts/{}.json", sbom.digest.replace(':', "-"));
    payloads.insert(path.clone(), (sbom.media_type.clone(), bytes));
    Ok(DeclaredSbom {
        artifact: artifact.digest.clone(),
        path,
        digest: sbom.digest.clone(),
        media_type: sbom.media_type.clone(),
    })
}

/// What a delta build leaves out: the base's inventory and where the base
/// put each blob; both empty for a full bundle.
#[derive(Clone, Copy)]
struct Delta<'a> {
    base: Option<&'a crate::offline_bundle::OfflineDeltaBase>,
    held: &'a BTreeSet<BlobAt>,
}

/// Where a blob sits on a site: registry, repository and digest. A site
/// holds a base layer only under the repository the base imported it to.
type BlobAt = (String, String, String);

fn blob_at(artifact: &OciArtifactRef) -> BlobAt {
    (
        artifact.registry.clone(),
        artifact.repository.clone(),
        artifact.digest.clone(),
    )
}

/// What the base release `spec` brought to the site: its images with every
/// blob they reference, where it put them, and its model weights, read from
/// the published release (#686). Closure walks manifests only (#841). When
/// even those cannot be resolved here, only its declared blobs count as
/// present, so the delta carries more, never less.
async fn delta_base(
    ctx: &mut Ctx,
    spec: &str,
    registry: &dyn ArtifactRegistry,
) -> Result<(crate::offline_bundle::OfflineDeltaBase, BTreeSet<BlobAt>)> {
    crate::offline_bundle::base_release_parts(spec)?;
    let release = load_release(ctx, spec)
        .await
        .with_context(|| format!("delta base release {spec}"))?;
    let layers: Vec<OciArtifactRef> = release
        .properties
        .get("oci_artifacts")
        .map(|raw| serde_json::from_str(raw))
        .transpose()?
        .unwrap_or_default();
    let weights = release
        .properties
        .get("manifest")
        .map(|raw| manifest::parse_raw(raw))
        .transpose()?
        .and_then(|parsed| parsed.model)
        .map(|model| model.artifact_digest)
        .into_iter()
        .collect();
    let held: BTreeSet<BlobAt> = crate::oci_artifact::image_closure(&layers, registry)
        .unwrap_or(layers)
        .iter()
        .map(blob_at)
        .collect();
    let digests: BTreeSet<String> = held.iter().map(|(_, _, digest)| digest.clone()).collect();
    Ok((
        crate::offline_bundle::OfflineDeltaBase {
            schema: crate::offline_bundle::DELTA_BASE_SCHEMA.into(),
            base_release: spec.into(),
            layers: digests.into_iter().collect(),
            weights,
        },
        held,
    ))
}

/// Drops from `base` every digest a target blob needs under a repository the
/// base did not put it in, so the delta carries those bytes.
fn narrow_to_held(
    base: &mut crate::offline_bundle::OfflineDeltaBase,
    held: &BTreeSet<BlobAt>,
    targets: &[OciArtifactRef],
) {
    let elsewhere: BTreeSet<&str> = targets
        .iter()
        .filter(|target| !held.contains(&blob_at(target)))
        .map(|target| target.digest.as_str())
        .collect();
    base.layers
        .retain(|digest| !elsewhere.contains(digest.as_str()));
}

async fn load_release(ctx: &mut Ctx, spec: &str) -> Result<Object> {
    let Some((product, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    let id = ontology::release_id(product, version);
    let release = ctx
        .get(&id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("release {spec} is not published"))?;
    if release.kind != ontology::KIND_RELEASE
        || release.properties.get("product").map(String::as_str) != Some(product)
        || release.properties.get("version").map(String::as_str) != Some(version)
    {
        bail!("release object {} does not match {spec}", release.id);
    }
    Ok(release)
}

fn validate_request(request: &BundleBuildRequest<'_>) -> Result<()> {
    if request.releases.is_empty() {
        bail!("bundle build requires at least one --release");
    }
    if request.tenant_id.trim().is_empty() || request.environment_id.trim().is_empty() {
        bail!("bundle build requires tenant and environment identities");
    }
    if request.exporter_identity.trim().is_empty() {
        bail!("bundle build requires an exporter identity from the public trust roots");
    }
    if request.expires_at_unix_ms <= request.issued_at_unix_ms {
        bail!("bundle validity interval must end after it starts");
    }
    if request.trust_roots.is_empty() {
        bail!("bundle build requires public trust roots");
    }
    Ok(())
}

fn insert_payload(
    payloads: &mut BTreeMap<String, (String, Vec<u8>)>,
    path: &str,
    media_type: &str,
    bytes: &[u8],
    files: &mut Vec<SbomFile>,
) -> Result<()> {
    if payloads.contains_key(path) {
        bail!("bundle already contains {path}");
    }
    refuse_private_keys(path, bytes)?;
    files.push(sbom_file(path, media_type, bytes));
    payloads.insert(path.into(), (media_type.into(), bytes.to_vec()));
    Ok(())
}

fn insert_checksum_manifest(
    payloads: &mut BTreeMap<String, (String, Vec<u8>)>,
    chunk_dir: &Path,
) -> Result<()> {
    let mut entries = Vec::new();
    for (path, (_, content)) in payloads.iter() {
        entries.push(ChecksumEntry {
            path: path.clone(),
            digest: sha256_digest(content),
            size: content.len() as u64,
        });
    }
    let mut artifacts = Vec::new();
    for path in [
        offline_chunk_store::CHUNK_MANIFEST_PATH,
        crate::offline_bundle::IMAGE_CHUNKS_PATH,
    ] {
        if let Some((_, raw)) = payloads.get(path) {
            let index: offline_chunk_store::OfflineChunkManifest = serde_json::from_slice(raw)
                .with_context(|| format!("parsing {path} for checksums"))?;
            artifacts.extend(index.artifacts);
        }
    }
    let mut seen = BTreeSet::new();
    for artifact in &artifacts {
        for chunk in &artifact.chunks {
            if !seen.insert(chunk.digest.clone()) {
                continue;
            }
            let hex = chunk
                .digest
                .strip_prefix("sha256:")
                .context("chunk digest must be sha256-prefixed")?;
            let path = chunk_dir.join(hex);
            let (digest, size) = sha256_file(&path)?;
            entries.push(ChecksumEntry {
                path: format!("chunks/{hex}"),
                digest,
                size,
            });
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = ChecksumManifest {
        schema: CHECKSUM_MANIFEST_SCHEMA.into(),
        entries,
    };
    payloads.insert(
        CHECKSUM_MANIFEST_PATH.into(),
        (
            CHECKSUM_MANIFEST_MEDIA.into(),
            serde_json::to_vec(&manifest)?,
        ),
    );
    Ok(())
}

fn collect_input_files(workdir: &Path, input: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let source = workdir.join(input);
    let metadata = std::fs::symlink_metadata(&source)
        .with_context(|| format!("reading release input {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("deploy input cannot be a symlink: {input}");
    }
    if metadata.is_file() {
        let bytes = std::fs::read(&source)
            .with_context(|| format!("reading release input {}", source.display()))?;
        return Ok(vec![(input.to_string(), bytes)]);
    }
    if metadata.is_dir() {
        let mut files = Vec::new();
        collect_dir_files(input, &source, &mut files)?;
        return Ok(files);
    }
    bail!("unsupported deploy input: {input}")
}

fn collect_dir_files(prefix: &str, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading release input {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("deploy input is not UTF-8: {prefix}"))?;
        let relative = format!("{prefix}/{name}");
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading release input {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("deploy input cannot be a symlink: {relative}");
        }
        if metadata.is_dir() {
            collect_dir_files(&relative, &path, files)?;
        } else if metadata.is_file() {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading release input {}", path.display()))?;
            files.push((relative, bytes));
        } else {
            bail!("unsupported deploy input: {relative}");
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("reading chunk {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((format!("sha256:{:x}", hasher.finalize()), size))
}

fn component_sbom(component: &str, kind: &str, files: &[SbomFile]) -> ComponentSbom {
    let mut files = files.to_vec();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut hasher = Sha256::new();
    hasher.update(component.as_bytes());
    for file in &files {
        hasher.update(file.path.as_bytes());
        hasher.update(file.digest.as_bytes());
        hasher.update(file.size.to_be_bytes());
    }
    ComponentSbom {
        schema: SBOM_SCHEMA.into(),
        component: component.into(),
        kind: kind.into(),
        digest: format!("sha256:{:x}", hasher.finalize()),
        files,
        declared: Vec::new(),
    }
}

fn sbom_file(path: &str, media_type: &str, bytes: &[u8]) -> SbomFile {
    SbomFile {
        path: path.into(),
        digest: sha256_digest(bytes),
        size: bytes.len() as u64,
        media_type: media_type.into(),
    }
}

fn sbom_file_stem(component: &str) -> String {
    component.replace(['/', '\\'], "-")
}

fn is_schema_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == "schemas"
        || lower.starts_with("schemas/")
        || lower.contains(".schema.")
        || lower.ends_with(".schema.json")
}

fn media_type_for(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".toml") {
        "application/toml"
    } else {
        "application/octet-stream"
    }
}

fn product_kind_name(manifest: &Manifest) -> &'static str {
    match manifest.product.kind {
        manifest::ProductKind::Software => "software",
        manifest::ProductKind::RoutingConfig => "routing_config",
        manifest::ProductKind::ModelRuntime => "model_runtime",
        manifest::ProductKind::PolicyBundle => "policy_bundle",
        manifest::ProductKind::EvalSuite => "eval_suite",
        manifest::ProductKind::AgentDefinition => "agent_definition",
        manifest::ProductKind::WorkerPool => "worker_pool",
        manifest::ProductKind::PromptPackage => "prompt_package",
        manifest::ProductKind::WorkshopModule => "workshop_module",
    }
}

fn named_fetch_error(error: anyhow::Error, artifacts: &[OciArtifactRef]) -> anyhow::Error {
    let text = error.to_string();
    if let Some(artifact) = artifacts
        .iter()
        .find(|artifact| text.contains(&artifact.digest))
    {
        anyhow::anyhow!("missing image {}", artifact.digest)
    } else {
        error
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn parse_trust_roots(bytes: &[u8]) -> Result<TrustRoots> {
    let raw = std::str::from_utf8(bytes).context("public trust roots must be UTF-8 TOML")?;
    let roots: TrustRoots = toml::from_str(raw).context("parsing public trust roots")?;
    roots.validate()?;
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{self, PublishOptions};
    use crate::client::Ctx;
    use crate::oci_artifact::{MemoryArtifactRegistry, OciArtifactRef};
    use crate::offline_host_binaries::HostBinaryProvenance;
    use crate::release_signing::{TRUST_ROOT_VERSION, key_id};
    use base64::Engine as _;
    use std::sync::Arc;

    #[tokio::test]
    async fn two_builds_of_the_same_inputs_produce_byte_identical_manifests() {
        let fixture = Fixture::new("identical").await;
        let first = fixture.build().await;
        let second = fixture
            .build_to(fixture.root.join("second.bundle.json"))
            .await;
        assert_eq!(
            payload(&first, CHECKSUM_MANIFEST_PATH),
            payload(&second, CHECKSUM_MANIFEST_PATH)
        );
        let sbom_path = "sbom/edge-app@1.0.0.json";
        assert_eq!(payload(&first, sbom_path), payload(&second, sbom_path));
        assert_eq!(
            payload(&first, "sbom/weights@1.0.0.json"),
            payload(&second, "sbom/weights@1.0.0.json")
        );
    }

    #[tokio::test]
    async fn sbom_and_checksum_are_covered_by_the_bundle_signature() {
        let fixture = Fixture::new("signed-manifests").await;
        let envelope = fixture.build().await;
        let verified = envelope
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at,
            )
            .unwrap();
        assert!(verified.entry(CHECKSUM_MANIFEST_PATH).is_some());
        assert!(verified.entry("sbom/edge-app@1.0.0.json").is_some());
        let checksum: ChecksumManifest =
            serde_json::from_slice(verified.entry(CHECKSUM_MANIFEST_PATH).unwrap()).unwrap();
        assert!(
            checksum
                .entries
                .iter()
                .any(|entry| entry.path == "sbom/edge-app@1.0.0.json")
        );
        let software: ComponentSbom =
            serde_json::from_slice(verified.entry("sbom/edge-app@1.0.0.json").unwrap()).unwrap();
        assert!(
            software
                .files
                .iter()
                .any(|file| file.path == fixture.image.layer_entry_path().unwrap())
        );
        let model: ComponentSbom =
            serde_json::from_slice(verified.entry("sbom/weights@1.0.0.json").unwrap()).unwrap();
        assert!(model.files.iter().any(|file| file.path
            == format!("weights/{}", fixture.weight_digest)
            && file.digest == fixture.weight_digest));

        let mut tampered = envelope.clone();
        let sbom = tampered
            .entries
            .iter_mut()
            .find(|entry| entry.path == "sbom/edge-app@1.0.0.json")
            .unwrap();
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&sbom.content_base64)
            .unwrap();
        bytes[0] ^= 1;
        sbom.content_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let err = tampered
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("sbom/edge-app@1.0.0.json") || err.contains("signed digest"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn advisory_feed_is_signed_and_checksummed() {
        let fixture = Fixture::new("advisory-feed").await;
        let archive = fixture.root.join("site.bundle.json");
        let feed = serde_json::to_vec(&serde_json::json!({
            "schema": crate::exposure::ADVISORY_FEED_SCHEMA,
            "generated_at": fixture.issued_at,
            "advisories": [{
                "id": "TENKAI-2026-1",
                "component": "openssl",
                "range": ">=1.0.0,<1.2.0",
                "severity": "high",
                "issued_at": 1
            }]
        }))
        .unwrap();
        let mut request = fixture.request(&archive);
        request.advisory_feed = Some(feed.as_slice());
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        let built = build(&mut ctx, &request).await.unwrap();
        let verified = built
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at,
            )
            .unwrap();
        let stored: crate::exposure::AdvisoryFeed = serde_json::from_slice(
            verified
                .entry(crate::exposure::ADVISORY_FEED_PATH)
                .expect("advisory feed"),
        )
        .unwrap();
        assert_eq!(stored.schema, crate::exposure::ADVISORY_FEED_SCHEMA);
        assert_eq!(stored.advisories[0].id, "TENKAI-2026-1");
        let checksum: ChecksumManifest =
            serde_json::from_slice(verified.entry(CHECKSUM_MANIFEST_PATH).unwrap()).unwrap();
        assert!(
            checksum
                .entries
                .iter()
                .any(|entry| entry.path == crate::exposure::ADVISORY_FEED_PATH)
        );
        let mut tampered = built;
        let entry = tampered
            .entries
            .iter_mut()
            .find(|entry| entry.path == crate::exposure::ADVISORY_FEED_PATH)
            .unwrap();
        entry.content_base64 =
            base64::engine::general_purpose::STANDARD.encode(b"{\"schema\":\"tampered\"}");
        let err = tampered
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(crate::exposure::ADVISORY_FEED_PATH) || err.contains("signed digest"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn invalid_advisory_feed_fails_the_build() {
        let fixture = Fixture::new("invalid-advisory-feed").await;
        let archive = fixture.root.join("site.bundle.json");
        let mut request = fixture.request(&archive);
        request.advisory_feed = Some(br#"{"schema":"nope"}"#);
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        let err = build(&mut ctx, &request).await.unwrap_err().to_string();
        assert!(err.contains("advisory feed"), "{err}");
    }

    #[tokio::test]
    async fn missing_image_fails_the_build_and_names_the_digest() {
        let mut fixture = Fixture::new("missing-image").await;
        fixture.registry = MemoryArtifactRegistry::new();
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("missing image") && err.contains(&fixture.image.digest),
            "{err}"
        );
    }

    /// The image's declared SBOM is carried as declared, named by the
    /// component SBOM, and listed in the signed checksum manifest.
    #[tokio::test]
    async fn the_declared_sbom_is_carried_and_named() {
        let fixture = Fixture::new("declared-sbom").await;
        let built = fixture.build().await;
        let sbom = fixture.image.sbom.clone().unwrap();
        let path = format!("sbom/artifacts/{}.json", sbom.digest.replace(':', "-"));
        assert_eq!(sha256_digest(&payload(&built, &path)), sbom.digest);
        let component: ComponentSbom =
            serde_json::from_slice(&payload(&built, "sbom/edge-app@1.0.0.json")).unwrap();
        assert_eq!(
            component.declared,
            [DeclaredSbom {
                artifact: fixture.image.digest.clone(),
                path: path.clone(),
                digest: sbom.digest,
                media_type: sbom.media_type,
            }]
        );
        let checksums = String::from_utf8(payload(&built, CHECKSUM_MANIFEST_PATH)).unwrap();
        assert!(checksums.contains(&path), "{checksums}");
    }

    /// An artifact whose SBOM is declared but not in the registry, or whose
    /// stored bytes differ, fails naming the SBOM and its artifact.
    #[tokio::test]
    async fn a_missing_or_altered_declared_sbom_fails_the_build() {
        let mut fixture = Fixture::new("missing-sbom").await;
        let layer = b"layer-a";
        fixture.registry = MemoryArtifactRegistry::new();
        fixture
            .registry
            .put(&fixture.image, layer.to_vec())
            .unwrap();
        let err = fixture.try_build().await.unwrap_err().to_string();
        let sbom = fixture.image.sbom.clone().unwrap();
        assert!(
            err.contains("missing SBOM")
                && err.contains(&sbom.digest)
                && err.contains(&fixture.image.digest),
            "{err}"
        );
    }

    #[tokio::test]
    async fn missing_weight_fails_the_build_and_names_the_digest() {
        let fixture = Fixture::new("missing-weight").await;
        std::fs::remove_file(fixture.weight_blob()).unwrap();
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("missing weight") && err.contains(&fixture.weight_digest),
            "{err}"
        );
    }

    #[tokio::test]
    async fn missing_schema_fails_the_build_and_names_the_path() {
        let fixture = Fixture::new("missing-schema").await;
        std::fs::remove_file(Path::new(&fixture.schema_workdir).join("schemas/edge.json")).unwrap();
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("missing schema") && err.contains("schemas/edge.json"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn mutated_workdir_fails_the_build_and_names_the_release() {
        let fixture = Fixture::new("mutated-workdir").await;
        std::fs::write(
            Path::new(&fixture.schema_workdir).join("schemas/edge.json"),
            b"tampered",
        )
        .unwrap();
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("edge-app@1.0.0")
                && err.contains("does not match published artifact digest"),
            "{err}"
        );
    }

    /// A stored manifest changed after publication, with its inputs and
    /// artifacts intact, fails the build naming the release.
    #[tokio::test]
    async fn a_changed_stored_manifest_fails_the_build() {
        let fixture = Fixture::new("changed-manifest").await;
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        let id = ontology::release_id("edge-app", "1.0.0");
        let mut release = ctx.get(&id).await.unwrap().unwrap();
        let raw =
            release.properties["manifest"].replace("install = \"true\"", "install = \"false\"");
        assert_ne!(raw, release.properties["manifest"]);
        release.properties.insert("manifest".into(), raw);
        ctx.put(release).await.unwrap();
        drop(ctx);
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("edge-app@1.0.0") && err.contains("does not match its published digest"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn directory_valued_input_is_packed_recursively() {
        let fixture = Fixture::new("dir-input").await;
        let dir_app = fixture.root.join("dir-app");
        std::fs::create_dir_all(dir_app.join("schemas")).unwrap();
        std::fs::write(dir_app.join("schemas/edge.json"), b"{\"type\":\"object\"}").unwrap();
        std::fs::write(
            dir_app.join("tenkai.toml"),
            r#"
[product]
name = "dir-app"
version = "1.0.0"

[deploy]
install = "true"
inputs = ["schemas"]
"#,
        )
        .unwrap();
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        catalog::publish(
            &mut ctx,
            &dir_app.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                state_dir: Some(fixture.root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let archive = fixture.root.join("dir.bundle.json");
        let mut request = fixture.request(&archive);
        request.releases = vec!["dir-app@1.0.0".into(), "weights@1.0.0".into()];
        let envelope = build(&mut ctx, &request).await.unwrap();
        assert_eq!(
            payload(&envelope, "releases/dir-app@1.0.0/schemas/edge.json"),
            b"{\"type\":\"object\"}"
        );
    }

    #[tokio::test]
    async fn checksum_omits_unreferenced_chunk_files() {
        let fixture = Fixture::new("stale-chunks").await;
        let first = fixture.build().await;
        let checksum = payload(&first, CHECKSUM_MANIFEST_PATH);
        let archive = fixture.root.join("site.bundle.json");
        let chunk_dir = offline_chunk_store::chunk_dir_beside(&archive).unwrap();
        std::fs::write(chunk_dir.join("a".repeat(64)), b"stale").unwrap();
        std::fs::remove_file(&archive).unwrap();
        let second = fixture.build().await;
        assert_eq!(payload(&second, CHECKSUM_MANIFEST_PATH), checksum);
        let parsed: ChecksumManifest = serde_json::from_slice(&checksum).unwrap();
        assert!(
            parsed
                .entries
                .iter()
                .all(|entry| entry.path != format!("chunks/{}", "a".repeat(64)))
        );
    }

    /// A release input holding a private key fails the build naming the
    /// file, and nothing is written at the destination.
    #[tokio::test]
    async fn a_private_key_in_a_release_input_fails_the_build() {
        let fixture = Fixture::new("private-key").await;
        let app = fixture.root.join("keyed-app");
        std::fs::create_dir_all(app.join("config")).unwrap();
        std::fs::write(
            app.join("config/tls.pem"),
            "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(
            app.join("tenkai.toml"),
            "[product]\nname = \"keyed-app\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"config\"]\n",
        )
        .unwrap();
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        catalog::publish(
            &mut ctx,
            &app.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                state_dir: Some(fixture.root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let archive = fixture.root.join("keyed.bundle.json");
        let mut request = fixture.request(&archive);
        request.releases = vec!["keyed-app@1.0.0".into()];
        let err = build(&mut ctx, &request).await.unwrap_err().to_string();
        assert!(
            err.contains("releases/keyed-app@1.0.0/config/tls.pem") && err.contains("private key"),
            "{err}"
        );
        assert!(!archive.exists());
    }

    /// A failed build leaves nothing at the destination, so the same command
    /// succeeds once the missing item is supplied.
    #[tokio::test]
    async fn a_failed_build_can_be_retried_at_the_same_destination() {
        let mut fixture = Fixture::new("retry").await;
        let full = std::mem::replace(&mut fixture.registry, MemoryArtifactRegistry::new());
        assert!(fixture.try_build().await.is_err());
        let archive = fixture.root.join("site.bundle.json");
        assert!(!archive.exists());
        fixture.registry = full;
        fixture.try_build().await.unwrap();
        assert!(archive.exists());
        let leftovers: Vec<_> = std::fs::read_dir(&fixture.root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".building"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_bare_file_name_is_written_in_the_working_directory() {
        assert_eq!(
            normalized_archive(Path::new("site-c.bundle.json")),
            Path::new("./site-c.bundle.json")
        );
        assert_eq!(
            normalized_archive(Path::new("out/site.bundle.json")),
            Path::new("out/site.bundle.json")
        );
    }

    /// Overlapping inputs, a directory and a file inside it, pack the file
    /// once.
    #[tokio::test]
    async fn overlapping_inputs_pack_each_file_once() {
        let fixture = Fixture::new("overlap").await;
        let app = fixture.root.join("overlap-app");
        std::fs::create_dir_all(app.join("schemas")).unwrap();
        std::fs::write(app.join("schemas/edge.json"), b"{\"type\":\"object\"}").unwrap();
        std::fs::write(
            app.join("tenkai.toml"),
            "[product]\nname = \"overlap-app\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"schemas\", \"schemas/edge.json\"]\n",
        )
        .unwrap();
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        catalog::publish(
            &mut ctx,
            &app.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                state_dir: Some(fixture.root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let archive = fixture.root.join("overlap.bundle.json");
        let mut request = fixture.request(&archive);
        request.releases = vec!["overlap-app@1.0.0".into()];
        let envelope = build(&mut ctx, &request).await.unwrap();
        let component: ComponentSbom =
            serde_json::from_slice(&payload(&envelope, "sbom/overlap-app@1.0.0.json")).unwrap();
        let schema = "releases/overlap-app@1.0.0/schemas/edge.json";
        assert_eq!(
            component
                .files
                .iter()
                .filter(|file| file.path == schema)
                .count(),
            1
        );
    }

    /// A release whose artifact is an OCI image manifest: its config and
    /// layer travel with it, the stack manifest names every one so a first
    /// install's preflight accepts the bundle, and the images inventory lists
    /// them.
    #[tokio::test]
    async fn an_image_manifest_names_its_whole_closure() {
        let fixture = Fixture::new("image-closure").await;
        let blob = |bytes: &[u8], media: &str| OciArtifactRef {
            registry: "registry.example".into(),
            repository: "edge/full".into(),
            digest: sha256_digest(bytes),
            media_type: media.into(),
            sbom: None,
        };
        let config = blob(b"config", "application/vnd.oci.image.config.v1+json");
        let layer = blob(b"layer-full", "application/vnd.oci.image.layer.v1.tar");
        let manifest_bytes = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config.digest, "mediaType": config.media_type},
            "layers": [{"digest": layer.digest, "mediaType": layer.media_type}],
        })
        .to_string()
        .into_bytes();
        let sbom_bytes = br#"{"spdxVersion":"SPDX-2.3","name":"full-app"}"#;
        let sbom = crate::oci_artifact::SbomRef {
            digest: sha256_digest(sbom_bytes),
            media_type: "application/spdx+json".into(),
        };
        let manifest = OciArtifactRef {
            sbom: Some(sbom.clone()),
            ..blob(
                &manifest_bytes,
                "application/vnd.oci.image.manifest.v1+json",
            )
        };
        for (reference, bytes) in [
            (&manifest, manifest_bytes.clone()),
            (&config, b"config".to_vec()),
            (&layer, b"layer-full".to_vec()),
            (
                &OciArtifactRef {
                    digest: sbom.digest.clone(),
                    media_type: sbom.media_type.clone(),
                    sbom: None,
                    ..manifest.clone()
                },
                sbom_bytes.to_vec(),
            ),
        ] {
            fixture.registry.put(reference, bytes).unwrap();
        }
        let app = fixture.root.join("full-app");
        std::fs::create_dir_all(app.join("schemas")).unwrap();
        std::fs::write(app.join("schemas/full.json"), b"{\"type\":\"object\"}").unwrap();
        std::fs::write(
            app.join("tenkai.toml"),
            format!(
                "[product]\nname = \"full-app\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"schemas/full.json\"]\n\n[[artifacts]]\nregistry = \"{}\"\nrepository = \"{}\"\ndigest = \"{}\"\nmedia_type = \"{}\"\nsbom = {{ digest = \"{}\", media_type = \"{}\" }}\n",
                manifest.registry,
                manifest.repository,
                manifest.digest,
                manifest.media_type,
                sbom.digest,
                sbom.media_type
            ),
        )
        .unwrap();
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        let publish_registry = Arc::new(MemoryArtifactRegistry::new());
        publish_registry.put(&manifest, manifest_bytes).unwrap();
        publish_registry.put(&config, b"config".to_vec()).unwrap();
        publish_registry
            .put(&layer, b"layer-full".to_vec())
            .unwrap();
        catalog::publish(
            &mut ctx,
            &app.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                artifact_registry: Some(publish_registry),
                state_dir: Some(fixture.root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let archive = fixture.root.join("full.bundle.json");
        let mut request = fixture.request(&archive);
        request.releases = vec!["full-app@1.0.0".into(), "weights@1.0.0".into()];
        let envelope = build(&mut ctx, &request).await.unwrap();
        let stack: OfflineStackManifest = serde_json::from_slice(&payload(
            &envelope,
            crate::offline_bundle::STACK_MANIFEST_PATH,
        ))
        .unwrap();
        for digest in [&manifest.digest, &config.digest, &layer.digest] {
            assert!(
                stack.images.contains(digest),
                "{digest} in {:?}",
                stack.images
            );
        }
        let images: ComponentSbom =
            serde_json::from_slice(&payload(&envelope, "sbom/images.json")).unwrap();
        assert_eq!(images.files.len(), 3);
        let verified = envelope
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at + 1,
            )
            .unwrap();
        // The content checks run first; only the importer's local stores,
        // which this test does not configure, remain.
        match crate::offline_bundle::preflight_full_stack(&verified, Some(&archive)) {
            Ok(()) => {}
            Err(error) if error.to_string().contains("is required to import") => {}
            Err(error) => panic!("preflight refused the bundle: {error}"),
        }
    }

    /// The bundle carries this build's docs under its version; extracted
    /// from the verified bundle they are byte for byte the source docs.
    #[tokio::test]
    async fn the_bundle_carries_this_versions_docs() {
        let fixture = Fixture::new("docs").await;
        let built = fixture.build().await;
        let verified = built
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at + 1,
            )
            .unwrap();
        let index = crate::offline_docs::index(&verified).unwrap().unwrap();
        assert_eq!(index.version, env!("CARGO_PKG_VERSION"));
        let out = fixture.root.join("docs-out");
        let written = crate::offline_docs::extract(&verified, &out).unwrap();
        assert_eq!(written, out.join(env!("CARGO_PKG_VERSION")));
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
        for file in &index.files {
            assert_eq!(
                std::fs::read(written.join(&file.path)).unwrap(),
                std::fs::read(source.join(&file.path)).unwrap(),
                "{}",
                file.path
            );
        }
        let checksums = String::from_utf8(payload(&built, CHECKSUM_MANIFEST_PATH)).unwrap();
        assert!(checksums.contains(crate::offline_docs::DOCS_INDEX_PATH));
        // A second extraction to the same place is refused, not merged.
        let err = crate::offline_docs::extract(&verified, &out).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    /// A delta from edge-app 1.0.0 to 1.1.0 carries only the layer 1.0.0
    /// lacks; the base layer travels as a signed reference, and a site
    /// without it is refused before any change, naming the digest (#686).
    #[tokio::test]
    async fn a_delta_carries_only_what_its_base_lacks() {
        let fixture = Fixture::new("delta").await;
        let sbom_of = |bytes: &[u8]| crate::oci_artifact::SbomRef {
            digest: sha256_digest(bytes),
            media_type: "application/spdx+json".into(),
        };
        let layer_b = b"layer-b";
        let sbom_b_bytes = br#"{"spdxVersion":"SPDX-2.3","name":"edge-app-b"}"#;
        let image_b = OciArtifactRef {
            digest: sha256_digest(layer_b),
            sbom: Some(sbom_of(sbom_b_bytes)),
            ..fixture.image.clone()
        };
        fixture.registry.put(&image_b, layer_b.to_vec()).unwrap();
        fixture
            .registry
            .put(
                &OciArtifactRef {
                    digest: sha256_digest(sbom_b_bytes),
                    media_type: "application/spdx+json".into(),
                    sbom: None,
                    ..image_b.clone()
                },
                sbom_b_bytes.to_vec(),
            )
            .unwrap();
        let app = fixture.root.join("edge-next");
        std::fs::create_dir_all(app.join("schemas")).unwrap();
        std::fs::write(app.join("schemas/edge.json"), b"{\"type\":\"object\"}").unwrap();
        let artifact = |image: &OciArtifactRef| {
            let sbom = image.sbom.as_ref().unwrap();
            format!(
                "\n[[artifacts]]\nregistry = \"{}\"\nrepository = \"{}\"\ndigest = \"{}\"\nmedia_type = \"{}\"\nsbom = {{ digest = \"{}\", media_type = \"{}\" }}\n",
                image.registry,
                image.repository,
                image.digest,
                image.media_type,
                sbom.digest,
                sbom.media_type
            )
        };
        std::fs::write(
            app.join("tenkai.toml"),
            format!(
                "[product]\nname = \"edge-app\"\nversion = \"1.1.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"schemas/edge.json\"]\n{}{}",
                artifact(&fixture.image),
                artifact(&image_b)
            ),
        )
        .unwrap();
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        let publish_registry = Arc::new(MemoryArtifactRegistry::new());
        publish_registry
            .put(&fixture.image, b"layer-a".to_vec())
            .unwrap();
        publish_registry.put(&image_b, layer_b.to_vec()).unwrap();
        catalog::publish(
            &mut ctx,
            &app.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                artifact_registry: Some(publish_registry),
                state_dir: Some(fixture.root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // The exporter need not hold what the base brought: this registry
        // has only the new layer and its SBOM.
        let exporter = MemoryArtifactRegistry::new();
        exporter.put(&image_b, layer_b.to_vec()).unwrap();
        exporter
            .put(
                &OciArtifactRef {
                    digest: sha256_digest(sbom_b_bytes),
                    media_type: "application/spdx+json".into(),
                    sbom: None,
                    ..image_b.clone()
                },
                sbom_b_bytes.to_vec(),
            )
            .unwrap();
        let archive = fixture.root.join("delta.bundle.json");
        let mut request = fixture.request(&archive);
        request.releases = vec!["edge-app@1.1.0".into(), "weights@1.0.0".into()];
        request.base = Some("edge-app@1.0.0".into());
        request.registry = &exporter;
        let delta = build(&mut ctx, &request).await.unwrap();
        let carried = |image: &OciArtifactRef| {
            delta
                .entries
                .iter()
                .any(|entry| entry.path == image.layer_entry_path().unwrap())
        };
        assert!(!carried(&fixture.image), "the base layer is not carried");
        assert!(carried(&image_b));
        let base: crate::offline_bundle::OfflineDeltaBase =
            serde_json::from_slice(&payload(&delta, crate::offline_bundle::DELTA_BASE_PATH))
                .unwrap();
        assert_eq!(base.base_release, "edge-app@1.0.0");
        assert_eq!(base.layers, std::slice::from_ref(&fixture.image.digest));

        let verified = delta
            .verify(
                &parse_trust_roots(&fixture.trust_toml).unwrap(),
                ontology::NS,
                "dark-1",
                fixture.issued_at + 1,
            )
            .unwrap();
        let empty = MemoryArtifactRegistry::new();
        let refused = crate::offline_bundle::preflight_delta_base(
            &verified,
            Some(&empty),
            &BTreeMap::from([(
                "registry.example".to_string(),
                "registry.example".to_string(),
            )]),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains(&fixture.image.digest), "{refused}");
    }

    /// A base that brought the model weights: the delta carries no chunks
    /// for them, and the stack manifest still names them.
    #[tokio::test]
    async fn a_delta_leaves_out_the_base_weights() {
        let fixture = Fixture::new("delta-weights").await;
        let mut ctx = Ctx::embedded(fixture.root.join("tenkai.db")).unwrap();
        let full = fixture.build().await;
        let weights = |bundle: &BundleEnvelope| {
            let stack: OfflineStackManifest = serde_json::from_slice(&payload(
                bundle,
                crate::offline_bundle::STACK_MANIFEST_PATH,
            ))
            .unwrap();
            stack.weights
        };
        let archive = fixture.root.join("delta-weights.bundle.json");
        let mut request = fixture.request(&archive);
        request.base = Some("weights@1.0.0".into());
        let delta = build(&mut ctx, &request).await.unwrap();
        assert_eq!(weights(&delta), weights(&full));
        // The weights' chunk index lists them in the full bundle; the delta
        // carries no chunks for them, so it has none for them either.
        let chunks = |bundle: &BundleEnvelope| {
            bundle
                .entries
                .iter()
                .find(|entry| entry.path == offline_chunk_store::CHUNK_MANIFEST_PATH)
                .map(|_| {
                    String::from_utf8(payload(bundle, offline_chunk_store::CHUNK_MANIFEST_PATH))
                        .unwrap()
                })
                .unwrap_or_default()
        };
        let digest = &weights(&full)[0];
        assert!(chunks(&full).contains(digest.as_str()));
        assert!(!chunks(&delta).contains(digest.as_str()));

        // A weights-only delta still declares its base, so import checks
        // the omitted weights against it.
        let weights_archive = fixture.root.join("weights-only.bundle.json");
        let mut request = fixture.request(&weights_archive);
        request.releases = vec!["weights@1.0.0".into()];
        request.base = Some("weights@1.0.0".into());
        let weights_only = build(&mut ctx, &request).await.unwrap();
        let base: crate::offline_bundle::OfflineDeltaBase = serde_json::from_slice(&payload(
            &weights_only,
            crate::offline_bundle::DELTA_BASE_PATH,
        ))
        .unwrap();
        assert_eq!(base.weights, std::slice::from_ref(digest));
    }

    /// A blob the target needs under another repository than the base put
    /// it in is carried: the site holds it only where the base imported it.
    #[test]
    fn a_base_blob_needed_elsewhere_is_carried() {
        let at = |repository: &str, digest: &str| OciArtifactRef {
            registry: "registry.example".into(),
            repository: repository.into(),
            digest: digest.into(),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            sbom: None,
        };
        let shared = format!("sha256:{}", "a".repeat(64));
        let kept = format!("sha256:{}", "b".repeat(64));
        let held: BTreeSet<BlobAt> = [
            blob_at(&at("edge/app", &shared)),
            blob_at(&at("edge/app", &kept)),
        ]
        .into_iter()
        .collect();
        let mut base = crate::offline_bundle::OfflineDeltaBase {
            schema: crate::offline_bundle::DELTA_BASE_SCHEMA.into(),
            base_release: "edge-app@1.0.0".into(),
            layers: vec![shared.clone(), kept.clone()],
            weights: Vec::new(),
        };
        narrow_to_held(
            &mut base,
            &held,
            &[at("edge/moved", &shared), at("edge/app", &kept)],
        );
        assert_eq!(base.layers, [kept]);
    }

    #[tokio::test]
    async fn existing_archive_destination_is_refused() {
        let fixture = Fixture::new("existing-out").await;
        let archive = fixture.root.join("site.bundle.json");
        std::fs::write(&archive, b"keep").unwrap();
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("already exists") && err.contains("site.bundle.json"),
            "{err}"
        );
        assert_eq!(std::fs::read(&archive).unwrap(), b"keep");
    }

    struct Fixture {
        root: std::path::PathBuf,
        signing: SigningKey,
        trust_toml: Vec<u8>,
        registry: MemoryArtifactRegistry,
        image: OciArtifactRef,
        weight_digest: String,
        weight_cache: std::path::PathBuf,
        schema_workdir: String,
        issued_at: i64,
    }

    impl Fixture {
        async fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "tenkai-bundle-build-{name}-{}-{}-{}",
                std::process::id(),
                crate::now_millis(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
            crate::ontology::register(&mut ctx).await.unwrap();
            let signing = SigningKey::from_bytes(&[7; 32]);
            let public = base64::engine::general_purpose::STANDARD
                .encode(signing.verifying_key().to_bytes());
            let trust_toml = format!(
                r#"version = {TRUST_ROOT_VERSION}

[[signers]]
key_id = "{}"
identity = "exporter"
public_key = "{public}"
"#,
                key_id(&signing.verifying_key().to_bytes())
            )
            .into_bytes();

            let layer = b"layer-a";
            let sbom_bytes = br#"{"spdxVersion":"SPDX-2.3","name":"edge-app"}"#;
            let sbom = crate::oci_artifact::SbomRef {
                digest: sha256_digest(sbom_bytes),
                media_type: "application/spdx+json".into(),
            };
            let image = OciArtifactRef {
                registry: "registry.example".into(),
                repository: "edge/app".into(),
                digest: sha256_digest(layer),
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                sbom: Some(sbom.clone()),
            };
            let sbom_document = OciArtifactRef {
                digest: sbom.digest.clone(),
                media_type: sbom.media_type.clone(),
                sbom: None,
                ..image.clone()
            };
            let registry = MemoryArtifactRegistry::new();
            registry.put(&image, layer.to_vec()).unwrap();
            registry.put(&sbom_document, sbom_bytes.to_vec()).unwrap();

            let software = root.join("software");
            std::fs::create_dir_all(software.join("schemas")).unwrap();
            std::fs::write(software.join("schemas/edge.json"), b"{\"type\":\"object\"}").unwrap();
            std::fs::write(
                software.join("tenkai.toml"),
                format!(
                    r#"
[product]
name = "edge-app"
version = "1.0.0"

[deploy]
install = "true"
inputs = ["schemas/edge.json"]

[[artifacts]]
registry = "{}"
repository = "{}"
digest = "{}"
media_type = "{}"
sbom = {{ digest = "{}", media_type = "{}" }}
"#,
                    image.registry,
                    image.repository,
                    image.digest,
                    image.media_type,
                    sbom.digest,
                    sbom.media_type
                ),
            )
            .unwrap();
            let publish_registry = Arc::new(MemoryArtifactRegistry::new());
            publish_registry.put(&image, layer.to_vec()).unwrap();
            catalog::publish(
                &mut ctx,
                &software.join("tenkai.toml"),
                &PublishOptions {
                    allow_unsigned_development: true,
                    artifact_registry: Some(publish_registry),
                    state_dir: Some(root.join("state")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let software_object = ctx
                .get(&ontology::release_id("edge-app", "1.0.0"))
                .await
                .unwrap()
                .unwrap();
            let schema_workdir = software_object.properties.get("workdir").unwrap().clone();

            let weight_bytes = b"weight-bytes";
            let weight_digest = sha256_digest(weight_bytes);
            let model = root.join("model");
            std::fs::create_dir_all(&model).unwrap();
            std::fs::write(
                model.join("tenkai.toml"),
                format!(
                    r#"
[product]
name = "weights"
version = "1.0.0"
kind = "model_runtime"

[model]
source = "hf://example/weights/weights.gguf"
revision = "0123456789abcdef0123456789abcdef01234567"
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "{weight_digest}"
license = "apache-2.0"

[runtime]
engine = "llama.cpp"
port = 18080
context_length = 4096

[requirements]
architecture = ["arm64"]
memory_gib = 8
accelerator = ["cpu"]

[health]
endpoint = "http://127.0.0.1:18080/v1/models"
max_startup_seconds = 30
"#
                ),
            )
            .unwrap();
            catalog::publish(
                &mut ctx,
                &model.join("tenkai.toml"),
                &PublishOptions {
                    allow_unsigned_development: true,
                    state_dir: Some(root.join("state")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let weight_cache = root.join("weights");
            let cache = crate::model_runtime::WeightCache::new(&weight_cache);
            let blob = cache.blob_path(&weight_digest).unwrap();
            std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
            std::fs::write(&blob, weight_bytes).unwrap();

            Self {
                root,
                signing,
                trust_toml,
                registry,
                image,
                weight_digest,
                weight_cache,
                schema_workdir,
                issued_at: 1_700_000_000_000,
            }
        }

        fn weight_blob(&self) -> std::path::PathBuf {
            crate::model_runtime::WeightCache::new(&self.weight_cache)
                .blob_path(&self.weight_digest)
                .unwrap()
        }

        fn request<'a>(&'a self, archive: &'a Path) -> BundleBuildRequest<'a> {
            BundleBuildRequest {
                releases: vec!["edge-app@1.0.0".into(), "weights@1.0.0".into()],
                tenant_id: ontology::NS.into(),
                environment_id: "dark-1".into(),
                archive,
                signing_key: &self.signing,
                exporter_identity: "exporter".into(),
                trust_roots: &self.trust_toml,
                hosts: vec![
                    host(HostBinaryRole::Cli, b"cli"),
                    host(HostBinaryRole::Server, b"server"),
                    host(HostBinaryRole::Executor, b"executor"),
                ],
                issued_at_unix_ms: self.issued_at,
                expires_at_unix_ms: default_expires_at(self.issued_at),
                registry: &self.registry,
                weight_cache: Some(&self.weight_cache),
                base: None,
                advisory_feed: None,
            }
        }

        async fn build(&self) -> BundleEnvelope {
            self.build_to(self.root.join("site.bundle.json")).await
        }

        async fn build_to(&self, archive: std::path::PathBuf) -> BundleEnvelope {
            let mut ctx = Ctx::embedded(self.root.join("tenkai.db")).unwrap();
            build(&mut ctx, &self.request(&archive)).await.unwrap()
        }

        async fn try_build(&self) -> Result<BundleEnvelope> {
            let mut ctx = Ctx::embedded(self.root.join("tenkai.db")).unwrap();
            build(&mut ctx, &self.request(&self.root.join("site.bundle.json"))).await
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn payload(bundle: &BundleEnvelope, path: &str) -> Vec<u8> {
        let entry = bundle
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap_or_else(|| panic!("missing {path}"));
        base64::engine::general_purpose::STANDARD
            .decode(&entry.content_base64)
            .unwrap()
    }

    fn host(role: HostBinaryRole, bytes: &'static [u8]) -> HostBinaryInput {
        HostBinaryInput {
            role,
            platform: "linux-x86_64".into(),
            bytes: bytes.to_vec(),
            provenance: HostBinaryProvenance {
                tag: "v0.0.0".into(),
                git_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                workflow: "release".into(),
            },
        }
    }
}

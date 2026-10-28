//! One command that assembles a signed full-stack offline bundle (#626).
//!
//! `tenkaictl bundle build` takes published releases and emits `tenkai.offline-bundle.v1`
//! plus the companion chunk store: images by digest, host binaries, configs,
//! public trust roots, model weights, a checksum manifest, and an SBOM per
//! component. The v1 archive schema is unchanged. Missing images, weights, or
//! schemas fail the build with the item named. Private keys never enter the
//! archive.

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
    claim_archive(request.archive)?;
    parse_trust_roots(request.trust_roots)?;
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

    let chunk_dir = offline_chunk_store::chunk_dir_beside(request.archive)?;
    std::fs::create_dir_all(&chunk_dir)
        .with_context(|| format!("creating chunk directory {}", chunk_dir.display()))?;

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
        )
        .await?;
        images.extend(assembled.images);
        weights.extend(assembled.weights);
        schemas.extend(assembled.schemas);
        artifacts.extend(assembled.artifacts);
        weight_chunks.extend(assembled.weight_chunks);
        sboms.push(assembled.sbom);
    }

    if !artifacts.is_empty() {
        crate::offline_bundle::insert_artifact_layers_chunked(
            &mut payloads,
            &artifacts,
            request.registry,
            Some((&chunk_dir, offline_chunk_store::DEFAULT_CHUNK_BYTES)),
        )
        .map_err(|error| named_fetch_error(error, &artifacts))?;
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

    for sbom in sboms {
        let path = format!("sbom/{}.json", sbom_file_stem(&sbom.component));
        payloads.insert(path, (SBOM_MEDIA.into(), serde_json::to_vec(&sbom)?));
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
    envelope.save(request.archive)?;
    Ok(envelope)
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
) -> Result<AssembledRelease> {
    let release = load_release(ctx, spec).await?;
    let raw = release
        .properties
        .get("manifest")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release {spec} has no stored manifest"))?;
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
    for artifact in &artifacts {
        artifact.validate()?;
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
                    crate::offline_bundle::IMAGE_CHUNKS_PATH.to_string()
                } else {
                    artifact.layer_entry_path()?
                };
                files.push(sbom_file(&path, &artifact.media_type, &bytes));
            }
            Err(_) => bail!("missing image {}", artifact.digest),
        }
        images.push(artifact.digest.clone());
    }

    let mut weights = Vec::new();
    let mut weight_chunks = Vec::new();
    if let Some(digest) = parsed
        .model
        .as_ref()
        .map(|model| model.artifact_digest.clone())
    {
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

    Ok(AssembledRelease {
        images,
        weights,
        schemas,
        artifacts,
        weight_chunks,
        sbom: component_sbom(spec, product_kind_name(&parsed), &files),
    })
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

fn claim_archive(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating bundle directory {}", parent.display()))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("bundle destination {} already exists", path.display()))?;
    Ok(())
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
    async fn missing_image_fails_the_build_and_names_the_digest() {
        let mut fixture = Fixture::new("missing-image").await;
        fixture.registry = MemoryArtifactRegistry::new();
        let err = fixture.try_build().await.unwrap_err().to_string();
        assert!(
            err.contains("missing image") && err.contains(&fixture.image.digest),
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
            let image = OciArtifactRef {
                registry: "registry.example".into(),
                repository: "edge/app".into(),
                digest: sha256_digest(layer),
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            };
            let registry = MemoryArtifactRegistry::new();
            registry.put(&image, layer.to_vec()).unwrap();

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
"#,
                    image.registry, image.repository, image.digest, image.media_type
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

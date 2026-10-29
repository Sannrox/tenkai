//! Companion chunk store for model-scale weights beside `tenkai.offline-bundle.v1`.
//!
//! Chunk payloads are files next to the JSON archive. The signed manifest is a
//! v1 JSON entry, so v1 schema and size limits stay unchanged.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::model_runtime::WeightCache;
use crate::offline_bundle::VerifiedBundle;
use crate::signature_verification;

pub const CHUNK_MANIFEST_SCHEMA: &str = "tenkai.offline-chunk-manifest.v1";
pub const CHUNK_MANIFEST_PATH: &str = "chunks/manifest.json";
pub const CHUNK_MANIFEST_MEDIA: &str = "application/vnd.tenkai.offline-chunk-manifest.v1+json";
pub const DEFAULT_CHUNK_BYTES: u64 = 64 * 1024 * 1024;
pub const MODEL_SCALE_WEIGHT_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const COPY_BUFFER: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineChunkManifest {
    pub schema: String,
    pub artifacts: Vec<OfflineChunkArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineChunkArtifact {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
    pub chunks: Vec<OfflineChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineChunk {
    pub digest: String,
    pub size: u64,
    pub index: u32,
}

pub fn chunk_dir_beside(bundle_path: &Path) -> Result<PathBuf> {
    let stem = bundle_path
        .file_stem()
        .and_then(|name| name.to_str())
        .context("offline bundle destination must have a UTF-8 file name")?;
    let parent = bundle_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{stem}.chunks")))
}

pub fn insert_chunk_manifest(
    payloads: &mut std::collections::BTreeMap<String, (String, Vec<u8>)>,
    artifacts: Vec<OfflineChunkArtifact>,
) -> Result<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    let manifest = OfflineChunkManifest {
        schema: CHUNK_MANIFEST_SCHEMA.into(),
        artifacts,
    };
    payloads.insert(
        CHUNK_MANIFEST_PATH.into(),
        (CHUNK_MANIFEST_MEDIA.into(), serde_json::to_vec(&manifest)?),
    );
    Ok(())
}

/// Stream `source` into verified chunk files under `chunk_dir`. Existing
/// matching chunks are kept so an interrupted export can resume.
pub fn export_weight_chunks(
    source: &Path,
    chunk_dir: &Path,
    chunk_size: u64,
) -> Result<OfflineChunkArtifact> {
    let meta =
        fs::metadata(source).with_context(|| format!("reading weight {}", source.display()))?;
    let mut input =
        File::open(source).with_context(|| format!("opening weight {}", source.display()))?;
    export_chunks(
        &mut input,
        meta.len(),
        "application/octet-stream",
        chunk_dir,
        chunk_size,
    )
    .with_context(|| format!("chunking weight {}", source.display()))
}

/// Stream `len` bytes of `input` into verified chunk files under
/// `chunk_dir`: weights, and image blobs too large for an archive entry
/// (#684). Existing matching chunks are kept so an interrupted export can
/// resume.
pub fn export_chunks(
    input: &mut dyn Read,
    len: u64,
    media_type: &str,
    chunk_dir: &Path,
    chunk_size: u64,
) -> Result<OfflineChunkArtifact> {
    if chunk_size == 0 {
        bail!("chunk size must be greater than zero");
    }
    fs::create_dir_all(chunk_dir)
        .with_context(|| format!("creating chunk directory {}", chunk_dir.display()))?;
    let mut hasher = Sha256::new();
    let mut chunks = Vec::new();
    let mut remaining = len;
    let mut index = 0_u32;
    while remaining > 0 {
        let take = remaining.min(chunk_size);
        let (digest, written) = write_chunk(input, chunk_dir, take, &mut hasher)?;
        if written != take {
            bail!(
                "input ended after {} bytes, expected {len}",
                len - remaining + written
            );
        }
        chunks.push(OfflineChunk {
            digest,
            size: take,
            index,
        });
        remaining -= take;
        index = index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("chunk index overflow"))?;
    }
    Ok(OfflineChunkArtifact {
        digest: format!("sha256:{:x}", hasher.finalize()),
        size: len,
        media_type: media_type.into(),
        chunks,
    })
}

/// A reader over `artifact`'s chunks in order, for streaming it into a
/// store. Each chunk file is opened only when the reader reaches it, so a
/// layer of many chunks holds one descriptor at a time. Callers verify the
/// chunks first and the store checks the whole digest before the blob is
/// visible.
pub fn chunk_reader(artifact: &OfflineChunkArtifact, chunk_dir: &Path) -> Result<Box<dyn Read>> {
    let pending = artifact
        .chunks
        .iter()
        .map(|chunk| Ok((chunk_path(chunk_dir, &chunk.digest)?, chunk.size)))
        .collect::<Result<std::collections::VecDeque<_>>>()?;
    Ok(Box::new(ChunkReader {
        pending,
        current: None,
    }))
}

struct ChunkReader {
    pending: std::collections::VecDeque<(PathBuf, u64)>,
    current: Option<std::io::Take<File>>,
}

impl Read for ChunkReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(current) = &mut self.current {
                let read = current.read(buffer)?;
                if read > 0 || buffer.is_empty() {
                    return Ok(read);
                }
                self.current = None;
            }
            let Some((path, size)) = self.pending.pop_front() else {
                return Ok(0);
            };
            self.current = Some(File::open(path)?.take(size));
        }
    }
}

/// Copy verified chunks into the weight cache. Matching cache hits and a
/// verified partial prefix resume. A corrupt chunk is refused before the
/// cache blob is replaced.
pub fn import_weight_chunks(
    bundle: &VerifiedBundle,
    chunk_dir: &Path,
    cache: &WeightCache,
) -> Result<Vec<PathBuf>> {
    import_weight_chunks_reporting(bundle, chunk_dir, cache, None)
}

/// [`import_weight_chunks`], reporting each weight's bytes to `progress`
/// chunk by chunk (#821).
pub fn import_weight_chunks_reporting(
    bundle: &VerifiedBundle,
    chunk_dir: &Path,
    cache: &WeightCache,
    progress: Option<&crate::import_progress::ImportProgress>,
) -> Result<Vec<PathBuf>> {
    let Some(raw) = bundle.entry(CHUNK_MANIFEST_PATH) else {
        return Ok(Vec::new());
    };
    let manifest: OfflineChunkManifest =
        serde_json::from_slice(raw).context("parsing offline chunk manifest")?;
    if manifest.schema != CHUNK_MANIFEST_SCHEMA {
        bail!(
            "unsupported offline chunk manifest schema {}",
            manifest.schema
        );
    }
    let mut admitted = Vec::with_capacity(manifest.artifacts.len());
    for artifact in &manifest.artifacts {
        admitted.push(import_one_artifact(artifact, chunk_dir, cache, progress)?);
    }
    Ok(admitted)
}

/// Confirm required weight chunks exist beside the archive without writing
/// the weight cache.
pub fn preflight_weight_chunks(
    bundle: &VerifiedBundle,
    bundle_path: Option<&Path>,
    required: &[String],
) -> Result<()> {
    let Some(raw) = bundle.entry(CHUNK_MANIFEST_PATH) else {
        bail!("bundle is missing a required weight chunk manifest");
    };
    let manifest: OfflineChunkManifest =
        serde_json::from_slice(raw).context("parsing offline chunk manifest")?;
    if manifest.schema != CHUNK_MANIFEST_SCHEMA {
        bail!(
            "unsupported offline chunk manifest schema {}",
            manifest.schema
        );
    }
    let path = bundle_path.context(
        "chunked offline bundle requires the archive path so companion chunks can be verified",
    )?;
    let chunk_dir = chunk_dir_beside(path)?;
    for artifact in &manifest.artifacts {
        if !required.iter().any(|digest| digest == &artifact.digest) {
            bail!(
                "offline stack manifest does not name required weight {}",
                artifact.digest
            );
        }
        preflight_weight_artifact(artifact, &chunk_dir)?;
    }
    for digest in required {
        if !manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.digest == *digest)
        {
            bail!("bundle is missing a required weight {digest}");
        }
    }
    Ok(())
}

/// Checks `artifact`'s chunks without writing: sequential indexes, each
/// chunk's size and digest, and the reassembled digest.
pub(crate) fn preflight_chunked_artifact(
    artifact: &OfflineChunkArtifact,
    chunk_dir: &Path,
) -> Result<()> {
    preflight_weight_artifact(artifact, chunk_dir)
}

fn preflight_weight_artifact(artifact: &OfflineChunkArtifact, chunk_dir: &Path) -> Result<()> {
    if artifact.chunks.is_empty() {
        bail!("offline weight {} has no chunks", artifact.digest);
    }
    let mut expected_prefix = 0_u64;
    let mut whole = Sha256::new();
    for (index, chunk) in artifact.chunks.iter().enumerate() {
        if chunk.index as usize != index {
            bail!(
                "offline weight {} chunk index is not sequential",
                artifact.digest
            );
        }
        expected_prefix = expected_prefix
            .checked_add(chunk.size)
            .ok_or_else(|| anyhow::anyhow!("chunk size overflow"))?;
        let file = chunk_path(chunk_dir, &chunk.digest)?;
        let meta = fs::metadata(&file)
            .with_context(|| format!("missing chunk {} ({})", chunk.digest, file.display()))?;
        if meta.len() != chunk.size {
            bail!(
                "chunk {} does not match its signed digest (size {})",
                chunk.digest,
                meta.len()
            );
        }
        let actual = digest_file(&file)?;
        if actual != chunk.digest {
            bail!(
                "chunk {} does not match its signed digest {actual}",
                chunk.digest
            );
        }
        let mut input = File::open(&file)?;
        let mut buffer = vec![0_u8; COPY_BUFFER];
        let mut remaining = chunk.size;
        while remaining > 0 {
            let want = remaining.min(buffer.len() as u64) as usize;
            let read = input.read(&mut buffer[..want])?;
            if read == 0 {
                bail!("chunk {} ended before its signed size", chunk.digest);
            }
            whole.update(&buffer[..read]);
            remaining -= read as u64;
        }
    }
    if expected_prefix != artifact.size {
        bail!(
            "offline weight {} chunk sizes do not sum to {}",
            artifact.digest,
            artifact.size
        );
    }
    let actual = format!("sha256:{:x}", whole.finalize());
    if actual != artifact.digest {
        bail!(
            "offline weight {} does not match reconstructed digest {actual}",
            artifact.digest
        );
    }
    Ok(())
}

/// Import companion chunks during isolated-bundle bind.
///
/// Bundles without `chunks/manifest.json` stay file-only. A chunked bundle
/// requires the JSON archive path (so `<stem>.chunks/` can be found) and
/// `TENKAI_WEIGHT_CACHE`.
/// What [`import_weight_chunks_for_bundle`] checks, without writing: the
/// archive path, a configured cache, and every chunk of every weight.
/// `reuse` is false when every weight must come from the source (an import
/// scanner is configured): cached and partial weights are then not counted,
/// and every chunk must be present.
pub fn preflight_weight_chunks_for_bundle(
    bundle: &VerifiedBundle,
    bundle_path: Option<&Path>,
    cache: Option<&WeightCache>,
    reuse: bool,
) -> Result<()> {
    let Some(raw) = bundle.entry(CHUNK_MANIFEST_PATH) else {
        return Ok(());
    };
    let cache = cache.context("TENKAI_WEIGHT_CACHE is required to import chunked weights")?;
    let manifest: OfflineChunkManifest =
        serde_json::from_slice(raw).context("parsing offline chunk manifest")?;
    if manifest.schema != CHUNK_MANIFEST_SCHEMA {
        bail!(
            "unsupported offline chunk manifest schema {}",
            manifest.schema
        );
    }
    for artifact in &manifest.artifacts {
        // A verified cached blob is reused without its chunks, as the real
        // import does; a damaged one would refuse the import.
        if cache
            .verify_cached(&artifact.digest)
            .with_context(|| format!("cached weight {} is damaged", artifact.digest))?
            && reuse
        {
            continue;
        }
        let path = bundle_path.context(
            "chunked offline bundle requires the archive path so companion chunks can be verified",
        )?;
        // An interrupted import resumes after its verified prefix and needs
        // only the remaining chunks.
        let partial = cache.blob_path(&artifact.digest)?.with_extension("partial");
        let skip = if reuse {
            resume_verified_prefix(&partial, artifact, false)?
        } else {
            0
        };
        if skip == 0 {
            preflight_weight_artifact(artifact, &chunk_dir_beside(path)?)?;
        } else {
            preflight_remaining_chunks(artifact, &chunk_dir_beside(path)?, &partial, skip)?;
        }
    }
    Ok(())
}

/// What a resumed import checks, read-only: chunk order and sizes, each
/// chunk it still reads from `skip` on, and the whole-weight digest of the
/// verified prefix in `partial` followed by those chunks.
fn preflight_remaining_chunks(
    artifact: &OfflineChunkArtifact,
    chunk_dir: &Path,
    partial: &Path,
    skip: usize,
) -> Result<()> {
    let mut total = 0_u64;
    for (index, chunk) in artifact.chunks.iter().enumerate() {
        if chunk.index as usize != index {
            bail!(
                "offline weight {} chunk index is not sequential",
                artifact.digest
            );
        }
        total = total
            .checked_add(chunk.size)
            .ok_or_else(|| anyhow::anyhow!("chunk size overflow"))?;
    }
    if total != artifact.size {
        bail!(
            "offline weight {} chunk sizes do not sum to {}",
            artifact.digest,
            artifact.size
        );
    }
    let prefix: u64 = artifact.chunks[..skip].iter().map(|chunk| chunk.size).sum();
    let mut whole = Sha256::new();
    std::io::copy(&mut File::open(partial)?.take(prefix), &mut whole)?;
    for chunk in &artifact.chunks[skip..] {
        let file = chunk_path(chunk_dir, &chunk.digest)?;
        let meta = fs::metadata(&file)
            .with_context(|| format!("missing chunk {} ({})", chunk.digest, file.display()))?;
        if meta.len() != chunk.size || digest_file(&file)? != chunk.digest {
            bail!("chunk {} does not match its signed digest", chunk.digest);
        }
        std::io::copy(&mut File::open(&file)?, &mut whole)?;
    }
    let actual = format!("sha256:{:x}", whole.finalize());
    if actual != artifact.digest {
        bail!(
            "offline weight {} does not match reconstructed digest {actual}",
            artifact.digest
        );
    }
    Ok(())
}

/// Remove any resumable partial weight for this bundle's weights, so the next
/// import reads every chunk from its source. Used when a scanner must see
/// all the bytes: a resumed prefix would skip the scanned source.
pub fn discard_partial_weights(bundle: &VerifiedBundle, cache: Option<&WeightCache>) -> Result<()> {
    let (Some(raw), Some(cache)) = (bundle.entry(CHUNK_MANIFEST_PATH), cache) else {
        return Ok(());
    };
    let manifest: OfflineChunkManifest =
        serde_json::from_slice(raw).context("parsing offline chunk manifest")?;
    for artifact in &manifest.artifacts {
        let partial = cache.blob_path(&artifact.digest)?.with_extension("partial");
        match fs::remove_file(&partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("discarding partial weight {}", partial.display()));
            }
        }
    }
    Ok(())
}

pub fn import_weight_chunks_for_bundle(
    bundle: &VerifiedBundle,
    bundle_path: Option<&Path>,
    cache: Option<&WeightCache>,
) -> Result<Vec<PathBuf>> {
    import_weight_chunks_for_bundle_reporting(bundle, bundle_path, cache, None)
}

/// [`import_weight_chunks_for_bundle`], reporting progress (#821).
pub fn import_weight_chunks_for_bundle_reporting(
    bundle: &VerifiedBundle,
    bundle_path: Option<&Path>,
    cache: Option<&WeightCache>,
    progress: Option<&crate::import_progress::ImportProgress>,
) -> Result<Vec<PathBuf>> {
    if bundle.entry(CHUNK_MANIFEST_PATH).is_none() {
        return Ok(Vec::new());
    }
    let path = bundle_path.context(
        "chunked offline bundle requires the archive path so companion chunks can be imported",
    )?;
    let cache = cache.context("TENKAI_WEIGHT_CACHE is required to import chunked weights")?;
    import_weight_chunks_reporting(bundle, &chunk_dir_beside(path)?, cache, progress)
}

/// Weight cache selected by `TENKAI_WEIGHT_CACHE`.
pub fn weight_cache_from_env() -> Result<Option<WeightCache>> {
    match crate::host_env::var_os("TENKAI_WEIGHT_CACHE") {
        Some(root) => Ok(Some(WeightCache::new(root))),
        None => Ok(None),
    }
}

pub fn peak_rss_bytes() -> Result<u64> {
    // SAFETY: `usage` is a zeroed `rusage` written only by getrusage.
    unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            bail!("failed to read process resource usage");
        }
        if cfg!(target_os = "linux") {
            Ok((usage.ru_maxrss as u64).saturating_mul(1024))
        } else {
            Ok(usage.ru_maxrss as u64)
        }
    }
}

fn write_chunk(
    input: &mut dyn Read,
    chunk_dir: &Path,
    take: u64,
    whole: &mut Sha256,
) -> Result<(String, u64)> {
    let parent = chunk_dir;
    let temporary = parent.join(format!(".chunk.{}.tmp", uuid::Uuid::new_v4()));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("creating chunk temporary {}", temporary.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut remaining = take;
    let result = (|| -> Result<(String, u64)> {
        while remaining > 0 {
            let want = remaining.min(buffer.len() as u64) as usize;
            let read = input.read(&mut buffer[..want])?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            whole.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
            remaining -= read as u64;
        }
        output.sync_all()?;
        drop(output);
        let written = take - remaining;
        let digest = format!("sha256:{:x}", hasher.finalize());
        let path = chunk_path(chunk_dir, &digest)?;
        if path.is_file() {
            let existing = digest_file(&path)?;
            if existing == digest && fs::metadata(&path)?.len() == written {
                let _ = fs::remove_file(&temporary);
                return Ok((digest, written));
            }
        }
        fs::rename(&temporary, &path)?;
        Ok((digest, written))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn import_one_artifact(
    artifact: &OfflineChunkArtifact,
    chunk_dir: &Path,
    cache: &WeightCache,
    progress: Option<&crate::import_progress::ImportProgress>,
) -> Result<PathBuf> {
    let report = |done: u64| {
        if let Some(progress) = progress {
            progress.report(&artifact.digest, "weights", done, artifact.size);
        }
    };
    signature_verification::validate_prefixed_digest("weight digest", &artifact.digest)?;
    if artifact.size > MAX_REASONABLE_WEIGHT {
        bail!(
            "offline weight {} exceeds the import size bound",
            artifact.digest
        );
    }
    let destination = cache.blob_path(&artifact.digest)?;
    if destination.is_file() {
        let admitted = cache.admit_file(&artifact.digest, &destination)?;
        report(artifact.size);
        return Ok(admitted);
    }
    let mut expected_prefix = 0_u64;
    for chunk in &artifact.chunks {
        expected_prefix = expected_prefix
            .checked_add(chunk.size)
            .ok_or_else(|| anyhow::anyhow!("chunk size overflow"))?;
    }
    if expected_prefix != artifact.size {
        bail!(
            "offline weight {} chunk sizes do not sum to {}",
            artifact.digest,
            artifact.size
        );
    }
    let parent = destination
        .parent()
        .context("weight cache blob is missing a parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating weight cache {}", parent.display()))?;
    let partial = destination.with_extension("partial");
    let skip = resume_verified_prefix(&partial, artifact, true)?;
    let mut output = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(skip == 0)
        .open(&partial)
        .with_context(|| format!("opening weight partial {}", partial.display()))?;
    if skip > 0 {
        output
            .seek(std::io::SeekFrom::End(0))
            .with_context(|| format!("resuming weight partial {}", partial.display()))?;
    }
    let mut whole = Sha256::new();
    if skip > 0 {
        let mut prefix = File::open(&partial)?;
        let mut buffer = vec![0_u8; COPY_BUFFER];
        loop {
            let read = prefix.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            whole.update(&buffer[..read]);
        }
    }
    let mut done: u64 = artifact
        .chunks
        .iter()
        .take(skip)
        .map(|chunk| chunk.size)
        .sum();
    report(done);
    for chunk in artifact.chunks.iter().skip(skip) {
        copy_verified_chunk(chunk_dir, chunk, &mut output, &mut whole)?;
        output.sync_all()?;
        done = done.saturating_add(chunk.size);
        report(done);
    }
    drop(output);
    let actual = format!("sha256:{:x}", whole.finalize());
    if actual != artifact.digest {
        let _ = fs::remove_file(&partial);
        bail!(
            "offline weight {} does not match reconstructed digest {actual}",
            artifact.digest
        );
    }
    let admitted = cache.admit_file(&artifact.digest, &partial)?;
    report(artifact.size);
    Ok(admitted)
}

/// Chunks of `artifact` already verified at the start of `partial`. When the
/// partial does not match, `discard` removes it (the import starts over); a
/// preview passes `false` and leaves it alone.
fn resume_verified_prefix(
    partial: &Path,
    artifact: &OfflineChunkArtifact,
    discard: bool,
) -> Result<usize> {
    let remove = |partial: &Path| {
        if discard {
            let _ = fs::remove_file(partial);
        }
    };
    if !partial.is_file() {
        return Ok(0);
    }
    let len = fs::metadata(partial)?.len();
    if len == 0 {
        return Ok(0);
    }
    let mut input = match File::open(partial) {
        Ok(file) => file,
        Err(_) => return Ok(0),
    };
    let mut acc = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER];
    for (index, chunk) in artifact.chunks.iter().enumerate() {
        let next = acc
            .checked_add(chunk.size)
            .ok_or_else(|| anyhow::anyhow!("chunk size overflow"))?;
        if next > len {
            break;
        }
        let mut hasher = Sha256::new();
        let mut remaining = chunk.size;
        while remaining > 0 {
            let want = remaining.min(buffer.len() as u64) as usize;
            let read = input.read(&mut buffer[..want])?;
            if read == 0 {
                remove(partial);
                return Ok(0);
            }
            hasher.update(&buffer[..read]);
            remaining -= read as u64;
        }
        if format!("sha256:{:x}", hasher.finalize()) != chunk.digest {
            remove(partial);
            return Ok(0);
        }
        acc = next;
        if acc == len {
            return Ok(index + 1);
        }
    }
    remove(partial);
    Ok(0)
}

fn copy_verified_chunk(
    chunk_dir: &Path,
    chunk: &OfflineChunk,
    output: &mut File,
    whole: &mut Sha256,
) -> Result<()> {
    signature_verification::validate_prefixed_digest("chunk digest", &chunk.digest)?;
    let path = chunk_path(chunk_dir, &chunk.digest)?;
    let meta = fs::metadata(&path)
        .with_context(|| format!("missing chunk {} ({})", chunk.digest, path.display()))?;
    if meta.len() != chunk.size {
        bail!(
            "chunk {} does not match its signed digest (size {})",
            chunk.digest,
            meta.len()
        );
    }
    let actual = digest_file(&path)?;
    if actual != chunk.digest {
        bail!(
            "chunk {} does not match its signed digest {actual}",
            chunk.digest
        );
    }
    let mut input = File::open(&path)
        .with_context(|| format!("missing chunk {} ({})", chunk.digest, path.display()))?;
    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut remaining = chunk.size;
    while remaining > 0 {
        let want = remaining.min(buffer.len() as u64) as usize;
        let read = input.read(&mut buffer[..want])?;
        if read == 0 {
            bail!("chunk {} ended before its signed size", chunk.digest);
        }
        whole.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Copy the chunks `bundle`'s signed chunk manifest names from `from` to
/// `to`, each bounded to its declared size. Nothing else in `from` is read.
pub fn copy_referenced_chunks(
    bundle: &crate::offline_bundle::BundleEnvelope,
    from: &Path,
    to: &Path,
) -> Result<()> {
    use base64::Engine as _;
    // Weight chunks and chunked image layers (#684) share the chunk store.
    let mut chunks = Vec::new();
    for path in [
        CHUNK_MANIFEST_PATH,
        crate::offline_bundle::IMAGE_CHUNKS_PATH,
    ] {
        let Some(entry) = bundle.entries.iter().find(|entry| entry.path == path) else {
            continue;
        };
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&entry.content_base64)
            .with_context(|| format!("decoding {path}"))?;
        let manifest: OfflineChunkManifest =
            serde_json::from_slice(&raw).with_context(|| format!("parsing {path}"))?;
        chunks.extend(
            manifest
                .artifacts
                .into_iter()
                .flat_map(|artifact| artifact.chunks),
        );
    }
    if chunks.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    for chunk in &chunks {
        let source = chunk_path(from, &chunk.digest)?;
        let target = chunk_path(to, &chunk.digest)?;
        if target.exists() {
            continue;
        }
        // Non-blocking open, then a regular-file check on the open file: a
        // FIFO or device in place of a chunk must not stall the import.
        let input = {
            use std::os::unix::fs::OpenOptionsExt as _;
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&source)
                .with_context(|| format!("missing chunk {} ({})", chunk.digest, source.display()))?
        };
        if !input.metadata()?.is_file() {
            bail!("chunk {} is not a regular file", chunk.digest);
        }
        let mut output = File::create(&target)?;
        // One byte past the declared size tells a longer file from a match.
        let copied = std::io::copy(&mut input.take(chunk.size + 1), &mut output)?;
        if copied != chunk.size {
            bail!("chunk {} does not match its signed size", chunk.digest);
        }
    }
    Ok(())
}

fn chunk_path(chunk_dir: &Path, digest: &str) -> Result<PathBuf> {
    let hex = digest
        .strip_prefix("sha256:")
        .context("chunk digest must be sha256-prefixed")?;
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("chunk digest {digest} is not a canonical sha256 hex");
    }
    Ok(chunk_dir.join(hex))
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

const MAX_REASONABLE_WEIGHT: u64 = 512 * 1024 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_bundle::{BundleEnvelope, BundleStatement};
    use crate::release_signing::{TrustRoots, TrustedSigner};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn digest(value: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(value))
    }

    fn roots(key: &SigningKey, identity: &str) -> TrustRoots {
        TrustRoots {
            version: 1,
            signers: vec![TrustedSigner {
                key_id: crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
                identity: identity.into(),
                public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            }],
        }
    }

    fn write_pattern(path: &Path, size: u64) {
        let mut file = File::create(path).unwrap();
        let mut left = size;
        let mut block = 0_u64;
        let mut buf = vec![0_u8; 64 * 1024];
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            for (i, byte) in buf[..n].iter_mut().enumerate() {
                *byte = (block.wrapping_add(i as u64) % 251) as u8;
            }
            file.write_all(&buf[..n]).unwrap();
            left -= n as u64;
            block += n as u64;
        }
        file.sync_all().unwrap();
    }

    fn sample_bundle(key: &SigningKey, artifact: OfflineChunkArtifact) -> BundleEnvelope {
        let mut payloads = BTreeMap::new();
        let approval = br#"{"approval":"plan-1"}"#.to_vec();
        payloads.insert(
            "approvals/plan-1.json".into(),
            ("application/json".into(), approval.clone()),
        );
        let plan = br#"{"plan":"plan-1"}"#.to_vec();
        payloads.insert(
            "plans/plan-1.json".into(),
            ("application/json".into(), plan.clone()),
        );
        payloads.insert(
            "releases/app@1.0.0/payload.bin".into(),
            (
                "application/octet-stream".into(),
                b"immutable payload".to_vec(),
            ),
        );
        insert_chunk_manifest(&mut payloads, vec![artifact]).unwrap();
        BundleEnvelope::create(
            BundleStatement {
                tenant_id: "tenant-1".into(),
                environment_id: "airgap-1".into(),
                plan_id: "plan-1".into(),
                plan_digest: digest(&plan),
                approval_digest: digest(&approval),
                release_ids: vec!["app@1.0.0".into()],
                exporter_identity: "exporter".into(),
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 10_000,
                entries: Vec::new(),
            },
            payloads,
            key,
        )
        .unwrap()
    }

    fn sandbox() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tenkai-chunks-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_only_bundle_imports_no_chunks() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut payloads = BTreeMap::new();
        let approval = br#"{"approval":"plan-1"}"#.to_vec();
        payloads.insert(
            "approvals/plan-1.json".into(),
            ("application/json".into(), approval.clone()),
        );
        let plan = br#"{"plan":"plan-1"}"#.to_vec();
        payloads.insert(
            "plans/plan-1.json".into(),
            ("application/json".into(), plan.clone()),
        );
        payloads.insert(
            "releases/app@1.0.0/payload.bin".into(),
            (
                "application/octet-stream".into(),
                b"immutable payload".to_vec(),
            ),
        );
        let archive = BundleEnvelope::create(
            BundleStatement {
                tenant_id: "tenant-1".into(),
                environment_id: "airgap-1".into(),
                plan_id: "plan-1".into(),
                plan_digest: digest(&plan),
                approval_digest: digest(&approval),
                release_ids: vec!["app@1.0.0".into()],
                exporter_identity: "exporter".into(),
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 10_000,
                entries: Vec::new(),
            },
            payloads,
            &key,
        )
        .unwrap();
        let verified = archive
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let dir = sandbox();
        let cache = WeightCache::new(dir.join("cache"));
        let imported = import_weight_chunks(&verified, &dir.join("missing"), &cache).unwrap();
        assert!(imported.is_empty());
        let skipped = import_weight_chunks_for_bundle(&verified, None, None).unwrap();
        assert!(skipped.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn chunked_bundle_import_requires_archive_path_and_cache() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        write_pattern(&source, 2 * 1024 * 1024);
        let archive_path = dir.join("delivery.json");
        let chunks = chunk_dir_beside(&archive_path).unwrap();
        let artifact = export_weight_chunks(&source, &chunks, 1024 * 1024).unwrap();
        let archive = sample_bundle(&key, artifact.clone());
        let verified = archive
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let err = import_weight_chunks_for_bundle(&verified, None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("archive path"), "{err}");
        let cache = WeightCache::new(dir.join("cache"));
        let err = import_weight_chunks_for_bundle(&verified, Some(&archive_path), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("TENKAI_WEIGHT_CACHE"), "{err}");
        let imported =
            import_weight_chunks_for_bundle(&verified, Some(&archive_path), Some(&cache)).unwrap();
        assert_eq!(digest_file(&imported[0]).unwrap(), artifact.digest);
        fs::remove_dir_all(dir).unwrap();
    }

    /// #821: a weight import reports its bytes chunk by chunk and reaches
    /// the weight's total.
    #[test]
    fn a_weight_import_reports_progress_up_to_its_total() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        write_pattern(&source, 3 * 1024 * 1024);
        let chunks = dir.join("delivery.chunks");
        let artifact = export_weight_chunks(&source, &chunks, 1024 * 1024).unwrap();
        let verified = sample_bundle(&key, artifact.clone())
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let cache = WeightCache::new(dir.join("cache"));
        let progress_file = dir.join("progress.json");
        let progress = crate::import_progress::ImportProgress::new(progress_file.clone());
        import_weight_chunks_reporting(&verified, &chunks, &cache, Some(&progress)).unwrap();
        let reported = crate::import_progress::read(&progress_file);
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert_eq!(reported[0].digest, artifact.digest);
        assert_eq!(reported[0].kind, "weights");
        assert_eq!(
            (reported[0].bytes_done, reported[0].bytes_total),
            (artifact.size, artifact.size)
        );
        // A re-import finds the weight cached and still reports it complete.
        let again_file = dir.join("progress-again.json");
        let again = crate::import_progress::ImportProgress::new(again_file.clone());
        import_weight_chunks_reporting(&verified, &chunks, &cache, Some(&again)).unwrap();
        let reported = crate::import_progress::read(&again_file);
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert_eq!(
            (reported[0].bytes_done, reported[0].bytes_total),
            (artifact.size, artifact.size)
        );
    }

    #[test]
    fn export_import_resume_and_refuse_corruption() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        write_pattern(&source, 3 * 1024 * 1024);
        let chunks = dir.join("delivery.chunks");
        let artifact = export_weight_chunks(&source, &chunks, 1024 * 1024).unwrap();
        assert_eq!(artifact.size, 3 * 1024 * 1024);
        assert_eq!(artifact.chunks.len(), 3);
        let replay = export_weight_chunks(&source, &chunks, 1024 * 1024).unwrap();
        assert_eq!(replay, artifact);

        let archive = sample_bundle(&key, artifact.clone());
        assert!(
            archive
                .statement
                .entries
                .iter()
                .all(|entry| entry.size <= crate::offline_bundle::MAX_ENTRY_BYTES)
        );
        let verified = archive
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let cache = WeightCache::new(dir.join("cache"));
        let first = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        let again = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        assert_eq!(first, again);
        assert_eq!(digest_file(&first[0]).unwrap(), artifact.digest);

        fs::remove_file(&first[0]).unwrap();
        let partial = cache
            .blob_path(&artifact.digest)
            .unwrap()
            .with_extension("partial");
        let first_chunk = chunk_path(&chunks, &artifact.chunks[0].digest).unwrap();
        fs::copy(first_chunk, &partial).unwrap();
        let resumed = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        assert_eq!(digest_file(&resumed[0]).unwrap(), artifact.digest);

        let target = cache.blob_path(&artifact.digest).unwrap();
        let before = fs::read(&target).unwrap();
        fs::remove_file(&target).unwrap();
        let corrupt = chunk_path(&chunks, &artifact.chunks[1].digest).unwrap();
        let original_chunk = fs::read(&corrupt).unwrap();
        fs::write(&corrupt, b"not-the-chunk").unwrap();
        let err = import_weight_chunks(&verified, &chunks, &cache)
            .unwrap_err()
            .to_string();
        assert!(err.contains(&artifact.chunks[1].digest), "{err}");
        assert!(!target.exists());
        fs::write(&corrupt, original_chunk).unwrap();
        let recovered = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        assert_eq!(fs::read(&recovered[0]).unwrap(), before);

        fs::remove_file(&recovered[0]).unwrap();
        let mut same_size = fs::read(&corrupt).unwrap();
        same_size[0] ^= 1;
        fs::write(&corrupt, &same_size).unwrap();
        let aligned = import_weight_chunks(&verified, &chunks, &cache)
            .unwrap_err()
            .to_string();
        assert!(aligned.contains(&artifact.chunks[1].digest), "{aligned}");
        same_size[0] ^= 1;
        fs::write(&corrupt, &same_size).unwrap();
        let recovered_aligned = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        assert_eq!(fs::read(&recovered_aligned[0]).unwrap(), before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsigned_or_retargeted_chunk_is_refused() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        write_pattern(&source, 2 * 1024 * 1024);
        let chunks = dir.join("delivery.chunks");
        let mut artifact = export_weight_chunks(&source, &chunks, 1024 * 1024).unwrap();
        artifact.chunks[0].digest = format!("sha256:{}", "ab".repeat(32));
        let archive = sample_bundle(&key, artifact.clone());
        let verified = archive
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let cache = WeightCache::new(dir.join("cache"));
        let err = import_weight_chunks(&verified, &chunks, &cache)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its signed digest") || err.contains("missing chunk"));
        assert!(!cache.blob_path(&artifact.digest).unwrap().exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removed_exporter_key_prevents_chunk_import() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        write_pattern(&source, 1024 * 1024);
        let chunks = dir.join("delivery.chunks");
        let artifact = export_weight_chunks(&source, &chunks, 1024 * 1024).unwrap();
        let archive = sample_bundle(&key, artifact);
        let err = archive
            .verify(&roots(&other, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a trusted signer")
                || err.contains("unknown")
                || err.contains("trust")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn over_archive_limit_weight_stays_out_of_json_entries() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        let size = crate::offline_bundle::MAX_ARCHIVE_BYTES + 8 * 1024 * 1024;
        write_pattern(&source, size);
        let chunks = dir.join("delivery.chunks");
        let artifact = export_weight_chunks(&source, &chunks, 32 * 1024 * 1024).unwrap();
        let archive = sample_bundle(&key, artifact.clone());
        let json = serde_json::to_vec(&archive).unwrap();
        assert!(
            (json.len() as u64) < crate::offline_bundle::MAX_ARCHIVE_BYTES,
            "json archive grew to {}",
            json.len()
        );
        let verified = archive
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let cache = WeightCache::new(dir.join("cache"));
        let rss_before = peak_rss_bytes().unwrap();
        let imported = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        let rss_after = peak_rss_bytes().unwrap();
        assert_eq!(digest_file(&imported[0]).unwrap(), artifact.digest);
        assert!(
            rss_after.saturating_sub(rss_before) < size / 2,
            "rss grew from {rss_before} to {rss_after} for {size} byte weight"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "generates a 20 GiB weight; run with --ignored for model-scale evidence"]
    fn model_scale_weight_exports_and_imports() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let dir = sandbox();
        let source = dir.join("weight.bin");
        write_pattern(&source, MODEL_SCALE_WEIGHT_BYTES);
        let chunks = dir.join("delivery.chunks");
        let artifact = export_weight_chunks(&source, &chunks, DEFAULT_CHUNK_BYTES).unwrap();
        assert_eq!(artifact.size, MODEL_SCALE_WEIGHT_BYTES);
        let archive = sample_bundle(&key, artifact.clone());
        let verified = archive
            .verify(&roots(&key, "exporter"), "tenant-1", "airgap-1", 2_000)
            .unwrap();
        let cache = WeightCache::new(dir.join("cache"));
        let rss_before = peak_rss_bytes().unwrap();
        let imported = import_weight_chunks(&verified, &chunks, &cache).unwrap();
        let rss = peak_rss_bytes().unwrap();
        assert_eq!(digest_file(&imported[0]).unwrap(), artifact.digest);
        assert!(
            rss < MODEL_SCALE_WEIGHT_BYTES / 4,
            "rss {rss} is not well below {MODEL_SCALE_WEIGHT_BYTES}"
        );
        let _ = rss_before;
        fs::remove_dir_all(dir).unwrap();
    }
}

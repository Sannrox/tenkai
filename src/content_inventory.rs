//! What release content this host holds (#680).
//!
//! For every catalog release, the OCI layers it names and the model weights
//! its manifest pins, whether the host holds those bytes in the local OCI
//! store (`TENKAI_OCI_STORE`, by digest under any registry path) or weight
//! cache (`TENKAI_WEIGHT_CACHE`) and how large they are, and what references
//! the release: channel heads and deployed versions. `missing` lists the
//! referenced content the host holds no bytes for, which is what an operator
//! must transfer before those releases can apply here.
//!
//! [`collect`] removes the content only releases nothing keeps name (#635):
//! a release is kept while a channel heads it, an environment has it
//! deployed or as its previous deployment (N-1, so rollback needs no
//! media), or an unfinished upgrade targets it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::oci_artifact::OciArtifactRef;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContentInventory {
    pub releases: Vec<ReleaseContent>,
    /// Referenced content this host holds no bytes for, as `<release> <digest>`.
    pub missing: Vec<String>,
    /// Bytes under the OCI store; absent when no store is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub oci_store_bytes: Option<u64>,
    /// Bytes under the weight cache; absent when no cache is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub weight_cache_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReleaseContent {
    pub id: String,
    pub product: String,
    pub version: String,
    pub content: Vec<ContentItem>,
    /// `channel <product>/<channel>` heads and `deployed <environment>`.
    pub referenced_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContentItem {
    pub digest: String,
    /// `layer` or `weights`.
    pub kind: String,
    /// Whether this host holds a file named for this digest: a layer under
    /// any registry path of the OCI store, a weight in the cache. Files are
    /// found by name and not re-hashed here; import, apply and fetch verify
    /// the bytes. An environment still pulls a layer through its own mirror
    /// path. Absent when the store that would hold it is not configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub size_bytes: Option<u64>,
}

impl ContentInventory {
    /// Keep only releases of products `allowed` admits, and their missing
    /// content. Store byte totals are host-wide and stay.
    pub fn retain_products(&mut self, allowed: impl Fn(&String) -> bool) {
        self.releases.retain(|release| allowed(&release.product));
        let kept = self
            .releases
            .iter()
            .map(|release| release.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        self.missing.retain(|entry| {
            entry
                .split_once(' ')
                .is_some_and(|(release, _)| kept.contains(release))
        });
    }
}

/// Inventory of the content stores configured in this process's environment.
pub async fn inventory(ctx: &mut Ctx) -> Result<ContentInventory> {
    let oci_root = crate::host_env::var_os("TENKAI_OCI_STORE")
        .filter(|root| !root.is_empty())
        .map(std::path::PathBuf::from);
    let weights = crate::offline_chunk_store::weight_cache_from_env()?;
    // Layers are stored under the mirror they were pulled through, which can
    // differ from the release's origin registry: index them by digest.
    let stored_layers = oci_root.as_deref().map(|root| {
        stored_layer_files(root)
            .into_iter()
            .map(|(digest, files)| (digest, files[0].1))
            .collect::<HashMap<_, _>>()
    });
    let mut references: Vec<(String, String, String)> = Vec::new();
    for channel in crate::catalog::list_channels(ctx).await? {
        references.push((
            channel.product.clone(),
            channel.head.clone(),
            format!("channel {}/{}", channel.product, channel.name),
        ));
    }
    for environment in crate::environment::list_environments(ctx).await? {
        for row in crate::environment::status(ctx, &environment.name).await? {
            if let Some(deployed) = row.deployed {
                references.push((
                    row.product,
                    deployed,
                    format!("deployed {}", environment.name),
                ));
            }
        }
    }
    let mut releases = Vec::new();
    let mut missing = Vec::new();
    for object in ctx.list_kind(crate::ontology::KIND_RELEASE).await? {
        let entry = crate::catalog::release_list_entry(object.clone());
        let mut content = Vec::new();
        let layers: Vec<OciArtifactRef> = object
            .properties
            .get("oci_artifacts")
            .map(|raw| serde_json::from_str(raw))
            .transpose()?
            .unwrap_or_default();
        for layer in layers {
            let size = stored_layers
                .as_ref()
                .map(|index| index.get(&layer.digest).copied());
            content.push(item(layer.digest, "layer", size));
        }
        if let Some(digest) = object
            .properties
            .get("manifest")
            .and_then(|raw| crate::manifest::parse_raw(raw).ok())
            .and_then(|manifest| manifest.model)
            .map(|model| model.artifact_digest)
        {
            let size = weights.as_ref().map(|cache| {
                cache
                    .blob_path(&digest)
                    .ok()
                    .and_then(|path| file_size(&path))
            });
            content.push(item(digest, "weights", size));
        }
        let referenced_by = references
            .iter()
            .filter(|(product, version, _)| {
                product == &entry.product && (version == &entry.version || version == &entry.id)
            })
            .map(|(_, _, by)| by.clone())
            .collect::<Vec<_>>();
        if !referenced_by.is_empty() {
            missing.extend(
                content
                    .iter()
                    .filter(|item| item.stored == Some(false))
                    .map(|item| format!("{} {}", entry.id, item.digest)),
            );
        }
        releases.push(ReleaseContent {
            id: entry.id,
            product: entry.product,
            version: entry.version,
            content,
            referenced_by,
        });
    }
    releases.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(ContentInventory {
        releases,
        missing,
        oci_store_bytes: oci_root.as_deref().map(directory_bytes),
        weight_cache_bytes: weights.as_ref().map(|cache| directory_bytes(cache.root())),
    })
}

fn item(digest: String, kind: &str, size: Option<Option<u64>>) -> ContentItem {
    ContentItem {
        digest,
        kind: kind.into(),
        stored: size.map(|size| size.is_some()),
        size_bytes: size.flatten(),
    }
}

fn file_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
}

/// Stored layer files (`sha256-<hex>`) under `root`, by digest, with their
/// sizes. A layer pulled through several mirrors has a file under each.
fn stored_layer_files(root: &Path) -> HashMap<String, Vec<(PathBuf, u64)>> {
    let mut index = HashMap::new();
    walk_layer_files(root, &mut index);
    index
}

fn walk_layer_files(root: &Path, index: &mut HashMap<String, Vec<(PathBuf, u64)>>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => walk_layer_files(&entry.path(), index),
            Ok(kind) if kind.is_file() => {
                if let (Some(hex), Ok(metadata)) = (
                    entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.strip_prefix("sha256-"))
                        .map(str::to_string),
                    entry.metadata(),
                ) {
                    index
                        .entry(format!("sha256:{hex}"))
                        .or_default()
                        .push((entry.path(), metadata.len()));
                }
            }
            _ => {}
        }
    }
}

/// Total size of the regular files under `root`; links are not followed.
fn directory_bytes(root: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => directory_bytes(&entry.path()),
            Ok(kind) if kind.is_file() => entry.metadata().map(|meta| meta.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// Advisory lock on the content stores of this host. Imports hold it
/// shared while they store content, and applies while they run; [`collect`]
/// holds it exclusive, so it never removes a blob an import or a running
/// apply relies on. Each configured store holds its own lock file.
pub struct ContentLock {
    /// One per configured store, OCI store first; released when dropped.
    _held: Vec<std::fs::File>,
}

impl ContentLock {
    const FILE: &'static str = ".tenkai-content.lock";

    /// The lock file of each configured store, in a fixed order so every
    /// process acquires them alike.
    fn open(oci_root: Option<&Path>, cache_root: Option<&Path>) -> Result<Vec<std::fs::File>> {
        let mut dirs = Vec::new();
        for dir in oci_root.into_iter().chain(cache_root) {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            // Both settings may name one directory: lock it once.
            let dir = dir
                .canonicalize()
                .with_context(|| format!("resolving {}", dir.display()))?;
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        dirs.iter()
            .map(|dir| {
                let path = dir.join(Self::FILE);
                std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path)
                    .with_context(|| format!("opening {}", path.display()))
            })
            .collect()
    }

    /// Wait for any running collection, then hold the stores this process's
    /// environment configures against one starting. The stores are
    /// resolved on the calling thread; the wait runs on a blocking thread.
    pub async fn shared_from_env() -> Result<Self> {
        let (oci_root, cache) = stores_from_env()?;
        let cache_root = cache.map(|cache| cache.root().to_path_buf());
        tokio::task::spawn_blocking(move || {
            let files = Self::open(oci_root.as_deref(), cache_root.as_deref())?;
            for file in &files {
                file.lock_shared().context("locking the content stores")?;
            }
            Ok(Self { _held: files })
        })
        .await
        .map_err(|error| anyhow::anyhow!("locking the content stores: {error}"))?
    }

    fn exclusive(oci_root: Option<&Path>, cache_root: Option<&Path>) -> Result<Self> {
        let files = Self::open(oci_root, cache_root)?;
        for file in &files {
            if file.try_lock().is_err() {
                bail!(
                    "an import or apply is using the content stores; collect content after it finishes"
                );
            }
        }
        Ok(Self { _held: files })
    }
}

fn stores_from_env() -> Result<(Option<PathBuf>, Option<crate::model_runtime::WeightCache>)> {
    let oci_root = crate::host_env::var_os("TENKAI_OCI_STORE")
        .filter(|root| !root.is_empty())
        .map(PathBuf::from);
    Ok((
        oci_root,
        crate::offline_chunk_store::weight_cache_from_env()?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentCollection {
    /// Kept releases, as `<release> <reason>`.
    pub kept: Vec<String>,
    /// Content no kept release names: removed, or on a dry run removable.
    pub collected: Vec<CollectedItem>,
    pub collected_bytes: u64,
    /// False on a dry run, which removes nothing.
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectedItem {
    pub digest: String,
    /// `layer` or `weights`.
    pub kind: String,
    pub size_bytes: u64,
}

/// [`collect`] over the stores this process's environment configures.
pub async fn collect_from_env(ctx: &mut Ctx, apply: bool) -> Result<ContentCollection> {
    let (oci_root, cache) = stores_from_env()?;
    collect(ctx, oci_root.as_deref(), cache.as_ref(), apply).await
}

/// Remove stored layers and weights that only unkept releases name (see
/// the module comment). Content no catalog release names is left alone: an
/// interrupted import may have stored it before its release was published.
/// An image manifest keeps the blobs it references. With `apply` false,
/// nothing is removed and the result lists what would be.
pub async fn collect(
    ctx: &mut Ctx,
    oci_root: Option<&Path>,
    cache: Option<&crate::model_runtime::WeightCache>,
    apply: bool,
) -> Result<ContentCollection> {
    let _lock = ContentLock::exclusive(oci_root, cache.map(|cache| cache.root()))?;
    let keep = kept_references(ctx).await?;
    let layer_files = oci_root.map(stored_layer_files).unwrap_or_default();
    let mut kept = Vec::new();
    let mut kept_digests = BTreeSet::new();
    let mut unkept_digests = BTreeSet::new();
    // Manifest digests by depth below a release's own artifacts.
    let mut manifest_depth: HashMap<String, usize> = HashMap::new();
    for object in ctx.list_kind(crate::ontology::KIND_RELEASE).await? {
        let entry = crate::catalog::release_list_entry(object.clone());
        let reasons: BTreeSet<&String> = keep
            .iter()
            .filter(|((product, version), _)| {
                product == &entry.product && (version == &entry.version || version == &entry.id)
            })
            .flat_map(|(_, reasons)| reasons)
            .collect();
        let digests = release_digests(
            &object,
            &layer_files,
            &mut manifest_depth,
            // Without an OCI store no layer is collected, so a kept image's
            // closure does not matter.
            oci_root.is_some() && !reasons.is_empty(),
        )?;
        if reasons.is_empty() {
            unkept_digests.extend(digests);
        } else {
            kept.extend(
                reasons
                    .into_iter()
                    .map(|reason| format!("{} {reason}", entry.id)),
            );
            kept_digests.extend(digests);
        }
    }
    // Deployments change only through apply, which holds the content lock
    // shared, so none moves while this runs. Channel heads and plans can:
    // refuse if they moved while this collection read them. A release made
    // live after its content went fails closed when an apply verifies it,
    // until its bundle is imported again.
    if apply && kept_references(ctx).await? != keep {
        bail!("release references changed during collection; run it again");
    }
    // Blobs go first, then manifests deepest first: an interrupted run
    // leaves every remaining blob reachable from a manifest still stored,
    // so the next run finds it again.
    let mut removable: Vec<&(&str, String)> = unkept_digests.difference(&kept_digests).collect();
    removable.sort_by_key(|(_, digest)| {
        manifest_depth
            .get(digest)
            .map_or((0, 0), |depth| (1, usize::MAX - depth))
    });
    let mut collected = Vec::new();
    for (kind, digest) in removable {
        match *kind {
            "layer" => {
                for (path, size) in layer_files.get(digest).into_iter().flatten() {
                    if apply {
                        crate::atomic_state::remove_if_exists(path)?;
                    }
                    collected.push(collected_item(digest, kind, *size));
                }
            }
            _ => {
                let Some(cache) = cache else { continue };
                let path = cache.blob_path(digest)?;
                if let Some(size) = file_size(&path) {
                    if apply {
                        crate::atomic_state::remove_if_exists(&path)?;
                    }
                    collected.push(collected_item(digest, kind, size));
                }
            }
        }
    }
    kept.sort();
    Ok(ContentCollection {
        kept,
        collected_bytes: collected.iter().map(|item| item.size_bytes).sum(),
        collected,
        applied: apply,
    })
}

/// Why each `(product, version)` is kept: channel heads, deployed and
/// previous deployments, releases unfinished plans name, and unfinished
/// upgrade targets.
async fn kept_references(ctx: &mut Ctx) -> Result<BTreeMap<(String, String), BTreeSet<String>>> {
    let mut keep: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for channel in crate::catalog::list_channels(ctx).await? {
        keep.entry((channel.product.clone(), channel.head.clone()))
            .or_default()
            .insert(format!("channel {}/{}", channel.product, channel.name));
    }
    for environment in ctx.list_kind(crate::ontology::KIND_ENVIRONMENT).await? {
        for (key, version) in &environment.properties {
            let (product, reason) = if let Some(product) = key.strip_prefix("deployed.") {
                (product, "deployed")
            } else if let Some(product) = key.strip_prefix("deployed_prev.") {
                (product, "previous")
            } else {
                continue;
            };
            keep.entry((product.to_string(), version.clone()))
                .or_default()
                .insert(format!("{reason} {}", environment.name));
        }
        let unfinished = [
            crate::plan::PlanState::Computed,
            crate::plan::PlanState::Running,
            crate::plan::PlanState::Blocked,
        ];
        for plan in
            crate::plan::list_for_environment(ctx, &environment.name, Some(&unfinished)).await?
        {
            for step in &plan.steps {
                for version in std::iter::once(&step.to).chain(&step.from) {
                    keep.entry((step.product.clone(), version.clone()))
                        .or_default()
                        .insert(format!("plan {}", plan.id));
                }
            }
        }
    }
    for (product, version) in crate::connectivity::unfinished_upgrade_releases(ctx).await? {
        keep.entry((product, version))
            .or_default()
            .insert("upgrade in progress".into());
    }
    Ok(keep)
}

fn collected_item(digest: &str, kind: &str, size_bytes: u64) -> CollectedItem {
    CollectedItem {
        digest: digest.into(),
        kind: kind.into(),
        size_bytes,
    }
}

/// Every `(kind, digest)` a release names: its layers, the blobs its
/// stored image manifests reference (transitively), and its weights.
fn release_digests(
    object: &crate::pb::sekai::Object,
    layer_files: &HashMap<String, Vec<(PathBuf, u64)>>,
    manifest_depth: &mut HashMap<String, usize>,
    kept: bool,
) -> Result<BTreeSet<(&'static str, String)>> {
    let mut digests = BTreeSet::new();
    let layers: Vec<OciArtifactRef> = object
        .properties
        .get("oci_artifacts")
        .map(|raw| serde_json::from_str(raw))
        .transpose()?
        .unwrap_or_default();
    let mut pending: Vec<(String, String, usize)> = layers
        .into_iter()
        .map(|layer| (layer.digest, layer.media_type, 0))
        .collect();
    while let Some((digest, media_type, depth)) = pending.pop() {
        if !digests.insert(("layer", digest.clone())) {
            continue;
        }
        if !crate::oci_artifact::is_manifest_media_type(&media_type) {
            continue;
        }
        let known = manifest_depth.entry(digest.clone()).or_insert(depth);
        *known = (*known).max(depth);
        // Any stored copy whose bytes match the digest will do.
        let bytes = layer_files
            .get(&digest)
            .into_iter()
            .flatten()
            .find_map(|(path, _)| {
                std::fs::read(path)
                    .ok()
                    .filter(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)) == digest)
            });
        let Some(bytes) = bytes else {
            // A kept image's closure must be known, or shared blobs could
            // go; an unkept manifest no longer stored reaches nothing.
            if kept {
                bail!(
                    "image manifest {digest} of kept release {} is missing or damaged here; import it again before collecting",
                    object.name
                );
            }
            continue;
        };
        pending.extend(
            crate::oci_artifact::referenced_blobs(&media_type, &bytes)?
                .into_iter()
                .map(|(digest, media_type)| (digest, media_type, depth + 1)),
        );
    }
    if let Some(digest) = object
        .properties
        .get("manifest")
        .and_then(|raw| crate::manifest::parse_raw(raw).ok())
        .and_then(|manifest| manifest.model)
        .map(|model| model.artifact_digest)
    {
        digests.insert(("weights", digest));
    }
    Ok(digests)
}

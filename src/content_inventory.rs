//! What release content this host holds (#680).
//!
//! For every catalog release, the OCI layers it names and the model weights
//! its manifest pins, whether the host holds those bytes in the local OCI
//! store (`TENKAI_OCI_STORE`, by digest under any registry path) or weight
//! cache (`TENKAI_WEIGHT_CACHE`) and how large they are, and what references
//! the release: channel heads and deployed versions. `missing` lists the
//! referenced content the host holds no bytes for, which is what an operator
//! must transfer before those releases can apply here.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

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
        let mut index = std::collections::HashMap::new();
        index_layers(root, &mut index);
        index
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

/// Stored layer files (`sha256-<hex>`) under `root`, by digest.
fn index_layers(root: &Path, index: &mut std::collections::HashMap<String, u64>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => index_layers(&entry.path(), index),
            Ok(kind) if kind.is_file() => {
                if let (Some(hex), Ok(metadata)) = (
                    entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.strip_prefix("sha256-"))
                        .map(str::to_string),
                    entry.metadata(),
                ) {
                    index.insert(format!("sha256:{hex}"), metadata.len());
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

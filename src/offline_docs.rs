//! Versioned docs inside the offline bundle (#646).
//!
//! A dark site cannot reach the online docs, so every bundle carries the docs
//! of the Tenkai version that built it. Production `tenkaictl` embeds this
//! tree's `docs/` at compile time and passes the bytes in; tests inject a
//! fixture. They sit under `docs/<version>/` with an index naming each file's
//! digest; the bundle signature covers both. `extract` verifies them against
//! the index and writes them out as plain files, readable with no network.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::offline_bundle::VerifiedBundle;

pub const DOCS_INDEX_SCHEMA: &str = "tenkai.offline-docs.v1";
pub const DOCS_INDEX_MEDIA: &str = "application/vnd.tenkai.offline-docs.v1+json";
pub const DOCS_INDEX_PATH: &str = "docs/index.json";

/// The signed list of bundled docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsIndex {
    pub schema: String,
    /// The Tenkai version the docs describe.
    pub version: String,
    pub files: Vec<DocsFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsFile {
    /// Relative to the version directory, `/`-separated.
    pub path: String,
    pub digest: String,
    pub size: u64,
}

/// The bundle entry path of one doc.
pub fn entry_path(version: &str, path: &str) -> String {
    format!("docs/{version}/{path}")
}

/// Adds `docs` for `version` and their index to `payloads`.
///
/// `docs` is the operator-doc tree the bundle builder supplies. Production
/// `tenkaictl` embeds this repository's `docs/`; tests inject a fixture.
pub fn insert(
    payloads: &mut BTreeMap<String, (String, Vec<u8>)>,
    version: &str,
    docs: &[(&str, &[u8])],
) -> Result<()> {
    if docs.is_empty() {
        bail!("offline bundle requires at least one doc");
    }
    let mut files = Vec::new();
    for &(path, bytes) in docs {
        safe_relative(path)?;
        let entry = entry_path(version, path);
        if payloads.contains_key(&entry) {
            bail!("bundle already contains {entry}");
        }
        payloads.insert(entry, (media_type(path).into(), bytes.to_vec()));
        files.push(DocsFile {
            path: path.into(),
            digest: sha256_digest(bytes),
            size: bytes.len() as u64,
        });
    }
    let index = DocsIndex {
        schema: DOCS_INDEX_SCHEMA.into(),
        version: version.into(),
        files,
    };
    payloads.insert(
        DOCS_INDEX_PATH.into(),
        (DOCS_INDEX_MEDIA.into(), serde_json::to_vec(&index)?),
    );
    Ok(())
}

/// The bundle's docs index, if it carries docs.
pub fn index(bundle: &VerifiedBundle) -> Result<Option<DocsIndex>> {
    let Some(raw) = bundle.entry(DOCS_INDEX_PATH) else {
        return Ok(None);
    };
    let index: DocsIndex = serde_json::from_slice(raw).context("parsing offline docs index")?;
    if index.schema != DOCS_INDEX_SCHEMA {
        bail!("unsupported offline docs schema {}", index.schema);
    }
    Ok(Some(index))
}

/// Writes a verified bundle's docs under `out/<version>/`, checking each file
/// against the signed index. `out/<version>` must not exist yet, so a partial
/// earlier extraction is never mistaken for a complete one. Answers the
/// version directory.
pub fn extract(bundle: &VerifiedBundle, out: &Path) -> Result<PathBuf> {
    let Some(index) = index(bundle)? else {
        bail!("offline bundle carries no docs ({DOCS_INDEX_PATH})");
    };
    safe_relative(&index.version).context("offline docs version")?;
    let target = out.join(&index.version);
    if target.exists() {
        bail!("docs destination {} already exists", target.display());
    }
    let staging = out.join(format!(
        ".{}.{}.extracting",
        index.version,
        uuid::Uuid::new_v4()
    ));
    let written = (|| -> Result<()> {
        std::fs::create_dir_all(&staging)
            .with_context(|| format!("creating {}", staging.display()))?;
        for file in &index.files {
            let relative = safe_relative(&file.path)?;
            let entry = entry_path(&index.version, &file.path);
            let bytes = bundle
                .entry(&entry)
                .with_context(|| format!("offline bundle is missing doc {entry}"))?;
            if sha256_digest(bytes) != file.digest {
                bail!("doc {entry} does not match its signed digest");
            }
            let path = staging.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let mut file = std::fs::File::create(&path)
                .with_context(|| format!("writing {}", path.display()))?;
            std::io::Write::write_all(&mut file, bytes)
                .and_then(|()| file.sync_all())
                .with_context(|| format!("writing {}", path.display()))?;
        }
        // Durable before it is published: a crash never leaves a complete-
        // looking version directory with missing or truncated docs.
        sync_directories(&staging)?;
        std::fs::rename(&staging, &target)
            .with_context(|| format!("publishing docs to {}", target.display()))?;
        sync_directory(out)
    })();
    if written.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    written?;
    Ok(target)
}

/// Syncs `root` and every directory below it.
fn sync_directories(root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing {}", path.display()))
}

/// A relative path with only normal components, so a signed index can never
/// write outside the destination.
fn safe_relative(path: &str) -> Result<PathBuf> {
    let candidate = Path::new(path);
    if path.is_empty()
        || !candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        bail!("offline doc path {path:?} is not a plain relative path");
    }
    Ok(candidate.to_path_buf())
}

/// The media type a bundled doc file is stored under.
pub fn media_type(path: &str) -> &'static str {
    if path.ends_with(".md") {
        "text/markdown"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_refuses_an_empty_doc_set() {
        let mut payloads = BTreeMap::new();
        let err = insert(&mut payloads, "0.0.0", &[]).unwrap_err();
        assert!(err.to_string().contains("at least one doc"), "{err}");
        assert!(payloads.is_empty());
    }

    #[test]
    fn only_plain_relative_paths_are_written() {
        for path in ["", "../escape.md", "/abs.md", "a/../../b.md", "./x.md"] {
            assert!(safe_relative(path).is_err(), "{path}");
        }
        safe_relative("guides/install.md").unwrap();
    }
}

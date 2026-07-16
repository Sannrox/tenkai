//! Product manifest (`tenkai.toml`): what a release is and how to apply it locally.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub product: ProductSection,
    pub deploy: DeploySection,
    #[serde(default)]
    pub gate: GateSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductSection {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploySection {
    /// Working directory for all commands, relative to the manifest file.
    #[serde(default = "default_workdir")]
    pub workdir: String,
    /// Command that installs/activates this release.
    pub install: String,
    /// Optional command that removes the product.
    #[serde(default)]
    pub uninstall: Option<String>,
    /// Optional health probe; exit 0 means healthy. Failure triggers rollback.
    #[serde(default)]
    pub health: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GateSection {
    /// chisei eval suite id; the latest run must be fully passing before apply.
    #[serde(default)]
    pub eval_suite: Option<String>,
}

fn default_workdir() -> String {
    ".".into()
}

pub struct LoadedManifest {
    pub manifest: Manifest,
    /// Raw manifest text as published (the release content).
    pub raw: String,
    /// Absolute workdir resolved against the manifest location.
    pub workdir: PathBuf,
}

/// Load a manifest from a file, or from stdin when the path is `-` (workdir
/// then resolves against the current directory — remote-published manifests
/// should keep their deploy commands self-contained).
pub fn load(path: &Path) -> Result<LoadedManifest> {
    let (raw, base) = if path == Path::new("-") {
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)
            .context("reading manifest from stdin")?;
        (raw, std::env::current_dir()?)
    } else {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        (raw, base)
    };
    let manifest: Manifest =
        toml::from_str(&raw).with_context(|| format!("parsing manifest {}", path.display()))?;
    if manifest.product.name.is_empty() || manifest.product.version.is_empty() {
        bail!("manifest needs product.name and product.version");
    }
    let workdir = base
        .join(&manifest.deploy.workdir)
        .canonicalize()
        .with_context(|| format!("resolving workdir {:?}", manifest.deploy.workdir))?;
    Ok(LoadedManifest {
        manifest,
        raw,
        workdir,
    })
}

pub fn parse_raw(raw: &str) -> Result<Manifest> {
    Ok(toml::from_str(raw)?)
}

pub fn digest(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

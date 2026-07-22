//! Product manifest (`tenkai.toml`): what a release is and how to apply it locally.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::executor::ExecutorKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub product: ProductSection,
    pub deploy: DeploySection,
    #[serde(default)]
    pub dependencies: Vec<DependencySection>,
    #[serde(default)]
    pub gate: GateSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencySection {
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductSection {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploySection {
    /// Deployment adapter. Existing manifests default to the local shell.
    #[serde(default)]
    pub executor: ExecutorKind,
    /// Working directory for all commands, relative to the manifest file.
    #[serde(default = "default_workdir")]
    pub workdir: String,
    /// Command that installs/activates this release.
    pub install: String,
    /// Immutable files or directories, relative to workdir, used by deploy commands.
    #[serde(default)]
    pub inputs: Vec<String>,
    /// Optional command that removes the product.
    #[serde(default)]
    pub uninstall: Option<String>,
    /// Optional command that prints the installed version. Exit code 3 means absent.
    #[serde(default)]
    pub observe: Option<String>,
    /// Optional health probe; exit 0 means healthy. Failure triggers rollback.
    #[serde(default)]
    pub health: Option<String>,
    /// Maximum duration for each install, uninstall, health, or restore command.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSection {
    /// chisei eval suite id; the latest run must be fully passing before apply.
    #[serde(default)]
    pub eval_suite: Option<String>,
}

fn default_workdir() -> String {
    ".".into()
}

fn default_timeout_seconds() -> Option<u64> {
    Some(600)
}

pub const MAX_DEPLOY_TIMEOUT_SECONDS: u64 = 60 * 60;

fn validate_timeout(manifest: &Manifest) -> Result<()> {
    match manifest.deploy.timeout_seconds {
        Some(0) => bail!("deploy.timeout_seconds must be greater than zero"),
        Some(seconds) if seconds > MAX_DEPLOY_TIMEOUT_SECONDS => {
            bail!("deploy.timeout_seconds must not exceed {MAX_DEPLOY_TIMEOUT_SECONDS} seconds")
        }
        _ => Ok(()),
    }
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
    if manifest.deploy.install.trim().is_empty() {
        bail!("manifest needs a non-empty deploy.install command");
    }
    validate_timeout(&manifest)?;
    crate::ontology::validate_identifier("product.name", &manifest.product.name)?;
    crate::ontology::validate_identifier("product.version", &manifest.product.version)?;
    validate_version(&manifest.product.version)?;
    validate_dependencies(&manifest)?;
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

pub fn validate_version(version: &str) -> Result<()> {
    semver::Version::parse(version)
        .with_context(|| format!("product.version {version:?} is not valid semver"))?;
    Ok(())
}

pub fn validate_dependencies(manifest: &Manifest) -> Result<()> {
    let mut products = std::collections::BTreeSet::new();
    for dependency in &manifest.dependencies {
        crate::ontology::validate_identifier("dependency.product", &dependency.product)?;
        if dependency.product == manifest.product.name {
            bail!("release {} cannot depend on itself", manifest.product.name);
        }
        if !products.insert(&dependency.product) {
            bail!(
                "release {} declares dependency {} more than once",
                manifest.product.name,
                dependency.product
            );
        }
        semver::VersionReq::parse(&dependency.version).with_context(|| {
            format!(
                "invalid dependency version range {:?} for {}",
                dependency.version, dependency.product
            )
        })?;
    }
    Ok(())
}

pub fn parse_raw(raw: &str) -> Result<Manifest> {
    Ok(toml::from_str(raw)?)
}

pub fn digest(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

pub fn artifact_digest(root: &Path, inputs: &[String]) -> Result<String> {
    fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    fn hash_permissions(metadata: &std::fs::Metadata, hasher: &mut Sha256) {
        use std::os::unix::fs::PermissionsExt as _;
        hasher.update((metadata.permissions().mode() & 0o7777).to_le_bytes());
    }

    fn hash_path(root: &Path, path: &Path, hasher: &mut Sha256) -> Result<()> {
        use std::os::unix::ffi::OsStrExt as _;
        let mut entries = std::fs::read_dir(path)
            .with_context(|| format!("reading artifact directory {}", path.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        hasher.update((entries.len() as u64).to_le_bytes());
        for entry in entries {
            let child = entry.path();
            let relative = child
                .strip_prefix(root)
                .with_context(|| format!("finding relative artifact path {}", child.display()))?;
            let metadata = std::fs::symlink_metadata(&child)?;
            hash_bytes(hasher, relative.as_os_str().as_bytes());
            hash_permissions(&metadata, hasher);
            if metadata.file_type().is_symlink() {
                bail!(
                    "artifact workdir cannot contain symlink {}",
                    child.display()
                );
            } else if metadata.is_dir() {
                hash_bytes(hasher, b"dir");
                hash_path(root, &child, hasher)?;
            } else if metadata.is_file() {
                hash_bytes(hasher, b"file");
                hasher.update(metadata.len().to_le_bytes());
                let mut file = std::fs::File::open(&child)?;
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = std::io::Read::read(&mut file, &mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
            } else {
                bail!(
                    "artifact workdir contains unsupported entry {}",
                    child.display()
                );
            }
        }
        Ok(())
    }

    let mut hasher = Sha256::new();
    let mut inputs = inputs.to_vec();
    inputs.sort();
    if inputs.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("deploy inputs must not contain duplicates");
    }
    hasher.update((inputs.len() as u64).to_le_bytes());
    for input in inputs {
        if input.is_empty() {
            bail!("deploy inputs must not contain empty paths");
        }
        let relative = Path::new(&input);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            bail!("deploy input must be a relative path without '..': {input}");
        }
        let path = root.join(relative);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading deploy input {}", path.display()))?;
        hash_permissions(&metadata, &mut hasher);
        if metadata.file_type().is_symlink() {
            bail!("deploy input cannot be a symlink: {}", path.display());
        } else if metadata.is_dir() {
            hash_bytes(&mut hasher, relative.to_string_lossy().as_bytes());
            hash_bytes(&mut hasher, b"dir");
            hash_path(root, &path, &mut hasher)?;
        } else if metadata.is_file() {
            hash_bytes(&mut hasher, relative.to_string_lossy().as_bytes());
            hash_bytes(&mut hasher, b"file");
            let bytes = std::fs::read(&path)?;
            hash_bytes(&mut hasher, &bytes);
        } else {
            bail!(
                "deploy input is not a file or directory: {}",
                path.display()
            );
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_entry(source: &Path, destination: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        bail!("deploy input cannot be a symlink: {}", source.display());
    }
    if metadata.is_dir() {
        std::fs::create_dir_all(destination)?;
        let mut entries = std::fs::read_dir(source)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            copy_entry(&entry.path(), &destination.join(entry.file_name()))?;
        }
        std::fs::set_permissions(destination, metadata.permissions())?;
    } else if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, destination)?;
        std::fs::set_permissions(destination, metadata.permissions())?;
    } else {
        bail!("unsupported deploy input: {}", source.display());
    }
    Ok(())
}

fn remove_entry(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        std::fs::remove_file(path)?;
        return Ok(());
    }
    if metadata.is_dir() {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        std::fs::set_permissions(path, permissions)?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                remove_entry(&entry.path())?;
            }
        }
        std::fs::remove_dir_all(path)?;
    } else {
        if let Some(parent) = path.parent() {
            let metadata = std::fs::metadata(parent)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(permissions.mode() | 0o700);
            std::fs::set_permissions(parent, permissions)?;
        }
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn prepare_copy_destination(root: &Path, relative: &Path) -> Result<PathBuf> {
    let components = relative.components().collect::<Vec<_>>();
    let mut parent = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let std::path::Component::Normal(component) = component else {
            bail!("deploy input destination is not a safe relative path");
        };
        parent.push(component);
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                remove_entry(&parent)?;
                std::fs::create_dir(&parent)?;
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => bail!(
                "deploy input parent is not a directory: {}",
                parent.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&parent)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let root = root.canonicalize()?;
    let parent = parent.canonicalize()?;
    if !parent.starts_with(&root) {
        bail!("deploy input destination escapes the runtime directory");
    }
    let file_name = relative
        .file_name()
        .context("deploy input destination has no file name")?;
    Ok(parent.join(file_name))
}

pub fn snapshot_workdir(
    source: &Path,
    inputs: &[String],
    manifest_digest: &str,
    expected_artifact_digest: &str,
) -> Result<PathBuf> {
    let state_dir = match std::env::var_os("TENKAI_STATE_DIR") {
        Some(path) => PathBuf::from(path),
        None => source
            .parent()
            .map(|parent| parent.join(".tenkai-state"))
            .unwrap_or_else(|| std::env::temp_dir().join("tenkai-state")),
    };
    let source = source.canonicalize()?;
    std::fs::create_dir_all(&state_dir)?;
    let state_dir = state_dir.canonicalize()?;
    let destination = state_dir
        .join("releases")
        .join(format!("{manifest_digest}-{expected_artifact_digest}"));
    if destination.starts_with(&source) {
        bail!("TENKAI_STATE_DIR must be outside the deployment workdir");
    }
    if destination.exists() {
        match artifact_digest(&destination, inputs) {
            Ok(digest) if digest == expected_artifact_digest => {
                return Ok(destination.canonicalize()?);
            }
            _ => std::fs::remove_dir_all(&destination)?,
        }
    }
    std::fs::create_dir_all(&destination)?;
    for input in inputs {
        let relative = Path::new(input);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            bail!("deploy input must be a relative path without '..': {input}");
        }
        copy_entry(&source.join(relative), &destination.join(relative))?;
    }
    let snapshot_digest = artifact_digest(&destination, inputs)?;
    if snapshot_digest != expected_artifact_digest {
        bail!("versioned deploy-input snapshot failed integrity verification");
    }
    Ok(destination.canonicalize()?)
}

pub fn execution_workdir(
    snapshot: &Path,
    inputs: &[String],
    expected_artifact_digest: &str,
    environment: &str,
    product: &str,
) -> Result<PathBuf> {
    let release_key = snapshot
        .file_name()
        .context("release snapshot has no content-addressed directory name")?;
    let state_dir = snapshot
        .parent()
        .and_then(Path::parent)
        .context("release snapshot is not inside the state directory")?;
    let destination = state_dir
        .join("runtime")
        .join(environment)
        .join(product)
        .join(release_key);
    if destination.exists() {
        if matches!(artifact_digest(&destination, inputs), Ok(digest) if digest == expected_artifact_digest)
        {
            return Ok(destination.canonicalize()?);
        }
        for input in inputs {
            let target = prepare_copy_destination(&destination, Path::new(input))?;
            remove_entry(&target)?;
            copy_entry(&snapshot.join(input), &target)?;
        }
    } else {
        std::fs::create_dir_all(&destination)?;
        for input in inputs {
            let target = prepare_copy_destination(&destination, Path::new(input))?;
            copy_entry(&snapshot.join(input), &target)?;
        }
    }
    let digest = artifact_digest(&destination, inputs)?;
    if digest != expected_artifact_digest {
        bail!("runtime deployment-input copy failed integrity verification");
    }
    Ok(destination.canonicalize()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn manifests_without_executor_use_local_shell() {
        let manifest = parse_raw(
            r#"
[product]
name = "api"
version = "1.0.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();

        assert_eq!(manifest.deploy.executor, ExecutorKind::LocalShell);
    }

    #[test]
    fn release_versions_must_be_semver() {
        assert!(validate_version("1.2.3+build.4").is_ok());
        assert!(validate_version("legacy_build").is_err());
    }

    #[test]
    fn artifact_digest_changes_with_executable_inputs() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-artifact-digest-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("deploy.sh"), "echo one\n").unwrap();
        let inputs = vec!["deploy.sh".to_string()];
        let first = artifact_digest(&root, &inputs).unwrap();
        std::fs::create_dir(root.join(".state")).unwrap();
        std::fs::write(root.join(".state/version"), "runtime").unwrap();
        assert_eq!(first, artifact_digest(&root, &inputs).unwrap());
        std::fs::write(root.join("deploy.sh"), "echo two\n").unwrap();
        let second = artifact_digest(&root, &inputs).unwrap();
        assert_ne!(first, second);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_copies_read_only_input_directories_outside_workdir() {
        let container = std::env::temp_dir().join(format!(
            "tenkai-snapshot-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let source = container.join("source");
        let config = source.join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("app.toml"), "enabled = true\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o555)).unwrap();
        let inputs = vec!["config".to_string()];
        let digest = artifact_digest(&source, &inputs).unwrap();
        let snapshot = snapshot_workdir(&source, &inputs, "manifest", &digest).unwrap();
        assert!(!snapshot.starts_with(&source));
        assert_eq!(artifact_digest(&snapshot, &inputs).unwrap(), digest);
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            snapshot.join("config"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::remove_dir_all(container).unwrap();
    }

    #[test]
    fn execution_workdirs_isolate_environment_runtime_state() {
        let container = std::env::temp_dir().join(format!(
            "tenkai-runtime-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let source = container.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("deploy.sh"), "echo deploy\n").unwrap();
        let inputs = vec!["deploy.sh".to_string()];
        let digest = artifact_digest(&source, &inputs).unwrap();
        let snapshot = snapshot_workdir(&source, &inputs, "manifest", &digest).unwrap();
        let first = execution_workdir(&snapshot, &inputs, &digest, "dev", "api").unwrap();
        let second = execution_workdir(&snapshot, &inputs, &digest, "prod", "api").unwrap();

        std::fs::write(first.join("runtime-state"), "dev").unwrap();
        assert_ne!(first, second);
        assert!(!second.join("runtime-state").exists());
        assert_eq!(artifact_digest(&first, &inputs).unwrap(), digest);
        std::fs::write(first.join("deploy.sh"), "corrupted\n").unwrap();
        let repaired = execution_workdir(&snapshot, &inputs, &digest, "dev", "api").unwrap();
        assert_eq!(artifact_digest(&repaired, &inputs).unwrap(), digest);
        assert!(repaired.join("runtime-state").exists());
        let outside = container.join("outside");
        std::fs::write(&outside, "do not overwrite\n").unwrap();
        std::fs::remove_file(repaired.join("deploy.sh")).unwrap();
        std::os::unix::fs::symlink(&outside, repaired.join("deploy.sh")).unwrap();
        let repaired = execution_workdir(&snapshot, &inputs, &digest, "dev", "api").unwrap();
        assert_eq!(
            std::fs::read_to_string(outside).unwrap(),
            "do not overwrite\n"
        );
        assert!(
            !std::fs::symlink_metadata(repaired.join("deploy.sh"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(container).unwrap();
    }
}

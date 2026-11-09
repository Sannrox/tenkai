//! Write a host step's sealed values to their target files (ADR 0048 §4).
//!
//! The target path is never taken from the request. It is
//! `<state_dir>/secrets/<environment>/<instance>/<secret>/<key>`, each
//! segment from the verified step and validated as a Tenkai identifier. Each
//! file is root-owned, mode 0600, written through a temporary file and a
//! rename, so a crash leaves either the old file or the new one, never part
//! of one. A retry writes the same bytes.
//!
//! Tenkai writes only inside an instance directory it created, which holds
//! [`OWNED_MARKER`]. A directory, file, or link someone else put on the path
//! fails the step instead of being replaced.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use tenkai::host_apply::VerifiedHostStep;
use tenkai::host_apply::sealed::BoundSecret;

use crate::ApplierPaths;

/// Present in every instance directory Tenkai created.
pub const OWNED_MARKER: &str = ".tenkai-owned";
const TEMP_PREFIX: &str = ".tmp-";

/// The directory `step`'s sealed values are written to, which its command
/// receives as `TENKAI_SECRETS_DIR`.
pub fn instance_dir(paths: &ApplierPaths, step: &VerifiedHostStep) -> Result<PathBuf> {
    let instance = if step.product_instance.is_empty() {
        &step.product
    } else {
        &step.product_instance
    };
    tenkai::ontology::validate_identifier("environment", &step.environment)?;
    tenkai::ontology::validate_identifier("instance", instance)?;
    Ok(paths
        .state_dir
        .join("secrets")
        .join(&step.environment)
        .join(instance))
}

/// Write `secrets` for `step` and return their directory.
pub fn write(
    paths: &ApplierPaths,
    step: &VerifiedHostStep,
    secrets: &[BoundSecret],
) -> Result<PathBuf> {
    let dir = instance_dir(paths, step)?;
    let base = paths.state_dir.join("secrets");
    let environment = base.join(&step.environment);
    for parent in [&base, &environment] {
        ensure_dir(parent)?;
    }
    create_owned(&environment, &dir)?;
    ensure_dir(&dir)?;
    if !std::fs::symlink_metadata(dir.join(OWNED_MARKER)).is_ok_and(|metadata| metadata.is_file()) {
        bail!(
            "{} was not created by Tenkai; its sealed values are not written there",
            dir.display()
        );
    }
    for secret in secrets {
        tenkai::ontology::validate_identifier("secret name", &secret.secret)?;
        tenkai::ontology::validate_identifier("secret key", &secret.key)?;
        let secret_dir = dir.join(&secret.secret);
        ensure_dir(&secret_dir)?;
        write_one(&secret_dir, &secret.key, &secret.value)
            .with_context(|| format!("writing sealed {}/{}", secret.secret, secret.key))?;
    }
    Ok(dir)
}

/// Create `dir` in `parent` already marked as Tenkai's, unless it exists:
/// a staging directory holding [`OWNED_MARKER`] is synced and renamed into
/// place, so a crash never leaves the directory without its marker. Staging
/// an earlier crash left is removed first.
fn create_owned(parent: &Path, dir: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dir).is_ok() {
        return Ok(());
    }
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("the instance directory has no name")?;
    // A digest of the name, not the name: any valid instance name keeps the
    // staging name short, and cleanup still finds only this instance's.
    let staging_prefix = format!(
        "{TEMP_PREFIX}{}-",
        &tenkai::host_apply::product_key(name, "")[..16]
    );
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        // Exactly this instance's staging, never a longer name's such as
        // `api-worker` for `api`.
        if entry
            .file_name()
            .to_str()
            .and_then(|entry| entry.strip_prefix(&staging_prefix))
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    let staging = parent.join(format!("{staging_prefix}{}", uuid::Uuid::new_v4().simple()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .with_context(|| format!("creating {}", staging.display()))?;
    create_file(&staging.join(OWNED_MARKER))?.sync_all()?;
    sync_dir(&staging)?;
    match std::fs::rename(&staging, dir) {
        Ok(()) => sync_dir(parent),
        // Created meanwhile by a step of the same product, which holds the
        // product lock, so this does not happen; never replace it anyway.
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(error).with_context(|| format!("creating {}", dir.display()))
        }
    }
}

/// Replace `<dir>/<key>` with `value`: a temporary file, synced, renamed
/// over the target, then the directory synced. Temporary files an earlier
/// crashed attempt left are removed first; a key never starts with `.`, so
/// none is a target, and steps of one product hold its lock. The temporary
/// name is short, so a key at the 253-byte limit still fits a filename.
fn write_one(dir: &Path, key: &str, value: &[u8]) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            std::fs::remove_file(entry.path())?;
        }
    }
    let target = dir.join(key);
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.is_file() && metadata.uid() == euid() => {}
        Ok(_) => bail!("the target exists and is not a file Tenkai wrote"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temp = dir.join(format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4().simple()));
    let mut file = create_file(&temp)?;
    file.write_all(value)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, &target)?;
    sync_dir(dir)
}

/// Create `dir` (mode 0700) if it is missing and return whether it was
/// created. An existing entry must be a directory this user owns that no
/// one else can write; a link is refused.
fn ensure_dir(dir: &Path) -> Result<bool> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {
            if let Some(parent) = dir.parent() {
                sync_dir(parent)?;
            }
            return Ok(true);
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("creating {}", dir.display())),
    }
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.uid() != euid() || metadata.mode() & 0o022 != 0 {
        bail!(
            "{} is not a directory only the applier can write",
            dir.display()
        );
    }
    Ok(false)
}

/// A new file, mode 0600, never following a link.
fn create_file(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

//! Write a host step's sealed values (ADR 0048 §4) and workload certificate
//! (ADR 0046 §4) to their target files.
//!
//! The target path is never taken from the request. It is
//! `<state_dir>/secrets/<environment>/<instance>/<secret>/<key>`, and
//! `<state_dir>/identity/<environment>/<instance>/current/<file>` for the
//! certificate, each segment from the verified step and validated as a
//! Tenkai identifier. Each
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

/// The tree under the state directory that sealed values are written to.
pub const SECRETS: &str = "secrets";
/// The tree under the state directory that workload certificates are
/// written to.
pub const IDENTITY: &str = "identity";
/// The link in an instance's certificate directory that names its current
/// generation; the command receives its path as `TENKAI_IDENTITY_DIR`.
pub const CURRENT_LINK: &str = "current";
const GENERATION_PREFIX: &str = "gen-";

/// The directory in `tree` ([`SECRETS`] or [`IDENTITY`]) that `step` writes
/// to, which its command receives as `TENKAI_SECRETS_DIR` or
/// `TENKAI_IDENTITY_DIR`.
pub fn instance_dir(paths: &ApplierPaths, tree: &str, step: &VerifiedHostStep) -> Result<PathBuf> {
    let instance = if step.product_instance.is_empty() {
        &step.product
    } else {
        &step.product_instance
    };
    tenkai::ontology::validate_identifier("environment", &step.environment)?;
    tenkai::ontology::validate_identifier("instance", instance)?;
    Ok(paths
        .state_dir
        .join(tree)
        .join(&step.environment)
        .join(instance))
}

/// Write `secrets` for `step` and return their directory.
pub fn write(
    paths: &ApplierPaths,
    step: &VerifiedHostStep,
    secrets: &[BoundSecret],
) -> Result<PathBuf> {
    let dir = owned_dir(paths, SECRETS, step)?;
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

/// Write `issued`, the workload certificate of `step`, and return the path
/// of its [`CURRENT_LINK`].
pub fn write_identity(
    paths: &ApplierPaths,
    step: &VerifiedHostStep,
    issued: &tenkai::workload_identity::IssuedIdentity,
) -> Result<PathBuf> {
    let dir = owned_dir(paths, IDENTITY, step)?;
    write_generation(&dir, &issued.files()?)
}

/// The [`CURRENT_LINK`] of `step`'s instance, when an earlier step wrote a
/// certificate there: what a health step's command reads.
pub fn installed_identity(
    paths: &ApplierPaths,
    step: &VerifiedHostStep,
) -> Result<Option<PathBuf>> {
    let current = instance_dir(paths, IDENTITY, step)?.join(CURRENT_LINK);
    match std::fs::symlink_metadata(&current) {
        Ok(metadata) if metadata.file_type().is_symlink() && metadata.uid() == euid() => {
            Ok(Some(current))
        }
        Ok(_) => bail!("{} is not a link Tenkai made", current.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write `files` as a new generation directory in `dir`, then switch
/// [`CURRENT_LINK`] to it with one rename. A reader that resolves the link
/// once and opens every file from that directory reads one whole set; one
/// that follows the link per file can straddle a switch. A crash before the
/// rename leaves the previous set, and the next write removes what it left.
/// The previous generation is kept, so a directory resolved just before the
/// switch stays readable; older ones go.
fn write_generation(dir: &Path, files: &[(&str, impl AsRef<[u8]>)]) -> Result<PathBuf> {
    let current = dir.join(CURRENT_LINK);
    let previous = match std::fs::symlink_metadata(&current) {
        Ok(metadata) if metadata.file_type().is_symlink() && metadata.uid() == euid() => {
            let target = std::fs::read_link(&current)?;
            let name = target
                .to_str()
                .filter(|name| name.starts_with(GENERATION_PREFIX) && !name.contains('/'))
                .with_context(|| format!("{} names no generation Tenkai wrote", current.display()))?
                .to_owned();
            Some(name)
        }
        Ok(_) => bail!("{} exists and is not a link Tenkai made", current.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(TEMP_PREFIX) {
            std::fs::remove_file(entry.path())?;
        } else if name.starts_with(GENERATION_PREFIX) && previous.as_deref() != Some(&*name) {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    let generation = format!("{GENERATION_PREFIX}{}", uuid::Uuid::new_v4().simple());
    let staged = dir.join(&generation);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    for (file, bytes) in files {
        let mut out = create_file(&staged.join(file))?;
        out.write_all(bytes.as_ref())
            .with_context(|| format!("writing {file}"))?;
        out.sync_all()?;
    }
    sync_dir(&staged)?;
    let link = dir.join(format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4().simple()));
    std::os::unix::fs::symlink(&generation, &link)?;
    std::fs::rename(&link, &current)?;
    sync_dir(dir)?;
    Ok(current)
}

/// The instance directory of `step` in `tree`, created marked as Tenkai's
/// if it is missing, and refused if someone else created it.
fn owned_dir(paths: &ApplierPaths, tree: &str, step: &VerifiedHostStep) -> Result<PathBuf> {
    let dir = instance_dir(paths, tree, step)?;
    let base = paths.state_dir.join(tree);
    let environment = base.join(&step.environment);
    for parent in [&base, &environment] {
        ensure_dir(parent)?;
    }
    create_owned(&environment, &dir)?;
    ensure_dir(&dir)?;
    if !std::fs::symlink_metadata(dir.join(OWNED_MARKER)).is_ok_and(|metadata| metadata.is_file()) {
        bail!(
            "{} was not created by Tenkai; nothing is written there",
            dir.display()
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn read(dir: &Path) -> Vec<(String, String)> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read_to_string(entry.path()).unwrap(),
                )
            })
            .collect();
        files.sort();
        files
    }

    #[test]
    fn a_host_write_interrupted_before_rename_leaves_the_previous_files_intact() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-identity-write-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let pairs = |set: [(&str, &str); 2]| {
            set.map(|(name, value)| (name.to_owned(), value.to_owned()))
                .to_vec()
        };
        let old = [("cert.pem", "old-cert"), ("key.pem", "old-key")];
        let current = write_generation(&dir, &old).unwrap();

        // A crash while the next generation was staged, before the link
        // switched: half a set, and a temporary link.
        std::fs::create_dir(dir.join(format!("{GENERATION_PREFIX}crashed"))).unwrap();
        std::fs::write(
            dir.join(format!("{GENERATION_PREFIX}crashed/cert.pem")),
            "new-cert",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            format!("{GENERATION_PREFIX}crashed"),
            dir.join(format!("{TEMP_PREFIX}link")),
        )
        .unwrap();
        assert_eq!(read(&current), pairs(old));

        // The retry switches to a whole new set and removes what the crash
        // left; the previous set stays for a reader that resolved the link
        // before the switch.
        let new = [("cert.pem", "new-cert"), ("key.pem", "new-key")];
        assert_eq!(write_generation(&dir, &new).unwrap(), current);
        assert_eq!(read(&current), pairs(new));
        let generations = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .filter(|entry| entry.as_ref().unwrap().file_name() != CURRENT_LINK)
                .count()
        };
        assert_eq!(generations(), 2);
        write_generation(&dir, &old).unwrap();
        assert_eq!(generations(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

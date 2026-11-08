//! Atomic, durable single-file state writes.
//!
//! Every replace of one state file goes through here: write a hidden sibling
//! created exclusively, sync it, verify what was written, rename it over the
//! file and sync the directory. A crash leaves the old file or the new one,
//! never a partial one, and a failure removes the sibling. Staging whole
//! directories, repointing symlinks, streaming large downloads and creating
//! a file that must never be overwritten are different operations and live
//! with their callers.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Fixed sibling (`path` + `.pending`) that earlier versions wrote through.
/// The verified writes remove one a crash left behind.
pub fn pending_path(path: &Path) -> PathBuf {
    let mut os = OsString::from(path.as_os_str());
    os.push(".pending");
    PathBuf::from(os)
}

/// Remove a file, treating absence as success.
pub fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

/// Read a file if present; `NotFound` yields `None`.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Durably replace `path` with `bytes`. With `mode` the file gets exactly
/// that mode (umask does not apply); without it, the usual default. The
/// directory must exist: a writer never recreates one removed under it.
pub fn write_file(path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
    replace(path, bytes, mode, |_| Ok(()))
}

/// Like [`write_file`], creating missing parent directories, and running
/// `verify` on the bytes read back from the temporary before the rename.
/// Failed verification leaves `path` unchanged.
pub fn write_bytes_verified(
    path: &Path,
    bytes: &[u8],
    verify: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    let parent = parent(path);
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create state directory {}", parent.display()))?;
    remove_if_exists(&pending_path(path))?;
    replace(path, bytes, None, verify)
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn replace(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    verify: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    let parent = parent(path);
    // Random, so a sibling a crash left behind never blocks a later write
    // and concurrent writers never share one.
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        uuid::Uuid::new_v4().simple()
    ));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("create temporary state {}", temporary.display()))?;
        if let Some(mode) = mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        verify(
            &std::fs::read(&temporary)
                .with_context(|| format!("read temporary state {}", temporary.display()))?,
        )?;
        std::fs::rename(&temporary, path).with_context(|| {
            format!(
                "atomically replace {} from {}",
                path.display(),
                temporary.display()
            )
        })?;
        sync_dir(parent)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// Sync a directory so a rename or create inside it survives a power loss.
pub fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("sync directory {}", dir.display()))
}

/// Serialize `value` as pretty JSON, verify the temporary by re-parsing into
/// `U`, then rename into place.
pub fn write_json_verified<T, U, F>(path: &Path, value: &T, verify: F) -> Result<()>
where
    T: Serialize,
    U: DeserializeOwned,
    F: FnOnce(&U) -> Result<()>,
{
    let bytes = serde_json::to_vec_pretty(value).context("encode state JSON")?;
    write_bytes_verified(path, &bytes, |raw| {
        let observed: U = serde_json::from_slice(raw).context("parse temporary state JSON")?;
        verify(&observed)
    })
}

/// Load optional JSON from `path`, mapping absence to `None`.
pub fn read_json_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match read_optional(path)? {
        Some(bytes) => {
            let value = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse state JSON {}", path.display()))?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    fn siblings(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_file_sets_the_exact_mode_and_cleans_up_a_failed_write() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-atomic-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let path = root.join("pins.json");
        assert!(write_file(&path, b"one", None).is_err(), "no directory");
        std::fs::create_dir_all(&root).unwrap();
        write_file(&path, b"one", Some(0o600)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        write_file(&path, b"two", Some(0o644)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (std::fs::read(&path).unwrap(), mode),
            (b"two".to_vec(), 0o644)
        );

        // A rename onto a directory fails after the temporary was written.
        let blocked = root.join("blocked");
        std::fs::create_dir_all(blocked.join("inside")).unwrap();
        assert!(write_file(&blocked, b"three", None).is_err());
        assert_eq!(siblings(&root), ["blocked", "pins.json"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        n: u32,
    }

    #[test]
    fn write_json_verified_commits_only_after_verify_succeeds() {
        let root = std::env::temp_dir().join(format!("tenkai-atomic-{}", uuid::Uuid::new_v4()));
        let path = root.join("active.json");
        let value = Sample {
            name: "ok".into(),
            n: 1,
        };

        write_json_verified::<Sample, Sample, _>(&path, &value, |observed| {
            assert_eq!(observed, &value);
            Ok(())
        })
        .unwrap();

        assert_eq!(siblings(&root), ["active.json"]);
        let loaded: Sample = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded, value);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_verify_leaves_destination_untouched() {
        let root = std::env::temp_dir().join(format!("tenkai-atomic-{}", uuid::Uuid::new_v4()));
        let path = root.join("active.json");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&path, b"{\"name\":\"prior\",\"n\":9}\n").unwrap();
        std::fs::write(pending_path(&path), b"left by an older version").unwrap();

        let err = write_json_verified::<Sample, Sample, _>(
            &path,
            &Sample {
                name: "new".into(),
                n: 2,
            },
            |_| bail!("reject"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("reject"));
        assert_eq!(siblings(&root), ["active.json"]);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("prior"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_if_exists_and_read_optional_handle_absence() {
        let root = std::env::temp_dir().join(format!("tenkai-atomic-{}", uuid::Uuid::new_v4()));
        let path = root.join("missing.json");
        remove_if_exists(&path).unwrap();
        assert!(read_optional(&path).unwrap().is_none());
        assert!(read_json_optional::<Sample>(&path).unwrap().is_none());
    }
}

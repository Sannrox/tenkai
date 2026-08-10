//! Atomic local state-file mutations for executor adapters.
//!
//! Local routing, model-runtime, and staged-artifact executors all need the
//! same durable mutation pattern: create parents, write a sibling temporary,
//! verify the temporary bytes, rename into place, and clean up on failure.
//! That behaviour lives here so callers learn a small interface and the
//! filesystem edge cases stay local.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Sibling temporary path used during an atomic replace (`path` + `.pending`).
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

/// Write `bytes` through a temporary sibling, run `verify` on the written
/// temporary contents, then rename into `path`. Failed verification removes the
/// temporary and leaves `path` unchanged.
pub fn write_bytes_verified(
    path: &Path,
    bytes: &[u8],
    verify: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("state path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create state directory {}", parent.display()))?;

    let temporary = pending_path(path);
    // Drop a leftover temporary from a prior crash before writing.
    let _ = std::fs::remove_file(&temporary);

    if let Err(error) = std::fs::write(&temporary, bytes) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("write temporary state {}", temporary.display()));
    }

    let observed = match std::fs::read(&temporary) {
        Ok(raw) => raw,
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error)
                .with_context(|| format!("read temporary state {}", temporary.display()));
        }
    };

    if let Err(error) = verify(&observed) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }

    std::fs::rename(&temporary, path).with_context(|| {
        format!(
            "atomically replace {} from {}",
            path.display(),
            temporary.display()
        )
    })?;
    Ok(())
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

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        n: u32,
    }

    #[test]
    fn pending_path_appends_suffix_without_replacing_extension() {
        assert_eq!(
            pending_path(Path::new("/tmp/active.json")),
            PathBuf::from("/tmp/active.json.pending")
        );
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

        assert!(!pending_path(&path).exists());
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
        assert!(!pending_path(&path).exists());
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

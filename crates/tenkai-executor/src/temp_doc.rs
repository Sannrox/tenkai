//! A document a deploy tool reads from a path (Helm values, a dependency
//! document, a ConfigMap), written where no other user can read, replace,
//! or redirect it.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// A file in a fresh 0700 directory under the temp dir, removed with the
/// directory on drop. The directory is created, never reused, so an entry
/// someone planted at its path fails the write instead of redirecting it.
pub(crate) struct TempDoc {
    dir: PathBuf,
    path: PathBuf,
}

impl TempDoc {
    /// Write `bytes` as `<temp>/tenkai-doc-<pid>-<random>/<name>`.
    pub(crate) fn write(name: &str, bytes: &[u8]) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-doc-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        Self::write_in(dir, name, bytes)
    }

    fn write_in(dir: PathBuf, name: &str, bytes: &[u8]) -> Result<Self> {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(name);
        let doc = Self { dir, path };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&doc.path)
            .with_context(|| format!("creating {}", doc.path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("writing {}", doc.path.display()))?;
        Ok(doc)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDoc {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// The document is private while it exists and gone after; a path
    /// planted where its directory goes is never followed.
    #[test]
    fn a_document_is_private_and_never_follows_a_planted_path() {
        let doc = TempDoc::write("values.json", b"{}").unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(doc.path()), 0o600);
        assert_eq!(mode(doc.path().parent().unwrap()), 0o700);
        assert_eq!(std::fs::read(doc.path()).unwrap(), b"{}");
        let dir = doc.path().parent().unwrap().to_path_buf();
        drop(doc);
        assert!(!dir.exists());

        let root = std::env::temp_dir().join(format!(
            "tenkai-doc-planted-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let planted = root.join("doc");
        std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();
        assert!(TempDoc::write_in(planted, "values.json", b"{}").is_err());
        assert!(!elsewhere.join("values.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}

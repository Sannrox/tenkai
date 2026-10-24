//! Environment-scoped Docker secret directory path. Credential bytes are refused.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Environment property that stores the secret-file directory path.
pub const DOCKER_SECRET_DIR_PROPERTY: &str = "docker_secret_dir";

/// Environment-scoped directory of secret env files. Credential bytes are refused.
pub fn validate_secret_dir_path(path: &Path) -> Result<()> {
    let raw = path.to_string_lossy();
    if raw.is_empty() || raw.contains('\0') || raw.contains('\n') {
        bail!("docker_secret_dir must be a single filesystem path");
    }
    let lower = raw.to_ascii_lowercase();
    for needle in ["-----begin ", "bearer ", "token=", "password=", "secret="] {
        if lower.contains(needle) {
            bail!("docker_secret_dir must be a directory path, not credential material");
        }
    }
    Ok(())
}

/// Read and admit `docker_secret_dir` from Environment properties.
pub fn secret_dir_from_properties(properties: &HashMap<String, String>) -> Result<Option<PathBuf>> {
    match properties.get(DOCKER_SECRET_DIR_PROPERTY) {
        None => Ok(None),
        Some(value) => {
            let path = PathBuf::from(value);
            validate_secret_dir_path(&path)?;
            Ok(Some(path))
        }
    }
}

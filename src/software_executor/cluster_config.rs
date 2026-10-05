//! Environment-scoped kubeconfig path admission. Credential bytes are refused.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Environment property that stores a kubeconfig file path.
pub const CLUSTER_CONFIG_PATH_PROPERTY: &str = "cluster_config_path";

/// Refuse credential material disguised as a kubeconfig path.
pub fn validate_cluster_config_path(path: &Path) -> Result<()> {
    let raw = path.to_string_lossy();
    if raw.is_empty() || raw.contains('\0') || raw.contains('\n') {
        bail!("cluster_config_path must be a single filesystem path");
    }
    let lower = raw.to_ascii_lowercase();
    for needle in [
        "-----begin ",
        "bearer ",
        "token=",
        "password=",
        "client-key-data",
    ] {
        if lower.contains(needle) {
            bail!("cluster_config_path must be a file path, not credential material");
        }
    }
    Ok(())
}

/// Read and admit `cluster_config_path` from Environment properties.
pub fn cluster_config_path_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Result<Option<PathBuf>> {
    match properties.get(CLUSTER_CONFIG_PATH_PROPERTY) {
        None => Ok(None),
        Some(value) => {
            let path = PathBuf::from(value);
            validate_cluster_config_path(&path)?;
            Ok(Some(path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_config_path_cannot_carry_credential_bytes() {
        let err = validate_cluster_config_path(Path::new("-----BEGIN CERTIFICATE-----"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("file path"), "{err}");
    }
}

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// One saved OIDC login, keyed by server URL. Issuer and token URL are pinned
/// at login so refresh never follows a later discovery document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedLogin {
    pub issuer: String,
    pub token_url: String,
    pub client_id: String,
    pub audience: String,
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds; omit when the provider did not send `expires_in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
}

pub(crate) struct TokenCache {
    path: PathBuf,
}

impl TokenCache {
    pub(crate) fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            path: config_dir.into().join("tokens.json"),
        }
    }

    pub(crate) fn get(&self, server_url: &str) -> Result<Option<SavedLogin>> {
        Ok(self.load()?.remove(server_url))
    }

    pub(crate) fn put(&self, server_url: &str, login: Option<&SavedLogin>) -> Result<()> {
        let mut logins = self.load()?;
        match login {
            Some(login) => {
                logins.insert(server_url.to_string(), login.clone());
            }
            None => {
                logins.remove(server_url);
            }
        }
        self.store(&logins)
    }

    fn load(&self) -> Result<BTreeMap<String, SavedLogin>> {
        let data = match fs::read(&self.path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(error).with_context(|| self.path.display().to_string()),
        };
        serde_json::from_slice(&data).with_context(|| {
            format!(
                "{} is corrupt; run tenkaictl logout and log in again",
                self.path.display()
            )
        })
    }

    fn store(&self, logins: &BTreeMap<String, SavedLogin>) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("token cache path has no parent directory")?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let data = serde_json::to_vec_pretty(logins)?;
        let tmp = self.path.with_extension("json.tmp");
        let _ = fs::remove_file(&tmp);
        write_private_file(&tmp, &data)?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {} from {}", self.path.display(), tmp.display()))?;
        Ok(())
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| path.display().to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn config_dir_from_env() -> Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let xdg = xdg.trim();
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("tenkai"));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("cannot find a config directory; set XDG_CONFIG_HOME")?;
    if home.trim().is_empty() {
        bail!("cannot find a config directory; set XDG_CONFIG_HOME");
    }
    Ok(PathBuf::from(home).join(".config/tenkai"))
}

/// Access tokens this close to expiry are refreshed before use.
pub(crate) const EXPIRY_SKEW_SECS: i64 = 30;

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

impl SavedLogin {
    pub(crate) fn access_token_usable(&self) -> bool {
        match self.expires_at_unix {
            Some(expiry) => expiry > now_unix() + EXPIRY_SKEW_SECS,
            None => self.refresh_token.is_none() && !self.access_token.is_empty(),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn store_forces_0600_even_if_tmp_already_existed() {
        let dir = std::env::temp_dir().join(format!("tenkai-tokens-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = TokenCache::new(&dir);
        let tmp = dir.join("tokens.json.tmp");
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        cache
            .put(
                "https://tenkai.example",
                Some(&SavedLogin {
                    issuer: "https://idp.example".into(),
                    token_url: "https://idp.example/token".into(),
                    client_id: "tenkai-cli".into(),
                    audience: "tenkai".into(),
                    access_token: "access".into(),
                    refresh_token: None,
                    expires_at_unix: None,
                }),
            )
            .unwrap();
        let mode = std::fs::metadata(dir.join("tokens.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "token cache mode {mode:#o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_expiry_with_refresh_token_is_not_usable() {
        let login = SavedLogin {
            issuer: "https://idp.example".into(),
            token_url: "https://idp.example/token".into(),
            client_id: "tenkai-cli".into(),
            audience: "tenkai".into(),
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            expires_at_unix: None,
        };
        assert!(!login.access_token_usable());
    }
}

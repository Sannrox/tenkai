use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
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
    /// Scopes requested at login; used to re-request a client-credentials token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Exclusive hold on `tokens.json.lock`. Dropping it releases the flock.
#[must_use = "the cache stays exclusive only while this guard lives"]
pub(crate) struct TokenCacheLock {
    _file: File,
}

#[derive(Clone)]
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
        let lock = self.lock_exclusive()?;
        self.put_locked(&lock, server_url, login)
    }

    /// Load-modify-store while the caller already holds `lock`.
    pub(crate) fn put_locked(
        &self,
        _lock: &TokenCacheLock,
        server_url: &str,
        login: Option<&SavedLogin>,
    ) -> Result<()> {
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

    /// Block until this process holds an exclusive flock on `tokens.json.lock`.
    pub(crate) fn lock_exclusive(&self) -> Result<TokenCacheLock> {
        let parent = self
            .path
            .parent()
            .context("token cache path has no parent directory")?;
        ensure_private_dir(parent)?;
        let lock_path = self.path.with_extension("json.lock");
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&lock_path)
            .with_context(|| lock_path.display().to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            lock_file_exclusive(&file)
                .with_context(|| format!("locking {}", lock_path.display()))?;
        }
        Ok(TokenCacheLock { _file: file })
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
        ensure_private_dir(parent)?;
        let data = serde_json::to_vec_pretty(logins)?;
        let tmp = unique_tmp(parent)?;
        let stored = write_private_file(&tmp, &data).and_then(|_| {
            fs::rename(&tmp, &self.path).with_context(|| {
                format!("replacing {} from {}", self.path.display(), tmp.display())
            })
        });
        if stored.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        stored
    }
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn unique_tmp(parent: &Path) -> Result<PathBuf> {
    let mut nonce = [0u8; 8];
    if getrandom::getrandom(&mut nonce).is_err() {
        bail!("entropy for token cache temp file");
    }
    Ok(parent.join(format!(
        "tokens.json.{}.{:016x}.tmp",
        std::process::id(),
        u64::from_be_bytes(nonce)
    )))
}

#[cfg(unix)]
fn lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `file` is open; the exclusive flock is released when it is dropped.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
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
    use std::sync::Barrier;

    fn sample_login(access: &str) -> SavedLogin {
        SavedLogin {
            issuer: "https://idp.example".into(),
            token_url: "https://idp.example/token".into(),
            client_id: "tenkai-cli".into(),
            audience: "tenkai".into(),
            access_token: access.into(),
            refresh_token: Some(format!("refresh-{access}")),
            expires_at_unix: None,
            scopes: Vec::new(),
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tenkai-tokens-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn store_forces_0600_on_cache_and_lock() {
        let dir = temp_dir();
        let cache = TokenCache::new(&dir);
        cache
            .put("https://tenkai.example", Some(&sample_login("access")))
            .unwrap();
        let cache_mode = std::fs::metadata(dir.join("tokens.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let lock_mode = std::fs::metadata(dir.join("tokens.json.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(cache_mode, 0o600, "token cache mode {cache_mode:#o}");
        assert_eq!(lock_mode, 0o600, "token lock mode {lock_mode:#o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_does_not_reuse_a_shared_tmp_name() {
        let dir = temp_dir();
        let cache = TokenCache::new(&dir);
        let stale = dir.join("tokens.json.tmp");
        std::fs::write(&stale, b"stale").unwrap();
        cache
            .put("https://tenkai.example", Some(&sample_login("access")))
            .unwrap();
        assert_eq!(std::fs::read(&stale).unwrap(), b"stale");
        let saved = cache.get("https://tenkai.example").unwrap().unwrap();
        assert_eq!(saved.access_token, "access");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_puts_keep_every_server() {
        let dir = temp_dir();
        let n = 8;
        let barrier = Barrier::new(n);
        std::thread::scope(|scope| {
            for i in 0..n {
                let barrier = &barrier;
                let dir = &dir;
                scope.spawn(move || {
                    let cache = TokenCache::new(dir);
                    barrier.wait();
                    cache
                        .put(
                            &format!("https://s{i}.example"),
                            Some(&sample_login(&format!("access-{i}"))),
                        )
                        .unwrap();
                });
            }
        });
        let cache = TokenCache::new(&dir);
        for i in 0..n {
            let saved = cache
                .get(&format!("https://s{i}.example"))
                .unwrap()
                .unwrap_or_else(|| panic!("lost server s{i}"));
            assert_eq!(saved.access_token, format!("access-{i}"));
            assert_eq!(saved.refresh_token, Some(format!("refresh-access-{i}")));
        }
        let raw = std::fs::read(dir.join("tokens.json")).unwrap();
        let parsed: BTreeMap<String, SavedLogin> = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed.len(), n);
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
            scopes: Vec::new(),
        };
        assert!(!login.access_token_usable());
    }
}

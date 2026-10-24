//! Secret settings read from the environment or a secret file (#687).
//!
//! A secret setting `X` resolves, in order, from:
//!
//! 1. `X` itself, the inline value (unchanged behavior);
//! 2. `X_FILE`, a path to a file holding the value;
//! 3. `$TENKAI_SECRET_DIR/X`, a file in a local secret directory.
//!
//! Setting both `X` and `X_FILE` is refused as ambiguous. A secret file must
//! resolve (symlinks are followed, as secret volume mounts use them) to a
//! regular file owned by this process's user with no group or world access.
//! The value is the file's text minus one trailing newline. Errors name the
//! setting and path, never the value, and nothing here logs a secret.
//!
//! Each call reads the file again, so a consumer that resolves per use sees a
//! rotated file without a restart.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// Directory holding one file per secret setting, named after it.
pub const SECRET_DIR_ENV: &str = "TENKAI_SECRET_DIR";

/// Largest secret file read.
const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// The secret setting `name`, or `None` when no source sets it.
pub fn read(name: &str) -> Result<Option<String>> {
    read_with(name, |key| std::env::var(key).ok())
}

/// The secret setting `name`; an error naming every source when none sets it.
pub fn require(name: &str) -> Result<String> {
    read(name)?.with_context(|| {
        format!("{name} is required (set {name}, {name}_FILE, or {SECRET_DIR_ENV}/{name})")
    })
}

/// Whether any source names the secret setting `name`, without reading it:
/// for guards that refuse a setting a host must not have.
pub fn is_configured(name: &str) -> bool {
    let set = |key: &str| std::env::var(key).is_ok_and(|value| !value.trim().is_empty());
    set(name)
        || set(&format!("{name}_FILE"))
        || std::env::var(SECRET_DIR_ENV)
            .ok()
            .filter(|dir| !dir.trim().is_empty())
            .is_some_and(|dir| std::fs::symlink_metadata(PathBuf::from(dir).join(name)).is_ok())
}

/// [`read`] with an explicit environment lookup.
fn read_with(name: &str, env: impl Fn(&str) -> Option<String>) -> Result<Option<String>> {
    let set = |key: &str| env(key).filter(|value| !value.trim().is_empty());
    let file_key = format!("{name}_FILE");
    match (set(name), set(&file_key)) {
        (Some(_), Some(_)) => bail!("set only one of {name} and {file_key}"),
        (Some(inline), None) => Ok(Some(inline)),
        (None, Some(path)) => read_secret_file(name, Path::new(&path)).map(Some),
        (None, None) => {
            let Some(dir) = set(SECRET_DIR_ENV) else {
                return Ok(None);
            };
            let path = PathBuf::from(dir).join(name);
            // Only a missing entry means unset; an unreadable directory or a
            // dangling link fails rather than reading as no secret.
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error)
                    .with_context(|| format!("{name}: inspecting secret file {}", path.display())),
                Ok(_) => read_secret_file(name, &path).map(Some),
            }
        }
    }
}

fn read_secret_file(name: &str, path: &Path) -> Result<String> {
    use std::io::Read as _;
    let resolved = path
        .canonicalize()
        .with_context(|| format!("{name}: secret file {} is unreadable", path.display()))?;
    // Open once and check the opened file, so the entry cannot be swapped
    // between the check and the read. Non-blocking, so a FIFO cannot stall.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&resolved)
        .with_context(|| format!("{name}: secret file {} is unreadable", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("{name}: inspecting secret file {}", path.display()))?;
    if !meta.is_file() {
        bail!(
            "{name}: secret file {} must be a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{name}: secret file {} must be owner-only (mode 0600 or 0400); found {mode:o}",
                path.display()
            );
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if meta.uid() != uid {
            bail!(
                "{name}: secret file {} must be owned by the user running tenkai",
                path.display()
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("{name}: reading secret file {}", path.display()))?;
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        bail!(
            "{name}: secret file {} is larger than {MAX_SECRET_BYTES} bytes",
            path.display()
        );
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{name}: secret file {} is not UTF-8 text", path.display()))?;
    let value = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if value.trim().is_empty() {
        bail!("{name}: secret file {} is empty", path.display());
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-secret-source-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    fn lookup(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn inline_values_keep_working_and_unset_reads_none() {
        let env = lookup(&[("TOKEN", "inline".into())]);
        assert_eq!(read_with("TOKEN", &env).unwrap().as_deref(), Some("inline"));
        assert_eq!(read_with("OTHER", &env).unwrap(), None);
    }

    #[test]
    fn a_file_reference_resolves_and_rereads_after_rotation() {
        let dir = temp_dir();
        let path = dir.join("token");
        write(&path, "first\n", 0o600);
        let env = lookup(&[("TOKEN_FILE", path.display().to_string())]);
        assert_eq!(read_with("TOKEN", &env).unwrap().as_deref(), Some("first"));
        write(&path, "second\n", 0o600);
        assert_eq!(read_with("TOKEN", &env).unwrap().as_deref(), Some("second"));
        // A symlink, as a mounted secret volume uses, resolves to its target.
        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            let env = lookup(&[("TOKEN_FILE", link.display().to_string())]);
            assert_eq!(read_with("TOKEN", &env).unwrap().as_deref(), Some("second"));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_secret_directory_supplies_settings_by_name() {
        let dir = temp_dir();
        write(&dir.join("TOKEN"), "from-dir", 0o400);
        let env = lookup(&[(SECRET_DIR_ENV, dir.display().to_string())]);
        assert_eq!(
            read_with("TOKEN", &env).unwrap().as_deref(),
            Some("from-dir")
        );
        assert_eq!(read_with("ABSENT", &env).unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_file_is_refused_without_its_value() {
        let dir = temp_dir();
        let path = dir.join("token");
        write(&path, "hunter2", 0o644);
        let env = lookup(&[("TOKEN_FILE", path.display().to_string())]);
        let error = read_with("TOKEN", &env).unwrap_err().to_string();
        assert!(error.contains("owner-only"), "{error}");
        assert!(!error.contains("hunter2"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_link_in_the_secret_directory_fails_instead_of_reading_unset() {
        let dir = temp_dir();
        std::os::unix::fs::symlink(dir.join("gone"), dir.join("TOKEN")).unwrap();
        let env = lookup(&[(SECRET_DIR_ENV, dir.display().to_string())]);
        assert!(read_with("TOKEN", &env).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn inline_and_file_together_are_ambiguous() {
        let env = lookup(&[
            ("TOKEN", "inline".into()),
            ("TOKEN_FILE", "/nonexistent".into()),
        ]);
        assert!(
            read_with("TOKEN", &env)
                .unwrap_err()
                .to_string()
                .contains("only one")
        );
    }
}

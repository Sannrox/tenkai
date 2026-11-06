//! Optional tenkaictl client config: system file, then user file.
//!
//! Flags and environment variables override both. The file never holds a
//! token; `token_file` is a path. A config not owned by root or by this user
//! is refused.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::args::{Cli, Command, Target};
use crate::catalog_args::ApprovalCommand;
use crate::migrate_args::MigrateCommand;

/// Default embedded store when `--database` / `TENKAI_DATABASE` are unset.
pub(crate) const DEFAULT_DATABASE: &str = ".tenkai-state/tenkai.db";

/// System-wide client config, unless `TENKAI_SYSTEM_CLIENT_CONFIG` names another file.
pub(crate) const SYSTEM_CLIENT_CONFIG: &str = "/etc/tenkai/client.toml";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClientConfig {
    pub target: Option<Target>,
    pub server_url: Option<String>,
    pub default_environment: Option<String>,
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfigFile {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    server_url: Option<String>,
    #[serde(default)]
    default_environment: Option<String>,
    #[serde(default)]
    token_file: Option<PathBuf>,
}

impl ClientConfigFile {
    fn into_config(self, path: &Path) -> Result<ClientConfig> {
        let target = match self
            .target
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            None => None,
            Some("embedded") => Some(Target::Embedded),
            Some("remote") => Some(Target::Remote),
            Some(other) => {
                bail!(
                    "{}: target must be \"embedded\" or \"remote\", not {other:?}",
                    path.display()
                )
            }
        };
        Ok(ClientConfig {
            target,
            server_url: nonempty_owned(self.server_url),
            default_environment: nonempty_owned(self.default_environment),
            token_file: self.token_file.filter(|path| !path.as_os_str().is_empty()),
        })
    }
}

fn nonempty_owned(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl ClientConfig {
    /// Load system config, then user config. Missing files are skipped.
    /// An unavailable user config directory or an unreadable user file is
    /// treated as no user file (`sudo -u tenkai` often inherits another
    /// account's `HOME` / `XDG_CONFIG_HOME`).
    pub(crate) fn load() -> Result<Self> {
        let mut config = ClientConfig::default();
        if let Some(system) = load_file(&system_config_path())? {
            config.merge(system);
        }
        if let Ok(user) = user_config_path()
            && let Some(user) = load_user_file(&user)?
        {
            config.merge(user);
        }
        Ok(config)
    }

    #[cfg(test)]
    pub(crate) fn load_from_paths(system: &Path, user: &Path) -> Result<Self> {
        let mut config = ClientConfig::default();
        if let Some(system) = load_file(system)? {
            config.merge(system);
        }
        if let Some(user) = load_user_file(user)? {
            config.merge(user);
        }
        Ok(config)
    }

    fn merge(&mut self, other: ClientConfig) {
        let server_url_changed = other.server_url.is_some() && other.server_url != self.server_url;
        if other.target.is_some() {
            self.target = other.target;
        }
        if other.server_url.is_some() {
            self.server_url = other.server_url;
        }
        if other.default_environment.is_some() {
            self.default_environment = other.default_environment;
        }
        if other.token_file.is_some() {
            self.token_file = other.token_file;
        } else if server_url_changed {
            // A token_file is bound to the server_url it was configured with.
            self.token_file = None;
        }
    }
}

pub(crate) fn system_config_path() -> PathBuf {
    std::env::var("TENKAI_SYSTEM_CLIENT_CONFIG")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SYSTEM_CLIENT_CONFIG))
}

pub(crate) fn user_config_path() -> Result<PathBuf> {
    Ok(crate::token_cache::config_dir_from_env()?.join("client.toml"))
}

fn is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    })
}

/// User overlay: skip a file this process cannot read. System config still
/// fails closed so a present `/etc/tenkai/client.toml` is never ignored.
fn load_user_file(path: &Path) -> Result<Option<ClientConfig>> {
    match load_file(path) {
        Ok(config) => Ok(config),
        Err(err) if is_permission_denied(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn load_file(path: &Path) -> Result<Option<ClientConfig>> {
    use std::io::Read as _;
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    let meta = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} must be a regular file", path.display());
    }
    require_trusted_config(path, &meta)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| path.display().to_string())?;
    let parsed: ClientConfigFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(parsed.into_config(path)?))
}

fn require_trusted_config(path: &Path, meta: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if meta.uid() != 0 && meta.uid() != uid {
            bail!(
                "{} must be owned by root or by the user running tenkaictl",
                path.display()
            );
        }
        if meta.mode() & 0o022 != 0 {
            bail!("{} must not be writable by group or others", path.display());
        }
    }
    let _ = (path, meta);
    Ok(())
}

/// Fill `--env` when the command takes one and the operator did not pass it:
/// config `default_environment`, else the unique registered environment.
pub(crate) fn resolve_environment(
    requested: Option<&str>,
    configured: Option<&str>,
    registered: &[String],
) -> Result<String> {
    if let Some(env) = requested.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(env.to_string());
    }
    if let Some(env) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(env.to_string());
    }
    match registered {
        [only] => Ok(only.clone()),
        [] => bail!("no environment is registered; pass --env or run tenkaictl env add <name>"),
        _ => bail!("pass --env; registered: {}", registered.join(", ")),
    }
}

pub(crate) fn needs_env_resolution(command: &mut Command) -> bool {
    command_env_mut(command).is_some_and(|slot| slot.is_none())
}

pub(crate) fn command_env_mut(command: &mut Command) -> Option<&mut Option<String>> {
    match command {
        Command::Plan { env, .. }
        | Command::Status { env, .. }
        | Command::Rollback { env, .. }
        | Command::Restart { env, .. } => Some(env),
        Command::Approval {
            command: ApprovalCommand::Submit { env, .. },
        } => Some(env),
        Command::Migrate {
            command: MigrateCommand::Preview { env, .. } | MigrateCommand::Apply { env, .. },
        } => Some(env),
        _ => None,
    }
}

pub(crate) fn require_env(env: Option<String>) -> Result<String> {
    env.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("pass --env"))
}

pub(crate) fn apply_resolved_environment(
    command: &mut Command,
    config: &ClientConfig,
    registered: &[String],
) -> Result<()> {
    let Some(slot) = command_env_mut(command) else {
        return Ok(());
    };
    if slot.is_some() {
        return Ok(());
    }
    *slot = Some(resolve_environment(
        None,
        config.default_environment.as_deref(),
        registered,
    )?);
    Ok(())
}

pub(crate) fn command_creates_store(command: &Command) -> bool {
    matches!(command, Command::Init | Command::Restore { .. })
}

/// True when `--database` / `--database=` is on argv. That names a local
/// store, so it overrides client.toml `target = "remote"` unless `--target`
/// is also set.
pub(crate) fn argv_has_database_flag<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    for arg in args {
        let arg = arg.as_ref();
        if arg == "--" {
            break;
        }
        if arg == "--database" {
            return true;
        }
        if let Some(text) = arg.to_str()
            && text.starts_with("--database=")
        {
            return true;
        }
    }
    false
}

/// Fill `server_url` and `token_file` from config. Capture whether the CLI
/// already had a server URL (flag or `TENKAI_SERVER_URL`) *before* copying
/// config: an override leaves the config token behind so it is not sent to a
/// different host. Login and logout never take `token_file` from config.
pub(crate) fn apply_server_and_token(cli: &mut Cli, config: &ClientConfig) {
    let server_url_from_flag_or_env = cli.server_url.is_some();
    if cli.server_url.is_none() {
        cli.server_url = config.server_url.clone();
    }
    if cli.token_file.is_none()
        && !server_url_from_flag_or_env
        && !matches!(cli.command, Command::Login { .. } | Command::Logout)
    {
        cli.token_file = config.token_file.clone();
    }
}

pub(crate) fn missing_default_store_message(database: &Path) -> String {
    format!(
        "no Tenkai store at {}; use --target remote --server-url <url>, or run tenkaictl init for a local store",
        database.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::Write;

    fn sample_remote_config() -> ClientConfig {
        ClientConfig {
            target: Some(Target::Remote),
            server_url: Some("http://127.0.0.1:8080".into()),
            default_environment: None,
            token_file: Some(PathBuf::from("/etc/tenkai/management.token")),
        }
    }

    #[test]
    fn argv_database_flag_is_detected() {
        assert!(argv_has_database_flag([
            "tenkaictl",
            "--database",
            "/var/lib/tenkai/tenkai.db",
            "init"
        ]));
        assert!(argv_has_database_flag([
            "tenkaictl",
            "--database=/tmp/tenkai.db",
            "env",
            "add",
            "edge"
        ]));
        assert!(!argv_has_database_flag([
            "tenkaictl",
            "status",
            "--env",
            "edge"
        ]));
        assert!(!argv_has_database_flag([
            "tenkaictl",
            "--",
            "--database",
            "nope"
        ]));
    }

    #[test]
    fn config_token_file_applies_together_with_config_server_url() {
        let mut cli = Cli::try_parse_from(["tenkaictl", "status"]).unwrap();
        apply_server_and_token(&mut cli, &sample_remote_config());
        assert_eq!(cli.server_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(
            cli.token_file.as_deref(),
            Some(Path::new("/etc/tenkai/management.token"))
        );
    }

    #[test]
    fn flag_server_url_does_not_take_config_token_file() {
        let mut cli = Cli::try_parse_from([
            "tenkaictl",
            "--server-url",
            "http://other.example:8080",
            "status",
        ])
        .unwrap();
        apply_server_and_token(&mut cli, &sample_remote_config());
        assert_eq!(cli.server_url.as_deref(), Some("http://other.example:8080"));
        assert!(cli.token_file.is_none());
    }

    #[test]
    fn login_does_not_take_config_token_file() {
        let mut cli = Cli::try_parse_from(["tenkaictl", "login"]).unwrap();
        apply_server_and_token(&mut cli, &sample_remote_config());
        assert_eq!(cli.server_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert!(cli.token_file.is_none());
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-client-config-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, body: &str) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        file.sync_all().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn user_config_overrides_system_and_missing_files_are_skipped() {
        let dir = temp_dir();
        let system = dir.join("system.toml");
        let user = dir.join("user.toml");
        write(
            &system,
            r#"
target = "remote"
server_url = "http://127.0.0.1:8080"
default_environment = "edge"
token_file = "/etc/tenkai/management.token"
"#,
        );
        write(
            &user,
            r#"
target = "embedded"
default_environment = "lab"
"#,
        );
        let config = ClientConfig::load_from_paths(&system, &user).unwrap();
        assert_eq!(config.target, Some(Target::Embedded));
        assert_eq!(config.server_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(config.default_environment.as_deref(), Some("lab"));
        assert_eq!(
            config.token_file.as_deref(),
            Some(Path::new("/etc/tenkai/management.token"))
        );

        let missing = dir.join("missing.toml");
        let only_system = ClientConfig::load_from_paths(&system, &missing).unwrap();
        assert_eq!(only_system.target, Some(Target::Remote));
        assert_eq!(only_system.default_environment.as_deref(), Some("edge"));
    }

    #[test]
    fn overlay_server_url_drops_inherited_token_file() {
        let dir = temp_dir();
        let system = dir.join("system.toml");
        let user = dir.join("user.toml");
        write(
            &system,
            r#"
target = "remote"
server_url = "http://127.0.0.1:8080"
token_file = "/etc/tenkai/management.token"
"#,
        );
        write(
            &user,
            r#"
server_url = "http://other.example:8080"
"#,
        );
        let config = ClientConfig::load_from_paths(&system, &user).unwrap();
        assert_eq!(
            config.server_url.as_deref(),
            Some("http://other.example:8080")
        );
        assert_eq!(config.token_file, None);

        write(
            &user,
            r#"
default_environment = "lab"
"#,
        );
        let same_server = ClientConfig::load_from_paths(&system, &user).unwrap();
        assert_eq!(
            same_server.token_file.as_deref(),
            Some(Path::new("/etc/tenkai/management.token"))
        );
    }

    #[test]
    fn flag_then_env_then_user_then_system_for_environment() {
        assert_eq!(
            resolve_environment(Some("flag"), Some("config"), &["a".into(), "b".into()]).unwrap(),
            "flag"
        );
        assert_eq!(
            resolve_environment(None, Some("config"), &["a".into()]).unwrap(),
            "config"
        );
        assert_eq!(
            resolve_environment(None, None, &["only".into()]).unwrap(),
            "only"
        );
        let err = resolve_environment(None, None, &["a".into(), "b".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("pass --env"), "{err}");
        assert!(err.contains("a, b"), "{err}");
        let empty = resolve_environment(None, None, &[])
            .unwrap_err()
            .to_string();
        assert!(empty.contains("no environment is registered"), "{empty}");
    }

    #[test]
    fn unknown_keys_and_targets_are_refused() {
        let dir = temp_dir();
        let path = dir.join("bad.toml");
        write(&path, "token = \"secret\"\n");
        let err = format!(
            "{:#}",
            ClientConfig::load_from_paths(&path, &dir.join("missing")).unwrap_err()
        );
        assert!(err.contains("unknown") || err.contains("token"), "{err}");

        write(&path, "target = \"cluster\"\n");
        let err = ClientConfig::load_from_paths(&path, &dir.join("missing"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("embedded"), "{err}");
        assert!(err.contains("remote"), "{err}");
    }

    #[test]
    fn missing_store_message_names_both_options() {
        let message = missing_default_store_message(Path::new(DEFAULT_DATABASE));
        assert!(message.contains("--target remote"), "{message}");
        assert!(message.contains("tenkaictl init"), "{message}");
        assert!(message.contains(DEFAULT_DATABASE), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_user_config_is_treated_as_absent() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = temp_dir();
        let user = dir.join("client.toml");
        write(&user, "target = \"remote\"\n");
        fs::set_permissions(&user, fs::Permissions::from_mode(0o000)).unwrap();
        let missing = dir.join("missing.toml");
        let config = ClientConfig::load_from_paths(&missing, &user).unwrap();
        assert_eq!(config, ClientConfig::default());
        fs::set_permissions(&user, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_system_config_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = temp_dir();
        let system = dir.join("client.toml");
        write(&system, "target = \"remote\"\n");
        fs::set_permissions(&system, fs::Permissions::from_mode(0o000)).unwrap();
        let err = ClientConfig::load_from_paths(&system, &dir.join("missing"))
            .unwrap_err()
            .to_string();
        fs::set_permissions(&system, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(err.contains("reading"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_writable_config_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir();
        let path = dir.join("client.toml");
        write(&path, "target = \"remote\"\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let err = ClientConfig::load_from_paths(&path, &dir.join("missing"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("writable"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_token_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir();
        let path = dir.join("token");
        write(&path, "s3cret\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = tenkai::secret_source::read_from_path("token_file", &path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("owner-only"), "{err}");
        assert!(!err.contains("s3cret"), "{err}");
    }
}

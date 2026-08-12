//! Generation-fenced local mutation supervision.
//!
//! This deep module owns executor-guard discovery, the controller/guard pipe
//! protocol, mutation locking, process-group cleanup, signals, and timeouts.
//! Callers retain lease ownership and expose only refresh plus generation.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;

use anyhow::{Context as _, Result, bail};

pub trait MutationFence: Send {
    fn generation(&self) -> u64;
    fn refresh(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

pub struct MutationCommand<'a> {
    pub lock_path: &'a Path,
    pub workdir: &'a Path,
    pub environment: &'a str,
    pub product: &'a str,
    pub command: &'a str,
}

/// Parent-process variables that may be inherited by deploy children.
///
/// Control-plane credentials (`TENKAI_MANAGEMENT_TOKEN`, `TENKAI_RUNTIME_TOKEN`,
/// outcome-provider tokens, `SEKAI_AUTH_TOKEN`, and similar) are intentionally
/// absent. Deploy shells receive only this allowlist plus the explicit Tenkai
/// fencing/identity variables set by [`configure_deploy_child_env`].
const DEPLOY_CHILD_INHERITED_ENV: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "TZ",
];

/// Secrets and control-plane credentials that must never reach deploy shells.
const DEPLOY_CHILD_FORBIDDEN_ENV: &[&str] = &[
    "SEKAI_AUTH_TOKEN",
    "TENKAI_MANAGEMENT_TOKEN",
    "TENKAI_RUNTIME_TOKEN",
    "TENKAI_RUNTIME_TOKENS",
    "TENKAI_OUTCOME_PROVIDER_TOKEN",
    "TENKAI_OUTCOME_PROVIDER_URL",
    "TENKAI_OUTCOME_PROVIDER_PRINCIPAL",
    "TENKAI_OUTCOME_PROVIDER_REGISTRATION",
    "TENKAI_JWT_VERIFIER_CONFIG",
    "TENKAI_POSTGRES_URL",
    "TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS",
];

fn executor_guard_executable() -> Result<PathBuf> {
    if let Some(configured) = std::env::var_os("TENKAI_EXECUTOR_GUARD") {
        let configured = PathBuf::from(configured);
        if configured.is_file() {
            return Ok(configured);
        }
        bail!(
            "TENKAI_EXECUTOR_GUARD does not identify a file: {}",
            configured.display()
        );
    }
    let current = std::env::current_exe()?;
    if current
        .file_stem()
        .is_some_and(|name| name.to_string_lossy().starts_with("tenkaictl"))
    {
        return Ok(current);
    }
    for directory in current.ancestors().skip(1).take(2) {
        let candidate = directory.join("tenkai-executor-guard");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "tenkai-executor-guard was not found beside {}; install both Tenkai binaries or set TENKAI_EXECUTOR_GUARD",
        current.display()
    )
}

/// Build the scrubbed environment for a deploy child process.
///
/// Starts empty (no parent inheritance), copies only
/// [`DEPLOY_CHILD_INHERITED_ENV`], then sets fencing/identity variables.
pub fn deploy_child_environment(
    environment: &str,
    product: &str,
    fencing_generation: Option<u64>,
) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    for key in DEPLOY_CHILD_INHERITED_ENV {
        if let Some(value) = std::env::var_os(key) {
            env.insert(OsString::from(*key), value);
        }
    }
    let identity_digest = crate::manifest::digest(&format!("{environment}\0{product}"));
    env.insert(
        OsString::from("TENKAI_ENVIRONMENT"),
        OsString::from(environment),
    );
    env.insert(OsString::from("TENKAI_PRODUCT"), OsString::from(product));
    env.insert(
        OsString::from("COMPOSE_PROJECT_NAME"),
        OsString::from(format!("tenkai-{}", &identity_digest[..16])),
    );
    if let Some(generation) = fencing_generation {
        env.insert(
            OsString::from("TENKAI_FENCING_GENERATION"),
            OsString::from(generation.to_string()),
        );
    }
    env
}

fn configure_deploy_child_env(
    command: &mut tokio::process::Command,
    environment: &str,
    product: &str,
    fencing_generation: Option<u64>,
) {
    command.env_clear();
    for (key, value) in deploy_child_environment(environment, product, fencing_generation) {
        command.env(key, value);
    }
}

pub async fn run(
    fence: &mut dyn MutationFence,
    mutation: MutationCommand<'_>,
) -> Result<Result<(), String>> {
    fence.refresh().await?;
    if let Some(parent) = mutation.lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut guard_command = tokio::process::Command::new(executor_guard_executable()?);
    if guard_command
        .as_std()
        .get_program()
        .to_string_lossy()
        .contains("tenkaictl")
    {
        guard_command.arg("__executor-guard");
    }
    // Scrub credentials before the trusted guard as defense in depth; the
    // untrusted install shell is scrubbed again in [`supervise`].
    configure_deploy_child_env(
        &mut guard_command,
        mutation.environment,
        mutation.product,
        Some(fence.generation()),
    );
    guard_command
        .arg("--lock")
        .arg(mutation.lock_path)
        .arg("--workdir")
        .arg(mutation.workdir)
        .arg("--environment")
        .arg(mutation.environment)
        .arg("--product")
        .arg(mutation.product)
        .arg("--generation")
        .arg(fence.generation().to_string())
        .arg("--command")
        .arg(mutation.command)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut guard = guard_command
        .spawn()
        .context("spawning deployment command guard")?;
    let mut control = guard
        .stdin
        .take()
        .context("deployment guard has no control pipe")?;
    let mut readiness = guard
        .stdout
        .take()
        .context("deployment guard has no readiness pipe")?;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut ready = [0_u8; 1];
    let mut ready_read = Box::pin(readiness.read_exact(&mut ready));
    let mut waiting_refresh = tokio::time::interval(std::time::Duration::from_secs(10));
    waiting_refresh.tick().await;
    loop {
        tokio::select! { result = &mut ready_read => { result?; break; }, _ = waiting_refresh.tick() => fence.refresh().await?, }
    }
    drop(ready_read);
    if ready != *b"R" {
        bail!("deployment command guard failed to acquire the mutation fence");
    }
    fence.refresh().await?;
    control.write_all(b"G").await?;
    let mut wait = Box::pin(guard.wait());
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(600));
    tokio::pin!(timeout);
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(10));
    refresh.tick().await;
    let (status, interrupted) = loop {
        tokio::select! {
            status = &mut wait => break (Some(status?), None),
            _ = &mut timeout => break (None, Some("deployment command exceeded the 10 minute timeout".to_string())),
            _ = interrupt.recv() => break (None, Some("deployment command interrupted".to_string())),
            _ = terminate.recv() => break (None, Some("deployment command terminated".to_string())),
            _ = refresh.tick() => if let Err(error) = fence.refresh().await { break (None, Some(format!("deployment command lost its environment fence: {error}"))); }
        }
    };
    if let Some(reason) = interrupted {
        drop(control);
        let _ = wait.await;
        return Ok(Err(reason));
    }
    fence.refresh().await?;
    let status = status.expect("completed command has an exit status");
    Ok(if status.success() {
        Ok(())
    } else {
        Err(format!("deployment command exited with {status}"))
    })
}

pub async fn supervise(mutation: MutationCommand<'_>, generation: u64) -> Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(mutation.lock_path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    std::io::stdout().write_all(b"R")?;
    std::io::stdout().flush()?;
    let mut go = [0_u8; 1];
    std::io::stdin().read_exact(&mut go)?;
    if go != *b"G" {
        bail!("executor guard did not receive start authorization");
    }
    let mut child = tokio::process::Command::new("sh");
    child
        .arg("-c")
        .arg(mutation.command)
        .current_dir(mutation.workdir)
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_deploy_child_env(
        &mut child,
        mutation.environment,
        mutation.product,
        Some(generation),
    );
    child.as_std_mut().process_group(0);
    let mut child = child.spawn().context("spawning deployment command")?;
    let process_group = child.id().context("deployment command has no process id")? as i32;
    let (closed_tx, mut controller_closed) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let result = std::io::stdin().read_to_end(&mut sink);
        let _ = closed_tx.send(result);
    });
    tokio::select! {
        status = child.wait() => { let status = status?; unsafe { libc::kill(-process_group, libc::SIGKILL) }; wait_for_process_group_exit(process_group).await?; if status.success() { Ok(()) } else { bail!("deployment command exited with {status}") } }
        _ = &mut controller_closed => { unsafe { libc::kill(-process_group, libc::SIGKILL) }; let _ = child.wait().await; wait_for_process_group_exit(process_group).await?; bail!("deployment controller exited") }
    }
}

async fn wait_for_process_group_exit(process_group: i32) -> Result<()> {
    loop {
        if unsafe { libc::kill(-process_group, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(error.into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_child_environment_excludes_control_plane_secrets() {
        let keys = [
            ("TENKAI_MANAGEMENT_TOKEN", "mgmt-secret"),
            ("TENKAI_RUNTIME_TOKEN", "runtime-secret"),
            ("TENKAI_RUNTIME_TOKENS", r#"{"t":"prod"}"#),
            ("TENKAI_OUTCOME_PROVIDER_TOKEN", "outcome-secret"),
            ("SEKAI_AUTH_TOKEN", "sekai-secret"),
            ("TENKAI_POSTGRES_URL", "postgres://secret"),
            ("PATH", "/usr/bin:/bin"),
        ];
        let mut previous = Vec::new();
        for (key, value) in keys {
            previous.push((key, std::env::var_os(key)));
            // SAFETY: test-only, single-threaded env mutation around one assertion.
            unsafe { std::env::set_var(key, value) };
        }

        let env = deploy_child_environment("lab", "app", Some(7));
        let env_keys: Vec<String> = env
            .keys()
            .map(|key| key.to_string_lossy().into_owned())
            .collect();

        for forbidden in DEPLOY_CHILD_FORBIDDEN_ENV {
            assert!(
                !env.contains_key(OsStr::new(forbidden)),
                "deploy child env must not contain {forbidden}"
            );
        }
        assert_eq!(
            env.get(OsStr::new("TENKAI_ENVIRONMENT"))
                .map(|value| value.as_os_str()),
            Some(OsStr::new("lab"))
        );
        assert_eq!(
            env.get(OsStr::new("TENKAI_PRODUCT"))
                .map(|value| value.as_os_str()),
            Some(OsStr::new("app"))
        );
        assert_eq!(
            env.get(OsStr::new("TENKAI_FENCING_GENERATION"))
                .map(|value| value.as_os_str()),
            Some(OsStr::new("7"))
        );
        assert!(
            env.contains_key(OsStr::new("PATH")),
            "PATH should remain available for install tools"
        );
        assert!(
            env_keys.iter().all(|key| {
                DEPLOY_CHILD_INHERITED_ENV.contains(&key.as_str())
                    || key == "TENKAI_ENVIRONMENT"
                    || key == "TENKAI_PRODUCT"
                    || key == "TENKAI_FENCING_GENERATION"
                    || key == "COMPOSE_PROJECT_NAME"
            }),
            "unexpected deploy child keys: {env_keys:?}"
        );

        for (key, value) in previous {
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }

    #[tokio::test]
    async fn deploy_shell_child_does_not_inherit_management_or_runtime_tokens() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-deploy-env-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("env.txt");
        let script = format!(
            "env | sort > {}",
            out.to_string_lossy().replace('\'', "'\\''")
        );

        let previous = [
            (
                "TENKAI_MANAGEMENT_TOKEN",
                std::env::var_os("TENKAI_MANAGEMENT_TOKEN"),
            ),
            (
                "TENKAI_RUNTIME_TOKEN",
                std::env::var_os("TENKAI_RUNTIME_TOKEN"),
            ),
            ("SEKAI_AUTH_TOKEN", std::env::var_os("SEKAI_AUTH_TOKEN")),
            (
                "TENKAI_OUTCOME_PROVIDER_TOKEN",
                std::env::var_os("TENKAI_OUTCOME_PROVIDER_TOKEN"),
            ),
        ];
        unsafe {
            std::env::set_var("TENKAI_MANAGEMENT_TOKEN", "mgmt-should-not-leak");
            std::env::set_var("TENKAI_RUNTIME_TOKEN", "runtime-should-not-leak");
            std::env::set_var("SEKAI_AUTH_TOKEN", "sekai-should-not-leak");
            std::env::set_var("TENKAI_OUTCOME_PROVIDER_TOKEN", "outcome-should-not-leak");
        }

        let mut child = tokio::process::Command::new("sh");
        child.arg("-c").arg(&script).current_dir(&dir);
        configure_deploy_child_env(&mut child, "lab", "app", Some(3));
        let status = child.status().await.unwrap();
        assert!(status.success());

        let dumped = std::fs::read_to_string(&out).unwrap();
        for forbidden in [
            "TENKAI_MANAGEMENT_TOKEN=",
            "TENKAI_RUNTIME_TOKEN=",
            "SEKAI_AUTH_TOKEN=",
            "TENKAI_OUTCOME_PROVIDER_TOKEN=",
            "mgmt-should-not-leak",
            "runtime-should-not-leak",
            "sekai-should-not-leak",
            "outcome-should-not-leak",
        ] {
            assert!(
                !dumped.contains(forbidden),
                "child env dump unexpectedly contained {forbidden}: {dumped}"
            );
        }
        assert!(dumped.contains("TENKAI_ENVIRONMENT=lab"));
        assert!(dumped.contains("TENKAI_PRODUCT=app"));
        assert!(dumped.contains("TENKAI_FENCING_GENERATION=3"));

        for (key, value) in previous {
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

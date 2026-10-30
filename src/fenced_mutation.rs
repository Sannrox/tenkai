//! Generation-fenced local mutation supervision.
//!
//! This deep module owns executor-guard discovery, the controller/guard pipe
//! protocol, mutation locking, process-group cleanup, signals, and timeouts.
//! Callers retain lease ownership and expose only refresh plus generation.

use std::collections::BTreeMap;
use std::ffi::OsString;
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

/// POSIX shell that runs `deploy.install`, health, and uninstall.
///
/// Absolute `/bin/sh` so a `sh` from PATH (wrappers, store links, a workdir
/// named `sh`) cannot fail the deploy after the child environment is scrubbed
/// (#794). Install tools still use the allowlisted `PATH`.
pub(crate) const DEPLOY_SHELL: &str = "/bin/sh";

/// Parent-process variables that may be inherited by deploy children.
///
/// Control-plane credentials (`TENKAI_MANAGEMENT_TOKEN`, `TENKAI_RUNTIME_TOKEN`,
/// outcome-provider and feedback-provider tokens, `SEKAI_AUTH_TOKEN`, and similar) are intentionally
/// absent. Deploy shells receive only this allowlist plus the explicit Tenkai
/// fencing/identity variables set by [`deploy_child_environment`].
const DEPLOY_CHILD_INHERITED_ENV: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "TZ",
];

/// Resolve the `tenkai-executor-guard` that fences shell-executor deploys.
///
/// `TENKAI_EXECUTOR_GUARD` wins; otherwise `tenkaictl` guards itself and other
/// hosts look for `tenkai-executor-guard` beside their own binary or one
/// directory up. Hosts call this at startup to advertise the shell executor.
pub fn executor_guard_executable() -> Result<PathBuf> {
    if let Some(configured) = std::env::var_os("TENKAI_EXECUTOR_GUARD") {
        let configured = PathBuf::from(configured);
        if is_executable_file(&configured) {
            return Ok(configured);
        }
        bail!(
            "TENKAI_EXECUTOR_GUARD does not identify an executable file: {}",
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
    let mut candidates = Vec::new();
    for directory in current.ancestors().skip(1).take(3) {
        candidates.push(directory.join("tenkai-executor-guard"));
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        candidates.push(
            PathBuf::from(target_dir)
                .join(profile)
                .join("tenkai-executor-guard"),
        );
    }
    for candidate in candidates {
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }
    bail!(
        "tenkai-executor-guard was not found beside {}; install both Tenkai binaries or set TENKAI_EXECUTOR_GUARD",
        current.display()
    )
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
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
    deploy_child_environment_from(environment, product, fencing_generation, |key| {
        std::env::var_os(key)
    })
}

/// [`deploy_child_environment`] with an explicit parent-environment lookup.
fn deploy_child_environment_from(
    environment: &str,
    product: &str,
    fencing_generation: Option<u64>,
    parent: impl Fn(&str) -> Option<OsString>,
) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    for key in DEPLOY_CHILD_INHERITED_ENV {
        if let Some(value) = parent(key) {
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
        .stderr(Stdio::piped());
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
    let guard_stderr = guard.stderr.take();
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
    enum Stop {
        Interrupted(String),
        FenceLost(anyhow::Error),
    }
    let (status, stop) = loop {
        tokio::select! {
            status = &mut wait => break (Some(status?), None),
            _ = &mut timeout => break (None, Some(Stop::Interrupted(
                "deployment command exceeded the 10 minute timeout".into(),
            ))),
            _ = interrupt.recv() => break (None, Some(Stop::Interrupted(
                "deployment command interrupted".into(),
            ))),
            _ = terminate.recv() => break (None, Some(Stop::Interrupted(
                "deployment command terminated".into(),
            ))),
            _ = refresh.tick() => {
                if let Err(error) = fence.refresh().await {
                    break (None, Some(Stop::FenceLost(error)));
                }
            }
        }
    };
    if let Some(stop) = stop {
        drop(control);
        let _ = wait.await;
        return match stop {
            Stop::Interrupted(reason) => Ok(Err(reason)),
            Stop::FenceLost(error) => Err(error),
        };
    }
    fence.refresh().await?;
    let status = status.expect("completed command has an exit status");
    if status.success() {
        return Ok(Ok(()));
    }
    // Guard failures write a reason here; a failed deploy command copies a
    // bounded, credential-free stderr snippet the same way (#794).
    let mut reason = String::new();
    if let Some(stderr) = guard_stderr {
        let _ = stderr.take(4096).read_to_string(&mut reason).await;
    }
    let reason = crate::software_executor::sanitize_diagnostic_text(reason.trim());
    Ok(Err(
        if let Some(detail) = reason.strip_prefix(GUARD_FAILED_PREFIX) {
            format!("deployment command guard failed: {detail}")
        } else if !reason.is_empty() {
            format!("deployment command exited with {status}: {reason}")
        } else {
            format!("deployment command exited with {status}")
        },
    ))
}

/// Run in-process `work` while holding the mutation lock, the same flock the
/// executor guard takes for shell commands. Callers refresh their generation
/// fence before and after, exactly as [`run`] does around a supervised shell.
///
/// The outer error is a lock failure; the inner result is `work`'s own, so
/// callers can keep control failures distinct from target failures.
pub fn with_mutation_lock<T>(
    lock_path: &Path,
    work: impl FnOnce() -> Result<T>,
) -> Result<Result<T>> {
    with_mutation_lock_authorized(lock_path, || Ok(()), work)
}

/// [`with_mutation_lock`] with a post-acquisition authorization handshake:
/// `authorize` runs after the lock is held and before `work`; when it fails,
/// `work` never runs. This mirrors the shell guard's ready/go exchange, so a
/// waiter that lost its fence while queued on the lock cannot mutate.
pub fn with_mutation_lock_authorized<T>(
    lock_path: &Path,
    authorize: impl FnOnce() -> Result<()>,
    work: impl FnOnce() -> Result<T>,
) -> Result<Result<T>> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Authorization is checked only once the lock is held; a failed check
    // releases the lock (on drop) without running the mutation.
    authorize()?;
    let result = work();
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
        let unlock = std::io::Error::last_os_error();
        return match result {
            Ok(value) => Ok(Ok(value)),
            Err(error) => {
                Err(error.context(format!("releasing mutation lock also failed: {unlock}")))
            }
        };
    }
    Ok(result)
}

/// Exit code of a guard that failed itself, as distinct from the deployment
/// command's own status. The guard writes [`GUARD_FAILED_PREFIX`] plus the
/// reason to stderr (#794). A command that exits 125 is not this case.
pub const GUARD_FAILED_EXIT: u8 = 125;

/// Stderr stamp so a command that exits 125 cannot look like a guard failure.
const GUARD_FAILED_PREFIX: &str = "tenkai-executor-guard: ";

/// A guard process's whole job: run [`supervise`] and return the exit code,
/// the deployment command's own status or [`GUARD_FAILED_EXIT`].
pub async fn guard(mutation: MutationCommand<'_>, generation: u64) -> u8 {
    use std::os::unix::process::ExitStatusExt as _;
    match supervise(mutation, generation).await {
        Ok(status) => match (status.code(), status.signal()) {
            (Some(code), _) => u8::try_from(code).unwrap_or(1),
            (None, Some(signal)) => u8::try_from(128 + signal).unwrap_or(1),
            (None, None) => 1,
        },
        Err(error) => {
            // One line: the controller reports it as the step's failure.
            eprintln!(
                "{GUARD_FAILED_PREFIX}{}",
                format!("{error:#}").replace('\n', " ")
            );
            GUARD_FAILED_EXIT
        }
    }
}

/// Take the mutation lock, wait for the controller's go, and run the
/// deployment command, returning its exit status. An error is the guard's
/// own failure, never the command's.
pub async fn supervise(
    mutation: MutationCommand<'_>,
    generation: u64,
) -> Result<std::process::ExitStatus> {
    use tokio::io::AsyncReadExt as _;

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
    let mut child = tokio::process::Command::new(DEPLOY_SHELL);
    child
        .arg("-c")
        .arg(mutation.command)
        .current_dir(mutation.workdir)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    configure_deploy_child_env(
        &mut child,
        mutation.environment,
        mutation.product,
        Some(generation),
    );
    child.as_std_mut().process_group(0);
    let mut child = child.spawn().context("spawning deployment command")?;
    let process_group = child.id().context("deployment command has no process id")? as i32;
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let drain = tokio::spawn({
        let captured = captured.clone();
        let mut pipe = child.stderr.take();
        async move {
            let Some(ref mut pipe) = pipe else {
                return;
            };
            let mut buf = [0_u8; 256];
            loop {
                match pipe.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut held = captured.lock().unwrap_or_else(|error| error.into_inner());
                        if held.len() < 4_096 {
                            let take = n.min(4_096 - held.len());
                            held.extend_from_slice(&buf[..take]);
                        }
                    }
                }
            }
        }
    });
    let (closed_tx, mut controller_closed) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let result = std::io::stdin().read_to_end(&mut sink);
        let _ = closed_tx.send(result);
    });
    let status = tokio::select! {
        biased;
        status = child.wait() => status?,
        _ = &mut controller_closed => {
            drain.abort();
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
            let _ = child.wait().await;
            wait_for_process_group_exit(process_group).await?;
            bail!("deployment controller exited");
        }
    };
    // Copy remaining bytes, but do not wait for a descendant that left the
    // process group and still holds the write end.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(50), drain).await;
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    wait_for_process_group_exit(process_group).await?;
    let stderr_buf = captured
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr_buf);
        let detail = crate::software_executor::sanitize_diagnostic_text(detail.trim());
        if !detail.is_empty() {
            eprintln!("{detail}");
        }
    }
    Ok(status)
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
    use std::ffi::OsStr;

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
        "TENKAI_FEEDBACK_PROVIDER_TOKEN",
        "TENKAI_FEEDBACK_PROVIDER_URL",
        "TENKAI_FEEDBACK_PROVIDER_PRINCIPAL",
        "TENKAI_FEEDBACK_PROVIDER_REGISTRATION",
        "TENKAI_JWT_VERIFIER_CONFIG",
        "TENKAI_POSTGRES_URL",
        "TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS",
    ];

    #[test]
    fn deploy_child_environment_excludes_control_plane_secrets() {
        let keys = [
            ("TENKAI_MANAGEMENT_TOKEN", "mgmt-secret"),
            ("TENKAI_RUNTIME_TOKEN", "runtime-secret"),
            ("TENKAI_RUNTIME_TOKENS", r#"{"t":"prod"}"#),
            ("TENKAI_OUTCOME_PROVIDER_TOKEN", "outcome-secret"),
            ("TENKAI_FEEDBACK_PROVIDER_TOKEN", "feedback-secret"),
            ("SEKAI_AUTH_TOKEN", "sekai-secret"),
            ("TENKAI_POSTGRES_URL", "postgres://secret"),
            ("PATH", "/usr/bin:/bin"),
        ];
        let parent: BTreeMap<&str, &str> = keys.into_iter().collect();
        let env = deploy_child_environment_from("lab", "app", Some(7), |key| {
            parent.get(key).map(OsString::from)
        });
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

        // Secrets are placed on the command rather than the test process, so
        // parallel tests never observe them; env_clear must drop both.
        let mut child = tokio::process::Command::new("sh");
        child
            .arg("-c")
            .arg(&script)
            .current_dir(&dir)
            .env("TENKAI_MANAGEMENT_TOKEN", "mgmt-should-not-leak")
            .env("TENKAI_RUNTIME_TOKEN", "runtime-should-not-leak")
            .env("SEKAI_AUTH_TOKEN", "sekai-should-not-leak")
            .env("TENKAI_OUTCOME_PROVIDER_TOKEN", "outcome-should-not-leak")
            .env("TENKAI_FEEDBACK_PROVIDER_TOKEN", "feedback-should-not-leak");
        configure_deploy_child_env(&mut child, "lab", "app", Some(3));
        let status = child.status().await.unwrap();
        assert!(status.success());

        let dumped = std::fs::read_to_string(&out).unwrap();
        for forbidden in [
            "TENKAI_MANAGEMENT_TOKEN=",
            "TENKAI_RUNTIME_TOKEN=",
            "SEKAI_AUTH_TOKEN=",
            "TENKAI_OUTCOME_PROVIDER_TOKEN=",
            "TENKAI_FEEDBACK_PROVIDER_TOKEN=",
            "mgmt-should-not-leak",
            "runtime-should-not-leak",
            "sekai-should-not-leak",
            "outcome-should-not-leak",
            "feedback-should-not-leak",
        ] {
            assert!(
                !dumped.contains(forbidden),
                "child env dump unexpectedly contained {forbidden}: {dumped}"
            );
        }
        assert!(dumped.contains("TENKAI_ENVIRONMENT=lab"));
        assert!(dumped.contains("TENKAI_PRODUCT=app"));
        assert!(dumped.contains("TENKAI_FENCING_GENERATION=3"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct StaticFence;

    impl MutationFence for StaticFence {
        fn generation(&self) -> u64 {
            1
        }

        fn refresh(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// The command's own exit status survives the guard, and a guard that
    /// fails itself says so instead of posing as the command (#794).
    #[tokio::test]
    async fn command_status_survives_and_guard_failure_names_itself() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-guard-status-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let lock_path = dir.join("mutation.lock");
        let command = |workdir: &Path, command: &str| {
            let workdir = workdir.to_path_buf();
            let command = command.to_string();
            let lock_path = lock_path.clone();
            async move {
                run(
                    &mut StaticFence,
                    MutationCommand {
                        lock_path: &lock_path,
                        workdir: &workdir,
                        environment: "lab",
                        product: "app",
                        command: &command,
                    },
                )
                .await
                .unwrap()
            }
        };

        assert_eq!(command(&dir, "true").await, Ok(()));
        assert_eq!(
            command(&dir, "exit 3").await,
            Err("deployment command exited with exit status: 3".into())
        );
        let named = command(&dir, "echo \"$0\" >&2; exit 1").await.unwrap_err();
        assert!(
            named.starts_with("deployment command exited with exit status: 1: "),
            "{named}"
        );
        assert!(
            named.contains(DEPLOY_SHELL),
            "deploy shell should be {DEPLOY_SHELL}, got {named}"
        );
        let leaked = command(
            &dir,
            "echo postgres://app:s3cret@db.internal/tenkai >&2; exit 1",
        )
        .await
        .unwrap_err();
        assert!(
            leaked.starts_with("deployment command exited with exit status: 1: "),
            "{leaked}"
        );
        assert!(!leaked.contains("s3cret"), "{leaked}");
        let docker_client = command(&dir, "echo client-daemon-error >&2; exit 125")
            .await
            .unwrap_err();
        assert!(
            docker_client.contains("deployment command exited with exit status: 125"),
            "{docker_client}"
        );
        assert!(!docker_client.contains("guard failed"), "{docker_client}");
        let missing = command(&dir.join("absent"), "true").await.unwrap_err();
        assert!(
            missing.starts_with("deployment command guard failed: spawning deployment command"),
            "{missing}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn denied_authorization_never_runs_guarded_work() {
        let dir = std::env::temp_dir().join(format!("tenkai-mutation-auth-{}", std::process::id()));
        let lock_path = dir.join("mutation.lock");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let result = with_mutation_lock_authorized(
            &lock_path,
            || anyhow::bail!("fence lost while queued"),
            move || {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(result.is_err(), "denied authorization must fail the guard");
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "guarded work ran without authorization"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mutation_lock_excludes_a_second_holder_while_work_runs() {
        let dir = std::env::temp_dir().join(format!("tenkai-mutation-lock-{}", std::process::id()));
        let lock_path = dir.join("mutation.lock");
        let probe_path = lock_path.clone();
        let observed =
            with_mutation_lock(&lock_path, move || {
                // A second open of the same lock must not acquire it while held.
                let second = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&probe_path)?;
                let rc = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                Ok(rc != 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK))
            })
            .unwrap()
            .unwrap();
        assert!(observed, "mutation lock was not held during guarded work");
        // After release the lock is free again.
        let third = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        let rc = unsafe { libc::flock(third.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "mutation lock stayed held after guarded work");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

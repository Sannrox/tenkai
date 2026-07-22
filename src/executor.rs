//! Typed deployment execution contract.

use std::future::Future;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;

use crate::plan::Action;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    Interrupt,
    Terminate,
}

#[derive(Debug, Clone, Default)]
pub struct Cancellation {
    signal: Arc<AtomicU8>,
}

impl Cancellation {
    pub fn cancel(&self, reason: CancelReason) {
        let signal = match reason {
            CancelReason::Interrupt => 1,
            CancelReason::Terminate => 2,
        };
        self.signal.store(signal, Ordering::SeqCst);
    }

    pub fn reason(&self) -> Option<&'static str> {
        self.cancel_reason().map(|reason| match reason {
            CancelReason::Interrupt => "deployment apply interrupted",
            CancelReason::Terminate => "deployment apply terminated",
        })
    }

    pub fn cancel_reason(&self) -> Option<CancelReason> {
        match self.signal.load(Ordering::SeqCst) {
            1 => Some(CancelReason::Interrupt),
            2 => Some(CancelReason::Terminate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutorKind {
    #[default]
    LocalShell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorInput {
    pub step_id: String,
    pub action: Action,
    pub environment: String,
    pub product: String,
    pub from_version: Option<String>,
    pub to_version: String,
    pub release_id: String,
    pub workdir: PathBuf,
    pub install: String,
    pub uninstall: Option<String>,
    pub health: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorObservationInput {
    pub environment: String,
    pub product: String,
    pub expected_version: String,
    pub workdir: PathBuf,
    pub observe: Option<String>,
    pub health: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedHealth {
    Healthy,
    Unhealthy,
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorObservation {
    pub installed_version: Option<String>,
    pub health: ObservedHealth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorObservationResult {
    pub observation: Option<ExecutorObservation>,
    pub detail: String,
}

impl ExecutorObservationResult {
    pub fn observed(installed_version: Option<String>, health: ObservedHealth) -> Self {
        Self {
            observation: Some(ExecutorObservation {
                installed_version,
                health,
            }),
            detail: String::new(),
        }
    }

    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            observation: None,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorPhase {
    Install,
    Uninstall,
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorFailureKind {
    Command,
    Infrastructure,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorResult {
    pub phase: ExecutorPhase,
    pub succeeded: bool,
    pub started: bool,
    pub detail: String,
    pub failure_kind: Option<ExecutorFailureKind>,
}

impl ExecutorResult {
    pub fn succeeded(phase: ExecutorPhase) -> Self {
        Self {
            phase,
            succeeded: true,
            started: true,
            detail: String::new(),
            failure_kind: None,
        }
    }

    pub fn failed(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            started: true,
            detail: detail.into(),
            failure_kind: Some(ExecutorFailureKind::Command),
        }
    }

    pub fn not_started(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            started: false,
            detail: detail.into(),
            failure_kind: Some(ExecutorFailureKind::Infrastructure),
        }
    }

    pub fn interrupted(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            started: true,
            detail: detail.into(),
            failure_kind: Some(ExecutorFailureKind::Interrupted),
        }
    }

    pub fn infrastructure_failed(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            started: true,
            detail: detail.into(),
            failure_kind: Some(ExecutorFailureKind::Infrastructure),
        }
    }
}

pub type ExecutorFuture<'a> = Pin<Box<dyn Future<Output = ExecutorResult> + Send + 'a>>;
pub type ExecutorObservationFuture<'a> =
    Pin<Box<dyn Future<Output = ExecutorObservationResult> + Send + 'a>>;

pub trait Executor: Send + Sync {
    fn observe<'a>(
        &'a self,
        _input: &'a ExecutorObservationInput,
        _cancellation: &'a Cancellation,
    ) -> ExecutorObservationFuture<'a> {
        Box::pin(async {
            ExecutorObservationResult::failed("executor does not support observation")
        })
    }

    fn activate<'a>(
        &'a self,
        input: &'a ExecutorInput,
        cancellation: &'a Cancellation,
    ) -> ExecutorFuture<'a>;

    fn deactivate<'a>(
        &'a self,
        input: &'a ExecutorInput,
        cancellation: &'a Cancellation,
    ) -> ExecutorFuture<'a>;
}

pub struct LocalShellExecutor;

const WATCHDOG_WRAPPER: &str = r#"
controller=$1
payload=$2
group=$$
(
  while kill -0 "$controller" 2>/dev/null && kill -0 "$group" 2>/dev/null; do sleep 0.1; done
  kill -KILL "-$group" 2>/dev/null
) &
watchdog=$!
# POSIX shells may attach /dev/null to an asynchronous command when job
# control is disabled. Duplicate the wrapper's stdin first and explicitly
# restore it for the payload so legacy commands can still consume piped input.
exec 3<&0
sh -c "$payload" <&3 &
child=$!
exec 3<&-
wait "$child"
status=$?
kill "$watchdog" 2>/dev/null
wait "$watchdog" 2>/dev/null
exit "$status"
"#;

fn command_with_parent_watchdog(command_text: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("sh");
    command
        .arg("-c")
        .arg(WATCHDOG_WRAPPER)
        .arg("tenkai-watchdog")
        .arg(std::process::id().to_string())
        .arg(command_text);
    command
}

impl LocalShellExecutor {
    async fn observe_version(
        &self,
        input: &ExecutorObservationInput,
        command_text: &str,
        cancellation: &Cancellation,
    ) -> Result<Option<String>, String> {
        if let Some(reason) = cancellation.reason() {
            return Err(reason.into());
        }
        let identity_digest =
            crate::manifest::digest(&format!("{}\0{}", input.environment, input.product));
        let mut command = command_with_parent_watchdog(command_text);
        command
            .current_dir(&input.workdir)
            .kill_on_drop(true)
            .env_remove("SEKAI_AUTH_TOKEN")
            .env("TENKAI_ENVIRONMENT", &input.environment)
            .env("TENKAI_PRODUCT", &input.product)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("tenkai-{}", &identity_digest[..16]),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command.as_std_mut().process_group(0);
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawning observation command failed: {error}"))?;
        let process_group = child.id().map(|id| -(id as i32));
        let stdout = child.stdout.take().expect("observation stdout is piped");
        let mut output = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stdout
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .await
                .map(|_| bytes)
        });
        let mut wait = Box::pin(child.wait());
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(input.timeout_seconds));
        let cancelled = async {
            loop {
                if let Some(reason) = cancellation.reason() {
                    break reason;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        };
        tokio::pin!(timeout);
        tokio::pin!(cancelled);
        let mut status = None;
        let mut bytes = None;
        let interrupted = loop {
            tokio::select! {
                result = &mut wait, if status.is_none() => {
                    status = Some(result.map_err(|error| format!("waiting for observation command failed: {error}")));
                }
                result = &mut output, if bytes.is_none() => {
                    bytes = Some(
                        result
                            .map_err(|error| format!("collecting observation output failed: {error}"))
                            .and_then(|result| result.map_err(|error| format!("reading observation output failed: {error}")))
                    );
                }
                _ = &mut timeout => break Some(format!(
                    "observation command exceeded its {} second timeout",
                    input.timeout_seconds
                )),
                reason = &mut cancelled => break Some(reason.into()),
            }
            if status.is_some() && bytes.is_some() {
                break None;
            }
        };
        if let Some(reason) = interrupted {
            if let Some(process_group) = process_group {
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
            }
            if status.is_none() {
                let _ = wait.await;
            }
            if bytes.is_none() {
                output.abort();
            }
            return Err(reason);
        }
        let status = status.expect("completed observation status")?;
        let bytes = bytes.expect("completed observation output")?;
        if bytes.len() > 64 * 1024 {
            return Err("observation command output exceeded 64 KiB".into());
        }
        if status.code() == Some(3) {
            return Ok(None);
        }
        if !status.success() {
            return Err(format!("observation command exited with {status}"));
        }
        let version = std::str::from_utf8(&bytes)
            .map_err(|_| "observation command output is not UTF-8")?
            .trim();
        if version.is_empty() {
            return Err("observation command returned an empty installed version".into());
        }
        crate::manifest::validate_version(version)
            .map_err(|_| "observation command returned an invalid semantic version")?;
        Ok(Some(version.into()))
    }

    async fn run_command(
        &self,
        input: &ExecutorInput,
        phase: ExecutorPhase,
        command_text: &str,
        cancellation: &Cancellation,
    ) -> ExecutorResult {
        if let Some(reason) = cancellation.reason() {
            return ExecutorResult::not_started(phase, reason);
        }
        let identity_digest =
            crate::manifest::digest(&format!("{}\0{}", input.environment, input.product));
        let compose_project = format!("tenkai-{}", &identity_digest[..16]);
        let mut command = command_with_parent_watchdog(command_text);
        command
            .current_dir(&input.workdir)
            .kill_on_drop(true)
            .env_remove("SEKAI_AUTH_TOKEN")
            .env("TENKAI_ENVIRONMENT", &input.environment)
            .env("TENKAI_PRODUCT", &input.product)
            .env("COMPOSE_PROJECT_NAME", compose_project)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.as_std_mut().process_group(0);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return ExecutorResult::not_started(
                    phase,
                    format!("spawning deployment command failed: {error}"),
                );
            }
        };
        let process_group = child.id().map(|id| -(id as i32));
        let mut wait = Box::pin(child.wait());
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(input.timeout_seconds));
        let cancelled = async {
            loop {
                if let Some(reason) = cancellation.reason() {
                    break reason;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        };
        tokio::pin!(timeout);
        tokio::pin!(cancelled);
        let (status, interrupted) = tokio::select! {
            status = &mut wait => (status, None),
            _ = &mut timeout => (Ok(Default::default()), Some((format!("deployment command exceeded its {} second timeout", input.timeout_seconds), ExecutorFailureKind::Infrastructure))),
            reason = &mut cancelled => (Ok(Default::default()), Some((reason.into(), ExecutorFailureKind::Interrupted))),
        };
        if let Some((reason, failure_kind)) = interrupted {
            if let Some(process_group) = process_group {
                // The shell is the process-group leader; a negative PID kills the full tree.
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
            }
            let _ = wait.await;
            return match failure_kind {
                ExecutorFailureKind::Infrastructure => {
                    ExecutorResult::infrastructure_failed(phase, reason)
                }
                ExecutorFailureKind::Interrupted => ExecutorResult::interrupted(phase, reason),
                ExecutorFailureKind::Command => unreachable!(),
            };
        }
        match status {
            Ok(status) if status.success() => ExecutorResult::succeeded(phase),
            Ok(status) => {
                ExecutorResult::failed(phase, format!("deployment command exited with {status}"))
            }
            Err(error) => ExecutorResult::infrastructure_failed(
                phase,
                format!("waiting for deployment command failed: {error}"),
            ),
        }
    }
}

impl Executor for LocalShellExecutor {
    fn observe<'a>(
        &'a self,
        input: &'a ExecutorObservationInput,
        cancellation: &'a Cancellation,
    ) -> ExecutorObservationFuture<'a> {
        Box::pin(async move {
            let Some(command) = input
                .observe
                .as_deref()
                .filter(|command| !command.is_empty())
            else {
                return ExecutorObservationResult::failed("release has no observation command");
            };
            let installed_version = match self.observe_version(input, command, cancellation).await {
                Ok(version) => version,
                Err(detail) => return ExecutorObservationResult::failed(detail),
            };
            let Some(_) = installed_version else {
                return ExecutorObservationResult::observed(None, ObservedHealth::NotChecked);
            };
            if installed_version.as_deref() != Some(input.expected_version.as_str()) {
                return ExecutorObservationResult::observed(
                    installed_version,
                    ObservedHealth::NotChecked,
                );
            }
            let Some(health) = input
                .health
                .as_deref()
                .filter(|command| !command.is_empty())
            else {
                return ExecutorObservationResult::observed(
                    installed_version,
                    ObservedHealth::NotChecked,
                );
            };
            let execution_input = ExecutorInput {
                step_id: "observation".into(),
                action: Action::Install,
                environment: input.environment.clone(),
                product: input.product.clone(),
                from_version: None,
                to_version: installed_version.clone().unwrap_or_default(),
                release_id: String::new(),
                workdir: input.workdir.clone(),
                install: String::new(),
                uninstall: None,
                health: None,
                timeout_seconds: input.timeout_seconds,
            };
            let health = self
                .run_command(
                    &execution_input,
                    ExecutorPhase::Health,
                    health,
                    cancellation,
                )
                .await;
            match health.failure_kind {
                None => {
                    ExecutorObservationResult::observed(installed_version, ObservedHealth::Healthy)
                }
                Some(ExecutorFailureKind::Command) => ExecutorObservationResult::observed(
                    installed_version,
                    ObservedHealth::Unhealthy,
                ),
                Some(ExecutorFailureKind::Infrastructure | ExecutorFailureKind::Interrupted) => {
                    ExecutorObservationResult::failed(health.detail)
                }
            }
        })
    }

    fn activate<'a>(
        &'a self,
        input: &'a ExecutorInput,
        cancellation: &'a Cancellation,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move {
            let install = self
                .run_command(input, ExecutorPhase::Install, &input.install, cancellation)
                .await;
            if !install.succeeded {
                return install;
            }
            match input
                .health
                .as_deref()
                .filter(|command| !command.is_empty())
            {
                Some(command) => {
                    let mut health = self
                        .run_command(input, ExecutorPhase::Health, command, cancellation)
                        .await;
                    health.started |= install.started;
                    health
                }
                None => install,
            }
        })
    }

    fn deactivate<'a>(
        &'a self,
        input: &'a ExecutorInput,
        cancellation: &'a Cancellation,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move {
            match input
                .uninstall
                .as_deref()
                .filter(|command| !command.is_empty())
            {
                Some(command) => {
                    self.run_command(input, ExecutorPhase::Uninstall, command, cancellation)
                        .await
                }
                None => ExecutorResult::not_started(
                    ExecutorPhase::Uninstall,
                    "release has no uninstall command",
                ),
            }
        })
    }
}

static LOCAL_SHELL_EXECUTOR: LocalShellExecutor = LocalShellExecutor;

pub fn select(kind: ExecutorKind) -> &'static dyn Executor {
    match kind {
        ExecutorKind::LocalShell => &LOCAL_SHELL_EXECUTOR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Selection {
        executor: ExecutorKind,
    }

    #[test]
    fn executor_kind_uses_stable_manifest_name() {
        let selection = Selection {
            executor: ExecutorKind::LocalShell,
        };
        assert_eq!(
            toml::to_string(&selection).unwrap(),
            "executor = \"local-shell\"\n"
        );
        assert_eq!(
            toml::from_str::<Selection>("executor = \"local-shell\"").unwrap(),
            selection
        );
    }

    fn input(workdir: PathBuf) -> ExecutorInput {
        ExecutorInput {
            step_id: "plan:step:0".into(),
            action: Action::Install,
            environment: "test".into(),
            product: "api".into(),
            from_version: None,
            to_version: "1.0.0".into(),
            release_id: "release:api:1.0.0".into(),
            workdir,
            install: "touch installed".into(),
            uninstall: Some("touch uninstalled".into()),
            health: Some("test -f healthy".into()),
            timeout_seconds: 600,
        }
    }

    fn observation_input(workdir: PathBuf, observe: &str) -> ExecutorObservationInput {
        ExecutorObservationInput {
            environment: "test".into(),
            product: "api".into(),
            expected_version: "1.2.3".into(),
            workdir,
            observe: Some(observe.into()),
            health: Some("test -f healthy".into()),
            timeout_seconds: 600,
        }
    }

    #[tokio::test]
    async fn local_shell_observes_version_and_health() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-observe-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::write(workdir.join("healthy"), "").unwrap();

        let result = LocalShellExecutor
            .observe(
                &observation_input(workdir.clone(), "printf '1.2.3\\n'"),
                &Cancellation::default(),
            )
            .await;

        assert_eq!(
            result,
            ExecutorObservationResult::observed(Some("1.2.3".into()), ObservedHealth::Healthy)
        );
        std::fs::remove_dir_all(workdir).unwrap();
    }

    #[tokio::test]
    async fn local_shell_distinguishes_absence_from_observation_failure() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-absent-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();

        let absent = LocalShellExecutor
            .observe(
                &observation_input(workdir.clone(), "exit 3"),
                &Cancellation::default(),
            )
            .await;
        let failed = LocalShellExecutor
            .observe(
                &observation_input(workdir.clone(), "exit 1"),
                &Cancellation::default(),
            )
            .await;

        assert_eq!(
            absent,
            ExecutorObservationResult::observed(None, ObservedHealth::NotChecked)
        );
        assert!(failed.observation.is_none());
        assert!(failed.detail.contains("exited"));
        std::fs::remove_dir_all(workdir).unwrap();
    }

    #[tokio::test]
    async fn local_shell_times_out_when_background_process_holds_stdout() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-observe-timeout-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let mut input = observation_input(workdir.clone(), "printf '1.2.3\\n'; sleep 60 &");
        input.timeout_seconds = 1;

        let result = LocalShellExecutor
            .observe(&input, &Cancellation::default())
            .await;

        assert!(result.observation.is_none());
        assert!(result.detail.contains("exceeded"));
        std::fs::remove_dir_all(workdir).unwrap();
    }

    #[tokio::test]
    async fn local_shell_does_not_report_health_timeout_as_unhealthy() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-health-timeout-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let mut input = observation_input(workdir.clone(), "printf '1.2.3\\n'");
        input.health = Some("sleep 60".into());
        input.timeout_seconds = 1;

        let result = LocalShellExecutor
            .observe(&input, &Cancellation::default())
            .await;

        assert!(result.observation.is_none());
        assert!(result.detail.contains("exceeded"));
        std::fs::remove_dir_all(workdir).unwrap();
    }

    #[tokio::test]
    async fn local_shell_returns_structured_health_failure() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-health-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let result = LocalShellExecutor
            .activate(&input(workdir.clone()), &Cancellation::default())
            .await;

        assert_eq!(result.phase, ExecutorPhase::Health);
        assert!(!result.succeeded);
        assert!(result.detail.contains("deployment command exited"));
        assert!(workdir.join("installed").exists());
        std::fs::remove_dir_all(workdir).unwrap();
    }

    #[tokio::test]
    async fn local_shell_runs_uninstall_command() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-uninstall-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let result = LocalShellExecutor
            .deactivate(&input(workdir.clone()), &Cancellation::default())
            .await;

        assert_eq!(result, ExecutorResult::succeeded(ExecutorPhase::Uninstall));
        assert!(workdir.join("uninstalled").exists());
        std::fs::remove_dir_all(workdir).unwrap();
    }

    #[tokio::test]
    async fn local_shell_does_not_start_after_cancellation() {
        let workdir = std::env::temp_dir().join(format!(
            "tenkai-executor-cancelled-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let cancellation = Cancellation::default();
        cancellation.cancel(CancelReason::Interrupt);

        let result = LocalShellExecutor
            .activate(&input(workdir.clone()), &cancellation)
            .await;

        assert!(!result.succeeded);
        assert!(!result.started);
        assert!(result.detail.contains("interrupted"));
        assert!(!workdir.join("installed").exists());
        std::fs::remove_dir_all(workdir).unwrap();
    }
}

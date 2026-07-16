//! Typed deployment execution contract.

use std::future::Future;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};

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
        match self.signal.load(Ordering::SeqCst) {
            1 => Some("deployment apply interrupted"),
            2 => Some("deployment apply terminated"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorPhase {
    Install,
    Uninstall,
    Health,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorResult {
    pub phase: ExecutorPhase,
    pub succeeded: bool,
    pub started: bool,
    pub detail: String,
}

impl ExecutorResult {
    pub fn succeeded(phase: ExecutorPhase) -> Self {
        Self {
            phase,
            succeeded: true,
            started: true,
            detail: String::new(),
        }
    }

    pub fn failed(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            started: true,
            detail: detail.into(),
        }
    }

    pub fn not_started(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            started: false,
            detail: detail.into(),
        }
    }
}

pub type ExecutorFuture<'a> = Pin<Box<dyn Future<Output = ExecutorResult> + Send + 'a>>;

pub trait Executor: Send + Sync {
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

impl LocalShellExecutor {
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
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(command_text)
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
            _ = &mut timeout => (Ok(Default::default()), Some(format!("deployment command exceeded its {} second timeout", input.timeout_seconds))),
            reason = &mut cancelled => (Ok(Default::default()), Some(reason.into())),
        };
        if let Some(reason) = interrupted {
            if let Some(process_group) = process_group {
                // The shell is the process-group leader; a negative PID kills the full tree.
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
            }
            let _ = wait.await;
            return ExecutorResult::failed(phase, reason);
        }
        match status {
            Ok(status) if status.success() => ExecutorResult::succeeded(phase),
            Ok(status) => {
                ExecutorResult::failed(phase, format!("deployment command exited with {status}"))
            }
            Err(error) => ExecutorResult::failed(
                phase,
                format!("waiting for deployment command failed: {error}"),
            ),
        }
    }
}

impl Executor for LocalShellExecutor {
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

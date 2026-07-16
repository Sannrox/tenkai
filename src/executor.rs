//! Typed deployment execution contract.

use std::future::Future;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use serde::{Deserialize, Serialize};

use crate::plan::Action;

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
    pub detail: String,
}

impl ExecutorResult {
    pub fn succeeded(phase: ExecutorPhase) -> Self {
        Self {
            phase,
            succeeded: true,
            detail: String::new(),
        }
    }

    pub fn failed(phase: ExecutorPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            succeeded: false,
            detail: detail.into(),
        }
    }
}

pub type ExecutorFuture<'a> = Pin<Box<dyn Future<Output = ExecutorResult> + Send + 'a>>;

pub trait Executor: Send + Sync {
    fn activate<'a>(&'a self, input: &'a ExecutorInput) -> ExecutorFuture<'a>;

    fn deactivate<'a>(&'a self, input: &'a ExecutorInput) -> ExecutorFuture<'a>;
}

pub struct LocalShellExecutor;

impl LocalShellExecutor {
    async fn run_command(
        &self,
        input: &ExecutorInput,
        phase: ExecutorPhase,
        command_text: &str,
    ) -> ExecutorResult {
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
                return ExecutorResult::failed(
                    phase,
                    format!("spawning deployment command failed: {error}"),
                );
            }
        };
        let process_group = child.id().map(|id| -(id as i32));
        let mut wait = Box::pin(child.wait());
        let mut interrupt =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(signal) => signal,
                Err(error) => {
                    return ExecutorResult::failed(
                        phase,
                        format!("registering interrupt handler failed: {error}"),
                    );
                }
            };
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    return ExecutorResult::failed(
                        phase,
                        format!("registering termination handler failed: {error}"),
                    );
                }
            };
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(600));
        tokio::pin!(timeout);
        let (status, interrupted) = tokio::select! {
            status = &mut wait => (status, None),
            _ = &mut timeout => (Ok(Default::default()), Some("deployment command exceeded the 10 minute timeout")),
            _ = interrupt.recv() => (Ok(Default::default()), Some("deployment command interrupted")),
            _ = terminate.recv() => (Ok(Default::default()), Some("deployment command terminated")),
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
    fn activate<'a>(&'a self, input: &'a ExecutorInput) -> ExecutorFuture<'a> {
        Box::pin(async move {
            let install = self
                .run_command(input, ExecutorPhase::Install, &input.install)
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
                    self.run_command(input, ExecutorPhase::Health, command)
                        .await
                }
                None => install,
            }
        })
    }

    fn deactivate<'a>(&'a self, input: &'a ExecutorInput) -> ExecutorFuture<'a> {
        Box::pin(async move {
            match input
                .uninstall
                .as_deref()
                .filter(|command| !command.is_empty())
            {
                Some(command) => {
                    self.run_command(input, ExecutorPhase::Uninstall, command)
                        .await
                }
                None => ExecutorResult::failed(
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
        let result = LocalShellExecutor.activate(&input(workdir.clone())).await;

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
        let result = LocalShellExecutor.deactivate(&input(workdir.clone())).await;

        assert_eq!(result, ExecutorResult::succeeded(ExecutorPhase::Uninstall));
        assert!(workdir.join("uninstalled").exists());
        std::fs::remove_dir_all(workdir).unwrap();
    }
}

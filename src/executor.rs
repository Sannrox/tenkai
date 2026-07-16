//! Typed deployment execution contract.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

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
}

//! Tenkai-owned model-routing configuration contract and executor port.
//!
//! The contract is provider-neutral. External policy/evaluation systems may
//! authorize a plan, but they never own Tenkai's applied or recovery state.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const ROUTING_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub version: u32,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub model: String,
    pub provider: String,
    #[serde(default = "default_weight")]
    pub weight: u16,
}

fn default_weight() -> u16 {
    100
}

impl RoutingConfig {
    pub fn validate(&self, allowed_providers: &[String]) -> Result<()> {
        if self.version != ROUTING_CONFIG_VERSION {
            bail!(
                "unsupported routing configuration version {}; expected {}",
                self.version,
                ROUTING_CONFIG_VERSION
            );
        }
        if self.routes.is_empty() {
            bail!("routing configuration must contain at least one route");
        }
        let allowed = allowed_providers
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let mut names = HashSet::new();
        for route in &self.routes {
            for (field, value) in [
                ("route.name", route.name.as_str()),
                ("route.model", route.model.as_str()),
                ("route.provider", route.provider.as_str()),
            ] {
                crate::ontology::validate_identifier(field, value)?;
            }
            if !names.insert(route.name.as_str()) {
                bail!("duplicate routing reference {:?}", route.name);
            }
            if !allowed.contains(route.provider.as_str()) {
                bail!(
                    "routing policy denies provider {:?} for route {:?}",
                    route.provider,
                    route.name
                );
            }
            if route.weight == 0 || route.weight > 100 {
                bail!("route {:?} weight must be between 1 and 100", route.name);
            }
        }
        Ok(())
    }
}

pub fn load_and_validate(path: &Path, allowed_providers: &[String]) -> Result<RoutingConfig> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading routing configuration {}", path.display()))?;
    let config: RoutingConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing routing configuration {}", path.display()))?;
    config.validate(allowed_providers)?;
    Ok(config)
}

pub fn digest(config: &RoutingConfig) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(config)?)))
}

pub trait RoutingConfigExecutor {
    fn apply(&self, config: &RoutingConfig) -> Result<String>;
    fn remove(&self) -> Result<()>;
    fn observe(&self) -> Result<Option<String>>;
}

/// Standalone executor adapter used by embedded Tenkai.
///
/// The state file is an external mutation target, not operational authority.
/// Tenkai's release, plan, receipt, and rollback records remain authoritative.
pub struct LocalRoutingConfigExecutor {
    state_path: PathBuf,
}

impl LocalRoutingConfigExecutor {
    pub fn new(state_path: PathBuf) -> Self {
        Self { state_path }
    }
}

impl RoutingConfigExecutor for LocalRoutingConfigExecutor {
    fn apply(&self, config: &RoutingConfig) -> Result<String> {
        let expected = digest(config)?;
        let parent = self
            .state_path
            .parent()
            .context("routing state path has no parent")?;
        std::fs::create_dir_all(parent)?;
        let temporary = self.state_path.with_extension("json.pending");
        std::fs::write(&temporary, serde_json::to_vec_pretty(config)?)?;
        let observed: RoutingConfig = serde_json::from_slice(&std::fs::read(&temporary)?)?;
        if digest(&observed)? != expected {
            let _ = std::fs::remove_file(&temporary);
            bail!("routing post-mutation verification failed");
        }
        std::fs::rename(&temporary, &self.state_path)?;
        if self.observe()?.as_deref() != Some(expected.as_str()) {
            bail!("routing post-mutation observation differs from requested configuration");
        }
        Ok(expected)
    }

    fn remove(&self) -> Result<()> {
        match std::fs::remove_file(&self.state_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn observe(&self) -> Result<Option<String>> {
        match std::fs::read(&self.state_path) {
            Ok(bytes) => {
                let config: RoutingConfig = serde_json::from_slice(&bytes)?;
                Ok(Some(digest(&config)?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(provider: &str) -> RoutingConfig {
        RoutingConfig {
            version: 1,
            routes: vec![Route {
                name: "chat".into(),
                model: "model-v1".into(),
                provider: provider.into(),
                weight: 100,
            }],
        }
    }

    #[test]
    fn invalid_reference_and_policy_fail_before_mutation() {
        let root = std::env::temp_dir().join(format!("tenkai-routing-{}", uuid::Uuid::new_v4()));
        let state = root.join("active.json");
        let executor = LocalRoutingConfigExecutor::new(state.clone());
        let invalid = config("unapproved");
        assert!(invalid.validate(&["local".into()]).is_err());
        assert!(!state.exists());
        assert!(executor.observe().unwrap().is_none());
    }

    #[test]
    fn local_executor_applies_observes_and_removes_atomically() {
        let root = std::env::temp_dir().join(format!("tenkai-routing-{}", uuid::Uuid::new_v4()));
        let executor = LocalRoutingConfigExecutor::new(root.join("active.json"));
        let config = config("local");
        config.validate(&["local".into()]).unwrap();
        let applied = executor.apply(&config).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(applied.as_str())
        );
        executor.remove().unwrap();
        assert!(executor.observe().unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_reapplies_the_pinned_previous_configuration() {
        let root = std::env::temp_dir().join(format!("tenkai-routing-{}", uuid::Uuid::new_v4()));
        let executor = LocalRoutingConfigExecutor::new(root.join("active.json"));
        let previous = config("local");
        let mut target = config("local");
        target.routes[0].model = "model-v2".into();

        let previous_digest = executor.apply(&previous).unwrap();
        let target_digest = executor.apply(&target).unwrap();
        assert_ne!(previous_digest, target_digest);
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(target_digest.as_str())
        );

        executor.apply(&previous).unwrap();
        assert_eq!(
            executor.observe().unwrap().as_deref(),
            Some(previous_digest.as_str())
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

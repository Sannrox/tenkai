//! Optional advisory deployment-outcome priors for planning.
//!
//! When enabled, the planner may annotate plans with historical failure
//! patterns. Priors are **advisory only** in this delivery: they never hard-block
//! planning, bypass signing/approval, or change selected release versions.
//!
//! Default is off. Enable with `TENKAI_PLAN_PRIORS=1` and optional
//! `TENKAI_PLAN_PRIORS_FILE` pointing at a JSON prior set. Missing file or
//! disabled flag leaves plan generation unchanged.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::plan::{EnvironmentInspectReport, Plan, Step};

/// One historical pattern used as an advisory prior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentOutcomePrior {
    pub product: String,
    /// Environment fact key that co-occurred with failures (e.g. `architecture`).
    pub fact_key: String,
    pub fact_value: String,
    /// Operator-visible advisory text (no secrets).
    pub note: String,
    /// Optional observed failure count for display only.
    #[serde(default)]
    pub failure_count: u32,
}

/// File format for local prior sets (`tenkai.plan-priors.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PriorSet {
    #[serde(default = "prior_set_schema")]
    pub schema: String,
    #[serde(default)]
    pub priors: Vec<DeploymentOutcomePrior>,
}

fn prior_set_schema() -> String {
    "tenkai.plan-priors.v1".into()
}

/// Host configuration for consulting priors during plan creation.
#[derive(Debug, Clone, Default)]
pub struct PriorConfig {
    pub enabled: bool,
    pub source_path: Option<PathBuf>,
}

impl PriorConfig {
    /// Resolve from environment. Default: disabled, no source.
    pub fn from_env() -> Self {
        let enabled = matches!(
            std::env::var("TENKAI_PLAN_PRIORS").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("on")
        );
        let source_path = std::env::var_os("TENKAI_PLAN_PRIORS_FILE").map(PathBuf::from);
        Self {
            enabled,
            source_path,
        }
    }

    pub fn load_priors(&self) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        let Some(path) = &self.source_path else {
            return Ok(Vec::new());
        };
        load_prior_file(path)
    }
}

pub fn load_prior_file(path: &Path) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let set: PriorSet = serde_json::from_str(&raw)?;
    for prior in &set.priors {
        if prior.product.trim().is_empty()
            || prior.fact_key.trim().is_empty()
            || prior.note.trim().is_empty()
        {
            anyhow::bail!("prior entries require non-empty product, fact_key, and note");
        }
        // Fail closed on obvious secret-looking material in notes.
        let lower = prior.note.to_lowercase();
        if lower.contains("bearer ")
            || lower.contains("token=")
            || lower.contains("password")
            || lower.contains("private_key")
        {
            anyhow::bail!("prior note must not contain secret-like material");
        }
    }
    Ok(set.priors)
}

/// Match priors against plan steps and environment facts; return advisory lines.
pub fn matching_prior_warnings(
    steps: &[Step],
    env_facts: &std::collections::BTreeMap<String, String>,
    priors: &[DeploymentOutcomePrior],
) -> Vec<String> {
    let mut warnings = Vec::new();
    for step in steps {
        for prior in priors {
            if prior.product != step.product {
                continue;
            }
            let Some(value) = env_facts.get(&prior.fact_key) else {
                continue;
            };
            if value != &prior.fact_value {
                continue;
            }
            let count = if prior.failure_count > 0 {
                format!(" (observed_failures={})", prior.failure_count)
            } else {
                String::new()
            };
            warnings.push(format!(
                "advisory prior for {} when {}={}: {}{}",
                prior.product, prior.fact_key, prior.fact_value, prior.note, count
            ));
        }
    }
    warnings.sort();
    warnings.dedup();
    warnings
}

/// Apply advisory priors to a computed plan (mutates annotations only).
pub fn annotate_plan_with_priors(
    plan: &mut Plan,
    env: &EnvironmentInspectReport,
    config: &PriorConfig,
) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let priors = config.load_priors()?;
    if priors.is_empty() {
        return Ok(());
    }
    let warnings = matching_prior_warnings(&plan.steps, &env.facts, &priors);
    if warnings.is_empty() {
        return Ok(());
    }
    plan.prior_warnings = warnings;
    if plan.status_detail.is_empty() {
        plan.status_detail = format!("advisory prior warnings: {}", plan.prior_warnings.len());
    } else if !plan.status_detail.contains("advisory prior") {
        plan.status_detail = format!(
            "{}; advisory prior warnings: {}",
            plan.status_detail,
            plan.prior_warnings.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Action, PLAN_FORMAT_VERSION, PlanState, Step};

    fn step(product: &str) -> Step {
        Step {
            id: "s0".into(),
            order: 0,
            product: product.into(),
            action: Action::Upgrade,
            from: Some("1.0.0".into()),
            to: "1.1.0".into(),
            release_id: format!("tenkai:release:{product}@1.1.0"),
            release_digest: "d".into(),
            artifact_digest: "a".into(),
            workdir: ".".into(),
            restore: None,
        }
    }

    #[test]
    fn disabled_priors_leave_plan_unchanged() {
        let mut plan = Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: "p".into(),
            content_id: "c".into(),
            environment: "local".into(),
            created_at: 1,
            inputs: Vec::new(),
            steps: vec![step("api")],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
        };
        let env = EnvironmentInspectReport {
            name: "local".into(),
            id: "tenkai:env:local".into(),
            description: String::new(),
            subscriptions: Vec::new(),
            facts: std::collections::BTreeMap::from([("architecture".into(), "x86_64".into())]),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            execution_note: String::new(),
        };
        annotate_plan_with_priors(
            &mut plan,
            &env,
            &PriorConfig {
                enabled: false,
                source_path: None,
            },
        )
        .unwrap();
        assert!(plan.prior_warnings.is_empty());
        assert!(plan.status_detail.is_empty());
    }

    #[test]
    fn matching_prior_adds_advisory_warning() {
        let priors = vec![DeploymentOutcomePrior {
            product: "api".into(),
            fact_key: "architecture".into(),
            fact_value: "x86_64".into(),
            note: "historical install failures on this architecture".into(),
            failure_count: 3,
        }];
        let facts = std::collections::BTreeMap::from([("architecture".into(), "x86_64".into())]);
        let warnings = matching_prior_warnings(&[step("api")], &facts, &priors);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("advisory prior"));
        assert!(warnings[0].contains("api"));
        assert!(!warnings[0].contains("Bearer"));
    }

    #[test]
    fn prior_file_round_trip_rejects_secret_notes() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-priors-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("priors.json");
        let set = PriorSet {
            schema: prior_set_schema(),
            priors: vec![DeploymentOutcomePrior {
                product: "api".into(),
                fact_key: "architecture".into(),
                fact_value: "arm64".into(),
                note: "ok note".into(),
                failure_count: 1,
            }],
        };
        std::fs::write(&path, serde_json::to_string_pretty(&set).unwrap()).unwrap();
        let loaded = load_prior_file(&path).unwrap();
        assert_eq!(loaded.len(), 1);

        let bad = PriorSet {
            schema: prior_set_schema(),
            priors: vec![DeploymentOutcomePrior {
                product: "api".into(),
                fact_key: "architecture".into(),
                fact_value: "arm64".into(),
                note: "token=supersecret".into(),
                failure_count: 1,
            }],
        };
        std::fs::write(&path, serde_json::to_string_pretty(&bad).unwrap()).unwrap();
        assert!(load_prior_file(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

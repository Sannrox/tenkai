//! Optional advisory deployment-outcome priors for planning.
//!
//! When enabled, the planner may annotate plans with historical failure
//! patterns. Priors are **advisory only** in this delivery: they never hard-block
//! planning, bypass signing/approval, or change selected release versions.
//!
//! Default is off. Enable with `TENKAI_PLAN_PRIORS=1` and optional
//! `TENKAI_PLAN_PRIORS_FILE` pointing at a JSON prior set. Missing file or
//! disabled flag leaves plan generation unchanged.
//!
//! Outcome history (#138): when `TENKAI_PLAN_PRIORS_OUTCOME=1`, priors are also
//! projected from OutcomeProvider-compatible events (`ProviderEvent` payloads
//! with schema `tenkai.outcome_prior.v1`), either from
//! `TENKAI_PLAN_PRIORS_OUTCOME_FILE` or an injectable [`OutcomePriorSource`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::plan::{EnvironmentInspectReport, Plan, Step};
use crate::providers::ProviderEvent;

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

/// Schema token for OutcomeProvider payload → prior projection (#138).
pub const OUTCOME_PRIOR_SCHEMA: &str = "tenkai.outcome_prior.v1";

/// Payload inside a [`ProviderEvent`] that can become an advisory prior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomePriorPayload {
    #[serde(default = "outcome_prior_schema")]
    pub schema: String,
    pub product: String,
    pub fact_key: String,
    pub fact_value: String,
    pub note: String,
    #[serde(default)]
    pub failure_count: u32,
}

fn outcome_prior_schema() -> String {
    OUTCOME_PRIOR_SCHEMA.into()
}

/// Injectable history source (in-process OutcomeProvider projection or test fake).
pub trait OutcomePriorSource: Send + Sync {
    fn load_outcome_priors(&self) -> anyhow::Result<Vec<DeploymentOutcomePrior>>;
}

/// Host configuration for consulting priors during plan creation.
#[derive(Debug, Clone, Default)]
pub struct PriorConfig {
    pub enabled: bool,
    pub source_path: Option<PathBuf>,
    /// When true, also load priors projected from outcome history (#138).
    pub outcome_enabled: bool,
    /// Optional JSON file of [`ProviderEvent`] values (or a wrapper object).
    pub outcome_path: Option<PathBuf>,
    /// When true, outcome projection failure fails plan annotation (visible).
    /// Default false: degrade to file-only priors with no silent inventing.
    pub outcome_required: bool,
}

impl PriorConfig {
    /// Resolve from environment. Default: disabled, no source.
    pub fn from_env() -> Self {
        let enabled = env_flag("TENKAI_PLAN_PRIORS");
        let source_path = std::env::var_os("TENKAI_PLAN_PRIORS_FILE").map(PathBuf::from);
        let outcome_enabled = env_flag("TENKAI_PLAN_PRIORS_OUTCOME");
        let outcome_path = std::env::var_os("TENKAI_PLAN_PRIORS_OUTCOME_FILE").map(PathBuf::from);
        let outcome_required = env_flag("TENKAI_PLAN_PRIORS_OUTCOME_REQUIRED");
        Self {
            enabled,
            source_path,
            outcome_enabled,
            outcome_path,
            outcome_required,
        }
    }

    pub fn load_priors(&self) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
        self.load_priors_with_outcome(None)
    }

    /// Load file priors plus optional OutcomeProvider / file outcome history.
    pub fn load_priors_with_outcome(
        &self,
        outcome: Option<&dyn OutcomePriorSource>,
    ) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        let mut priors = Vec::new();
        if let Some(path) = &self.source_path {
            priors.extend(load_prior_file(path)?);
        }
        if self.outcome_enabled {
            match load_outcome_priors(self, outcome) {
                Ok(extra) => priors.extend(extra),
                Err(error) if self.outcome_required => return Err(error),
                Err(error) => {
                    // Visible degradation: surface in stderr; do not invent priors.
                    eprintln!("plan priors outcome history unavailable: {error:#}");
                }
            }
        }
        Ok(priors)
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("on")
    )
}

pub fn load_prior_file(path: &Path) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let set: PriorSet = serde_json::from_str(&raw)?;
    validate_priors(&set.priors)?;
    Ok(set.priors)
}

fn validate_priors(priors: &[DeploymentOutcomePrior]) -> anyhow::Result<()> {
    for prior in priors {
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
    Ok(())
}

/// Project OutcomeProvider events into advisory priors (#138).
///
/// Only payloads with `schema = tenkai.outcome_prior.v1` are accepted. Other
/// events are skipped (not errors) so mixed outcome streams remain usable.
pub fn project_priors_from_outcome_events(
    events: &[ProviderEvent],
) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
    let mut priors = Vec::new();
    for event in events {
        event
            .binding
            .validate()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let payload: OutcomePriorPayload = match serde_json::from_str(&event.payload_json) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if payload.schema != OUTCOME_PRIOR_SCHEMA {
            continue;
        }
        let prior = DeploymentOutcomePrior {
            product: payload.product,
            fact_key: payload.fact_key,
            fact_value: payload.fact_value,
            note: payload.note,
            failure_count: payload.failure_count,
        };
        validate_priors(std::slice::from_ref(&prior))?;
        priors.push(prior);
    }
    Ok(priors)
}

fn load_outcome_priors(
    config: &PriorConfig,
    outcome: Option<&dyn OutcomePriorSource>,
) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
    let mut priors = Vec::new();
    if let Some(source) = outcome {
        priors.extend(source.load_outcome_priors()?);
    }
    if let Some(path) = &config.outcome_path {
        if !path.exists() {
            if config.outcome_required {
                anyhow::bail!(
                    "outcome prior file {} is missing (TENKAI_PLAN_PRIORS_OUTCOME_REQUIRED)",
                    path.display()
                );
            }
        } else {
            priors.extend(load_outcome_events_file(path)?);
        }
    }
    if priors.is_empty()
        && outcome.is_none()
        && config.outcome_path.is_none()
        && config.outcome_required
    {
        anyhow::bail!(
            "outcome priors required but no OutcomePriorSource or TENKAI_PLAN_PRIORS_OUTCOME_FILE configured"
        );
    }
    Ok(priors)
}

/// Load a JSON file of provider events: either `[ProviderEvent, ...]` or
/// `{ "events": [ ... ] }`.
pub fn load_outcome_events_file(path: &Path) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
    let raw = std::fs::read_to_string(path)?;
    let events = parse_outcome_events_json(&raw)?;
    project_priors_from_outcome_events(&events)
}

fn parse_outcome_events_json(raw: &str) -> anyhow::Result<Vec<ProviderEvent>> {
    if let Ok(events) = serde_json::from_str::<Vec<ProviderEvent>>(raw) {
        return Ok(events);
    }
    #[derive(Deserialize)]
    struct Wrapper {
        events: Vec<ProviderEvent>,
    }
    let wrapper: Wrapper = serde_json::from_str(raw).map_err(|e| {
        anyhow::anyhow!("outcome events JSON must be an array or {{events:[...]}}: {e}")
    })?;
    Ok(wrapper.events)
}

/// Project history from an in-process [`crate::providers::LocalEventSink`].
pub struct LocalEventSinkPriorSource<'a> {
    pub sink: &'a crate::providers::LocalEventSink,
}

impl OutcomePriorSource for LocalEventSinkPriorSource<'_> {
    fn load_outcome_priors(&self) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
        let events = self.sink.received();
        project_priors_from_outcome_events(&events)
    }
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
    annotate_plan_with_priors_and_outcome(plan, env, config, None)
}

/// Like [`annotate_plan_with_priors`] with an injectable OutcomeProvider history.
pub fn annotate_plan_with_priors_and_outcome(
    plan: &mut Plan,
    env: &EnvironmentInspectReport,
    config: &PriorConfig,
    outcome: Option<&dyn OutcomePriorSource>,
) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let priors = config.load_priors_with_outcome(outcome)?;
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
            recalled_recovery_reason: None,
        };
        let env = EnvironmentInspectReport {
            name: "local".into(),
            id: "tenkai:env:local".into(),
            description: String::new(),
            subscriptions: Vec::new(),
            facts: std::collections::BTreeMap::from([("architecture".into(), "x86_64".into())]),
            overlays: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            terminal_outcomes: Vec::new(),
            execution_note: String::new(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
        };
        annotate_plan_with_priors(
            &mut plan,
            &env,
            &PriorConfig {
                enabled: false,
                ..PriorConfig::default()
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

    #[test]
    fn project_priors_from_outcome_events_and_annotate() {
        use crate::providers::{EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderEvent};

        let binding = EvidenceBinding {
            contract_version: PROVIDER_CONTRACT_VERSION,
            release_digest: "sha256:r".into(),
            plan_digest: "sha256:p".into(),
            configuration_digest: "sha256:c".into(),
            environment_id: "local".into(),
        };
        let payload = OutcomePriorPayload {
            schema: OUTCOME_PRIOR_SCHEMA.into(),
            product: "api".into(),
            fact_key: "architecture".into(),
            fact_value: "x86_64".into(),
            note: "provider-projected install failures".into(),
            failure_count: 2,
        };
        let event = ProviderEvent {
            id: "ev-1".into(),
            binding,
            payload_json: serde_json::to_string(&payload).unwrap(),
            collected_at_ms: None,
            source_sequence: None,
        };
        let priors = project_priors_from_outcome_events(&[event]).unwrap();
        assert_eq!(priors.len(), 1);
        assert_eq!(priors[0].product, "api");

        struct FixedSource(Vec<DeploymentOutcomePrior>);
        impl OutcomePriorSource for FixedSource {
            fn load_outcome_priors(&self) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
                Ok(self.0.clone())
            }
        }
        let source = FixedSource(priors);
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
            recalled_recovery_reason: None,
        };
        let env = EnvironmentInspectReport {
            name: "local".into(),
            id: "tenkai:env:local".into(),
            description: String::new(),
            subscriptions: Vec::new(),
            facts: std::collections::BTreeMap::from([("architecture".into(), "x86_64".into())]),
            overlays: Default::default(),
            lease: crate::apply::EnvironmentLeaseInspect {
                held: false,
                owner: None,
                generation: None,
                expires_at_ms: None,
                status: "absent".into(),
            },
            latest_plan: None,
            terminal_outcomes: Vec::new(),
            execution_note: String::new(),
            observed_type_digest: None,
            observed_runtime_digest: None,
            module_activations: Vec::new(),
        };
        let config = PriorConfig {
            enabled: true,
            outcome_enabled: true,
            ..PriorConfig::default()
        };
        annotate_plan_with_priors_and_outcome(&mut plan, &env, &config, Some(&source)).unwrap();
        assert_eq!(plan.prior_warnings.len(), 1);
        assert!(plan.prior_warnings[0].contains("provider-projected"));
    }

    #[test]
    fn outcome_required_fails_closed_when_source_errors() {
        struct Boom;
        impl OutcomePriorSource for Boom {
            fn load_outcome_priors(&self) -> anyhow::Result<Vec<DeploymentOutcomePrior>> {
                anyhow::bail!("provider unavailable")
            }
        }
        let config = PriorConfig {
            enabled: true,
            outcome_enabled: true,
            outcome_required: true,
            ..PriorConfig::default()
        };
        let err = config
            .load_priors_with_outcome(Some(&Boom))
            .unwrap_err()
            .to_string();
        assert!(err.contains("provider unavailable"));
    }

    #[test]
    fn outcome_payload_rejects_secret_notes() {
        use crate::providers::{EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderEvent};
        let event = ProviderEvent {
            id: "ev".into(),
            binding: EvidenceBinding {
                contract_version: PROVIDER_CONTRACT_VERSION,
                release_digest: "sha256:r".into(),
                plan_digest: "sha256:p".into(),
                configuration_digest: "sha256:c".into(),
                environment_id: "e".into(),
            },
            payload_json: serde_json::to_string(&OutcomePriorPayload {
                schema: OUTCOME_PRIOR_SCHEMA.into(),
                product: "api".into(),
                fact_key: "architecture".into(),
                fact_value: "x86_64".into(),
                note: "token=secret".into(),
                failure_count: 1,
            })
            .unwrap(),
            collected_at_ms: None,
            source_sequence: None,
        };
        assert!(project_priors_from_outcome_events(&[event]).is_err());
    }
}

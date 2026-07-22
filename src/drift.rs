//! Executor observations and persisted reported deployment state.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::executor::{
    Cancellation, ExecutorObservation, ExecutorObservationInput, ExecutorObservationResult,
    ObservedHealth,
};
use crate::manifest;
use crate::ontology::{KIND_ENVIRONMENT, KIND_RELEASE, env_id, release_id, validate_identifier};
use crate::pb::sekai::Object;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationReport {
    pub product: String,
    pub configured: bool,
    pub observation: Option<ExecutorObservation>,
    pub error: Option<String>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    Missing,
    Unexpected,
    Version,
    Health,
}

impl std::fmt::Display for DriftKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "missing",
            Self::Unexpected => "unexpected",
            Self::Version => "version",
            Self::Health => "health",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Drift {
    pub product: String,
    pub kind: DriftKind,
    pub desired_version: Option<String>,
    pub last_applied_version: Option<String>,
    pub observed_version: Option<String>,
    pub observed_health: Option<ObservedHealth>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservationSnapshot {
    pub product: String,
    pub status: Option<String>,
    pub observed_version: Option<String>,
    pub observed_health: Option<ObservedHealth>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProductState {
    pub desired_version: Option<String>,
    pub last_applied_version: Option<String>,
    pub observed_version: Option<String>,
    pub observed_health: Option<ObservedHealth>,
    pub observation_succeeded: bool,
}

/// Classify independently actionable drift from successful executor reports.
pub fn classify(states: &BTreeMap<String, ProductState>) -> Vec<Drift> {
    let mut drift = Vec::new();
    for (product, state) in states {
        if !state.observation_succeeded {
            continue;
        }
        let mut push = |kind| {
            drift.push(Drift {
                product: product.clone(),
                kind,
                desired_version: state.desired_version.clone(),
                last_applied_version: state.last_applied_version.clone(),
                observed_version: state.observed_version.clone(),
                observed_health: state.observed_health,
            });
        };
        match (&state.desired_version, &state.observed_version) {
            (Some(_), None) => push(DriftKind::Missing),
            (None, Some(_)) => push(DriftKind::Unexpected),
            (Some(desired), Some(observed)) if desired != observed => push(DriftKind::Version),
            _ => {}
        }
        if state.observed_version.is_some()
            && state.observed_health == Some(ObservedHealth::Unhealthy)
        {
            push(DriftKind::Health);
        }
    }
    drift
}

pub fn states_from_properties(
    properties: &HashMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> BTreeMap<String, ProductState> {
    let mut products = desired
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for key in properties.keys() {
        for prefix in [
            "deployed.",
            "observed.",
            "observation_status.",
            "deployment_health.",
        ] {
            if let Some(product) = key.strip_prefix(prefix) {
                products.insert(product.into());
            }
        }
    }
    products
        .into_iter()
        .map(|product| {
            let health = match properties
                .get(&format!("observed_health.{product}"))
                .map(String::as_str)
            {
                Some("healthy") => Some(ObservedHealth::Healthy),
                Some("unhealthy") => Some(ObservedHealth::Unhealthy),
                Some("not_checked") => Some(ObservedHealth::NotChecked),
                _ => None,
            };
            let state = ProductState {
                desired_version: desired.get(&product).cloned(),
                last_applied_version: properties.get(&format!("deployed.{product}")).cloned(),
                observed_version: properties.get(&format!("observed.{product}")).cloned(),
                observed_health: health,
                observation_succeeded: properties
                    .get(&format!("observation_status.{product}"))
                    .is_some_and(|status| status == "succeeded"),
            };
            (product, state)
        })
        .collect()
}

pub fn snapshot_from_properties(
    properties: &HashMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> Vec<ObservationSnapshot> {
    states_from_properties(properties, desired)
        .into_iter()
        .map(|(product, state)| ObservationSnapshot {
            status: properties
                .get(&format!("observation_status.{product}"))
                .cloned(),
            product,
            observed_version: state.observed_version,
            observed_health: state.observed_health,
        })
        .collect()
}

impl ObservationReport {
    fn from_result(
        product: String,
        configured: bool,
        result: ExecutorObservationResult,
        observed_at: i64,
    ) -> Self {
        Self {
            product,
            configured,
            observation: result.observation,
            error: (!result.detail.is_empty()).then_some(result.detail),
            observed_at,
        }
    }
}

fn apply_report(environment: &mut Object, report: &ObservationReport) {
    let product = &report.product;
    if !report.configured {
        environment.properties.insert(
            format!("observation_status.{product}"),
            "unconfigured".into(),
        );
        environment
            .properties
            .remove(&format!("observation_error.{product}"));
        return;
    }
    environment.properties.insert(
        format!("observation_status.{product}"),
        if report.observation.is_some() {
            "succeeded"
        } else {
            "failed"
        }
        .into(),
    );
    environment.properties.insert(
        format!("observed_at.{product}"),
        report.observed_at.to_string(),
    );
    if let Some(error) = &report.error {
        environment
            .properties
            .insert(format!("observation_error.{product}"), error.clone());
    } else {
        environment
            .properties
            .remove(&format!("observation_error.{product}"));
    }
    let Some(observation) = &report.observation else {
        return;
    };
    environment
        .properties
        .remove(&format!("deployment_health.{product}"));
    environment
        .properties
        .remove(&format!("deployment_error.{product}"));
    match &observation.installed_version {
        Some(version) => {
            environment
                .properties
                .insert(format!("observed.{product}"), version.clone());
        }
        None => {
            environment
                .properties
                .remove(&format!("observed.{product}"));
        }
    }
    environment.properties.insert(
        format!("observed_health.{product}"),
        match observation.health {
            ObservedHealth::Healthy => "healthy",
            ObservedHealth::Unhealthy => "unhealthy",
            ObservedHealth::NotChecked => "not_checked",
        }
        .into(),
    );
}

pub(crate) fn clear_observation_properties(environment: &mut Object, product: &str) {
    for prefix in [
        "observed.",
        "observed_health.",
        "observed_at.",
        "observation_status.",
        "observation_error.",
    ] {
        environment.properties.remove(&format!("{prefix}{product}"));
    }
}

fn release_observation_input(
    release: &Object,
    environment: &str,
    product: &str,
) -> Result<(crate::executor::ExecutorKind, ExecutorObservationInput)> {
    if release.kind != KIND_RELEASE {
        bail!(
            "object {} is {}, not {KIND_RELEASE}",
            release.id,
            release.kind
        );
    }
    let raw = release
        .properties
        .get("manifest")
        .with_context(|| format!("release {} has no manifest", release.id))?;
    if release.properties.get("digest") != Some(&manifest::digest(raw)) {
        bail!("release {} manifest digest does not match", release.id);
    }
    let manifest = manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {}", release.id))?;
    if manifest.product.name != product {
        bail!(
            "release {} manifest belongs to {}, not {product}",
            release.id,
            manifest.product.name
        );
    }
    if manifest.deploy.observe.as_deref().is_none_or(str::is_empty) {
        return Ok((
            manifest.deploy.executor,
            ExecutorObservationInput {
                environment: environment.into(),
                product: product.into(),
                expected_version: manifest.product.version,
                workdir: PathBuf::new(),
                observe: None,
                health: manifest.deploy.health,
                timeout_seconds: manifest.deploy.timeout_seconds.unwrap_or(600),
            },
        ));
    }
    let snapshot = release
        .properties
        .get("workdir")
        .filter(|workdir| !workdir.is_empty())
        .map(PathBuf::from)
        .with_context(|| format!("release {} has no deployment workdir", release.id))?;
    let artifact_digest = release
        .properties
        .get("artifact_digest")
        .filter(|digest| !digest.is_empty())
        .with_context(|| format!("release {} has no artifact digest", release.id))?;
    let actual_digest = manifest::artifact_digest(&snapshot, &manifest.deploy.inputs)
        .with_context(|| format!("verifying immutable inputs for {}", release.id))?;
    if actual_digest != *artifact_digest {
        bail!("release {} immutable deployment inputs changed", release.id);
    }
    let workdir = if manifest.deploy.inputs.is_empty() {
        snapshot
            .canonicalize()
            .with_context(|| format!("resolving deployment workdir for release {}", release.id))?
    } else {
        manifest::execution_workdir(
            &snapshot,
            &manifest.deploy.inputs,
            artifact_digest,
            environment,
            product,
        )?
    };
    Ok((
        manifest.deploy.executor,
        ExecutorObservationInput {
            environment: environment.into(),
            product: product.into(),
            expected_version: manifest.product.version.clone(),
            workdir,
            observe: manifest.deploy.observe,
            health: manifest.deploy.health,
            timeout_seconds: manifest.deploy.timeout_seconds.unwrap_or(600),
        },
    ))
}

fn verify_observation_runtime(release: &Object, input: &ExecutorObservationInput) -> Result<()> {
    let raw = release
        .properties
        .get("manifest")
        .with_context(|| format!("release {} has no manifest", release.id))?;
    if release.properties.get("digest") != Some(&manifest::digest(raw)) {
        bail!("release {} manifest digest does not match", release.id);
    }
    let stored = manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {}", release.id))?;
    let expected = release
        .properties
        .get("artifact_digest")
        .filter(|digest| !digest.is_empty())
        .with_context(|| format!("release {} has no artifact digest", release.id))?;
    let actual = manifest::artifact_digest(&input.workdir, &stored.deploy.inputs)
        .with_context(|| format!("verifying observation runtime for {}", release.id))?;
    if actual != *expected {
        bail!("release {} observation runtime inputs changed", release.id);
    }
    Ok(())
}

pub(crate) async fn observe_locked(
    ctx: &mut Ctx,
    environment: &str,
    cancellation: &Cancellation,
) -> Result<Vec<ObservationReport>> {
    let id = env_id(environment);
    let mut environment_object = ctx
        .get(&id)
        .await?
        .with_context(|| format!("environment {environment} is not registered"))?;
    if environment_object.kind != KIND_ENVIRONMENT {
        bail!(
            "object {id} is {}, not {KIND_ENVIRONMENT}",
            environment_object.kind
        );
    }
    let products = environment_object
        .properties
        .keys()
        .filter_map(|key| key.strip_prefix("deployed.").map(str::to_string))
        .collect::<Vec<_>>();
    let mut reports = Vec::with_capacity(products.len());
    for product in products {
        if let Some(reason) = cancellation.reason() {
            bail!(reason);
        }
        let (configured, result) = async {
            let release = environment_object
                .properties
                .get(&format!("deployed_release.{product}"))
                .cloned()
                .unwrap_or_else(|| {
                    release_id(
                        &product,
                        &environment_object.properties[&format!("deployed.{product}")],
                    )
                });
            let release = ctx
                .get(&release)
                .await?
                .with_context(|| format!("last-applied release for {product} is not published"))?;
            let (kind, input) = release_observation_input(&release, environment, &product)?;
            let configured = input
                .observe
                .as_deref()
                .is_some_and(|command| !command.is_empty());
            let result = crate::executor::select(kind)
                .observe(&input, cancellation)
                .await;
            if configured {
                let current_release = ctx
                    .get(&release.id)
                    .await?
                    .with_context(|| format!("release {} disappeared", release.id))?;
                verify_observation_runtime(&current_release, &input)
                    .context("rechecking immutable observation inputs")?;
            }
            Ok::<_, anyhow::Error>((configured, result))
        }
        .await
        .unwrap_or_else(|error| (true, ExecutorObservationResult::failed(error.to_string())));
        if let Some(reason) = cancellation.reason() {
            bail!(reason);
        }
        reports.push(ObservationReport::from_result(
            product,
            configured,
            result,
            crate::now_millis(),
        ));
    }
    for report in &reports {
        apply_report(&mut environment_object, report);
    }
    environment_object.updated = crate::now_millis();
    ctx.put(environment_object).await?;
    Ok(reports)
}

/// Observe every last-applied product and persist reported state independently.
pub async fn observe(ctx: &mut Ctx, environment: &str) -> Result<Vec<ObservationReport>> {
    let signals = crate::apply::monitor_shutdown_signals()?;
    observe_with_cancellation(ctx, environment, signals.forward()).await
}

pub(crate) async fn observe_with_cancellation(
    ctx: &mut Ctx,
    environment: &str,
    cancellation: &Cancellation,
) -> Result<Vec<ObservationReport>> {
    validate_identifier("environment", environment)?;
    crate::apply::observe_environment(ctx, environment, cancellation).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::ontology::NS;

    fn environment() -> Object {
        Object {
            id: env_id("test"),
            kind: KIND_ENVIRONMENT.into(),
            name: "test".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("deployed.api".into(), "1.0.0".into()),
                ("observed.api".into(), "0.9.0".into()),
                ("observed_health.api".into(), "healthy".into()),
            ]),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn successful_observation_is_stored_separately_from_last_applied() {
        let mut environment = environment();
        apply_report(
            &mut environment,
            &ObservationReport {
                product: "api".into(),
                configured: true,
                observation: Some(ExecutorObservation {
                    installed_version: Some("2.0.0".into()),
                    health: ObservedHealth::Unhealthy,
                }),
                error: None,
                observed_at: 10,
            },
        );

        assert_eq!(environment.properties["deployed.api"], "1.0.0");
        assert_eq!(environment.properties["observed.api"], "2.0.0");
        assert_eq!(environment.properties["observed_health.api"], "unhealthy");
        assert_eq!(
            environment.properties["observation_status.api"],
            "succeeded"
        );
    }

    #[test]
    fn failed_observation_preserves_last_successful_report() {
        let mut environment = environment();
        apply_report(
            &mut environment,
            &ObservationReport {
                product: "api".into(),
                configured: true,
                observation: None,
                error: Some("probe unavailable".into()),
                observed_at: 10,
            },
        );

        assert_eq!(environment.properties["observed.api"], "0.9.0");
        assert_eq!(environment.properties["observed_health.api"], "healthy");
        assert_eq!(environment.properties["observation_status.api"], "failed");
        assert_eq!(
            environment.properties["observation_error.api"],
            "probe unavailable"
        );
    }

    #[test]
    fn confirmed_absence_clears_only_observed_version() {
        let mut environment = environment();
        apply_report(
            &mut environment,
            &ObservationReport {
                product: "api".into(),
                configured: true,
                observation: Some(ExecutorObservation {
                    installed_version: None,
                    health: ObservedHealth::NotChecked,
                }),
                error: None,
                observed_at: 10,
            },
        );

        assert_eq!(environment.properties["deployed.api"], "1.0.0");
        assert!(!environment.properties.contains_key("observed.api"));
        assert_eq!(
            environment.properties["observation_status.api"],
            "succeeded"
        );
    }

    #[test]
    fn deployment_changes_clear_stale_observation_properties() {
        let mut environment = environment();
        environment
            .properties
            .insert("observation_status.api".into(), "succeeded".into());
        environment
            .properties
            .insert("observed_at.api".into(), "10".into());

        clear_observation_properties(&mut environment, "api");

        assert_eq!(environment.properties["deployed.api"], "1.0.0");
        assert!(!environment.properties.contains_key("observed.api"));
        assert!(!environment.properties.contains_key("observed_health.api"));
        assert!(
            !environment
                .properties
                .contains_key("observation_status.api")
        );
        assert!(!environment.properties.contains_key("observed_at.api"));
    }

    #[test]
    fn unconfigured_observation_does_not_require_legacy_artifact_metadata() {
        let raw = r#"
[product]
name = "api"
version = "1.0.0"

[deploy]
install = "true"
"#;
        let release = Object {
            id: release_id("api", "1.0.0"),
            kind: KIND_RELEASE.into(),
            name: "api 1.0.0".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("manifest".into(), raw.into()),
                ("digest".into(), manifest::digest(raw)),
            ]),
            created: 1,
            updated: 1,
        };

        let (_, input) = release_observation_input(&release, "test", "api").unwrap();

        assert!(input.observe.is_none());
        assert!(input.workdir.as_os_str().is_empty());
    }

    fn state(
        desired: Option<&str>,
        applied: Option<&str>,
        observed: Option<&str>,
        health: Option<ObservedHealth>,
    ) -> ProductState {
        ProductState {
            desired_version: desired.map(str::to_string),
            last_applied_version: applied.map(str::to_string),
            observed_version: observed.map(str::to_string),
            observed_health: health,
            observation_succeeded: true,
        }
    }

    #[test]
    fn classifies_all_drift_kinds() {
        let states = BTreeMap::from([
            (
                "missing".into(),
                state(Some("1.0.0"), Some("1.0.0"), None, None),
            ),
            (
                "unexpected".into(),
                state(None, Some("1.0.0"), Some("1.0.0"), None),
            ),
            (
                "version".into(),
                state(
                    Some("2.0.0"),
                    Some("2.0.0"),
                    Some("1.0.0"),
                    Some(ObservedHealth::Healthy),
                ),
            ),
            (
                "unhealthy".into(),
                state(
                    Some("1.0.0"),
                    Some("1.0.0"),
                    Some("1.0.0"),
                    Some(ObservedHealth::Unhealthy),
                ),
            ),
        ]);

        let drift = classify(&states);

        assert_eq!(
            drift
                .iter()
                .map(|drift| (drift.product.as_str(), drift.kind))
                .collect::<Vec<_>>(),
            [
                ("missing", DriftKind::Missing),
                ("unexpected", DriftKind::Unexpected),
                ("unhealthy", DriftKind::Health),
                ("version", DriftKind::Version),
            ]
        );
    }

    #[test]
    fn failed_observation_is_not_evidence_of_absence() {
        let states = BTreeMap::from([(
            "api".into(),
            ProductState {
                desired_version: Some("1.0.0".into()),
                last_applied_version: Some("1.0.0".into()),
                observed_version: None,
                observed_health: None,
                observation_succeeded: false,
            },
        )]);

        assert!(classify(&states).is_empty());
    }

    #[test]
    fn unknown_deployment_state_remains_visible_without_an_observation() {
        let properties = HashMap::from([
            ("deployment_health.api".into(), "unknown".into()),
            ("deployment_error.api".into(), "recovery required".into()),
        ]);

        let states = states_from_properties(&properties, &BTreeMap::new());

        assert!(states.contains_key("api"));
        assert!(classify(&states).is_empty());
    }

    #[test]
    fn version_and_health_drift_are_both_reported() {
        let states = BTreeMap::from([(
            "api".into(),
            state(
                Some("2.0.0"),
                Some("2.0.0"),
                Some("1.0.0"),
                Some(ObservedHealth::Unhealthy),
            ),
        )]);

        assert_eq!(
            classify(&states)
                .iter()
                .map(|drift| drift.kind)
                .collect::<Vec<_>>(),
            [DriftKind::Version, DriftKind::Health]
        );
    }
}

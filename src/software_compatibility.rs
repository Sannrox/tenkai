//! Signed software requirements and content-bound environment preflight evidence.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Contract requirements use same-major semantic versions at or above the minimum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityProfile {
    pub version: u32,
    pub components: BTreeMap<String, ComponentRequirement>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub facts: BTreeMap<String, String>,
    pub schema: Option<SchemaRequirement>,
    pub max_evidence_age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentRequirement {
    pub pin: ComponentPin,
    #[serde(default)]
    pub requires: BTreeMap<String, String>,
    #[serde(default)]
    pub provides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ComponentPin {
    Revision(String),
    Digest(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaRequirement {
    pub minimum: u64,
    pub maximum: u64,
    pub migration: MigrationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    Stable,
    Pending,
}

/// Observations describe the candidate's constituents and installed dependencies.
/// The environment owner supplies this evidence; it grants no execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub version: u32,
    pub release_digest: String,
    pub environment: String,
    pub observed_at_ms: i64,
    pub components: BTreeMap<String, ComponentObservation>,
    pub contracts: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub schema_version: Option<u64>,
    pub migration: MigrationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentObservation {
    pub pin: ComponentPin,
    #[serde(default)]
    pub requires: BTreeMap<String, String>,
    pub provides: BTreeMap<String, String>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum CompatibilityFailure {
    MissingEvidence,
    InvalidEvidence,
    AmbiguousEvidence,
    PreflightUnavailable,
    AmbiguousComponent { component: String },
    ReleaseBinding,
    EnvironmentBinding,
    StaleEvidence,
    MissingComponent { component: String },
    ComponentChanged { component: String },
    MissingCapability { capability: String },
    UnsatisfiedFact { fact: String },
    MissingContract { contract: String },
    AmbiguousContract { contract: String },
    IncompatibleContract { contract: String },
    UnsupportedSchema,
    MigrationState,
}

/// Public reports contain requirement identifiers, never observed facts or payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CompatibilityReport {
    pub version: u32,
    pub release_digest: String,
    pub failures: Vec<CompatibilityFailure>,
}

impl CompatibilityProfile {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.components.is_empty() || self.components.len() > 128 {
            bail!("software compatibility requires version 1 and 1..128 components");
        }
        if self.max_evidence_age_ms == 0 || self.max_evidence_age_ms > 86_400_000 {
            bail!("software compatibility evidence age must be 1..86400000 milliseconds");
        }
        for (name, component) in &self.components {
            validate_identifier(name)?;
            component.pin.validate()?;
            validate_contracts(&component.requires)?;
            validate_contracts(&component.provides)?;
        }
        if self.capabilities.len() > 128 || self.facts.len() > 128 {
            bail!("too many software compatibility requirements");
        }
        for capability in &self.capabilities {
            validate_identifier(capability)?;
        }
        for (key, value) in &self.facts {
            crate::environment::validate_fact_key(key)?;
            crate::environment::validate_fact_value(key, value)?;
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                bail!("invalid software compatibility fact requirement");
            }
        }
        if self
            .schema
            .as_ref()
            .is_some_and(|schema| schema.minimum > schema.maximum)
        {
            bail!("software compatibility schema minimum exceeds maximum");
        }
        Ok(())
    }
}

impl ComponentPin {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Digest(value) => {
                let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
                    hex.len() == 64
                        && hex
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                });
                if !valid {
                    bail!("component digest must be canonical sha256");
                }
            }
            Self::Revision(value) => {
                if !matches!(value.len(), 40 | 64)
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    bail!("component revision must be an immutable hexadecimal source revision");
                }
            }
        }
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("invalid software compatibility identifier");
    }
    Ok(())
}

fn validate_contracts(contracts: &BTreeMap<String, String>) -> Result<()> {
    if contracts.len() > 128 {
        bail!("too many software contracts");
    }
    for (name, version) in contracts {
        validate_identifier(name)?;
        let parsed = semver::Version::parse(version)?;
        if !parsed.pre.is_empty() || !parsed.build.is_empty() {
            bail!("software contract versions must be stable semantic versions");
        }
    }
    Ok(())
}

/// Evaluate in sorted component/contract order so identical evidence yields identical reports.
pub fn evaluate(
    profile: &CompatibilityProfile,
    release_digest: &str,
    environment: &str,
    evidence: Option<&CompatibilityEvidence>,
    facts: &BTreeMap<String, String>,
    now_ms: i64,
) -> Result<CompatibilityReport> {
    profile.validate()?;
    let mut report = CompatibilityReport {
        version: 1,
        release_digest: release_digest.into(),
        failures: Vec::new(),
    };
    let Some(evidence) = evidence else {
        report.failures.push(CompatibilityFailure::MissingEvidence);
        return Ok(report);
    };
    if evidence.version != 1
        || evidence.capabilities.len() > 128
        || evidence.components.len() > 128
        || validate_contracts(&evidence.contracts).is_err()
        || evidence.components.iter().any(|(name, component)| {
            validate_identifier(name).is_err()
                || component.pin.validate().is_err()
                || validate_contracts(&component.provides).is_err()
                || validate_contracts(&component.requires).is_err()
        })
        || evidence
            .capabilities
            .iter()
            .any(|name| validate_identifier(name).is_err())
    {
        report.failures.push(CompatibilityFailure::InvalidEvidence);
        return Ok(report);
    }
    if evidence.environment != environment {
        report
            .failures
            .push(CompatibilityFailure::EnvironmentBinding);
    }
    if evidence.release_digest != release_digest {
        report.failures.push(CompatibilityFailure::ReleaseBinding);
    }
    if evidence.observed_at_ms <= 0
        || evidence.observed_at_ms > now_ms
        || now_ms.saturating_sub(evidence.observed_at_ms) as u64 > profile.max_evidence_age_ms
    {
        report.failures.push(CompatibilityFailure::StaleEvidence);
    }
    let mut contracts: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, version) in &evidence.contracts {
        contracts.entry(name).or_default().push(version);
    }
    for component in evidence.components.values() {
        for (name, version) in &component.provides {
            contracts.entry(name).or_default().push(version);
        }
    }
    for (name, required) in &profile.components {
        match evidence.components.get(name) {
            None => report
                .failures
                .push(CompatibilityFailure::MissingComponent {
                    component: name.clone(),
                }),
            Some(observed) => {
                if observed.pin != required.pin
                    || observed.provides != required.provides
                    || observed.requires != required.requires
                {
                    report
                        .failures
                        .push(CompatibilityFailure::ComponentChanged {
                            component: name.clone(),
                        });
                }
            }
        }
        check_contracts(&required.requires, &contracts, &mut report.failures)?;
    }
    // Retained observations constrain the proposed final component set too.
    for (name, component) in &evidence.components {
        if !profile.components.contains_key(name) {
            check_contracts(&component.requires, &contracts, &mut report.failures)?;
        }
    }
    let mut capabilities = profile.capabilities.clone();
    capabilities.sort();
    capabilities.dedup();
    for capability in capabilities {
        if !evidence.capabilities.contains(&capability) {
            report
                .failures
                .push(CompatibilityFailure::MissingCapability { capability });
        }
    }
    for (fact, expected) in &profile.facts {
        if facts.get(fact) != Some(expected) {
            report
                .failures
                .push(CompatibilityFailure::UnsatisfiedFact { fact: fact.clone() });
        }
    }
    if let Some(schema) = &profile.schema {
        if !evidence
            .schema_version
            .is_some_and(|version| version >= schema.minimum && version <= schema.maximum)
        {
            report
                .failures
                .push(CompatibilityFailure::UnsupportedSchema);
        }
        if evidence.migration != schema.migration {
            report.failures.push(CompatibilityFailure::MigrationState);
        }
    }
    Ok(report)
}

fn check_contracts(
    requirements: &BTreeMap<String, String>,
    contracts: &BTreeMap<&str, Vec<&str>>,
    failures: &mut Vec<CompatibilityFailure>,
) -> Result<()> {
    for (contract, minimum) in requirements {
        let failure = match contracts.get(contract.as_str()).map(Vec::as_slice) {
            None | Some([]) => Some(CompatibilityFailure::MissingContract {
                contract: contract.clone(),
            }),
            Some([provided]) => {
                let actual = semver::Version::parse(provided)?;
                let minimum = semver::Version::parse(minimum)?;
                (actual.major != minimum.major || actual < minimum).then(|| {
                    CompatibilityFailure::IncompatibleContract {
                        contract: contract.clone(),
                    }
                })
            }
            Some(_) => Some(CompatibilityFailure::AmbiguousContract {
                contract: contract.clone(),
            }),
        };
        if let Some(failure) = failure {
            failures.push(failure);
        }
    }
    Ok(())
}

/// Refusal retains the structured report across application error boundaries.
#[derive(Debug, thiserror::Error)]
#[error("software compatibility blocked: {report:?}")]
pub struct CompatibilityBlocked {
    pub report: CompatibilityReport,
}

pub(crate) const EVIDENCE_KIND: &str = "tenkai.software_compatibility_evidence";

/// Persist immutable, environment-scoped observations without changing deployment state.
pub async fn record_evidence(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    evidence: CompatibilityEvidence,
) -> Result<()> {
    crate::environment::environment(ctx, environment).await?;
    if evidence.environment != environment {
        bail!("software compatibility evidence environment mismatch");
    }
    let now = crate::now_millis();
    if evidence.version != 1 || evidence.observed_at_ms <= 0 || evidence.observed_at_ms > now {
        bail!("invalid software compatibility evidence version or observation time");
    }
    if evidence.release_digest.len() != 64
        || !evidence
            .release_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("software compatibility evidence needs a canonical release manifest digest");
    }
    let raw = serde_json::to_string(&evidence)?;
    if raw.len() > 64 * 1024 {
        bail!("software compatibility evidence exceeds 64 KiB");
    }
    // Validate all identifiers and versions before storing supplied observations.
    if evidence.components.len() > 128 || evidence.capabilities.len() > 128 {
        bail!("too many software compatibility observations");
    }
    validate_contracts(&evidence.contracts)?;
    for (name, component) in &evidence.components {
        validate_identifier(name)?;
        component.pin.validate()?;
        validate_contracts(&component.requires)?;
        validate_contracts(&component.provides)?;
    }
    for name in &evidence.capabilities {
        validate_identifier(name)?;
    }
    let identity = format!("{:x}", Sha256::digest(raw.as_bytes()));
    let record = crate::pb::sekai::Object {
        id: format!("tenkai:software-compatibility:{environment}:{identity}"),
        kind: EVIDENCE_KIND.into(),
        namespace: crate::ontology::NS.into(),
        name: identity,
        properties: std::collections::HashMap::from([
            ("environment".into(), environment.into()),
            ("release_digest".into(), evidence.release_digest),
            (
                "observed_at_order".into(),
                format!("{:020}", evidence.observed_at_ms),
            ),
            ("evidence".into(), raw),
        ]),
        created: now,
        updated: now,
        ..Default::default()
    };
    match ctx.create_once(record).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => Ok(()),
        Err(status) => Err(status.into()),
    }
}

/// Read the newest observation for this exact release; equal-time conflicts fail closed.
pub async fn report(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    release: &str,
) -> Result<Option<CompatibilityReport>> {
    let release = if release.starts_with("tenkai:release:") {
        release.to_string()
    } else {
        let (product, version) = release
            .split_once('@')
            .context("expected product@version")?;
        crate::ontology::validate_identifier("product", product)?;
        crate::ontology::validate_identifier("version", version)?;
        crate::ontology::release_id(product, version)
    };
    let object = ctx
        .get(&release)
        .await?
        .context("compatibility release not found")?;
    let raw = object
        .properties
        .get("manifest")
        .context("compatibility release has no manifest")?;
    let manifest = crate::manifest::parse_raw(raw)?;
    let digest = crate::manifest::digest(raw);
    if object.properties.get("digest") != Some(&digest) {
        bail!("software compatibility release manifest digest changed");
    }
    report_manifest(ctx, environment, &manifest, &digest).await
}

pub(crate) async fn report_manifest(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    manifest: &crate::manifest::Manifest,
    digest: &str,
) -> Result<Option<CompatibilityReport>> {
    let Some(profile) = &manifest.compatibility else {
        return Ok(None);
    };
    let facts = crate::environment::list_environment_facts(ctx, environment).await?;
    let records = ctx
        .find_by_property_matching(crate::embedded::PropertyIndexQuery {
            equals_key: Some("release_digest"),
            equals_value: Some(digest),
            ..crate::embedded::PropertyIndexQuery::new(EVIDENCE_KIND, "environment", environment)
        })
        .await?;
    let mut observations = Vec::new();
    for record in records {
        let Some(raw) = record.properties.get("evidence") else {
            return Ok(Some(CompatibilityReport {
                version: 1,
                release_digest: digest.into(),
                failures: vec![CompatibilityFailure::InvalidEvidence],
            }));
        };
        let identity = format!("{:x}", Sha256::digest(raw.as_bytes()));
        if record.id != format!("tenkai:software-compatibility:{environment}:{identity}") {
            return Ok(Some(CompatibilityReport {
                version: 1,
                release_digest: digest.into(),
                failures: vec![CompatibilityFailure::InvalidEvidence],
            }));
        }
        match serde_json::from_str::<CompatibilityEvidence>(raw) {
            Ok(evidence) => observations.push(evidence),
            Err(_) => {
                return Ok(Some(CompatibilityReport {
                    version: 1,
                    release_digest: digest.into(),
                    failures: vec![CompatibilityFailure::InvalidEvidence],
                }));
            }
        }
    }
    observations.sort_by_key(|evidence| evidence.observed_at_ms);
    if observations.len() > 1
        && observations[observations.len() - 1].observed_at_ms
            == observations[observations.len() - 2].observed_at_ms
    {
        return Ok(Some(CompatibilityReport {
            version: 1,
            release_digest: digest.into(),
            failures: vec![CompatibilityFailure::AmbiguousEvidence],
        }));
    }
    let now = crate::now_millis();
    let mut result = evaluate(
        profile,
        digest,
        environment,
        observations.last(),
        &facts,
        now,
    )?;
    let env = crate::environment::environment(ctx, environment).await?;
    let mut installed: Vec<_> = env
        .properties
        .iter()
        .filter_map(|(key, version)| {
            key.strip_prefix("deployed.")
                .map(|product| (product.to_string(), version.clone()))
        })
        .collect();
    installed.sort();
    let mut names: std::collections::BTreeSet<_> = profile.components.keys().cloned().collect();
    for (product, version) in installed {
        if product == manifest.product.name {
            continue;
        }
        let release = crate::ontology::release_id(&product, &version);
        let snapshot =
            crate::catalog::load_recoverable_snapshot(ctx, &release, environment).await?;
        let raw = snapshot
            .object
            .properties
            .get("manifest")
            .context("installed release has no manifest")?;
        let installed_manifest = crate::manifest::parse_raw(raw)?;
        let Some(installed_profile) = &installed_manifest.compatibility else {
            continue;
        };
        for name in installed_profile.components.keys() {
            if !names.insert(name.clone()) {
                result
                    .failures
                    .push(CompatibilityFailure::AmbiguousComponent {
                        component: name.clone(),
                    });
            }
        }
        let retained = evaluate(
            installed_profile,
            digest,
            environment,
            observations.last(),
            &facts,
            now,
        )?;
        result.failures.extend(retained.failures);
    }
    result.failures.sort();
    result.failures.dedup();
    Ok(Some(result))
}

pub(crate) async fn require_release(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    release: &str,
) -> Result<()> {
    if let Some(report) = report(ctx, environment, release).await?
        && !report.failures.is_empty()
    {
        return Err(CompatibilityBlocked { report }.into());
    }
    Ok(())
}

pub(crate) async fn require_manifest(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    manifest: &crate::manifest::Manifest,
    digest: &str,
) -> Result<()> {
    let report = report_manifest(ctx, environment, manifest, digest)
        .await
        .map_err(|_| CompatibilityBlocked {
            report: CompatibilityReport {
                version: 1,
                release_digest: digest.into(),
                failures: vec![CompatibilityFailure::PreflightUnavailable],
            },
        })?;
    if let Some(report) = report
        && !report.failures.is_empty()
    {
        return Err(CompatibilityBlocked { report }.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CompatibilityProfile, CompatibilityEvidence) {
        let pin = ComponentPin::Digest(format!("sha256:{}", "a".repeat(64)));
        let profile = CompatibilityProfile {
            version: 1,
            components: BTreeMap::from([(
                "web".into(),
                ComponentRequirement {
                    pin: pin.clone(),
                    requires: BTreeMap::from([("database".into(), "1.2.0".into())]),
                    provides: BTreeMap::new(),
                },
            )]),
            capabilities: vec!["containers".into()],
            facts: BTreeMap::new(),
            schema: Some(SchemaRequirement {
                minimum: 2,
                maximum: 4,
                migration: MigrationState::Stable,
            }),
            max_evidence_age_ms: 100,
        };
        let evidence = CompatibilityEvidence {
            version: 1,
            release_digest: "a".repeat(64),
            environment: "test".into(),
            observed_at_ms: 1_000,
            components: BTreeMap::from([(
                "web".into(),
                ComponentObservation {
                    pin,
                    requires: BTreeMap::from([("database".into(), "1.2.0".into())]),
                    provides: BTreeMap::new(),
                },
            )]),
            contracts: BTreeMap::from([("database".into(), "1.3.0".into())]),
            capabilities: vec!["containers".into()],
            schema_version: Some(3),
            migration: MigrationState::Stable,
        };
        (profile, evidence)
    }

    #[test]
    fn compatibility_refusals_cover_content_freshness_and_requirements() {
        let (profile, original) = fixture();
        let report = |evidence: &CompatibilityEvidence| {
            evaluate(
                &profile,
                &original.release_digest,
                "test",
                Some(evidence),
                &BTreeMap::new(),
                1_050,
            )
            .unwrap()
        };
        assert!(report(&original).failures.is_empty());
        let cases = [
            (
                "capability",
                CompatibilityFailure::MissingCapability {
                    capability: "containers".into(),
                },
            ),
            (
                "contract",
                CompatibilityFailure::IncompatibleContract {
                    contract: "database".into(),
                },
            ),
            ("schema", CompatibilityFailure::UnsupportedSchema),
            (
                "digest",
                CompatibilityFailure::ComponentChanged {
                    component: "web".into(),
                },
            ),
            (
                "requirements",
                CompatibilityFailure::ComponentChanged {
                    component: "web".into(),
                },
            ),
            ("stale", CompatibilityFailure::StaleEvidence),
            ("release", CompatibilityFailure::ReleaseBinding),
            ("environment", CompatibilityFailure::EnvironmentBinding),
        ];
        for (case, expected) in cases {
            let mut evidence = original.clone();
            match case {
                "capability" => evidence.capabilities.clear(),
                "contract" => {
                    evidence.contracts.insert("database".into(), "2.0.0".into());
                }
                "requirements" => evidence.components.get_mut("web").unwrap().requires.clear(),
                "schema" => evidence.schema_version = Some(5),
                "digest" => {
                    evidence.components.get_mut("web").unwrap().pin =
                        ComponentPin::Digest(format!("sha256:{}", "b".repeat(64)))
                }
                "stale" => evidence.observed_at_ms = 900,
                "release" => evidence.release_digest = "b".repeat(64),
                "environment" => evidence.environment = "other".into(),
                _ => unreachable!(),
            }
            assert_eq!(report(&evidence).failures, vec![expected], "{case}");
        }
    }

    #[test]
    fn retained_dependents_and_ambiguous_providers_fail_closed() {
        let (profile, mut evidence) = fixture();
        evidence.components.insert(
            "retained".into(),
            ComponentObservation {
                pin: ComponentPin::Revision("a".repeat(40)),
                provides: BTreeMap::new(),
                requires: BTreeMap::from([("database".into(), "2.0.0".into())]),
            },
        );
        let report = evaluate(
            &profile,
            &evidence.release_digest,
            "test",
            Some(&evidence),
            &BTreeMap::new(),
            1_050,
        )
        .unwrap();
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::IncompatibleContract {
                contract: "database".into()
            }]
        );
        evidence
            .components
            .get_mut("retained")
            .unwrap()
            .provides
            .insert("database".into(), "1.3.0".into());
        let report = evaluate(
            &profile,
            &evidence.release_digest,
            "test",
            Some(&evidence),
            &BTreeMap::new(),
            1_050,
        )
        .unwrap();
        assert!(
            report
                .failures
                .iter()
                .all(|failure| matches!(failure, CompatibilityFailure::AmbiguousContract { .. }))
        );
    }

    async fn publish_fixture(
        ctx: &mut crate::client::Ctx,
        root: &std::path::Path,
        version: &str,
        max_age_ms: u64,
    ) -> (CompatibilityEvidence, std::path::PathBuf) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut profile, mut evidence) = fixture();
        profile.max_evidence_age_ms = max_age_ms;
        let database = ComponentRequirement {
            pin: ComponentPin::Revision("b".repeat(40)),
            requires: BTreeMap::new(),
            provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
        };
        evidence.components.insert(
            "database".into(),
            ComponentObservation {
                pin: database.pin.clone(),
                requires: database.requires.clone(),
                provides: database.provides.clone(),
            },
        );
        evidence.contracts.clear();
        profile.components.insert("database".into(), database);
        let mut manifest = crate::manifest::parse_raw(&format!("[product]\nname = \"compat-app\"\nversion = \"{version}\"\n[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n")).unwrap();
        manifest.compatibility = Some(profile);
        let raw = toml::to_string(&manifest).unwrap();
        let path = dir.join("tenkai.toml");
        std::fs::write(&path, &raw).unwrap();
        let signature = dir.join("signature.json");
        let roots = dir.join("trust.toml");
        crate::dev_sign::sign_release(&root.join("keys"), &path, &signature, &roots).unwrap();
        crate::catalog::publish(
            ctx,
            &path,
            &crate::catalog::PublishOptions {
                signature: Some(signature),
                trust_roots: Some(roots),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        evidence.release_digest = crate::manifest::digest(&raw);
        evidence.environment = "local".into();
        evidence.observed_at_ms =
            crate::now_millis() - if max_age_ms < 50_000 { 0 } else { 50_000 };
        (evidence, path)
    }

    fn execution_options(
        executor: std::sync::Arc<crate::software_executor::FakeSoftwareExecutor>,
    ) -> crate::apply::ExecutionOptions<'static> {
        crate::apply::ExecutionOptions {
            skip_gates: true,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                reason: "compatibility lifecycle fixture",
            },
            software_executor: Some(executor),
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
            delivery_fence: None,
        }
    }

    #[tokio::test]
    async fn signed_software_lifecycle_rechecks_preflight_before_any_executor_mutation() {
        for case in [
            "compatible",
            "capability",
            "contract",
            "schema",
            "digest",
            "stale",
        ] {
            let root =
                std::env::temp_dir().join(format!("tenkai-compatibility-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let mut ctx = crate::client::Ctx::embedded(root.join("state.db")).unwrap();
            crate::ontology::register(&mut ctx).await.unwrap();
            crate::environment::env_add(&mut ctx, "local", "fixture")
                .await
                .unwrap();
            let (original, path) = publish_fixture(
                &mut ctx,
                &root,
                "1.0.0",
                if case == "stale" { 2_000 } else { 100_000 },
            )
            .await;
            let actor = crate::auth_context::test_management_context("compatibility-test");
            crate::catalog::promote(&mut ctx, &actor, "compat-app@1.0.0", "stable")
                .await
                .unwrap();
            crate::environment::subscribe(&mut ctx, "local", "compat-app", "stable")
                .await
                .unwrap();
            record_evidence(&mut ctx, "local", original.clone())
                .await
                .unwrap();
            let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
            let executor =
                std::sync::Arc::new(crate::software_executor::FakeSoftwareExecutor::new());
            let runtime = if case != "compatible" {
                let reconciler = std::sync::Arc::new(
                    crate::reconciler::Reconciler::new(
                        ctx.clone(),
                        crate::reconciler::Config::default(),
                    )
                    .unwrap(),
                );
                let store = std::sync::Arc::new(
                    crate::storage::SqliteStore::open(root.join("state.db")).unwrap(),
                );
                let operations = crate::runtime_delivery::RuntimeDeliveryOperations::new(
                    std::collections::HashMap::from([("fixture-runtime".into(), "local".into())]),
                    reconciler,
                    store,
                );
                let work = operations
                    .claim_work(Some("fixture-runtime"), Some("fixture-instance"), "local")
                    .await
                    .unwrap();
                let claim = work.claim.unwrap();
                Some((operations, claim))
            } else {
                None
            };
            let mut evidence = original.clone();
            evidence.observed_at_ms += 1_000;
            let expected = match case {
                "capability" => {
                    evidence.capabilities.clear();
                    Some(CompatibilityFailure::MissingCapability {
                        capability: "containers".into(),
                    })
                }
                "contract" => {
                    evidence
                        .components
                        .get_mut("database")
                        .unwrap()
                        .provides
                        .insert("database".into(), "2.0.0".into());
                    Some(CompatibilityFailure::IncompatibleContract {
                        contract: "database".into(),
                    })
                }
                "schema" => {
                    evidence.schema_version = Some(5);
                    Some(CompatibilityFailure::UnsupportedSchema)
                }
                "digest" => {
                    evidence.components.get_mut("web").unwrap().pin =
                        ComponentPin::Digest(format!("sha256:{}", "c".repeat(64)));
                    Some(CompatibilityFailure::ComponentChanged {
                        component: "web".into(),
                    })
                }
                "stale" => {
                    let deadline = original.observed_at_ms + 2_001;
                    let remaining = deadline.saturating_sub(crate::now_millis()).max(0) as u64;
                    tokio::time::sleep(std::time::Duration::from_millis(remaining)).await;
                    Some(CompatibilityFailure::StaleEvidence)
                }
                _ => None,
            };
            if case != "stale" {
                record_evidence(&mut ctx, "local", evidence).await.unwrap();
            }
            if let Some(expected) = expected {
                let (operations, claim) = runtime.unwrap();
                assert!(
                    operations
                        .claim_work(Some("fixture-runtime"), Some("fixture-instance"), "local")
                        .await
                        .is_err(),
                    "{case}"
                );
                assert!(
                    operations
                        .renew(
                            Some("fixture-runtime"),
                            Some("fixture-instance"),
                            "local",
                            &crate::runtime_delivery::RuntimeHeartbeat {
                                plan_id: plan.id.clone(),
                                generation: claim.generation
                            }
                        )
                        .await
                        .is_err(),
                    "{case}"
                );
                let report = report(&mut ctx, "local", "compat-app@1.0.0")
                    .await
                    .unwrap()
                    .unwrap();
                assert!(report.failures.contains(&expected), "{case}: {report:?}");
                let error = crate::plan::create(&mut ctx, "local").await.unwrap_err();
                assert!(
                    error.downcast_ref::<CompatibilityBlocked>().is_some(),
                    "{case}: {error}"
                );
                let error = crate::apply::execute_with_options(
                    &mut ctx,
                    &plan.id,
                    execution_options(executor.clone()),
                )
                .await
                .unwrap_err();
                assert!(
                    error.downcast_ref::<CompatibilityBlocked>().is_some(),
                    "{case}: {error}"
                );
                assert!(executor.applied_keys().is_empty(), "{case}");
            } else {
                let outcomes = crate::apply::execute_with_options(
                    &mut ctx,
                    &plan.id,
                    execution_options(executor.clone()),
                )
                .await
                .unwrap();
                assert!(outcomes.iter().all(|outcome| outcome.status == "succeeded"));
                assert_eq!(executor.applied_keys().len(), 1);
                // Compatibility metadata is signed: changing it cannot reuse the signature.
                let raw = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("100000", "99999");
                std::fs::write(&path, raw).unwrap();
                assert!(
                    crate::catalog::publish(
                        &mut ctx,
                        &path,
                        &crate::catalog::PublishOptions {
                            signature: Some(path.with_file_name("signature.json")),
                            trust_roots: Some(path.with_file_name("trust.toml")),
                            ..Default::default()
                        }
                    )
                    .await
                    .is_err()
                );
            }
            drop(ctx);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn rollback_rechecks_the_previous_release_against_current_schema() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-compatibility-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = crate::client::Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("compatibility-test");
        let executor = std::sync::Arc::new(crate::software_executor::FakeSoftwareExecutor::new());
        let mut previous = None;
        for version in ["1.0.0", "1.1.0"] {
            let (evidence, _) = publish_fixture(&mut ctx, &root, version, 100_000).await;
            if previous.is_none() {
                previous = Some(evidence.clone());
            }
            record_evidence(&mut ctx, "local", evidence).await.unwrap();
            crate::catalog::promote(&mut ctx, &actor, &format!("compat-app@{version}"), "stable")
                .await
                .unwrap();
            crate::environment::subscribe(&mut ctx, "local", "compat-app", "stable")
                .await
                .unwrap();
            let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
            crate::apply::execute_with_options(
                &mut ctx,
                &plan.id,
                execution_options(executor.clone()),
            )
            .await
            .unwrap();
        }
        let step = crate::plan::rollback_step(&mut ctx, "local", "compat-app")
            .await
            .unwrap();
        let plan = crate::plan::create_from_steps(&mut ctx, "local", vec![step])
            .await
            .unwrap();
        let mut evidence = previous.unwrap();
        evidence.observed_at_ms += 1_000;
        evidence.schema_version = Some(10);
        record_evidence(&mut ctx, "local", evidence).await.unwrap();
        assert!(
            crate::plan::rollback_step(&mut ctx, "local", "compat-app")
                .await
                .unwrap_err()
                .downcast_ref::<CompatibilityBlocked>()
                .is_some()
        );
        let keys = executor.applied_keys();
        assert!(
            crate::apply::execute_with_options(
                &mut ctx,
                &plan.id,
                execution_options(executor.clone())
            )
            .await
            .unwrap_err()
            .downcast_ref::<CompatibilityBlocked>()
            .is_some()
        );
        assert_eq!(executor.applied_keys(), keys);
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            env.properties
                .get("deployed.compat-app")
                .map(String::as_str),
            Some("1.1.0")
        );
        drop(ctx);
        std::fs::remove_dir_all(root).unwrap();
    }
}

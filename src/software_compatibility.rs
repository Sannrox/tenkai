//! Signed software requirements and content-bound environment preflight evidence.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Contract requirements use same-major semantic versions at or above the minimum.
/// Profile version 2 also requires the minor to match below 1.0 (ADR 0043 §1).
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

/// A contract requirement: a string minimum, or a table with `optional` on profile v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ContractRequirement {
    Minimum(String),
    Detailed {
        minimum: String,
        #[serde(default)]
        optional: bool,
    },
}

impl ContractRequirement {
    pub fn minimum(&self) -> &str {
        match self {
            Self::Minimum(value) | Self::Detailed { minimum: value, .. } => value,
        }
    }

    pub fn optional(&self) -> bool {
        matches!(self, Self::Detailed { optional: true, .. })
    }

    fn is_table_form(&self) -> bool {
        matches!(self, Self::Detailed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentRequirement {
    pub pin: ComponentPin,
    #[serde(default)]
    pub requires: BTreeMap<String, ContractRequirement>,
    #[serde(default)]
    pub provides: BTreeMap<String, String>,
}

impl ComponentRequirement {
    fn required_minimums(&self) -> BTreeMap<String, String> {
        self.requires
            .iter()
            .map(|(name, requirement)| (name.clone(), requirement.minimum().to_string()))
            .collect()
    }
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

/// Public reports contain requirement identifiers, never observed facts or payloads.
// HTTP/CLI JSON keep the CompatibilityReport schema name; satisfied_by is additive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "CompatibilityReport")]
pub struct CompatibilityOutcome {
    pub version: u32,
    pub release_digest: String,
    pub failures: Vec<CompatibilityFailure>,
    /// Required contracts satisfied by a last-successful deployment (`product@version`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub satisfied_by: BTreeMap<String, String>,
}

/// Candidate evaluation plus the unmet required contracts of that profile.
///
/// Kept off [`CompatibilityOutcome`] so adding hold provenance is not a public
/// struct-literal break.
pub(crate) struct CompatibilityEval {
    pub outcome: CompatibilityOutcome,
    pub candidate_unmet: BTreeMap<String, String>,
}

impl From<CompatibilityOutcome> for CompatibilityReport {
    fn from(outcome: CompatibilityOutcome) -> Self {
        Self {
            version: outcome.version,
            release_digest: outcome.release_digest,
            failures: outcome.failures,
        }
    }
}

impl CompatibilityReport {
    fn with_failures(
        release_digest: impl Into<String>,
        failures: Vec<CompatibilityFailure>,
    ) -> Self {
        Self {
            version: 1,
            release_digest: release_digest.into(),
            failures,
        }
    }
}

impl CompatibilityOutcome {
    fn with_failures(
        release_digest: impl Into<String>,
        failures: Vec<CompatibilityFailure>,
    ) -> Self {
        Self {
            version: 1,
            release_digest: release_digest.into(),
            failures,
            satisfied_by: BTreeMap::new(),
        }
    }
}

impl CompatibilityEval {
    fn with_failures(
        release_digest: impl Into<String>,
        failures: Vec<CompatibilityFailure>,
    ) -> Self {
        Self {
            outcome: CompatibilityOutcome::with_failures(release_digest, failures),
            candidate_unmet: BTreeMap::new(),
        }
    }
}

impl From<CompatibilityEval> for CompatibilityOutcome {
    fn from(eval: CompatibilityEval) -> Self {
        eval.outcome
    }
}

impl From<CompatibilityEval> for CompatibilityReport {
    fn from(eval: CompatibilityEval) -> Self {
        eval.outcome.into()
    }
}

/// Last-successful deployments that offer a contract: name -> `(product@version, contract version)`.
type DeployedOffers = BTreeMap<String, Vec<(String, String)>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContractOfferSource<'a> {
    Observed,
    Deployed(&'a str),
}

#[derive(Clone, Copy, Debug)]
struct ContractOffer<'a> {
    version: &'a str,
    source: ContractOfferSource<'a>,
}

impl CompatibilityProfile {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.version, 1 | 2)
            || self.components.is_empty()
            || self.components.len() > 128
        {
            bail!("software compatibility requires version 1 or 2 and 1..128 components");
        }
        if self.max_evidence_age_ms == 0 || self.max_evidence_age_ms > 86_400_000 {
            bail!("software compatibility evidence age must be 1..86400000 milliseconds");
        }
        for (name, component) in &self.components {
            validate_identifier(name)?;
            component.pin.validate()?;
            validate_requirements(self.version, &component.requires)?;
            validate_contracts(&component.provides)?;
        }
        if self.version >= 2 {
            refuse_requirement_cycle(&self.components)?;
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
        validate_contract_version(version)?;
    }
    Ok(())
}

fn validate_requirements(
    profile_version: u32,
    requirements: &BTreeMap<String, ContractRequirement>,
) -> Result<()> {
    if requirements.len() > 128 {
        bail!("too many software contracts");
    }
    for (name, requirement) in requirements {
        validate_identifier(name)?;
        validate_contract_version(requirement.minimum())?;
        if profile_version < 2 && requirement.is_table_form() {
            bail!(
                "table-form contract requirements need [compatibility] version = 2 (contract {name})"
            );
        }
    }
    Ok(())
}

fn validate_contract_version(version: &str) -> Result<()> {
    let parsed = semver::Version::parse(version)?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        bail!("software contract versions must be stable semantic versions");
    }
    Ok(())
}

/// Publication refuses a cycle among this release's own provides/requires.
fn refuse_requirement_cycle(components: &BTreeMap<String, ComponentRequirement>) -> Result<()> {
    let mut providers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, component) in components {
        for contract in component.provides.keys() {
            providers
                .entry(contract.as_str())
                .or_default()
                .push(name.as_str());
        }
    }
    let mut edges: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for (name, component) in components {
        for contract in component.requires.keys() {
            if let Some(targets) = providers.get(contract.as_str()) {
                for target in targets {
                    edges
                        .entry(name.as_str())
                        .or_default()
                        .push((*target, contract.as_str()));
                }
            }
        }
    }
    let mut visiting = Vec::new();
    let mut visiting_set = BTreeMap::new();
    let mut done = BTreeSet::new();
    for name in components.keys() {
        visit_requirement_edge(
            name.as_str(),
            &edges,
            &mut visiting,
            &mut visiting_set,
            &mut done,
        )?;
    }
    Ok(())
}

fn visit_requirement_edge<'a>(
    node: &'a str,
    edges: &BTreeMap<&'a str, Vec<(&'a str, &'a str)>>,
    visiting: &mut Vec<(&'a str, &'a str)>,
    visiting_set: &mut BTreeMap<&'a str, usize>,
    done: &mut BTreeSet<&'a str>,
) -> Result<()> {
    if done.contains(node) {
        return Ok(());
    }
    if let Some(&index) = visiting_set.get(node) {
        let mut cycle: Vec<&str> = visiting[index..].iter().map(|(name, _)| *name).collect();
        cycle.push(node);
        let contracts: Vec<&str> = visiting[index..]
            .iter()
            .map(|(_, contract)| *contract)
            .collect();
        bail!(
            "software compatibility requirement cycle: {} (contracts: {})",
            cycle.join(" -> "),
            contracts.join(", ")
        );
    }
    visiting_set.insert(node, visiting.len());
    if let Some(next) = edges.get(node) {
        for &(target, contract) in next {
            visiting.push((node, contract));
            visit_requirement_edge(target, edges, visiting, visiting_set, done)?;
            visiting.pop();
        }
    }
    visiting_set.remove(node);
    done.insert(node);
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
    evaluate_owned(
        profile,
        release_digest,
        environment,
        evidence,
        facts,
        now_ms,
        None,
        &BTreeMap::new(),
    )
    .map(Into::into)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_owned(
    profile: &CompatibilityProfile,
    release_digest: &str,
    environment: &str,
    evidence: Option<&CompatibilityEvidence>,
    facts: &BTreeMap<String, String>,
    now_ms: i64,
    owned: Option<&BTreeSet<String>>,
    deployed: &DeployedOffers,
) -> Result<CompatibilityEval> {
    profile.validate()?;
    let mut report = CompatibilityOutcome::with_failures(release_digest, Vec::new());
    let mut candidate_unmet = BTreeMap::new();
    let Some(evidence) = evidence else {
        report.failures.push(CompatibilityFailure::MissingEvidence);
        return Ok(CompatibilityEval {
            outcome: report,
            candidate_unmet,
        });
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
        return Ok(CompatibilityEval {
            outcome: report,
            candidate_unmet,
        });
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
    let contracts = contract_offers(Some(evidence), deployed);
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
                    || observed.requires != required.required_minimums()
                {
                    report
                        .failures
                        .push(CompatibilityFailure::ComponentChanged {
                            component: name.clone(),
                        });
                }
            }
        }
        let unmet = check_contracts(
            profile.version,
            &required.requires,
            &contracts,
            &mut report.failures,
            &mut report.satisfied_by,
        )?;
        for (contract, minimum) in unmet {
            candidate_unmet
                .entry(contract)
                .and_modify(|existing| {
                    *existing = stricter_contract_minimum(existing, &minimum);
                })
                .or_insert(minimum);
        }
    }
    // Retained observations constrain the proposed final component set too.
    // Keep every component's provides. Skip requires owned by another profile;
    // that profile is evaluated separately with its optional semantics.
    for (name, component) in &evidence.components {
        if profile.components.contains_key(name) {
            continue;
        }
        if owned.is_some_and(|set| set.contains(name)) {
            continue;
        }
        let retained = component
            .requires
            .iter()
            .map(|(contract, minimum)| {
                (
                    contract.clone(),
                    ContractRequirement::Minimum(minimum.clone()),
                )
            })
            .collect();
        let _ = check_contracts(
            1,
            &retained,
            &contracts,
            &mut report.failures,
            &mut BTreeMap::new(),
        )?;
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
    Ok(CompatibilityEval {
        outcome: report,
        candidate_unmet,
    })
}

fn contract_offers<'a>(
    evidence: Option<&'a CompatibilityEvidence>,
    deployed: &'a DeployedOffers,
) -> BTreeMap<&'a str, Vec<ContractOffer<'a>>> {
    let mut contracts: BTreeMap<&str, Vec<ContractOffer<'_>>> = BTreeMap::new();
    if let Some(evidence) = evidence {
        for (name, version) in &evidence.contracts {
            contracts
                .entry(name.as_str())
                .or_default()
                .push(ContractOffer {
                    version,
                    source: ContractOfferSource::Observed,
                });
        }
        for component in evidence.components.values() {
            for (name, version) in &component.provides {
                contracts
                    .entry(name.as_str())
                    .or_default()
                    .push(ContractOffer {
                        version,
                        source: ContractOfferSource::Observed,
                    });
            }
        }
    }
    for (name, offers) in deployed {
        for (release, version) in offers {
            contracts
                .entry(name.as_str())
                .or_default()
                .push(ContractOffer {
                    version,
                    source: ContractOfferSource::Deployed(release),
                });
        }
    }
    contracts
}

fn add_deployed_provides(
    deployed: &mut DeployedOffers,
    product: &str,
    version: &str,
    profile: &CompatibilityProfile,
) {
    let release = format!("{product}@{version}");
    for component in profile.components.values() {
        for (contract, contract_version) in &component.provides {
            deployed
                .entry(contract.clone())
                .or_default()
                .push((release.clone(), contract_version.clone()));
        }
    }
}

/// Environment-level constraints from an installed profile. Candidate observations
/// no longer restate that product's component pins.
fn check_environment_constraints(
    profile: &CompatibilityProfile,
    evidence: &CompatibilityEvidence,
    facts: &BTreeMap<String, String>,
    failures: &mut Vec<CompatibilityFailure>,
) {
    let mut capabilities = profile.capabilities.clone();
    capabilities.sort();
    capabilities.dedup();
    for capability in capabilities {
        if !evidence.capabilities.contains(&capability) {
            failures.push(CompatibilityFailure::MissingCapability { capability });
        }
    }
    for (fact, expected) in &profile.facts {
        if facts.get(fact) != Some(expected) {
            failures.push(CompatibilityFailure::UnsatisfiedFact { fact: fact.clone() });
        }
    }
    if let Some(schema) = &profile.schema {
        if !evidence
            .schema_version
            .is_some_and(|version| version >= schema.minimum && version <= schema.maximum)
        {
            failures.push(CompatibilityFailure::UnsupportedSchema);
        }
        if evidence.migration != schema.migration {
            failures.push(CompatibilityFailure::MigrationState);
        }
    }
}

fn check_contracts(
    profile_version: u32,
    requirements: &BTreeMap<String, ContractRequirement>,
    contracts: &BTreeMap<&str, Vec<ContractOffer<'_>>>,
    failures: &mut Vec<CompatibilityFailure>,
    satisfied_by: &mut BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut unmet: BTreeMap<String, String> = BTreeMap::new();
    for (contract, requirement) in requirements {
        let offers = contracts.get(contract.as_str()).map(Vec::as_slice);
        let failure = match offers {
            None | Some([]) if requirement.optional() => None,
            None | Some([]) => Some(CompatibilityFailure::MissingContract {
                contract: contract.clone(),
            }),
            Some([provided]) => {
                let actual = semver::Version::parse(provided.version)?;
                let minimum = semver::Version::parse(requirement.minimum())?;
                if !contract_satisfies(profile_version, &actual, &minimum) {
                    Some(CompatibilityFailure::IncompatibleContract {
                        contract: contract.clone(),
                    })
                } else {
                    if let ContractOfferSource::Deployed(release) = provided.source {
                        satisfied_by.insert(contract.clone(), release.to_string());
                    }
                    None
                }
            }
            Some(_) => Some(CompatibilityFailure::AmbiguousContract {
                contract: contract.clone(),
            }),
        };
        if let Some(failure) = failure {
            if !requirement.optional()
                && matches!(
                    failure,
                    CompatibilityFailure::MissingContract { .. }
                        | CompatibilityFailure::IncompatibleContract { .. }
                )
            {
                let minimum = requirement.minimum().to_string();
                unmet
                    .entry(contract.clone())
                    .and_modify(|existing| {
                        *existing = stricter_contract_minimum(existing, &minimum);
                    })
                    .or_insert(minimum);
            }
            failures.push(failure);
        }
    }
    Ok(unmet)
}

pub(crate) fn contract_satisfies(
    profile_version: u32,
    actual: &semver::Version,
    minimum: &semver::Version,
) -> bool {
    if actual.major != minimum.major || actual < minimum {
        return false;
    }
    if profile_version >= 2 && minimum.major == 0 && actual.minor != minimum.minor {
        return false;
    }
    true
}

/// Refusal retains the structured report across application error boundaries.
#[derive(Debug, thiserror::Error)]
#[error("software compatibility blocked: {report:?}")]
pub struct CompatibilityBlocked {
    pub report: CompatibilityReport,
}

/// Candidate-required contracts that are unmet and the only failures on `outcome`.
///
/// Reconcile records a hold for `candidate_unmet` (ADR 0043 §4). That set
/// comes from the candidate profile's own `check_contracts`, so an installed
/// dependent's stricter minimum cannot be mistaken for the candidate's.
/// Any other failure, or a contract failure the candidate does not require,
/// still refuses. Optional requirements never hold.
pub(crate) fn holdable_unmet_requirements(
    outcome: &CompatibilityOutcome,
    candidate_unmet: &BTreeMap<String, String>,
    profile: &CompatibilityProfile,
) -> Option<Vec<(String, String)>> {
    if outcome.failures.is_empty() || candidate_unmet.is_empty() {
        return None;
    }
    let mut required = BTreeSet::new();
    for component in profile.components.values() {
        for (contract, requirement) in &component.requires {
            if !requirement.optional() {
                required.insert(contract.as_str());
            }
        }
    }
    for failure in &outcome.failures {
        match failure {
            CompatibilityFailure::MissingContract { contract }
            | CompatibilityFailure::IncompatibleContract { contract } => {
                if !required.contains(contract.as_str()) {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(
        candidate_unmet
            .iter()
            .map(|(c, m)| (c.clone(), m.clone()))
            .collect(),
    )
}

/// Remaining profiles after overlay must still satisfy every required contract
/// that a Tenkai-deployed provider satisfied before the plan (ADR 0043 §5).
///
/// Optional requirements may be absent. A required contract that had no matching
/// deployed provider before the plan stays on observation rules. The refusal
/// names the dependent product and the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemainingDependentRefusal {
    pub dependent: String,
    pub contract: String,
    pub kind: RemainingDependentKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemainingDependentKind {
    Ambiguous,
    Unsatisfied { minimum: String },
}

/// First remaining dependent that would be unsatisfied or left ambiguous.
pub(crate) fn remaining_dependent_refusal(
    remaining: &BTreeMap<String, CompatibilityProfile>,
    previous: &BTreeMap<String, CompatibilityProfile>,
) -> Result<Option<RemainingDependentRefusal>> {
    for (dependent, profile) in remaining {
        for component in profile.components.values() {
            for (contract, requirement) in &component.requires {
                let matching = matching_deployed_providers(
                    remaining,
                    contract,
                    requirement,
                    profile.version,
                    dependent,
                )?;
                if matching.len() > 1 {
                    return Ok(Some(RemainingDependentRefusal {
                        dependent: dependent.clone(),
                        contract: contract.clone(),
                        kind: RemainingDependentKind::Ambiguous,
                    }));
                }
                if !matching.is_empty() {
                    continue;
                }
                if requirement.optional() {
                    continue;
                }
                let before = matching_deployed_providers(
                    previous,
                    contract,
                    requirement,
                    profile.version,
                    dependent,
                )?;
                if before.is_empty() {
                    continue;
                }
                return Ok(Some(RemainingDependentRefusal {
                    dependent: dependent.clone(),
                    contract: contract.clone(),
                    kind: RemainingDependentKind::Unsatisfied {
                        minimum: requirement.minimum().to_string(),
                    },
                }));
            }
        }
    }
    Ok(None)
}

pub(crate) fn refuse_unsatisfied_dependents(
    remaining: &BTreeMap<String, CompatibilityProfile>,
    previous: &BTreeMap<String, CompatibilityProfile>,
) -> Result<()> {
    match remaining_dependent_refusal(remaining, previous)? {
        None => Ok(()),
        Some(RemainingDependentRefusal {
            dependent,
            contract,
            kind: RemainingDependentKind::Ambiguous,
        }) => bail!(
            "plan would leave installed dependent {dependent} with ambiguous contract {contract}"
        ),
        Some(RemainingDependentRefusal {
            dependent,
            contract,
            kind: RemainingDependentKind::Unsatisfied { minimum },
        }) => bail!(
            "plan would leave installed dependent {dependent} without required contract {contract} (>={minimum})"
        ),
    }
}

pub(crate) fn matching_deployed_providers(
    profiles: &BTreeMap<String, CompatibilityProfile>,
    contract: &str,
    requirement: &ContractRequirement,
    profile_version: u32,
    dependent: &str,
) -> Result<Vec<String>> {
    let mut matching = Vec::new();
    for (provider, profile) in profiles {
        if provider == dependent {
            continue;
        }
        for component in profile.components.values() {
            let Some(version) = component.provides.get(contract) else {
                continue;
            };
            let actual = semver::Version::parse(version)
                .with_context(|| format!("provided {contract} version {version} on {provider}"))?;
            let minimum = semver::Version::parse(requirement.minimum()).with_context(|| {
                format!(
                    "required {contract} minimum {} on {dependent}",
                    requirement.minimum()
                )
            })?;
            if contract_satisfies(profile_version, &actual, &minimum) {
                matching.push(provider.clone());
                break;
            }
        }
    }
    matching.sort();
    matching.dedup();
    Ok(matching)
}

fn stricter_contract_minimum(left: &str, right: &str) -> String {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left_ver), Ok(right_ver)) if right_ver > left_ver => right.to_string(),
        _ => left.to_string(),
    }
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
    Ok(report_eval(ctx, environment, release)
        .await?
        .map(Into::into))
}

/// Same as [`report`], including which deployed release satisfied each required contract.
pub async fn report_outcome(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    release: &str,
) -> Result<Option<CompatibilityOutcome>> {
    Ok(report_eval(ctx, environment, release)
        .await?
        .map(Into::into))
}

pub(crate) async fn report_eval(
    ctx: &mut crate::client::Ctx,
    environment: &str,
    release: &str,
) -> Result<Option<CompatibilityEval>> {
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
) -> Result<Option<CompatibilityEval>> {
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
            return Ok(Some(CompatibilityEval::with_failures(
                digest,
                vec![CompatibilityFailure::InvalidEvidence],
            )));
        };
        let identity = format!("{:x}", Sha256::digest(raw.as_bytes()));
        if record.id != format!("tenkai:software-compatibility:{environment}:{identity}") {
            return Ok(Some(CompatibilityEval::with_failures(
                digest,
                vec![CompatibilityFailure::InvalidEvidence],
            )));
        }
        match serde_json::from_str::<CompatibilityEvidence>(raw) {
            Ok(evidence) => observations.push(evidence),
            Err(_) => {
                return Ok(Some(CompatibilityEval::with_failures(
                    digest,
                    vec![CompatibilityFailure::InvalidEvidence],
                )));
            }
        }
    }
    observations.sort_by_key(|evidence| evidence.observed_at_ms);
    if observations.len() > 1
        && observations[observations.len() - 1].observed_at_ms
            == observations[observations.len() - 2].observed_at_ms
    {
        return Ok(Some(CompatibilityEval::with_failures(
            digest,
            vec![CompatibilityFailure::AmbiguousEvidence],
        )));
    }
    let now = crate::now_millis();
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
    let mut owned: BTreeSet<String> = profile.components.keys().cloned().collect();
    let mut installed_profiles = Vec::new();
    let mut deployed = DeployedOffers::new();
    let mut ambiguous = Vec::new();
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
        let Some(installed_profile) = installed_manifest.compatibility else {
            continue;
        };
        for name in installed_profile.components.keys() {
            if !owned.insert(name.clone()) {
                ambiguous.push(CompatibilityFailure::AmbiguousComponent {
                    component: name.clone(),
                });
            }
        }
        add_deployed_provides(&mut deployed, &product, &version, &installed_profile);
        installed_profiles.push(installed_profile);
    }
    let mut result = evaluate_owned(
        profile,
        digest,
        environment,
        observations.last(),
        &facts,
        now,
        Some(&owned),
        &deployed,
    )?;
    result.outcome.failures.extend(ambiguous);
    // Deployed releases satisfy contracts from their signed provides. Do not
    // require the candidate observation to re-state those components. Still
    // check each installed profile's requires, schema, capabilities, and facts
    // so a candidate cannot silently unsatisfy a declared dependent.
    // Freshness stays the candidate profile's max_evidence_age_ms: deployed
    // provides do not expire (ADR 0043 §2), so an installed profile's evidence
    // age bound is not applied to another release's observation.
    let offers = contract_offers(observations.last(), &deployed);
    for installed_profile in &installed_profiles {
        if let Some(evidence) = observations.last() {
            check_environment_constraints(
                installed_profile,
                evidence,
                &facts,
                &mut result.outcome.failures,
            );
        } else {
            for (fact, expected) in &installed_profile.facts {
                if facts.get(fact) != Some(expected) {
                    result
                        .outcome
                        .failures
                        .push(CompatibilityFailure::UnsatisfiedFact { fact: fact.clone() });
                }
            }
        }
        for component in installed_profile.components.values() {
            let _ = check_contracts(
                installed_profile.version,
                &component.requires,
                &offers,
                &mut result.outcome.failures,
                &mut BTreeMap::new(),
            )?;
        }
    }
    result.outcome.failures.sort();
    result.outcome.failures.dedup();
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
            report: CompatibilityReport::with_failures(
                digest,
                vec![CompatibilityFailure::PreflightUnavailable],
            ),
        })?;
    if let Some(eval) = report
        && !eval.outcome.failures.is_empty()
    {
        return Err(CompatibilityBlocked {
            report: eval.into(),
        }
        .into());
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
                    requires: BTreeMap::from([(
                        "database".into(),
                        ContractRequirement::Minimum("1.2.0".into()),
                    )]),
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

    fn failures(
        profile: &CompatibilityProfile,
        evidence: &CompatibilityEvidence,
    ) -> Vec<CompatibilityFailure> {
        evaluate(
            profile,
            &evidence.release_digest,
            "test",
            Some(evidence),
            &BTreeMap::new(),
            1_050,
        )
        .unwrap()
        .failures
    }

    const V1_STRING_MANIFEST: &str = concat!(
        "[product]\nname = \"compat-app\"\nversion = \"1.0.0\"\n",
        "[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n",
        "[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n",
        "[compatibility.components.web.pin]\nkind = \"revision\"\n",
        "value = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        "[compatibility.components.web.requires]\ndatabase = \"1.2.0\"\n",
    );

    #[test]
    fn v1_string_requirements_parse_validate_and_keep_digest() {
        let digest = crate::manifest::digest(V1_STRING_MANIFEST);
        let manifest = crate::manifest::parse_raw(V1_STRING_MANIFEST).unwrap();
        let profile = manifest.compatibility.as_ref().unwrap();
        profile.validate().unwrap();
        assert_eq!(profile.version, 1);
        assert_eq!(
            profile.components["web"].requires["database"],
            ContractRequirement::Minimum("1.2.0".into())
        );
        assert_eq!(crate::manifest::digest(V1_STRING_MANIFEST), digest);
        let encoded = toml::to_string(&manifest).unwrap();
        assert!(encoded.contains("database = \"1.2.0\""));
        assert!(!encoded.contains("optional"));
    }

    #[test]
    fn v1_refuses_table_form_requirements() {
        let raw = concat!(
            "[product]\nname = \"compat-app\"\nversion = \"1.0.0\"\n",
            "[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n",
            "[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n",
            "[compatibility.components.web.pin]\nkind = \"revision\"\n",
            "value = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "[compatibility.components.web.requires]\n",
            "database = { minimum = \"1.2.0\", optional = true }\n",
        );
        let err = crate::manifest::parse_raw(raw).unwrap_err().to_string();
        assert!(err.contains("version = 2"), "{err}");
        assert!(err.contains("database"), "{err}");
    }

    #[test]
    fn v2_parses_and_signs_string_and_table_requirements() {
        let raw = concat!(
            "[product]\nname = \"compat-app\"\nversion = \"1.0.0\"\n",
            "[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n",
            "[compatibility]\nversion = 2\nmax_evidence_age_ms = 60000\n",
            "[compatibility.components.web.pin]\nkind = \"revision\"\n",
            "value = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "[compatibility.components.web.requires]\n",
            "database = \"1.2.0\"\n",
            "connector = { minimum = \"0.1.0\", optional = true }\n",
        );
        let manifest = crate::manifest::parse_raw(raw).unwrap();
        let profile = manifest.compatibility.as_ref().unwrap();
        profile.validate().unwrap();
        assert_eq!(profile.version, 2);
        assert_eq!(
            profile.components["web"].requires["database"],
            ContractRequirement::Minimum("1.2.0".into())
        );
        assert_eq!(
            profile.components["web"].requires["connector"],
            ContractRequirement::Detailed {
                minimum: "0.1.0".into(),
                optional: true,
            }
        );
        let root = std::env::temp_dir().join(format!(
            "tenkai-compat-v2-sign-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("tenkai.toml");
        std::fs::write(&path, raw).unwrap();
        crate::dev_sign::sign_release(
            &root.join("keys"),
            &path,
            &root.join("signature.json"),
            &root.join("trust.toml"),
        )
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_matching_requires_minor_below_one_and_keeps_same_major_above() {
        let (mut profile, mut evidence) = fixture();
        profile.version = 2;
        profile.components.get_mut("web").unwrap().requires =
            BTreeMap::from([("api".into(), ContractRequirement::Minimum("0.1.0".into()))]);
        evidence.components.get_mut("web").unwrap().requires =
            BTreeMap::from([("api".into(), "0.1.0".into())]);
        evidence.contracts = BTreeMap::from([("api".into(), "0.1.4".into())]);
        assert!(failures(&profile, &evidence).is_empty());

        evidence.contracts.insert("api".into(), "0.2.0".into());
        assert_eq!(
            failures(&profile, &evidence),
            vec![CompatibilityFailure::IncompatibleContract {
                contract: "api".into()
            }]
        );

        profile.components.get_mut("web").unwrap().requires =
            BTreeMap::from([("api".into(), ContractRequirement::Minimum("1.2.0".into()))]);
        evidence.components.get_mut("web").unwrap().requires =
            BTreeMap::from([("api".into(), "1.2.0".into())]);
        evidence.contracts.insert("api".into(), "1.3.0".into());
        assert!(failures(&profile, &evidence).is_empty());
        evidence.contracts.insert("api".into(), "2.0.0".into());
        assert_eq!(
            failures(&profile, &evidence),
            vec![CompatibilityFailure::IncompatibleContract {
                contract: "api".into()
            }]
        );
    }

    #[test]
    fn v2_optional_absent_is_not_missing_and_present_incompatible_fails() {
        let (mut profile, mut evidence) = fixture();
        profile.version = 2;
        profile.components.get_mut("web").unwrap().requires = BTreeMap::from([(
            "connector".into(),
            ContractRequirement::Detailed {
                minimum: "0.1.0".into(),
                optional: true,
            },
        )]);
        evidence.components.get_mut("web").unwrap().requires =
            BTreeMap::from([("connector".into(), "0.1.0".into())]);
        evidence.contracts.clear();
        assert!(failures(&profile, &evidence).is_empty());

        evidence
            .contracts
            .insert("connector".into(), "0.2.0".into());
        assert_eq!(
            failures(&profile, &evidence),
            vec![CompatibilityFailure::IncompatibleContract {
                contract: "connector".into()
            }]
        );
    }

    #[test]
    fn v1_self_requirement_on_a_provided_contract_still_validates() {
        let (mut profile, _) = fixture();
        profile
            .components
            .get_mut("web")
            .unwrap()
            .provides
            .insert("database".into(), "1.3.0".into());
        profile.validate().unwrap();
        profile.version = 2;
        let err = profile.validate().unwrap_err().to_string();
        assert!(err.contains("requirement cycle"), "{err}");
    }

    #[test]
    fn other_owned_components_keep_provides_and_skip_their_requires() {
        let (profile, mut evidence) = fixture();
        evidence.contracts.clear();
        evidence.components.insert(
            "api".into(),
            ComponentObservation {
                pin: ComponentPin::Revision("c".repeat(40)),
                requires: BTreeMap::from([("connector".into(), "0.1.0".into())]),
                provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
            },
        );
        evidence.components.insert(
            "worker".into(),
            ComponentObservation {
                pin: ComponentPin::Revision("d".repeat(40)),
                requires: BTreeMap::from([("queue".into(), "1.0.0".into())]),
                provides: BTreeMap::new(),
            },
        );
        let owned = BTreeSet::from(["web".into(), "api".into()]);
        let report = evaluate_owned(
            &profile,
            &evidence.release_digest,
            "test",
            Some(&evidence),
            &BTreeMap::new(),
            1_050,
            Some(&owned),
            &BTreeMap::new(),
        )
        .unwrap()
        .outcome;
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::MissingContract {
                contract: "queue".into()
            }]
        );
        assert_eq!(
            failures(&profile, &evidence),
            vec![
                CompatibilityFailure::MissingContract {
                    contract: "connector".into()
                },
                CompatibilityFailure::MissingContract {
                    contract: "queue".into()
                }
            ]
        );
    }

    #[test]
    fn publication_refuses_in_release_requirement_cycle() {
        let (mut profile, _) = fixture();
        profile.version = 2;
        profile.components = BTreeMap::from([
            (
                "api".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("a".repeat(40)),
                    requires: BTreeMap::from([(
                        "store".into(),
                        ContractRequirement::Minimum("1.0.0".into()),
                    )]),
                    provides: BTreeMap::from([("api".into(), "1.0.0".into())]),
                },
            ),
            (
                "store".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("b".repeat(40)),
                    requires: BTreeMap::from([(
                        "api".into(),
                        ContractRequirement::Minimum("1.0.0".into()),
                    )]),
                    provides: BTreeMap::from([("store".into(), "1.0.0".into())]),
                },
            ),
        ]);
        let err = profile.validate().unwrap_err().to_string();
        assert!(err.contains("requirement cycle"), "{err}");
        assert!(err.contains("api -> store -> api"), "{err}");
        assert!(err.contains("contracts: store, api"), "{err}");
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

    fn evaluate_with_deployed(
        profile: &CompatibilityProfile,
        evidence: &CompatibilityEvidence,
        deployed: &DeployedOffers,
    ) -> CompatibilityOutcome {
        evaluate_owned(
            profile,
            &evidence.release_digest,
            "test",
            Some(evidence),
            &BTreeMap::new(),
            1_050,
            None,
            deployed,
        )
        .unwrap()
        .outcome
    }

    #[test]
    fn holdable_unmet_is_only_the_candidate_required_contracts() {
        let (profile, evidence) = fixture();
        let digest = evidence.release_digest.clone();
        let missing = CompatibilityOutcome {
            version: 1,
            release_digest: digest.clone(),
            failures: vec![CompatibilityFailure::MissingContract {
                contract: "database".into(),
            }],
            satisfied_by: BTreeMap::new(),
        };
        let missing_unmet = BTreeMap::from([("database".into(), "1.2.0".into())]);
        assert_eq!(
            holdable_unmet_requirements(&missing, &missing_unmet, &profile),
            Some(vec![("database".into(), "1.2.0".into())])
        );
        let mixed = CompatibilityOutcome {
            version: 1,
            release_digest: digest.clone(),
            failures: vec![
                CompatibilityFailure::MissingContract {
                    contract: "database".into(),
                },
                CompatibilityFailure::StaleEvidence,
            ],
            satisfied_by: BTreeMap::new(),
        };
        assert_eq!(
            holdable_unmet_requirements(&mixed, &missing_unmet, &profile),
            None
        );
        let other = CompatibilityOutcome {
            version: 1,
            release_digest: digest,
            failures: vec![CompatibilityFailure::MissingContract {
                contract: "queue".into(),
            }],
            satisfied_by: BTreeMap::new(),
        };
        let other_unmet = BTreeMap::from([("queue".into(), "1.0.0".into())]);
        assert_eq!(
            holdable_unmet_requirements(&other, &other_unmet, &profile),
            None
        );
        let satisfied_elsewhere = CompatibilityOutcome {
            version: 1,
            release_digest: evidence.release_digest.clone(),
            failures: vec![CompatibilityFailure::IncompatibleContract {
                contract: "database".into(),
            }],
            satisfied_by: BTreeMap::from([("database".into(), "compat-db@1.0.0".into())]),
        };
        assert_eq!(
            holdable_unmet_requirements(&satisfied_elsewhere, &BTreeMap::new(), &profile),
            None
        );
        let mut two = profile.clone();
        two.components.insert(
            "api".into(),
            ComponentRequirement {
                pin: ComponentPin::Revision("b".repeat(40)),
                requires: BTreeMap::from([(
                    "database".into(),
                    ContractRequirement::Minimum("1.5.0".into()),
                )]),
                provides: BTreeMap::new(),
            },
        );
        let incompatible = CompatibilityOutcome {
            version: 1,
            release_digest: evidence.release_digest.clone(),
            failures: vec![CompatibilityFailure::IncompatibleContract {
                contract: "database".into(),
            }],
            satisfied_by: BTreeMap::new(),
        };
        let incompatible_unmet = BTreeMap::from([("database".into(), "1.5.0".into())]);
        assert_eq!(
            holdable_unmet_requirements(&incompatible, &incompatible_unmet, &two),
            Some(vec![("database".into(), "1.5.0".into())])
        );
    }

    fn remaining_profile(
        requires: &[(&str, &str, bool)],
        provides: &[(&str, &str)],
    ) -> CompatibilityProfile {
        CompatibilityProfile {
            version: 2,
            components: BTreeMap::from([(
                "main".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("a".repeat(40)),
                    requires: requires
                        .iter()
                        .map(|(contract, minimum, optional)| {
                            (
                                (*contract).into(),
                                if *optional {
                                    ContractRequirement::Detailed {
                                        minimum: (*minimum).into(),
                                        optional: true,
                                    }
                                } else {
                                    ContractRequirement::Minimum((*minimum).into())
                                },
                            )
                        })
                        .collect(),
                    provides: provides
                        .iter()
                        .map(|(contract, version)| ((*contract).into(), (*version).into()))
                        .collect(),
                },
            )]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 60_000,
        }
    }

    #[test]
    fn refuse_unsatisfied_dependents_names_the_dependent() {
        let app = remaining_profile(&[("database", "1.0.0", false)], &[]);
        let db = remaining_profile(&[], &[("database", "1.0.0")]);
        let previous = BTreeMap::from([("app".into(), app.clone()), ("db".into(), db.clone())]);
        let err = refuse_unsatisfied_dependents(
            &BTreeMap::from([("app".into(), app.clone())]),
            &previous,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("installed dependent app"), "{err}");
        assert!(err.contains("database"), "{err}");
        refuse_unsatisfied_dependents(
            &BTreeMap::from([("app".into(), app.clone()), ("db".into(), db.clone())]),
            &previous,
        )
        .unwrap();
        let optional = remaining_profile(&[("database", "1.0.0", true)], &[]);
        refuse_unsatisfied_dependents(
            &BTreeMap::from([("app".into(), optional.clone())]),
            &BTreeMap::from([("app".into(), optional), ("db".into(), db)]),
        )
        .unwrap();
        refuse_unsatisfied_dependents(
            &BTreeMap::from([("app".into(), app.clone())]),
            &BTreeMap::from([("app".into(), app)]),
        )
        .unwrap();
        let high = remaining_profile(&[("database", "2.0.0", false)], &[]);
        let high_db = remaining_profile(&[], &[("database", "2.0.0")]);
        let low = remaining_profile(&[], &[("database", "1.0.0")]);
        let err = refuse_unsatisfied_dependents(
            &BTreeMap::from([("app".into(), high.clone()), ("db".into(), low)]),
            &BTreeMap::from([("app".into(), high), ("db".into(), high_db)]),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("installed dependent app"), "{err}");
        assert!(err.contains("database"), "{err}");
    }

    #[test]
    fn deployed_release_satisfies_requirement_without_observed_contract() {
        let (profile, mut evidence) = fixture();
        evidence.contracts.clear();
        let deployed = BTreeMap::from([(
            "database".into(),
            vec![("compat-db@1.0.0".into(), "1.3.0".into())],
        )]);
        let report = evaluate_with_deployed(&profile, &evidence, &deployed);
        assert!(report.failures.is_empty(), "{report:?}");
        assert_eq!(
            report.satisfied_by.get("database").map(String::as_str),
            Some("compat-db@1.0.0")
        );
    }

    #[test]
    fn deployed_and_observed_contract_is_ambiguous() {
        let (profile, evidence) = fixture();
        let deployed = BTreeMap::from([(
            "database".into(),
            vec![("compat-db@1.0.0".into(), "1.3.0".into())],
        )]);
        let report = evaluate_with_deployed(&profile, &evidence, &deployed);
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::AmbiguousContract {
                contract: "database".into()
            }]
        );
        assert!(report.satisfied_by.is_empty());
    }

    #[test]
    fn two_deployed_providers_of_one_contract_are_ambiguous() {
        let (profile, mut evidence) = fixture();
        evidence.contracts.clear();
        let deployed = BTreeMap::from([(
            "database".into(),
            vec![
                ("compat-db@1.0.0".into(), "1.3.0".into()),
                ("compat-db-b@1.0.0".into(), "1.4.0".into()),
            ],
        )]);
        let report = evaluate_with_deployed(&profile, &evidence, &deployed);
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::AmbiguousContract {
                contract: "database".into()
            }]
        );
    }

    #[test]
    fn unmet_required_contract_is_still_missing() {
        let (profile, mut evidence) = fixture();
        evidence.contracts.clear();
        let report = evaluate_with_deployed(&profile, &evidence, &BTreeMap::new());
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::MissingContract {
                contract: "database".into()
            }]
        );
    }

    #[test]
    fn incompatible_deployed_contract_is_refused() {
        let (profile, mut evidence) = fixture();
        evidence.contracts.clear();
        let deployed = BTreeMap::from([(
            "database".into(),
            vec![("compat-db@1.0.0".into(), "2.0.0".into())],
        )]);
        let report = evaluate_with_deployed(&profile, &evidence, &deployed);
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::IncompatibleContract {
                contract: "database".into()
            }]
        );
    }

    #[test]
    fn two_components_in_one_release_providing_the_same_contract_stay_ambiguous() {
        let (profile, mut evidence) = fixture();
        evidence.contracts.clear();
        let mut deployed = DeployedOffers::new();
        let provider = CompatibilityProfile {
            version: 1,
            components: BTreeMap::from([
                (
                    "primary".into(),
                    ComponentRequirement {
                        pin: ComponentPin::Revision("b".repeat(40)),
                        requires: BTreeMap::new(),
                        provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
                    },
                ),
                (
                    "replica".into(),
                    ComponentRequirement {
                        pin: ComponentPin::Revision("c".repeat(40)),
                        requires: BTreeMap::new(),
                        provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
                    },
                ),
            ]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 100,
        };
        add_deployed_provides(&mut deployed, "compat-db", "1.0.0", &provider);
        let report = evaluate_with_deployed(&profile, &evidence, &deployed);
        assert_eq!(
            report.failures,
            vec![CompatibilityFailure::AmbiguousContract {
                contract: "database".into()
            }]
        );
    }

    #[test]
    fn installed_schema_bounds_still_constrain_the_observation() {
        let (_, mut evidence) = fixture();
        evidence.schema_version = Some(4);
        let mut failures = Vec::new();
        let installed = CompatibilityProfile {
            version: 1,
            components: BTreeMap::from([(
                "store".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("b".repeat(40)),
                    requires: BTreeMap::new(),
                    provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
                },
            )]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: Some(SchemaRequirement {
                minimum: 2,
                maximum: 3,
                migration: MigrationState::Stable,
            }),
            max_evidence_age_ms: 100,
        };
        check_environment_constraints(&installed, &evidence, &BTreeMap::new(), &mut failures);
        assert_eq!(failures, vec![CompatibilityFailure::UnsupportedSchema]);
    }

    #[test]
    fn installed_capability_requirements_still_constrain_the_observation() {
        let (_, mut evidence) = fixture();
        evidence.capabilities.clear();
        let mut failures = Vec::new();
        let installed = CompatibilityProfile {
            version: 1,
            components: BTreeMap::from([(
                "store".into(),
                ComponentRequirement {
                    pin: ComponentPin::Revision("b".repeat(40)),
                    requires: BTreeMap::new(),
                    provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
                },
            )]),
            capabilities: vec!["containers".into()],
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 100,
        };
        check_environment_constraints(&installed, &evidence, &BTreeMap::new(), &mut failures);
        assert_eq!(
            failures,
            vec![CompatibilityFailure::MissingCapability {
                capability: "containers".into()
            }]
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
                requires: database.required_minimums(),
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

    async fn publish_signed_release(
        ctx: &mut crate::client::Ctx,
        root: &std::path::Path,
        product: &str,
        version: &str,
        profile: CompatibilityProfile,
    ) -> String {
        let dir = root.join(format!("{product}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut manifest = crate::manifest::parse_raw(&format!(
            "[product]\nname = \"{product}\"\nversion = \"{version}\"\n[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n"
        ))
        .unwrap();
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
        crate::manifest::digest(&raw)
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
            software_executors: crate::software_executor::SoftwareExecutors::with_default(executor),
            model_runtime_executor: None,
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

    #[tokio::test]
    async fn deployed_provider_satisfies_requirement_across_restart() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-compat-deployed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("state.db");
        let mut ctx = crate::client::Ctx::embedded(&db).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("compatibility-test");
        let executor = std::sync::Arc::new(crate::software_executor::FakeSoftwareExecutor::new());

        let db_pin = ComponentPin::Revision("b".repeat(40));
        let db_profile = CompatibilityProfile {
            version: 1,
            components: BTreeMap::from([(
                "store".into(),
                ComponentRequirement {
                    pin: db_pin.clone(),
                    requires: BTreeMap::new(),
                    provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
                },
            )]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 100_000,
        };
        let db_digest =
            publish_signed_release(&mut ctx, &root, "compat-db", "1.0.0", db_profile).await;
        let db_evidence = CompatibilityEvidence {
            version: 1,
            release_digest: db_digest,
            environment: "local".into(),
            observed_at_ms: crate::now_millis(),
            components: BTreeMap::from([(
                "store".into(),
                ComponentObservation {
                    pin: db_pin,
                    requires: BTreeMap::new(),
                    provides: BTreeMap::from([("database".into(), "1.3.0".into())]),
                },
            )]),
            contracts: BTreeMap::new(),
            capabilities: Vec::new(),
            schema_version: None,
            migration: MigrationState::Stable,
        };
        record_evidence(&mut ctx, "local", db_evidence)
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "compat-db@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::subscribe(&mut ctx, "local", "compat-db", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(&mut ctx, &plan.id, execution_options(executor.clone()))
            .await
            .unwrap();

        let (mut app_profile, mut app_evidence) = fixture();
        app_profile.max_evidence_age_ms = 100_000;
        let app_digest =
            publish_signed_release(&mut ctx, &root, "compat-app", "1.0.0", app_profile).await;
        app_evidence.release_digest = app_digest;
        app_evidence.environment = "local".into();
        app_evidence.observed_at_ms = crate::now_millis() - 2_000;
        app_evidence.contracts.clear();
        record_evidence(&mut ctx, "local", app_evidence.clone())
            .await
            .unwrap();

        let first = report_outcome(&mut ctx, "local", "compat-app@1.0.0")
            .await
            .unwrap()
            .unwrap();
        assert!(first.failures.is_empty(), "{first:?}");
        assert_eq!(
            first.satisfied_by.get("database").map(String::as_str),
            Some("compat-db@1.0.0")
        );

        crate::catalog::promote(&mut ctx, &actor, "compat-app@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::subscribe(&mut ctx, "local", "compat-app", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(&mut ctx, &plan.id, execution_options(executor.clone()))
            .await
            .unwrap();

        drop(ctx);
        let mut restarted = crate::client::Ctx::embedded(&db).unwrap();
        let second = report_outcome(&mut restarted, "local", "compat-app@1.0.0")
            .await
            .unwrap()
            .unwrap();
        assert!(second.failures.is_empty(), "{second:?}");
        assert_eq!(
            second.satisfied_by.get("database").map(String::as_str),
            Some("compat-db@1.0.0")
        );
        drop(restarted);

        let mut other = crate::client::Ctx::embedded(&db).unwrap();
        let third = report_outcome(&mut other, "local", "compat-app@1.0.0")
            .await
            .unwrap()
            .unwrap();
        assert!(third.failures.is_empty(), "{third:?}");
        assert_eq!(
            third.satisfied_by.get("database").map(String::as_str),
            Some("compat-db@1.0.0")
        );

        app_evidence.observed_at_ms = crate::now_millis();
        app_evidence
            .contracts
            .insert("database".into(), "1.3.0".into());
        record_evidence(&mut other, "local", app_evidence)
            .await
            .unwrap();
        let ambiguous = report_outcome(&mut other, "local", "compat-app@1.0.0")
            .await
            .unwrap()
            .unwrap();
        assert!(
            ambiguous
                .failures
                .contains(&CompatibilityFailure::AmbiguousContract {
                    contract: "database".into()
                }),
            "{ambiguous:?}"
        );

        drop(other);
        std::fs::remove_dir_all(root).unwrap();
    }
}

//! Durable environment bindings from a dependent instance to a provider instance (ADR 0044 §3).
//!
//! Stored as `binding.{dependent}/{contract}=provider`. The slash separates the
//! dependent from the contract so both names may contain dots. Bindings are
//! environment configuration, not catalog facts.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::dependency_document::{self, DeployedRelease, MatchingProvider};
use crate::environment::environment;
use crate::ontology::{validate_identifier, validate_instance_name};
use crate::software_compatibility::{CompatibilityProfile, ContractRequirement};

/// Environment property prefix for one binding.
pub const BINDING_PREFIX: &str = "binding.";
pub use crate::ontology::OBSERVED_INSTANCE;

/// Bindings for one environment: (dependent instance, contract) → provider instance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvironmentBindings {
    inner: BTreeMap<(String, String), String>,
}

impl EnvironmentBindings {
    /// Parse `binding.*` properties. A malformed key is skipped; bind writes only valid keys.
    pub fn from_properties(properties: &HashMap<String, String>) -> Self {
        let mut inner = BTreeMap::new();
        for (key, provider) in properties {
            let Some((dependent, contract)) = parse_binding_key(key) else {
                continue;
            };
            if provider.is_empty() {
                continue;
            }
            inner.insert((dependent, contract), provider.clone());
        }
        Self { inner }
    }

    pub fn get(&self, dependent: &str, contract: &str) -> Option<&str> {
        self.inner
            .get(&(dependent.to_string(), contract.to_string()))
            .map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Bindings for `dependent`, contract → provider.
    pub fn for_dependent(&self, dependent: &str) -> BTreeMap<String, String> {
        self.inner
            .iter()
            .filter(|((name, _), _)| name == dependent)
            .map(|((_, contract), provider)| (contract.clone(), provider.clone()))
            .collect()
    }

    /// Sorted (dependent, contract, provider) triples for plan content identity.
    pub fn content_identity(&self) -> Vec<(String, String, String)> {
        self.inner
            .iter()
            .map(|((dependent, contract), provider)| {
                (dependent.clone(), contract.clone(), provider.clone())
            })
            .collect()
    }

    pub fn without(&self, dependent: &str, contract: &str) -> Self {
        let mut inner = self.inner.clone();
        inner.remove(&(dependent.to_string(), contract.to_string()));
        Self { inner }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.inner.iter().map(|((dependent, contract), provider)| {
            (dependent.as_str(), contract.as_str(), provider.as_str())
        })
    }

    pub fn insert(&mut self, dependent: &str, contract: &str, provider: &str) {
        self.inner.insert(
            (dependent.to_string(), contract.to_string()),
            provider.to_string(),
        );
    }
}

/// `binding.{dependent}/{contract}`.
pub fn binding_key(dependent: &str, contract: &str) -> String {
    format!("{BINDING_PREFIX}{dependent}/{contract}")
}

/// Split `binding.{dependent}/{contract}`; both names may contain dots.
pub fn parse_binding_key(key: &str) -> Option<(String, String)> {
    let rest = key.strip_prefix(BINDING_PREFIX)?;
    let (dependent, contract) = rest.split_once('/')?;
    if dependent.is_empty() || contract.is_empty() {
        return None;
    }
    Some((dependent.to_string(), contract.to_string()))
}

pub(crate) fn validate_binding_names(
    dependent: &str,
    contract: &str,
    provider: Option<&str>,
) -> Result<()> {
    if dependent == OBSERVED_INSTANCE {
        bail!("dependent instance {dependent} is reserved");
    }
    validate_instance_or_default(dependent)?;
    validate_identifier("contract", contract)?;
    if let Some(provider) = provider
        && provider != OBSERVED_INSTANCE
    {
        validate_instance_or_default(provider)?;
    }
    Ok(())
}

fn validate_instance_or_default(name: &str) -> Result<()> {
    // Product-named default instances may use product identifier characters.
    if validate_instance_name(name).is_ok() {
        return Ok(());
    }
    validate_identifier("instance", name)
}

/// Store `binding.{dependent}/{contract}=provider`. Refuses a provider that
/// does not currently provide a satisfying version of the contract.
pub async fn bind(
    ctx: &mut Ctx,
    env: &str,
    dependent: &str,
    contract: &str,
    provider: &str,
) -> Result<String> {
    validate_binding_names(dependent, contract, Some(provider))?;
    let owner = format!("environment-config:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, env, &owner).await?;
    let result = bind_locked(ctx, env, dependent, contract, provider, &lease).await;
    finish_environment_mutation(ctx, &lease, result).await
}

/// [`bind`] for a caller that already holds the environment apply lease.
pub(crate) async fn bind_locked(
    ctx: &mut Ctx,
    env: &str,
    dependent: &str,
    contract: &str,
    provider: &str,
    lease: &crate::apply::EnvironmentLease,
) -> Result<String> {
    validate_binding_names(dependent, contract, Some(provider))?;
    let mut env_obj = environment(ctx, env).await?;
    let deployed = dependency_document::deployed_set(ctx, &env_obj).await?;
    let observed = observed_provides_for_dependent(ctx, &env_obj, dependent).await?;
    let required = required_for_dependent(ctx, &env_obj, dependent, contract, &deployed).await?;
    if !provider_satisfies(
        dependent,
        contract,
        provider,
        &deployed,
        &observed,
        required.as_ref(),
    )? {
        bail!(
            "binding {dependent} {contract}={provider} refused: {provider} does not provide a satisfying version of {contract} for {dependent}"
        );
    }
    env_obj
        .properties
        .insert(binding_key(dependent, contract), provider.to_string());
    env_obj.updated = crate::now_millis();
    persist_environment(ctx, env_obj, lease).await?;
    Ok(format!("bound {env} {dependent} {contract}={provider}"))
}

/// Remove one binding. Refused when an installed dependent would then lack a
/// unique satisfying provider for a required contract.
pub async fn unbind(ctx: &mut Ctx, env: &str, dependent: &str, contract: &str) -> Result<String> {
    validate_binding_names(dependent, contract, None)?;
    let owner = format!("environment-config:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, env, &owner).await?;
    let result = unbind_locked(ctx, env, dependent, contract, &lease).await;
    finish_environment_mutation(ctx, &lease, result).await
}

/// [`unbind`] for a caller that already holds the environment apply lease.
pub(crate) async fn unbind_locked(
    ctx: &mut Ctx,
    env: &str,
    dependent: &str,
    contract: &str,
    lease: &crate::apply::EnvironmentLease,
) -> Result<String> {
    validate_binding_names(dependent, contract, None)?;
    let mut env_obj = environment(ctx, env).await?;
    let key = binding_key(dependent, contract);
    if !env_obj.properties.contains_key(&key) {
        bail!("environment {env} has no binding {dependent} {contract}");
    }
    let deployed = dependency_document::deployed_set(ctx, &env_obj).await?;
    refuse_required_unbind(dependent, contract, &deployed)?;
    env_obj.properties.remove(&key);
    env_obj.updated = crate::now_millis();
    persist_environment(ctx, env_obj, lease).await?;
    Ok(format!("unbound {env} {dependent} {contract}"))
}

async fn persist_environment(
    ctx: &mut Ctx,
    object: crate::pb::sekai::Object,
    lease: &crate::apply::EnvironmentLease,
) -> Result<()> {
    ctx.guarded_update(
        object,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

async fn finish_environment_mutation(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    result: Result<String>,
) -> Result<String> {
    match (result, crate::apply::release_environment(ctx, lease).await) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the environment configuration lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment configuration lease")),
    }
}

fn refuse_required_unbind(
    dependent: &str,
    contract: &str,
    deployed: &BTreeMap<String, DeployedRelease>,
) -> Result<()> {
    let Some(deployed) = deployed.get(dependent) else {
        return Ok(());
    };
    let Some(requirement) = requirement_for(&deployed.profile, contract) else {
        return Ok(());
    };
    if requirement.optional() {
        return Ok(());
    }
    bail!("unbind refused: installed dependent {dependent} requires {contract}")
}

/// Apply a binding to a matching-provider list. Unbound several stay several.
pub(crate) fn select_matching(
    dependent: &str,
    contract: &str,
    matching: Vec<MatchingProvider>,
    bindings: &EnvironmentBindings,
) -> Vec<MatchingProvider> {
    match bindings.get(dependent, contract) {
        Some(provider) => matching
            .into_iter()
            .filter(|candidate| candidate.instance == provider)
            .collect(),
        None => matching,
    }
}

/// Strictest requirement for `contract` across components. A required entry
/// wins over optional; the higher minimum wins.
fn requirement_for(profile: &CompatibilityProfile, contract: &str) -> Option<ContractRequirement> {
    let mut selected: Option<ContractRequirement> = None;
    for component in profile.components.values() {
        let Some(next) = component.requires.get(contract) else {
            continue;
        };
        selected = Some(match selected {
            None => next.clone(),
            Some(existing) => merge_requirement(existing, next),
        });
    }
    selected
}

fn merge_requirement(
    left: ContractRequirement,
    right: &ContractRequirement,
) -> ContractRequirement {
    let minimum =
        crate::software_compatibility::stricter_contract_minimum(left.minimum(), right.minimum());
    if left.optional() && right.optional() {
        ContractRequirement::Detailed {
            minimum,
            optional: true,
        }
    } else {
        ContractRequirement::Minimum(minimum)
    }
}

async fn required_for_dependent(
    ctx: &mut Ctx,
    env_obj: &crate::pb::sekai::Object,
    dependent: &str,
    contract: &str,
    deployed: &BTreeMap<String, DeployedRelease>,
) -> Result<Option<(ContractRequirement, u32)>> {
    if let Some(deployed) = deployed.get(dependent) {
        return Ok(requirement_for(&deployed.profile, contract)
            .map(|requirement| (requirement, deployed.profile.version)));
    }
    let Some(release) =
        crate::dependency_document::instance_release_id(ctx, env_obj, dependent).await?
    else {
        return Ok(None);
    };
    let Some(profile) = crate::dependency_document::stored_profile_by_id(ctx, &release).await?
    else {
        return Ok(None);
    };
    Ok(requirement_for(&profile, contract).map(|requirement| (requirement, profile.version)))
}

fn provider_satisfies(
    _dependent: &str,
    contract: &str,
    provider: &str,
    deployed: &BTreeMap<String, DeployedRelease>,
    observed: &BTreeMap<String, String>,
    required: Option<&(ContractRequirement, u32)>,
) -> Result<bool> {
    let (requirement, profile_version) = match required {
        Some((requirement, version)) => (Some(requirement), *version),
        None => (None, 1),
    };
    if provider == OBSERVED_INSTANCE {
        let Some(version) = observed.get(contract) else {
            return Ok(false);
        };
        return offer_satisfies(version, requirement, profile_version);
    }
    let Some(deployed) = deployed.get(provider) else {
        return Ok(false);
    };
    for component in deployed.profile.components.values() {
        if let Some(version) = component.provides.get(contract)
            && offer_satisfies(version, requirement, profile_version)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn offer_satisfies(
    version: &str,
    requirement: Option<&ContractRequirement>,
    profile_version: u32,
) -> Result<bool> {
    let Some(requirement) = requirement else {
        return Ok(true);
    };
    let actual = semver::Version::parse(version)?;
    let minimum = semver::Version::parse(requirement.minimum())?;
    Ok(crate::software_compatibility::contract_satisfies(
        profile_version,
        &actual,
        &minimum,
    ))
}

/// Digest-bound observation of `dependent`, the same evidence `report_manifest` uses.
async fn observed_provides_for_dependent(
    ctx: &mut Ctx,
    env_obj: &crate::pb::sekai::Object,
    dependent: &str,
) -> Result<BTreeMap<String, String>> {
    let Some(digest) =
        crate::dependency_document::instance_release_digest(ctx, env_obj, dependent).await?
    else {
        return Ok(BTreeMap::new());
    };
    crate::software_compatibility::observed_contract_versions(ctx, &env_obj.name, &digest).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_key_splits_dependent_then_contract_with_dots() {
        let key = binding_key("app-a", "connector.capture");
        assert_eq!(key, "binding.app-a/connector.capture");
        assert_eq!(
            parse_binding_key(&key),
            Some(("app-a".into(), "connector.capture".into()))
        );
        assert_eq!(
            parse_binding_key("binding.app/database"),
            Some(("app".into(), "database".into()))
        );
        assert_eq!(
            parse_binding_key(&binding_key("api-service_2.0", "database")),
            Some(("api-service_2.0".into(), "database".into()))
        );
        assert_eq!(parse_binding_key("binding.app"), None);
        assert_eq!(parse_binding_key("binding.app.database"), None);
        assert_eq!(parse_binding_key("fact.architecture"), None);
    }

    #[test]
    fn from_properties_reads_sorted_bindings() {
        let properties = HashMap::from([
            ("binding.app/database".into(), "db-a".into()),
            ("binding.app/connector.capture".into(), "side".into()),
            ("deployed.app".into(), "1.0.0".into()),
            ("binding.broken".into(), "x".into()),
        ]);
        let bindings = EnvironmentBindings::from_properties(&properties);
        assert_eq!(bindings.get("app", "database"), Some("db-a"));
        assert_eq!(bindings.get("app", "connector.capture"), Some("side"));
        assert_eq!(
            bindings.content_identity(),
            vec![
                ("app".into(), "connector.capture".into(), "side".into()),
                ("app".into(), "database".into(), "db-a".into()),
            ]
        );
        assert_eq!(
            bindings.for_dependent("app"),
            BTreeMap::from([
                ("connector.capture".into(), "side".into()),
                ("database".into(), "db-a".into()),
            ])
        );
    }

    fn provider(instance: &str, version: &str) -> MatchingProvider {
        MatchingProvider {
            product: instance.into(),
            instance: instance.into(),
            release: version.into(),
            contract_version: "1.0.0".into(),
        }
    }

    #[test]
    fn select_matching_keeps_unbound_several_and_filters_a_binding() {
        let matching = vec![provider("db-a", "1.0.0"), provider("db-b", "1.1.0")];
        let unbound = select_matching(
            "app",
            "database",
            matching.clone(),
            &EnvironmentBindings::default(),
        );
        assert_eq!(unbound.len(), 2);
        let mut bindings = EnvironmentBindings::default();
        bindings.insert("app", "database", "db-b");
        let bound = select_matching("app", "database", matching, &bindings);
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].instance, "db-b");
    }

    fn remaining_profile(
        requires: &[(&str, &str, bool)],
        provides: &[(&str, &str)],
    ) -> CompatibilityProfile {
        CompatibilityProfile {
            version: 2,
            components: BTreeMap::from([(
                "main".into(),
                crate::software_compatibility::ComponentRequirement {
                    pin: crate::software_compatibility::ComponentPin::Revision("a".repeat(40)),
                    requires: requires
                        .iter()
                        .map(|(contract, minimum, optional)| {
                            (
                                (*contract).into(),
                                if *optional {
                                    crate::software_compatibility::ContractRequirement::Detailed {
                                        minimum: (*minimum).into(),
                                        optional: true,
                                    }
                                } else {
                                    crate::software_compatibility::ContractRequirement::Minimum(
                                        (*minimum).into(),
                                    )
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
    fn unbind_of_required_installed_dependent_is_refused() {
        let app = remaining_profile(&[("database", "1.0.0", false)], &[]);
        let deployed = BTreeMap::from([("app".into(), DeployedRelease::of("app", "1.0.0", app))]);
        let err = refuse_required_unbind("app", "database", &deployed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unbind refused"), "{err}");
        assert!(err.contains("app"), "{err}");
        assert!(err.contains("database"), "{err}");
        let optional = remaining_profile(&[("database", "1.0.0", true)], &[]);
        let deployed =
            BTreeMap::from([("app".into(), DeployedRelease::of("app", "1.0.0", optional))]);
        refuse_required_unbind("app", "database", &deployed).unwrap();
        refuse_required_unbind("missing", "database", &deployed).unwrap();
        let mixed = CompatibilityProfile {
            version: 2,
            components: BTreeMap::from([
                (
                    "api".into(),
                    crate::software_compatibility::ComponentRequirement {
                        pin: crate::software_compatibility::ComponentPin::Revision("a".repeat(40)),
                        requires: BTreeMap::from([(
                            "database".into(),
                            crate::software_compatibility::ContractRequirement::Detailed {
                                minimum: "1.0.0".into(),
                                optional: true,
                            },
                        )]),
                        provides: BTreeMap::new(),
                    },
                ),
                (
                    "worker".into(),
                    crate::software_compatibility::ComponentRequirement {
                        pin: crate::software_compatibility::ComponentPin::Revision("a".repeat(40)),
                        requires: BTreeMap::from([(
                            "database".into(),
                            crate::software_compatibility::ContractRequirement::Minimum(
                                "1.2.0".into(),
                            ),
                        )]),
                        provides: BTreeMap::new(),
                    },
                ),
            ]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 60_000,
        };
        let deployed = BTreeMap::from([("app".into(), DeployedRelease::of("app", "1.0.0", mixed))]);
        let err = refuse_required_unbind("app", "database", &deployed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unbind refused"), "{err}");
        let req = requirement_for(&deployed["app"].profile, "database").unwrap();
        assert!(!req.optional());
        assert_eq!(req.minimum(), "1.2.0");
    }

    #[test]
    fn bind_names_are_validated() {
        let err = validate_binding_names("observed", "database", Some("db-a"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");
        validate_binding_names("app", "database", Some("observed")).unwrap();
        validate_binding_names("app", "connector.capture", Some("db-a")).unwrap();
    }
}

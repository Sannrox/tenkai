//! Derived dependency document for a release that declares requirements (ADR 0043 §6).
//!
//! The document is computed from stored successful deployments only. Executors
//! deliver it; it carries no endpoints or credentials.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::environment_bindings::{EnvironmentBindings, OBSERVED_INSTANCE};
use crate::ontology::release_id;
use crate::pb::sekai::Object;
use crate::software_compatibility::{CompatibilityProfile, ContractRequirement};

/// Format version of [`DependencyDocument`].
pub const FORMAT_VERSION: u32 = 1;
/// File name on host spool and the ConfigMap data key.
pub const HOST_FILE: &str = "tenkai-dependencies.json";
/// Path inside a Docker container.
pub const DOCKER_PATH: &str = "/etc/tenkai/dependencies.json";
/// Helm `--set-file` destination.
pub const HELM_VALUES_KEY: &str = "tenkai.dependencies";
/// ConfigMap data key (same bytes as [`HOST_FILE`]).
pub const CONFIGMAP_KEY: &str = HOST_FILE;
/// Environment property holding the last applied document digest.
pub const APPLIED_PROPERTY_PREFIX: &str = "applied_dependencies.";

/// v1 dependency document: one entry per required or optional contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyDocument {
    pub version: u32,
    pub contracts: BTreeMap<String, DependencyContract>,
}

/// Last successful deployment of one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployedRelease {
    /// Catalog product. Equals the instance name when unnamed.
    pub product: String,
    pub version: String,
    pub profile: CompatibilityProfile,
}

impl DeployedRelease {
    pub fn of(product: &str, version: &str, profile: CompatibilityProfile) -> Self {
        Self {
            product: product.to_string(),
            version: version.to_string(),
            profile,
        }
    }
}

/// One contract in the document: the providing release, or `absent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DependencyContract {
    Present {
        product: String,
        release: String,
        contract: String,
        /// Provider instance. Omitted when it equals `product`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        instance: String,
    },
    Absent,
}

impl DependencyDocument {
    /// Canonical JSON: sorted contract keys, no extra whitespace.
    pub fn to_canonical_json(&self) -> Result<String> {
        serde_json::to_string(self).context("serializing dependency document")
    }

    /// SHA-256 hex of [`Self::to_canonical_json`].
    pub fn digest(&self) -> Result<String> {
        Ok(digest_json(&self.to_canonical_json()?))
    }
}

/// SHA-256 hex of canonical document JSON.
pub fn digest_json(json: &str) -> String {
    format!("{:x}", Sha256::digest(json.as_bytes()))
}

/// ConfigMap name for an in-cluster document (`tenkai-dependencies-<instance>`).
/// The default instance is the product, so existing names stay.
pub fn configmap_name(instance: &str) -> String {
    let label = crate::software_executor::k8s_label_value(instance)
        .to_ascii_lowercase()
        .replace(['_', '.'], "-");
    format!("tenkai-dependencies-{label}")
}

/// Kubernetes ConfigMap JSON for `request`, when it carries a document.
pub fn configmap_json(request: &crate::software_executor::SoftwareApplyRequest) -> Option<String> {
    if request.dependency_document.is_empty() {
        return None;
    }
    let name = configmap_name(request.instance_name());
    let value = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": request.environment,
            "labels": {
                "tenkai.product": crate::software_executor::k8s_label_value(&request.product),
                "tenkai.instance": crate::software_executor::k8s_label_value(request.instance_name()),
            }
        },
        "data": {
            CONFIGMAP_KEY: request.dependency_document,
        }
    });
    Some(value.to_string())
}

/// Document for `product` from `deployed` (instance → version, profile).
///
/// `None` when the profile declares no requirements. Fails closed if a required
/// contract would be absent or a contract has several providers.
pub fn document_for(
    product: &str,
    profile: &CompatibilityProfile,
    deployed: &BTreeMap<String, DeployedRelease>,
) -> Result<Option<DependencyDocument>> {
    document_for_bound(
        product,
        profile,
        deployed,
        &EnvironmentBindings::default(),
        &BTreeMap::new(),
    )
}

/// [`document_for`] honoring environment bindings (ADR 0044 §3).
///
/// `observed` is digest-bound contract versions for `product` (instance
/// `observed`). Empty when the dependent has no observation.
pub fn document_for_bound(
    product: &str,
    profile: &CompatibilityProfile,
    deployed: &BTreeMap<String, DeployedRelease>,
    bindings: &EnvironmentBindings,
    observed: &BTreeMap<String, String>,
) -> Result<Option<DependencyDocument>> {
    let mut requirements: BTreeMap<String, ContractRequirement> = BTreeMap::new();
    for component in profile.components.values() {
        for (contract, requirement) in &component.requires {
            requirements.insert(contract.clone(), requirement.clone());
        }
    }
    if requirements.is_empty() {
        return Ok(None);
    }
    let mut contracts = BTreeMap::new();
    for (contract, requirement) in requirements {
        if self_satisfies(profile, &contract, &requirement)? {
            continue;
        }
        let matching = crate::environment_bindings::select_matching(
            product,
            &contract,
            matching_providers(
                product,
                &contract,
                &requirement,
                profile.version,
                deployed,
                observed,
            )?,
            bindings,
        );
        match matching.as_slice() {
            [] if requirement.optional() => {
                contracts.insert(contract, DependencyContract::Absent);
            }
            [] => bail!(
                "required contract {contract} would be absent in the dependency document for {product}"
            ),
            [provider] => {
                let instance = if provider.instance == provider.product {
                    String::new()
                } else {
                    provider.instance.clone()
                };
                contracts.insert(
                    contract,
                    DependencyContract::Present {
                        product: provider.product.clone(),
                        release: provider.release.clone(),
                        contract: provider.contract_version.clone(),
                        instance,
                    },
                );
            }
            _ => bail!("dependency document for {product} has ambiguous providers for {contract}"),
        }
    }
    if contracts.is_empty() {
        return Ok(None);
    }
    Ok(Some(DependencyDocument {
        version: FORMAT_VERSION,
        contracts,
    }))
}

/// True when this release already provides a satisfying version of `contract`.
pub(crate) fn self_satisfies(
    profile: &CompatibilityProfile,
    contract: &str,
    requirement: &ContractRequirement,
) -> Result<bool> {
    for component in profile.components.values() {
        let Some(version) = component.provides.get(contract) else {
            continue;
        };
        let actual = semver::Version::parse(version)
            .with_context(|| format!("provided {contract} version {version}"))?;
        let minimum = semver::Version::parse(requirement.minimum())
            .with_context(|| format!("required {contract} minimum {}", requirement.minimum()))?;
        if crate::software_compatibility::contract_satisfies(profile.version, &actual, &minimum) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone)]
pub(crate) struct MatchingProvider {
    pub product: String,
    /// Instance that provides the contract. Equals `product` when unnamed.
    pub instance: String,
    pub release: String,
    pub contract_version: String,
}

pub(crate) fn matching_providers(
    dependent: &str,
    contract: &str,
    requirement: &ContractRequirement,
    profile_version: u32,
    deployed: &BTreeMap<String, DeployedRelease>,
    observed: &BTreeMap<String, String>,
) -> Result<Vec<MatchingProvider>> {
    let mut matching = Vec::new();
    for (instance, deployed) in deployed {
        if instance == dependent {
            continue;
        }
        let product = if deployed.product.is_empty() {
            instance.as_str()
        } else {
            deployed.product.as_str()
        };
        for component in deployed.profile.components.values() {
            let Some(version) = component.provides.get(contract) else {
                continue;
            };
            let actual = semver::Version::parse(version)
                .with_context(|| format!("provided {contract} version {version} on {instance}"))?;
            let minimum = semver::Version::parse(requirement.minimum()).with_context(|| {
                format!(
                    "required {contract} minimum {} on {dependent}",
                    requirement.minimum()
                )
            })?;
            if crate::software_compatibility::contract_satisfies(profile_version, &actual, &minimum)
            {
                matching.push(MatchingProvider {
                    product: product.to_string(),
                    instance: instance.clone(),
                    release: deployed.version.clone(),
                    contract_version: version.clone(),
                });
                break;
            }
        }
    }
    if let Some(version) = observed.get(contract) {
        let actual = semver::Version::parse(version)
            .with_context(|| format!("observed {contract} version {version}"))?;
        let minimum = semver::Version::parse(requirement.minimum()).with_context(|| {
            format!(
                "required {contract} minimum {} on {dependent}",
                requirement.minimum()
            )
        })?;
        if crate::software_compatibility::contract_satisfies(profile_version, &actual, &minimum) {
            matching.push(MatchingProvider {
                product: OBSERVED_INSTANCE.to_string(),
                instance: OBSERVED_INSTANCE.to_string(),
                release: version.clone(),
                contract_version: version.clone(),
            });
        }
    }
    matching.sort_by(|left, right| left.instance.cmp(&right.instance));
    matching.dedup_by(|left, right| left.instance == right.instance);
    Ok(matching)
}

/// Catalog release id currently deployed or subscribed for `instance`.
pub(crate) async fn instance_release_id(
    ctx: &mut Ctx,
    environment: &Object,
    instance: &str,
) -> Result<Option<String>> {
    if let Some(version) = environment.properties.get(&format!("deployed.{instance}")) {
        return Ok(Some(
            environment
                .properties
                .get(&format!("deployed_release.{instance}"))
                .cloned()
                .unwrap_or_else(|| release_id(instance, version)),
        ));
    }
    let subscriptions = crate::environment::list_subscriptions(ctx, environment).await?;
    let Some(sub) = subscriptions.iter().find(|row| row.instance == instance) else {
        return Ok(None);
    };
    let Some(release) = sub.channel.properties.get("current_release") else {
        return Ok(None);
    };
    if release.is_empty() {
        return Ok(None);
    }
    Ok(Some(release.clone()))
}

/// Manifest digest of the release currently deployed or subscribed for `instance`.
pub(crate) async fn instance_release_digest(
    ctx: &mut Ctx,
    environment: &Object,
    instance: &str,
) -> Result<Option<String>> {
    let Some(id) = instance_release_id(ctx, environment, instance).await? else {
        return Ok(None);
    };
    stored_release_digest(ctx, &id).await
}

async fn stored_release_digest(ctx: &mut Ctx, id: &str) -> Result<Option<String>> {
    let Some(object) = ctx.get(id).await? else {
        return Ok(None);
    };
    Ok(object.properties.get("digest").cloned())
}

/// Profiles of releases whose last deployment in `environment` succeeded.
///
/// Keyed by instance. Catalog product comes from `deployed_release.{instance}`.
pub async fn deployed_set(
    ctx: &mut Ctx,
    environment: &Object,
) -> Result<BTreeMap<String, DeployedRelease>> {
    let mut deployed = BTreeMap::new();
    for (key, version) in &environment.properties {
        let Some(instance) = key.strip_prefix("deployed.") else {
            continue;
        };
        let id = environment
            .properties
            .get(&format!("deployed_release.{instance}"))
            .cloned()
            .unwrap_or_else(|| release_id(instance, version));
        let Some(profile) = stored_profile_by_id(ctx, &id).await? else {
            continue;
        };
        let product = id
            .strip_prefix("tenkai:release:")
            .and_then(|spec| spec.split_once('@'))
            .map(|(product, _)| product.to_string())
            .unwrap_or_else(|| instance.to_string());
        deployed.insert(
            instance.to_string(),
            DeployedRelease {
                product,
                version: version.clone(),
                profile,
            },
        );
    }
    Ok(deployed)
}

pub(crate) async fn stored_profile(
    ctx: &mut Ctx,
    product: &str,
    version: &str,
) -> Result<Option<CompatibilityProfile>> {
    stored_profile_by_id(ctx, &release_id(product, version)).await
}

pub(crate) async fn stored_profile_by_id(
    ctx: &mut Ctx,
    id: &str,
) -> Result<Option<CompatibilityProfile>> {
    let Some(object) = ctx.get(id).await? else {
        return Ok(None);
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(None);
    };
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {id}"))?;
    Ok(manifest.compatibility)
}

/// Canonical JSON for `instance` from the environment's deployed set.
/// Empty `instance` means the product name. Uses the currently deployed
/// (or subscribed) release digest for `observed`.
pub async fn json_for_product(
    ctx: &mut Ctx,
    environment: &Object,
    instance: &str,
    profile: &CompatibilityProfile,
) -> Result<Option<String>> {
    json_for_observed(ctx, environment, instance, profile, None).await
}

/// Apply-time document for the target release digest, not the still-deployed one.
pub async fn json_for_release(
    ctx: &mut Ctx,
    environment: &Object,
    instance: &str,
    profile: &CompatibilityProfile,
    release_digest: &str,
) -> Result<Option<String>> {
    json_for_observed(ctx, environment, instance, profile, Some(release_digest)).await
}

async fn json_for_observed(
    ctx: &mut Ctx,
    environment: &Object,
    instance: &str,
    profile: &CompatibilityProfile,
    release_digest: Option<&str>,
) -> Result<Option<String>> {
    let deployed = deployed_set(ctx, environment).await?;
    let bindings = EnvironmentBindings::from_properties(&environment.properties);
    let observed = match release_digest {
        Some(digest) if !digest.is_empty() => {
            crate::software_compatibility::observed_contract_versions(
                ctx,
                &environment.name,
                digest,
            )
            .await?
        }
        _ => observed_for_instance(ctx, environment, instance).await?,
    };
    match document_for_bound(instance, profile, &deployed, &bindings, &observed)? {
        Some(document) => Ok(Some(document.to_canonical_json()?)),
        None => Ok(None),
    }
}

async fn observed_for_instance(
    ctx: &mut Ctx,
    environment: &Object,
    instance: &str,
) -> Result<BTreeMap<String, String>> {
    let Some(digest) = instance_release_digest(ctx, environment, instance).await? else {
        return Ok(BTreeMap::new());
    };
    crate::software_compatibility::observed_contract_versions(ctx, &environment.name, &digest).await
}

/// Record or clear `applied_dependencies.{instance}` from the current deployed set.
pub async fn stamp(ctx: &mut Ctx, environment: &mut Object, instance: &str) -> Result<()> {
    let key = format!("{APPLIED_PROPERTY_PREFIX}{instance}");
    let Some(version) = environment
        .properties
        .get(&format!("deployed.{instance}"))
        .cloned()
    else {
        environment.properties.remove(&key);
        return Ok(());
    };
    let id = environment
        .properties
        .get(&format!("deployed_release.{instance}"))
        .cloned()
        .unwrap_or_else(|| release_id(instance, &version));
    let Some(profile) = stored_profile_by_id(ctx, &id).await? else {
        environment.properties.remove(&key);
        return Ok(());
    };
    let deployed = deployed_set(ctx, environment).await?;
    let bindings = EnvironmentBindings::from_properties(&environment.properties);
    let observed = observed_for_instance(ctx, environment, instance).await?;
    match document_for_bound(instance, &profile, &deployed, &bindings, &observed)? {
        Some(document) => {
            environment.properties.insert(key, document.digest()?);
        }
        None => {
            environment.properties.remove(&key);
        }
    }
    Ok(())
}

/// Digest last applied for `instance`, empty when none.
pub fn applied_digest(environment: &Object, instance: &str) -> String {
    environment
        .properties
        .get(&format!("{APPLIED_PROPERTY_PREFIX}{instance}"))
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_compatibility::{
        CompatibilityProfile, ComponentPin, ComponentRequirement, ContractRequirement,
    };

    fn profile(
        version: u32,
        requires: &[(&str, &str, bool)],
        provides: &[(&str, &str)],
    ) -> CompatibilityProfile {
        CompatibilityProfile {
            version,
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
                        .map(|(contract, ver)| ((*contract).into(), (*ver).into()))
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
    fn no_requirements_yields_no_document() {
        let app = profile(2, &[], &[]);
        assert_eq!(document_for("app", &app, &BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn in_release_provider_is_omitted() {
        let app = profile(2, &[("database", "1.0.0", false)], &[("database", "1.3.0")]);
        assert_eq!(document_for("app", &app, &BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn required_present_and_optional_absent() {
        let app = profile(
            2,
            &[("database", "1.0.0", false), ("connector", "0.1.0", true)],
            &[],
        );
        let db = profile(2, &[], &[("database", "1.3.0")]);
        let deployed = BTreeMap::from([("db".into(), DeployedRelease::of("db", "1.2.0", db))]);
        let document = document_for("app", &app, &deployed).unwrap().unwrap();
        assert_eq!(document.version, 1);
        assert_eq!(
            document.contracts.get("database"),
            Some(&DependencyContract::Present {
                product: "db".into(),
                release: "1.2.0".into(),
                contract: "1.3.0".into(),
                instance: String::new(),
            })
        );
        assert_eq!(
            document.contracts.get("connector"),
            Some(&DependencyContract::Absent)
        );
        let json = document.to_canonical_json().unwrap();
        assert_eq!(json, document.to_canonical_json().unwrap());
        assert!(json.contains("\"state\":\"absent\""));
        assert!(!json.contains("endpoint"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn optional_present() {
        let app = profile(2, &[("connector", "0.1.0", true)], &[]);
        let connector = profile(2, &[], &[("connector", "0.1.4")]);
        let deployed = BTreeMap::from([(
            "side".into(),
            DeployedRelease::of("side", "0.1.4", connector),
        )]);
        let document = document_for("app", &app, &deployed).unwrap().unwrap();
        assert_eq!(
            document.contracts["connector"],
            DependencyContract::Present {
                product: "side".into(),
                release: "0.1.4".into(),
                contract: "0.1.4".into(),
                instance: String::new(),
            }
        );
    }

    #[test]
    fn required_absent_fails_closed() {
        let app = profile(2, &[("database", "1.0.0", false)], &[]);
        let err = document_for("app", &app, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("database"), "{err}");
        assert!(err.contains("absent"), "{err}");
    }

    #[test]
    fn ambiguous_providers_fail_closed() {
        let app = profile(2, &[("database", "1.0.0", false)], &[]);
        let db = profile(2, &[], &[("database", "1.0.0")]);
        let deployed = BTreeMap::from([
            ("db".into(), DeployedRelease::of("db", "1.0.0", db.clone())),
            (
                "db2".into(),
                DeployedRelease::of("db2", "1.1.0", db.clone()),
            ),
        ]);
        let err = document_for("app", &app, &deployed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous"), "{err}");
        let mut bindings = crate::environment_bindings::EnvironmentBindings::default();
        bindings.insert("app", "database", "db2");
        let document = document_for_bound("app", &app, &deployed, &bindings, &BTreeMap::new())
            .unwrap()
            .unwrap();
        assert_eq!(
            document.contracts.get("database"),
            Some(&DependencyContract::Present {
                product: "db2".into(),
                release: "1.1.0".into(),
                contract: "1.0.0".into(),
                instance: String::new(),
            })
        );
        bindings.insert("app", "database", "db-private");
        let named = profile(2, &[], &[("database", "1.0.0")]);
        let deployed_named = BTreeMap::from([
            ("db".into(), DeployedRelease::of("db", "1.0.0", db.clone())),
            (
                "db-private".into(),
                DeployedRelease::of("database", "1.1.0", named),
            ),
        ]);
        bindings.insert("app", "database", "db-private");
        let document =
            document_for_bound("app", &app, &deployed_named, &bindings, &BTreeMap::new())
                .unwrap()
                .unwrap();
        match document.contracts.get("database") {
            Some(DependencyContract::Present {
                product, instance, ..
            }) => {
                assert_eq!(product, "database");
                assert_eq!(instance, "db-private");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bound_observation_is_named_in_the_document() {
        let app = profile(2, &[("database", "1.0.0", false)], &[]);
        let db = profile(2, &[], &[("database", "1.0.0")]);
        let deployed = BTreeMap::from([("db".into(), DeployedRelease::of("db", "1.0.0", db))]);
        let observed = BTreeMap::from([("database".into(), "1.3.0".into())]);
        let err = document_for_bound(
            "app",
            &app,
            &deployed,
            &EnvironmentBindings::default(),
            &observed,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("ambiguous"), "{err}");
        let mut bindings = EnvironmentBindings::default();
        bindings.insert("app", "database", OBSERVED_INSTANCE);
        let document = document_for_bound("app", &app, &deployed, &bindings, &observed)
            .unwrap()
            .unwrap();
        assert_eq!(
            document.contracts.get("database"),
            Some(&DependencyContract::Present {
                product: OBSERVED_INSTANCE.into(),
                release: "1.3.0".into(),
                contract: "1.3.0".into(),
                instance: String::new(),
            })
        );
    }

    #[tokio::test]
    async fn json_for_release_uses_target_digest_observation() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-dep-digest-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        let digest_old = "ab".repeat(32);
        let digest_new = "cd".repeat(32);
        let pin = "a".repeat(40);
        for (digest, version) in [(&digest_old, "1.0.0"), (&digest_new, "1.3.0")] {
            crate::software_compatibility::record_evidence(
                &mut ctx,
                "local",
                crate::software_compatibility::CompatibilityEvidence {
                    version: 1,
                    release_digest: digest.clone(),
                    environment: "local".into(),
                    observed_at_ms: crate::now_millis() - 1_000,
                    components: BTreeMap::from([(
                        "app".into(),
                        crate::software_compatibility::ComponentObservation {
                            pin: crate::software_compatibility::ComponentPin::Revision(pin.clone()),
                            requires: BTreeMap::from([("database".into(), "1.0.0".into())]),
                            provides: BTreeMap::new(),
                        },
                    )]),
                    contracts: BTreeMap::from([("database".into(), version.into())]),
                    capabilities: Vec::new(),
                    schema_version: None,
                    migration: crate::software_compatibility::MigrationState::Stable,
                },
            )
            .await
            .unwrap();
        }
        let mut env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        env.properties
            .insert("binding.app/database".into(), OBSERVED_INSTANCE.into());
        env.updated = crate::now_millis();
        ctx.put(env.clone()).await.unwrap();
        let app = profile(2, &[("database", "1.0.0", false)], &[]);
        let old = json_for_release(&mut ctx, &env, "app", &app, &digest_old)
            .await
            .unwrap()
            .unwrap();
        let new = json_for_release(&mut ctx, &env, "app", &app, &digest_new)
            .await
            .unwrap()
            .unwrap();
        assert!(old.contains("\"release\":\"1.0.0\""), "{old}");
        assert!(new.contains("\"release\":\"1.3.0\""), "{new}");
        assert_ne!(old, new);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configmap_json_is_absent_without_a_document() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-dep-cm-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let request = crate::software_executor::request_from_parts(
            "api",
            "1.0.0",
            "prod",
            &root,
            "tenkai:release:api@1.0.0",
        );
        assert_eq!(configmap_json(&request), None);
        let _ = std::fs::remove_dir_all(root);
    }
}

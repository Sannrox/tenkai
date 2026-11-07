//! Derived dependency document for a release that declares requirements (ADR 0043 §6).
//!
//! The document is computed from stored successful deployments only. Executors
//! deliver it; it carries no endpoints or credentials.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
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

/// One contract in the document: the providing release, or `absent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DependencyContract {
    Present {
        product: String,
        release: String,
        contract: String,
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

/// ConfigMap name for an in-cluster document (`tenkai-dependencies-<product>`).
pub fn configmap_name(product: &str) -> String {
    let label = crate::software_executor::k8s_label_value(product)
        .to_ascii_lowercase()
        .replace(['_', '.'], "-");
    format!("tenkai-dependencies-{label}")
}

/// Kubernetes ConfigMap JSON for `request`, when it carries a document.
pub fn configmap_json(request: &crate::software_executor::SoftwareApplyRequest) -> Option<String> {
    if request.dependency_document.is_empty() {
        return None;
    }
    let name = configmap_name(&request.product);
    let value = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": request.environment,
            "labels": {
                "tenkai.product": crate::software_executor::k8s_label_value(&request.product),
            }
        },
        "data": {
            CONFIGMAP_KEY: request.dependency_document,
        }
    });
    Some(value.to_string())
}

/// Document for `product` from `deployed` (product → version, profile).
///
/// `None` when the profile declares no requirements. Fails closed if a required
/// contract would be absent or a contract has several providers.
pub fn document_for(
    product: &str,
    profile: &CompatibilityProfile,
    deployed: &BTreeMap<String, (String, CompatibilityProfile)>,
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
        let matching =
            matching_providers(product, &contract, &requirement, profile.version, deployed)?;
        match matching.as_slice() {
            [] if requirement.optional() => {
                contracts.insert(contract, DependencyContract::Absent);
            }
            [] => bail!(
                "required contract {contract} would be absent in the dependency document for {product}"
            ),
            [provider] => {
                contracts.insert(
                    contract,
                    DependencyContract::Present {
                        product: provider.product.clone(),
                        release: provider.release.clone(),
                        contract: provider.contract_version.clone(),
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

pub(crate) struct MatchingProvider {
    pub product: String,
    pub release: String,
    pub contract_version: String,
}

pub(crate) fn matching_providers(
    dependent: &str,
    contract: &str,
    requirement: &ContractRequirement,
    profile_version: u32,
    deployed: &BTreeMap<String, (String, CompatibilityProfile)>,
) -> Result<Vec<MatchingProvider>> {
    let mut matching = Vec::new();
    for (provider, (release, profile)) in deployed {
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
            if crate::software_compatibility::contract_satisfies(profile_version, &actual, &minimum)
            {
                matching.push(MatchingProvider {
                    product: provider.clone(),
                    release: release.clone(),
                    contract_version: version.clone(),
                });
                break;
            }
        }
    }
    matching.sort_by(|left, right| left.product.cmp(&right.product));
    matching.dedup_by(|left, right| left.product == right.product);
    Ok(matching)
}

/// Profiles of releases whose last deployment in `environment` succeeded.
pub async fn deployed_set(
    ctx: &mut Ctx,
    environment: &Object,
) -> Result<BTreeMap<String, (String, CompatibilityProfile)>> {
    let mut deployed = BTreeMap::new();
    for (key, version) in &environment.properties {
        let Some(product) = key.strip_prefix("deployed.") else {
            continue;
        };
        let Some(profile) = stored_profile(ctx, product, version).await? else {
            continue;
        };
        deployed.insert(product.to_string(), (version.clone(), profile));
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

/// Canonical JSON for `product` from the environment's deployed set.
pub async fn json_for_product(
    ctx: &mut Ctx,
    environment: &Object,
    product: &str,
    profile: &CompatibilityProfile,
) -> Result<Option<String>> {
    let deployed = deployed_set(ctx, environment).await?;
    match document_for(product, profile, &deployed)? {
        Some(document) => Ok(Some(document.to_canonical_json()?)),
        None => Ok(None),
    }
}

/// Record or clear `applied_dependencies.{product}` from the current deployed set.
pub async fn stamp(ctx: &mut Ctx, environment: &mut Object, product: &str) -> Result<()> {
    let key = format!("{APPLIED_PROPERTY_PREFIX}{product}");
    let Some(version) = environment
        .properties
        .get(&format!("deployed.{product}"))
        .cloned()
    else {
        environment.properties.remove(&key);
        return Ok(());
    };
    let Some(profile) = stored_profile(ctx, product, &version).await? else {
        environment.properties.remove(&key);
        return Ok(());
    };
    let deployed = deployed_set(ctx, environment).await?;
    match document_for(product, &profile, &deployed)? {
        Some(document) => {
            environment.properties.insert(key, document.digest()?);
        }
        None => {
            environment.properties.remove(&key);
        }
    }
    Ok(())
}

/// Digest last applied for `product`, empty when none.
pub fn applied_digest(environment: &Object, product: &str) -> String {
    environment
        .properties
        .get(&format!("{APPLIED_PROPERTY_PREFIX}{product}"))
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
        let deployed = BTreeMap::from([("db".into(), ("1.2.0".into(), db))]);
        let document = document_for("app", &app, &deployed).unwrap().unwrap();
        assert_eq!(document.version, 1);
        assert_eq!(
            document.contracts.get("database"),
            Some(&DependencyContract::Present {
                product: "db".into(),
                release: "1.2.0".into(),
                contract: "1.3.0".into(),
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
        let deployed = BTreeMap::from([("side".into(), ("0.1.4".into(), connector))]);
        let document = document_for("app", &app, &deployed).unwrap().unwrap();
        assert_eq!(
            document.contracts["connector"],
            DependencyContract::Present {
                product: "side".into(),
                release: "0.1.4".into(),
                contract: "0.1.4".into(),
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
            ("db".into(), ("1.0.0".into(), db.clone())),
            ("db2".into(), ("1.1.0".into(), db)),
        ]);
        let err = document_for("app", &app, &deployed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous"), "{err}");
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

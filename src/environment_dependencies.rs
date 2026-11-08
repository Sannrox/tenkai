//! Operator view of environment dependency holds, providers, and impact (ADR 0043).
//!
//! Derived only from stored deployments, subscription profiles, and
//! `dependency_hold.*`. The payload has no endpoints or credentials.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::dependency_document;
use crate::environment::{
    DependencyHold, StatusRow, UnmetContract, dependency_hold, environment, status, status_state,
};
use crate::software_compatibility::{CompatibilityProfile, RemainingDependentRefusal};

/// Environment dependency graph for status and `env dependencies`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentDependencies {
    pub environment: String,
    pub holds: Vec<DependencyHoldView>,
    pub products: Vec<ProductDependencyView>,
}

/// One durable unmet-required-contract hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DependencyHoldView {
    pub product: String,
    pub release_id: String,
    pub contracts: Vec<UnmetContract>,
    pub held_at: i64,
}

/// One subscribed or deployed product in contract plan order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProductDependencyView {
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub version: Option<String>,
    pub state: String,
    pub requirements: Vec<RequirementView>,
    pub impact: ProductImpact,
}

/// One required or optional contract on a product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RequirementView {
    pub contract: String,
    pub minimum: String,
    pub optional: bool,
    pub provider: ProviderView,
}

/// How a contract is satisfied in the deployed set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderView {
    Unique {
        product: String,
        release: String,
        contract: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        instance: String,
    },
    Absent,
    Ambiguous {
        products: Vec<String>,
    },
}

/// Remaining-dependent protection for remove, upgrade, and rollback of a product.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProductImpact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub remove: Option<ImpactRefusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub upgrade: Option<ImpactRefusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub rollback: Option<ImpactRefusal>,
}

/// A remaining installed dependent that would be unsatisfied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ImpactRefusal {
    pub dependent: String,
    pub contract: String,
}

impl EnvironmentDependencies {
    /// Empty view after tenant isolation (fixtures do not model contracts).
    pub fn empty(environment: impl Into<String>) -> Self {
        Self {
            environment: environment.into(),
            holds: Vec::new(),
            products: Vec::new(),
        }
    }

    /// Human text: holds first, then products in contract plan order.
    pub fn to_text(&self) -> String {
        let mut lines = Vec::new();
        if !self.holds.is_empty() {
            lines.push("holds:".into());
            for hold in &self.holds {
                let contracts = hold
                    .contracts
                    .iter()
                    .map(|c| {
                        if c.candidates.is_empty() {
                            format!("{} >= {}", c.contract, c.minimum)
                        } else {
                            format!(
                                "{} >= {} [{}]",
                                c.contract,
                                c.minimum,
                                c.candidates.join(", ")
                            )
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!("  {}  {contracts}", hold.product));
            }
        }
        for product in &self.products {
            let version = product.version.as_deref().unwrap_or("-");
            lines.push(format!("{} {version} {}", product.product, product.state));
            for requirement in &product.requirements {
                let optional = if requirement.optional {
                    " optional"
                } else {
                    ""
                };
                lines.push(format!(
                    "  {} >= {}{optional}  {}",
                    requirement.contract,
                    requirement.minimum,
                    provider_text(&requirement.provider)
                ));
            }
            if let Some(impact) = impact_text(&product.impact) {
                lines.push(format!("  impact: {impact}"));
            }
        }
        if lines.is_empty() {
            lines.push(format!(
                "{} has no subscribed or deployed products",
                self.environment
            ));
        }
        lines.join("\n")
    }

    /// Graphviz edges from unique or ambiguous providers to dependents.
    pub fn to_dot(&self) -> String {
        let mut lines = vec!["digraph {".into()];
        for product in &self.products {
            for requirement in &product.requirements {
                match &requirement.provider {
                    ProviderView::Unique {
                        product: provider,
                        instance,
                        ..
                    } => {
                        let from = if instance.is_empty() {
                            provider.as_str()
                        } else {
                            instance.as_str()
                        };
                        lines.push(format!(
                            "  \"{from}\" -> \"{}\" [label=\"{}\"];",
                            product.product, requirement.contract
                        ));
                    }
                    ProviderView::Ambiguous { products } => {
                        for provider in products {
                            lines.push(format!(
                                "  \"{provider}\" -> \"{}\" [label=\"{} (ambiguous)\"];",
                                product.product, requirement.contract
                            ));
                        }
                    }
                    ProviderView::Absent => {}
                }
            }
        }
        lines.push("}".into());
        lines.join("\n")
    }
}

fn provider_text(provider: &ProviderView) -> String {
    match provider {
        ProviderView::Unique {
            product,
            release,
            contract,
            instance,
        } => {
            if instance.is_empty() || instance == product {
                format!("{product}@{release} ({contract})")
            } else {
                format!("{instance} {product}@{release} ({contract})")
            }
        }
        ProviderView::Absent => "absent".into(),
        ProviderView::Ambiguous { products } => format!("ambiguous ({})", products.join(", ")),
    }
}

fn impact_text(impact: &ProductImpact) -> Option<String> {
    let mut parts = Vec::new();
    for (action, refusal) in [
        ("remove", &impact.remove),
        ("upgrade", &impact.upgrade),
        ("rollback", &impact.rollback),
    ] {
        if let Some(refusal) = refusal {
            parts.push(format!(
                "{action} refused ({} requires {})",
                refusal.dependent, refusal.contract
            ));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// Read-only dependency view for `environment`.
pub async fn for_environment(ctx: &mut Ctx, env: &str) -> Result<EnvironmentDependencies> {
    let env_obj = environment(ctx, env).await?;
    let rows = status(ctx, env).await?;
    let deployed = dependency_document::deployed_set(ctx, &env_obj).await?;
    let holds = holds_from_properties(&env_obj.properties);
    let mut products: BTreeMap<String, ViewedProduct> = BTreeMap::new();
    for (instance, deployed) in &deployed {
        products.insert(
            instance.clone(),
            ViewedProduct {
                version: Some(deployed.version.clone()),
                state: "deployed".into(),
                profile: Some(deployed.profile.clone()),
            },
        );
    }
    for row in &rows {
        let profile = profile_for_row(ctx, row).await?;
        apply_status_row(&mut products, row, profile);
    }
    let deployed_profiles: BTreeMap<String, CompatibilityProfile> = deployed
        .iter()
        .map(|(instance, deployed)| (instance.clone(), deployed.profile.clone()))
        .collect();
    let bindings =
        crate::environment_bindings::EnvironmentBindings::from_properties(&env_obj.properties);
    let mut observed = BTreeMap::new();
    for name in products.keys() {
        let Some(digest) =
            dependency_document::instance_release_digest(ctx, &env_obj, name).await?
        else {
            continue;
        };
        observed.insert(
            name.clone(),
            crate::software_compatibility::observed_contract_versions(ctx, env, &digest).await?,
        );
    }
    view_from(
        env,
        holds,
        &products,
        &deployed,
        &deployed_profiles,
        &bindings,
        &observed,
    )
}

struct ViewedProduct {
    version: Option<String>,
    state: String,
    profile: Option<CompatibilityProfile>,
}

/// Overlay a status row. A dependency hold uses the held release's profile,
/// not the currently deployed one.
fn apply_status_row(
    products: &mut BTreeMap<String, ViewedProduct>,
    row: &StatusRow,
    profile: Option<CompatibilityProfile>,
) {
    let instance = if row.instance.is_empty() {
        row.product.as_str()
    } else {
        row.instance.as_str()
    };
    let entry = products
        .entry(instance.to_string())
        .or_insert(ViewedProduct {
            version: row.deployed.clone(),
            state: status_state(row).to_string(),
            profile: None,
        });
    entry.version = row.deployed.clone().or_else(|| {
        if row.head != "-" {
            Some(row.head.clone())
        } else {
            None
        }
    });
    entry.state = status_state(row).to_string();
    if row.dependency_hold.is_some() {
        if profile.is_some() {
            entry.profile = profile;
        }
    } else if entry.profile.is_none() {
        entry.profile = profile;
    }
}

fn holds_from_properties(properties: &HashMap<String, String>) -> Vec<(String, DependencyHold)> {
    let mut products = BTreeSet::new();
    for key in properties.keys() {
        if let Some(product) = key.strip_prefix("dependency_hold.") {
            products.insert(product.to_string());
        }
    }
    let mut holds = Vec::new();
    for product in products {
        if let Some(hold) = dependency_hold(properties, &product) {
            holds.push((product, hold));
        }
    }
    holds
}

async fn profile_for_row(ctx: &mut Ctx, row: &StatusRow) -> Result<Option<CompatibilityProfile>> {
    if let Some(hold) = &row.dependency_hold {
        return dependency_document::stored_profile_by_id(ctx, &hold.release_id).await;
    }
    if let Some(version) = row.deployed.as_deref() {
        return dependency_document::stored_profile(ctx, &row.product, version).await;
    }
    if row.head != "-" {
        return dependency_document::stored_profile(ctx, &row.product, &row.head).await;
    }
    Ok(None)
}

fn view_from(
    environment: &str,
    holds: Vec<(String, DependencyHold)>,
    products: &BTreeMap<String, ViewedProduct>,
    deployed: &BTreeMap<String, dependency_document::DeployedRelease>,
    deployed_profiles: &BTreeMap<String, CompatibilityProfile>,
    bindings: &crate::environment_bindings::EnvironmentBindings,
    observed: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<EnvironmentDependencies> {
    let members: BTreeSet<String> = products.keys().cloned().collect();
    let mut edges = Vec::new();
    let mut views = BTreeMap::new();
    let empty = BTreeMap::new();
    for (name, product) in products {
        let requirements = requirements_for(
            name,
            product.profile.as_ref(),
            deployed,
            bindings,
            observed.get(name).unwrap_or(&empty),
        )?;
        for requirement in &requirements {
            if let ProviderView::Unique {
                product: provider,
                instance,
                ..
            } = &requirement.provider
            {
                let from = if instance.is_empty() {
                    provider.as_str()
                } else {
                    instance.as_str()
                };
                if members.contains(from) {
                    edges.push((from.to_string(), name.clone()));
                }
            }
        }
        views.insert(
            name.clone(),
            ProductDependencyView {
                product: name.clone(),
                version: product.version.clone(),
                state: product.state.clone(),
                requirements,
                impact: impact_for(name, deployed_profiles, bindings)?,
            },
        );
    }
    let order = contract_plan_names(&members, &edges);
    Ok(EnvironmentDependencies {
        environment: environment.to_string(),
        holds: holds
            .into_iter()
            .map(|(product, hold)| DependencyHoldView {
                product,
                release_id: hold.release_id,
                contracts: hold
                    .contracts
                    .into_iter()
                    .map(|(contract, minimum)| {
                        let candidates =
                            hold.candidates.get(&contract).cloned().unwrap_or_default();
                        UnmetContract {
                            contract,
                            minimum,
                            candidates,
                        }
                    })
                    .collect(),
                held_at: hold.held_at,
            })
            .collect(),
        products: order
            .into_iter()
            .filter_map(|name| views.remove(&name))
            .collect(),
    })
}

fn requirements_for(
    product: &str,
    profile: Option<&CompatibilityProfile>,
    deployed: &BTreeMap<String, dependency_document::DeployedRelease>,
    bindings: &crate::environment_bindings::EnvironmentBindings,
    observed: &BTreeMap<String, String>,
) -> Result<Vec<RequirementView>> {
    let Some(profile) = profile else {
        return Ok(Vec::new());
    };
    let mut requirements = BTreeMap::new();
    for component in profile.components.values() {
        for (contract, requirement) in &component.requires {
            requirements.insert(contract.clone(), requirement.clone());
        }
    }
    let mut out = Vec::new();
    for (contract, requirement) in requirements {
        if dependency_document::self_satisfies(profile, &contract, &requirement)? {
            continue;
        }
        let matching = crate::environment_bindings::select_matching(
            product,
            &contract,
            dependency_document::matching_providers(
                product,
                &contract,
                &requirement,
                profile.version,
                deployed,
                observed,
            )?,
            bindings,
        );
        let provider = match matching.as_slice() {
            [] => ProviderView::Absent,
            [provider] => ProviderView::Unique {
                product: provider.product.clone(),
                release: provider.release.clone(),
                contract: provider.contract_version.clone(),
                instance: if provider.instance == provider.product {
                    String::new()
                } else {
                    provider.instance.clone()
                },
            },
            several => ProviderView::Ambiguous {
                products: several.iter().map(|m| m.instance.clone()).collect(),
            },
        };
        out.push(RequirementView {
            contract,
            minimum: requirement.minimum().to_string(),
            optional: requirement.optional(),
            provider,
        });
    }
    Ok(out)
}

fn impact_for(
    product: &str,
    deployed_profiles: &BTreeMap<String, CompatibilityProfile>,
    bindings: &crate::environment_bindings::EnvironmentBindings,
) -> Result<ProductImpact> {
    if !deployed_profiles.contains_key(product) {
        return Ok(ProductImpact::default());
    }
    let mut without = deployed_profiles.clone();
    without.remove(product);
    let remove = refusal_view(
        crate::software_compatibility::remaining_dependent_refusal_bound(
            &without,
            deployed_profiles,
            bindings,
        )?,
    );
    let mut dropped = deployed_profiles.clone();
    if let Some(profile) = dropped.get_mut(product) {
        for component in profile.components.values_mut() {
            component.provides.clear();
        }
    }
    let drop_provides = refusal_view(
        crate::software_compatibility::remaining_dependent_refusal_bound(
            &dropped,
            deployed_profiles,
            bindings,
        )?,
    );
    Ok(ProductImpact {
        remove,
        upgrade: drop_provides.clone(),
        rollback: drop_provides,
    })
}

fn refusal_view(refusal: Option<RemainingDependentRefusal>) -> Option<ImpactRefusal> {
    refusal.map(|refusal| ImpactRefusal {
        dependent: refusal.dependent,
        contract: refusal.contract,
    })
}

/// Providers before dependents; name order among products with no unique edge.
fn contract_plan_names(members: &BTreeSet<String>, edges: &[(String, String)]) -> Vec<String> {
    let mut incoming: BTreeMap<&str, usize> =
        members.iter().map(|name| (name.as_str(), 0)).collect();
    let mut outgoing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (from, to) in edges {
        if !members.contains(from) || !members.contains(to) || from == to {
            continue;
        }
        *incoming.entry(to.as_str()).or_default() += 1;
        outgoing.entry(from.as_str()).or_default().push(to.as_str());
    }
    let mut ready: BTreeSet<&str> = incoming
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(name, _)| *name)
        .collect();
    let mut order = Vec::new();
    while let Some(next) = ready.iter().next().copied() {
        ready.remove(next);
        order.push(next.to_string());
        if let Some(children) = outgoing.get(next) {
            for child in children {
                if let Some(count) = incoming.get_mut(child) {
                    *count -= 1;
                    if *count == 0 {
                        ready.insert(child);
                    }
                }
            }
        }
    }
    for leftover in members {
        if !order.iter().any(|name| name == leftover) {
            order.push(leftover.clone());
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{StatusDependencyHold, StatusRow};
    use crate::software_compatibility::{
        CompatibilityProfile, ComponentPin, ComponentRequirement, ContractRequirement,
    };

    fn profile(requires: &[(&str, &str, bool)], provides: &[(&str, &str)]) -> CompatibilityProfile {
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

    fn product(version: &str, state: &str, profile: CompatibilityProfile) -> ViewedProduct {
        ViewedProduct {
            version: Some(version.into()),
            state: state.into(),
            profile: Some(profile),
        }
    }

    fn rel(
        name: &str,
        version: &str,
        profile: CompatibilityProfile,
    ) -> (String, dependency_document::DeployedRelease) {
        (
            name.into(),
            dependency_document::DeployedRelease::of(name, version, profile),
        )
    }

    fn view(
        holds: Vec<(String, DependencyHold)>,
        products: BTreeMap<String, ViewedProduct>,
        deployed: BTreeMap<String, dependency_document::DeployedRelease>,
    ) -> EnvironmentDependencies {
        let deployed_profiles = deployed
            .iter()
            .map(|(name, deployed)| (name.clone(), deployed.profile.clone()))
            .collect();
        view_from(
            "local",
            holds,
            &products,
            &deployed,
            &deployed_profiles,
            &crate::environment_bindings::EnvironmentBindings::default(),
            &BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn providers_precede_dependents_and_unique_provider_is_named() {
        let db = profile(&[], &[("database", "1.0.0")]);
        let app = profile(&[("database", "1.0.0", false)], &[]);
        let deployed = BTreeMap::from([
            rel("app", "1.0.0", app.clone()),
            rel("db", "1.2.0", db.clone()),
        ]);
        let products = BTreeMap::from([
            ("app".into(), product("1.0.0", "current", app)),
            ("db".into(), product("1.2.0", "current", db)),
        ]);
        let view = view(Vec::new(), products, deployed);
        let names: Vec<_> = view.products.iter().map(|p| p.product.as_str()).collect();
        assert_eq!(names, ["db", "app"]);
        assert_eq!(
            view.products[1].requirements,
            vec![RequirementView {
                contract: "database".into(),
                minimum: "1.0.0".into(),
                optional: false,
                provider: ProviderView::Unique {
                    product: "db".into(),
                    release: "1.2.0".into(),
                    contract: "1.0.0".into(),
                    instance: String::new(),
                },
            }]
        );
        let impact = &view.products[0].impact;
        assert_eq!(
            impact
                .remove
                .as_ref()
                .map(|r| (r.dependent.as_str(), r.contract.as_str())),
            Some(("app", "database"))
        );
        assert_eq!(impact.upgrade, impact.remove);
        assert_eq!(impact.rollback, impact.remove);
        let text = view.to_text();
        assert!(text.contains("db 1.2.0 current"), "{text}");
        assert!(text.contains("app 1.0.0 current"), "{text}");
        assert!(text.contains("db@1.2.0"), "{text}");
        assert!(
            text.contains("remove refused (app requires database)"),
            "{text}"
        );
        let dot = view.to_dot();
        assert!(
            dot.contains("\"db\" -> \"app\" [label=\"database\"]"),
            "{dot}"
        );
    }

    #[test]
    fn optional_absent_and_ambiguous_providers() {
        let app = profile(
            &[("database", "1.0.0", false), ("connector", "0.1.0", true)],
            &[],
        );
        let db = profile(&[], &[("database", "1.0.0")]);
        let other = profile(&[], &[("database", "1.0.0")]);
        let deployed = BTreeMap::from([
            rel("app", "1.0.0", app.clone()),
            rel("db", "1.0.0", db.clone()),
            rel("other", "1.0.0", other.clone()),
        ]);
        let products = BTreeMap::from([
            ("app".into(), product("1.0.0", "current", app)),
            ("db".into(), product("1.0.0", "current", db)),
            ("other".into(), product("1.0.0", "current", other)),
        ]);
        let view = view(Vec::new(), products, deployed);
        let app = view.products.iter().find(|p| p.product == "app").unwrap();
        assert_eq!(
            app.requirements
                .iter()
                .find(|r| r.contract == "connector")
                .map(|r| &r.provider),
            Some(&ProviderView::Absent)
        );
        match app
            .requirements
            .iter()
            .find(|r| r.contract == "database")
            .map(|r| &r.provider)
        {
            Some(ProviderView::Ambiguous { products }) => {
                assert_eq!(products, &["db".to_string(), "other".to_string()]);
            }
            other => panic!("expected ambiguous, got {other:?}"),
        }
        for provider in ["db", "other"] {
            assert_eq!(
                view.products
                    .iter()
                    .find(|p| p.product == provider)
                    .map(|p| p.impact.remove.is_some()),
                Some(false),
                "{provider}"
            );
        }
        let text = view.to_text();
        assert!(text.contains("absent"), "{text}");
        assert!(text.contains("ambiguous (db, other)"), "{text}");
        let dot = view.to_dot();
        assert!(dot.contains("ambiguous"), "{dot}");
    }

    #[test]
    fn optional_only_provider_remove_is_allowed() {
        let app = profile(&[("connector", "0.1.0", true)], &[]);
        let side = profile(&[], &[("connector", "0.1.0")]);
        let deployed = BTreeMap::from([
            rel("app", "1.0.0", app.clone()),
            rel("side", "1.0.0", side.clone()),
        ]);
        let products = BTreeMap::from([
            ("app".into(), product("1.0.0", "current", app)),
            ("side".into(), product("1.0.0", "current", side)),
        ]);
        let view = view(Vec::new(), products, deployed);
        let side = view.products.iter().find(|p| p.product == "side").unwrap();
        assert_eq!(side.impact, ProductImpact::default());
    }

    #[test]
    fn hold_uses_held_release_profile_not_deployed() {
        let deployed_app = profile(&[], &[]);
        let held_app = profile(&[("database", "2.0.0", false)], &[]);
        let mut products =
            BTreeMap::from([("app".into(), product("1.0.0", "current", deployed_app))]);
        let row = StatusRow {
            product: "app".into(),

            instance: "app".into(),
            channel: "stable".into(),
            deployed: Some("1.0.0".into()),
            health: None,
            error: None,
            head: "2.0.0".into(),
            overlay_stale: false,
            delivery_hold: None,
            dependency_hold: Some(StatusDependencyHold {
                release_id: "tenkai:release:app@2.0.0".into(),
                contracts: vec![UnmetContract {
                    contract: "database".into(),
                    minimum: "2.0.0".into(),
                    candidates: Vec::new(),
                }],
                held_at: 1,
            }),
        };
        apply_status_row(&mut products, &row, Some(held_app));
        assert_eq!(products["app"].state, "waiting");
        let hold = DependencyHold {
            release_id: "tenkai:release:app@2.0.0".into(),
            contracts: vec![("database".into(), "2.0.0".into())],
            held_at: 1,
            candidates: BTreeMap::new(),
        };
        let view = view(vec![("app".into(), hold)], products, BTreeMap::new());
        assert_eq!(view.products[0].state, "waiting");
        assert_eq!(
            view.products[0].requirements,
            vec![RequirementView {
                contract: "database".into(),
                minimum: "2.0.0".into(),
                optional: false,
                provider: ProviderView::Absent,
            }]
        );
    }

    #[test]
    fn holds_list_first_and_waiting_product_names_absent_provider() {
        let app = profile(&[("database", "1.0.0", false)], &[]);
        let hold = DependencyHold {
            release_id: "tenkai:release:app@1.0.0".into(),
            contracts: vec![("database".into(), "1.0.0".into())],
            held_at: 10,
            candidates: BTreeMap::new(),
        };
        let products = BTreeMap::from([("app".into(), product("1.0.0", "waiting", app.clone()))]);
        let view = view(vec![("app".into(), hold)], products, BTreeMap::new());
        assert_eq!(view.holds[0].product, "app");
        assert_eq!(
            view.holds[0].contracts,
            vec![UnmetContract {
                contract: "database".into(),
                minimum: "1.0.0".into(),
                candidates: Vec::new(),
            }]
        );
        assert_eq!(view.products[0].state, "waiting");
        assert_eq!(
            view.products[0].requirements[0].provider,
            ProviderView::Absent
        );
        let text = view.to_text();
        assert!(text.starts_with("holds:"), "{text}");
        assert!(text.contains("app  database >= 1.0.0"), "{text}");
    }

    #[test]
    fn payload_omits_endpoints_and_instance_names() {
        let db = profile(&[], &[("database", "1.0.0")]);
        let app = profile(&[("database", "1.0.0", false)], &[]);
        let deployed = BTreeMap::from([
            rel("app", "1.0.0", app.clone()),
            rel("db", "1.0.0", db.clone()),
        ]);
        let products = BTreeMap::from([
            ("app".into(), product("1.0.0", "current", app)),
            ("db".into(), product("1.0.0", "current", db)),
        ]);
        let json = serde_json::to_string(&view(Vec::new(), products, deployed)).unwrap();
        for forbidden in ["endpoint", "credential", "instance", "host", "password"] {
            assert!(
                !json.to_ascii_lowercase().contains(forbidden),
                "{forbidden} in {json}"
            );
        }
    }
}

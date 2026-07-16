//! Deterministic dependency and version resolution.

use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub product: String,
    pub requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub product: String,
    pub version: String,
    pub dependencies: Vec<Dependency>,
    /// Exact fact values required by this release. Candidates with missing or
    /// different environment facts are not eligible.
    pub required_facts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// Channel heads are fixed roots; dependency releases may be selected from
    /// any compatible published candidate.
    pub roots: BTreeMap<String, String>,
    /// Environment pins/ranges, grouped by product. Every range must match.
    pub version_requirements: BTreeMap<String, Vec<String>>,
    pub facts: BTreeMap<String, String>,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub selected: BTreeMap<String, String>,
    /// Dependencies precede dependents. Ties are ordered by product name.
    pub install_order: Vec<String>,
}

impl Resolution {
    pub fn removal_order(&self) -> Vec<String> {
        self.install_order.iter().rev().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionError(String);

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ResolutionError {}

#[derive(Clone)]
struct ParsedDependency {
    product: String,
    requirement: VersionReq,
    expression: String,
}

#[derive(Clone)]
struct ParsedCandidate {
    version: Version,
    version_text: String,
    dependencies: Vec<ParsedDependency>,
    required_facts: BTreeMap<String, String>,
}

#[derive(Clone)]
struct Requirement {
    range: VersionReq,
    exact_versions: Vec<String>,
    expression: String,
    source: String,
}

struct Catalog {
    by_product: BTreeMap<String, Vec<ParsedCandidate>>,
}

pub fn resolve(request: &Request) -> Result<Resolution, ResolutionError> {
    let catalog = parse_catalog(&request.candidates)?;
    let mut requirements = BTreeMap::<String, Vec<Requirement>>::new();
    for (product, expressions) in &request.version_requirements {
        for expression in expressions {
            add_requirement(
                &mut requirements,
                product,
                expression,
                format!("environment constraint on {product}"),
            )?;
        }
    }
    for (product, version) in &request.roots {
        Version::parse(version).map_err(|error| {
            ResolutionError(format!(
                "channel head {product}@{version} is not valid semver: {error}"
            ))
        })?;
        add_requirement(
            &mut requirements,
            product,
            &format!("={version}"),
            format!("subscribed channel head {product}@{version}"),
        )?;
    }

    let selected = search(
        &catalog,
        &request.roots,
        &request.facts,
        requirements,
        BTreeMap::new(),
    )?;
    let install_order = topological_order(&selected)?;
    let selected = selected
        .into_iter()
        .map(|(product, candidate)| (product, candidate.version_text))
        .collect();
    Ok(Resolution {
        selected,
        install_order,
    })
}

fn parse_catalog(candidates: &[Candidate]) -> Result<Catalog, ResolutionError> {
    let mut by_product = BTreeMap::<String, Vec<ParsedCandidate>>::new();
    let mut identities = BTreeSet::new();
    for candidate in candidates {
        let version = Version::parse(&candidate.version).map_err(|error| {
            ResolutionError(format!(
                "published release {}@{} is not valid semver: {error}",
                candidate.product, candidate.version
            ))
        })?;
        if !identities.insert((candidate.product.clone(), version.clone())) {
            return Err(ResolutionError(format!(
                "catalog contains duplicate release {}@{}",
                candidate.product, candidate.version
            )));
        }
        let mut dependencies = Vec::new();
        let mut dependency_products = BTreeSet::new();
        for dependency in &candidate.dependencies {
            if dependency.product == candidate.product {
                return Err(ResolutionError(format!(
                    "release {}@{} depends on itself",
                    candidate.product, candidate.version
                )));
            }
            if !dependency_products.insert(dependency.product.clone()) {
                return Err(ResolutionError(format!(
                    "release {}@{} declares dependency {} more than once",
                    candidate.product, candidate.version, dependency.product
                )));
            }
            let requirement = VersionReq::parse(&dependency.requirement).map_err(|error| {
                ResolutionError(format!(
                    "release {}@{} has invalid dependency range {} for {}: {error}",
                    candidate.product,
                    candidate.version,
                    dependency.requirement,
                    dependency.product
                ))
            })?;
            dependencies.push(ParsedDependency {
                product: dependency.product.clone(),
                requirement,
                expression: dependency.requirement.clone(),
            });
        }
        dependencies.sort_by(|a, b| a.product.cmp(&b.product));
        by_product
            .entry(candidate.product.clone())
            .or_default()
            .push(ParsedCandidate {
                version,
                version_text: candidate.version.clone(),
                dependencies,
                required_facts: candidate.required_facts.clone(),
            });
    }
    for candidates in by_product.values_mut() {
        candidates.sort_by(|a, b| b.version.cmp(&a.version));
    }
    Ok(Catalog { by_product })
}

fn add_requirement(
    requirements: &mut BTreeMap<String, Vec<Requirement>>,
    product: &str,
    expression: &str,
    source: String,
) -> Result<(), ResolutionError> {
    let range = VersionReq::parse(expression).map_err(|error| {
        ResolutionError(format!(
            "invalid version requirement {expression} for {product}: {error}"
        ))
    })?;
    requirements
        .entry(product.to_string())
        .or_default()
        .push(Requirement {
            range,
            exact_versions: exact_versions(expression),
            expression: expression.to_string(),
            source,
        });
    Ok(())
}

fn search(
    catalog: &Catalog,
    roots: &BTreeMap<String, String>,
    facts: &BTreeMap<String, String>,
    requirements: BTreeMap<String, Vec<Requirement>>,
    selected: BTreeMap<String, ParsedCandidate>,
) -> Result<BTreeMap<String, ParsedCandidate>, ResolutionError> {
    for (product, candidate) in &selected {
        if let Some(required) = requirements.get(product)
            && !required
                .iter()
                .all(|item| requirement_matches(item, candidate))
        {
            return Err(conflict(product, required, catalog, facts));
        }
    }
    let Some(product) = requirements
        .keys()
        .find(|product| !selected.contains_key(*product))
        .cloned()
    else {
        topological_order(&selected)?;
        return Ok(selected);
    };
    let required = requirements.get(&product).expect("selected map checked");
    let Some(candidates) = catalog.by_product.get(&product) else {
        return Err(ResolutionError(format!(
            "dependency {product} has no published releases (required by {})",
            requirement_sources(required)
        )));
    };
    let forced = roots.get(&product);
    let eligible = candidates.iter().filter(|candidate| {
        forced.is_none_or(|version| version == &candidate.version_text)
            && required
                .iter()
                .all(|item| requirement_matches(item, candidate))
            && facts_match(candidate, facts)
    });
    let mut last_error = None;
    for candidate in eligible {
        let mut next_selected = selected.clone();
        next_selected.insert(product.clone(), candidate.clone());
        let mut next_requirements = requirements.clone();
        let mut invalid = None;
        for dependency in &candidate.dependencies {
            let requirement = Requirement {
                range: dependency.requirement.clone(),
                exact_versions: exact_versions(&dependency.expression),
                expression: dependency.expression.clone(),
                source: format!("{}@{}", product, candidate.version_text),
            };
            next_requirements
                .entry(dependency.product.clone())
                .or_default()
                .push(requirement.clone());
            if let Some(selected_dependency) = next_selected.get(&dependency.product)
                && !requirement_matches(&requirement, selected_dependency)
            {
                invalid = Some(conflict(
                    &dependency.product,
                    next_requirements
                        .get(&dependency.product)
                        .expect("dependency requirement inserted"),
                    catalog,
                    facts,
                ));
                break;
            }
        }
        if let Some(error) = invalid {
            last_error = Some(error);
            continue;
        }
        match search(catalog, roots, facts, next_requirements, next_selected) {
            Ok(solution) => return Ok(solution),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| conflict(&product, required, catalog, facts)))
}

fn requirement_matches(requirement: &Requirement, candidate: &ParsedCandidate) -> bool {
    requirement.range.matches(&candidate.version)
        && requirement
            .exact_versions
            .iter()
            .all(|exact| exact == &candidate.version_text)
}

fn exact_versions(expression: &str) -> Vec<String> {
    expression
        .split(',')
        .filter_map(|comparator| comparator.trim().strip_prefix('='))
        .map(str::trim)
        .filter(|version| Version::parse(version).is_ok())
        .map(str::to_string)
        .collect()
}

fn facts_match(candidate: &ParsedCandidate, facts: &BTreeMap<String, String>) -> bool {
    candidate
        .required_facts
        .iter()
        .all(|(name, value)| facts.get(name) == Some(value))
}

fn requirement_sources(requirements: &[Requirement]) -> String {
    let mut descriptions = requirements
        .iter()
        .map(|item| format!("{} requires {}", item.source, item.expression))
        .collect::<Vec<_>>();
    descriptions.sort();
    descriptions.dedup();
    descriptions.join(", ")
}

fn conflict(
    product: &str,
    requirements: &[Requirement],
    catalog: &Catalog,
    facts: &BTreeMap<String, String>,
) -> ResolutionError {
    let available = catalog
        .by_product
        .get(product)
        .map(|candidates| {
            candidates
                .iter()
                .map(|candidate| {
                    if facts_match(candidate, facts) {
                        candidate.version_text.clone()
                    } else {
                        let missing = candidate
                            .required_facts
                            .iter()
                            .filter(|(name, value)| facts.get(*name) != Some(*value))
                            .map(|(name, value)| format!("{name}={value}"))
                            .collect::<Vec<_>>()
                            .join(" and ");
                        format!("{} (needs {missing})", candidate.version_text)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "none".to_string());
    ResolutionError(format!(
        "no release of {product} satisfies {}; published candidates: {available}",
        requirement_sources(requirements)
    ))
}

fn topological_order(
    selected: &BTreeMap<String, ParsedCandidate>,
) -> Result<Vec<String>, ResolutionError> {
    let mut dependents = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = selected
        .keys()
        .map(|product| (product.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (product, candidate) in selected {
        for dependency in &candidate.dependencies {
            if selected.contains_key(&dependency.product)
                && dependents
                    .entry(dependency.product.clone())
                    .or_default()
                    .insert(product.clone())
            {
                *indegree.get_mut(product).expect("selected product") += 1;
            }
        }
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(product, _)| product.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(selected.len());
    while let Some(product) = ready.pop_first() {
        order.push(product.clone());
        if let Some(children) = dependents.get(&product) {
            for child in children {
                let degree = indegree.get_mut(child).expect("selected dependent");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }
    if order.len() != selected.len() {
        let remaining = indegree
            .into_iter()
            .filter(|(_, degree)| *degree > 0)
            .map(|(product, _)| product)
            .collect::<Vec<_>>();
        return Err(ResolutionError(format!(
            "dependency cycle detected among {}",
            remaining.join(" -> ")
        )));
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(product: &str, version: &str, dependencies: &[(&str, &str)]) -> Candidate {
        Candidate {
            product: product.into(),
            version: version.into(),
            dependencies: dependencies
                .iter()
                .map(|(product, requirement)| Dependency {
                    product: (*product).into(),
                    requirement: (*requirement).into(),
                })
                .collect(),
            required_facts: BTreeMap::new(),
        }
    }

    #[test]
    fn resolves_transitive_dependencies_before_dependents() {
        let request = Request {
            roots: BTreeMap::from([("web".into(), "2.0.0".into())]),
            candidates: vec![
                candidate("web", "2.0.0", &[("api", "^2")]),
                candidate("api", "2.1.0", &[("db", ">=1.0, <2")]),
                candidate("db", "1.5.0", &[]),
            ],
            ..Request::default()
        };
        let result = resolve(&request).unwrap();
        assert_eq!(result.install_order, ["db", "api", "web"]);
        assert_eq!(result.removal_order(), ["web", "api", "db"]);
    }

    #[test]
    fn selects_highest_compatible_published_release() {
        let request = Request {
            roots: BTreeMap::from([("app".into(), "1.0.0".into())]),
            candidates: vec![
                candidate("app", "1.0.0", &[("runtime", "^1")]),
                candidate("runtime", "2.0.0", &[]),
                candidate("runtime", "1.4.0", &[]),
                candidate("runtime", "1.2.0", &[]),
            ],
            ..Request::default()
        };
        assert_eq!(resolve(&request).unwrap().selected["runtime"], "1.4.0");
    }

    #[test]
    fn environment_pin_cannot_be_overridden_by_a_dependency() {
        let request = Request {
            roots: BTreeMap::from([("app".into(), "1.0.0".into())]),
            version_requirements: BTreeMap::from([("runtime".into(), vec!["=1.0.0".into()])]),
            candidates: vec![
                candidate("app", "1.0.0", &[("runtime", ">=2")]),
                candidate("runtime", "2.0.0", &[]),
                candidate("runtime", "1.0.0", &[]),
            ],
            ..Request::default()
        };
        let error = resolve(&request).unwrap_err().to_string();
        assert!(error.contains("environment constraint on runtime requires =1.0.0"));
        assert!(error.contains("app@1.0.0 requires >=2"));
    }

    #[test]
    fn release_facts_fail_closed_when_missing() {
        let mut gated = candidate("runtime", "1.0.0", &[]);
        gated.required_facts.insert("gpu".into(), "cuda".into());
        let request = Request {
            roots: BTreeMap::from([("runtime".into(), "1.0.0".into())]),
            candidates: vec![gated],
            ..Request::default()
        };
        let error = resolve(&request).unwrap_err().to_string();
        assert!(error.contains("needs gpu=cuda"));
    }

    #[test]
    fn cycles_produce_no_ordered_solution() {
        let request = Request {
            roots: BTreeMap::from([("a".into(), "1.0.0".into())]),
            candidates: vec![
                candidate("a", "1.0.0", &[("b", "*")]),
                candidate("b", "1.0.0", &[("a", "*")]),
            ],
            ..Request::default()
        };
        assert!(resolve(&request).unwrap_err().to_string().contains("cycle"));
    }

    #[test]
    fn cycle_in_a_preferred_candidate_backtracks_to_a_valid_release() {
        let request = Request {
            roots: BTreeMap::from([("a".into(), "1.0.0".into())]),
            candidates: vec![
                candidate("a", "1.0.0", &[("b", "*")]),
                candidate("b", "2.0.0", &[("a", "*")]),
                candidate("b", "1.0.0", &[]),
            ],
            ..Request::default()
        };
        let resolution = resolve(&request).unwrap();
        assert_eq!(resolution.selected["b"], "1.0.0");
        assert_eq!(resolution.install_order, ["b", "a"]);
    }

    #[test]
    fn exact_pins_include_build_metadata() {
        let request = Request {
            roots: BTreeMap::from([("app".into(), "1.0.0".into())]),
            version_requirements: BTreeMap::from([(
                "runtime".into(),
                vec!["=1.0.0+expected".into()],
            )]),
            candidates: vec![
                candidate("app", "1.0.0", &[("runtime", "*")]),
                candidate("runtime", "1.0.0+other", &[]),
            ],
            ..Request::default()
        };
        let error = resolve(&request).unwrap_err().to_string();
        assert!(error.contains("=1.0.0+expected"));
    }

    #[test]
    fn exact_build_pins_allow_whitespace_and_compound_comparators() {
        for requirement in [" =1.0.0+expected", ">=1.0.0, =1.0.0+expected"] {
            let request = Request {
                roots: BTreeMap::from([("app".into(), "1.0.0".into())]),
                version_requirements: BTreeMap::from([(
                    "runtime".into(),
                    vec![requirement.into()],
                )]),
                candidates: vec![
                    candidate("app", "1.0.0", &[("runtime", "*")]),
                    candidate("runtime", "1.0.0+other", &[]),
                ],
                ..Request::default()
            };
            assert!(resolve(&request).is_err(), "requirement {requirement}");
        }
    }

    #[test]
    fn input_order_does_not_change_the_resolution() {
        let candidates = vec![
            candidate("z", "1.0.0", &[("a", "*")]),
            candidate("a", "1.0.0", &[]),
            candidate("m", "1.0.0", &[]),
        ];
        let first = resolve(&Request {
            roots: BTreeMap::from([("z".into(), "1.0.0".into()), ("m".into(), "1.0.0".into())]),
            candidates: candidates.clone(),
            ..Request::default()
        })
        .unwrap();
        let second = resolve(&Request {
            roots: BTreeMap::from([("m".into(), "1.0.0".into()), ("z".into(), "1.0.0".into())]),
            candidates: candidates.into_iter().rev().collect(),
            ..Request::default()
        })
        .unwrap();
        assert_eq!(first, second);
    }
}

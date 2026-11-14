//! Operator grouping labels on environments and releases, and selector resolve.
//!
//! Labels sit beside capability facts: facts are host inventory, labels are
//! how an operator groups the fleet. A selector expands to concrete
//! environment names at the moment an existing list-taking operation runs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT, KIND_RELEASE, release_id, validate_identifier};
use crate::pb::sekai::Object;

const PROPERTY_PREFIX: &str = "label.";

/// One `key=value`, `key!=value`, or `key in (a,b)` clause. Commas between
/// clauses mean AND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    source: String,
    clauses: Vec<Clause>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Clause {
    Equals {
        key: String,
        value: String,
    },
    NotEquals {
        key: String,
        value: String,
    },
    In {
        key: String,
        values: BTreeSet<String>,
    },
}

impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.source)
    }
}

impl Selector {
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// True when `input` is a selector rather than a comma-separated name list.
pub fn looks_like_selector(input: &str) -> bool {
    let input = input.trim();
    input.contains('=') || input.contains(" in (") || input.contains(" in(")
}

pub fn validate_label_key(key: &str) -> Result<()> {
    validate_identifier("label key", key)
        .map_err(|error| anyhow::anyhow!("invalid label key {key:?}: {error}"))
}

pub fn validate_label_value(key: &str, value: &str) -> Result<()> {
    validate_identifier("label value", value)
        .map_err(|error| anyhow::anyhow!("invalid label value {value:?} for key {key}: {error}"))
}

pub fn parse_label_pair(spec: &str) -> Result<(String, String)> {
    let Some((key, value)) = spec.split_once('=') else {
        bail!("expected <key>=<value>, got {spec:?}");
    };
    let key = key.trim();
    let value = value.trim();
    validate_label_key(key)?;
    validate_label_value(key, value)?;
    Ok((key.to_string(), value.to_string()))
}

/// Query of `GET /v1/environments`.
#[derive(Debug, Clone, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct EnvironmentListQuery {
    /// Only environments matching this selector (`key=value`, `key!=value`,
    /// `key in (a,b)`). Omitted or blank lists every environment.
    #[serde(default)]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub selector: Option<String>,
}

/// Why a selector does not parse. `clause` names the clause that is wrong,
/// and is `None` when the selector as a whole is malformed (empty, an empty
/// clause, or unbalanced parentheses).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SelectorError {
    pub clause: Option<String>,
    pub message: String,
}

impl SelectorError {
    fn whole(error: impl std::fmt::Display) -> Self {
        Self {
            clause: None,
            message: error.to_string(),
        }
    }
}

pub fn parse_selector(input: &str) -> std::result::Result<Selector, SelectorError> {
    let source = input.trim();
    if source.is_empty() {
        return Err(SelectorError::whole("selector must not be empty"));
    }
    let mut clauses = Vec::new();
    for clause in split_clauses(source).map_err(SelectorError::whole)? {
        clauses.push(parse_clause(clause).map_err(|error| SelectorError {
            clause: Some(clause.to_string()),
            message: error.to_string(),
        })?);
    }
    Ok(Selector {
        source: source.to_string(),
        clauses,
    })
}

/// Comma-separated names, or a selector that stands in for that list.
pub async fn resolve_cohort(ctx: &mut Ctx, input: &str) -> Result<Vec<String>> {
    let input = input.trim();
    if looks_like_selector(input) {
        require_matching_environments(ctx, &parse_selector(input)?).await
    } else {
        parse_name_list(input)
    }
}

pub fn parse_name_list(input: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    for name in input.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        validate_identifier("environment", name)?;
        if !seen.insert(name.to_string()) {
            bail!("environment list contains duplicate environment {name}");
        }
        names.push(name.to_string());
    }
    if names.is_empty() {
        bail!("environment list must not be empty");
    }
    Ok(names)
}

pub fn labels_from_object(object: &Object) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    for (key, value) in &object.properties {
        if let Some(name) = key.strip_prefix(PROPERTY_PREFIX) {
            labels.insert(name.to_string(), value.clone());
        }
    }
    labels
}

pub fn matches(labels: &BTreeMap<String, String>, selector: &Selector) -> bool {
    selector.clauses.iter().all(|clause| match clause {
        Clause::Equals { key, value } => labels.get(key).is_some_and(|have| have == value),
        Clause::NotEquals { key, value } => labels.get(key).is_none_or(|have| have != value),
        Clause::In { key, values } => labels.get(key).is_some_and(|have| values.contains(have)),
    })
}

pub async fn matching_environments(ctx: &mut Ctx, selector: &Selector) -> Result<Vec<String>> {
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = Vec::new();
    for object in environments {
        if crate::environment::retirement_from_object(&object).is_some() {
            continue;
        }
        if matches(&labels_from_object(&object), selector) {
            names.push(object.name);
        }
    }
    Ok(names)
}

pub async fn require_matching_environments(
    ctx: &mut Ctx,
    selector: &Selector,
) -> Result<Vec<String>> {
    let names = matching_environments(ctx, selector).await?;
    if names.is_empty() {
        bail!("selector {selector} matches no environments");
    }
    Ok(names)
}

pub async fn set_environment(ctx: &mut Ctx, env: &str, key: &str, value: &str) -> Result<String> {
    validate_label_key(key)?;
    validate_label_value(key, value)?;
    let mut object = crate::environment::environment(ctx, env).await?;
    object
        .properties
        .insert(format!("{PROPERTY_PREFIX}{key}"), value.to_string());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("set {env} label {key}={value}"))
}

pub async fn clear_environment(ctx: &mut Ctx, env: &str, key: &str) -> Result<String> {
    validate_label_key(key)?;
    let mut object = crate::environment::environment(ctx, env).await?;
    let property = format!("{PROPERTY_PREFIX}{key}");
    if object.properties.remove(&property).is_none() {
        bail!("environment {env} has no label {key}");
    }
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("cleared {env} label {key}"))
}

pub async fn list_environment(ctx: &mut Ctx, env: &str) -> Result<BTreeMap<String, String>> {
    let object = crate::environment::environment(ctx, env).await?;
    Ok(labels_from_object(&object))
}

/// Mutates only `label.*`. The write replaces the whole KIND_RELEASE object,
/// matching recall and same-content republish; the store has no per-property merge.
pub async fn set_release(ctx: &mut Ctx, spec: &str, key: &str, value: &str) -> Result<String> {
    validate_label_key(key)?;
    validate_label_value(key, value)?;
    let mut object = release_object(ctx, spec).await?;
    object
        .properties
        .insert(format!("{PROPERTY_PREFIX}{key}"), value.to_string());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("set {spec} label {key}={value}"))
}

pub async fn clear_release(ctx: &mut Ctx, spec: &str, key: &str) -> Result<String> {
    validate_label_key(key)?;
    let mut object = release_object(ctx, spec).await?;
    let property = format!("{PROPERTY_PREFIX}{key}");
    if object.properties.remove(&property).is_none() {
        bail!("release {spec} has no label {key}");
    }
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!("cleared {spec} label {key}"))
}

pub async fn list_release(ctx: &mut Ctx, spec: &str) -> Result<BTreeMap<String, String>> {
    let object = release_object(ctx, spec).await?;
    Ok(labels_from_object(&object))
}

async fn release_object(ctx: &mut Ctx, spec: &str) -> Result<Object> {
    let Some((product, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    validate_identifier("product", product)?;
    validate_identifier("version", version)?;
    let id = release_id(product, version);
    let object = ctx
        .get(&id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("release {spec} is not published"))?;
    if object.kind != KIND_RELEASE {
        bail!("object {id} is {}, not {KIND_RELEASE}", object.kind);
    }
    Ok(object)
}

fn split_clauses(input: &str) -> Result<Vec<&str>> {
    let mut clauses = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    for (index, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    bail!("selector {input:?} has an unmatched ')'");
                }
            }
            ',' if depth == 0 => {
                let clause = input[start..index].trim();
                if clause.is_empty() {
                    bail!("selector {input:?} has an empty clause");
                }
                clauses.push(clause);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        bail!("selector {input:?} has an unmatched '('");
    }
    let last = input[start..].trim();
    if last.is_empty() {
        bail!("selector {input:?} has an empty clause");
    }
    clauses.push(last);
    Ok(clauses)
}

fn parse_clause(clause: &str) -> Result<Clause> {
    if let Some((key, rest)) = split_in(clause) {
        let key = key.trim();
        validate_label_key(key)
            .map_err(|error| anyhow::anyhow!("invalid selector clause {clause:?}: {error}"))?;
        let rest = rest.trim();
        let Some(inner) = rest
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
        else {
            bail!("invalid selector clause {clause:?}: expected `in (a,b)`");
        };
        let mut values = BTreeSet::new();
        for value in inner.split(',') {
            let value = value.trim();
            if value.is_empty() {
                bail!("invalid selector clause {clause:?}: empty value in the list");
            }
            validate_label_value(key, value)
                .map_err(|error| anyhow::anyhow!("invalid selector clause {clause:?}: {error}"))?;
            values.insert(value.to_string());
        }
        if values.is_empty() {
            bail!("invalid selector clause {clause:?}: empty value in the list");
        }
        return Ok(Clause::In {
            key: key.to_string(),
            values,
        });
    }
    if let Some((key, value)) = clause.split_once("!=") {
        let key = key.trim();
        let value = value.trim();
        validate_label_key(key)
            .map_err(|error| anyhow::anyhow!("invalid selector clause {clause:?}: {error}"))?;
        validate_label_value(key, value)
            .map_err(|error| anyhow::anyhow!("invalid selector clause {clause:?}: {error}"))?;
        return Ok(Clause::NotEquals {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    if let Some((key, value)) = clause.split_once('=') {
        let key = key.trim();
        let value = value.trim();
        validate_label_key(key)
            .map_err(|error| anyhow::anyhow!("invalid selector clause {clause:?}: {error}"))?;
        validate_label_value(key, value)
            .map_err(|error| anyhow::anyhow!("invalid selector clause {clause:?}: {error}"))?;
        return Ok(Clause::Equals {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    bail!(
        "invalid selector clause {clause:?}: expected `key=value`, `key!=value`, or `key in (a,b)`"
    );
}

fn split_in(clause: &str) -> Option<(&str, &str)> {
    if let Some(index) = clause.find(" in (") {
        return Some((&clause[..index], &clause[index + 4..]));
    }
    if let Some(index) = clause.find(" in(") {
        return Some((&clause[..index], &clause[index + 3..]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::plan;

    fn temp_db(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-labels-{label}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ))
    }

    #[test]
    fn parse_refuses_the_offending_clause() {
        let error = parse_selector("tier=canary,=prod").unwrap_err();
        assert_eq!(error.clause.as_deref(), Some("=prod"));
        assert!(error.message.contains("invalid selector clause"), "{error}");
        assert_eq!(parse_selector("tier=a,").unwrap_err().clause, None);
        let error = parse_label_pair("=x").unwrap_err().to_string();
        assert!(error.contains("invalid label key"), "{error}");
        let error = parse_selector("tier in ()").unwrap_err().to_string();
        assert!(error.contains("empty value"), "{error}");
    }

    #[test]
    fn selector_and_in_and_not_equals() {
        let selector = parse_selector("tier in (canary,prod),region!=eu").unwrap();
        let mut canary = BTreeMap::new();
        canary.insert("tier".into(), "canary".into());
        canary.insert("region".into(), "us".into());
        assert!(matches(&canary, &selector));
        canary.insert("region".into(), "eu".into());
        assert!(!matches(&canary, &selector));
        canary.insert("region".into(), "us".into());
        canary.insert("tier".into(), "stage".into());
        assert!(!matches(&canary, &selector));
        let missing = BTreeMap::from([("tier".into(), "canary".into())]);
        assert!(matches(&missing, &selector));
    }

    #[tokio::test]
    async fn resolve_includes_later_labels_and_empty_refuses() {
        let database = temp_db("resolve");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "alpha", "a").await.unwrap();
        plan::env_add(&mut ctx, "beta", "b").await.unwrap();
        let selector = parse_selector("tier=canary").unwrap();
        let error = require_matching_environments(&mut ctx, &selector)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("matches no environments"), "{error}");
        set_environment(&mut ctx, "alpha", "tier", "canary")
            .await
            .unwrap();
        assert_eq!(
            require_matching_environments(&mut ctx, &selector)
                .await
                .unwrap(),
            vec!["alpha".to_string()]
        );
        set_environment(&mut ctx, "beta", "tier", "canary")
            .await
            .unwrap();
        assert_eq!(
            require_matching_environments(&mut ctx, &selector)
                .await
                .unwrap(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn wave_snapshot_freezes_resolved_names() {
        let database = temp_db("wave-freeze");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "alpha", "a").await.unwrap();
        plan::env_add(&mut ctx, "beta", "b").await.unwrap();
        set_environment(&mut ctx, "alpha", "tier", "canary")
            .await
            .unwrap();
        let names = resolve_cohort(&mut ctx, "tier=canary").await.unwrap();
        let spec = crate::wave::WaveSpec::new(names, true).unwrap();
        assert_eq!(spec.environments, ["alpha"]);
        set_environment(&mut ctx, "beta", "tier", "canary")
            .await
            .unwrap();
        assert_eq!(spec.environments, ["alpha"]);
        assert_eq!(
            resolve_cohort(&mut ctx, "tier=canary").await.unwrap(),
            ["alpha", "beta"]
        );
        let _ = std::fs::remove_file(&database);
    }
}

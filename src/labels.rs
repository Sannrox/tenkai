//! Operator grouping labels on environments and releases, and selector resolve.
//!
//! Labels sit beside capability facts: facts are host inventory, labels are
//! how an operator groups the fleet. A selector expands to concrete
//! environment names at the moment an existing list-taking operation runs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};

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
    Ok(resolve_cohort_recorded(ctx, input).await?.0)
}

/// [`resolve_cohort`], plus the selector and its matches when `input` was a
/// selector, for a record that keeps where its cohort came from.
pub async fn resolve_cohort_recorded(
    ctx: &mut Ctx,
    input: &str,
) -> Result<(Vec<String>, Option<crate::delivery_hold::HoldSelector>)> {
    let input = input.trim();
    if looks_like_selector(input) {
        let selector = parse_selector(input)?;
        let environments = require_matching_environments(ctx, &selector).await?;
        let recorded = crate::delivery_hold::HoldSelector {
            selector: selector.source().to_string(),
            environments: environments.clone(),
        };
        Ok((environments, Some(recorded)))
    } else {
        Ok((parse_name_list(input)?, None))
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

/// Who set the current value of a label, keyed by label.
const SET_BY_PREFIX: &str = "label_by.";
/// When the current value of a label was set, in unix ms, keyed by label.
const SET_AT_PREFIX: &str = "label_at.";

/// Kind of the append-only label change records.
pub const LABEL_AUDIT_KIND: &str = "tenkai.label_audit";

/// One label on a read: the value, and who set it and when. Labels set
/// before provenance was recorded read back without `set_by` and `set_at`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct LabelView {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub set_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub set_at: Option<i64>,
}

/// `set` or `clear`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LabelAction {
    Set,
    Clear,
}

/// One recorded label change, as the history read returns it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct LabelChange {
    /// Unique id of this change; replays of it record nothing new.
    pub id: String,
    /// Order among this subject's label changes, from 1. Two writers that
    /// race on one subject can share a sequence; both changes are kept.
    pub sequence: u64,
    pub key: String,
    /// The value set. Omitted on `clear`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub value: Option<String>,
    pub action: LabelAction,
    pub actor: String,
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub reason: Option<String>,
}

/// What a label is on, and the name it is recorded under.
#[derive(Debug, Clone, Copy)]
enum Subject<'a> {
    Environment(&'a str),
    Release(&'a str),
}

impl Subject<'_> {
    fn kind(self) -> &'static str {
        match self {
            Self::Environment(_) => "environment",
            Self::Release(_) => "release",
        }
    }

    fn id(&self) -> &str {
        match self {
            Self::Environment(name) | Self::Release(name) => name,
        }
    }
}

/// `key=value`, then `set by <actor> at <ms>` when that is recorded.
pub fn render_label(key: &str, label: &LabelView) -> String {
    match (&label.set_by, label.set_at) {
        (Some(actor), Some(at)) => format!("{key}={} set by {actor} at {at}", label.value),
        _ => format!("{key}={}", label.value),
    }
}

/// One history line: time, actor, action, the label, and the reason.
pub fn render_change(change: &LabelChange) -> String {
    let label = match (&change.action, &change.value) {
        (LabelAction::Set, Some(value)) => format!("set {}={value}", change.key),
        _ => format!("clear {}", change.key),
    };
    match &change.reason {
        Some(reason) => format!("{} {} {label}: {reason}", change.at, change.actor),
        None => format!("{} {} {label}", change.at, change.actor),
    }
}

/// Every label of `object` with the provenance of its current value.
pub fn label_views_from_object(object: &Object) -> BTreeMap<String, LabelView> {
    labels_from_object(object)
        .into_iter()
        .map(|(key, value)| {
            let set_by = object
                .properties
                .get(&format!("{SET_BY_PREFIX}{key}"))
                .cloned();
            let set_at = object
                .properties
                .get(&format!("{SET_AT_PREFIX}{key}"))
                .and_then(|at| at.parse().ok());
            (
                key,
                LabelView {
                    value,
                    set_by,
                    set_at,
                },
            )
        })
        .collect()
}

/// The last change to a label, kept on the subject until the next change
/// to that key, keyed by label. It makes the history append recoverable.
const LAST_CHANGE_PREFIX: &str = "label_change.";
/// Sequence of the subject's latest label change.
const SEQUENCE_PROPERTY: &str = "label_sequence";

/// Set or clear `key` on `object` with its provenance and the change itself,
/// in one put, then append the change record. A crash between the two
/// leaves the change on the subject: history reads include it, and the next
/// change to that key appends it first. Appends are idempotent, so nothing
/// is recorded twice.
async fn write_label(
    ctx: &mut Ctx,
    mut object: Object,
    subject: Subject<'_>,
    key: &str,
    value: Option<&str>,
    actor: &str,
    reason: &str,
) -> Result<()> {
    let last_change = format!("{LAST_CHANGE_PREFIX}{key}");
    if let Some(previous) = stored_change(&object, &last_change)? {
        append_change(ctx, subject, &previous).await?;
    }
    let at = crate::now_millis();
    let label = format!("{PROPERTY_PREFIX}{key}");
    let set_by = format!("{SET_BY_PREFIX}{key}");
    let set_at = format!("{SET_AT_PREFIX}{key}");
    match value {
        Some(value) => {
            object.properties.insert(label, value.to_string());
            object.properties.insert(set_by, actor.to_string());
            object.properties.insert(set_at, at.to_string());
        }
        None => {
            if object.properties.remove(&label).is_none() {
                bail!("{} {} has no label {key}", subject.kind(), subject.id());
            }
            object.properties.remove(&set_by);
            object.properties.remove(&set_at);
        }
    }
    let sequence = match object.properties.get(SEQUENCE_PROPERTY) {
        Some(sequence) => sequence
            .parse::<u64>()
            .with_context(|| format!("{} has an unreadable {SEQUENCE_PROPERTY}", object.id))?,
        None => 0,
    } + 1;
    object
        .properties
        .insert(SEQUENCE_PROPERTY.into(), sequence.to_string());
    let change = LabelChange {
        id: uuid::Uuid::new_v4().to_string(),
        sequence,
        key: key.to_string(),
        value: value.map(str::to_string),
        action: if value.is_some() {
            LabelAction::Set
        } else {
            LabelAction::Clear
        },
        actor: actor.to_string(),
        at,
        reason: Some(reason.trim().to_string()).filter(|reason| !reason.is_empty()),
    };
    object
        .properties
        .insert(last_change, serde_json::to_string(&change)?);
    object.updated = at;
    ctx.put(object).await?;
    append_change(ctx, subject, &change).await
}

fn stored_change(object: &Object, property: &str) -> Result<Option<LabelChange>> {
    object
        .properties
        .get(property)
        .map(|json| {
            serde_json::from_str(json)
                .with_context(|| format!("{} has an unreadable {property}", object.id))
        })
        .transpose()
}

fn change_properties(
    subject: Subject<'_>,
    change: &LabelChange,
) -> std::collections::HashMap<String, String> {
    let mut properties = std::collections::HashMap::from([
        ("subject_kind".to_string(), subject.kind().to_string()),
        ("subject".to_string(), subject.id().to_string()),
        ("key".to_string(), change.key.clone()),
        (
            "action".to_string(),
            match change.action {
                LabelAction::Set => "set",
                LabelAction::Clear => "clear",
            }
            .to_string(),
        ),
        ("actor".to_string(), change.actor.clone()),
        (
            "reason".to_string(),
            change.reason.clone().unwrap_or_default(),
        ),
        ("at".to_string(), change.at.to_string()),
        ("sequence".to_string(), change.sequence.to_string()),
        ("change_id".to_string(), change.id.clone()),
    ]);
    if let Some(value) = &change.value {
        properties.insert("value".into(), value.clone());
    }
    properties
}

/// Record `change` once, under its id. A record already there is this
/// change replayed after a crash, so it counts as written.
async fn append_change(ctx: &mut Ctx, subject: Subject<'_>, change: &LabelChange) -> Result<()> {
    let kind = subject.kind();
    let name = subject.id();
    let object = Object {
        id: format!("tenkai:label_audit:{kind}:{name}:{}", change.id),
        kind: LABEL_AUDIT_KIND.into(),
        name: format!("label {} on {kind} {name}", change.key),
        namespace: crate::ontology::NS.into(),
        external_id: String::new(),
        properties: change_properties(subject, change),
        created: change.at,
        updated: change.at,
    };
    match ctx.create_once(object).await {
        Ok(_) => Ok(()),
        Err(status) if crate::client::is_unique_conflict(&status) => Ok(()),
        Err(status) => Err(status.into()),
    }
}

/// Recorded changes to the labels of `object`, oldest first, including a
/// last change whose record a crash left unwritten.
async fn changes(ctx: &mut Ctx, subject: Subject<'_>, object: &Object) -> Result<Vec<LabelChange>> {
    let mut objects = ctx.list_kind(LABEL_AUDIT_KIND).await?;
    objects.retain(|object| {
        object.properties.get("subject_kind").map(String::as_str) == Some(subject.kind())
            && object.properties.get("subject").map(String::as_str) == Some(subject.id())
    });
    let mut changes = objects
        .iter()
        .map(|object| {
            let field = |key: &str| object.properties.get(key).cloned().unwrap_or_default();
            Ok(LabelChange {
                id: field("change_id"),
                sequence: field("sequence").parse()?,
                key: field("key"),
                value: object.properties.get("value").cloned(),
                action: match field("action").as_str() {
                    "set" => LabelAction::Set,
                    "clear" => LabelAction::Clear,
                    other => bail!("label change {} has action {other:?}", object.id),
                },
                actor: field("actor"),
                at: field("at").parse()?,
                reason: object
                    .properties
                    .get("reason")
                    .filter(|reason| !reason.is_empty())
                    .cloned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for property in object.properties.keys() {
        if property.starts_with(LAST_CHANGE_PREFIX)
            && let Some(last) = stored_change(object, property)?
            && !changes.iter().any(|change| change.id == last.id)
        {
            changes.push(last);
        }
    }
    changes.sort_by(|a, b| (a.sequence, a.at, &a.id).cmp(&(b.sequence, b.at, &b.id)));
    Ok(changes)
}

/// Set `key` on `env`, holding the environment apply lease for the write so
/// it cannot interleave with an apply or another configuration change, which
/// also replace the environment object (#1310). Refused while one runs.
pub async fn set_environment(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    value: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    under_environment_lease(ctx, env, async |ctx| {
        set_environment_held(ctx, env, key, value, actor, reason).await
    })
    .await
}

/// Clear `key` on `env` under the environment apply lease, like
/// [`set_environment`].
pub async fn clear_environment(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    under_environment_lease(ctx, env, async |ctx| {
        clear_environment_held(ctx, env, key, actor, reason).await
    })
    .await
}

async fn under_environment_lease(
    ctx: &mut Ctx,
    env: &str,
    write: impl AsyncFnOnce(&mut Ctx) -> Result<String>,
) -> Result<String> {
    let owner = format!("environment-labels:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, env, &owner).await?;
    let result = write(ctx).await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => Err(error.context(format!(
            "releasing the environment label lease also failed: {unlock}"
        ))),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment label lease")),
    }
}

/// [`set_environment`] for a caller that already holds the environment lease.
pub(crate) async fn set_environment_held(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    value: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    validate_label_key(key)?;
    validate_label_value(key, value)?;
    let object = crate::environment::environment(ctx, env).await?;
    write_label(
        ctx,
        object,
        Subject::Environment(env),
        key,
        Some(value),
        actor,
        reason,
    )
    .await?;
    Ok(format!("set {env} label {key}={value}"))
}

/// [`clear_environment`] for a caller that already holds the environment
/// lease.
pub(crate) async fn clear_environment_held(
    ctx: &mut Ctx,
    env: &str,
    key: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    validate_label_key(key)?;
    let object = crate::environment::environment(ctx, env).await?;
    write_label(
        ctx,
        object,
        Subject::Environment(env),
        key,
        None,
        actor,
        reason,
    )
    .await?;
    Ok(format!("cleared {env} label {key}"))
}

pub async fn list_environment(ctx: &mut Ctx, env: &str) -> Result<BTreeMap<String, LabelView>> {
    let object = crate::environment::environment(ctx, env).await?;
    Ok(label_views_from_object(&object))
}

/// Label changes recorded on `env`, oldest first.
pub async fn environment_history(ctx: &mut Ctx, env: &str) -> Result<Vec<LabelChange>> {
    let object = crate::environment::environment(ctx, env).await?;
    changes(ctx, Subject::Environment(env), &object).await
}

/// Mutates only labels and their provenance. The write replaces the whole
/// KIND_RELEASE object, matching recall and same-content republish; the store
/// has no per-property merge.
pub async fn set_release(
    ctx: &mut Ctx,
    spec: &str,
    key: &str,
    value: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    validate_label_key(key)?;
    validate_label_value(key, value)?;
    let object = release_object(ctx, spec).await?;
    write_label(
        ctx,
        object,
        Subject::Release(spec),
        key,
        Some(value),
        actor,
        reason,
    )
    .await?;
    Ok(format!("set {spec} label {key}={value}"))
}

pub async fn clear_release(
    ctx: &mut Ctx,
    spec: &str,
    key: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    validate_label_key(key)?;
    let object = release_object(ctx, spec).await?;
    write_label(
        ctx,
        object,
        Subject::Release(spec),
        key,
        None,
        actor,
        reason,
    )
    .await?;
    Ok(format!("cleared {spec} label {key}"))
}

pub async fn list_release(ctx: &mut Ctx, spec: &str) -> Result<BTreeMap<String, LabelView>> {
    let object = release_object(ctx, spec).await?;
    Ok(label_views_from_object(&object))
}

/// Label changes recorded on the release `spec`, oldest first.
pub async fn release_history(ctx: &mut Ctx, spec: &str) -> Result<Vec<LabelChange>> {
    let object = release_object(ctx, spec).await?;
    changes(ctx, Subject::Release(spec), &object).await
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
        set_environment(&mut ctx, "alpha", "tier", "canary", "test", "")
            .await
            .unwrap();
        assert_eq!(
            require_matching_environments(&mut ctx, &selector)
                .await
                .unwrap(),
            vec!["alpha".to_string()]
        );
        set_environment(&mut ctx, "beta", "tier", "canary", "test", "")
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
    async fn a_label_write_waits_for_no_apply_and_releases_its_lease() {
        let database = temp_db("leased");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "alpha", "a").await.unwrap();
        let apply = crate::apply::claim_environment(&mut ctx, "alpha", "apply-test")
            .await
            .unwrap();
        let error = set_environment(&mut ctx, "alpha", "tier", "canary", "test", "")
            .await
            .unwrap_err();
        assert!(crate::apply::is_apply_in_progress(&error), "{error:#}");
        assert!(
            list_environment(&mut ctx, "alpha")
                .await
                .unwrap()
                .is_empty()
        );
        crate::apply::release_environment(&mut ctx, &apply)
            .await
            .unwrap();
        set_environment(&mut ctx, "alpha", "tier", "canary", "test", "")
            .await
            .unwrap();
        clear_environment(&mut ctx, "alpha", "tier", "test", "")
            .await
            .unwrap();
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
        set_environment(&mut ctx, "alpha", "tier", "canary", "test", "")
            .await
            .unwrap();
        let names = resolve_cohort(&mut ctx, "tier=canary").await.unwrap();
        let spec = crate::wave::WaveSpec::new(names, true).unwrap();
        assert_eq!(spec.environments, ["alpha"]);
        set_environment(&mut ctx, "beta", "tier", "canary", "test", "")
            .await
            .unwrap();
        assert_eq!(spec.environments, ["alpha"]);
        assert_eq!(
            resolve_cohort(&mut ctx, "tier=canary").await.unwrap(),
            ["alpha", "beta"]
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn a_change_stranded_by_a_crash_is_recorded_once() {
        let database = temp_db("stranded-change");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "alpha", "a").await.unwrap();
        // The state a crash after the label put and before the append leaves.
        let mut object = crate::environment::environment(&mut ctx, "alpha")
            .await
            .unwrap();
        let stranded = LabelChange {
            id: "stranded".into(),
            sequence: 1,
            key: "tier".into(),
            value: Some("canary".into()),
            action: LabelAction::Set,
            actor: "alice".into(),
            at: 1,
            reason: None,
        };
        object
            .properties
            .insert("label.tier".into(), "canary".into());
        object
            .properties
            .insert(SEQUENCE_PROPERTY.into(), "1".into());
        object.properties.insert(
            format!("{LAST_CHANGE_PREFIX}tier"),
            serde_json::to_string(&stranded).unwrap(),
        );
        ctx.put(object).await.unwrap();
        assert_eq!(
            environment_history(&mut ctx, "alpha").await.unwrap(),
            std::slice::from_ref(&stranded)
        );

        clear_environment(&mut ctx, "alpha", "tier", "bob", "done")
            .await
            .unwrap();
        // Replaying an already recorded change adds nothing.
        append_change(&mut ctx, Subject::Environment("alpha"), &stranded)
            .await
            .unwrap();
        let history = environment_history(&mut ctx, "alpha").await.unwrap();
        let actors: Vec<_> = history
            .iter()
            .map(|change| (change.action, change.actor.as_str()))
            .collect();
        assert_eq!(
            actors,
            [(LabelAction::Set, "alice"), (LabelAction::Clear, "bob")]
        );

        // Identical content is still a distinct change.
        for value in ["a", "b", "a"] {
            set_environment(&mut ctx, "alpha", "tier", value, "carol", "")
                .await
                .unwrap();
        }
        let values: Vec<_> = environment_history(&mut ctx, "alpha")
            .await
            .unwrap()
            .into_iter()
            .map(|change| (change.sequence, change.value))
            .collect();
        assert_eq!(
            values,
            [
                (1, Some("canary".into())),
                (2, None),
                (3, Some("a".into())),
                (4, Some("b".into())),
                (5, Some("a".into())),
            ]
        );
        let _ = std::fs::remove_file(&database);
    }
}

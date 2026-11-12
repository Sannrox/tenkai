//! Re-assess subscribed and running releases when an advisory feed is admitted (#900).
//!
//! Each (release, advisory) pair is one catalog object. `create_once` keeps
//! the first-seen time; a later import of the same pair is a no-op. Closing a
//! withdrawn or revised pair waits until the current generation's assessment
//! marker is complete, so a crash mid-pass does not drop or duplicate records.
//! Writes abort when a newer preferred feed generation has already landed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context as _, Result, bail};

use crate::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind,
};
use crate::client::{Ctx, LeaseError};
use crate::fleet::OpenEnvironmentExposure;
use crate::ontology::{KIND_ENVIRONMENT, KIND_RELEASE, NS};
use crate::pb::sekai::Object;

use super::{
    AUTO_RECALL_SEVERITY_PROPERTY, Advisory, AdvisoryFeed, KIND_DEPLOYED_EXPOSURE,
    KIND_EXPOSURE_ASSESSMENT, MAX_EXPOSURE_AGE_PROPERTY_PREFIX, Severity, load_advisory_feed,
    stored_inventory, validate_stored_inventory, version_in_range,
};

const AUTO_RECALL_AUTHENTICATOR: &str = "deployed-exposure-auto-recall";
pub(super) const ASSESSMENT_LEASE_NAMESPACE: &str = "tenkai/exposure-assessment";
pub(super) const ASSESSMENT_LEASE_KEY: &str = "write";
const ASSESSMENT_LEASE_TTL_MS: i64 = 120_000;
const ASSESSMENT_LEASE_ATTEMPTS: usize = 8;
const ASSESSMENT_LEASE_REFRESH_EVERY: usize = 16;

/// Durable (release, advisory) match with its first-seen time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployedExposure {
    pub release: String,
    pub release_id: String,
    pub advisory_id: String,
    pub severity: Severity,
    pub component: String,
    pub component_version: String,
    pub first_seen_at: i64,
    pub closed_at: Option<i64>,
    pub auto_recalled_at: Option<i64>,
}

/// Re-assess every subscribed or running release against the preferred feed.
///
/// Safe to retry: existing pairs keep `first_seen_at`, and withdrawn or
/// revised pairs close only after this generation's assessment marker is
/// written. A pass aborts if a newer preferred generation lands mid-flight.
pub async fn reassess_deployed(ctx: &mut Ctx) -> Result<Vec<DeployedExposure>> {
    let Some((feed, _)) = load_advisory_feed(ctx).await? else {
        return Ok(Vec::new());
    };
    reassess_loaded(ctx, &feed, feed.generated_at).await
}

pub(super) async fn reassess_loaded(
    ctx: &mut Ctx,
    feed: &AdvisoryFeed,
    generation: i64,
) -> Result<Vec<DeployedExposure>> {
    let token = begin_assessment_write(ctx).await?;
    let result = reassess_under_lease(ctx, feed, generation, &token).await;
    let released = end_assessment_write(ctx, &token).await;
    match (result, released) {
        (Ok(records), Ok(_)) => Ok(records),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(release)) => Err(error.context(release)),
    }
}

pub(super) async fn begin_assessment_write(ctx: &mut Ctx) -> Result<String> {
    let owner = format!(
        "exposure-assessment:{}:{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    for _ in 0..ASSESSMENT_LEASE_ATTEMPTS {
        match ctx
            .acquire_lease(
                ASSESSMENT_LEASE_NAMESPACE,
                ASSESSMENT_LEASE_KEY,
                &owner,
                ASSESSMENT_LEASE_TTL_MS,
            )
            .await
        {
            Ok(lease) => return Ok(lease.fencing_token),
            Err(LeaseError::AlreadyExists) => {
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("exposure assessment lease is held")
}

pub(super) async fn end_assessment_write(ctx: &mut Ctx, fencing_token: &str) -> Result<()> {
    ctx.release_lease(
        ASSESSMENT_LEASE_NAMESPACE,
        ASSESSMENT_LEASE_KEY,
        fencing_token,
    )
    .await?;
    Ok(())
}

pub(super) async fn reassess_under_lease(
    ctx: &mut Ctx,
    feed: &AdvisoryFeed,
    generation: i64,
    fencing_token: &str,
) -> Result<Vec<DeployedExposure>> {
    refuse_stale_assessment(ctx, generation).await?;
    let scoped = scoped_release_ids(ctx).await?;
    let in_scope: BTreeSet<String> = scoped.values().flatten().cloned().collect();
    let matches = match_scoped(ctx, feed, &in_scope).await?;
    write_fenced_assessment(
        ctx,
        feed,
        generation,
        &scoped,
        &in_scope,
        &matches,
        fencing_token,
    )
    .await?;
    list_open_records(ctx).await
}

async fn write_fenced_assessment(
    ctx: &mut Ctx,
    feed: &AdvisoryFeed,
    generation: i64,
    scoped: &BTreeMap<String, BTreeSet<String>>,
    in_scope: &BTreeSet<String>,
    matches: &[DeployedExposure],
    fencing_token: &str,
) -> Result<()> {
    refuse_stale_assessment(ctx, generation).await?;
    refresh_assessment_lease(ctx, fencing_token).await?;
    for (index, matched) in matches.iter().enumerate() {
        if index > 0 && index.is_multiple_of(ASSESSMENT_LEASE_REFRESH_EVERY) {
            refresh_assessment_lease(ctx, fencing_token).await?;
            refuse_stale_assessment(ctx, generation).await?;
        }
        persist_open_match(ctx, matched, generation, fencing_token).await?;
    }
    refresh_assessment_lease(ctx, fencing_token).await?;
    mark_assessment_complete(ctx, generation, fencing_token).await?;
    close_unmatched(ctx, feed, matches, in_scope, generation, fencing_token).await?;
    refresh_assessment_lease(ctx, fencing_token).await?;
    auto_recall_new_matches(ctx, scoped, matches, generation, fencing_token).await?;
    Ok(())
}

async fn refresh_assessment_lease(ctx: &mut Ctx, fencing_token: &str) -> Result<()> {
    ctx.refresh_lease(
        ASSESSMENT_LEASE_NAMESPACE,
        ASSESSMENT_LEASE_KEY,
        fencing_token,
        ASSESSMENT_LEASE_TTL_MS,
    )
    .await?;
    Ok(())
}

/// Environment name → subscribed or deployed release ids.
async fn scoped_release_ids(ctx: &mut Ctx) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut scoped = BTreeMap::new();
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    for environment in environments {
        if crate::environment::retirement_from_object(&environment).is_some() {
            continue;
        }
        let mut ids = BTreeSet::new();
        for (key, value) in &environment.properties {
            if let Some(rest) = key.strip_prefix("deployed_release.")
                && !rest.is_empty()
                && !value.is_empty()
            {
                ids.insert(value.clone());
            }
        }
        for subscription in crate::environment::list_subscriptions(ctx, &environment).await? {
            if let Some(release_id) = subscription
                .channel
                .properties
                .get("current_release")
                .filter(|value| !value.is_empty())
            {
                ids.insert(release_id.clone());
            }
        }
        scoped.insert(environment.name.clone(), ids);
    }
    Ok(scoped)
}

/// Open exposures joined onto the environments that subscribe to or run them.
pub async fn open_environment_exposures(
    ctx: &mut Ctx,
) -> Result<BTreeMap<String, Vec<OpenEnvironmentExposure>>> {
    let records = list_open_records(ctx).await?;
    if records.is_empty() {
        return Ok(BTreeMap::new());
    }
    let scoped = scoped_release_ids(ctx).await?;
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let now = crate::now_millis();
    let mut by_env = BTreeMap::new();
    for environment in environments {
        if crate::environment::retirement_from_object(&environment).is_some() {
            continue;
        }
        let Some(release_ids) = scoped.get(&environment.name) else {
            continue;
        };
        let mut rows = Vec::new();
        for record in &records {
            if !release_ids.contains(&record.release_id) {
                continue;
            }
            let age_ms = now.saturating_sub(record.first_seen_at);
            let max_age_ms = max_age_ms_for(&environment, record.severity);
            rows.push(OpenEnvironmentExposure {
                release: record.release.clone(),
                advisory_id: record.advisory_id.clone(),
                severity: record.severity.as_str().into(),
                first_seen_at: record.first_seen_at,
                age_ms,
                overdue: max_age_ms.is_some_and(|max| age_ms > max),
            });
        }
        rows.sort_by(|left, right| {
            left.release
                .cmp(&right.release)
                .then(left.advisory_id.cmp(&right.advisory_id))
        });
        if !rows.is_empty() {
            by_env.insert(environment.name, rows);
        }
    }
    Ok(by_env)
}

async fn match_scoped(
    ctx: &mut Ctx,
    feed: &AdvisoryFeed,
    in_scope: &BTreeSet<String>,
) -> Result<Vec<DeployedExposure>> {
    if in_scope.is_empty() || feed.advisories.is_empty() {
        return Ok(Vec::new());
    }
    let mut matched = Vec::new();
    for release in ctx.list_kind(KIND_RELEASE).await? {
        if !in_scope.contains(&release.id) {
            continue;
        }
        validate_stored_inventory(&release, None)?;
        let Some(inventory) = stored_inventory(&release)? else {
            continue;
        };
        let product = release
            .properties
            .get("product")
            .cloned()
            .unwrap_or_default();
        let version = release
            .properties
            .get("version")
            .cloned()
            .unwrap_or_default();
        let spec = format!("{product}@{version}");
        for advisory in &feed.advisories {
            if let Some(hit) = matching_component(&inventory.components, advisory)? {
                matched.push(DeployedExposure {
                    release: spec.clone(),
                    release_id: release.id.clone(),
                    advisory_id: advisory.id.clone(),
                    severity: advisory.severity,
                    component: hit.0,
                    component_version: hit.1,
                    first_seen_at: 0,
                    closed_at: None,
                    auto_recalled_at: None,
                });
            }
        }
    }
    matched.sort_by(|left, right| {
        left.release_id
            .cmp(&right.release_id)
            .then(left.advisory_id.cmp(&right.advisory_id))
    });
    Ok(matched)
}

fn matching_component(
    components: &[super::InventoryComponent],
    advisory: &Advisory,
) -> Result<Option<(String, String)>> {
    for component in components {
        if component.name == advisory.component
            && version_in_range(&component.version, &advisory.range)?
        {
            return Ok(Some((component.name.clone(), component.version.clone())));
        }
    }
    Ok(None)
}

async fn persist_open_match(
    ctx: &mut Ctx,
    matched: &DeployedExposure,
    generation: i64,
    fencing_token: &str,
) -> Result<()> {
    refuse_stale_assessment(ctx, generation).await?;
    let now = crate::now_millis();
    let id = exposure_record_id(&matched.release_id, &matched.advisory_id);
    match ctx.get(&id).await? {
        None => {
            let proposed = exposure_object(matched, generation, now, now);
            ctx.guarded_create(
                proposed,
                ASSESSMENT_LEASE_NAMESPACE,
                ASSESSMENT_LEASE_KEY,
                fencing_token,
            )
            .await?;
            Ok(())
        }
        Some(mut existing) => {
            if existing.kind != KIND_DEPLOYED_EXPOSURE {
                bail!("deployed exposure id {id} exists with a different kind");
            }
            if existing.properties.get("release_id").map(String::as_str)
                != Some(matched.release_id.as_str())
                || existing.properties.get("advisory_id").map(String::as_str)
                    != Some(matched.advisory_id.as_str())
            {
                bail!("deployed exposure {id} already exists with different identity");
            }
            if recorded_generation(&existing) > generation {
                return Ok(());
            }
            existing
                .properties
                .insert("last_seen_generation".into(), generation.to_string());
            existing
                .properties
                .insert("severity".into(), matched.severity.as_str().into());
            existing
                .properties
                .insert("component".into(), matched.component.clone());
            existing.properties.insert(
                "component_version".into(),
                matched.component_version.clone(),
            );
            existing.properties.remove("closed_at");
            existing.updated = now;
            ctx.guarded_update(
                existing,
                ASSESSMENT_LEASE_NAMESPACE,
                ASSESSMENT_LEASE_KEY,
                fencing_token,
            )
            .await?;
            Ok(())
        }
    }
}

async fn mark_assessment_complete(
    ctx: &mut Ctx,
    generation: i64,
    fencing_token: &str,
) -> Result<()> {
    refuse_stale_assessment(ctx, generation).await?;
    let now = crate::now_millis();
    let id = assessment_id(generation);
    match ctx.get(&id).await? {
        None => {
            ctx.guarded_create(
                assessment_object(generation, now, now),
                ASSESSMENT_LEASE_NAMESPACE,
                ASSESSMENT_LEASE_KEY,
                fencing_token,
            )
            .await?;
            Ok(())
        }
        Some(mut existing) => {
            if existing.kind != KIND_EXPOSURE_ASSESSMENT {
                bail!("exposure assessment id {id} exists with a different kind");
            }
            existing
                .properties
                .insert("completed_at".into(), now.to_string());
            existing.updated = now;
            ctx.guarded_update(
                existing,
                ASSESSMENT_LEASE_NAMESPACE,
                ASSESSMENT_LEASE_KEY,
                fencing_token,
            )
            .await?;
            Ok(())
        }
    }
}

async fn assessment_completed(ctx: &mut Ctx, generation: i64) -> Result<bool> {
    let Some(object) = ctx.get(&assessment_id(generation)).await? else {
        return Ok(false);
    };
    Ok(object
        .properties
        .get("completed_at")
        .is_some_and(|value| !value.is_empty()))
}

async fn close_unmatched(
    ctx: &mut Ctx,
    feed: &AdvisoryFeed,
    matched: &[DeployedExposure],
    in_scope: &BTreeSet<String>,
    generation: i64,
    fencing_token: &str,
) -> Result<()> {
    refuse_stale_assessment(ctx, generation).await?;
    if !assessment_completed(ctx, generation).await? {
        return Ok(());
    }
    let live: BTreeSet<&str> = feed
        .advisories
        .iter()
        .map(|advisory| advisory.id.as_str())
        .collect();
    let matched_pairs: BTreeSet<(&str, &str)> = matched
        .iter()
        .map(|row| (row.release_id.as_str(), row.advisory_id.as_str()))
        .collect();
    let now = crate::now_millis();
    let mut seen = 0usize;
    for mut object in ctx.list_kind(KIND_DEPLOYED_EXPOSURE).await? {
        if object.kind != KIND_DEPLOYED_EXPOSURE {
            continue;
        }
        seen += 1;
        if seen.is_multiple_of(ASSESSMENT_LEASE_REFRESH_EVERY) {
            refresh_assessment_lease(ctx, fencing_token).await?;
            refuse_stale_assessment(ctx, generation).await?;
        }
        if object
            .properties
            .get("closed_at")
            .is_some_and(|value| !value.is_empty())
        {
            continue;
        }
        if recorded_generation(&object) > generation {
            continue;
        }
        let Some(advisory_id) = object.properties.get("advisory_id").map(String::as_str) else {
            continue;
        };
        let Some(release_id) = object.properties.get("release_id").map(String::as_str) else {
            continue;
        };
        let withdrawn = !live.contains(advisory_id);
        let revised =
            in_scope.contains(release_id) && !matched_pairs.contains(&(release_id, advisory_id));
        if !withdrawn && !revised {
            continue;
        }
        object
            .properties
            .insert("last_seen_generation".into(), generation.to_string());
        object
            .properties
            .insert("closed_at".into(), now.to_string());
        object.updated = now;
        ctx.guarded_update(
            object,
            ASSESSMENT_LEASE_NAMESPACE,
            ASSESSMENT_LEASE_KEY,
            fencing_token,
        )
        .await?;
    }
    Ok(())
}

async fn auto_recall_new_matches(
    ctx: &mut Ctx,
    scoped: &BTreeMap<String, BTreeSet<String>>,
    matches: &[DeployedExposure],
    generation: i64,
    fencing_token: &str,
) -> Result<()> {
    if matches.is_empty() {
        return Ok(());
    }
    refuse_stale_assessment(ctx, generation).await?;
    let mut environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let mut thresholds = HashMap::new();
    for environment in &environments {
        if crate::environment::retirement_from_object(environment).is_some() {
            continue;
        }
        if let Some(severity) = auto_recall_threshold(environment)? {
            thresholds.insert(environment.name.clone(), severity);
        }
    }
    if thresholds.is_empty() {
        return Ok(());
    }
    let mut recalled = BTreeSet::new();
    for matched in matches {
        let Some(record) = load_record(ctx, &matched.release_id, &matched.advisory_id).await?
        else {
            continue;
        };
        if record.closed_at.is_some() || record.auto_recalled_at.is_some() {
            continue;
        }
        let mut should_recall = false;
        for (env_name, release_ids) in scoped {
            if !release_ids.contains(&matched.release_id) {
                continue;
            }
            if thresholds
                .get(env_name)
                .is_some_and(|threshold| matched.severity >= *threshold)
            {
                should_recall = true;
                break;
            }
        }
        if !should_recall {
            continue;
        }
        if recalled.insert(matched.release.clone()) {
            refuse_stale_assessment(ctx, generation).await?;
            refresh_assessment_lease(ctx, fencing_token).await?;
            let actor = auto_recall_actor(&matched.advisory_id, &matched.release_id)?;
            crate::catalog::persist_recall_claim_with_fence(
                ctx,
                &actor,
                &matched.release_id,
                Some((
                    ASSESSMENT_LEASE_NAMESPACE,
                    ASSESSMENT_LEASE_KEY,
                    fencing_token,
                )),
                &[],
            )
            .await?;
        }
        stamp_auto_recalled(
            ctx,
            &matched.release_id,
            &matched.advisory_id,
            generation,
            fencing_token,
        )
        .await?;
    }
    Ok(())
}

fn auto_recall_threshold(environment: &Object) -> Result<Option<Severity>> {
    let Some(value) = environment.properties.get(AUTO_RECALL_SEVERITY_PROPERTY) else {
        return Ok(None);
    };
    Ok(Some(Severity::parse(value).with_context(|| {
        format!("environment policy {AUTO_RECALL_SEVERITY_PROPERTY} is invalid")
    })?))
}

fn auto_recall_actor(advisory_id: &str, release_id: &str) -> Result<AuthenticatedRequestContext> {
    AuthenticatedRequestContextBuilder::new(
        format!("{AUTO_RECALL_AUTHENTICATOR}:{advisory_id}:{release_id}"),
        PrincipalIdentity {
            id: format!("{advisory_id}:{release_id}"),
            kind: PrincipalKind::Service,
        },
        AUTO_RECALL_AUTHENTICATOR,
    )
    .build()
    .map_err(|error| anyhow::anyhow!("{error}"))
}

async fn stamp_auto_recalled(
    ctx: &mut Ctx,
    release_id: &str,
    advisory_id: &str,
    generation: i64,
    fencing_token: &str,
) -> Result<()> {
    refuse_stale_assessment(ctx, generation).await?;
    let id = exposure_record_id(release_id, advisory_id);
    let Some(mut object) = ctx.get(&id).await? else {
        return Ok(());
    };
    if recorded_generation(&object) > generation {
        return Ok(());
    }
    if object
        .properties
        .get("auto_recalled_at")
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(());
    }
    let now = crate::now_millis();
    object
        .properties
        .insert("auto_recalled_at".into(), now.to_string());
    object.updated = now;
    ctx.guarded_update(
        object,
        ASSESSMENT_LEASE_NAMESPACE,
        ASSESSMENT_LEASE_KEY,
        fencing_token,
    )
    .await?;
    Ok(())
}

async fn refuse_stale_assessment(ctx: &mut Ctx, generation: i64) -> Result<()> {
    match preferred_generation(ctx).await? {
        Some(preferred) if preferred > generation => {
            bail!("exposure assessment generation {generation} is stale; preferred is {preferred}")
        }
        None => bail!("exposure assessment generation {generation} has no preferred feed"),
        Some(_) => Ok(()),
    }
}

async fn preferred_generation(ctx: &mut Ctx) -> Result<Option<i64>> {
    Ok(load_advisory_feed(ctx)
        .await?
        .map(|(feed, _)| feed.generated_at))
}

fn recorded_generation(object: &Object) -> i64 {
    object
        .properties
        .get("last_seen_generation")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

async fn load_record(
    ctx: &mut Ctx,
    release_id: &str,
    advisory_id: &str,
) -> Result<Option<DeployedExposure>> {
    let Some(object) = ctx
        .get(&exposure_record_id(release_id, advisory_id))
        .await?
    else {
        return Ok(None);
    };
    if object.kind != KIND_DEPLOYED_EXPOSURE {
        return Ok(None);
    }
    Ok(Some(parse_exposure_object(&object)?))
}

async fn list_open_records(ctx: &mut Ctx) -> Result<Vec<DeployedExposure>> {
    let mut records = Vec::new();
    for object in ctx.list_kind(KIND_DEPLOYED_EXPOSURE).await? {
        if object.kind != KIND_DEPLOYED_EXPOSURE {
            continue;
        }
        let parsed = parse_exposure_object(&object)?;
        if parsed.closed_at.is_none() {
            records.push(parsed);
        }
    }
    records.sort_by(|left, right| {
        left.release_id
            .cmp(&right.release_id)
            .then(left.advisory_id.cmp(&right.advisory_id))
    });
    Ok(records)
}

fn parse_exposure_object(object: &Object) -> Result<DeployedExposure> {
    let property = |name: &str| -> Result<String> {
        object
            .properties
            .get(name)
            .cloned()
            .filter(|value| !value.is_empty())
            .with_context(|| format!("deployed exposure {} is missing {name}", object.id))
    };
    let first_seen_at = property("first_seen_at")?
        .parse::<i64>()
        .context("deployed exposure first_seen_at is not an integer")?;
    let optional_time = |name: &str| -> Result<Option<i64>> {
        object
            .properties
            .get(name)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<i64>()
                    .with_context(|| format!("deployed exposure {name} is not an integer"))
            })
            .transpose()
    };
    Ok(DeployedExposure {
        release: property("release")?,
        release_id: property("release_id")?,
        advisory_id: property("advisory_id")?,
        severity: Severity::parse(&property("severity")?)?,
        component: property("component")?,
        component_version: property("component_version")?,
        first_seen_at,
        closed_at: optional_time("closed_at")?,
        auto_recalled_at: optional_time("auto_recalled_at")?,
    })
}

fn max_age_ms_for(environment: &Object, severity: Severity) -> Option<i64> {
    environment
        .properties
        .get(&format!(
            "{MAX_EXPOSURE_AGE_PROPERTY_PREFIX}{}",
            severity.as_str()
        ))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

fn exposure_record_id(release_id: &str, advisory_id: &str) -> String {
    format!("tenkai:exposure:{release_id}:{advisory_id}")
}

fn assessment_id(generation: i64) -> String {
    format!("tenkai:exposure-assessment:{generation}")
}

fn exposure_object(
    matched: &DeployedExposure,
    generation: i64,
    first_seen_at: i64,
    now: i64,
) -> Object {
    Object {
        id: exposure_record_id(&matched.release_id, &matched.advisory_id),
        kind: KIND_DEPLOYED_EXPOSURE.into(),
        name: format!("{} {}", matched.release, matched.advisory_id),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("release".into(), matched.release.clone()),
            ("release_id".into(), matched.release_id.clone()),
            ("advisory_id".into(), matched.advisory_id.clone()),
            ("severity".into(), matched.severity.as_str().into()),
            ("component".into(), matched.component.clone()),
            (
                "component_version".into(),
                matched.component_version.clone(),
            ),
            ("first_seen_at".into(), first_seen_at.to_string()),
            ("last_seen_generation".into(), generation.to_string()),
        ]),
        created: now,
        updated: now,
    }
}

fn assessment_object(generation: i64, completed_at: i64, now: i64) -> Object {
    Object {
        id: assessment_id(generation),
        kind: KIND_EXPOSURE_ASSESSMENT.into(),
        name: format!("exposure-assessment-{generation}"),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("generated_at".into(), generation.to_string()),
            ("completed_at".into(), completed_at.to_string()),
        ]),
        created: now,
        updated: now,
    }
}

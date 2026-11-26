//! Product recall ranges: inclusive `--from`, exclusive `--before`, open-ended
//! when `--before` is omitted. Lookup consults them; no stamp is written on
//! each covered release, so closing a range admits the fix.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::client::Ctx;
use crate::ontology::{KIND_RELEASE_RECALL_RANGE, release_recall_range_id, validate_identifier};

use super::object;

/// One version subtracted from a recorded recall range at lookup time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecallRangeExclusionView {
    pub version: String,
    pub reason: String,
    pub actor: String,
    pub recorded_at: i64,
}

/// Recorded recall range for one product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecallRange {
    pub product: String,
    pub from: String,
    pub before: Option<String>,
    pub reason: String,
    pub actor: String,
    pub recorded_at: i64,
    pub exclusions: Vec<RecallRangeExclusionView>,
}

/// Operator-visible recall range for `GET /v1/products/{product}/recall-ranges`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecallRangeView {
    pub product: String,
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub before: Option<String>,
    pub reason: String,
    pub actor: String,
    pub recorded_at: i64,
    pub covers_future: bool,
    /// Versions subtracted from this range at lookup. Omitted when none,
    /// including ranges recorded before exclusions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<RecallRangeExclusionView>,
}

impl From<&RecallRange> for RecallRangeView {
    fn from(range: &RecallRange) -> Self {
        Self {
            product: range.product.clone(),
            from: range.from.clone(),
            before: range.before.clone(),
            reason: range.reason.clone(),
            actor: range.actor.clone(),
            recorded_at: range.recorded_at,
            covers_future: range.before.is_none(),
            exclusions: range.exclusions.clone(),
        }
    }
}

/// Recorded recall ranges for one product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecallRangePage {
    pub items: Vec<RecallRangeView>,
}

impl RecallRange {
    pub fn label(&self) -> String {
        match &self.before {
            Some(before) => format!("{} [{}, {before})", self.product, self.from),
            None => format!("{} [{}, ∞)", self.product, self.from),
        }
    }

    fn covers(&self, version: &semver::Version) -> Result<bool> {
        let from = parse_version("--from", &self.from)?;
        if version.cmp_precedence(&from).is_lt() {
            return Ok(false);
        }
        match &self.before {
            Some(before) => Ok(version
                .cmp_precedence(&parse_version("--before", before)?)
                .is_lt()),
            None => Ok(true),
        }
    }

    fn excludes_version(&self, version: &semver::Version) -> bool {
        self.exclusions.iter().any(|exclusion| {
            parse_version("excluded version", &exclusion.version)
                .is_ok_and(|excluded| excluded.cmp_precedence(version).is_eq())
        })
    }

    fn currently_covers(&self, version: &semver::Version) -> Result<bool> {
        Ok(self.covers(version)? && !self.excludes_version(version))
    }
}

fn parse_version(label: &str, value: &str) -> Result<semver::Version> {
    semver::Version::parse(value)
        .with_context(|| format!("{label} {value:?} is not a semantic version"))
}

fn require_bounds(from: &str, before: Option<&str>) -> Result<()> {
    let from_v = parse_version("--from", from)?;
    if let Some(before) = before {
        let before_v = parse_version("--before", before)?;
        anyhow::ensure!(
            before_v.cmp_precedence(&from_v).is_gt(),
            "recall range is empty: --before must be after --from"
        );
    }
    Ok(())
}

fn close_claim_id(product: &str, from: &str) -> String {
    format!("{}:close", release_recall_range_id(product, from))
}

fn exclusion_id(product: &str, from: &str, version: &str) -> String {
    format!(
        "{}:exclude:{version}",
        release_recall_range_id(product, from)
    )
}

fn exclusion_removed_id(product: &str, from: &str, version: &str) -> String {
    format!("{}:removed", exclusion_id(product, from, version))
}

fn require_reason<'a>(reason: &'a str, what: &str) -> Result<&'a str> {
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "{what} reason must not be empty");
    anyhow::ensure!(reason.len() <= 1024, "{what} reason exceeds 1024 bytes");
    Ok(reason)
}

fn range_from_object(object: &crate::pb::record::Object) -> Result<RecallRange> {
    let from = object
        .properties
        .get("from")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{} has no from", object.id))?;
    let before = object
        .properties
        .get("before")
        .filter(|value| !value.is_empty())
        .cloned();
    Ok(RecallRange {
        product: object
            .properties
            .get("product")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{} has no product", object.id))?
            .clone(),
        from: from.clone(),
        before,
        reason: object.properties.get("reason").cloned().unwrap_or_default(),
        actor: object.properties.get("actor").cloned().unwrap_or_default(),
        recorded_at: object
            .properties
            .get("recorded_at")
            .ok_or_else(|| anyhow::anyhow!("{} has no recorded_at", object.id))?
            .parse()?,
        exclusions: Vec::new(),
    })
}

fn exclusion_from_object(object: &crate::pb::record::Object) -> Result<RecallRangeExclusionView> {
    Ok(RecallRangeExclusionView {
        version: object
            .properties
            .get("excluded_version")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{} has no excluded_version", object.id))?
            .clone(),
        reason: object.properties.get("reason").cloned().unwrap_or_default(),
        actor: object.properties.get("actor").cloned().unwrap_or_default(),
        recorded_at: object
            .properties
            .get("recorded_at")
            .ok_or_else(|| anyhow::anyhow!("{} has no recorded_at", object.id))?
            .parse()?,
    })
}

fn overlay_close(range: &mut RecallRange, close: &crate::pb::record::Object) {
    if range.before.is_none() {
        range.before = close
            .properties
            .get("before")
            .filter(|value| !value.is_empty())
            .cloned();
    }
}

async fn list_product_ranges(ctx: &mut Ctx, product: &str) -> Result<Vec<RecallRange>> {
    let mut recorded = HashMap::new();
    let mut closes = HashMap::new();
    let mut exclusions: HashMap<String, Vec<crate::pb::record::Object>> = HashMap::new();
    let mut removed = HashMap::new();
    for object in ctx.list_kind(KIND_RELEASE_RECALL_RANGE).await? {
        if object.kind != KIND_RELEASE_RECALL_RANGE {
            continue;
        }
        if object.properties.get("product").map(String::as_str) != Some(product) {
            continue;
        }
        let Some(from) = object
            .properties
            .get("from")
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if object.id == release_recall_range_id(product, from) {
            recorded.insert(from.clone(), object);
        } else if object.id == close_claim_id(product, from) {
            closes.insert(from.clone(), object);
        } else if let Some(version) = object
            .properties
            .get("excluded_version")
            .filter(|value| !value.is_empty())
        {
            if object.id == exclusion_removed_id(product, from, version) {
                removed.insert((from.clone(), version.clone()), object);
            } else if object.id == exclusion_id(product, from, version) {
                exclusions.entry(from.clone()).or_default().push(object);
            }
        }
    }
    let mut ranges = Vec::new();
    for (from, object) in recorded {
        let mut range = range_from_object(&object)?;
        if let Some(close) = closes.get(&from) {
            overlay_close(&mut range, close);
        }
        let mut active = Vec::new();
        if let Some(objects) = exclusions.get(&from) {
            for exclusion in objects {
                let Some(version) = exclusion
                    .properties
                    .get("excluded_version")
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                if removed.contains_key(&(from.clone(), version.clone())) {
                    continue;
                }
                active.push(exclusion_from_object(exclusion)?);
            }
        }
        active.sort_by(|left, right| from_order(&left.version, &right.version));
        range.exclusions = active;
        ranges.push(range);
    }
    Ok(ranges)
}

/// Recorded ranges for `product`, ordered by `--from` in semver precedence,
/// ties broken by the raw string.
pub async fn list_recall_ranges(ctx: &mut Ctx, product: &str) -> Result<RecallRangePage> {
    validate_identifier("product", product)?;
    let mut items: Vec<RecallRangeView> = list_product_ranges(ctx, product)
        .await?
        .iter()
        .map(RecallRangeView::from)
        .collect();
    items.sort_by(|left, right| {
        from_order(&left.from, &right.from).then_with(|| left.product.cmp(&right.product))
    });
    Ok(RecallRangePage { items })
}

/// Semver precedence of two `--from` versions, ties broken by the raw string,
/// so 1.9.0 sorts before 1.10.0.
fn from_order(left: &str, right: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp_precedence(&right),
        _ => std::cmp::Ordering::Equal,
    }
    .then_with(|| left.cmp(right))
}

/// The first recorded range that currently covers `release_id`.
pub(crate) async fn covering_recall_range(
    ctx: &mut Ctx,
    release_id: &str,
) -> Result<Option<RecallRange>> {
    let Some((product, version)) = release_id
        .strip_prefix("tenkai:release:")
        .and_then(|spec| spec.split_once('@'))
    else {
        return Ok(None);
    };
    let version = match semver::Version::parse(version) {
        Ok(version) => version,
        Err(_) => return Ok(None),
    };
    for range in list_product_ranges(ctx, product).await? {
        if range.currently_covers(&version)? {
            return Ok(Some(range));
        }
    }
    Ok(None)
}

/// Ranges whose bounds cover `release_id`, including those that exclude it.
pub(crate) async fn bounds_covering_recall_ranges(
    ctx: &mut Ctx,
    release_id: &str,
) -> Result<Vec<RecallRange>> {
    let Some((product, version)) = release_id
        .strip_prefix("tenkai:release:")
        .and_then(|spec| spec.split_once('@'))
    else {
        return Ok(Vec::new());
    };
    let version = match semver::Version::parse(version) {
        Ok(version) => version,
        Err(_) => return Ok(Vec::new()),
    };
    let mut ranges = Vec::new();
    for range in list_product_ranges(ctx, product).await? {
        if range.covers(&version)? {
            ranges.push(range);
        }
    }
    ranges.sort_by(|left, right| {
        from_order(&left.from, &right.from).then_with(|| left.product.cmp(&right.product))
    });
    Ok(ranges)
}

pub(crate) async fn range_recalls(ctx: &mut Ctx, release_id: &str) -> Result<bool> {
    Ok(covering_recall_range(ctx, release_id).await?.is_some())
}

/// Record a range. The same product and `--from` twice is a no-op when bounds match.
pub async fn record_recall_range(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    from: &str,
    before: Option<&str>,
    reason: &str,
) -> Result<String> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    validate_identifier("product", product)?;
    let reason = require_reason(reason, "recall range")?;
    require_bounds(from, before)?;
    let id = release_recall_range_id(product, from);
    let recorded_at = crate::now_millis();
    let mut properties = HashMap::from([
        ("product".into(), product.to_string()),
        ("from".into(), from.to_string()),
        ("reason".into(), reason.to_string()),
        ("actor".into(), actor.principal_id().to_string()),
        ("recorded_at".into(), recorded_at.to_string()),
    ]);
    if let Some(before) = before {
        properties.insert("before".into(), before.to_string());
    }
    let proposed = object(
        id.clone(),
        KIND_RELEASE_RECALL_RANGE,
        format!("recall {product} from {from}"),
        properties,
    );
    match ctx.create_once(proposed).await {
        Ok(_) => Ok(format!(
            "recorded recall range {}",
            RecallRange {
                product: product.into(),
                from: from.into(),
                before: before.map(str::to_string),
                reason: reason.into(),
                actor: actor.principal_id().into(),
                recorded_at,
                exclusions: Vec::new(),
            }
            .label()
        )),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let existing = ctx
                .get(&id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("recall range {id} appeared then vanished"))?;
            let mut existing = range_from_object(&existing)?;
            if let Some(close) = ctx.get(&close_claim_id(product, from)).await? {
                overlay_close(&mut existing, &close);
            }
            let same_before = existing.before.as_deref() == before;
            anyhow::ensure!(
                existing.product == product && existing.from == from && same_before,
                "recall range {} already exists",
                existing.label()
            );
            Ok(format!(
                "recall range {} already recorded",
                existing.label()
            ))
        }
        Err(status) => Err(status.into()),
    }
}

/// Set `--before` on an open-ended range. A closed range never widens.
pub async fn close_recall_range(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    from: &str,
    before: &str,
) -> Result<String> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    validate_identifier("product", product)?;
    require_bounds(from, Some(before))?;
    let id = release_recall_range_id(product, from);
    let Some(recorded) = ctx.get(&id).await? else {
        bail!("no open recall range {product} from {from}");
    };
    if recorded.kind != KIND_RELEASE_RECALL_RANGE {
        bail!(
            "{} is {}, not {KIND_RELEASE_RECALL_RANGE}",
            recorded.id,
            recorded.kind
        );
    }
    let mut existing = range_from_object(&recorded)?;
    if let Some(close) = ctx.get(&close_claim_id(product, from)).await? {
        overlay_close(&mut existing, &close);
    }
    if let Some(current) = &existing.before {
        anyhow::ensure!(
            current == before,
            "recall range {} cannot widen",
            existing.label()
        );
        return Ok(format!("recall range {} already closed", existing.label()));
    }
    let recorded_at = crate::now_millis();
    let proposed = object(
        close_claim_id(product, from),
        KIND_RELEASE_RECALL_RANGE,
        format!("close recall {product} from {from}"),
        HashMap::from([
            ("product".into(), product.to_string()),
            ("from".into(), from.to_string()),
            ("before".into(), before.to_string()),
            ("reason".into(), existing.reason.clone()),
            ("actor".into(), existing.actor.clone()),
            ("recorded_at".into(), recorded_at.to_string()),
            ("closed_by".into(), actor.principal_id().to_string()),
        ]),
    );
    match ctx.create_once(proposed).await {
        Ok(_) => {}
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let claimed = ctx
                .get(&close_claim_id(product, from))
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "recall range close {} appeared then vanished",
                        close_claim_id(product, from)
                    )
                })?;
            let claimed_before = claimed
                .properties
                .get("before")
                .filter(|value| !value.is_empty())
                .map(String::as_str);
            anyhow::ensure!(
                claimed_before == Some(before),
                "recall range {} cannot widen",
                existing.label()
            );
            return Ok(format!(
                "recall range {} already closed",
                RecallRange {
                    before: Some(before.into()),
                    ..existing
                }
                .label()
            ));
        }
        Err(status) => return Err(status.into()),
    }
    Ok(format!(
        "closed recall range {}",
        RecallRange {
            before: Some(before.into()),
            ..existing
        }
        .label()
    ))
}

async fn load_recorded_range(ctx: &mut Ctx, product: &str, from: &str) -> Result<RecallRange> {
    validate_identifier("product", product)?;
    parse_version("--from", from)?;
    let id = release_recall_range_id(product, from);
    let Some(recorded) = ctx.get(&id).await? else {
        bail!("no recall range {product} from {from}");
    };
    if recorded.kind != KIND_RELEASE_RECALL_RANGE {
        bail!(
            "{} is {}, not {KIND_RELEASE_RECALL_RANGE}",
            recorded.id,
            recorded.kind
        );
    }
    let mut existing = range_from_object(&recorded)?;
    if let Some(close) = ctx.get(&close_claim_id(product, from)).await? {
        overlay_close(&mut existing, &close);
    }
    Ok(existing)
}

/// Subtract `version` from the range named by `product` and `from`. Lookup no
/// longer treats that version as recalled by this range. A release recalled on
/// its own, or by another range, stays recalled.
pub async fn exclude_from_recall_range(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    from: &str,
    version: &str,
    reason: &str,
) -> Result<String> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let reason = require_reason(reason, "recall range exclusion")?;
    let parsed = parse_version("--exclude", version)?;
    let existing = load_recorded_range(ctx, product, from).await?;
    anyhow::ensure!(
        existing.covers(&parsed)?,
        "version {version} is not inside recall range {}",
        existing.label()
    );
    if ctx
        .get(&exclusion_removed_id(product, from, version))
        .await?
        .is_some()
    {
        bail!(
            "exclusion of {version} on recall range {} was removed",
            existing.label()
        );
    }
    let recorded_at = crate::now_millis();
    let proposed = object(
        exclusion_id(product, from, version),
        KIND_RELEASE_RECALL_RANGE,
        format!("exclude {version} from recall {product} from {from}"),
        HashMap::from([
            ("product".into(), product.to_string()),
            ("from".into(), from.to_string()),
            ("excluded_version".into(), version.to_string()),
            ("reason".into(), reason.to_string()),
            ("actor".into(), actor.principal_id().to_string()),
            ("recorded_at".into(), recorded_at.to_string()),
        ]),
    );
    match ctx.create_once(proposed).await {
        Ok(_) => Ok(format!(
            "excluded {version} from recall range {}",
            existing.label()
        )),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let claimed = ctx
                .get(&exclusion_id(product, from, version))
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "recall range exclusion {} appeared then vanished",
                        exclusion_id(product, from, version)
                    )
                })?;
            let claimed_version = claimed
                .properties
                .get("excluded_version")
                .map(String::as_str);
            anyhow::ensure!(
                claimed_version == Some(version),
                "recall range {} already has an exclusion at {}",
                existing.label(),
                exclusion_id(product, from, version)
            );
            Ok(format!(
                "exclusion of {version} on recall range {} already recorded",
                existing.label()
            ))
        }
        Err(status) => Err(status.into()),
    }
}

/// Remove an exclusion so the range recalls `version` again. Fail-closed
/// lookup and planning apply immediately.
pub async fn remove_recall_range_exclusion(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    product: &str,
    from: &str,
    version: &str,
    reason: &str,
) -> Result<String> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let reason = require_reason(reason, "recall range exclusion removal")?;
    parse_version("--exclude", version)?;
    let existing = load_recorded_range(ctx, product, from).await?;
    let Some(exclusion) = ctx.get(&exclusion_id(product, from, version)).await? else {
        bail!(
            "no exclusion of {version} on recall range {}",
            existing.label()
        );
    };
    if exclusion.kind != KIND_RELEASE_RECALL_RANGE {
        bail!(
            "{} is {}, not {KIND_RELEASE_RECALL_RANGE}",
            exclusion.id,
            exclusion.kind
        );
    }
    let recorded_at = crate::now_millis();
    let proposed = object(
        exclusion_removed_id(product, from, version),
        KIND_RELEASE_RECALL_RANGE,
        format!("remove exclusion of {version} from recall {product} from {from}"),
        HashMap::from([
            ("product".into(), product.to_string()),
            ("from".into(), from.to_string()),
            ("excluded_version".into(), version.to_string()),
            ("reason".into(), reason.to_string()),
            ("actor".into(), actor.principal_id().to_string()),
            ("recorded_at".into(), recorded_at.to_string()),
            ("removed_by".into(), actor.principal_id().to_string()),
        ]),
    );
    match ctx.create_once(proposed).await {
        Ok(_) => Ok(format!(
            "removed exclusion of {version} from recall range {}",
            existing.label()
        )),
        Err(status) if crate::client::is_unique_conflict(&status) => Ok(format!(
            "exclusion of {version} on recall range {} already removed",
            existing.label()
        )),
        Err(status) => Err(status.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{PublishOptions, inspect_release, publish, recall, release_is_recalled};
    use crate::client::Ctx;
    use crate::ontology::release_id;

    async fn published(product: &str, version: &str) -> (std::path::PathBuf, Ctx) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recall-range-{}-{}-{version}-{}",
            std::process::id(),
            product,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "{product}"
version = "{version}"

[deploy]
install = "true"
"#
            ),
        )
        .unwrap();
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        (root, ctx)
    }

    #[tokio::test]
    async fn range_recalls_inside_and_admits_outside() {
        let (root, mut ctx) = published("api", "1.1.0").await;
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.2.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "0.9.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("range");
        record_recall_range(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            Some("1.2.0"),
            "bad series",
        )
        .await
        .unwrap();
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.1.0"))
                .await
                .unwrap()
        );
        assert!(
            !release_is_recalled(&mut ctx, &release_id("api", "0.9.0"))
                .await
                .unwrap()
        );
        assert!(
            !release_is_recalled(&mut ctx, &release_id("api", "1.2.0"))
                .await
                .unwrap()
        );
        let inspected = inspect_release(&mut ctx, "api@1.1.0").await.unwrap();
        assert_eq!(
            inspected.recall_range.as_deref(),
            Some("api [1.0.0, 1.2.0)")
        );
        let outside = inspect_release(&mut ctx, "api@0.9.0").await.unwrap();
        assert_eq!(outside.recall_range, None);
        let again = record_recall_range(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            Some("1.2.0"),
            "bad series",
        )
        .await
        .unwrap();
        assert!(again.contains("already recorded"), "{again}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn open_range_recalls_later_publish_and_close_admits_fix() {
        let (root, mut ctx) = published("api", "1.0.0").await;
        let actor = crate::auth_context::test_management_context("range");
        record_recall_range(&mut ctx, &actor, "api", "1.0.0", None, "open defect")
            .await
            .unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.1.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.1.0"))
                .await
                .unwrap()
        );
        close_recall_range(&mut ctx, &actor, "api", "1.0.0", "1.2.0")
            .await
            .unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.2.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        publish(&mut ctx, &root.join("tenkai.toml"), &options)
            .await
            .unwrap();
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.1.0"))
                .await
                .unwrap()
        );
        assert!(
            !release_is_recalled(&mut ctx, &release_id("api", "1.2.0"))
                .await
                .unwrap()
        );
        let widen = close_recall_range(&mut ctx, &actor, "api", "1.0.0", "1.3.0")
            .await
            .unwrap_err()
            .to_string();
        assert!(widen.contains("cannot widen"), "{widen}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ranges_list_in_semver_order_not_text_order() {
        let mut froms = vec!["1.10.0", "1.9.0", "1.9.0+b", "1.9.0+a", "1.2.0"];
        froms.sort_by(|left, right| from_order(left, right));
        assert_eq!(froms, ["1.2.0", "1.9.0", "1.9.0+a", "1.9.0+b", "1.10.0"]);
    }

    #[test]
    fn coverage_follows_semver_precedence_not_build_metadata() {
        let range = RecallRange {
            product: "api".into(),
            from: "1.0.0+b.2".into(),
            before: Some("1.1.0+b.1".into()),
            reason: "x".into(),
            actor: "range".into(),
            recorded_at: 0,
            exclusions: Vec::new(),
        };
        assert!(
            range
                .covers(&semver::Version::parse("1.0.0").unwrap())
                .unwrap()
        );
        assert!(
            range
                .covers(&semver::Version::parse("1.0.0+b.1").unwrap())
                .unwrap()
        );
        assert!(
            !range
                .covers(&semver::Version::parse("1.1.0").unwrap())
                .unwrap()
        );
        let empty = require_bounds("1.0.0+b.2", Some("1.0.0+b.1"))
            .unwrap_err()
            .to_string();
        assert!(empty.contains("empty"), "{empty}");
    }

    #[tokio::test]
    async fn non_semantic_and_empty_range_are_named() {
        let (root, mut ctx) = published("api", "1.0.0").await;
        let actor = crate::auth_context::test_management_context("range");
        let semver = record_recall_range(&mut ctx, &actor, "api", "not-a-version", None, "x")
            .await
            .unwrap_err()
            .to_string();
        assert!(semver.contains("semantic version"), "{semver}");
        let empty = record_recall_range(&mut ctx, &actor, "api", "1.2.0", Some("1.2.0"), "x")
            .await
            .unwrap_err()
            .to_string();
        assert!(empty.contains("empty"), "{empty}");
        let _ = recall(&mut ctx, &actor, "api@1.0.0").await.unwrap();
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn exclusion_lifts_only_that_range_and_removing_it_recalls_again() {
        let (root, mut ctx) = published("api", "1.1.0").await;
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        for version in ["1.0.0", "1.2.0"] {
            std::fs::write(
                root.join("tenkai.toml"),
                format!(
                    r#"
[product]
name = "api"
version = "{version}"

[deploy]
install = "true"
"#
                ),
            )
            .unwrap();
            publish(&mut ctx, &root.join("tenkai.toml"), &options)
                .await
                .unwrap();
        }
        let actor = crate::auth_context::test_management_context("range");
        record_recall_range(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            Some("1.3.0"),
            "bad series",
        )
        .await
        .unwrap();
        record_recall_range(&mut ctx, &actor, "api", "1.2.0", None, "later defect")
            .await
            .unwrap();
        let _ = recall(&mut ctx, &actor, "api@1.1.0").await.unwrap();
        exclude_from_recall_range(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            "1.1.0",
            "keep serving 1.1.0",
        )
        .await
        .unwrap();
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.1.0"))
                .await
                .unwrap(),
            "own recall stays after the range exclusion"
        );
        let excluded = exclude_from_recall_range(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            "1.0.0",
            "keep serving 1.0.0",
        )
        .await
        .unwrap();
        assert!(excluded.contains("excluded 1.0.0"), "{excluded}");
        assert!(
            !release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.2.0"))
                .await
                .unwrap(),
            "another range still recalls 1.2.0"
        );
        let ranges = list_recall_ranges(&mut ctx, "api").await.unwrap();
        let first = ranges
            .items
            .iter()
            .find(|range| range.from == "1.0.0")
            .expect("range from 1.0.0");
        assert_eq!(
            first
                .exclusions
                .iter()
                .map(|exclusion| exclusion.version.as_str())
                .collect::<Vec<_>>(),
            ["1.0.0", "1.1.0"]
        );
        let inspected = inspect_release(&mut ctx, "api@1.0.0").await.unwrap();
        assert_eq!(inspected.recall_range, None, "{inspected:?}");
        assert_eq!(
            inspected
                .recall_range_exclusions
                .iter()
                .map(|exclusion| exclusion.version.as_str())
                .collect::<Vec<_>>(),
            ["1.0.0", "1.1.0"]
        );
        let outside =
            exclude_from_recall_range(&mut ctx, &actor, "api", "1.0.0", "0.9.0", "not in range")
                .await
                .unwrap_err()
                .to_string();
        assert!(outside.contains("not inside"), "{outside}");
        let denied = exclude_from_recall_range(
            &mut ctx,
            &crate::auth_context::test_human_context("range-reader"),
            "api",
            "1.0.0",
            "1.0.0",
            "nope",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            denied.contains("insufficient delivery capability"),
            "{denied}"
        );
        let removed = remove_recall_range_exclusion(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            "1.0.0",
            "put 1.0.0 back",
        )
        .await
        .unwrap();
        assert!(removed.contains("removed exclusion"), "{removed}");
        assert!(
            release_is_recalled(&mut ctx, &release_id("api", "1.0.0"))
                .await
                .unwrap()
        );
        let ranges = list_recall_ranges(&mut ctx, "api").await.unwrap();
        let first = ranges
            .items
            .iter()
            .find(|range| range.from == "1.0.0")
            .expect("range from 1.0.0");
        assert_eq!(
            first
                .exclusions
                .iter()
                .map(|exclusion| exclusion.version.as_str())
                .collect::<Vec<_>>(),
            ["1.1.0"]
        );
        let again = remove_recall_range_exclusion(
            &mut ctx,
            &actor,
            "api",
            "1.0.0",
            "1.0.0",
            "put 1.0.0 back",
        )
        .await
        .unwrap();
        assert!(again.contains("already removed"), "{again}");
        let _ = std::fs::remove_dir_all(root);
    }
}

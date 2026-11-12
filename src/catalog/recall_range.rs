//! Product recall ranges: inclusive `--from`, exclusive `--before`, open-ended
//! when `--before` is omitted. Lookup consults them; no stamp is written on
//! each covered release, so closing a range admits the fix.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};

use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::client::Ctx;
use crate::ontology::{KIND_RELEASE_RECALL_RANGE, release_recall_range_id, validate_identifier};

use super::object;

/// Recorded recall range for one product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecallRange {
    pub product: String,
    pub from: String,
    pub before: Option<String>,
    pub reason: String,
    pub actor: String,
    pub recorded_at: i64,
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

fn range_from_object(object: &crate::pb::sekai::Object) -> Result<RecallRange> {
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
    })
}

fn overlay_close(range: &mut RecallRange, close: &crate::pb::sekai::Object) {
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
        }
    }
    let mut ranges = Vec::new();
    for (from, object) in recorded {
        let mut range = range_from_object(&object)?;
        if let Some(close) = closes.get(&from) {
            overlay_close(&mut range, close);
        }
        ranges.push(range);
    }
    Ok(ranges)
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
        if range.covers(&version)? {
            return Ok(Some(range));
        }
    }
    Ok(None)
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
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "recall range reason must not be empty");
    anyhow::ensure!(
        reason.len() <= 1024,
        "recall range reason exceeds 1024 bytes"
    );
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
            crate::now_millis()
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
    fn coverage_follows_semver_precedence_not_build_metadata() {
        let range = RecallRange {
            product: "api".into(),
            from: "1.0.0+b.2".into(),
            before: Some("1.1.0+b.1".into()),
            reason: "x".into(),
            actor: "range".into(),
            recorded_at: 0,
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
}

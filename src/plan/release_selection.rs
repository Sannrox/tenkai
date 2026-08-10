//! Release selection policy for one Environment subscription.
//!
//! This private module keeps version constraints, capability facts, model-runtime
//! variant discovery, and deterministic diagnostics behind one selection interface.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::manifest::{ModelRequirementsSection, ProductKind};
use crate::ontology::{REL_RELEASE_OF, product_id, release_id};
use crate::pb::sekai::Object;

pub(super) struct ChannelHead<'a> {
    pub product: &'a str,
    pub version: &'a str,
    pub release_id: &'a str,
}

pub(super) struct SelectedRelease {
    pub version: String,
    pub release_id: String,
    pub kind: ProductKind,
}

/// Resolve a promoted channel head against one Environment's constraints and facts.
///
/// Version pins override the channel head. Version ranges remain half-open. For
/// model-runtime products, the channel head is a rollout ceiling and the highest
/// feasible published sibling is selected deterministically.
pub(super) async fn select(
    ctx: &mut Ctx,
    environment: &Object,
    environment_name: &str,
    channel: ChannelHead<'_>,
) -> Result<SelectedRelease> {
    enforce_capability_constraints(ctx, environment, environment_name).await?;
    let (version, release_id) = resolve_constrained_release(
        ctx,
        environment,
        environment_name,
        channel.product,
        channel.version,
        channel.release_id,
    )
    .await?;
    let kind = release_product_kind(ctx, &release_id).await?;
    Ok(SelectedRelease {
        version,
        release_id,
        kind,
    })
}

async fn resolve_constrained_release(
    ctx: &mut Ctx,
    environment: &Object,
    environment_name: &str,
    product: &str,
    channel_version: &str,
    channel_release: &str,
) -> Result<(String, String)> {
    let pin_key = format!("constraint.version_pin.{product}");
    let range_key = format!("constraint.version_range.{product}");
    let pin = environment.properties.get(&pin_key).cloned();
    let range = environment.properties.get(&range_key).cloned();

    if let Some(pin) = pin.as_ref() {
        if pin.trim().is_empty() {
            bail!("constraint version pin for {product} must not be empty");
        }
        let pinned_release = release_id(product, pin);
        if ctx.get(&pinned_release).await?.is_none() {
            bail!(
                "version pin {pin} for {product} in {environment_name} is not published (constraint {pin_key})"
            );
        }
        if let Some(range) = range.as_ref()
            && !version_in_range(pin, range)?
        {
            bail!(
                "version pin {pin} for {product} in {environment_name} violates version range constraint {range:?} ({range_key})"
            );
        }
        ensure_model_runtime_fits(ctx, environment_name, product, pin, &pinned_release).await?;
        if pin != channel_version {
            return Ok((pin.clone(), pinned_release));
        }
        return Ok((channel_version.into(), channel_release.into()));
    }

    if let Some(range) = range.as_ref()
        && !version_in_range(channel_version, range)?
        && !release_is_model_runtime(ctx, channel_release).await?
    {
        bail!(
            "channel head {channel_version} for {product} in {environment_name} violates version range constraint {range:?} ({range_key})"
        );
    }

    if release_is_model_runtime(ctx, channel_release).await?
        || product_has_model_runtime_release(ctx, product).await?
    {
        return select_model_runtime_variant(
            ctx,
            environment_name,
            product,
            channel_version,
            channel_release,
            range.as_deref(),
        )
        .await;
    }

    if let Some(range) = range.as_ref()
        && !version_in_range(channel_version, range)?
    {
        bail!(
            "channel head {channel_version} for {product} in {environment_name} violates version range constraint {range:?} ({range_key})"
        );
    }
    Ok((channel_version.into(), channel_release.into()))
}

async fn release_is_model_runtime(ctx: &mut Ctx, release: &str) -> Result<bool> {
    let Some(object) = ctx.get(release).await? else {
        return Ok(false);
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(false);
    };
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {release}"))?;
    Ok(manifest.product.kind == ProductKind::ModelRuntime)
}

async fn product_has_model_runtime_release(ctx: &mut Ctx, product: &str) -> Result<bool> {
    let releases = ctx
        .linked(&product_id(product), REL_RELEASE_OF, "in")
        .await?;
    for release in releases {
        if release_is_model_runtime(ctx, &release.id).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Match model-runtime requirements against Environment capability facts.
pub fn model_requirements_fit(
    environment: &str,
    product: &str,
    version: &str,
    facts: &BTreeMap<String, String>,
    requirements: &ModelRequirementsSection,
) -> Result<()> {
    let architecture = facts.get("architecture").ok_or_else(|| {
        anyhow::anyhow!(
            "model_runtime {product}@{version} requires environment fact architecture for {environment}; set it with `tenkaictl env facts set {environment} architecture=…`"
        )
    })?;
    if !requirements
        .architecture
        .iter()
        .any(|allowed| allowed == architecture)
    {
        bail!(
            "model_runtime {product}@{version} requirements.architecture {:?} does not include environment {environment} fact architecture={architecture}",
            requirements.architecture
        );
    }

    let memory_raw = facts.get("memory_gib").ok_or_else(|| {
        anyhow::anyhow!(
            "model_runtime {product}@{version} requires environment fact memory_gib for {environment}; set it with `tenkaictl env facts set {environment} memory_gib=…`"
        )
    })?;
    let memory: u32 = memory_raw.parse().with_context(|| {
        format!(
            "environment {environment} fact memory_gib={memory_raw:?} is not a non-negative integer"
        )
    })?;
    if memory < requirements.memory_gib {
        bail!(
            "model_runtime {product}@{version} requires memory_gib>={} but environment {environment} fact memory_gib={memory}",
            requirements.memory_gib
        );
    }

    if !requirements.accelerator.is_empty() {
        let accelerator = facts.get("accelerator").ok_or_else(|| {
            anyhow::anyhow!(
                "model_runtime {product}@{version} requires environment fact accelerator for {environment}; set it with `tenkaictl env facts set {environment} accelerator=…`"
            )
        })?;
        if !requirements
            .accelerator
            .iter()
            .any(|allowed| allowed == accelerator)
        {
            bail!(
                "model_runtime {product}@{version} requirements.accelerator {:?} does not include environment {environment} fact accelerator={accelerator}",
                requirements.accelerator
            );
        }
    }
    Ok(())
}

async fn ensure_model_runtime_fits(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
    version: &str,
    release: &str,
) -> Result<()> {
    let Some(object) = ctx.get(release).await? else {
        bail!("release {release} is not published");
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(());
    };
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {release}"))?;
    if manifest.product.kind != ProductKind::ModelRuntime {
        return Ok(());
    }
    let requirements = manifest.requirements.as_ref().ok_or_else(|| {
        anyhow::anyhow!("model_runtime {product}@{version} has no [requirements] section")
    })?;
    let facts = crate::environment::list_environment_facts(ctx, environment).await?;
    model_requirements_fit(environment, product, version, &facts, requirements)
}

async fn select_model_runtime_variant(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
    channel_version: &str,
    channel_release: &str,
    range: Option<&str>,
) -> Result<(String, String)> {
    let facts = crate::environment::list_environment_facts(ctx, environment).await?;
    let linked = ctx
        .linked(&product_id(product), REL_RELEASE_OF, "in")
        .await?;
    let channel_semver = semver::Version::parse(channel_version).ok();
    let mut candidates = Vec::new();
    for release in linked {
        let Some(version) = release.properties.get("version").cloned() else {
            continue;
        };
        if let Some(range) = range
            && !version_in_range(&version, range)?
        {
            continue;
        }
        if let (Some(head), Ok(candidate)) = (&channel_semver, semver::Version::parse(&version))
            && candidate > *head
        {
            continue;
        }
        let Some(raw) = release.properties.get("manifest") else {
            continue;
        };
        let manifest = crate::manifest::parse_raw(raw)
            .with_context(|| format!("parsing stored manifest of {}", release.id))?;
        if manifest.product.kind != ProductKind::ModelRuntime {
            continue;
        }
        let Some(requirements) = manifest.requirements.as_ref() else {
            continue;
        };
        if model_requirements_fit(environment, product, &version, &facts, requirements).is_ok() {
            candidates.push((version, release.id));
        }
    }

    if candidates.is_empty() {
        if let Err(head_error) =
            ensure_model_runtime_fits(ctx, environment, product, channel_version, channel_release)
                .await
        {
            bail!(
                "no model_runtime variant of {product} fits environment {environment} facts (architecture/memory_gib/accelerator); channel head rejected: {head_error}"
            );
        }
        bail!(
            "no model_runtime variant of {product} fits environment {environment} facts (architecture/memory_gib/accelerator); publish a feasible variant or relax constraints"
        );
    }

    candidates.sort_by(|(a, _), (b, _)| {
        match (semver::Version::parse(a), semver::Version::parse(b)) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            _ => a.cmp(b),
        }
    });
    Ok(candidates
        .pop()
        .expect("candidates non-empty after empty check"))
}

fn version_in_range(version: &str, range: &str) -> Result<bool> {
    let Some((min, max)) = range.split_once("..") else {
        bail!("version range must be min..max, got {range:?}");
    };
    let version =
        semver::Version::parse(version).with_context(|| format!("invalid version {version:?}"))?;
    let min = semver::Version::parse(min.trim())
        .with_context(|| format!("invalid version range minimum in {range:?}"))?;
    let max = semver::Version::parse(max.trim())
        .with_context(|| format!("invalid version range maximum in {range:?}"))?;
    if min >= max {
        bail!("version range minimum must be less than maximum in {range:?}");
    }
    Ok(version >= min && version < max)
}

async fn enforce_capability_constraints(
    ctx: &mut Ctx,
    environment: &Object,
    environment_name: &str,
) -> Result<()> {
    for (key, expected) in &environment.properties {
        let Some(fact_key) = key.strip_prefix("constraint.require_fact.") else {
            continue;
        };
        crate::environment::validate_fact_key(fact_key)?;
        let actual =
            crate::environment::require_environment_fact(ctx, environment_name, fact_key).await?;
        if expected != "*" && expected != &actual {
            bail!(
                "environment {environment_name} fact {fact_key}={actual} does not satisfy constraint {expected:?} ({key})"
            );
        }
    }
    Ok(())
}

async fn release_product_kind(ctx: &mut Ctx, release: &str) -> Result<ProductKind> {
    let object = ctx
        .get(release)
        .await?
        .with_context(|| format!("release {release} not found for product kind lookup"))?;
    let raw = object
        .properties
        .get("manifest")
        .with_context(|| format!("release {release} has no stored manifest"))?;
    let manifest = crate::manifest::parse_raw(raw)
        .with_context(|| format!("parsing stored manifest of {release}"))?;
    Ok(manifest.product.kind)
}

#[cfg(test)]
mod tests {
    use super::version_in_range;

    #[test]
    fn version_range_is_half_open() {
        assert!(version_in_range("1.0.0", "1.0.0..2.0.0").unwrap());
        assert!(version_in_range("1.9.9", "1.0.0..2.0.0").unwrap());
        assert!(!version_in_range("2.0.0", "1.0.0..2.0.0").unwrap());
        assert!(!version_in_range("0.9.0", "1.0.0..2.0.0").unwrap());
        assert!(version_in_range("bad", "1.0.0..2.0.0").is_err());
        assert!(version_in_range("1.0.0", "2.0.0..1.0.0").is_err());
    }
}

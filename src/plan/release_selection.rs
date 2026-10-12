//! Release selection policy for one Environment subscription.
//!
//! This private module keeps version constraints, capability facts, model-runtime
//! variant discovery, and deterministic diagnostics behind one selection interface.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};

use crate::client::Ctx;
use crate::manifest::{GpuRequirements, ModelRequirementsSection, ProductKind};
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
    let (version, release_id) = resolve_subscription_selection(
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

/// Recompute the constrained desired release identity for one subscription.
///
/// Admission must compare against this selection, not the raw channel head:
/// version pins and model-runtime variant choice intentionally diverge from
/// `current_version` / `current_release`.
pub(crate) async fn resolve_subscription_selection(
    ctx: &mut Ctx,
    environment: &Object,
    environment_name: &str,
    product: &str,
    channel_version: &str,
    channel_release: &str,
) -> Result<(String, String)> {
    enforce_capability_constraints(ctx, environment, environment_name).await?;
    resolve_constrained_release(
        ctx,
        environment,
        environment_name,
        product,
        channel_version,
        channel_release,
    )
    .await
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
    if let Some(gpu) = &requirements.gpu {
        gpu_requirements_fit(facts, gpu).map_err(|refusal| {
            anyhow::anyhow!(
                "model_runtime {product}@{version} does not fit environment {environment}: {refusal}"
            )
        })?;
    }
    Ok(())
}

/// Why a variant's GPU requirements do not fit an Environment's `gpu_*` facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FitRefusal {
    /// The fact is not recorded; unknown never fits.
    MissingFact { fact: &'static str },
    /// The fact is recorded but unparseable.
    InvalidFact { fact: &'static str, actual: String },
    /// The fact is not one of the allowed values.
    NotAllowed {
        fact: &'static str,
        actual: String,
        allowed: Vec<String>,
    },
    /// The fact is below the required minimum.
    BelowMinimum {
        fact: &'static str,
        actual: String,
        minimum: String,
    },
}

impl FitRefusal {
    /// Stable machine-readable reason.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingFact { .. } => "fact_missing",
            Self::InvalidFact { .. } => "fact_invalid",
            Self::NotAllowed { .. } => "fact_not_allowed",
            Self::BelowMinimum { .. } => "fact_below_minimum",
        }
    }
}

impl std::fmt::Display for FitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFact { fact } => write!(
                f,
                "[{}] environment fact {fact} is unknown; set it with `tenkaictl env facts set`",
                self.code()
            ),
            Self::InvalidFact { fact, actual } => {
                write!(
                    f,
                    "[{}] environment fact {fact}={actual:?} is invalid",
                    self.code()
                )
            }
            Self::NotAllowed {
                fact,
                actual,
                allowed,
            } => write!(
                f,
                "[{}] environment fact {fact}={actual} is not one of {allowed:?}",
                self.code()
            ),
            Self::BelowMinimum {
                fact,
                actual,
                minimum,
            } => write!(
                f,
                "[{}] environment fact {fact}={actual} is below the required {minimum}",
                self.code()
            ),
        }
    }
}

/// Match `[requirements.gpu]` against Environment facts. Every requirement needs its
/// fact; a missing fact is a refusal, never a fit.
pub fn gpu_requirements_fit(
    facts: &BTreeMap<String, String>,
    gpu: &GpuRequirements,
) -> Result<(), FitRefusal> {
    let fact = |name: &'static str| {
        facts
            .get(name)
            .map(String::as_str)
            .ok_or(FitRefusal::MissingFact { fact: name })
    };
    let one_of = |name: &'static str, allowed: &[String]| {
        if allowed.is_empty() {
            return Ok(());
        }
        let actual = fact(name)?;
        if allowed.iter().any(|value| value == actual) {
            Ok(())
        } else {
            Err(FitRefusal::NotAllowed {
                fact: name,
                actual: actual.into(),
                allowed: allowed.to_vec(),
            })
        }
    };
    let at_least = |name: &'static str, minimum: u32| {
        let actual = fact(name)?;
        let parsed: u32 = actual.parse().map_err(|_| FitRefusal::InvalidFact {
            fact: name,
            actual: actual.into(),
        })?;
        if parsed >= minimum {
            Ok(())
        } else {
            Err(FitRefusal::BelowMinimum {
                fact: name,
                actual: actual.into(),
                minimum: minimum.to_string(),
            })
        }
    };
    let version_at_least = |name: &'static str, minimum: &Option<String>| {
        let Some(minimum) = minimum else {
            return Ok(());
        };
        let actual = fact(name)?;
        let parsed = dotted_version(actual).ok_or_else(|| FitRefusal::InvalidFact {
            fact: name,
            actual: actual.into(),
        })?;
        let required = dotted_version(minimum).ok_or_else(|| FitRefusal::InvalidFact {
            fact: name,
            actual: minimum.clone(),
        })?;
        if parsed >= required {
            Ok(())
        } else {
            Err(FitRefusal::BelowMinimum {
                fact: name,
                actual: actual.into(),
                minimum: minimum.clone(),
            })
        }
    };

    one_of("gpu_vendor", &gpu.vendor)?;
    one_of("gpu_family", &gpu.families)?;
    at_least("gpu_count", gpu.count.max(gpu.tensor_parallel))?;
    at_least("gpu_vram_gib", gpu.vram_gib)?;
    version_at_least("gpu_driver_version", &gpu.driver_min)?;
    if let Some(runtime) = &gpu.runtime {
        one_of("gpu_runtime", std::slice::from_ref(runtime))?;
        version_at_least("gpu_runtime_version", &gpu.runtime_min)?;
    }
    Ok(())
}

/// Dotted numeric version (`535.104.05`, `12.2`) as comparable components, with
/// trailing zeros dropped so `12.2` equals `12.2.0`.
pub fn dotted_version(value: &str) -> Option<Vec<u64>> {
    let mut parts = value
        .trim()
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    while parts.last() == Some(&0) {
        parts.pop();
    }
    Some(parts)
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
                "no model_runtime variant of {product} fits environment {environment} facts (architecture/memory_gib/accelerator/gpu); channel head rejected: {head_error}"
            );
        }
        bail!(
            "no model_runtime variant of {product} fits environment {environment} facts (architecture/memory_gib/accelerator/gpu); publish a feasible variant or relax constraints"
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

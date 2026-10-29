//! Per-release component inventory, advisory-feed import, and exposure query
//! (#692, #645).
//!
//! A signed release may declare `[inventory] document = "..."`; that file is
//! part of the content digest, stored next to the release, and refused when
//! unsigned or mismatched. A signed `tenkai.advisory-feed.v1` travels as
//! `advisories/feed.json` in `tenkai.offline-bundle.v1`; import applies bundled
//! revocations, verifies the envelope, then matches locally. Query and advisory
//! matching read only catalog and environment state.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::connectivity::CONNECTIVITY_CLASS_PROPERTY;
use crate::manifest::{self, Manifest};
use crate::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, KIND_RELEASE, NS};
use crate::pb::sekai::Object;
use crate::plan::Step;
use crate::provider_event::{ProviderEventStore, enqueue_optional_event};
use crate::providers::{EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderEvent};

/// Stored advisory-feed object kind.
pub const KIND_ADVISORY_FEED: &str = "tenkai.advisory_feed";
/// Native inventory document schema.
pub const INVENTORY_SCHEMA: &str = "tenkai.component-inventory.v1";
/// Advisory feed document schema.
pub const ADVISORY_FEED_SCHEMA: &str = "tenkai.advisory-feed.v1";
/// Signed bundle path for an advisory feed (#645).
pub const ADVISORY_FEED_PATH: &str = "advisories/feed.json";
/// Media type of [`ADVISORY_FEED_PATH`].
pub const ADVISORY_FEED_MEDIA: &str = "application/vnd.tenkai.advisory-feed.v1+json";
/// Optional outbox kind for matched exposures. Off unless [`export_exposures`] runs.
pub const EXPOSURE_PROVIDER_KIND: &str = "exposure";
/// Environment property: unix-ms of the last successful isolated bundle import.
pub const LAST_BUNDLE_IMPORT_AT_PROPERTY: &str = "last_bundle_import_at";
/// Environment property: max advisory-feed age in milliseconds.
pub const MAX_FEED_AGE_PROPERTY: &str = "exposure.max_feed_age_ms";
/// Environment property: block plans at this severity or above.
pub const BLOCK_SEVERITY_PROPERTY: &str = "exposure.block_severity";

const FEED_ID: &str = "tenkai:advisory-feed";
const ALIAS_LEASE_NAMESPACE: &str = "tenkai/advisory-feed";
const ALIAS_LEASE_KEY: &str = "alias";
const ALIAS_LEASE_TTL_MS: i64 = 15_000;
const INVENTORY_DIGEST_PROPERTY: &str = "inventory.digest";
const INVENTORY_DOCUMENT_PROPERTY: &str = "inventory.document";
const INVENTORY_SCHEMA_PROPERTY: &str = "inventory.schema";

/// Query parameters for `GET /v1/exposures` and `tenkaictl exposure query`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExposureQueryRequest {
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub range: String,
}

/// One component listed in a release inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InventoryComponent {
    pub name: String,
    pub version: String,
}

/// Parsed component inventory covered by a release signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ComponentInventory {
    pub schema: String,
    pub digest: String,
    pub components: Vec<InventoryComponent>,
}

/// How current an environment's deployed release observation is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Freshness {
    Hub,
    AsOfLastBundleImport { imported_at: i64 },
    Unknown,
}

/// One environment running a matching release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentExposure {
    pub environment: String,
    pub deployed_release: String,
    pub freshness: Freshness,
}

/// One catalog release that contains the queried component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseExposure {
    pub release: String,
    pub product: String,
    pub version: String,
    pub release_id: String,
    pub component: String,
    pub component_version: String,
    pub channels: Vec<String>,
    pub environments: Vec<EnvironmentExposure>,
}

/// Result of an exposure query. Matching is local; it does not contact a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExposureQueryResult {
    pub component: String,
    pub range: String,
    pub matches: Vec<ReleaseExposure>,
}

/// One advisory in a locally imported feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Advisory {
    pub id: String,
    pub component: String,
    pub range: String,
    pub severity: Severity,
    #[serde(default)]
    pub issued_at: i64,
}

/// Advisory feed stored as one catalog object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdvisoryFeed {
    pub schema: String,
    #[serde(default)]
    pub generated_at: i64,
    pub advisories: Vec<Advisory>,
}

/// A release component that matches an advisory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MatchedExposure {
    pub advisory_id: String,
    pub severity: Severity,
    pub component: String,
    pub component_version: String,
    pub release: String,
    pub release_id: String,
}

/// Imported feed age and the releases it currently flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdvisoryFeedStatus {
    pub imported: bool,
    pub imported_at: i64,
    pub generated_at: i64,
    pub age_ms: i64,
    pub advisory_count: usize,
    pub matches: Vec<MatchedExposure>,
}

/// Ordered advisory severities. Higher values are more severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => bail!("unknown advisory severity {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Load, parse, and persist a declared inventory onto a release object.
///
/// Inventory requires a verified release signature. The document is already
/// covered by `artifact_digest` through [`Manifest::immutable_inputs`].
pub fn persist_inventory(
    properties: &mut HashMap<String, String>,
    manifest: &Manifest,
    workdir: &Path,
    signed: bool,
) -> Result<()> {
    let Some(section) = &manifest.inventory else {
        return Ok(());
    };
    if !signed {
        bail!(
            "unsigned inventory is refused; publish with a release signature that covers [inventory]"
        );
    }
    let loaded = load_inventory_file(workdir, &section.document)?;
    properties.insert(INVENTORY_SCHEMA_PROPERTY.into(), loaded.schema);
    properties.insert(INVENTORY_DIGEST_PROPERTY.into(), loaded.digest);
    properties.insert(
        INVENTORY_DOCUMENT_PROPERTY.into(),
        String::from_utf8(loaded.bytes).context("inventory document must be UTF-8 JSON")?,
    );
    Ok(())
}

/// Refuse a stored inventory that does not match its digest or workdir file.
pub fn validate_stored_inventory(release: &Object, workdir: Option<&Path>) -> Result<()> {
    let Some(stored) = stored_inventory(release)? else {
        return Ok(());
    };
    let Some(raw) = release.properties.get("manifest") else {
        return Ok(());
    };
    let parsed = manifest::parse_raw(raw)?;
    let Some(section) = &parsed.inventory else {
        bail!(
            "release {} has an inventory that is not declared in its signed manifest",
            release.id
        );
    };
    // Catalog reads pass `None` so a second instance does not need the
    // publisher's snapshot. Publish passes the workdir being admitted.
    if let Some(root) = workdir {
        let file = load_inventory_file(root, &section.document)?;
        if file.digest != stored.digest {
            bail!(
                "release {} inventory is not covered by its signed content digest",
                release.id
            );
        }
    }
    Ok(())
}

/// Query releases, channels, and environments that contain `component` in `range`.
pub async fn query(ctx: &mut Ctx, component: &str, range: &str) -> Result<ExposureQueryResult> {
    if component.trim().is_empty() || range.trim().is_empty() {
        bail!("exposure query requires --component and --range");
    }
    semver::VersionReq::parse(range).with_context(|| format!("invalid version range {range:?}"))?;
    let channels = ctx.list_kind(KIND_CHANNEL).await?;
    let environments = ctx.list_kind(KIND_ENVIRONMENT).await?;
    let mut matches = Vec::new();
    for release in ctx.list_kind(KIND_RELEASE).await? {
        validate_stored_inventory(&release, None)?;
        let Some(inventory) = stored_inventory(&release)? else {
            continue;
        };
        let mut hit = None;
        for entry in &inventory.components {
            if entry.name == component && version_in_range(&entry.version, range)? {
                hit = Some(entry);
                break;
            }
        }
        let Some(hit) = hit else {
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
        let mut matched_channels: Vec<String> = channels
            .iter()
            .filter(|channel| {
                channel
                    .properties
                    .get("current_release")
                    .map(String::as_str)
                    == Some(&release.id)
            })
            .map(|channel| {
                let product = channel
                    .properties
                    .get("product")
                    .cloned()
                    .unwrap_or_default();
                let name = channel
                    .properties
                    .get("channel")
                    .cloned()
                    .unwrap_or_default();
                format!("{product}/{name}")
            })
            .collect();
        matched_channels.sort();
        let mut matched_environments = Vec::new();
        for environment in &environments {
            let deployed = environment
                .properties
                .get(&format!("deployed_release.{product}"))
                .map(String::as_str);
            if deployed != Some(release.id.as_str()) {
                continue;
            }
            matched_environments.push(EnvironmentExposure {
                environment: environment.name.clone(),
                deployed_release: spec.clone(),
                freshness: environment_freshness(environment),
            });
        }
        matched_environments.sort_by(|left, right| left.environment.cmp(&right.environment));
        matches.push(ReleaseExposure {
            release: spec,
            product,
            version,
            release_id: release.id,
            component: hit.name.clone(),
            component_version: hit.version.clone(),
            channels: matched_channels,
            environments: matched_environments,
        });
    }
    matches.sort_by(|left, right| left.release_id.cmp(&right.release_id));
    Ok(ExposureQueryResult {
        component: component.into(),
        range: range.into(),
        matches,
    })
}

/// Parse a `tenkai.advisory-feed.v1` document. Used by bundle build and import.
pub fn parse_advisory_feed(bytes: &[u8]) -> Result<AdvisoryFeed> {
    let feed: AdvisoryFeed = serde_json::from_slice(bytes).context("advisory feed is not JSON")?;
    if feed.schema != ADVISORY_FEED_SCHEMA {
        bail!("advisory feed schema is not {ADVISORY_FEED_SCHEMA}");
    }
    for advisory in &feed.advisories {
        if advisory.id.trim().is_empty() || advisory.component.trim().is_empty() {
            bail!("advisory id and component are required");
        }
        semver::VersionReq::parse(&advisory.range)
            .with_context(|| format!("advisory {} has an invalid range", advisory.id))?;
    }
    Ok(feed)
}

/// Admit a verified advisory feed. Each `generated_at` is an immutable
/// object; reads take the highest generation, so an older import cannot
/// replace a newer one. The preferred generation is also written to
/// `tenkai:advisory-feed` so mixed-version readers still see it.
pub async fn import_advisory_feed(
    ctx: &mut Ctx,
    mut feed: AdvisoryFeed,
    imported_at: i64,
) -> Result<()> {
    if feed.schema.is_empty() {
        feed.schema = ADVISORY_FEED_SCHEMA.into();
    }
    let feed = parse_advisory_feed(&serde_json::to_vec(&feed)?)?;
    let now = crate::now_millis();
    let id = feed_object_id(feed.generated_at);
    match ctx
        .create_once(advisory_feed_object(id.clone(), &feed, imported_at, now)?)
        .await
    {
        Ok(_) => {}
        Err(crate::client::ClientError::UniqueConflict) => {
            let existing = ctx
                .get(&id)
                .await?
                .context("advisory feed generation conflicted but is missing")?;
            let document = existing
                .properties
                .get("document")
                .context("advisory feed is missing its document")?;
            let stored = parse_advisory_feed(document.as_bytes())?;
            if stored != feed {
                bail!(
                    "advisory feed generation {} already exists with different content",
                    feed.generated_at
                );
            }
        }
        Err(error) => return Err(error.into()),
    }
    publish_legacy_feed_alias(ctx).await
}

/// Apply bundled revocations, then verify. Same order as bind and first-install.
pub fn verify_envelope_for_import(
    envelope: &crate::offline_bundle::BundleEnvelope,
    roots: &crate::release_signing::TrustRoots,
    env: &str,
    now: i64,
) -> Result<crate::offline_bundle::VerifiedBundle> {
    crate::key_revocation::import_from_bundle(envelope)?;
    envelope.verify(roots, NS, env, now)
}

/// Parse `advisories/feed.json` when present, before any catalog mutation.
pub fn preflight_verified_bundle(verified: &crate::offline_bundle::VerifiedBundle) -> Result<()> {
    let Some(bytes) = verified.entry(ADVISORY_FEED_PATH) else {
        return Ok(());
    };
    let feed = parse_advisory_feed(bytes)?;
    refuse_generated_after_issued(feed.generated_at, verified.statement().issued_at_unix_ms)
}

/// A feed clock after the signed bundle issued-at cannot become the preferred generation.
pub fn refuse_generated_after_issued(generated_at: i64, issued_at: i64) -> Result<()> {
    if generated_at > 0 && generated_at > issued_at {
        bail!("advisory feed generated_at {generated_at} is after bundle issued_at {issued_at}");
    }
    Ok(())
}

/// Import `advisories/feed.json` from a verified bundle. Missing is a no-op.
pub async fn import_from_verified_bundle(
    ctx: &mut Ctx,
    verified: &crate::offline_bundle::VerifiedBundle,
) -> Result<Option<AdvisoryFeedStatus>> {
    let Some(bytes) = verified.entry(ADVISORY_FEED_PATH) else {
        return Ok(None);
    };
    let mut feed = parse_advisory_feed(bytes)?;
    let issued_at = verified.statement().issued_at_unix_ms;
    refuse_generated_after_issued(feed.generated_at, issued_at)?;
    if feed.generated_at <= 0 {
        feed.generated_at = issued_at;
    }
    import_advisory_feed(ctx, feed, crate::now_millis()).await?;
    Ok(Some(inspect(ctx).await?))
}

/// Show the imported feed age and the releases it currently flags.
pub async fn inspect(ctx: &mut Ctx) -> Result<AdvisoryFeedStatus> {
    let Some((feed, imported_at)) = load_advisory_feed(ctx).await? else {
        return Ok(AdvisoryFeedStatus {
            imported: false,
            imported_at: 0,
            generated_at: 0,
            age_ms: 0,
            advisory_count: 0,
            matches: Vec::new(),
        });
    };
    let generated_at = feed_clock(&feed, imported_at);
    let now = crate::now_millis();
    Ok(AdvisoryFeedStatus {
        imported: true,
        imported_at,
        generated_at,
        age_ms: now.saturating_sub(generated_at),
        advisory_count: feed.advisories.len(),
        matches: match_advisories(ctx).await?,
    })
}

/// Match the imported advisory feed against stored inventories. No network.
pub async fn match_advisories(ctx: &mut Ctx) -> Result<Vec<MatchedExposure>> {
    let Some((feed, _)) = load_advisory_feed(ctx).await? else {
        return Ok(Vec::new());
    };
    let mut matched = Vec::new();
    for release in ctx.list_kind(KIND_RELEASE).await? {
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
            for component in &inventory.components {
                if component.name == advisory.component
                    && version_in_range(&component.version, &advisory.range)?
                {
                    matched.push(MatchedExposure {
                        advisory_id: advisory.id.clone(),
                        severity: advisory.severity,
                        component: component.name.clone(),
                        component_version: component.version.clone(),
                        release: spec.clone(),
                        release_id: release.id.clone(),
                    });
                }
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

/// Enqueue matched exposures on the optional integration outbox.
///
/// Planning and apply never call this. With export off, they are unchanged.
pub fn export_exposures(
    store: &impl ProviderEventStore,
    matches: &[MatchedExposure],
    now: i64,
) -> Result<()> {
    for matched in matches {
        let payload = serde_json::to_string(matched)?;
        let payload_digest = digest_bytes(payload.as_bytes());
        let binding = EvidenceBinding {
            contract_version: PROVIDER_CONTRACT_VERSION,
            release_digest: matched.release_id.clone(),
            plan_digest: payload_digest.clone(),
            configuration_digest: payload_digest,
            environment_id: "catalog".into(),
        };
        let event = ProviderEvent {
            id: format!(
                "exposure:{}:{}:{}:{}",
                matched.advisory_id,
                matched.release_id,
                matched.component,
                matched.component_version
            ),
            binding,
            payload_json: payload,
            collected_at_ms: None,
            source_sequence: None,
        };
        enqueue_optional_event(store, EXPOSURE_PROVIDER_KIND, &event, now)
            .map_err(anyhow::Error::from)?;
    }
    Ok(())
}

/// Plan-start gate: stale advisory feed or unmitigated severity on a target.
///
/// Returns a named reason (`exposure_feed_stale` / `exposure_unmitigated`)
/// when the environment has configured the corresponding policy property.
pub async fn plan_gate(ctx: &mut Ctx, environment: &str, steps: &[Step]) -> Result<Option<String>> {
    if steps
        .iter()
        .all(|step| step.action == crate::plan::Action::Rollback)
    {
        return Ok(None);
    }
    let env = crate::environment::environment(ctx, environment).await?;
    if let Some(detail) = stale_feed_reason(&env, ctx).await? {
        return Ok(Some(detail));
    }
    let Some(threshold) = env.properties.get(BLOCK_SEVERITY_PROPERTY) else {
        return Ok(None);
    };
    let threshold = match Severity::parse(threshold) {
        Ok(severity) => severity,
        Err(error) => {
            return Ok(Some(format!(
                "exposure_unmitigated: environment policy {BLOCK_SEVERITY_PROPERTY} is invalid: {error}"
            )));
        }
    };
    if load_advisory_feed(ctx).await?.is_none() {
        return Ok(Some(
            "exposure_unmitigated: no advisory feed has been imported".into(),
        ));
    }
    let matched = match_advisories(ctx).await?;
    for step in steps {
        if step.action == crate::plan::Action::Rollback {
            continue;
        }
        if let Some(hit) = matched
            .iter()
            .filter(|entry| entry.release_id == step.release_id && entry.severity >= threshold)
            .min_by(|left, right| left.advisory_id.cmp(&right.advisory_id))
        {
            return Ok(Some(format!(
                "exposure_unmitigated: {} {} on {} matches {} ({})",
                hit.component,
                hit.component_version,
                hit.release,
                hit.advisory_id,
                hit.severity.as_str()
            )));
        }
    }
    Ok(None)
}

/// Stamp last-bundle-import freshness. Same get-then-put as other Environment
/// property writes (`set_environment_fact`, connectivity class).
pub async fn record_bundle_import(
    ctx: &mut Ctx,
    environment: &str,
    imported_at: i64,
) -> Result<()> {
    let mut object = crate::environment::environment(ctx, environment).await?;
    object.properties.insert(
        LAST_BUNDLE_IMPORT_AT_PROPERTY.into(),
        imported_at.to_string(),
    );
    object.updated = imported_at;
    ctx.put(object).await?;
    Ok(())
}

struct LoadedInventory {
    schema: String,
    digest: String,
    bytes: Vec<u8>,
}

fn load_inventory_file(workdir: &Path, relative: &str) -> Result<LoadedInventory> {
    manifest::validate_input_path("inventory.document", relative)?;
    let path = workdir.join(relative);
    let bytes =
        std::fs::read(&path).with_context(|| format!("reading inventory {}", path.display()))?;
    let digest = digest_bytes(&bytes);
    let parsed = parse_inventory_bytes(&bytes)?;
    Ok(LoadedInventory {
        schema: parsed.schema,
        digest,
        bytes,
    })
}

fn parse_inventory_bytes(bytes: &[u8]) -> Result<ComponentInventory> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("inventory document is not JSON")?;
    parse_inventory_value(&value, digest_bytes(bytes))
}

fn parse_inventory_value(value: &serde_json::Value, digest: String) -> Result<ComponentInventory> {
    if value.get("schema").and_then(|value| value.as_str()) == Some(INVENTORY_SCHEMA) {
        let components = value
            .get("components")
            .and_then(|value| value.as_array())
            .context("tenkai component inventory needs a components array")?;
        return Ok(ComponentInventory {
            schema: INVENTORY_SCHEMA.into(),
            digest,
            components: parse_components(components)?,
        });
    }
    if value.get("bomFormat").and_then(|value| value.as_str()) == Some("CycloneDX") {
        let components = value
            .get("components")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        return Ok(ComponentInventory {
            schema: "CycloneDX".into(),
            digest,
            components: parse_components(&components)?,
        });
    }
    bail!("inventory document must be {INVENTORY_SCHEMA} or CycloneDX JSON");
}

fn parse_components(values: &[serde_json::Value]) -> Result<Vec<InventoryComponent>> {
    let mut components = Vec::new();
    collect_components(values, &mut components);
    if components.is_empty() {
        bail!("inventory document lists no named components with versions");
    }
    components.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });
    components.dedup();
    Ok(components)
}

fn collect_components(values: &[serde_json::Value], components: &mut Vec<InventoryComponent>) {
    for value in values {
        if let Some(component) = component_from_value(value) {
            components.push(component);
        }
        if let Some(nested) = value.get("components").and_then(|value| value.as_array()) {
            collect_components(nested, components);
        }
    }
}

fn component_from_value(value: &serde_json::Value) -> Option<InventoryComponent> {
    let name = value
        .get("name")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    let version = value
        .get("version")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    match (
        name,
        version,
        value.get("purl").and_then(|value| value.as_str()),
    ) {
        (Some(name), Some(version), _) => Some(InventoryComponent {
            name: name.into(),
            version: version.into(),
        }),
        (_, _, Some(purl)) => {
            let (name, version) = parse_purl(purl)?;
            Some(InventoryComponent { name, version })
        }
        _ => None,
    }
}

fn parse_purl(purl: &str) -> Option<(String, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (path, version) = rest.split_once('@')?;
    let name = path.rsplit('/').next()?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.into(), version.into()))
}

fn stored_inventory(release: &Object) -> Result<Option<ComponentInventory>> {
    let Some(document) = release.properties.get(INVENTORY_DOCUMENT_PROPERTY) else {
        return Ok(None);
    };
    let digest = release
        .properties
        .get(INVENTORY_DIGEST_PROPERTY)
        .cloned()
        .unwrap_or_default();
    if digest != digest_bytes(document.as_bytes()) {
        bail!(
            "release {} stored inventory does not match its recorded digest",
            release.id
        );
    }
    let parsed = parse_inventory_bytes(document.as_bytes())?;
    if parsed.digest != digest {
        bail!(
            "release {} stored inventory does not match its recorded digest",
            release.id
        );
    }
    Ok(Some(parsed))
}

fn environment_freshness(environment: &Object) -> Freshness {
    let class = environment
        .properties
        .get(CONNECTIVITY_CLASS_PROPERTY)
        .map(String::as_str)
        .unwrap_or("connected");
    match class {
        "isolated" | "intermittent" => environment
            .properties
            .get(LAST_BUNDLE_IMPORT_AT_PROPERTY)
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .map(|imported_at| Freshness::AsOfLastBundleImport { imported_at })
            .unwrap_or(Freshness::Unknown),
        _ => Freshness::Hub,
    }
}

fn version_in_range(version: &str, range: &str) -> Result<bool> {
    let req = semver::VersionReq::parse(range)
        .with_context(|| format!("invalid version range {range:?}"))?;
    match semver::Version::parse(version) {
        Ok(parsed) => Ok(req.matches(&parsed)),
        // Inventories admit non-SemVer strings (`1.1.1k`). Query and gates
        // cannot prove those are outside a range, so they match.
        Err(_) => Ok(true),
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn feed_object_id(generated_at: i64) -> String {
    format!("{FEED_ID}:{generated_at}")
}

fn advisory_feed_object(
    id: String,
    feed: &AdvisoryFeed,
    imported_at: i64,
    now: i64,
) -> Result<Object> {
    let document = serde_json::to_string(feed)?;
    let mut properties = HashMap::from([
        ("document".into(), document),
        ("imported_at".into(), imported_at.to_string()),
        ("generated_at".into(), feed.generated_at.to_string()),
    ]);
    properties.insert(
        "digest".into(),
        digest_bytes(properties["document"].as_bytes()),
    );
    Ok(Object {
        id,
        kind: KIND_ADVISORY_FEED.into(),
        name: "advisory-feed".into(),
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now,
        updated: now,
    })
}

/// Previous readers load only `tenkai:advisory-feed`. Publish the preferred
/// generation there under a lease so a stale writer cannot overwrite a newer
/// alias after another import has already returned.
async fn publish_legacy_feed_alias(ctx: &mut Ctx) -> Result<()> {
    const ATTEMPTS: usize = 8;
    let owner = format!(
        "advisory-feed:{}:{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    for _ in 0..ATTEMPTS {
        let lease = match ctx
            .acquire_lease(
                ALIAS_LEASE_NAMESPACE,
                ALIAS_LEASE_KEY,
                &owner,
                ALIAS_LEASE_TTL_MS,
            )
            .await
        {
            Ok(lease) => lease,
            Err(crate::client::LeaseError::AlreadyExists) => {
                tokio::task::yield_now().await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let result = publish_fenced_alias(ctx, &lease.fencing_token).await;
        let released = ctx
            .release_lease(ALIAS_LEASE_NAMESPACE, ALIAS_LEASE_KEY, &lease.fencing_token)
            .await;
        match (result, released) {
            (Ok(()), Ok(_)) => return Ok(()),
            (Err(error), Ok(_)) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Err(error), Err(release)) => return Err(error.context(release)),
        }
    }
    bail!("advisory feed alias lease is held")
}

async fn publish_fenced_alias(ctx: &mut Ctx, fencing_token: &str) -> Result<()> {
    let Some((feed, imported_at)) = preferred_generation_feed(ctx).await? else {
        return Ok(());
    };
    write_legacy_alias_if_newer(ctx, &feed, imported_at, fencing_token).await
}

/// Write the alias only for the preferred generation. A stale writer that
/// selected an older feed cannot replace a newer alias, and a later import
/// can still repair an alias that raced ahead of the preferred generation.
async fn write_legacy_alias_if_newer(
    ctx: &mut Ctx,
    feed: &AdvisoryFeed,
    imported_at: i64,
    fencing_token: &str,
) -> Result<()> {
    let Some((preferred, _)) = preferred_generation_feed(ctx).await? else {
        return Ok(());
    };
    if feed.generated_at != preferred.generated_at {
        return Ok(());
    }
    if alias_matches(ctx, feed).await? {
        return Ok(());
    }
    let object = advisory_feed_object(FEED_ID.into(), feed, imported_at, crate::now_millis())?;
    if ctx.get(FEED_ID).await?.is_some() {
        ctx.guarded_update(
            object,
            ALIAS_LEASE_NAMESPACE,
            ALIAS_LEASE_KEY,
            fencing_token,
        )
        .await?;
    } else {
        ctx.guarded_create(
            object,
            ALIAS_LEASE_NAMESPACE,
            ALIAS_LEASE_KEY,
            fencing_token,
        )
        .await?;
    }
    Ok(())
}

async fn alias_matches(ctx: &mut Ctx, feed: &AdvisoryFeed) -> Result<bool> {
    match ctx.get(FEED_ID).await? {
        None => Ok(false),
        Some(existing) if existing.kind != KIND_ADVISORY_FEED => {
            bail!("advisory feed id {FEED_ID} exists with a different kind");
        }
        Some(existing) => {
            let Some(document) = existing.properties.get("document") else {
                return Ok(false);
            };
            match parse_advisory_feed(document.as_bytes()) {
                Ok(stored) => Ok(&stored == feed),
                Err(_) => Ok(false),
            }
        }
    }
}

async fn load_advisory_feed(ctx: &mut Ctx) -> Result<Option<(AdvisoryFeed, i64)>> {
    if let Some(feed) = preferred_generation_feed(ctx).await? {
        return Ok(Some(feed));
    }
    load_feed_object(ctx, FEED_ID).await
}

async fn preferred_generation_feed(ctx: &mut Ctx) -> Result<Option<(AdvisoryFeed, i64)>> {
    let mut best: Option<(AdvisoryFeed, i64)> = None;
    for object in ctx.list_kind(KIND_ADVISORY_FEED).await? {
        if object.kind != KIND_ADVISORY_FEED || object.id == FEED_ID {
            continue;
        }
        let parsed = parsed_feed_object(&object)?;
        let take = match &best {
            Some((current, _)) => parsed.0.generated_at > current.generated_at,
            None => true,
        };
        if take {
            best = Some(parsed);
        }
    }
    Ok(best)
}

async fn load_feed_object(ctx: &mut Ctx, id: &str) -> Result<Option<(AdvisoryFeed, i64)>> {
    let Some(object) = ctx.get(id).await? else {
        return Ok(None);
    };
    if object.kind != KIND_ADVISORY_FEED {
        return Ok(None);
    }
    Ok(Some(parsed_feed_object(&object)?))
}

fn parsed_feed_object(object: &Object) -> Result<(AdvisoryFeed, i64)> {
    let document = object
        .properties
        .get("document")
        .context("advisory feed is missing its document")?;
    let feed = parse_advisory_feed(document.as_bytes())?;
    let imported_at = object
        .properties
        .get("imported_at")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    Ok((feed, imported_at))
}

fn feed_clock(feed: &AdvisoryFeed, imported_at: i64) -> i64 {
    if feed.generated_at > 0 {
        feed.generated_at
    } else {
        imported_at
    }
}

async fn stale_feed_reason(env: &Object, ctx: &mut Ctx) -> Result<Option<String>> {
    let Some(max_age) = env.properties.get(MAX_FEED_AGE_PROPERTY) else {
        return Ok(None);
    };
    let max_age = match max_age.parse::<i64>() {
        Ok(value) if value > 0 => value,
        _ => {
            return Ok(Some(format!(
                "exposure_feed_stale: environment policy {MAX_FEED_AGE_PROPERTY} is invalid"
            )));
        }
    };
    let clock = match load_advisory_feed(ctx).await? {
        Some((feed, imported_at)) => {
            let clock = feed_clock(&feed, imported_at);
            if clock > 0 {
                clock
            } else {
                return Ok(Some(
                    "exposure_feed_stale: no advisory feed has been imported".into(),
                ));
            }
        }
        _ => {
            return Ok(Some(
                "exposure_feed_stale: no advisory feed has been imported".into(),
            ));
        }
    };
    let now = crate::now_millis();
    if now.saturating_sub(clock) > max_age {
        return Ok(Some(format!(
            "exposure_feed_stale: advisory feed generated_at {clock} is older than {max_age} ms"
        )));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;
    use crate::ontology::release_id;

    fn native_inventory(name: &str, version: &str) -> String {
        serde_json::json!({
            "schema": INVENTORY_SCHEMA,
            "components": [{"name": name, "version": version}]
        })
        .to_string()
    }

    fn cyclonedx_inventory(name: &str, version: &str) -> String {
        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{
                "type": "library",
                "name": name,
                "version": version
            }]
        })
        .to_string()
    }

    fn write_product(root: &Path, version: &str, inventory: &str) -> std::path::PathBuf {
        let product = root.join("product");
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(product.join("sbom.json"), inventory).unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "api"
version = "{version}"

[deploy]
install = "true"

[inventory]
document = "sbom.json"
"#
            ),
        )
        .unwrap();
        product
    }

    async fn signed_publish(ctx: &mut Ctx, root: &Path, version: &str, inventory: &str) {
        let product = write_product(root, version, inventory);
        let keys = root.join("keys");
        let signature = root.join("signature.json");
        let trust = root.join("trust-roots.toml");
        crate::dev_sign::sign_release(&keys, &product.join("tenkai.toml"), &signature, &trust)
            .unwrap();
        crate::catalog::publish(
            ctx,
            &product.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn parse_advisory_feed_allows_an_empty_list() {
        let empty = parse_advisory_feed(
            serde_json::json!({
                "schema": ADVISORY_FEED_SCHEMA,
                "generated_at": 1,
                "advisories": []
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        assert!(empty.advisories.is_empty());
        let err = parse_advisory_feed(br#"{"schema":"nope","advisories":[]}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("advisory feed schema"), "{err}");
    }

    #[test]
    fn parses_native_and_cyclonedx_inventories() {
        let native =
            parse_inventory_bytes(native_inventory("openssl", "1.1.1").as_bytes()).unwrap();
        assert_eq!(native.schema, INVENTORY_SCHEMA);
        assert_eq!(native.components[0].name, "openssl");
        let cdx =
            parse_inventory_bytes(cyclonedx_inventory("openssl", "1.1.1").as_bytes()).unwrap();
        assert_eq!(cdx.schema, "CycloneDX");
        assert_eq!(cdx.components[0].version, "1.1.1");
        let purl = parse_inventory_bytes(
            serde_json::json!({
                "schema": INVENTORY_SCHEMA,
                "components": [{"purl": "pkg:generic/openssl@1.1.1"}]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(purl.components[0].name, "openssl");
        assert!(version_in_range("1.1.1", ">=1.0.0,<1.2.0").unwrap());
        assert!(!version_in_range("1.3.0", ">=1.0.0,<1.2.0").unwrap());
        assert!(version_in_range("1.1.1k", ">=1.0.0").unwrap());
        assert!(version_in_range("1.1.1k", ">=9.0.0").unwrap());
        let nested = parse_inventory_bytes(
            serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{
                    "type": "library",
                    "name": "api",
                    "version": "1.0.0",
                    "components": [{
                        "type": "library",
                        "name": "openssl",
                        "version": "1.1.1"
                    }]
                }]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            nested.components,
            vec![
                InventoryComponent {
                    name: "api".into(),
                    version: "1.0.0".into()
                },
                InventoryComponent {
                    name: "openssl".into(),
                    version: "1.1.1".into()
                }
            ]
        );
    }

    #[tokio::test]
    async fn unsigned_inventory_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-unsigned-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let product = write_product(&root, "1.0.0", &native_inventory("openssl", "1.1.1"));
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let error = crate::catalog::publish(
            &mut ctx,
            &product.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                state_dir: Some(root.join("state")),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("unsigned inventory"), "{error}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn query_lists_hub_and_isolated_spoke_freshness() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-query-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &cyclonedx_inventory("openssl", "1.1.1"),
        )
        .await;
        let actor = crate::auth_context::test_management_context("exposure-query");
        crate::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "hub", "connected hub")
            .await
            .unwrap();
        crate::environment::env_add(&mut ctx, "spoke", "isolated spoke")
            .await
            .unwrap();
        crate::connectivity::set_connectivity_class(
            &mut ctx,
            "hub",
            crate::connectivity::ConnectivityClass::Connected,
        )
        .await
        .unwrap();
        crate::connectivity::set_connectivity_class(
            &mut ctx,
            "spoke",
            crate::connectivity::ConnectivityClass::Isolated,
        )
        .await
        .unwrap();
        let imported_at = 1_700_000_000_000;
        record_bundle_import(&mut ctx, "spoke", imported_at)
            .await
            .unwrap();
        for name in ["hub", "spoke"] {
            let mut env = crate::environment::environment(&mut ctx, name)
                .await
                .unwrap();
            env.properties.insert("deployed.api".into(), "1.0.0".into());
            env.properties
                .insert("deployed_release.api".into(), release_id("api", "1.0.0"));
            ctx.put(env).await.unwrap();
        }
        let rid = release_id("api", "1.0.0");
        let stored = ctx.get(&rid).await.unwrap().unwrap();
        if let Some(snapshot) = stored.properties.get("workdir") {
            let _ = std::fs::remove_dir_all(snapshot);
        }
        let result = query(&mut ctx, "openssl", ">=1.0.0,<1.2.0").await.unwrap();
        assert_eq!(result.matches.len(), 1);
        let hit = &result.matches[0];
        assert_eq!(hit.release, "api@1.0.0");
        assert_eq!(hit.component_version, "1.1.1");
        assert_eq!(hit.channels, vec!["api/stable".to_string()]);
        assert_eq!(hit.environments.len(), 2);
        assert_eq!(hit.environments[0].environment, "hub");
        assert_eq!(hit.environments[0].freshness, Freshness::Hub);
        assert_eq!(hit.environments[1].environment, "spoke");
        assert_eq!(
            hit.environments[1].freshness,
            Freshness::AsOfLastBundleImport { imported_at }
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn mismatched_inventory_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-mismatch-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        let rid = release_id("api", "1.0.0");
        let mut release = ctx.get(&rid).await.unwrap().unwrap();
        release.properties.insert(
            INVENTORY_DOCUMENT_PROPERTY.into(),
            native_inventory("openssl", "9.9.9"),
        );
        ctx.put(release).await.unwrap();
        let error = query(&mut ctx, "openssl", ">=1.0.0")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not match its recorded digest"),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn advisory_matching_and_gates_are_local() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-gates-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        crate::environment::env_add(&mut ctx, "hub", "hub")
            .await
            .unwrap();
        let step = Step {
            id: String::new(),
            order: 0,
            product: "api".into(),
            action: crate::plan::Action::Upgrade,
            from: None,
            to: "1.0.0".into(),
            release_id: release_id("api", "1.0.0"),
            release_digest: "fixture".into(),
            artifact_digest: "fixture".into(),
            workdir: ".".into(),
            restore: None,
        };
        let mut env = crate::environment::environment(&mut ctx, "hub")
            .await
            .unwrap();
        env.properties
            .insert(BLOCK_SEVERITY_PROPERTY.into(), "high".into());
        ctx.put(env).await.unwrap();
        let missing = plan_gate(&mut ctx, "hub", std::slice::from_ref(&step))
            .await
            .unwrap()
            .expect("missing feed");
        assert!(
            missing.starts_with("exposure_unmitigated:") && missing.contains("no advisory feed"),
            "{missing}"
        );
        let mut env = crate::environment::environment(&mut ctx, "hub")
            .await
            .unwrap();
        env.properties.remove(BLOCK_SEVERITY_PROPERTY);
        ctx.put(env).await.unwrap();
        import_advisory_feed(
            &mut ctx,
            feed_document(vec![matched_advisory()], 0),
            crate::now_millis(),
        )
        .await
        .unwrap();
        let matched = match_advisories(&mut ctx).await.unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].advisory_id, "TENKAI-2026-1");
        assert_eq!(
            plan_gate(&mut ctx, "hub", std::slice::from_ref(&step))
                .await
                .unwrap(),
            None
        );
        let mut env = crate::environment::environment(&mut ctx, "hub")
            .await
            .unwrap();
        env.properties
            .insert(BLOCK_SEVERITY_PROPERTY.into(), "high".into());
        ctx.put(env).await.unwrap();
        let blocked = plan_gate(&mut ctx, "hub", std::slice::from_ref(&step))
            .await
            .unwrap()
            .expect("severity gate");
        assert!(blocked.starts_with("exposure_unmitigated:"), "{blocked}");
        let mut env = crate::environment::environment(&mut ctx, "hub")
            .await
            .unwrap();
        env.properties.remove(BLOCK_SEVERITY_PROPERTY);
        env.properties
            .insert(MAX_FEED_AGE_PROPERTY.into(), "1".into());
        ctx.put(env).await.unwrap();
        import_advisory_feed(&mut ctx, feed_document(vec![matched_advisory()], 1), 1)
            .await
            .unwrap();
        let stale = plan_gate(&mut ctx, "hub", std::slice::from_ref(&step))
            .await
            .unwrap()
            .expect("stale feed");
        assert!(stale.starts_with("exposure_feed_stale:"), "{stale}");
        let mut rollback = step;
        rollback.action = crate::plan::Action::Rollback;
        assert_eq!(
            plan_gate(&mut ctx, "hub", std::slice::from_ref(&rollback))
                .await
                .unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn matched_advisory() -> Advisory {
        Advisory {
            id: "TENKAI-2026-1".into(),
            component: "openssl".into(),
            range: ">=1.0.0,<1.2.0".into(),
            severity: Severity::High,
            issued_at: 1,
        }
    }

    fn feed_document(advisories: Vec<Advisory>, generated_at: i64) -> AdvisoryFeed {
        AdvisoryFeed {
            schema: ADVISORY_FEED_SCHEMA.into(),
            generated_at,
            advisories,
        }
    }

    #[tokio::test]
    async fn outbox_export_off_leaves_planning_unchanged() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-outbox-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        crate::environment::env_add(&mut ctx, "hub", "hub")
            .await
            .unwrap();
        import_advisory_feed(
            &mut ctx,
            feed_document(vec![matched_advisory()], 0),
            crate::now_millis(),
        )
        .await
        .unwrap();
        let step = Step {
            id: String::new(),
            order: 0,
            product: "api".into(),
            action: crate::plan::Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: release_id("api", "1.0.0"),
            release_digest: "fixture".into(),
            artifact_digest: "fixture".into(),
            workdir: ".".into(),
            restore: None,
        };
        assert_eq!(plan_gate(&mut ctx, "hub", &[step]).await.unwrap(), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn signed_bundle_feed_flags_a_vulnerable_release_offline() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-bundle-feed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        signed_publish(
            &mut ctx,
            &root,
            "1.0.0",
            &native_inventory("openssl", "1.1.1"),
        )
        .await;
        crate::environment::env_add(&mut ctx, "spoke", "isolated spoke")
            .await
            .unwrap();
        let generated_at = 1_700_000_000_000;
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let feed = feed_document(vec![matched_advisory()], generated_at);
        let verified = signed_feed_bundle(&key, &feed);
        let status = import_from_verified_bundle(&mut ctx, &verified)
            .await
            .unwrap()
            .expect("feed imported");
        assert!(status.imported);
        assert_eq!(status.generated_at, generated_at);
        assert_eq!(status.advisory_count, 1);
        assert_eq!(status.matches.len(), 1);
        assert_eq!(status.matches[0].advisory_id, "TENKAI-2026-1");
        assert_eq!(status.matches[0].release, "api@1.0.0");
        let inspected = inspect(&mut ctx).await.unwrap();
        assert!(inspected.age_ms > 0);
        assert_eq!(inspected.generated_at, generated_at);

        let mut env = crate::environment::environment(&mut ctx, "spoke")
            .await
            .unwrap();
        env.properties
            .insert(MAX_FEED_AGE_PROPERTY.into(), "1".into());
        ctx.put(env).await.unwrap();
        let step = Step {
            id: String::new(),
            order: 0,
            product: "api".into(),
            action: crate::plan::Action::Upgrade,
            from: None,
            to: "1.0.0".into(),
            release_id: release_id("api", "1.0.0"),
            release_digest: "fixture".into(),
            artifact_digest: "fixture".into(),
            workdir: ".".into(),
            restore: None,
        };
        let stale = plan_gate(&mut ctx, "spoke", std::slice::from_ref(&step))
            .await
            .unwrap()
            .expect("stale feed");
        assert!(stale.starts_with("exposure_feed_stale:"), "{stale}");
        assert!(stale.contains("generated_at"), "{stale}");

        let mut tampered = signed_feed_envelope(&key, &feed, statement_issued_at(&feed));
        tampered.entries[0].content_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"{}");
        let error = tampered
            .verify(
                &exporter_roots(&key),
                crate::ontology::NS,
                "spoke",
                generated_at + 1,
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not match its signed digest") || error.contains("digest"),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn missing_generated_at_uses_bundle_issued_at() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-feed-clock-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
        let feed = feed_document(vec![matched_advisory()], 0);
        let verified = signed_feed_bundle(&key, &feed);
        let status = import_from_verified_bundle(&mut ctx, &verified)
            .await
            .unwrap()
            .expect("feed imported");
        assert_eq!(status.generated_at, verified.statement().issued_at_unix_ms);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn empty_feed_imports_and_older_generation_is_kept() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-feed-generation-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let empty = import_from_verified_bundle(
            &mut ctx,
            &signed_feed_bundle(&key, &feed_document(Vec::new(), 1_000)),
        )
        .await
        .unwrap()
        .expect("empty feed");
        assert!(empty.imported);
        assert_eq!(empty.advisory_count, 0);
        let newer = import_from_verified_bundle(
            &mut ctx,
            &signed_feed_bundle(&key, &feed_document(vec![matched_advisory()], 2_000)),
        )
        .await
        .unwrap()
        .expect("newer feed");
        assert_eq!(newer.generated_at, 2_000);
        assert_eq!(newer.advisory_count, 1);
        let older = import_from_verified_bundle(
            &mut ctx,
            &signed_feed_bundle(&key, &feed_document(Vec::new(), 1_500)),
        )
        .await
        .unwrap()
        .expect("older skipped");
        assert_eq!(older.generated_at, 2_000);
        assert_eq!(older.advisory_count, 1);
        let conflict = import_advisory_feed(
            &mut ctx,
            feed_document(
                vec![Advisory {
                    id: "TENKAI-2026-2".into(),
                    component: "openssl".into(),
                    range: ">=1.0.0".into(),
                    severity: Severity::Low,
                    issued_at: 1,
                }],
                2_000,
            ),
            3,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(conflict.contains("different content"), "{conflict}");
        let future = feed_document(vec![matched_advisory()], 2_000);
        let future_bundle = signed_feed_envelope(&key, &future, 1_000)
            .verify(&exporter_roots(&key), crate::ontology::NS, "spoke", 1_001)
            .unwrap();
        let preflight_err = preflight_verified_bundle(&future_bundle)
            .unwrap_err()
            .to_string();
        assert!(
            preflight_err.contains("after bundle issued_at"),
            "{preflight_err}"
        );
        let future_err = import_from_verified_bundle(&mut ctx, &future_bundle)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            future_err.contains("after bundle issued_at"),
            "{future_err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn import_keeps_legacy_feed_id_current() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-legacy-feed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let mut properties = HashMap::from([
            (
                "document".into(),
                serde_json::json!({
                    "schema": ADVISORY_FEED_SCHEMA,
                    "advisories": []
                })
                .to_string(),
            ),
            ("imported_at".into(), "1".into()),
        ]);
        properties.insert(
            "digest".into(),
            digest_bytes(properties["document"].as_bytes()),
        );
        ctx.put(Object {
            id: FEED_ID.into(),
            kind: KIND_ADVISORY_FEED.into(),
            name: "advisory-feed".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties,
            created: 1,
            updated: 1,
        })
        .await
        .unwrap();
        import_advisory_feed(&mut ctx, feed_document(vec![matched_advisory()], 2_000), 2)
            .await
            .unwrap();
        let alias = parse_advisory_feed(
            ctx.get(FEED_ID)
                .await
                .unwrap()
                .expect("legacy id")
                .properties["document"]
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(alias.generated_at, 2_000);
        assert_eq!(alias.advisories.len(), 1);
        ctx.put(
            advisory_feed_object(FEED_ID.into(), &feed_document(Vec::new(), 9_999), 9, 9).unwrap(),
        )
        .await
        .unwrap();
        let status = inspect(&mut ctx).await.unwrap();
        assert_eq!(status.generated_at, 2_000);
        assert_eq!(status.advisory_count, 1);
        import_advisory_feed(&mut ctx, feed_document(Vec::new(), 1_500), 3)
            .await
            .unwrap();
        let alias = parse_advisory_feed(
            ctx.get(FEED_ID)
                .await
                .unwrap()
                .expect("legacy id")
                .properties["document"]
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(alias.generated_at, 2_000);
        assert_eq!(alias.advisories.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn older_writer_cannot_overwrite_a_newer_alias() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exposure-alias-fence-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("state.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        import_advisory_feed(&mut ctx, feed_document(vec![matched_advisory()], 2_000), 2)
            .await
            .unwrap();
        let lease = ctx
            .acquire_lease(
                ALIAS_LEASE_NAMESPACE,
                ALIAS_LEASE_KEY,
                "stale-writer",
                ALIAS_LEASE_TTL_MS,
            )
            .await
            .unwrap();
        write_legacy_alias_if_newer(
            &mut ctx,
            &feed_document(Vec::new(), 100),
            1,
            &lease.fencing_token,
        )
        .await
        .unwrap();
        let alias = parse_advisory_feed(
            ctx.get(FEED_ID)
                .await
                .unwrap()
                .expect("legacy id")
                .properties["document"]
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(alias.generated_at, 2_000);
        assert_eq!(alias.advisories.len(), 1);
        ctx.release_lease(ALIAS_LEASE_NAMESPACE, ALIAS_LEASE_KEY, &lease.fencing_token)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn feed_import_applies_bundled_revocations_before_verify() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[211u8; 32]);
        let feed = feed_document(Vec::new(), 1_000);
        let envelope = signed_feed_envelope_with_revocations(&key, &feed, 1_000);
        let err = verify_envelope_for_import(
            &envelope,
            &exporter_roots(&key),
            "spoke",
            envelope.statement.issued_at_unix_ms.saturating_add(1),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(crate::key_revocation::REVOCATIONS_ENV),
            "{err}"
        );
        envelope
            .verify(
                &exporter_roots(&key),
                crate::ontology::NS,
                "spoke",
                envelope.statement.issued_at_unix_ms.saturating_add(1),
            )
            .unwrap();
    }

    fn signed_feed_bundle(
        key: &ed25519_dalek::SigningKey,
        feed: &AdvisoryFeed,
    ) -> crate::offline_bundle::VerifiedBundle {
        let envelope = signed_feed_envelope(key, feed, statement_issued_at(feed));
        let now = envelope.statement.issued_at_unix_ms.saturating_add(1);
        envelope
            .verify(&exporter_roots(key), crate::ontology::NS, "spoke", now)
            .unwrap()
    }

    fn statement_issued_at(feed: &AdvisoryFeed) -> i64 {
        if feed.generated_at > 0 {
            feed.generated_at
        } else {
            1_700_000_000_000
        }
    }

    fn signed_feed_envelope(
        key: &ed25519_dalek::SigningKey,
        feed: &AdvisoryFeed,
        issued_at: i64,
    ) -> crate::offline_bundle::BundleEnvelope {
        signed_feed_envelope_from_payloads(key, feed, issued_at, std::collections::BTreeMap::new())
    }

    fn signed_feed_envelope_with_revocations(
        key: &ed25519_dalek::SigningKey,
        feed: &AdvisoryFeed,
        issued_at: i64,
    ) -> crate::offline_bundle::BundleEnvelope {
        let mut extra = std::collections::BTreeMap::new();
        crate::offline_bundle::insert_key_revocations(
            &mut extra,
            &crate::key_revocation::RevocationList {
                schema: crate::key_revocation::REVOCATIONS_SCHEMA.into(),
                key_id: "revocation-authority".into(),
                statement: crate::key_revocation::RevocationStatement {
                    sequence: 1,
                    issued_at: 1,
                    revoked: Vec::new(),
                },
                signature: "not-verified-here".into(),
            },
        )
        .unwrap();
        signed_feed_envelope_from_payloads(key, feed, issued_at, extra)
    }

    fn signed_feed_envelope_from_payloads(
        key: &ed25519_dalek::SigningKey,
        feed: &AdvisoryFeed,
        issued_at: i64,
        mut payloads: std::collections::BTreeMap<String, (String, Vec<u8>)>,
    ) -> crate::offline_bundle::BundleEnvelope {
        use crate::offline_bundle::{BundleEnvelope, BundleStatement};
        use sha2::{Digest as _, Sha256};
        let plan = br#"{"plan":"content"}"#.to_vec();
        let approval = br#"{"approval":"content"}"#.to_vec();
        let feed_bytes = serde_json::to_vec(feed).unwrap();
        payloads.insert(
            "approvals/content.json".into(),
            ("application/json".into(), approval.clone()),
        );
        payloads.insert(
            ADVISORY_FEED_PATH.into(),
            (ADVISORY_FEED_MEDIA.into(), feed_bytes),
        );
        payloads.insert(
            "plans/content.json".into(),
            ("application/json".into(), plan.clone()),
        );
        payloads.insert(
            "releases/api@1.0.0/payload.bin".into(),
            ("application/octet-stream".into(), b"payload".to_vec()),
        );
        let digest = |bytes: &[u8]| format!("sha256:{:x}", Sha256::digest(bytes));
        BundleEnvelope::create(
            BundleStatement {
                tenant_id: crate::ontology::NS.into(),
                environment_id: "spoke".into(),
                plan_id: "content".into(),
                plan_digest: digest(&plan),
                approval_digest: digest(&approval),
                release_ids: vec!["api@1.0.0".into()],
                exporter_identity: "exporter".into(),
                issued_at_unix_ms: issued_at,
                expires_at_unix_ms: issued_at + 10_000,
                entries: Vec::new(),
            },
            payloads,
            key,
        )
        .unwrap()
    }

    fn exporter_roots(key: &ed25519_dalek::SigningKey) -> crate::release_signing::TrustRoots {
        crate::release_signing::TrustRoots {
            version: 1,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: crate::release_signing::key_id(&key.verifying_key().to_bytes()),
                identity: "exporter".into(),
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    key.verifying_key().to_bytes(),
                ),
            }],
        }
    }
}

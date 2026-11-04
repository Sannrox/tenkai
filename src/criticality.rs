//! Declared and imported derived criticality on environments and products (#694).
//!
//! An operator declares `low`, `medium`, `high`, or `critical` with an owner
//! and a reason. A signed `tenkai.derived-criticality.v2` envelope can add a
//! derived value from an external evidence source. The effective value is the
//! higher of the two; a stale or missing derived value is shown and never
//! lowers it. Tenkai does not read or interpret markings.
//!
//! This module is a type and property-math leaf. Persistence, signing, and
//! import live in the criticality store module so environment inspect and
//! approval policy can read criticality without a module cycle.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

/// Signed derived-criticality envelope schema. Its signature covers the
/// statement bytes the producer sent (#866); see
/// `docs/manage-environments.md#derived-criticality-wire-format`.
pub const DERIVED_SCHEMA: &str = "tenkai.derived-criticality.v2";
/// Deprecated (#866): signed over Tenkai's re-encoding of the parsed
/// statement. Verified for envelopes and bundles made by earlier releases,
/// never produced, and removed in a later release.
pub const LEGACY_DERIVED_SCHEMA: &str = "tenkai.derived-criticality.v1";
/// Signed bundle path for a derived-criticality envelope.
pub const DERIVED_PATH: &str = "criticality/derived.json";
/// Media type of [`DERIVED_PATH`].
pub const DERIVED_MEDIA: &str = "application/vnd.tenkai.derived-criticality.v2+json";
/// Trust roots that may sign derived criticality.
pub const CRITICALITY_TRUST_ROOTS_ENV: &str = "TENKAI_CRITICALITY_TRUST_ROOTS";

/// Prefix of every [`DERIVED_SCHEMA`] signed message.
pub const SIGNING_DOMAIN: &[u8] = b"TENKAI-DERIVED-CRITICALITY-V2\0";
const LEGACY_SIGNING_DOMAIN: &[u8] = b"TENKAI-DERIVED-CRITICALITY-V1\0";
const MAX_ASSIGNMENTS: usize = 4_096;
pub(crate) const MAX_REASON_BYTES: usize = 1_024;
pub(crate) const DECLARED_LEVEL: &str = "criticality.declared";
pub(crate) const DECLARED_OWNER: &str = "criticality.declared.owner";
pub(crate) const DECLARED_REASON: &str = "criticality.declared.reason";
pub(crate) const DECLARED_SET_AT: &str = "criticality.declared.set_at";
pub(crate) const DERIVED_LEVEL: &str = "criticality.derived";
pub(crate) const DERIVED_SOURCE: &str = "criticality.derived.source";
pub(crate) const DERIVED_REASON: &str = "criticality.derived.reason";
pub(crate) const DERIVED_GENERATED_AT: &str = "criticality.derived.generated_at";
pub(crate) const DERIVED_IMPORTED_AT: &str = "criticality.derived.imported_at";
pub(crate) const DERIVED_MAX_AGE_MS: &str = "criticality.derived.max_age_ms";
pub(crate) const DERIVED_KEY_ID: &str = "criticality.derived.key_id";

/// Ordered operator-facing criticality. Higher values matter more.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CriticalityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl CriticalityLevel {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => bail!("unknown criticality {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Who a criticality assignment names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CriticalityTargetKind {
    Environment,
    Product,
}

impl CriticalityTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Product => "product",
        }
    }
}

/// Operator-declared criticality, with who set it and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeclaredCriticality {
    pub level: CriticalityLevel,
    pub owner: String,
    pub reason: String,
    pub set_at: i64,
    pub source: String,
}

/// Imported derived criticality. `stale` is computed at read time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DerivedCriticality {
    pub level: CriticalityLevel,
    pub source: String,
    pub reason: String,
    pub generated_at: i64,
    pub imported_at: i64,
    pub age_ms: i64,
    pub stale: bool,
}

/// Declared, derived, and the higher of the two that still counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EffectiveCriticality {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub effective: Option<CriticalityLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub declared: Option<DeclaredCriticality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub derived: Option<DerivedCriticality>,
}

impl EffectiveCriticality {
    pub fn is_empty(&self) -> bool {
        self.effective.is_none() && self.declared.is_none() && self.derived.is_none()
    }
}

/// Body of `PUT` environment/product criticality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCriticalityRequest {
    pub level: CriticalityLevel,
    pub owner: String,
    pub reason: String,
}

impl SetCriticalityRequest {
    pub fn validate(&self) -> Result<()> {
        require_owner_reason(&self.owner, &self.reason)
    }
}

/// Result of importing a signed derived envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DerivedImportResult {
    pub applied: usize,
}

/// One assignment of a [`DerivedStatement`]. A verifier ignores fields it
/// does not know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedAssignment {
    pub kind: CriticalityTargetKind,
    pub name: String,
    pub level: CriticalityLevel,
    pub source: String,
    #[serde(default)]
    pub reason: String,
}

/// What a derived-criticality producer signs ([`DERIVED_SCHEMA`]). A
/// verifier ignores fields it does not know; the signature still covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedStatement {
    pub generated_at: i64,
    pub max_age_ms: i64,
    pub assignments: Vec<DerivedAssignment>,
}

/// Signed derived criticality from an external evidence source (#866).
/// Wire format: docs/manage-environments.md#derived-criticality-wire-format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DerivedEnvelope {
    /// `tenkai.derived-criticality.v2`.
    pub schema: String,
    /// `sha256:` and the lowercase hex SHA-256 of the signer's Ed25519 public key.
    pub key_id: String,
    /// Standard padded base64 of the statement JSON bytes the producer signed.
    pub statement: String,
    /// Standard padded base64 Ed25519 signature over
    /// `TENKAI-DERIVED-CRITICALITY-V2`, one NUL byte, and the statement bytes.
    pub signature: String,
}

/// A deprecated [`LEGACY_DERIVED_SCHEMA`] envelope. Its signature covers
/// the serde_json encoding of [`LegacyStatement`], so these types are frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: LegacyStatement,
    pub signature: String,
}

/// Statement of a [`LegacyEnvelope`], frozen with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyStatement {
    pub generated_at: i64,
    pub max_age_ms: i64,
    pub assignments: Vec<LegacyAssignment>,
}

/// Assignment of a [`LegacyStatement`], frozen with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyAssignment {
    pub kind: CriticalityTargetKind,
    pub name: String,
    pub level: CriticalityLevel,
    pub source: String,
    #[serde(default)]
    pub reason: String,
}

impl From<LegacyStatement> for DerivedStatement {
    fn from(legacy: LegacyStatement) -> Self {
        Self {
            generated_at: legacy.generated_at,
            max_age_ms: legacy.max_age_ms,
            assignments: legacy
                .assignments
                .into_iter()
                .map(|assignment| DerivedAssignment {
                    kind: assignment.kind,
                    name: assignment.name,
                    level: assignment.level,
                    source: assignment.source,
                    reason: assignment.reason,
                })
                .collect(),
        }
    }
}

/// A derived-criticality envelope as received, before its signature is checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ReceivedEnvelope {
    Current(DerivedEnvelope),
    Legacy(LegacyEnvelope),
}

/// A derived-criticality statement whose signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDerived {
    pub key_id: String,
    pub statement: DerivedStatement,
}

/// The message a [`LEGACY_DERIVED_SCHEMA`] signature covers.
pub(crate) fn legacy_signed_message(statement: &LegacyStatement) -> Result<Vec<u8>> {
    let mut bytes = LEGACY_SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

impl DerivedEnvelope {
    /// The statement without checking its signature. Only for a lint by a
    /// holder of no trust roots (bundle build); every import verifies first.
    pub(crate) fn unverified_statement(&self) -> Result<DerivedStatement> {
        let bytes = STANDARD
            .decode(&self.statement)
            .context("derived criticality statement is not standard padded base64")?;
        let statement: DerivedStatement =
            serde_json::from_slice(&bytes).context("derived criticality statement is not valid")?;
        statement.validate()?;
        Ok(statement)
    }
}

pub(crate) fn require_owner_reason(owner: &str, reason: &str) -> Result<()> {
    let owner = owner.trim();
    let reason = reason.trim();
    if owner.is_empty() || owner.chars().any(char::is_control) {
        bail!("criticality owner is required");
    }
    if owner.len() > MAX_REASON_BYTES {
        bail!("criticality owner exceeds {MAX_REASON_BYTES} bytes");
    }
    if reason.is_empty() || reason.chars().any(char::is_control) {
        bail!("criticality reason is required");
    }
    if reason.len() > MAX_REASON_BYTES {
        bail!("criticality reason exceeds {MAX_REASON_BYTES} bytes");
    }
    Ok(())
}

/// Read declared and derived values from stored object properties.
pub fn from_properties(
    properties: &HashMap<String, String>,
    now: i64,
) -> Result<EffectiveCriticality> {
    let declared = match properties.get(DECLARED_LEVEL) {
        None => None,
        Some(level) => Some(DeclaredCriticality {
            level: CriticalityLevel::parse(level)?,
            owner: properties.get(DECLARED_OWNER).cloned().unwrap_or_default(),
            reason: properties.get(DECLARED_REASON).cloned().unwrap_or_default(),
            set_at: properties
                .get(DECLARED_SET_AT)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            source: "declared".into(),
        }),
    };
    let derived = match properties.get(DERIVED_LEVEL) {
        None => None,
        Some(level) => {
            let generated_at = properties
                .get(DERIVED_GENERATED_AT)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let imported_at = properties
                .get(DERIVED_IMPORTED_AT)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let max_age_ms = properties
                .get(DERIVED_MAX_AGE_MS)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let age_ms = now.saturating_sub(generated_at);
            let stale = max_age_ms > 0 && age_ms > max_age_ms;
            Some(DerivedCriticality {
                level: CriticalityLevel::parse(level)?,
                source: properties.get(DERIVED_SOURCE).cloned().unwrap_or_default(),
                reason: properties.get(DERIVED_REASON).cloned().unwrap_or_default(),
                generated_at,
                imported_at,
                age_ms,
                stale,
            })
        }
    };
    let effective = [
        declared.as_ref().map(|value| value.level),
        derived
            .as_ref()
            .and_then(|value| (!value.stale).then_some(value.level)),
    ]
    .into_iter()
    .flatten()
    .max();
    Ok(EffectiveCriticality {
        effective,
        declared,
        derived,
    })
}

/// Effective level only, for sorting and policy.
pub fn effective_level(
    properties: &HashMap<String, String>,
    now: i64,
) -> Result<Option<CriticalityLevel>> {
    Ok(from_properties(properties, now)?.effective)
}

pub(crate) fn higher(
    left: Option<CriticalityLevel>,
    right: Option<CriticalityLevel>,
) -> Option<CriticalityLevel> {
    match (left, right) {
        (None, right) => right,
        (left, None) => left,
        (Some(left), Some(right)) => Some(left.max(right)),
    }
}

impl ReceivedEnvelope {
    /// Read and parse an envelope file. The signature is not checked here.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading derived criticality {}", path.display()))?;
        parse_envelope(&raw)
            .with_context(|| format!("parsing derived criticality {}", path.display()))
    }

    pub fn key_id(&self) -> &str {
        match self {
            Self::Current(envelope) => &envelope.key_id,
            Self::Legacy(envelope) => &envelope.key_id,
        }
    }
}

impl DerivedStatement {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.generated_at <= 0 {
            bail!("derived criticality generated_at must be positive");
        }
        if self.max_age_ms <= 0 {
            bail!("derived criticality max_age_ms must be positive");
        }
        if self.assignments.is_empty() {
            bail!("derived criticality needs at least one assignment");
        }
        if self.assignments.len() > MAX_ASSIGNMENTS {
            bail!("derived criticality exceeds {MAX_ASSIGNMENTS} assignments");
        }
        let mut seen = std::collections::BTreeSet::new();
        for assignment in &self.assignments {
            validate_assignment_name(assignment)?;
            if assignment.source.trim().is_empty()
                || assignment.source.chars().any(char::is_control)
            {
                bail!("derived criticality source is required");
            }
            if assignment.reason.chars().any(char::is_control) {
                bail!("derived criticality reason must not contain control characters");
            }
            if assignment.reason.len() > MAX_REASON_BYTES {
                bail!("derived criticality reason exceeds {MAX_REASON_BYTES} bytes");
            }
            if !seen.insert((assignment.kind.as_str(), assignment.name.as_str())) {
                bail!(
                    "derived criticality names {} {} twice",
                    assignment.kind.as_str(),
                    assignment.name
                );
            }
        }
        Ok(())
    }
}

fn validate_assignment_name(assignment: &DerivedAssignment) -> Result<()> {
    let label = assignment.kind.as_str();
    let mut chars = assignment.name.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        bail!(
            "{label} must start with an ASCII letter or digit and contain only letters, digits, '.', '_', '-', or '+'"
        );
    }
    Ok(())
}

fn validate_key_id_shape(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("derived criticality key id must use the sha256:<hex> format");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("derived criticality key id must contain 64 lowercase hexadecimal characters");
    }
    Ok(())
}

/// Parse a derived-criticality envelope by its `schema`, without checking
/// the signature. A schema this release does not verify is refused by name.
pub fn parse_envelope(bytes: &[u8]) -> Result<ReceivedEnvelope> {
    #[derive(Deserialize)]
    struct Schema {
        schema: String,
    }
    let Schema { schema } = serde_json::from_slice(bytes)
        .context("derived criticality is not a JSON object with a schema")?;
    let envelope = match schema.as_str() {
        DERIVED_SCHEMA => ReceivedEnvelope::Current(
            serde_json::from_slice(bytes).context("derived criticality envelope is not valid")?,
        ),
        LEGACY_DERIVED_SCHEMA => ReceivedEnvelope::Legacy(
            serde_json::from_slice(bytes).context("derived criticality envelope is not valid")?,
        ),
        other => bail!(
            "unsupported derived criticality schema {other:?}; this release verifies {DERIVED_SCHEMA} and the deprecated {LEGACY_DERIVED_SCHEMA}"
        ),
    };
    validate_key_id_shape(envelope.key_id())?;
    Ok(envelope)
}

/// A derived envelope clock after the signed bundle issued-at cannot become the preferred generation.
pub fn refuse_generated_after_issued(generated_at: i64, issued_at: i64) -> Result<()> {
    if generated_at > 0 && generated_at > issued_at {
        bail!(
            "derived criticality generated_at {generated_at} is after bundle issued_at {issued_at}"
        );
    }
    Ok(())
}

/// Allowed importer-clock lead so a slightly fast signer still verifies.
pub(crate) const DERIVED_CLOCK_SKEW_MS: i64 = 60_000;

/// A derived envelope dated after the import clock cannot become the preferred generation.
pub fn refuse_generated_in_the_future(generated_at: i64, now: i64) -> Result<()> {
    if generated_at > now.saturating_add(DERIVED_CLOCK_SKEW_MS) {
        bail!("derived criticality generated_at {generated_at} is after import clock {now}");
    }
    Ok(())
}

/// True when continue-after-failure is refused for this effective level.
pub fn continue_after_failure_refused(
    effective: Option<CriticalityLevel>,
    max: Option<CriticalityLevel>,
) -> bool {
    matches!((effective, max), (Some(effective), Some(max)) if effective > max)
}

/// Keep product criticality across a republish that rewrites the product object.
pub fn preserve_product_properties(
    existing: Option<&HashMap<String, String>>,
    mut properties: HashMap<String, String>,
) -> HashMap<String, String> {
    let Some(existing) = existing else {
        return properties;
    };
    for (key, value) in existing {
        if key.starts_with("criticality.") {
            properties
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    properties
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_is_the_higher_of_declared_and_fresh_derived() {
        let mut properties = HashMap::new();
        properties.insert(DECLARED_LEVEL.into(), "medium".into());
        properties.insert(DECLARED_OWNER.into(), "alice".into());
        properties.insert(DECLARED_REASON.into(), "pci".into());
        properties.insert(DECLARED_SET_AT.into(), "1".into());
        properties.insert(DERIVED_LEVEL.into(), "critical".into());
        properties.insert(DERIVED_SOURCE.into(), "governance-catalog".into());
        properties.insert(DERIVED_GENERATED_AT.into(), "10".into());
        properties.insert(DERIVED_IMPORTED_AT.into(), "11".into());
        properties.insert(DERIVED_MAX_AGE_MS.into(), "100".into());
        let now = 50;
        let view = from_properties(&properties, now).unwrap();
        assert_eq!(view.effective, Some(CriticalityLevel::Critical));
        assert!(!view.derived.as_ref().unwrap().stale);

        properties.insert(DERIVED_LEVEL.into(), "low".into());
        let view = from_properties(&properties, now).unwrap();
        assert_eq!(view.effective, Some(CriticalityLevel::Medium));
    }

    #[test]
    fn stale_derived_is_shown_and_never_lowers_effective() {
        let mut properties = HashMap::new();
        properties.insert(DECLARED_LEVEL.into(), "high".into());
        properties.insert(DECLARED_OWNER.into(), "alice".into());
        properties.insert(DECLARED_REASON.into(), "prod".into());
        properties.insert(DECLARED_SET_AT.into(), "1".into());
        properties.insert(DERIVED_LEVEL.into(), "low".into());
        properties.insert(DERIVED_SOURCE.into(), "governance-catalog".into());
        properties.insert(DERIVED_GENERATED_AT.into(), "10".into());
        properties.insert(DERIVED_IMPORTED_AT.into(), "11".into());
        properties.insert(DERIVED_MAX_AGE_MS.into(), "5".into());
        let view = from_properties(&properties, 100).unwrap();
        assert!(view.derived.as_ref().unwrap().stale);
        assert_eq!(view.effective, Some(CriticalityLevel::High));

        properties.remove(DECLARED_LEVEL);
        properties.remove(DECLARED_OWNER);
        properties.remove(DECLARED_REASON);
        properties.remove(DECLARED_SET_AT);
        let view = from_properties(&properties, 100).unwrap();
        assert!(view.derived.as_ref().unwrap().stale);
        assert_eq!(view.effective, None);
    }

    #[test]
    fn continue_after_failure_refused_above_the_policy_max() {
        assert!(!continue_after_failure_refused(
            Some(CriticalityLevel::High),
            Some(CriticalityLevel::High)
        ));
        assert!(continue_after_failure_refused(
            Some(CriticalityLevel::Critical),
            Some(CriticalityLevel::High)
        ));
        assert!(!continue_after_failure_refused(
            Some(CriticalityLevel::Critical),
            None
        ));
    }

    #[test]
    fn refuse_generated_in_the_future_allows_skew_and_rejects_far_ahead() {
        assert!(refuse_generated_in_the_future(100, 100).is_ok());
        assert!(refuse_generated_in_the_future(100 + DERIVED_CLOCK_SKEW_MS, 100).is_ok());
        let error = refuse_generated_in_the_future(100 + DERIVED_CLOCK_SKEW_MS + 1, 100)
            .unwrap_err()
            .to_string();
        assert!(error.contains("after import clock"), "{error}");
    }

    #[test]
    fn preserve_product_properties_keeps_criticality_across_publish() {
        let existing = HashMap::from([
            ("description".into(), "old".into()),
            (DECLARED_LEVEL.into(), "high".into()),
            (DECLARED_OWNER.into(), "alice".into()),
        ]);
        let next = preserve_product_properties(
            Some(&existing),
            HashMap::from([("description".into(), "new".into())]),
        );
        assert_eq!(next.get("description").unwrap(), "new");
        assert_eq!(next.get(DECLARED_LEVEL).unwrap(), "high");
        assert_eq!(next.get(DECLARED_OWNER).unwrap(), "alice");
    }
}

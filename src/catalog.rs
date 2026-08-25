//! Catalog operations: publish immutable releases, promote them into channels.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::change_set_pin::{self, ChangeSetEvidenceInput, ChangeSetPinProjection};
use crate::client::Ctx;
use crate::manifest;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::release_provenance::{self, ProvenanceEnvelope, ProvenanceProjection};
use crate::release_signing::{self, VerificationEvidence};

mod publication;
mod trust;

pub use trust::{inspect_release, require_deployable_trust, reverify_release};
pub(crate) use trust::{load_deployable_snapshot, load_recoverable_snapshot, release_is_recalled};

/// Version of the transport-independent Catalog application contract.
pub const CATALOG_CONTRACT_VERSION: u32 = 1;

/// Immutable metadata returned to planners and other Catalog consumers.
///
/// Payload bytes remain in the referenced content store. `content_path` is the
/// embedded filesystem adapter's locator; a remote adapter translates its own
/// opaque locator without changing the digest identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDescriptor {
    pub contract_version: u32,
    pub release_id: String,
    pub product: String,
    pub version: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub content_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_set_pin: Option<ChangeSetPinProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResult {
    pub release: String,
    pub provenance_digests: Vec<String>,
    pub message: String,
}

#[derive(Debug)]
pub enum CatalogLookupError {
    NotFound { release_id: String },
    Recalled { release_id: String },
    Malformed { release_id: String, reason: String },
    TrustDenied { release_id: String, reason: String },
    Provider(anyhow::Error),
}

impl std::fmt::Display for CatalogLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { release_id } => {
                write!(formatter, "release object {release_id} not found")
            }
            Self::Recalled { release_id } => write!(formatter, "release {release_id} is recalled"),
            Self::Malformed { release_id, reason } => {
                write!(formatter, "release {release_id} is malformed: {reason}")
            }
            Self::TrustDenied { release_id, reason } => {
                write!(
                    formatter,
                    "release {release_id} is not deployable: {reason}"
                )
            }
            Self::Provider(error) => write!(formatter, "Catalog provider failed: {error}"),
        }
    }
}

impl std::error::Error for CatalogLookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

pub type CatalogLookupResult<T> = std::result::Result<T, CatalogLookupError>;

/// Stable read port used by planning in embedded and future server hosts.
///
/// Implementations must provide immutable lookup and fail closed for recalled
/// content. Remote transports must preserve the typed not-found/recalled
/// behavior and run the same conformance cases as the embedded adapter.
pub trait CatalogReader {
    fn lookup_release<'a>(
        &'a mut self,
        release_id: &'a str,
        environment: &'a str,
    ) -> impl std::future::Future<Output = CatalogLookupResult<ReleaseDescriptor>> + Send + 'a;
}

/// In-process Catalog adapter. This is intentionally an application boundary,
/// not a service boundary.
pub struct EmbeddedCatalog<'a> {
    ctx: &'a mut Ctx,
}

impl<'a> EmbeddedCatalog<'a> {
    pub fn new(ctx: &'a mut Ctx) -> Self {
        Self { ctx }
    }
}

impl CatalogReader for EmbeddedCatalog<'_> {
    // Keep the explicit `Send` bound promised by the public transport seam.
    #[allow(clippy::manual_async_fn)]
    fn lookup_release<'a>(
        &'a mut self,
        release_id: &'a str,
        environment: &'a str,
    ) -> impl std::future::Future<Output = CatalogLookupResult<ReleaseDescriptor>> + Send + 'a {
        async move {
            let release = self
                .ctx
                .get(release_id)
                .await
                .map_err(CatalogLookupError::Provider)?
                .ok_or_else(|| CatalogLookupError::NotFound {
                    release_id: release_id.into(),
                })?;
            trust::descriptor_from_object(self.ctx, &release, environment).await
        }
    }
}

#[derive(Debug, Clone)]
enum PublicationTrust {
    Verified(Box<VerifiedPublication>),
    UnsignedDevelopment,
}

#[derive(Debug, Clone)]
struct VerifiedPublication {
    evidence: VerificationEvidence,
    envelope: release_signing::SignatureEnvelope,
}

impl PublicationTrust {
    fn properties(&self) -> Result<HashMap<String, String>> {
        match self {
            Self::Verified(verified) => Ok(HashMap::from([
                ("verification_status".into(), "verified".into()),
                (
                    "signature_algorithm".into(),
                    release_signing::SIGNATURE_ALGORITHM.into(),
                ),
                (
                    "signer_identity".into(),
                    verified.evidence.signer_identity.clone(),
                ),
                (
                    "signer_key_id".into(),
                    verified.evidence.signer_key_id.clone(),
                ),
                (
                    "signer_public_key".into(),
                    verified.evidence.signer_public_key.clone(),
                ),
                (
                    "signature_statement_digest".into(),
                    verified.evidence.statement_digest.clone(),
                ),
                (
                    "signature_envelope".into(),
                    serde_json::to_string(&verified.envelope)?,
                ),
                (
                    "provenance".into(),
                    serde_json::to_string(&verified.evidence.provenance)?,
                ),
            ])),
            Self::UnsignedDevelopment => Ok(HashMap::from([
                ("verification_status".into(), "unsigned-development".into()),
                ("signature_algorithm".into(), "none".into()),
            ])),
        }
    }

    fn description(&self) -> String {
        match self {
            Self::Verified(verified) => {
                format!("signed by {}", verified.evidence.signer_identity)
            }
            Self::UnsignedDevelopment => "unsigned development release".into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    pub signature: Option<PathBuf>,
    pub trust_roots: Option<PathBuf>,
    pub allow_unsigned_development: bool,
    pub provenance: Vec<PathBuf>,
    pub provenance_trust_roots: Option<PathBuf>,
    pub change_set_evidence: Option<ChangeSetEvidenceInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseVerificationView {
    pub release_id: String,
    pub product: String,
    pub version: String,
    pub status: String,
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    pub manifest_digest: String,
    pub artifact_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<release_signing::Provenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governance_provenance: Vec<ProvenanceProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_set_pin: Option<ChangeSetPinProjection>,
}

fn parse_release_spec(spec: &str) -> Result<(&str, &str)> {
    let Some((product, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    validate_identifier("product", product)?;
    validate_identifier("version", version)?;
    Ok((product, version))
}

async fn release_for_spec(ctx: &mut Ctx, spec: &str) -> Result<Object> {
    let (product, version) = parse_release_spec(spec)?;
    let id = release_id(product, version);
    let release = ctx
        .get(&id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("release {spec} is not published"))?;
    validate_release_identity(&release, product, version)?;
    Ok(release)
}

fn validate_release_identity(release: &Object, product: &str, version: &str) -> Result<()> {
    let expected_id = release_id(product, version);
    if release.kind != KIND_RELEASE
        || release.id != expected_id
        || release.properties.get("product").map(String::as_str) != Some(product)
        || release.properties.get("version").map(String::as_str) != Some(version)
    {
        bail!(
            "release object {} does not match expected identity {product}@{version}",
            release.id
        );
    }
    Ok(())
}

fn provenance_properties(
    envelopes: &[ProvenanceEnvelope],
) -> Result<(HashMap<String, String>, Vec<String>)> {
    if envelopes.is_empty() {
        return Ok((HashMap::new(), Vec::new()));
    }
    let digests = envelopes
        .iter()
        .map(ProvenanceEnvelope::digest)
        .collect::<Result<Vec<_>>>()?;
    let projections = envelopes
        .iter()
        .map(ProvenanceEnvelope::projection)
        .collect::<Result<Vec<_>>>()?;
    Ok((
        HashMap::from([
            (
                "provenance_envelopes".into(),
                serde_json::to_string(envelopes)?,
            ),
            (
                "provenance_digests".into(),
                serde_json::to_string(&digests)?,
            ),
            (
                "provenance_projections".into(),
                serde_json::to_string(&projections)?,
            ),
        ]),
        digests,
    ))
}

fn validate_stored_provenance(release: &Object, expected: &HashMap<String, String>) -> Result<()> {
    for key in [
        "provenance_envelopes",
        "provenance_digests",
        "provenance_projections",
    ] {
        let stored = release
            .properties
            .get(key)
            .map(String::as_str)
            .unwrap_or("");
        let wanted = expected.get(key).map(String::as_str).unwrap_or("");
        if stored != wanted {
            bail!(
                "release {} already exists with different immutable provenance",
                release.id
            );
        }
    }
    Ok(())
}

fn validate_provenance_admission(
    envelopes: &[ProvenanceEnvelope],
    existing_release: bool,
    now_unix_ms: i64,
) -> Result<()> {
    if !existing_release {
        for envelope in envelopes {
            envelope.validate(now_unix_ms)?;
        }
    }
    Ok(())
}

fn verify_publication(
    options: &PublishOptions,
    manifest_digest: &str,
    artifact_digest: &str,
) -> Result<PublicationTrust> {
    match (&options.signature, &options.trust_roots) {
        (Some(signature), Some(trust_roots)) => {
            if options.allow_unsigned_development {
                bail!("--allow-unsigned-development cannot be combined with signed publication");
            }
            let envelope = release_signing::SignatureEnvelope::load(signature)?;
            let roots = release_signing::TrustRoots::load(trust_roots)?;
            let evidence = release_signing::verify_release(
                &envelope,
                &roots,
                manifest_digest,
                artifact_digest,
            )?;
            Ok(PublicationTrust::Verified(Box::new(VerifiedPublication {
                evidence,
                envelope,
            })))
        }
        (None, None) if options.allow_unsigned_development => {
            Ok(PublicationTrust::UnsignedDevelopment)
        }
        (None, None) => bail!(
            "release publication requires --signature and --trust-roots; use --allow-unsigned-development only for local development"
        ),
        _ => bail!("signed publication requires both --signature and --trust-roots"),
    }
}

async fn backfill_legacy_verification(
    ctx: &mut Ctx,
    release_id: &str,
    verification_properties: &HashMap<String, String>,
) -> Result<()> {
    let claim_id = release_verification_id(release_id);
    let mut claim_properties = verification_properties.clone();
    claim_properties.insert("release_id".into(), release_id.into());
    let claim = object(
        claim_id.clone(),
        KIND_RELEASE_VERIFICATION,
        format!("verification for {release_id}"),
        claim_properties.clone(),
    );
    match ctx.create_once(claim.clone()).await {
        Ok(_) => {}
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) =>
        {
            let existing_claim = ctx.get(&claim_id).await?.ok_or_else(|| {
                anyhow::anyhow!("release verification claim {claim_id} appeared then vanished")
            })?;
            if existing_claim.id != claim.id
                || existing_claim.kind != claim.kind
                || existing_claim.name != claim.name
                || existing_claim.namespace != claim.namespace
                || existing_claim.external_id != claim.external_id
                || existing_claim.properties != claim_properties
            {
                bail!("release {release_id} already has different immutable verification evidence");
            }
        }
        Err(status) => return Err(status.into()),
    }
    ctx.link(release_id, &claim_id, REL_HAS_RELEASE_VERIFICATION)
        .await?;
    let expected_link_id = format!("{release_id}--{REL_HAS_RELEASE_VERIFICATION}--{claim_id}");
    if !ctx
        .links(release_id, REL_HAS_RELEASE_VERIFICATION)
        .await?
        .iter()
        .any(|link| {
            link.id == expected_link_id
                && link.from_id == release_id
                && link.to_id == claim_id
                && link.relation == REL_HAS_RELEASE_VERIFICATION
        })
    {
        bail!("release {release_id} verification link has conflicting immutable identity");
    }
    Ok(())
}

fn object(id: String, kind: &str, name: String, properties: HashMap<String, String>) -> Object {
    let now = crate::now_millis();
    Object {
        id,
        kind: kind.into(),
        name,
        namespace: NS.into(),
        external_id: String::new(),
        properties,
        created: now,
        updated: now,
    }
}

fn validate_stored_release_content(
    release: &Object,
    expected_manifest_digest: &str,
    expected_artifact_digest: &str,
) -> Result<()> {
    let raw_manifest = release
        .properties
        .get("manifest")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("legacy release {} has no stored manifest", release.id))?;
    let actual_manifest_digest = manifest::digest(raw_manifest);
    if actual_manifest_digest != expected_manifest_digest
        || release.properties.get("digest").map(String::as_str)
            != Some(actual_manifest_digest.as_str())
    {
        bail!(
            "legacy release {} stored manifest does not match its recorded or signed digest",
            release.id
        );
    }

    let stored_manifest = manifest::parse_raw(raw_manifest)?;
    let workdir = release
        .properties
        .get("workdir")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("legacy release {} has no stored workdir", release.id))?;
    let actual_artifact_digest =
        manifest::artifact_digest(Path::new(workdir), &stored_manifest.immutable_inputs())?;
    if actual_artifact_digest != expected_artifact_digest
        || release
            .properties
            .get("artifact_digest")
            .filter(|value| !value.is_empty())
            .is_some_and(|value| value != &actual_artifact_digest)
    {
        bail!(
            "legacy release {} stored artifacts do not match their recorded or signed digest",
            release.id
        );
    }
    Ok(())
}

/// Publish the manifest as an immutable release of its product.
pub async fn publish(
    ctx: &mut Ctx,
    manifest_path: &Path,
    options: &PublishOptions,
) -> Result<String> {
    Ok(publication::admit(
        ctx,
        manifest_path,
        options,
        publication::ResultContract::Message,
    )
    .await?
    .message)
}

pub async fn publish_with_result(
    ctx: &mut Ctx,
    manifest_path: &Path,
    options: &PublishOptions,
) -> Result<PublishResult> {
    publication::admit(
        ctx,
        manifest_path,
        options,
        publication::ResultContract::Bounded,
    )
    .await
}

/// Point a channel of the product at an already-published release.
pub async fn promote(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    spec: &str,
    channel: &str,
) -> Result<String> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let Some((name, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    validate_identifier("product", name)?;
    validate_identifier("version", version)?;
    validate_identifier("channel", channel)?;
    let rid = release_id(name, version);
    let Some(release) = ctx.get(&rid).await? else {
        bail!("release {name}@{version} is not published");
    };
    change_set_pin::require_stored_accepted(&release)?;
    let owner = format!(
        "promotion:{}:{spec}:{}",
        actor.principal_id(),
        crate::now_millis()
    );
    let name = name.to_string();
    let version = version.to_string();
    let channel = channel.to_string();
    let promotion_name = name.clone();
    let promotion_version = version.clone();
    let promotion_channel = channel.clone();
    let promoted_release = rid.clone();
    crate::canary::guarded_promotion(ctx, actor, &name, &version, &channel, &owner, move |ctx| {
        Box::pin(async move {
            let cid = channel_id(&promotion_name, &promotion_channel);
            let channel_head = object(
                cid.clone(),
                KIND_CHANNEL,
                format!("{promotion_name}/{promotion_channel}"),
                HashMap::from([
                    ("product".into(), promotion_name.clone()),
                    ("channel".into(), promotion_channel.clone()),
                    ("current_version".into(), promotion_version.clone()),
                    ("current_release".into(), promoted_release.clone()),
                ]),
            );
            if ctx.get(&cid).await?.is_none() {
                ctx.create_once(object(
                    cid.clone(),
                    KIND_CHANNEL,
                    format!("{promotion_name}/{promotion_channel}"),
                    HashMap::from([
                        ("product".into(), promotion_name.clone()),
                        ("channel".into(), promotion_channel.clone()),
                    ]),
                ))
                .await?;
            }
            ctx.link(&cid, &promoted_release, REL_PROMOTES).await?;
            ctx.put(channel_head).await?;
            Ok::<_, anyhow::Error>(format!(
                "promoted {promotion_name}@{promotion_version} to channel {promotion_channel}"
            ))
        })
    })
    .await
}

/// Mark a published release recalled. Lookup and planning fail closed afterwards.
pub async fn recall(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    spec: &str,
) -> Result<String> {
    actor
        .require_delivery_capability(DeliveryCapability::Management)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut release = release_for_spec(ctx, spec).await?;
    if release
        .properties
        .get("recalled_at")
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(format!("release {spec} is already recalled"));
    }
    let claim_id = release_recall_id(&release.id);
    let recalled_at = crate::now_millis().to_string();
    let recalled_by = actor.principal_id().to_string();
    let proposed = object(
        claim_id.clone(),
        KIND_RELEASE_RECALL,
        format!("recall {}", release.id),
        HashMap::from([
            ("release_id".into(), release.id.clone()),
            ("recalled_at".into(), recalled_at.clone()),
            ("recalled_by".into(), recalled_by.clone()),
            (
                "principal_kind".into(),
                actor.principal_kind_name().to_string(),
            ),
        ]),
    );
    let claim = match ctx.create_once(proposed.clone()).await {
        Ok(claim) => claim,
        Err(status)
            if status.code() == tonic::Code::AlreadyExists
                || (status.code() == tonic::Code::Internal
                    && status.message().contains("UNIQUE")) =>
        {
            ctx.get(&claim_id).await?.ok_or_else(|| {
                anyhow::anyhow!("release recall claim {claim_id} appeared then vanished")
            })?
        }
        Err(status) => return Err(status.into()),
    };
    if claim.kind != KIND_RELEASE_RECALL || claim.properties.get("release_id") != Some(&release.id)
    {
        bail!("release {} has conflicting recall evidence", release.id);
    }
    let recalled_at = claim
        .properties
        .get("recalled_at")
        .cloned()
        .filter(|value| !value.is_empty())
        .unwrap_or(recalled_at);
    let recalled_by = claim
        .properties
        .get("recalled_by")
        .cloned()
        .filter(|value| !value.is_empty())
        .unwrap_or(recalled_by);
    release.properties.insert("recalled_at".into(), recalled_at);
    release.properties.insert("recalled_by".into(), recalled_by);
    ctx.put(release).await?;
    Ok(format!("recalled {spec}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    #[test]
    fn publication_fails_closed_without_signature_configuration() {
        let error =
            verify_publication(&PublishOptions::default(), &"a".repeat(64), &"b".repeat(64))
                .unwrap_err();
        assert!(error.to_string().contains("requires --signature"));
    }

    #[test]
    fn unsigned_development_policy_must_be_explicit() {
        let options = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        let trust = verify_publication(&options, &"a".repeat(64), &"b".repeat(64)).unwrap();
        assert!(matches!(trust, PublicationTrust::UnsignedDevelopment));
        assert_eq!(
            trust.properties().unwrap().get("verification_status"),
            Some(&"unsigned-development".into())
        );
    }

    #[test]
    fn verified_publication_properties_retain_reverification_evidence() {
        let provenance = release_signing::Provenance {
            source_uri: "https://example.com/source".into(),
            revision: "abc123".into(),
            builder: "test-builder".into(),
            built_at_unix_ms: 1,
            materials: std::collections::BTreeMap::new(),
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut envelope = release_signing::SignatureEnvelope {
            schema: release_signing::ENVELOPE_SCHEMA.into(),
            key_id: release_signing::key_id(&public_key),
            statement: release_signing::ReleaseStatement {
                manifest_digest: "2".repeat(64),
                artifact_digest: "3".repeat(64),
                provenance: provenance.clone(),
            },
            signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        };
        envelope.signature = base64::engine::general_purpose::STANDARD.encode(
            signing_key
                .sign(&envelope.signed_bytes().unwrap())
                .to_bytes(),
        );
        let trust = PublicationTrust::Verified(Box::new(VerifiedPublication {
            evidence: VerificationEvidence {
                signer_identity: "release@example.com".into(),
                signer_key_id: envelope.key_id.clone(),
                signer_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                manifest_digest: envelope.statement.manifest_digest.clone(),
                artifact_digest: envelope.statement.artifact_digest.clone(),
                statement_digest: envelope.statement_digest().unwrap(),
                provenance,
            },
            envelope: envelope.clone(),
        }));
        let properties = trust.properties().unwrap();
        assert_eq!(
            properties.get("verification_status"),
            Some(&"verified".into())
        );
        assert_eq!(
            properties.get("signer_identity"),
            Some(&"release@example.com".into())
        );
        assert_eq!(
            serde_json::from_str::<release_signing::SignatureEnvelope>(
                properties.get("signature_envelope").unwrap()
            )
            .unwrap(),
            envelope
        );
        let release = object(
            "tenkai:release:api@1.0.0".into(),
            KIND_RELEASE,
            "api@1.0.0".into(),
            HashMap::from([
                ("product".into(), "api".into()),
                ("version".into(), "1.0.0".into()),
                ("digest".into(), "2".repeat(64)),
                ("artifact_digest".into(), "3".repeat(64)),
            ]),
        );
        let view = trust::verification_view(&release, &properties).unwrap();
        assert_eq!(view.status, "verified");
        assert_eq!(view.signer_identity.as_deref(), Some("release@example.com"));

        let mut substituted = release;
        substituted
            .properties
            .insert("product".into(), "other".into());
        assert!(validate_release_identity(&substituted, "api", "1.0.0").is_err());
    }

    fn test_provenance(now: i64) -> release_provenance::ProvenanceEnvelope {
        release_provenance::ProvenanceEnvelope {
            profile: release_provenance::GOVERNED_SUBJECT_PROFILE.into(),
            issuer: "sekai-chisei".into(),
            issuer_key_id: String::new(),
            subject: "candidate-1".into(),
            content_digest: format!("sha256:{}", "1".repeat(64)),
            decision: "allow".into(),
            receipt_schema: "chisei.governed-subject-receipt/v1".into(),
            receipt_digest: format!("sha256:{}", "2".repeat(64)),
            governed_references: vec![release_provenance::GovernedReference {
                kind: "operation".into(),
                id: "operation-1".into(),
                digest: format!("sha256:{}", "3".repeat(64)),
            }],
            observed_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        }
    }

    #[tokio::test]
    async fn publication_persists_replays_and_conflicts_on_provenance() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-provenance-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let manifest_path = root.join("tenkai.toml");
        std::fs::write(
            &manifest_path,
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        let provenance_path = root.join("provenance.json");
        let provenance = test_provenance(crate::now_millis());
        let mut provenance = provenance;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        provenance.issuer_key_id = release_signing::key_id(&signing_key.verifying_key().to_bytes());
        provenance.content_digest = release_provenance::release_content_digest(
            &manifest::digest(&std::fs::read_to_string(&manifest_path).unwrap()),
            &manifest::artifact_digest(
                &root,
                &manifest::load(&manifest_path)
                    .unwrap()
                    .manifest
                    .immutable_inputs(),
            )
            .unwrap(),
        )
        .unwrap();
        provenance.signature = base64::engine::general_purpose::STANDARD.encode(
            signing_key
                .sign(&provenance.signed_bytes().unwrap())
                .to_bytes(),
        );
        std::fs::write(
            &provenance_path,
            serde_json::to_vec_pretty(&provenance).unwrap(),
        )
        .unwrap();
        let roots_path = root.join("provenance-trust.toml");
        let roots = release_signing::TrustRoots {
            version: release_signing::TRUST_ROOT_VERSION,
            signers: vec![release_signing::TrustedSigner {
                key_id: provenance.issuer_key_id.clone(),
                identity: provenance.issuer.clone(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(signing_key.verifying_key().to_bytes()),
            }],
        };
        std::fs::write(&roots_path, toml::to_string(&roots).unwrap()).unwrap();

        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = PublishOptions {
            allow_unsigned_development: true,
            provenance: vec![provenance_path.clone()],
            provenance_trust_roots: Some(roots_path),
            ..Default::default()
        };
        let first = publish_with_result(&mut ctx, &manifest_path, &options)
            .await
            .unwrap();
        assert_eq!(first.provenance_digests, vec![provenance.digest().unwrap()]);
        let replay = publish_with_result(&mut ctx, &manifest_path, &options)
            .await
            .unwrap();
        assert!(replay.message.contains("already published"));

        let inspected = inspect_release(&mut ctx, "api@1.0.0").await.unwrap();
        assert_eq!(inspected.governance_provenance.len(), 1);
        assert_eq!(
            inspected.governance_provenance[0].envelope_digest,
            provenance.digest().unwrap()
        );

        let mut changed = provenance;
        changed.subject = "candidate-2".into();
        changed.signature = base64::engine::general_purpose::STANDARD.encode(
            signing_key
                .sign(&changed.signed_bytes().unwrap())
                .to_bytes(),
        );
        std::fs::write(
            &provenance_path,
            serde_json::to_vec_pretty(&changed).unwrap(),
        )
        .unwrap();
        let error = publish_with_result(&mut ctx, &manifest_path, &options)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different immutable provenance"));

        let absent = PublishOptions {
            allow_unsigned_development: true,
            ..Default::default()
        };
        assert!(
            publish_with_result(&mut ctx, &manifest_path, &absent)
                .await
                .unwrap_err()
                .to_string()
                .contains("different immutable provenance")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_provenance_is_allowed_only_for_existing_release_replay() {
        let envelope = test_provenance(1_000);
        assert!(
            validate_provenance_admission(std::slice::from_ref(&envelope), false, 100_000).is_err()
        );
        assert!(validate_provenance_admission(&[envelope], true, 100_000).is_ok());
    }

    #[tokio::test]
    async fn recall_fails_closed_on_lookup() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recall-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.0.0"

[deploy]
install = "true"
"#,
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
        let actor = crate::auth_context::test_management_context("recall-test");
        assert!(
            recall(&mut ctx, &actor, "api@1.0.0")
                .await
                .unwrap()
                .contains("recalled")
        );
        let err = crate::catalog::EmbeddedCatalog::new(&mut ctx)
            .lookup_release("tenkai:release:api@1.0.0", "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("recalled"), "{err}");
        let claim = ctx
            .get(&release_recall_id("tenkai:release:api@1.0.0"))
            .await
            .unwrap()
            .expect("recall claim");
        assert_eq!(claim.kind, KIND_RELEASE_RECALL);
        assert_eq!(
            claim.properties.get("recalled_by").map(String::as_str),
            Some(actor.principal_id())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn recall_claim_fails_closed_before_release_stamp() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recall-claim-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.0.0"

[deploy]
install = "true"
"#,
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
        ctx.create_once(object(
            release_recall_id("tenkai:release:api@1.0.0"),
            KIND_RELEASE_RECALL,
            "recall tenkai:release:api@1.0.0".into(),
            HashMap::from([
                ("release_id".into(), "tenkai:release:api@1.0.0".into()),
                ("recalled_at".into(), "1".into()),
                ("recalled_by".into(), "operator".into()),
            ]),
        ))
        .await
        .unwrap();
        let err = crate::catalog::EmbeddedCatalog::new(&mut ctx)
            .lookup_release("tenkai:release:api@1.0.0", "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("recalled"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }
}

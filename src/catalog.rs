//! Catalog operations: publish immutable releases, promote them into channels.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::Serialize;

use crate::client::Ctx;
use crate::manifest;
use crate::ontology::*;
use crate::pb::sekai::Object;
use crate::release_signing::{self, VerificationEvidence};

const VERIFICATION_PROPERTY_KEYS: &[&str] = &[
    "verification_status",
    "signature_algorithm",
    "signer_identity",
    "signer_key_id",
    "signature_statement_digest",
    "signature_envelope",
    "provenance",
];

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

    fn permits_legacy_backfill(&self, properties: &HashMap<String, String>) -> bool {
        matches!(self, Self::Verified(_))
            && VERIFICATION_PROPERTY_KEYS
                .iter()
                .all(|key| !properties.contains_key(*key))
    }
}

#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    pub signature: Option<PathBuf>,
    pub trust_roots: Option<PathBuf>,
    pub allow_unsigned_development: bool,
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

async fn stored_verification_properties(
    ctx: &mut Ctx,
    release: &Object,
) -> Result<HashMap<String, String>> {
    if release.properties.contains_key("verification_status") {
        return Ok(release.properties.clone());
    }
    let claim_id = release_verification_id(&release.id);
    let claim = ctx.get(&claim_id).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "release {} has no verification evidence; republish it with a trusted signature",
            release.id
        )
    })?;
    if claim.id != claim_id
        || claim.kind != KIND_RELEASE_VERIFICATION
        || claim.namespace != NS
        || !claim.external_id.is_empty()
        || claim.properties.get("release_id") != Some(&release.id)
        || claim
            .properties
            .get("verification_status")
            .map(String::as_str)
            != Some("verified")
        || claim
            .properties
            .get("signature_algorithm")
            .map(String::as_str)
            != Some(release_signing::SIGNATURE_ALGORITHM)
    {
        bail!(
            "release {} has malformed linked verification evidence",
            release.id
        );
    }
    let linked = ctx
        .links(&release.id, REL_HAS_RELEASE_VERIFICATION)
        .await?
        .iter()
        .any(|link| {
            link.id
                == format!(
                    "{}--{}--{}",
                    release.id, REL_HAS_RELEASE_VERIFICATION, claim_id
                )
                && link.from_id == release.id
                && link.to_id == claim_id
                && link.relation == REL_HAS_RELEASE_VERIFICATION
        });
    if !linked {
        bail!(
            "release {} verification claim is not linked from the release",
            release.id
        );
    }
    Ok(claim.properties)
}

fn property<'a>(properties: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    properties
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("release verification evidence has no {key}"))
}

fn verification_view(
    release: &Object,
    properties: &HashMap<String, String>,
) -> Result<ReleaseVerificationView> {
    let status = property(properties, "verification_status")?;
    let algorithm = property(properties, "signature_algorithm")?;
    let product = property(&release.properties, "product")?;
    let version = property(&release.properties, "version")?;
    let manifest_digest = property(&release.properties, "digest")?;
    let artifact_digest = property(&release.properties, "artifact_digest")?;
    match status {
        "verified" => {
            if algorithm != release_signing::SIGNATURE_ALGORITHM {
                bail!("verified release has unsupported signature algorithm {algorithm:?}");
            }
            let provenance: release_signing::Provenance =
                serde_json::from_str(property(properties, "provenance")?)?;
            provenance.validate()?;
            Ok(ReleaseVerificationView {
                release_id: release.id.clone(),
                product: product.into(),
                version: version.into(),
                status: status.into(),
                algorithm: algorithm.into(),
                signer_identity: Some(property(properties, "signer_identity")?.into()),
                signer_key_id: Some(property(properties, "signer_key_id")?.into()),
                manifest_digest: manifest_digest.into(),
                artifact_digest: artifact_digest.into(),
                statement_digest: Some(property(properties, "signature_statement_digest")?.into()),
                provenance: Some(provenance),
            })
        }
        "unsigned-development" => {
            if algorithm != "none" {
                bail!("unsigned development release must use signature algorithm none");
            }
            Ok(ReleaseVerificationView {
                release_id: release.id.clone(),
                product: product.into(),
                version: version.into(),
                status: status.into(),
                algorithm: algorithm.into(),
                signer_identity: None,
                signer_key_id: None,
                manifest_digest: manifest_digest.into(),
                artifact_digest: artifact_digest.into(),
                statement_digest: None,
                provenance: None,
            })
        }
        other => bail!("release has unknown verification status {other:?}"),
    }
}

pub async fn inspect_release(ctx: &mut Ctx, spec: &str) -> Result<ReleaseVerificationView> {
    let release = release_for_spec(ctx, spec).await?;
    let properties = stored_verification_properties(ctx, &release).await?;
    verification_view(&release, &properties)
}

pub async fn reverify_release(
    ctx: &mut Ctx,
    spec: &str,
    trust_roots_path: &Path,
) -> Result<ReleaseVerificationView> {
    let release = release_for_spec(ctx, spec).await?;
    let properties = stored_verification_properties(ctx, &release).await?;
    let stored = verification_view(&release, &properties)?;
    if stored.status != "verified" {
        bail!("release {spec} is unsigned development content and cannot be reverified");
    }
    let envelope: release_signing::SignatureEnvelope =
        serde_json::from_str(property(&properties, "signature_envelope")?)?;
    envelope.validate()?;
    let roots = release_signing::TrustRoots::load(trust_roots_path)?;

    let raw_manifest = property(&release.properties, "manifest")?;
    let manifest = manifest::parse_raw(raw_manifest)?;
    if manifest.product.name != stored.product || manifest.product.version != stored.version {
        bail!(
            "release {spec} manifest identity {}@{} does not match its catalog identity",
            manifest.product.name,
            manifest.product.version
        );
    }
    let actual_manifest_digest = manifest::digest(raw_manifest);
    let workdir = Path::new(property(&release.properties, "workdir")?);
    let actual_artifact_digest = manifest::artifact_digest(workdir, &manifest.deploy.inputs)?;
    let evidence = release_signing::verify_release(
        &envelope,
        &roots,
        &actual_manifest_digest,
        &actual_artifact_digest,
    )?;
    if stored.signer_identity.as_deref() != Some(evidence.signer_identity.as_str())
        || stored.signer_key_id.as_deref() != Some(evidence.signer_key_id.as_str())
        || stored.statement_digest.as_deref() != Some(evidence.statement_digest.as_str())
        || stored.manifest_digest != evidence.manifest_digest
        || stored.artifact_digest != evidence.artifact_digest
        || stored.provenance.as_ref() != Some(&evidence.provenance)
    {
        bail!("release {spec} reverification result differs from its stored evidence");
    }
    Ok(stored)
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
        manifest::artifact_digest(Path::new(workdir), &stored_manifest.deploy.inputs)?;
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
    let loaded = manifest::load(manifest_path)?;
    let name = loaded.manifest.product.name.clone();
    let version = loaded.manifest.product.version.clone();
    let digest = manifest::digest(&loaded.raw);
    let artifact_digest =
        manifest::artifact_digest(&loaded.workdir, &loaded.manifest.deploy.inputs)?;
    let verification = verify_publication(options, &digest, &artifact_digest)?;
    let verification_properties = verification.properties()?;
    let versioned_workdir = manifest::snapshot_workdir(
        &loaded.workdir,
        &loaded.manifest.deploy.inputs,
        &digest,
        &artifact_digest,
    )?;

    let rid = release_id(&name, &version);
    let existing_release = if let Some(mut existing) = ctx.get(&rid).await? {
        let existing_digest = existing
            .properties
            .get("digest")
            .cloned()
            .unwrap_or_default();
        let existing_artifact_digest = existing
            .properties
            .get("artifact_digest")
            .cloned()
            .unwrap_or_default();
        let verification_unchanged = VERIFICATION_PROPERTY_KEYS
            .iter()
            .all(|key| existing.properties.get(*key) == verification_properties.get(*key));
        let legacy_backfill = verification.permits_legacy_backfill(&existing.properties);
        if existing_digest == digest
            && (existing_artifact_digest.is_empty() || existing_artifact_digest == artifact_digest)
            && (verification_unchanged || legacy_backfill)
        {
            if legacy_backfill {
                validate_stored_release_content(&existing, &digest, &artifact_digest)?;
                backfill_legacy_verification(ctx, &rid, &verification_properties).await?;
            }
            existing
                .properties
                .insert("artifact_digest".into(), artifact_digest.clone());
            existing
                .properties
                .insert("workdir".into(), versioned_workdir.display().to_string());
            existing.updated = crate::now_millis();
            ctx.put(existing).await?;
            true
        } else {
            bail!(
                "release {name}@{version} already exists with different content or verification evidence — releases are immutable, bump product.version"
            );
        }
    } else {
        let mut properties = HashMap::from([
            ("product".into(), name.clone()),
            ("version".into(), version.clone()),
            ("digest".into(), digest.clone()),
            ("artifact_digest".into(), artifact_digest.clone()),
            ("manifest".into(), loaded.raw.clone()),
            ("workdir".into(), versioned_workdir.display().to_string()),
        ]);
        properties.extend(verification_properties.clone());
        let release = object(
            rid.clone(),
            KIND_RELEASE,
            format!("{name}@{version}"),
            properties,
        );
        match ctx.create_once(release).await {
            Ok(_) => {}
            Err(status)
                if status.code() == tonic::Code::AlreadyExists
                    || (status.code() == tonic::Code::Internal
                        && status.message().contains("UNIQUE")) =>
            {
                let existing = ctx.get(&rid).await?.ok_or_else(|| {
                    anyhow::anyhow!("release {rid} appeared concurrently then vanished")
                })?;
                let legacy_backfill = verification.permits_legacy_backfill(&existing.properties);
                let existing_artifact_digest = existing
                    .properties
                    .get("artifact_digest")
                    .map(String::as_str)
                    .unwrap_or_default();
                if existing.properties.get("digest") != Some(&digest)
                    || if legacy_backfill {
                        !existing_artifact_digest.is_empty()
                            && existing_artifact_digest != artifact_digest
                    } else {
                        existing_artifact_digest != artifact_digest
                    }
                    || (!legacy_backfill
                        && VERIFICATION_PROPERTY_KEYS.iter().any(|key| {
                            existing.properties.get(*key) != verification_properties.get(*key)
                        }))
                {
                    bail!(
                        "release {name}@{version} was concurrently published with different content or verification evidence"
                    );
                }
                if legacy_backfill {
                    validate_stored_release_content(&existing, &digest, &artifact_digest)?;
                    let mut pinned = existing.clone();
                    pinned
                        .properties
                        .insert("artifact_digest".into(), artifact_digest.clone());
                    pinned
                        .properties
                        .insert("workdir".into(), versioned_workdir.display().to_string());
                    pinned.updated = crate::now_millis();
                    ctx.put(pinned).await?;
                    backfill_legacy_verification(ctx, &rid, &verification_properties).await?;
                }
            }
            Err(status) => return Err(status.into()),
        }
        false
    };

    let pid = product_id(&name);
    ctx.put(object(
        pid.clone(),
        KIND_PRODUCT,
        name.clone(),
        HashMap::from([(
            "description".into(),
            loaded.manifest.product.description.clone(),
        )]),
    ))
    .await?;
    ctx.link(&rid, &pid, REL_RELEASE_OF).await?;

    if existing_release {
        Ok(format!(
            "{name}@{version} already published (digest unchanged)"
        ))
    } else {
        let trust = verification.description();
        Ok(format!(
            "published {name}@{version} ({}, {trust})",
            &digest[..12]
        ))
    }
}

/// Point a channel of the product at an already-published release.
pub async fn promote(ctx: &mut Ctx, spec: &str, channel: &str) -> Result<String> {
    let Some((name, version)) = spec.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    validate_identifier("product", name)?;
    validate_identifier("version", version)?;
    validate_identifier("channel", channel)?;
    let rid = release_id(name, version);
    if ctx.get(&rid).await?.is_none() {
        bail!("release {name}@{version} is not published");
    }
    let owner = format!("promotion:{spec}:{}", crate::now_millis());
    let lock = crate::canary::claim_promotion_lock(ctx, name, channel, &owner).await?;
    let result = async {
        let canary_authorization =
            crate::canary::authorize_promotion(ctx, name, version, channel).await?;

        let cid = channel_id(name, channel);
        let channel_head = object(
            cid.clone(),
            KIND_CHANNEL,
            format!("{name}/{channel}"),
            HashMap::from([
                ("product".into(), name.to_string()),
                ("channel".into(), channel.to_string()),
                ("current_version".into(), version.to_string()),
                ("current_release".into(), rid.clone()),
            ]),
        );
        if let Some(expected) = canary_authorization.as_ref() {
            crate::canary::confirm_policy_active(ctx, expected).await?;
        }
        crate::canary::confirm_promotion_lock(ctx, &lock).await?;
        if ctx.get(&cid).await?.is_none() {
            ctx.create_once(object(
                cid.clone(),
                KIND_CHANNEL,
                format!("{name}/{channel}"),
                HashMap::from([
                    ("product".into(), name.to_string()),
                    ("channel".into(), channel.to_string()),
                ]),
            ))
            .await?;
        }
        ctx.link(&cid, &rid, REL_PROMOTES).await?;
        ctx.put(channel_head).await?;

        Ok::<_, anyhow::Error>(format!("promoted {name}@{version} to channel {channel}"))
    }
    .await;
    let unlock = crate::canary::release_promotion_lock(ctx, &lock).await;
    match (result, unlock) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion lock also failed: {unlock}")))
        }
        (Ok(_), Err(error)) => Err(error.context("releasing promotion lock failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let envelope = release_signing::SignatureEnvelope {
            schema: release_signing::ENVELOPE_SCHEMA.into(),
            key_id: format!("sha256:{}", "1".repeat(64)),
            statement: release_signing::ReleaseStatement {
                manifest_digest: "2".repeat(64),
                artifact_digest: "3".repeat(64),
                provenance: provenance.clone(),
            },
            signature: "signature".into(),
        };
        let trust = PublicationTrust::Verified(Box::new(VerifiedPublication {
            evidence: VerificationEvidence {
                signer_identity: "release@example.com".into(),
                signer_key_id: envelope.key_id.clone(),
                manifest_digest: envelope.statement.manifest_digest.clone(),
                artifact_digest: envelope.statement.artifact_digest.clone(),
                statement_digest: "4".repeat(64),
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
        assert!(trust.permits_legacy_backfill(&HashMap::new()));
        assert!(!trust.permits_legacy_backfill(&properties));

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
        let view = verification_view(&release, &properties).unwrap();
        assert_eq!(view.status, "verified");
        assert_eq!(view.signer_identity.as_deref(), Some("release@example.com"));

        let mut substituted = release;
        substituted
            .properties
            .insert("product".into(), "other".into());
        assert!(validate_release_identity(&substituted, "api", "1.0.0").is_err());
    }
}

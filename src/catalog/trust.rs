//! Private Catalog Release trust, lookup, inspect, and reverify.
//!
//! The interface owns linked verification-claim loading, envelope checks,
//! unsigned-local-only policy, two-read deployable snapshots, inspect, and
//! reverify. Public Catalog callers stay thin so apply and CLI do not
//! re-encode those rules.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, bail};

use super::*;

#[derive(Debug)]
pub(crate) struct DeployableSnapshot {
    pub descriptor: ReleaseDescriptor,
    pub object: Object,
}

pub(super) async fn descriptor_from_object(
    ctx: &mut Ctx,
    release: &Object,
    environment: &str,
) -> CatalogLookupResult<ReleaseDescriptor> {
    descriptor_from_object_with_admission(ctx, release, environment, SnapshotAdmission::Standard)
        .await
}

#[derive(Clone, Copy)]
pub(crate) enum SnapshotAdmission {
    Standard,
    AuditedRecovery,
}

fn release_object_is_recalled(release: &Object) -> bool {
    release
        .properties
        .get("recalled_at")
        .is_some_and(|value| !value.is_empty())
}

pub(crate) async fn release_is_recalled(ctx: &mut Ctx, release_id: &str) -> Result<bool> {
    if ctx
        .get(release_id)
        .await?
        .is_some_and(|release| release_object_is_recalled(&release))
    {
        return Ok(true);
    }
    Ok(ctx
        .get(&release_recall_id(release_id))
        .await?
        .is_some_and(|claim| claim.kind == KIND_RELEASE_RECALL))
}

async fn admit_recall(
    ctx: &mut Ctx,
    release: &Object,
    admission: SnapshotAdmission,
) -> CatalogLookupResult<()> {
    if matches!(admission, SnapshotAdmission::AuditedRecovery) {
        return Ok(());
    }
    if release_object_is_recalled(release)
        || ctx
            .get(&release_recall_id(&release.id))
            .await
            .map_err(CatalogLookupError::Provider)?
            .is_some_and(|claim| claim.kind == KIND_RELEASE_RECALL)
    {
        return Err(CatalogLookupError::Recalled {
            release_id: release.id.clone(),
        });
    }
    Ok(())
}

/// Lookup a Release, then re-read and re-admit the snapshot apply will consume.
///
/// The compatibility store does not yet provide a transactional read spanning
/// the Catalog descriptor and the object rows used for pin matching.
pub(crate) async fn load_deployable_snapshot(
    ctx: &mut Ctx,
    release_id: &str,
    environment: &str,
) -> Result<DeployableSnapshot> {
    load_snapshot(ctx, release_id, environment, SnapshotAdmission::Standard).await
}

/// Same snapshot as deployable lookup, but recalled content is admitted for an
/// audited rollback recovery. Trust and digest checks still apply.
pub(crate) async fn load_recoverable_snapshot(
    ctx: &mut Ctx,
    release_id: &str,
    environment: &str,
) -> Result<DeployableSnapshot> {
    load_snapshot(
        ctx,
        release_id,
        environment,
        SnapshotAdmission::AuditedRecovery,
    )
    .await
}

async fn load_snapshot(
    ctx: &mut Ctx,
    release_id: &str,
    environment: &str,
    admission: SnapshotAdmission,
) -> Result<DeployableSnapshot> {
    let first = ctx
        .get(release_id)
        .await
        .map_err(CatalogLookupError::Provider)?
        .ok_or_else(|| CatalogLookupError::NotFound {
            release_id: release_id.into(),
        })?;
    let descriptor =
        descriptor_from_object_with_admission(ctx, &first, environment, admission).await?;
    let Some(object) = ctx.get(release_id).await? else {
        bail!("release object {release_id} not found");
    };
    if object.kind != KIND_RELEASE {
        bail!("object {release_id} is {}, not {KIND_RELEASE}", object.kind);
    }
    admit_recall(ctx, &object, admission).await?;
    require_deployable_trust(ctx, &object, environment).await?;
    Ok(DeployableSnapshot { descriptor, object })
}

async fn descriptor_from_object_with_admission(
    ctx: &mut Ctx,
    release: &Object,
    environment: &str,
    admission: SnapshotAdmission,
) -> CatalogLookupResult<ReleaseDescriptor> {
    if release.kind != KIND_RELEASE {
        return Err(CatalogLookupError::Malformed {
            release_id: release.id.clone(),
            reason: format!("object kind is {}, expected {KIND_RELEASE}", release.kind),
        });
    }
    admit_recall(ctx, release, admission).await?;
    require_deployable_trust(ctx, release, environment)
        .await
        .map_err(|error| CatalogLookupError::TrustDenied {
            release_id: release.id.clone(),
            reason: error.to_string(),
        })?;
    let required = |key| {
        property(&release.properties, key).map_err(|error| CatalogLookupError::Malformed {
            release_id: release.id.clone(),
            reason: error.to_string(),
        })
    };
    Ok(ReleaseDescriptor {
        contract_version: CATALOG_CONTRACT_VERSION,
        release_id: release.id.clone(),
        product: required("product")?.into(),
        version: required("version")?.into(),
        manifest_digest: required("digest")?.into(),
        artifact_digest: required("artifact_digest")?.into(),
        content_path: required("workdir")?.into(),
        provenance: stored_provenance(release).map_err(|error| CatalogLookupError::Malformed {
            release_id: release.id.clone(),
            reason: error.to_string(),
        })?,
    })
}

fn stored_provenance(release: &Object) -> Result<Vec<ProvenanceProjection>> {
    let Some(raw_envelopes) = release.properties.get("provenance_envelopes") else {
        if release.properties.contains_key("provenance_digests")
            || release.properties.contains_key("provenance_projections")
        {
            bail!("stored release provenance properties are incomplete");
        }
        return Ok(Vec::new());
    };
    let envelopes: Vec<ProvenanceEnvelope> = serde_json::from_str(raw_envelopes)?;
    let stored_digests: Vec<String> = serde_json::from_str(
        release
            .properties
            .get("provenance_digests")
            .ok_or_else(|| anyhow::anyhow!("stored release provenance has no digest list"))?,
    )?;
    let stored_projections: Vec<ProvenanceProjection> = serde_json::from_str(
        release
            .properties
            .get("provenance_projections")
            .ok_or_else(|| anyhow::anyhow!("stored release provenance has no projections"))?,
    )?;
    let expected_digests = envelopes
        .iter()
        .map(ProvenanceEnvelope::stored_digest)
        .collect::<Result<Vec<_>>>()?;
    let expected_projections = envelopes
        .iter()
        .map(ProvenanceEnvelope::stored_projection)
        .collect::<Result<Vec<_>>>()?;
    if stored_digests != expected_digests || stored_projections != expected_projections {
        bail!("stored release provenance projections do not match their canonical envelopes");
    }
    Ok(expected_projections)
}

async fn stored_verification_properties(
    ctx: &mut Ctx,
    release: &Object,
) -> Result<HashMap<String, String>> {
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

/// Unsigned releases are a compatibility escape hatch for the built-in local
/// development environment, never an authorization for remote deployment.
pub(super) fn require_deployable_trust_properties(
    properties: &HashMap<String, String>,
    environment: &str,
) -> Result<()> {
    if environment == "local" {
        return Ok(());
    }
    match properties.get("verification_status").map(String::as_str) {
        Some("verified") => Ok(()),
        Some(status) => bail!(
            "release trust status {status:?} is not deployable to non-local environment {environment}"
        ),
        None => bail!(
            "release has no verification evidence and is not deployable to non-local environment {environment}"
        ),
    }
}

pub async fn require_deployable_trust(
    ctx: &mut Ctx,
    release: &Object,
    environment: &str,
) -> Result<()> {
    if environment == "local" {
        return Ok(());
    }
    let properties = stored_verification_properties(ctx, release).await?;
    verification_view(release, &properties)?;
    require_deployable_trust_properties(&properties, environment)
}

pub(super) fn verification_view(
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
            let envelope: release_signing::SignatureEnvelope =
                serde_json::from_str(property(properties, "signature_envelope")?)?;
            let roots = release_signing::TrustRoots {
                version: release_signing::TRUST_ROOT_VERSION,
                signers: vec![release_signing::TrustedSigner {
                    key_id: property(properties, "signer_key_id")?.into(),
                    identity: property(properties, "signer_identity")?.into(),
                    public_key: property(properties, "signer_public_key")?.into(),
                }],
            };
            let evidence = release_signing::verify_release(
                &envelope,
                &roots,
                manifest_digest,
                artifact_digest,
            )?;
            if evidence.statement_digest != property(properties, "signature_statement_digest")? {
                bail!("stored release signature statement digest does not match its envelope");
            }
            let provenance: release_signing::Provenance =
                serde_json::from_str(property(properties, "provenance")?)?;
            if provenance != evidence.provenance {
                bail!("stored release provenance does not match its signed envelope");
            }
            Ok(ReleaseVerificationView {
                release_id: release.id.clone(),
                product: product.into(),
                version: version.into(),
                status: status.into(),
                algorithm: algorithm.into(),
                signer_identity: Some(evidence.signer_identity),
                signer_key_id: Some(evidence.signer_key_id),
                manifest_digest: manifest_digest.into(),
                artifact_digest: artifact_digest.into(),
                statement_digest: Some(evidence.statement_digest),
                provenance: Some(evidence.provenance),
                governance_provenance: stored_provenance(release)?,
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
                governance_provenance: stored_provenance(release)?,
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
    let actual_artifact_digest = manifest::artifact_digest(workdir, &manifest.immutable_inputs())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_development_releases_are_confined_to_local_environment() {
        let unsigned =
            HashMap::from([("verification_status".into(), "unsigned-development".into())]);
        assert!(require_deployable_trust_properties(&unsigned, "local").is_ok());
        assert!(require_deployable_trust_properties(&unsigned, "prod").is_err());
        assert!(require_deployable_trust_properties(&HashMap::new(), "prod").is_err());

        let verified = HashMap::from([("verification_status".into(), "verified".into())]);
        assert!(require_deployable_trust_properties(&verified, "prod").is_ok());
    }

    async fn unsigned_release(ctx: &mut Ctx, recalled: bool) -> Object {
        let mut properties = HashMap::from([
            ("product".into(), "api".into()),
            ("version".into(), "1.0.0".into()),
            ("digest".into(), "a".repeat(64)),
            ("artifact_digest".into(), "b".repeat(64)),
            ("workdir".into(), "/tmp/tenkai-trust-test".into()),
        ]);
        if recalled {
            properties.insert("recalled_at".into(), "1".into());
        }
        let release = object(
            release_id("api", "1.0.0"),
            KIND_RELEASE,
            "api@1.0.0".into(),
            properties,
        );
        ctx.put(release.clone()).await.unwrap();
        let claim_id = release_verification_id(&release.id);
        let claim = object(
            claim_id.clone(),
            KIND_RELEASE_VERIFICATION,
            format!("verification for {}", release.id),
            HashMap::from([
                ("release_id".into(), release.id.clone()),
                ("verification_status".into(), "unsigned-development".into()),
                ("signature_algorithm".into(), "none".into()),
            ]),
        );
        ctx.put(claim).await.unwrap();
        ctx.link(&release.id, &claim_id, REL_HAS_RELEASE_VERIFICATION)
            .await
            .unwrap();
        release
    }

    #[tokio::test]
    async fn deployable_snapshot_admits_unsigned_local_and_rejects_prod_and_recall() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-trust-snapshot-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        unsigned_release(&mut ctx, false).await;

        let snapshot = load_deployable_snapshot(&mut ctx, &release_id("api", "1.0.0"), "local")
            .await
            .unwrap();
        assert_eq!(snapshot.descriptor.product, "api");
        assert_eq!(snapshot.object.kind, KIND_RELEASE);

        let prod = load_deployable_snapshot(&mut ctx, &release_id("api", "1.0.0"), "prod")
            .await
            .unwrap_err();
        assert!(prod.to_string().contains("not deployable"));

        unsigned_release(&mut ctx, true).await;
        let recalled = load_deployable_snapshot(&mut ctx, &release_id("api", "1.0.0"), "local")
            .await
            .unwrap_err();
        assert!(recalled.to_string().contains("recalled"));
        let recovered = load_recoverable_snapshot(&mut ctx, &release_id("api", "1.0.0"), "local")
            .await
            .unwrap();
        assert_eq!(recovered.descriptor.release_id, release_id("api", "1.0.0"));
    }
}

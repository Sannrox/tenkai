//! Family release trains: a signed set of component releases tested together.
//!
//! A train profile (`tenkai.release-train.v1`, for example `train-2026.11`)
//! names every component version and family release digest that passed the
//! family conformance matrix together. [`admit`] verifies the profile against
//! the release trust roots and binds each entry to a published Catalog Release
//! that carries that family release manifest (`catalog publish
//! --family-release`) and a `[compatibility]` profile, its matrix. A train
//! enters the `candidate` channel; [`promote_stable`] is the explicit step to
//! `stable`. When any member carries gate flags, that step also needs an
//! explicit approval, as a flagged release holds a single channel. Trains are
//! immutable once admitted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::auth_context::{AuthenticatedRequestContext, DeliveryCapability};
use crate::client::Ctx;
use crate::ontology::{NS, release_id, validate_identifier};
use crate::pb::sekai::Object;
use crate::release_signing::{SignatureEnvelope, TrustRoots, verify_release};
use crate::signature_verification::validate_prefixed_digest;

pub const SCHEMA: &str = "tenkai.release-train.v1";
pub const TRAIN_KIND: &str = "tenkai.release_train";
const GATE_FLAGS_PROPERTY: &str = "gate_flags";

/// The channel a train is in. Trains only move forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainChannel {
    Candidate,
    Stable,
}

impl TrainChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Stable => "stable",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "candidate" => Ok(Self::Candidate),
            "stable" => Ok(Self::Stable),
            other => bail!("unknown release train channel {other:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    name: String,
    components: Vec<Member>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    component: String,
    version: String,
    /// Digest of the component's admitted family release manifest.
    digest: String,
}

/// An admitted train as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Train {
    pub name: String,
    pub digest: String,
    pub channel: TrainChannel,
    /// `component -> (version, family release digest)`.
    pub components: BTreeMap<String, (String, String)>,
    /// Gate flags carried by any member release, recorded at admission.
    pub gate_flags: BTreeSet<crate::family_release::GateFlag>,
}

/// Inputs to admit a train profile.
pub struct Evidence<'a> {
    pub profile: &'a Path,
    pub signature: &'a Path,
    pub trust_roots: &'a Path,
}

/// Verify and store a train profile in the `candidate` channel. Admitting the
/// same document again is a no-op; a different document under the same name
/// is refused.
pub async fn admit(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    evidence: &Evidence<'_>,
) -> Result<Train> {
    require_publish(actor)?;
    let raw = std::fs::read_to_string(evidence.profile)
        .with_context(|| format!("reading release train {}", evidence.profile.display()))?;
    let profile: Profile = serde_json::from_str(&raw).context("parsing the release train")?;
    validate(&profile)?;
    let digest = crate::manifest::digest(&raw);
    let envelope = SignatureEnvelope::load(evidence.signature)?;
    let roots = TrustRoots::load(evidence.trust_roots)?;
    verify_release(
        &envelope,
        &roots,
        &digest,
        &members_digest(&profile.components),
    )
    .context("verifying the release train signature")?;
    let mut gate_flags = BTreeSet::new();
    for member in &profile.components {
        gate_flags.extend(require_member(ctx, member).await?);
    }

    let id = train_id(&profile.name);
    if let Some(existing) = ctx.get(&id).await? {
        ensure!(
            existing.properties.get("digest") == Some(&digest),
            "release train {} already exists with a different profile; trains are immutable",
            profile.name
        );
        return stored(&existing);
    }
    let now = crate::now_millis();
    let object = Object {
        id,
        kind: TRAIN_KIND.into(),
        name: profile.name.clone(),
        namespace: NS.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("document".into(), raw),
            ("digest".into(), digest),
            ("channel".into(), TrainChannel::Candidate.as_str().into()),
            ("admitted_by".into(), actor.principal_id().to_string()),
            (
                GATE_FLAGS_PROPERTY.into(),
                crate::family_release::join_flags(&gate_flags),
            ),
        ]),
        created: now,
        updated: now,
    };
    match ctx.create_once(object.clone()).await {
        Ok(_) => stored(&object),
        Err(status) if crate::client::is_unique_conflict(&status) => {
            let existing = ctx
                .get(&object.id)
                .await?
                .context("release train appeared concurrently then vanished")?;
            ensure!(
                existing.properties.get("digest") == object.properties.get("digest"),
                "release train {} was concurrently admitted with a different profile",
                object.name
            );
            stored(&existing)
        }
        Err(status) => Err(status.into()),
    }
}

/// Move a `candidate` train to `stable`. Promoting a stable train is a no-op.
/// A train whose members carry gate flags needs `approve_gates`, which records
/// the approving principal; without it the promotion is refused.
pub async fn promote_stable(
    ctx: &mut Ctx,
    actor: &AuthenticatedRequestContext,
    name: &str,
    approve_gates: bool,
) -> Result<Train> {
    require_publish(actor)?;
    validate_identifier("release train", name)?;
    let Some(mut object) = ctx.get(&train_id(name)).await? else {
        bail!("release train {name} is not admitted");
    };
    let train = stored(&object)?;
    if train.channel == TrainChannel::Stable {
        return Ok(train);
    }
    if !train.gate_flags.is_empty() {
        ensure!(
            approve_gates,
            "release train {name} carries gate flags {}; approve them to promote it to stable",
            crate::family_release::join_flags(&train.gate_flags)
        );
        object
            .properties
            .insert("gates_approved_by".into(), actor.principal_id().to_string());
    }
    object
        .properties
        .insert("channel".into(), TrainChannel::Stable.as_str().into());
    object
        .properties
        .insert("promoted_by".into(), actor.principal_id().to_string());
    object.updated = crate::now_millis();
    ctx.put(object.clone()).await?;
    stored(&object)
}

/// Read an admitted train.
pub async fn show(ctx: &mut Ctx, name: &str) -> Result<Train> {
    validate_identifier("release train", name)?;
    let Some(object) = ctx.get(&train_id(name)).await? else {
        bail!("release train {name} is not admitted");
    };
    stored(&object)
}

fn train_id(name: &str) -> String {
    format!("tenkai:release_train:{name}")
}

fn require_publish(actor: &AuthenticatedRequestContext) -> Result<()> {
    actor
        .require_delivery_capability(DeliveryCapability::Publish)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn stored(object: &Object) -> Result<Train> {
    let property = |key: &str| {
        object
            .properties
            .get(key)
            .with_context(|| format!("release train {} has no {key}", object.name))
    };
    let profile: Profile = serde_json::from_str(property("document")?)?;
    Ok(Train {
        name: object.name.clone(),
        digest: property("digest")?.clone(),
        channel: TrainChannel::parse(property("channel")?)?,
        gate_flags: crate::family_release::parse_flags(
            object
                .properties
                .get(GATE_FLAGS_PROPERTY)
                .map(String::as_str)
                .unwrap_or_default(),
        )?,
        components: profile
            .components
            .into_iter()
            .map(|member| (member.component, (member.version, member.digest)))
            .collect(),
    })
}

fn validate(profile: &Profile) -> Result<()> {
    ensure!(
        profile.schema == SCHEMA,
        "release train schema must be {SCHEMA}, got {:?}",
        profile.schema
    );
    validate_identifier("release train", &profile.name)?;
    ensure!(
        !profile.components.is_empty() && profile.components.len() <= 128,
        "release train must name 1..128 components"
    );
    let mut seen = std::collections::BTreeSet::new();
    for member in &profile.components {
        validate_identifier("component", &member.component)?;
        validate_identifier("version", &member.version)?;
        validate_prefixed_digest(
            &format!("component {} digest", member.component),
            &member.digest,
        )?;
        ensure!(
            seen.insert(member.component.as_str()),
            "release train names component {} more than once",
            member.component
        );
    }
    Ok(())
}

/// A member must be a published release admitted with this exact family
/// release manifest and carrying its compatibility matrix. Returns the gate
/// flags the release carries.
async fn require_member(
    ctx: &mut Ctx,
    member: &Member,
) -> Result<BTreeSet<crate::family_release::GateFlag>> {
    let spec = format!("{}@{}", member.component, member.version);
    let Some(release) = ctx
        .get(&release_id(&member.component, &member.version))
        .await?
    else {
        bail!("release train member {spec} is not published");
    };
    let family = release
        .properties
        .get(crate::family_release::DIGEST_PROPERTY)
        .with_context(|| {
            format!("release train member {spec} was published without a family release manifest")
        })?;
    // The stored digest is bare hex; the profile names it as sha256:<hex>.
    ensure!(
        member.digest.strip_prefix("sha256:") == Some(family.as_str()),
        "release train member {spec} names family release digest {}, but the release carries sha256:{family}",
        member.digest
    );
    let manifest = release
        .properties
        .get("manifest")
        .with_context(|| format!("release {spec} has no stored manifest"))?;
    let manifest = crate::manifest::parse_raw(manifest)
        .with_context(|| format!("parsing the stored manifest of {spec}"))?;
    ensure!(
        manifest.compatibility.is_some(),
        "release train member {spec} has no [compatibility] matrix"
    );
    crate::family_release::stored_gate_flags(&release)
}

/// SHA-256 over the sorted `component version digest` lines, so the signature
/// binds the exact member set.
fn members_digest(members: &[Member]) -> String {
    let mut lines: Vec<String> = members
        .iter()
        .map(|member| format!("{} {} {}", member.component, member.version, member.digest))
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in &lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{FamilyReleaseInput, PublishOptions};
    use crate::software_compatibility::{CompatibilityProfile, ComponentPin, ComponentRequirement};
    use std::path::PathBuf;

    /// Unique per process and call, so parallel tests and agents never share files.
    fn scratch(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenkai-release-train-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn matrix(component: &str) -> CompatibilityProfile {
        CompatibilityProfile {
            version: 1,
            components: BTreeMap::from([(
                component.to_string(),
                ComponentRequirement {
                    pin: ComponentPin::Digest(format!("sha256:{}", "c".repeat(64))),
                    requires: BTreeMap::new(),
                    provides: BTreeMap::new(),
                },
            )]),
            capabilities: Vec::new(),
            facts: BTreeMap::new(),
            schema: None,
            max_evidence_age_ms: 60_000,
        }
    }

    /// Publish `component@version` signed, with a family release manifest,
    /// and with a `[compatibility]` matrix when `with_matrix`. Returns the
    /// family release digest as `sha256:<hex>`.
    async fn publish(
        ctx: &mut Ctx,
        dir: &Path,
        component: &str,
        version: &str,
        with_matrix: bool,
        gate_flags: &[&str],
    ) -> String {
        let product = dir.join(format!("{component}-{version}"));
        std::fs::create_dir_all(&product).unwrap();
        let mut manifest = crate::manifest::parse_raw(&format!(
            "[product]\nname = \"{component}\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"
        ))
        .unwrap();
        if with_matrix {
            manifest.compatibility = Some(matrix(component));
        }
        let toml_path = product.join("tenkai.toml");
        std::fs::write(&toml_path, toml::to_string(&manifest).unwrap()).unwrap();
        let signature = product.join("release.sig.json");
        let roots = product.join("trust-roots.toml");
        crate::dev_sign::sign_release(&dir.join("keys"), &toml_path, &signature, &roots).unwrap();

        let family = serde_json::json!({
            "schema": crate::family_release::SCHEMA,
            "component": component,
            "version": version,
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "tag": format!("v{version}"),
            "binaries": [{"name": format!("{component}.tar.gz"), "digest": format!("sha256:{}", "a".repeat(64))}],
            "images": [],
            "gate_flags": gate_flags,
        })
        .to_string();
        let family_path = product.join("family-release.json");
        std::fs::write(&family_path, &family).unwrap();
        let (manifest_digest, contents_digest) =
            crate::family_release::signed_digests(&family).unwrap();
        let family_signature = product.join("family-release.sig.json");
        crate::dev_sign::sign_digests(
            &dir.join("keys"),
            &manifest_digest,
            &contents_digest,
            &family_signature,
            &product.join("family-trust-roots.toml"),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &toml_path,
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(roots),
                family_release: Some(FamilyReleaseInput {
                    manifest: family_path,
                    signature: family_signature,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        format!("sha256:{manifest_digest}")
    }

    /// Write and sign a train profile; returns its evidence paths.
    fn train(
        dir: &Path,
        name: &str,
        members: &[(&str, &str, &str)],
    ) -> (PathBuf, PathBuf, PathBuf) {
        let raw = serde_json::json!({
            "schema": SCHEMA,
            "name": name,
            "components": members
                .iter()
                .map(|(component, version, digest)| serde_json::json!({
                    "component": component, "version": version, "digest": digest,
                }))
                .collect::<Vec<_>>(),
        })
        .to_string();
        let out = dir.join(format!("{name}-{}", crate::manifest::digest(&raw)));
        std::fs::create_dir_all(&out).unwrap();
        let profile_path = out.join("train.json");
        std::fs::write(&profile_path, &raw).unwrap();
        let profile: Profile = serde_json::from_str(&raw).unwrap();
        let signature = out.join("train.sig.json");
        let roots = out.join("trust-roots.toml");
        crate::dev_sign::sign_digests(
            &dir.join("keys"),
            &crate::manifest::digest(&raw),
            &members_digest(&profile.components),
            &signature,
            &roots,
        )
        .unwrap();
        (profile_path, signature, roots)
    }

    async fn admit_paths(ctx: &mut Ctx, paths: &(PathBuf, PathBuf, PathBuf)) -> Result<Train> {
        let actor = crate::auth_context::test_management_context("release-train");
        admit(
            ctx,
            &actor,
            &Evidence {
                profile: &paths.0,
                signature: &paths.1,
                trust_roots: &paths.2,
            },
        )
        .await
    }

    async fn ctx_in(dir: &Path) -> Ctx {
        let mut ctx = Ctx::embedded(dir.join("catalog.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx
    }

    #[tokio::test]
    async fn train_lists_components_by_digest_and_promotes_explicitly() {
        let dir = scratch("promote");
        let mut ctx = ctx_in(&dir).await;
        let actor = crate::auth_context::test_management_context("release-train");
        let kako = publish(&mut ctx, &dir, "kako", "0.2.0", true, &[]).await;
        let rusui = publish(&mut ctx, &dir, "rusui", "1.0.0", true, &[]).await;
        let paths = train(
            &dir,
            "train-2026.11",
            &[("kako", "0.2.0", &kako), ("rusui", "1.0.0", &rusui)],
        );

        let admitted = admit_paths(&mut ctx, &paths).await.unwrap();
        assert_eq!(admitted.channel, TrainChannel::Candidate);
        assert_eq!(admitted.components["kako"], ("0.2.0".into(), kako.clone()));
        assert_eq!(admitted.components["rusui"], ("1.0.0".into(), rusui));
        // Admission alone never reaches stable; re-admitting is a no-op.
        assert_eq!(admit_paths(&mut ctx, &paths).await.unwrap(), admitted);
        assert_eq!(
            show(&mut ctx, "train-2026.11").await.unwrap().channel,
            TrainChannel::Candidate
        );

        let stable = promote_stable(&mut ctx, &actor, "train-2026.11", false)
            .await
            .unwrap();
        assert_eq!(stable.channel, TrainChannel::Stable);
        assert_eq!(stable.components, admitted.components);
        assert_eq!(
            promote_stable(&mut ctx, &actor, "train-2026.11", false)
                .await
                .unwrap(),
            stable
        );

        // Same name, different members: trains are immutable.
        let other = train(&dir, "train-2026.11", &[("kako", "0.2.0", &kako)]);
        let error = admit_paths(&mut ctx, &other).await.unwrap_err();
        assert!(error.to_string().contains("immutable"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn train_with_gate_flagged_member_needs_approval_to_reach_stable() {
        let dir = scratch("gates");
        let mut ctx = ctx_in(&dir).await;
        let actor = crate::auth_context::test_management_context("release-train");
        let kako = publish(&mut ctx, &dir, "kako", "0.3.0", true, &["migration"]).await;
        let paths = train(&dir, "train-2027.01", &[("kako", "0.3.0", &kako)]);
        let admitted = admit_paths(&mut ctx, &paths).await.unwrap();
        assert_eq!(
            admitted.gate_flags,
            BTreeSet::from([crate::family_release::GateFlag::Migration])
        );

        let error = promote_stable(&mut ctx, &actor, "train-2027.01", false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("approve"), "{error}");
        assert_eq!(
            show(&mut ctx, "train-2027.01").await.unwrap().channel,
            TrainChannel::Candidate
        );

        let stable = promote_stable(&mut ctx, &actor, "train-2027.01", true)
            .await
            .unwrap();
        assert_eq!(stable.channel, TrainChannel::Stable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn member_without_matrix_or_matching_digest_is_refused() {
        let dir = scratch("refuse");
        let mut ctx = ctx_in(&dir).await;
        let kako = publish(&mut ctx, &dir, "kako", "0.2.0", true, &[]).await;
        let bare = publish(&mut ctx, &dir, "bare", "1.0.0", false, &[]).await;

        let error = admit_paths(
            &mut ctx,
            &train(
                &dir,
                "train-2026.12",
                &[("kako", "0.2.0", &kako), ("bare", "1.0.0", &bare)],
            ),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("no [compatibility] matrix"),
            "{error}"
        );

        let wrong = format!("sha256:{}", "f".repeat(64));
        let error = admit_paths(
            &mut ctx,
            &train(&dir, "train-2026.12", &[("kako", "0.2.0", &wrong)]),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("family release digest"),
            "{error}"
        );

        let error = admit_paths(
            &mut ctx,
            &train(&dir, "train-2026.12", &[("kako", "9.9.9", &kako)]),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("not published"), "{error}");
        assert!(show(&mut ctx, "train-2026.12").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

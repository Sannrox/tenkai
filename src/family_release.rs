//! Family release manifests admitted alongside a Catalog Release.
//!
//! A component's `v*` workflow emits a `tenkai.family-release-manifest.v1`
//! JSON document: component, version, git SHA, binary and image digests,
//! attestation references, and gate flags. `catalog publish
//! --family-release` verifies it against the publication trust roots, refuses
//! tag-only or `latest` image references, and stores its digest and gate flags
//! on the release. `catalog promote` then holds the target channel for human
//! approval when the release carries any gate flag.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::pb::sekai::Object;
use crate::release_signing::{SignatureEnvelope, TrustRoots, verify_release};
use crate::signature_verification::validate_prefixed_digest;

pub const SCHEMA: &str = "tenkai.family-release-manifest.v1";
/// Release property holding the admitted family manifest digest.
pub const DIGEST_PROPERTY: &str = "family_release_digest";
/// Release property holding the comma-separated gate flags.
pub const GATE_FLAGS_PROPERTY: &str = "family_release_gate_flags";

/// A release marker that requires human approval before a channel serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateFlag {
    Breaking,
    Migration,
    Realm,
}

impl GateFlag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Breaking => "breaking",
            Self::Migration => "migration",
            Self::Realm => "realm",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "breaking" => Ok(Self::Breaking),
            "migration" => Ok(Self::Migration),
            "realm" => Ok(Self::Realm),
            other => bail!("unknown release gate flag {other:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Named {
    name: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema: String,
    component: String,
    version: String,
    git_sha: String,
    tag: Option<String>,
    binaries: Vec<Named>,
    images: Vec<Named>,
    #[serde(default)]
    attestations: Vec<String>,
    #[serde(default)]
    gate_flags: Vec<GateFlag>,
}

/// Inputs to verify a family release manifest at publication.
pub struct Evidence<'a> {
    pub manifest: &'a Path,
    pub signature: &'a Path,
    pub trust_roots: &'a Path,
}

/// A verified family release manifest bound to one Catalog Release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub digest: String,
    pub gate_flags: BTreeSet<GateFlag>,
}

impl Admitted {
    /// Properties stored on the release record.
    pub fn properties(&self) -> HashMap<String, String> {
        HashMap::from([
            (DIGEST_PROPERTY.into(), self.digest.clone()),
            (GATE_FLAGS_PROPERTY.into(), join_flags(&self.gate_flags)),
        ])
    }
}

/// Verify `evidence` for release `product@version`: schema, identity, digests,
/// image references, and a release signature whose manifest digest is the
/// document's SHA-256 and whose artifact digest covers every named digest.
pub fn admit(evidence: &Evidence<'_>, product: &str, version: &str) -> Result<Admitted> {
    let raw = std::fs::read_to_string(evidence.manifest).with_context(|| {
        format!(
            "reading family release manifest {}",
            evidence.manifest.display()
        )
    })?;
    let manifest: Manifest =
        serde_json::from_str(&raw).context("parsing the family release manifest")?;
    validate(&manifest, product, version)?;
    let (digest, contents) = signed_digests(&raw)?;
    let envelope = SignatureEnvelope::load(evidence.signature)?;
    let roots = TrustRoots::load(
        evidence.trust_roots,
        crate::signature_verification::TrustRootKind::Release,
    )?;
    verify_release(&envelope, &roots, &digest, &contents)
        .context("verifying the family release manifest signature")?;
    Ok(Admitted {
        digest,
        gate_flags: manifest.gate_flags.into_iter().collect(),
    })
}

/// Gate flags stored on a release; empty for a release published without a
/// family manifest.
pub fn stored_gate_flags(release: &Object) -> Result<BTreeSet<GateFlag>> {
    parse_flags(
        release
            .properties
            .get(GATE_FLAGS_PROPERTY)
            .map(String::as_str)
            .unwrap_or_default(),
    )
}

/// Parse a comma-separated gate flag list as written by [`join_flags`].
pub(crate) fn parse_flags(value: &str) -> Result<BTreeSet<GateFlag>> {
    value
        .split(',')
        .filter(|flag| !flag.is_empty())
        .map(GateFlag::parse)
        .collect()
}

/// A re-publication must bring the same family manifest as the stored release,
/// or none on both sides: releases are immutable.
pub fn validate_stored(release: &Object, admitted: Option<&Admitted>) -> Result<()> {
    let stored = release.properties.get(DIGEST_PROPERTY);
    match (stored, admitted) {
        (None, None) => Ok(()),
        (Some(stored), Some(admitted)) if *stored == admitted.digest => Ok(()),
        _ => bail!(
            "release {} already exists with a different family release manifest; releases are immutable",
            release.name
        ),
    }
}

/// Channel hold reason for a release that carries gate flags.
pub fn hold_reason(release: &str, flags: &BTreeSet<GateFlag>) -> String {
    format!(
        "release {release} carries gate flags {}; approve before this channel serves it",
        join_flags(flags)
    )
}

pub(crate) fn join_flags(flags: &BTreeSet<GateFlag>) -> String {
    flags
        .iter()
        .map(|flag| flag.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn validate(manifest: &Manifest, product: &str, version: &str) -> Result<()> {
    ensure!(
        manifest.schema == SCHEMA,
        "family release manifest schema must be {SCHEMA}, got {:?}",
        manifest.schema
    );
    ensure!(
        manifest.component == product,
        "family release manifest names component {:?}, but the release is {product}",
        manifest.component
    );
    ensure!(
        manifest.version == version,
        "family release manifest names version {:?}, but the release is {version}",
        manifest.version
    );
    ensure!(
        manifest.git_sha.len() == 40
            && manifest
                .git_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "family release manifest git_sha must be a full lowercase SHA"
    );
    if let Some(tag) = &manifest.tag {
        ensure!(
            *tag == format!("v{version}"),
            "family release manifest tag {tag:?} does not match version {version}"
        );
    }
    ensure!(
        !manifest.binaries.is_empty() || !manifest.images.is_empty(),
        "family release manifest lists no binaries or images"
    );
    for binary in &manifest.binaries {
        ensure!(
            !binary.name.is_empty(),
            "family release binary name must not be empty"
        );
        validate_prefixed_digest(&format!("binary {} digest", binary.name), &binary.digest)?;
    }
    for image in &manifest.images {
        validate_image(image)?;
    }
    for attestation in &manifest.attestations {
        ensure!(
            !attestation.is_empty() && !attestation.chars().any(char::is_control),
            "family release attestation reference must be a non-empty string"
        );
    }
    Ok(())
}

/// Images are admitted by digest only: a `latest` name or a missing or
/// malformed digest is a tag-only reference and is refused.
fn validate_image(image: &Named) -> Result<()> {
    ensure!(
        !image.name.is_empty(),
        "family release image name must not be empty"
    );
    ensure!(
        !image.name.contains('@'),
        "image {:?} must carry its digest in the digest field, not the name",
        image.name
    );
    let tag = image
        .name
        .rsplit_once('/')
        .map_or(image.name.as_str(), |(_, last)| last)
        .rsplit_once(':')
        .map(|(_, tag)| tag);
    ensure!(
        tag != Some("latest"),
        "image {:?} uses the latest tag; admit images by digest",
        image.name
    );
    validate_prefixed_digest(
        &format!(
            "image {} digest (tag-only references are refused)",
            image.name
        ),
        &image.digest,
    )
}

/// The `(manifest digest, artifact digest)` pair a release signature over the
/// family manifest `raw` must carry. Signers and tests use it to sign.
pub(crate) fn signed_digests(raw: &str) -> Result<(String, String)> {
    let manifest: Manifest =
        serde_json::from_str(raw).context("parsing the family release manifest")?;
    Ok((crate::manifest::digest(raw), contents_digest(&manifest)))
}

/// SHA-256 over the sorted `kind name digest` lines of every binary and
/// image, so the signature binds the exact admitted contents.
fn contents_digest(manifest: &Manifest) -> String {
    let mut lines: Vec<String> = manifest
        .binaries
        .iter()
        .map(|item| format!("binary {} {}", item.name, item.digest))
        .chain(
            manifest
                .images
                .iter()
                .map(|item| format!("image {} {}", item.name, item.digest)),
        )
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
    use crate::client::Ctx;
    use crate::delivery_hold::HoldScope;
    use std::path::PathBuf;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn manifest_json(version: &str, image: (&str, &str), flags: &[&str]) -> String {
        serde_json::json!({
            "schema": SCHEMA,
            "component": "family-demo",
            "version": version,
            "git_sha": SHA,
            "tag": format!("v{version}"),
            "binaries": [{"name": "family-demo.tar.gz", "digest": digest('a')}],
            "images": [{"name": image.0, "digest": image.1}],
            "attestations": ["https://example.invalid/attestations/1"],
            "gate_flags": flags,
        })
        .to_string()
    }

    /// Unique per process and call, so parallel tests and agents never share files.
    fn scratch(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenkai-family-release-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write and sign `raw` with the dev key in `dir/keys`; returns
    /// (manifest, signature, trust roots).
    fn signed(dir: &Path, raw: &str) -> (PathBuf, PathBuf, PathBuf) {
        let manifest_path = dir.join("family-release.json");
        std::fs::write(&manifest_path, raw).unwrap();
        let (manifest_digest, contents) = signed_digests(raw).unwrap();
        let signature = dir.join("family-release.sig.json");
        let roots = dir.join("trust-roots.toml");
        crate::dev_sign::sign_digests(
            &dir.join("keys"),
            &manifest_digest,
            &contents,
            &signature,
            &roots,
        )
        .unwrap();
        (manifest_path, signature, roots)
    }

    /// Sign `raw` and admit it as release family-demo@`version`.
    fn admit_raw(raw: &str, version: &str) -> Result<Admitted> {
        let dir = scratch("admit");
        let (manifest, signature, trust_roots) = signed(&dir, raw);
        let result = admit(
            &Evidence {
                manifest: &manifest,
                signature: &signature,
                trust_roots: &trust_roots,
            },
            "family-demo",
            version,
        );
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn digest_pinned_manifest_admits_with_its_gate_flags() {
        let image = ("ghcr.io/sannrox/family-demo:1.0.0", digest('b'));
        let plain = admit_raw(&manifest_json("1.0.0", (image.0, &image.1), &[]), "1.0.0").unwrap();
        assert!(plain.gate_flags.is_empty());
        let flagged = admit_raw(
            &manifest_json("1.0.0", (image.0, &image.1), &["migration", "breaking"]),
            "1.0.0",
        )
        .unwrap();
        assert_eq!(
            flagged.gate_flags,
            BTreeSet::from([GateFlag::Breaking, GateFlag::Migration])
        );
        assert_eq!(
            flagged.properties()[GATE_FLAGS_PROPERTY],
            "breaking,migration"
        );
    }

    /// Release candidates (the v* workflow's `X.Y.Z-rc.N`) admit at their own
    /// version and never stand in for the final, or the final for them.
    #[test]
    fn release_candidate_versions_match_exactly() {
        let image = ("ghcr.io/sannrox/family-demo:1.0.0-rc.1", digest('b'));
        let candidate = manifest_json("1.0.0-rc.1", (image.0, &image.1), &["breaking"]);
        let admitted = admit_raw(&candidate, "1.0.0-rc.1").unwrap();
        assert_eq!(admitted.gate_flags, BTreeSet::from([GateFlag::Breaking]));
        let error = admit_raw(&candidate, "1.0.0").unwrap_err().to_string();
        assert!(error.contains("version"), "{error}");
        let final_release = manifest_json("1.0.0", (image.0, &image.1), &[]);
        let error = admit_raw(&final_release, "1.0.0-rc.1")
            .unwrap_err()
            .to_string();
        assert!(error.contains("version"), "{error}");
    }

    #[test]
    fn latest_and_tag_only_image_references_are_refused() {
        for (name, image_digest, expected) in [
            (
                "ghcr.io/sannrox/family-demo:latest",
                digest('b'),
                "latest tag",
            ),
            (
                "ghcr.io/sannrox/family-demo:1.0.0",
                String::new(),
                "tag-only",
            ),
            (
                "ghcr.io/sannrox/family-demo:1.0.0",
                "1.0.0".into(),
                "tag-only",
            ),
            (
                "ghcr.io/sannrox/family-demo@sha256:abc",
                digest('b'),
                "digest field",
            ),
        ] {
            let error = admit_raw(&manifest_json("1.0.0", (name, &image_digest), &[]), "1.0.0")
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{name}: {error}");
        }
    }

    #[test]
    fn identity_mismatch_and_tampering_are_refused() {
        let image = ("ghcr.io/sannrox/family-demo:1.0.0", digest('b'));
        let error = admit_raw(&manifest_json("2.0.0", (image.0, &image.1), &[]), "1.0.0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("version"), "{error}");

        // A manifest edited after signing no longer matches its signature.
        let dir = scratch("tamper");
        let raw = manifest_json("1.0.0", (image.0, &image.1), &[]);
        let (manifest, signature, trust_roots) = signed(&dir, &raw);
        std::fs::write(&manifest, raw.replace("\"tag\"", "\"tag\" ")).unwrap();
        let error = admit(
            &Evidence {
                manifest: &manifest,
                signature: &signature,
                trust_roots: &trust_roots,
            },
            "family-demo",
            "1.0.0",
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("manifest digest"),
            "{error:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn temp_ctx(dir: &Path) -> Ctx {
        let mut ctx = Ctx::embedded(dir.join("catalog.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx
    }

    /// Publish family-demo@`version` signed, with a family manifest carrying
    /// `flags`, from `dir`. Signatures are written once per version and flag
    /// set and reused, so a re-publication brings identical evidence.
    async fn publish(ctx: &mut Ctx, dir: &Path, version: &str, flags: &[&str]) -> Result<()> {
        let product = dir.join(format!("product-{version}"));
        let toml = product.join("tenkai.toml");
        let signature = product.join("release.sig.json");
        let roots = product.join("trust-roots.toml");
        if !toml.exists() {
            std::fs::create_dir_all(&product).unwrap();
            std::fs::write(
                &toml,
                format!("[product]\nname = \"family-demo\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"),
            )
            .unwrap();
            crate::dev_sign::sign_release(&dir.join("keys"), &toml, &signature, &roots).unwrap();
        }
        let family_dir = product.join(format!("family-{}", flags.join("-")));
        std::fs::create_dir_all(&family_dir).unwrap();
        let image = digest('b');
        let raw = manifest_json(version, ("ghcr.io/sannrox/family-demo:1", &image), flags);
        let family_path = family_dir.join("family-release.json");
        std::fs::write(&family_path, &raw).unwrap();
        let parsed: Manifest = serde_json::from_str(&raw).unwrap();
        let family_signature = family_dir.join("family-release.sig.json");
        if !family_signature.exists() {
            crate::dev_sign::sign_digests(
                &dir.join("keys"),
                &crate::manifest::digest(&raw),
                &contents_digest(&parsed),
                &family_signature,
                &family_dir.join("trust-roots.toml"),
            )
            .unwrap();
        }
        let options = PublishOptions {
            signature: Some(signature),
            trust_roots: Some(roots),
            family_release: Some(FamilyReleaseInput {
                manifest: family_path,
                signature: family_signature,
            }),
            ..Default::default()
        };
        crate::catalog::publish(ctx, &toml, &options)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn promote_holds_the_channel_for_a_flagged_release_only() {
        let dir = scratch("promote");
        let mut ctx = temp_ctx(&dir).await;
        let actor = crate::auth_context::test_management_context("family-promote");
        publish(&mut ctx, &dir, "1.0.0", &[]).await.unwrap();
        publish(&mut ctx, &dir, "1.1.0", &["migration"])
            .await
            .unwrap();

        crate::catalog::promote(&mut ctx, &actor, "family-demo@1.0.0", "candidate")
            .await
            .unwrap();
        let scope = HoldScope::channel("family-demo", "candidate");
        assert_eq!(
            crate::delivery_hold::get(&mut ctx, &scope).await.unwrap(),
            None
        );

        crate::catalog::promote(&mut ctx, &actor, "family-demo@1.1.0", "candidate")
            .await
            .unwrap();
        let hold = crate::delivery_hold::get(&mut ctx, &scope)
            .await
            .unwrap()
            .expect("a migration-flagged release holds the channel");
        assert!(hold.reason.contains("family-demo@1.1.0"), "{}", hold.reason);
        assert!(hold.reason.contains("migration"), "{}", hold.reason);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn republishing_with_a_different_family_manifest_is_refused() {
        let dir = scratch("immutable");
        let mut ctx = temp_ctx(&dir).await;
        publish(&mut ctx, &dir, "1.0.0", &[]).await.unwrap();
        publish(&mut ctx, &dir, "1.0.0", &[]).await.unwrap();
        let error = publish(&mut ctx, &dir, "1.0.0", &["realm"])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("immutable"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

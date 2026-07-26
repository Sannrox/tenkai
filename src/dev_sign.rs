//! Development-only release signing and plan-approval helpers (#149).
//!
//! **Not production KMS.** Keys live in an operator-chosen directory (default
//! `.tenkai-dev-keys/`). Private keys are never printed to stdout.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::client::Ctx;
use crate::manifest::{self, artifact_digest, digest as manifest_digest};
use crate::plan;
use crate::plan_approval::{
    APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, canonical_bytes,
    verify as verify_plan_approval,
};
use crate::release_signing::{
    ENVELOPE_SCHEMA, Provenance, ReleaseStatement, SignatureEnvelope, TRUST_ROOT_VERSION,
    TrustRoots as ReleaseTrustRoots, key_id, verify_release,
};

/// Default relative directory for laptop dogfood keys (gitignored recommended).
pub const DEFAULT_DEV_KEYS_DIR: &str = ".tenkai-dev-keys";

const RELEASE_KEY_FILE: &str = "release.ed25519";
const APPROVAL_KEY_FILE: &str = "approval.ed25519";
const WARNING: &str =
    "WARNING: development-only keys (not production KMS). Keep private key files offline.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenPaths {
    pub trust_roots: PathBuf,
    pub envelope: PathBuf,
}

/// Ensure a keys directory exists and contains release + approval private keys.
///
/// Private keys are 32 raw bytes at mode `0600`. Public material is never written
/// here (trust-roots are written next to signatures when signing).
pub fn init_dev_keys(dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(dir)
        .with_context(|| format!("creating dev keys directory {}", dir.display()))?;
    ensure_key_file(&dir.join(RELEASE_KEY_FILE))?;
    ensure_key_file(&dir.join(APPROVAL_KEY_FILE))?;
    let readme = dir.join("README.txt");
    if !readme.exists() {
        fs::write(
            &readme,
            format!(
                "{WARNING}\n\
                 Files:\n\
                 - {RELEASE_KEY_FILE}: Ed25519 seed for release signatures\n\
                 - {APPROVAL_KEY_FILE}: Ed25519 seed for plan approvals\n\
                 Never commit these files. Never pass private keys on argv.\n"
            ),
        )?;
    }
    Ok(dir.to_path_buf())
}

fn ensure_key_file(path: &Path) -> Result<()> {
    if path.exists() {
        validate_existing_key_file(path)?;
        return Ok(());
    }
    let mut seed = [0_u8; 32];
    random_seed(&mut seed)?;
    write_private_seed(path, &seed)?;
    Ok(())
}

fn validate_existing_key_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting private key {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "private key {} must not be a symlink (dev signing refuses followable key paths)",
            path.display()
        );
    }
    if !meta.file_type().is_file() {
        bail!("private key {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "private key {} must be mode 0600 (or owner-only); found {:o}",
                path.display(),
                mode
            );
        }
    }
    if meta.len() != 32 {
        bail!(
            "private key {} must be exactly 32 bytes (got {})",
            path.display(),
            meta.len()
        );
    }
    Ok(())
}

fn write_private_seed(path: &Path, seed: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating private key {}", path.display()))?;
        file.write_all(seed)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, seed)
            .with_context(|| format!("creating private key {}", path.display()))?;
    }
    Ok(())
}

fn load_private_seed(path: &Path) -> Result<[u8; 32]> {
    validate_existing_key_file(path)?;
    let bytes =
        fs::read(path).with_context(|| format!("reading private key {}", path.display()))?;
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn random_seed(buf: &mut [u8; 32]) -> Result<()> {
    let mut f = fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    f.read_exact(buf)?;
    Ok(())
}

fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

fn trust_roots_toml(key_id: &str, identity: &str, public_key_b64: &str) -> String {
    format!(
        r#"version = {TRUST_ROOT_VERSION}

[[signers]]
key_id = "{key_id}"
identity = "{identity}"
public_key = "{public_key_b64}"
"#
    )
}

/// Best-effort absolute path for collision checks (does not require the path to exist).
fn abs_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// True when two paths refer to the same filesystem object (same path, symlink target, or inode).
fn paths_alias(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let a_abs = abs_path(a);
    let b_abs = abs_path(b);
    if a_abs == b_abs {
        return true;
    }
    // Compare after symlink resolution when both exist.
    if let (Ok(ca), Ok(cb)) = (a_abs.canonicalize(), b_abs.canonicalize())
        && ca == cb
    {
        return true;
    }
    // Hard-link / same-inode detection when both exist as files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if let (Ok(ma), Ok(mb)) = (fs::metadata(&a_abs), fs::metadata(&b_abs))
            && ma.is_file()
            && mb.is_file()
            && ma.dev() == mb.dev()
            && ma.ino() == mb.ino()
        {
            return true;
        }
    }
    false
}

/// Reject output paths that collide with each other or with private key files.
fn reject_output_path_collisions(
    keys_dir: &Path,
    envelope_out: &Path,
    trust_roots_out: &Path,
) -> Result<()> {
    if paths_alias(envelope_out, trust_roots_out) {
        bail!(
            "signature/approval output and trust-roots output must be distinct paths (got both {})",
            envelope_out.display()
        );
    }
    let protected = [
        keys_dir.join(RELEASE_KEY_FILE),
        keys_dir.join(APPROVAL_KEY_FILE),
    ];
    for out in [envelope_out, trust_roots_out] {
        for key_path in &protected {
            if paths_alias(out, key_path) {
                bail!(
                    "refusing to write {} over private key file {}",
                    out.display(),
                    key_path.display()
                );
            }
        }
    }
    Ok(())
}

/// Sign a release for `manifest_path` using keys in `keys_dir`.
pub fn sign_release(
    keys_dir: &Path,
    manifest_path: &Path,
    signature_out: &Path,
    trust_roots_out: &Path,
) -> Result<WrittenPaths> {
    init_dev_keys(keys_dir)?;
    reject_output_path_collisions(keys_dir, signature_out, trust_roots_out)?;
    let seed = load_private_seed(&keys_dir.join(RELEASE_KEY_FILE))?;
    let signing_key = signing_key_from_seed(&seed);
    let public = signing_key.verifying_key().to_bytes();
    let kid = key_id(&public);

    let loaded = manifest::load(manifest_path)?;
    let raw = fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let m_digest = manifest_digest(&raw);
    let a_digest = artifact_digest(&loaded.workdir, &loaded.manifest.immutable_inputs())?;

    let roots = trust_roots_toml(&kid, "dogfood-release@localhost", &STANDARD.encode(public));
    write_text_owner_only(trust_roots_out, &roots)?;

    let mut envelope = SignatureEnvelope {
        schema: ENVELOPE_SCHEMA.into(),
        key_id: kid,
        statement: ReleaseStatement {
            manifest_digest: m_digest.clone(),
            artifact_digest: a_digest.clone(),
            provenance: Provenance {
                source_uri: "https://github.com/Sannrox/tenkai".into(),
                revision: "dogfood".into(),
                builder: "tenkaictl-dev-sign-release".into(),
                built_at_unix_ms: crate::now_millis(),
                materials: Default::default(),
            },
        },
        signature: String::new(),
    };
    let signed_bytes = envelope.signed_bytes()?;
    let signature = signing_key.sign(&signed_bytes);
    envelope.signature = STANDARD.encode(signature.to_bytes());
    envelope.validate()?;
    write_text_owner_only(signature_out, &serde_json::to_string_pretty(&envelope)?)?;

    // Fail closed: envelope must verify against the trust roots we just wrote.
    let roots = ReleaseTrustRoots::load(trust_roots_out)?;
    verify_release(&envelope, &roots, &m_digest, &a_digest)?;

    Ok(WrittenPaths {
        trust_roots: trust_roots_out.to_path_buf(),
        envelope: signature_out.to_path_buf(),
    })
}

/// Sign a plan approval for `plan_id` loaded from embedded `database`.
pub async fn sign_plan_approval(
    keys_dir: &Path,
    database: &Path,
    plan_id: &str,
    approval_out: &Path,
    trust_roots_out: &Path,
    ttl_secs: i64,
) -> Result<WrittenPaths> {
    if ttl_secs <= 0 {
        bail!("approval ttl_secs must be positive");
    }
    let ttl_ms = ttl_secs
        .checked_mul(1000)
        .ok_or_else(|| anyhow::anyhow!("approval ttl_secs is too large (overflow)"))?;
    init_dev_keys(keys_dir)?;
    reject_output_path_collisions(keys_dir, approval_out, trust_roots_out)?;
    let seed = load_private_seed(&keys_dir.join(APPROVAL_KEY_FILE))?;
    let signing_key = signing_key_from_seed(&seed);
    let public = signing_key.verifying_key().to_bytes();
    let kid = key_id(&public);

    let mut ctx = Ctx::embedded(database)?;
    let plan = plan::load(&mut ctx, plan_id).await?;
    let plan_digest = format!("sha256:{}", plan.executable_digest()?);

    let roots = trust_roots_toml(&kid, "dogfood-approver@localhost", &STANDARD.encode(public));
    write_text_owner_only(trust_roots_out, &roots)?;

    let now = crate::now_millis();
    let expires_at = now
        .checked_add(ttl_ms)
        .ok_or_else(|| anyhow::anyhow!("approval expiry overflow; reduce --ttl-secs"))?;
    let statement = ApprovalStatement {
        plan_digest,
        environment: plan.environment.clone(),
        purpose: "execute_plan".into(),
        skip_gates: false,
        issued_at: now,
        expires_at,
        policy_provider: "builtin".into(),
        policy_evidence_id: "dogfood-approve".into(),
        policy_digest: format!("sha256:{}", "a".repeat(64)),
    };
    let bytes = canonical_bytes(&statement)?;
    let signature = signing_key.sign(&bytes);
    let envelope = ApprovalEnvelope {
        schema: APPROVAL_SCHEMA.into(),
        key_id: kid,
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    };
    write_text_owner_only(approval_out, &serde_json::to_string_pretty(&envelope)?)?;
    verify_plan_approval(&plan, approval_out, trust_roots_out, now + 1, false)?;

    Ok(WrittenPaths {
        trust_roots: trust_roots_out.to_path_buf(),
        envelope: approval_out.to_path_buf(),
    })
}

/// Write text without following symlinks; owner-only mode on Unix (0600).
///
/// Rejects an existing symlink target so a pre-planted `/tmp/...` link cannot
/// redirect the write. Uses create+truncate on a non-symlink path only.
fn write_text_owner_only(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent for {}", path.display()))?;
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to write through symlink {} (remove it or choose another path)",
                path.display()
            );
        }
        if !meta.file_type().is_file() {
            bail!("refusing to write {}: not a regular file", path.display());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        // O_NOFOLLOW refuses opening a symlink even if one appears after the check.
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        opts.custom_flags(libc::O_NOFOLLOW);
        opts.mode(0o600);
        match opts.open(path) {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())
                    .with_context(|| format!("writing {}", path.display()))?;
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                bail!(
                    "refusing to write through symlink {} (remove it or choose another path)",
                    path.display()
                );
            }
            Err(err) => {
                return Err(err).with_context(|| format!("writing {}", path.display()));
            }
        }
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

pub fn warning_line() -> &'static str {
    WARNING
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Action, Step, create_from_steps};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-dev-sign-{name}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn init_keys_and_sign_release_verifies() {
        let root = temp_dir("release");
        let keys = root.join("keys");
        init_dev_keys(&keys).unwrap();
        assert!(keys.join(RELEASE_KEY_FILE).exists());
        assert!(keys.join(APPROVAL_KEY_FILE).exists());

        // Minimal software product workdir
        let product = root.join("product");
        fs::create_dir_all(product.join("manifests")).unwrap();
        fs::write(
            product.join("manifests/app.yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        )
        .unwrap();
        let manifest = product.join("tenkai.toml");
        fs::write(
            &manifest,
            r#"
[product]
name = "demo"
version = "0.1.0"

[deploy]
workdir = "."
install = "true"
inputs = ["manifests"]
"#,
        )
        .unwrap();

        let sig = root.join("rel.sig.json");
        let trust = root.join("rel-trust.toml");
        let written = sign_release(&keys, &manifest, &sig, &trust).unwrap();
        assert!(written.envelope.exists());
        assert!(written.trust_roots.exists());
        let body = fs::read_to_string(&sig).unwrap();
        assert!(!body.contains("private"));
        assert!(body.contains(ENVELOPE_SCHEMA));
        let trust_body = fs::read_to_string(&trust).unwrap();
        assert!(trust_body.contains("dogfood-release@localhost"));
        // Envelope must not embed the raw private seed bytes as text.
        let seed = load_private_seed(&keys.join(RELEASE_KEY_FILE)).unwrap();
        let seed_b64 = STANDARD.encode(seed);
        assert!(!body.contains(&seed_b64));
        assert!(!trust_body.contains(&seed_b64));

        // Colliding outputs / private-key overwrite must fail closed.
        let same = root.join("same-out");
        let err = sign_release(&keys, &manifest, &same, &same)
            .unwrap_err()
            .to_string();
        assert!(err.contains("distinct"), "{err}");
        let key_path = keys.join(RELEASE_KEY_FILE);
        let err = sign_release(&keys, &manifest, &key_path, &trust)
            .unwrap_err()
            .to_string();
        assert!(err.contains("private key"), "{err}");
        // Seed file must still be intact after the rejected attempt.
        assert_eq!(load_private_seed(&key_path).unwrap(), seed);

        // Symlinked output path must be refused (no follow).
        #[cfg(unix)]
        {
            let link = root.join("sig-link.json");
            let victim = root.join("victim.txt");
            fs::write(&victim, "keep-me").unwrap();
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            let trust2 = root.join("trust2.toml");
            let err = sign_release(&keys, &manifest, &link, &trust2)
                .unwrap_err()
                .to_string();
            assert!(err.contains("symlink"), "{err}");
            assert_eq!(fs::read_to_string(&victim).unwrap(), "keep-me");
        }
    }

    #[tokio::test]
    async fn sign_plan_approval_verifies() {
        let root = temp_dir("approval");
        let keys = root.join("keys");
        init_dev_keys(&keys).unwrap();
        let db = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&db).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        plan::env_add(&mut ctx, "stage", "dogfood stage")
            .await
            .unwrap();
        let plan = create_from_steps(
            &mut ctx,
            "stage",
            vec![Step {
                id: "s0".into(),
                order: 0,
                product: "demo".into(),
                action: Action::Install,
                from: None,
                to: "0.1.0".into(),
                release_id: "tenkai:release:demo@0.1.0".into(),
                release_digest: "d".into(),
                artifact_digest: "a".into(),
                workdir: ".".into(),
                restore: None,
            }],
        )
        .await
        .unwrap();

        let approval = root.join("approval.json");
        let trust = root.join("approval-trust.toml");
        let written = sign_plan_approval(&keys, &db, &plan.id, &approval, &trust, 3600)
            .await
            .unwrap();
        assert!(written.envelope.exists());
        let body = fs::read_to_string(&approval).unwrap();
        assert!(body.contains(APPROVAL_SCHEMA));
        assert!(body.contains("stage"));
    }
}

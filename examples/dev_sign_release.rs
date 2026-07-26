//! Development-only helper: emit trust-roots TOML + detached release signature.
//!
//! ```text
//! cargo run --example dev_sign_release -- \
//!   examples/hello-minikube/tenkai.toml \
//!   /tmp/dogfood-trust.toml \
//!   /tmp/dogfood.sig.json
//! ```
//!
//! Not for production key management. Keys are generated ephemerally unless
//! `TENKAI_DEV_SIGNING_SEED` is a 64-char hex seed (32 bytes).

use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use tenkai::manifest::{self, artifact_digest, digest as manifest_digest};
use tenkai::release_signing::{
    ENVELOPE_SCHEMA, Provenance, ReleaseStatement, SignatureEnvelope, TRUST_ROOT_VERSION, key_id,
};

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("dev_sign_release: {error:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let manifest_path = PathBuf::from(args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: dev_sign_release <manifest.toml> <trust.toml> <sig.json>")
    })?);
    let trust_path = PathBuf::from(args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: dev_sign_release <manifest.toml> <trust.toml> <sig.json>")
    })?);
    let sig_path = PathBuf::from(args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: dev_sign_release <manifest.toml> <trust.toml> <sig.json>")
    })?);

    let loaded = manifest::load(&manifest_path)?;
    let raw = std::fs::read_to_string(&manifest_path)?;
    let m_digest = manifest_digest(&raw);
    let a_digest = artifact_digest(&loaded.workdir, &loaded.manifest.immutable_inputs())?;

    let signing_key = load_or_generate_key()?;
    let public = signing_key.verifying_key().to_bytes();
    let kid = key_id(&public);

    let roots = format!(
        r#"version = {TRUST_ROOT_VERSION}

[[signers]]
key_id = "{kid}"
identity = "dogfood@localhost"
public_key = "{pk}"
"#,
        pk = STANDARD.encode(public),
    );
    if let Some(parent) = trust_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&trust_path, roots)?;

    let envelope = SignatureEnvelope {
        schema: ENVELOPE_SCHEMA.into(),
        key_id: kid,
        statement: ReleaseStatement {
            manifest_digest: m_digest,
            artifact_digest: a_digest,
            provenance: Provenance {
                source_uri: "https://github.com/Sannrox/tenkai".into(),
                revision: "dogfood".into(),
                builder: "tenkai-dev-sign-release".into(),
                built_at_unix_ms: tenkai::now_millis(),
                materials: Default::default(),
            },
        },
        signature: String::new(),
    };
    let signed_bytes = envelope.signed_bytes()?;
    let signature = signing_key.sign(&signed_bytes);
    let mut envelope = envelope;
    envelope.signature = STANDARD.encode(signature.to_bytes());
    envelope.validate()?;

    if let Some(parent) = sig_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&sig_path, serde_json::to_string_pretty(&envelope)?)?;
    println!("wrote trust roots {}", trust_path.display());
    println!("wrote signature  {}", sig_path.display());
    println!(
        "publish with: tenkaictl publish {} --signature {} --trust-roots {}",
        manifest_path.display(),
        sig_path.display(),
        trust_path.display()
    );
    Ok(())
}

fn load_or_generate_key() -> anyhow::Result<SigningKey> {
    if let Ok(hex) = std::env::var("TENKAI_DEV_SIGNING_SEED") {
        let hex = hex.trim();
        anyhow::ensure!(
            hex.len() == 64,
            "TENKAI_DEV_SIGNING_SEED must be 32-byte hex"
        );
        let mut bytes = [0_u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk)?;
            bytes[i] = u8::from_str_radix(s, 16)?;
        }
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let mut bytes = [0_u8; 32];
    getrandom_fill(&mut bytes)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn getrandom_fill(buf: &mut [u8]) -> anyhow::Result<()> {
    // Prefer OS randomness via /dev/urandom (macOS/Linux dogfood hosts).
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)?;
    Ok(())
}

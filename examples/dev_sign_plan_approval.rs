//! Development-only: sign a plan-approval envelope for non-local apply.
//!
//! ```text
//! cargo run --example dev_sign_plan_approval -- \
//!   --database .tenkai-dogfood-minikube/tenkai.db \
//!   --plan-id 'tenkai:plan:…' \
//!   --trust-roots /tmp/approval-trust.toml \
//!   --out /tmp/approval.json
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey};
use tenkai::client::Ctx;
use tenkai::plan;
use tenkai::plan_approval::{
    APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, canonical_bytes,
};
use tenkai::release_signing::key_id;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    plan_id: String,
    #[arg(long)]
    trust_roots: PathBuf,
    #[arg(long)]
    out: PathBuf,
    /// Approval lifetime in seconds (default 1 hour).
    #[arg(long, default_value_t = 3600)]
    ttl_secs: i64,
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("dev_sign_plan_approval: {error:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut ctx = Ctx::embedded(&args.database)?;
    let plan = plan::load(&mut ctx, &args.plan_id).await?;
    let plan_digest = format!("sha256:{}", plan.executable_digest()?);
    let signing_key = load_or_generate_key()?;
    let public = signing_key.verifying_key().to_bytes();
    let kid = key_id(&public);

    let roots = format!(
        r#"version = 1

[[signers]]
key_id = "{kid}"
identity = "approver@localhost"
public_key = "{pk}"
"#,
        pk = STANDARD.encode(public),
    );
    if let Some(parent) = args.trust_roots.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.trust_roots, roots)?;

    let now = tenkai::now_millis();
    let statement = ApprovalStatement {
        plan_digest,
        environment: plan.environment.clone(),
        purpose: "execute_plan".into(),
        skip_gates: false,
        issued_at: now,
        expires_at: now + args.ttl_secs.saturating_mul(1000),
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
    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.out, serde_json::to_string_pretty(&envelope)?)?;
    println!("wrote approval trust roots {}", args.trust_roots.display());
    println!("wrote approval envelope  {}", args.out.display());
    println!(
        "apply with: tenkaictl --database {} apply {} --approval {} --approval-trust-roots {}",
        args.database.display(),
        args.plan_id,
        args.out.display(),
        args.trust_roots.display()
    );
    Ok(())
}

fn load_or_generate_key() -> anyhow::Result<SigningKey> {
    if let Ok(hex) = std::env::var("TENKAI_DEV_APPROVAL_SEED") {
        let hex = hex.trim();
        anyhow::ensure!(
            hex.len() == 64,
            "TENKAI_DEV_APPROVAL_SEED must be 32-byte hex"
        );
        let mut bytes = [0_u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }
        return Ok(SigningKey::from_bytes(&bytes));
    }
    if let Ok(hex) = std::env::var("TENKAI_DEV_SIGNING_SEED") {
        let hex = hex.trim();
        anyhow::ensure!(
            hex.len() == 64,
            "TENKAI_DEV_SIGNING_SEED must be 32-byte hex"
        );
        let mut bytes = [0_u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let mut bytes = [0_u8; 32];
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(SigningKey::from_bytes(&bytes))
}

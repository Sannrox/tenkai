use std::path::PathBuf;

use clap::Subcommand;
use tenkai::dev_sign;

#[derive(Subcommand)]
pub(crate) enum DevCommand {
    /// Create a local directory of development Ed25519 keys (mode 0600).
    InitKeys {
        /// Directory for private key material (default `.tenkai-dev-keys`).
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        dir: PathBuf,
    },
    /// Sign a release for publish --signature / --trust-roots (dogfood only).
    SignRelease {
        /// Path to tenkai.toml
        manifest: PathBuf,
        /// Keys directory from `dev init-keys`
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        keys: PathBuf,
        /// Output path for detached release signature JSON
        #[arg(long)]
        signature: PathBuf,
        /// Output path for release trust-roots TOML
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Sign a plan approval for apply --approval (dogfood only; non-local envs).
    SignApproval {
        #[arg(required_unless_present = "plan_digest")]
        plan_id: Option<String>,
        /// Content-bound plan digest from remote `plan` when the hub database is not local.
        #[arg(long, requires = "env")]
        plan_digest: Option<String>,
        /// Environment bound into the approval when signing from `--plan-digest`.
        #[arg(long, requires = "plan_digest")]
        env: Option<String>,
        /// Keys directory from `dev init-keys`
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        keys: PathBuf,
        /// Output path for plan-approval JSON envelope
        #[arg(long)]
        approval: PathBuf,
        /// Output path for approval trust-roots TOML
        #[arg(long)]
        trust_roots: PathBuf,
        /// Approval lifetime in seconds
        #[arg(long, default_value_t = 3600)]
        ttl_secs: i64,
    },
    /// Sign a package-migration approval for migrate --approval (dogfood only).
    SignMigrationApproval {
        /// Content-bound migration identity digest from `migrate preview`.
        #[arg(long)]
        identity: String,
        /// Environment bound into the approval statement.
        #[arg(long)]
        env: String,
        /// Keys directory from `dev init-keys`
        #[arg(long, default_value = dev_sign::DEFAULT_DEV_KEYS_DIR)]
        keys: PathBuf,
        /// Output path for package-migration-approval JSON envelope
        #[arg(long)]
        approval: PathBuf,
        /// Output path for approval trust-roots TOML
        #[arg(long)]
        trust_roots: PathBuf,
        /// Approval lifetime in seconds
        #[arg(long, default_value_t = 3600)]
        ttl_secs: i64,
    },
}

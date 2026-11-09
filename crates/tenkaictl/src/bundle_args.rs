use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct BundleBuild {
    /// Catalog identity `product@version`. Repeatable. Required unless
    /// `--hosts-dir` is set for a hosts-only bundle.
    #[arg(long = "release", required_unless_present = "hosts_dir")]
    pub(crate) releases: Vec<String>,
    /// Environment identity bound into the signed statement.
    #[arg(long)]
    pub(crate) env: String,
    /// New archive path; companion chunks are written beside it.
    #[arg(long)]
    pub(crate) out: PathBuf,
    /// Key file (32-byte Ed25519 seed, mode 0600) or `pkcs11:` token locator of the bundle exporter.
    #[arg(long)]
    pub(crate) signing_key: PathBuf,
    /// Public Ed25519 trust roots copied into the archive. Never a seed.
    #[arg(long)]
    pub(crate) trust_roots: PathBuf,
    /// Directory of packaged hosts: `<platform>/{tenkaictl,tenkai-server,tenkai-executor-guard}`.
    /// Required when no `--release` is given.
    #[arg(long, required_unless_present = "releases")]
    pub(crate) hosts_dir: Option<PathBuf>,
    /// Host release tag recorded next to bundled binaries.
    #[arg(long, requires = "hosts_dir")]
    pub(crate) host_tag: Option<String>,
    /// Host git sha recorded next to bundled binaries.
    #[arg(long, requires = "hosts_dir")]
    pub(crate) host_git_sha: Option<String>,
    /// Host workflow name recorded next to bundled binaries.
    #[arg(long, requires = "hosts_dir")]
    pub(crate) host_workflow: Option<String>,
    /// Issued-at unix milliseconds. Defaults to now. Pin for identical rebuilds.
    #[arg(long)]
    pub(crate) issued_at_unix_ms: Option<i64>,
    /// Expires-at unix milliseconds. Defaults to issued-at plus seven days.
    #[arg(long)]
    pub(crate) expires_at_unix_ms: Option<i64>,
    /// Build a delta against this release (`product@version`), which the
    /// site already holds: its layers and weights are left out.
    #[arg(long)]
    pub(crate) base: Option<String>,
    /// Signed `tenkai.advisory-feed.v1` JSON carried as `advisories/feed.json`.
    #[arg(long)]
    pub(crate) advisory_feed: Option<PathBuf>,
    /// Signed `tenkai.derived-criticality.v2` JSON carried as `criticality/derived.json`.
    #[arg(long)]
    pub(crate) derived_criticality: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum BundleCommand {
    /// Sign one offline bundle from published releases, or a hosts-only bundle.
    Build(Box<BundleBuild>),
    /// Verify a bundle and write its docs to `<out>/<version>/`.
    Docs {
        /// The signed offline bundle archive.
        #[arg(long)]
        bundle: PathBuf,
        /// Public Ed25519 trust roots to verify it against.
        #[arg(long)]
        trust_roots: PathBuf,
        /// Environment identity the bundle was signed for.
        #[arg(long)]
        env: String,
        /// Directory to write the docs under; `<out>/<version>` must not exist.
        #[arg(long)]
        out: PathBuf,
    },
}

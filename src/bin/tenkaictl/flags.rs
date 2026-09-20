use std::path::PathBuf;

use clap::Args;

#[derive(Args, Debug)]
pub(crate) struct ApprovalFileFlags {
    /// Detached signed-approval JSON envelope.
    #[arg(
        long,
        requires = "approval_trust_roots",
        conflicts_with = "allow_unapproved_development"
    )]
    pub(crate) approval: Option<PathBuf>,
    /// Current Ed25519 trust roots for approvers.
    #[arg(
        long,
        requires = "approval",
        conflicts_with = "allow_unapproved_development"
    )]
    pub(crate) approval_trust_roots: Option<PathBuf>,
    /// Explicitly bypass signed approval for the built-in local environment.
    #[arg(long, requires = "development_reason")]
    pub(crate) allow_unapproved_development: bool,
    /// Audited justification for the local-development bypass.
    #[arg(long, requires = "allow_unapproved_development")]
    pub(crate) development_reason: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct ApprovalDirFlags {
    /// Directory of detached signed-approval JSON envelopes.
    #[arg(
        long,
        requires = "approval_trust_roots",
        conflicts_with = "allow_unapproved_development"
    )]
    pub(crate) approval_dir: Option<PathBuf>,
    /// Current Ed25519 trust roots for approvers.
    #[arg(
        long,
        requires = "approval_dir",
        conflicts_with = "allow_unapproved_development"
    )]
    pub(crate) approval_trust_roots: Option<PathBuf>,
    /// Explicitly bypass signed approval for the built-in local environment.
    #[arg(long, requires = "development_reason")]
    pub(crate) allow_unapproved_development: bool,
    /// Audited justification for the local-development bypass.
    #[arg(long, requires = "allow_unapproved_development")]
    pub(crate) development_reason: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct DevelopmentBypassFlags {
    /// Explicitly bypass signed approval for the built-in local environment.
    #[arg(long, requires = "development_reason")]
    pub(crate) allow_unapproved_development: bool,
    /// Audited justification for the local-development bypass.
    #[arg(long, requires = "allow_unapproved_development")]
    pub(crate) development_reason: Option<String>,
}

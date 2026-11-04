//! Where the applier keeps things, and the root-owned configuration and
//! trust it reads.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use tenkai::host_apply::{HostApprovalPolicy, HostTrust};

pub const CONFIG_FILE: &str = "host-applier.toml";
pub const RELEASE_TRUST_ROOTS_FILE: &str = "release-trust-roots.toml";
pub const HOST_APPROVAL_POLICY_FILE: &str = "host-approval-policy.toml";
pub const KEY_REVOCATIONS_FILE: &str = "key-revocations.json";
pub const KEY_REVOCATION_TRUST_ROOTS_FILE: &str = "key-revocation-trust-roots.toml";

/// The three root-owned directories. Production uses the defaults; tests
/// point every one at a unique temporary directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplierPaths {
    /// Configuration and trust: `/etc/tenkai`.
    pub config_dir: PathBuf,
    /// Persistent records: `/var/lib/tenkai-host`.
    pub state_dir: PathBuf,
    /// Copies and locks, cleared at boot: `/run/tenkai-host`.
    pub run_dir: PathBuf,
}

impl Default for ApplierPaths {
    fn default() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/tenkai"),
            state_dir: PathBuf::from("/var/lib/tenkai-host"),
            run_dir: PathBuf::from("/run/tenkai-host"),
        }
    }
}

impl ApplierPaths {
    /// Directory an instance's root-owned copy lives in.
    pub fn work_dir(&self, instance: &str) -> PathBuf {
        self.run_dir.join("work").join(instance)
    }
}

/// `host-applier.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplierConfig {
    pub version: u32,
    /// The server-owned directory requests are spooled into, one
    /// subdirectory per instance.
    pub spool_dir: PathBuf,
    /// Wall-clock limit of one command; the process group is killed after it.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    /// Largest total size of one release's copied artifacts.
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    /// Most files and directories one release's artifacts may hold.
    #[serde(default = "default_max_artifact_entries")]
    pub max_artifact_entries: u64,
}

fn default_timeout_seconds() -> u64 {
    30 * 60
}

fn default_max_artifact_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

fn default_max_artifact_entries() -> u64 {
    100_000
}

impl ApplierConfig {
    /// The copy bounds this configuration sets.
    pub fn copy_limits(&self) -> crate::copy::CopyLimits {
        crate::copy::CopyLimits {
            max_bytes: self.max_artifact_bytes,
            max_entries: self.max_artifact_entries,
        }
    }

    pub fn load(paths: &ApplierPaths) -> Result<Self> {
        let path = paths.config_dir.join(CONFIG_FILE);
        let raw = read_trusted(&path)?;
        let config: Self =
            toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        if config.version != 1 {
            bail!("{} must use version 1", path.display());
        }
        if !config.spool_dir.is_absolute() {
            bail!("{} spool_dir must be an absolute path", path.display());
        }
        if config.timeout_seconds == 0
            || config.max_artifact_bytes == 0
            || config.max_artifact_entries == 0
        {
            bail!(
                "{} timeout_seconds, max_artifact_bytes, and max_artifact_entries must be positive",
                path.display()
            );
        }
        Ok(config)
    }
}

/// Load the release trust roots and host approval policy, and apply the
/// installed revocation list to this process (ADR 0036). Every file must be
/// owned by this process's user (root in production) and not writable by
/// group or others. A revocation list without its authorities fails closed.
pub fn load_trust(paths: &ApplierPaths) -> Result<HostTrust> {
    require_trusted(&paths.config_dir)?;
    let release_path = paths.config_dir.join(RELEASE_TRUST_ROOTS_FILE);
    let release_roots: tenkai::release_signing::TrustRoots =
        toml::from_str(&read_trusted(&release_path)?)
            .with_context(|| format!("parsing {}", release_path.display()))?;
    release_roots
        .validate()
        .with_context(|| format!("validating {}", release_path.display()))?;
    let policy_path = paths.config_dir.join(HOST_APPROVAL_POLICY_FILE);
    let policy = HostApprovalPolicy::parse(&read_trusted(&policy_path)?)
        .with_context(|| format!("loading {}", policy_path.display()))?;

    let revocations = paths.config_dir.join(KEY_REVOCATIONS_FILE);
    let authorities = paths.config_dir.join(KEY_REVOCATION_TRUST_ROOTS_FILE);
    match (revocations.exists(), authorities.exists()) {
        (true, false) => bail!(
            "{} is installed but {} is missing; cannot verify revocations",
            revocations.display(),
            authorities.display()
        ),
        (true, true) => {
            require_trusted(&revocations)?;
            let roots: tenkai::release_signing::TrustRoots =
                toml::from_str(&read_trusted(&authorities)?)
                    .with_context(|| format!("parsing {}", authorities.display()))?;
            roots
                .validate()
                .with_context(|| format!("validating {}", authorities.display()))?;
            tenkai::key_revocation::load_installed(&revocations, &roots)?;
        }
        (false, _) => {}
    }
    Ok(HostTrust {
        release_roots,
        policy,
    })
}

fn read_trusted(path: &Path) -> Result<String> {
    require_trusted(path)?;
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Refuse a file or directory another user could have written: it must be
/// owned by this process's effective user and not group- or other-writable.
pub fn require_trusted(path: &Path) -> Result<()> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    if metadata.uid() != euid {
        bail!(
            "{} is owned by uid {}, not by the applier's uid {euid}",
            path.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("{} is writable by group or others", path.display());
    }
    Ok(())
}

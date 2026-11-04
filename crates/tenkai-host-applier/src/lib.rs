//! The root-side applier for privileged host releases (ADR 0041 §2).
//!
//! `tenkai-host-apply@<instance>.service` runs it as root for one spooled
//! request. Intake copies the request into root-owned storage
//! ([`copy::copy_request`]) and verifies only that copy
//! ([`tenkai::host_apply::verify_copied_request`]) against the root-owned
//! trust in the config directory ([`config::load_trust`]).

pub mod config;
pub mod copy;

use anyhow::{Context as _, Result};
use tenkai::host_apply::{HostTrust, VerifiedHostStep};

pub use config::{ApplierConfig, ApplierPaths};
pub use copy::CopiedRequest;

/// A spooled request, copied and verified.
#[derive(Debug)]
pub struct Intake {
    pub copied: CopiedRequest,
    pub verified: VerifiedHostStep,
}

/// Copy `instance` from the spool into a fresh root-owned work directory and
/// verify the copy at `now_ms`. A work directory left by an earlier run of
/// the same instance is discarded first.
pub fn intake(
    paths: &ApplierPaths,
    config: &ApplierConfig,
    trust: &HostTrust,
    instance: &str,
    now_ms: i64,
) -> Result<Intake> {
    tenkai::host_apply::validate_instance_name(instance)?;
    let work = paths.work_dir(instance);
    let parent = work.parent().context("work directory has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    if work.exists() {
        std::fs::remove_dir_all(&work)
            .with_context(|| format!("removing stale {}", work.display()))?;
    }
    let copied = copy::copy_request(
        &config.spool_dir,
        instance,
        &work,
        config.max_artifact_bytes,
    )?;
    let verified = tenkai::host_apply::verify_copied_request(
        &copied.request,
        instance,
        &copied.workdir,
        trust,
        now_ms,
    )?;
    Ok(Intake { copied, verified })
}

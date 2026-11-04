//! The root-side applier for privileged host releases (ADR 0041 §2).
//!
//! `tenkai-host-apply@<instance>.service` runs it as root for one spooled
//! request ([`apply`]); see `docs/host-releases.md`. Intake copies the request into root-owned storage
//! ([`copy::copy_request`]), verifies only that copy
//! ([`tenkai::host_apply::verify_request`]) against the root-owned trust in
//! the config directory ([`config::load_trust`]), and only then copies and
//! checks the release workdir. A verified step then passes the per-product
//! critical section ([`store::admit`]) before its command runs, and its
//! result is recorded durably ([`store::Running::finish`]).

mod apply;
pub mod config;
pub mod copy;
pub mod run;
pub mod store;

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use tenkai::host_apply::{HostApplyRequest, HostTrust, VerifiedHostStep};

pub use apply::{Applied, apply};
pub use config::{ApplierConfig, ApplierPaths};

/// A spooled request, copied and verified.
#[derive(Debug)]
pub struct Intake {
    pub request: HostApplyRequest,
    /// The copied release workdir the command runs in.
    pub workdir: PathBuf,
    pub verified: VerifiedHostStep,
}

/// Copy `instance` from the spool into a fresh root-owned work directory and
/// verify the copy at `now_ms`: the request first, and only once it verified
/// the release workdir. A work directory left by an earlier run of the same
/// instance is discarded first; a failed intake removes its own.
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
    discard_work(&work)?;
    let result = (|| {
        let spooled = copy::copy_request(&config.spool_dir, instance, &work)?;
        let verified =
            tenkai::host_apply::verify_request(&spooled.request, instance, trust, now_ms)?;
        let workdir = spooled.copy_artifacts(&verified.inputs, config.copy_limits())?;
        verified.verify_artifacts(&workdir)?;
        Ok(Intake {
            request: spooled.request,
            workdir,
            verified,
        })
    })();
    if result.is_err() {
        discard_work(&work)?;
    }
    result
}

/// Remove an instance's root-owned copy, if there is one.
pub fn discard_work(work: &Path) -> Result<()> {
    match std::fs::remove_dir_all(work) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", work.display())),
    }
}

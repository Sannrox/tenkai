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
pub mod fence;
pub mod run;
pub mod secrets;
pub mod store;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
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
    /// The step's sealed values, bound to its approved slots and held only
    /// in memory until they are written ([`secrets::write`]).
    pub secrets: Vec<tenkai::host_apply::sealed::BoundSecret>,
    /// The workload certificate the step installs, bound to its approved
    /// grant ([`secrets::write_identity`]).
    pub identity: Option<tenkai::workload_identity::IssuedIdentity>,
}

/// Copy `instance` from the spool into an empty root-owned work directory and
/// verify the copy at `now_ms`: the request first, and only once it verified
/// the release workdir. Whatever an earlier run of the same instance left in
/// the work directory is discarded first; a failed intake empties its own.
pub fn intake(
    paths: &ApplierPaths,
    config: &ApplierConfig,
    trust: &HostTrust,
    instance: &str,
    now_ms: i64,
) -> Result<Intake> {
    tenkai::host_apply::validate_instance_name(instance)?;
    let work = paths.work_dir(instance);
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))?;
    empty_dir(&work)?;
    let result = (|| {
        let spooled = copy::copy_request(&config.spool_dir, instance, &work)?;
        let verified =
            tenkai::host_apply::verify_request(&spooled.request, instance, trust, now_ms)?;
        // A step writes exactly the sealed values and the workload
        // certificate its approved plan names.
        let (secrets, identity) = match spooled.read_sealed()? {
            None if !verified.sealed.is_empty() => {
                bail!("the approved step writes sealed values, and none were spooled")
            }
            None if verified.identity.is_some() => {
                bail!("the approved step grants a workload certificate, and none was spooled")
            }
            None => (Vec::new(), None),
            Some(values) => {
                let instance = if verified.product_instance.is_empty() {
                    &verified.product
                } else {
                    &verified.product_instance
                };
                let secrets = values.bind(&verified.environment, instance, &verified.sealed)?;
                (secrets, values.bind_identity(verified.identity.as_ref())?)
            }
        };
        let workdir = spooled.copy_artifacts(&verified.inputs, config.copy_limits())?;
        verified.verify_artifacts(&workdir)?;
        Ok(Intake {
            request: spooled.request,
            workdir,
            verified,
            secrets,
            identity,
        })
    })();
    if result.is_err() {
        discard_work(&work)?;
    }
    result
}

/// Remove an instance's root-owned copy, if there is one. Under the unit the
/// work directory is its `RuntimeDirectory=`, a mount point systemd removes
/// when the unit stops, so only its contents go here.
pub fn discard_work(work: &Path) -> Result<()> {
    if !work.exists() {
        return Ok(());
    }
    empty_dir(work)?;
    match std::fs::remove_dir(work) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ResourceBusy
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("removing {}", work.display())),
    }
}

/// Remove everything inside `dir`, which is root-owned.
fn empty_dir(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        }
        .with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

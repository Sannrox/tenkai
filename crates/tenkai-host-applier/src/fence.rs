//! Fencing across the applier's own death (ADR 0041 §2).
//!
//! The per-product lock is an `flock` the applier holds, so it is released
//! when the applier dies, while the command it started may still run. Under
//! `tenkai-host-apply@.service` the applier and everything it started share
//! the unit's control group. A start records that group, and a start without
//! a result is settled as interrupted only once the group holds no process
//! but the settling applier: until then the product admits nothing.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use tenkai::host_apply::state::HostApplyStarted;

/// Where the cgroup v2 hierarchy is mounted.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The applier's own cgroup v2 path when it runs as an instance of
/// `tenkai-host-apply@.service` (Linux). Anywhere else, such as a shell or a
/// test, the group holds unrelated processes and nothing is recorded.
pub fn own_cgroup() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = raw.lines().find_map(|line| line.strip_prefix("0::"))?;
    is_unit_group(path).then(|| path.to_owned())
}

/// A cgroup v2 path whose last component is an instance of the unit.
pub fn is_unit_group(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("..")
        && path
            .rsplit('/')
            .next()
            .and_then(|unit| unit.strip_prefix("tenkai-host-apply@"))
            .and_then(|unit| unit.strip_suffix(".service"))
            .is_some_and(|instance| tenkai::host_apply::validate_instance_name(instance).is_ok())
}

/// Refuse while `started`'s control group under `root` still holds a process
/// other than this applier. A group that no longer exists is empty; a start
/// that recorded no group (outside the unit) has nothing to check.
pub fn execution_gone(root: &Path, started: &HostApplyStarted) -> Result<()> {
    let Some(group) = &started.cgroup else {
        return Ok(());
    };
    if !is_unit_group(group) {
        bail!("recorded control group {group} is not an instance of tenkai-host-apply@.service");
    }
    let procs = root
        .join(group.trim_start_matches('/'))
        .join("cgroup.procs");
    let listed = match std::fs::read_to_string(&procs) {
        Ok(listed) => listed,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", procs.display()));
        }
    };
    let me = std::process::id().to_string();
    if listed.lines().any(|pid| !pid.is_empty() && pid != me) {
        bail!(
            "step {} of {} in {} was interrupted, but processes it started are still running in {group}; the product admits nothing until they are gone",
            started.instance,
            started.product,
            started.environment
        );
    }
    Ok(())
}

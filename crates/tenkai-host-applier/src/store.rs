//! Durable applier state and the per-product critical section (ADR 0041 §2).
//!
//! Records live under the persistent state directory and are replaced
//! atomically (write, fsync, rename, fsync the directory). The per-product
//! lock lives under the run directory and is an `flock`, so a crashed
//! applier never leaves it held. Every decision is made under that lock from
//! the records alone, so a restart, a reboot, or a replayed request reaches
//! the same answer.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tenkai::host_apply::state::{
    AppliedStateRecord, HostApplyOutcome, HostApplyResult, HostApplyStarted, RESULT_FILE,
    STARTED_FILE, instance_dir, record_path,
};
use tenkai::host_apply::{VerifiedHostStep, product_key};

use crate::ApplierPaths;

/// The recorded result of `instance`, if it completed. Needs no lock: a
/// result file is written once and never changes.
pub fn recorded_result(paths: &ApplierPaths, instance: &str) -> Result<Option<HostApplyResult>> {
    tenkai::host_apply::validate_instance_name(instance)?;
    read_json(&instance_dir(&paths.state_dir, instance).join(RESULT_FILE))
}

/// What the critical section decided for one verified step.
#[derive(Debug)]
pub enum Admission {
    /// The instance already started once; this is how it ended.
    Recorded(HostApplyResult),
    /// Admitted and durably started: run the command, then [`Running::finish`].
    Run(Box<Running>),
}

/// An admitted step. Holds the product lock until it is finished or dropped;
/// dropping it without finishing is a crash, which the next admission for
/// the product resolves as interrupted.
#[derive(Debug)]
pub struct Running {
    paths: ApplierPaths,
    started: HostApplyStarted,
    /// The advanced record, for an install or uninstall.
    record: Option<AppliedStateRecord>,
    _lock: OwnedFd,
}

impl Running {
    pub fn started(&self) -> &HostApplyStarted {
        &self.started
    }

    /// Durably record how the command ended and release the lock. The
    /// product record moves to `applied` or `empty` on success and stays
    /// `dirty` otherwise; it is written before the instance's result file so
    /// a crash in between still finds the result in the record.
    pub fn finish(
        self,
        outcome: HostApplyOutcome,
        exit_status: Option<i32>,
        detail: impl Into<String>,
        now_ms: i64,
    ) -> Result<HostApplyResult> {
        let result = self.started.result(outcome, exit_status, detail, now_ms);
        if let Some(record) = &self.record {
            write_record(&self.paths, &record.complete(&self.started, &result))?;
        }
        write_result(&self.paths, &result)?;
        Ok(result)
    }
}

/// The critical section: under the per-product lock, settle the step that
/// last advanced the record, return the recorded result of an instance that
/// already started, then check that the approvals are still valid after the
/// wait for the lock, the generation, source release, and downgrade
/// approvals, and durably write the advanced record and the `started` record
/// before anything runs.
pub fn admit(paths: &ApplierPaths, step: &VerifiedHostStep) -> Result<Admission> {
    let lock = lock_product(paths, &step.environment, &step.product)?;
    let now_ms = tenkai::now_millis();
    let mut record = read_record(paths, &step.environment, &step.product)?;
    settle_last(paths, &mut record, now_ms)?;
    if let Some(result) = recorded_result(paths, &step.instance)? {
        return Ok(Admission::Recorded(result));
    }
    let started_path = instance_dir(&paths.state_dir, &step.instance).join(STARTED_FILE);
    if let Some(started) = read_json::<HostApplyStarted>(&started_path)? {
        // The lock is ours, so whoever started it is gone.
        let result = interrupted(&started, now_ms);
        write_result(paths, &result)?;
        return Ok(Admission::Recorded(result));
    }
    step.approvals.require_unexpired(now_ms)?;
    let (started, advanced) = record.admit(step, now_ms)?;
    if let Some(advanced) = &advanced {
        write_record(paths, advanced)?;
    }
    write_json(&started_path, &started)?;
    Ok(Admission::Run(Box::new(Running {
        paths: paths.clone(),
        started,
        record: advanced,
        _lock: lock,
    })))
}

/// Make sure the install or uninstall that last advanced `record` has a
/// result file: the one its completion recorded, or interrupted.
fn settle_last(paths: &ApplierPaths, record: &mut AppliedStateRecord, now_ms: i64) -> Result<()> {
    let Some(last) = record.last_started.clone() else {
        return Ok(());
    };
    if recorded_result(paths, &last.instance)?.is_some() {
        return Ok(());
    }
    let result = match &record.last_result {
        Some(result) if result.instance == last.instance => result.clone(),
        _ => {
            let result = interrupted(&last, now_ms);
            record.last_result = Some(result.clone());
            write_record(paths, record)?;
            result
        }
    };
    write_result(paths, &result)
}

fn interrupted(started: &HostApplyStarted, now_ms: i64) -> HostApplyResult {
    started.result(
        HostApplyOutcome::Interrupted,
        None,
        "started but never finished: the applier stopped or the host rebooted",
        now_ms,
    )
}

/// The record of one product, or a fresh `empty` one.
pub fn read_record(
    paths: &ApplierPaths,
    environment: &str,
    product: &str,
) -> Result<AppliedStateRecord> {
    let path = record_path(&paths.state_dir, environment, product);
    let record = read_json::<AppliedStateRecord>(&path)?
        .unwrap_or_else(|| AppliedStateRecord::empty(environment, product));
    if record.environment != environment || record.product != product {
        anyhow::bail!("{} belongs to another product", path.display());
    }
    Ok(record)
}

fn write_record(paths: &ApplierPaths, record: &AppliedStateRecord) -> Result<()> {
    write_json(
        &record_path(&paths.state_dir, &record.environment, &record.product),
        record,
    )
}

fn write_result(paths: &ApplierPaths, result: &HostApplyResult) -> Result<()> {
    write_json(
        &instance_dir(&paths.state_dir, &result.instance).join(RESULT_FILE),
        result,
    )
}

/// Take the exclusive per-product lock, waiting for a running step.
fn lock_product(paths: &ApplierPaths, environment: &str, product: &str) -> Result<OwnedFd> {
    let dir = paths.run_dir.join("locks");
    create_dirs(&dir)?;
    let path = dir.join(format!("{}.lock", product_key(environment, product)));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let fd = OwnedFd::from(file);
    rustix::fs::flock(&fd, rustix::fs::FlockOperation::LockExclusive)
        .with_context(|| format!("locking {}", path.display()))?;
    Ok(fd)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("parsing {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Replace `path` atomically and durably, readable by everyone and writable
/// only by the applier.
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().context("record path has no parent")?;
    create_dirs(parent)?;
    let staged: PathBuf = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("record"),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&staged, path).with_context(|| format!("replacing {}", path.display()))?;
    // The rename, and the entry of a directory created for it just now.
    std::fs::File::open(parent)?.sync_all()?;
    if let Some(grandparent) = parent.parent() {
        std::fs::File::open(grandparent)?.sync_all()?;
    }
    Ok(())
}

fn create_dirs(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

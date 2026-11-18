//! Durable applier state and the per-product critical section (ADR 0041 §2).
//!
//! Records live under the persistent state directory and are replaced
//! atomically (write, fsync, rename, fsync the directory). The per-product
//! lock lives under the run directory and is an `flock`, so a crashed
//! applier never leaves it held. Every decision is made under that lock from
//! the records alone, so a restart, a reboot, or a replayed request reaches
//! the same answer.
//!
//! Every step of an OS image release (ADR 0051) acts on the one host-wide
//! OS image record under the one host-wide lock instead ([`Scope`]). Its
//! `reboot` and `confirm` also read what the updater reports, through the
//! root-owned reader ([`crate::os_image`]).

use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tenkai::host_apply::identity::{
    HostIdentityRecord, IDENTITY_RECORD_SCHEMA, identity_record_path,
};
use tenkai::host_apply::os_image::{
    AwaitingBoot, OS_IMAGE_KEY, check_confirmable, confirm_verdict, os_image_record_path,
};
use tenkai::host_apply::state::{
    AppliedStateRecord, HostApplyOutcome, HostApplyRefused, HostApplyResult, HostApplyStarted,
    REFUSED_FILE, REFUSED_SCHEMA, RESULT_FILE, STARTED_FILE, instance_dir, record_path,
};
use tenkai::host_apply::{HostAction, VerifiedHostStep, product_key};

use crate::ApplierPaths;

/// The recorded result of `instance`, if it completed. Needs no lock: a
/// result file is written once and never changes.
pub fn recorded_result(paths: &ApplierPaths, instance: &str) -> Result<Option<HostApplyResult>> {
    tenkai::host_apply::validate_instance_name(instance)?;
    read_json(&instance_dir(&paths.state_dir, instance).join(RESULT_FILE))
}

/// Record why `instance` was refused before anything started. It replaces
/// an earlier refusal and never blocks a later start.
pub fn record_refusal(
    paths: &ApplierPaths,
    instance: &str,
    reason: &str,
    now_ms: i64,
) -> Result<()> {
    tenkai::host_apply::validate_instance_name(instance)?;
    write_json(
        paths,
        &instance_dir(&paths.state_dir, instance).join(REFUSED_FILE),
        &HostApplyRefused {
            schema: REFUSED_SCHEMA.into(),
            instance: instance.into(),
            reason: reason.into(),
            refused_at: now_ms,
        },
    )
}

/// The latest refusal of `instance`, if any.
pub fn refusal(paths: &ApplierPaths, instance: &str) -> Result<Option<HostApplyRefused>> {
    tenkai::host_apply::validate_instance_name(instance)?;
    read_json(&instance_dir(&paths.state_dir, instance).join(REFUSED_FILE))
}

/// How a started instance stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// It ended: its result record.
    Result(HostApplyResult),
    /// A `reboot` that asked the updater to reboot and waits for the
    /// `verify` that settles it.
    AwaitingBoot(AwaitingBoot),
}

/// How `instance` ended, if it ever started, from root-owned records alone:
/// its result, a `reboot` still awaiting its boot, or, for a start without a
/// result, the result the record kept, the settled `confirm`, or
/// `interrupted`. Runs before any intake, so a crashed instance resolves
/// even when its request is gone or no longer verifies. Waits for the lock
/// when the instance is still running.
pub fn recover(paths: &ApplierPaths, instance: &str) -> Result<Option<Ended>> {
    if let Some(result) = recorded_result(paths, instance)? {
        return Ok(Some(Ended::Result(result)));
    }
    let started_path = instance_dir(&paths.state_dir, instance).join(STARTED_FILE);
    let Some(started) = read_json::<HostApplyStarted>(&started_path)? else {
        return Ok(None);
    };
    let scope = Scope::of_started(&started);
    let _lock = lock(paths, &scope)?;
    let now_ms = tenkai::now_millis();
    let mut record = read_record_in(paths, &scope, &started.environment, &started.product)?;
    settle_last(paths, &scope, &mut record, now_ms)?;
    if let Some(result) = recorded_result(paths, instance)? {
        return Ok(Some(Ended::Result(result)));
    }
    if let Some(awaiting) = awaiting(&record, instance) {
        return Ok(Some(Ended::AwaitingBoot(awaiting.clone())));
    }
    let result = interrupted(&started, now_ms);
    write_result(paths, &result)?;
    Ok(Some(Ended::Result(result)))
}

/// The record's `awaiting_boot`, when it is `instance`'s.
fn awaiting<'a>(record: &'a AppliedStateRecord, instance: &str) -> Option<&'a AwaitingBoot> {
    record
        .awaiting_boot
        .as_ref()
        .filter(|awaiting| awaiting.instance == instance)
}

/// Which applied-state record a step acts on, and the lock that guards it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    /// The record of one environment and product.
    Product {
        environment: String,
        product: String,
    },
    /// The host-wide OS image record (ADR 0051 §2).
    OsImage,
}

impl Scope {
    fn of_step(step: &VerifiedHostStep) -> Self {
        Self::of(step.os_image.is_some(), &step.environment, &step.product)
    }

    fn of_started(started: &HostApplyStarted) -> Self {
        Self::of(
            started.image_digest.is_some(),
            &started.environment,
            &started.product,
        )
    }

    fn of(os_image: bool, environment: &str, product: &str) -> Self {
        if os_image {
            Self::OsImage
        } else {
            Self::Product {
                environment: environment.into(),
                product: product.into(),
            }
        }
    }

    fn path(&self, state_dir: &Path) -> std::path::PathBuf {
        match self {
            Self::Product {
                environment,
                product,
            } => record_path(state_dir, environment, product),
            Self::OsImage => os_image_record_path(state_dir),
        }
    }

    fn lock_name(&self) -> String {
        match self {
            Self::Product {
                environment,
                product,
            } => product_key(environment, product),
            Self::OsImage => OS_IMAGE_KEY.into(),
        }
    }
}

/// What the critical section decided for one verified step.
#[derive(Debug)]
pub enum Admission {
    /// The instance already started once, or settled without a command (a
    /// `verify`); this is how it ended.
    Recorded(HostApplyResult),
    /// The instance is a `reboot` that already asked the updater to reboot.
    AwaitingBoot(AwaitingBoot),
    /// Admitted and durably started: run the command, then [`Running::finish`]
    /// (or, for a `reboot` whose command succeeded, [`Running::await_boot`]).
    Run(Box<Running>),
}

/// An admitted step. Holds the product lock until it is finished or dropped;
/// dropping it without finishing is a crash, which the next admission for
/// the product resolves as interrupted.
#[derive(Debug)]
pub struct Running {
    paths: ApplierPaths,
    scope: Scope,
    started: HostApplyStarted,
    /// The record as it was written when the step started.
    record: AppliedStateRecord,
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
        write_record(
            &self.paths,
            &self.scope,
            &self.record.complete(&self.started, &result),
        )?;
        write_result(&self.paths, &result)?;
        Ok(result)
    }

    /// A `reboot` whose command asked the updater to reboot: leave its start
    /// without a result, as `awaiting_boot` expects, and release the lock.
    pub fn await_boot(self) -> Result<AwaitingBoot> {
        awaiting(&self.record, &self.started.instance)
            .cloned()
            .context("only a reboot step awaits a boot")
    }
}

/// The critical section: under the per-product lock (the host-wide lock for
/// an OS image release), settle the step that last advanced the record,
/// return the recorded result of an instance that already started, then
/// recount the approvals still valid after the wait for the lock, check the
/// generation, source release, and downgrade approvals, and durably write
/// the advanced record and the `started` record before anything runs.
///
/// A `reboot` also records `awaiting_boot` with the image booted now; a
/// `confirm` first requires the host to boot the expected image; a `verify`
/// settles the awaiting `reboot` from the image booted now and returns its
/// own result, with no command to run.
pub fn admit(paths: &ApplierPaths, step: &VerifiedHostStep) -> Result<Admission> {
    admit_at(paths, step, tenkai::now_millis())
}

/// [`admit`] as of `now_ms`, the time approvals and settled starts are
/// judged against. Tests pass a fixed time to decide expiry without a sleep.
pub fn admit_at(paths: &ApplierPaths, step: &VerifiedHostStep, now_ms: i64) -> Result<Admission> {
    let scope = Scope::of_step(step);
    let os_image = match scope {
        Scope::OsImage => Some(crate::ApplierConfig::load(paths)?.os_image()?.clone()),
        Scope::Product { .. } => None,
    };
    let lock = lock(paths, &scope)?;
    let mut record = read_record_in(paths, &scope, &step.environment, &step.product)?;
    settle_last(paths, &scope, &mut record, now_ms)?;
    if let Some(result) = recorded_result(paths, &step.instance)? {
        return Ok(Admission::Recorded(result));
    }
    if let Some(awaiting) = awaiting(&record, &step.instance) {
        return Ok(Admission::AwaitingBoot(awaiting.clone()));
    }
    let started_path = instance_dir(&paths.state_dir, &step.instance).join(STARTED_FILE);
    if let Some(started) = read_json::<HostApplyStarted>(&started_path)? {
        // Settled above when it was the product's last start; otherwise a
        // later step already ran, so nothing of it is left.
        let result = interrupted(&started, now_ms);
        write_result(paths, &result)?;
        return Ok(Admission::Recorded(result));
    }
    let step = VerifiedHostStep {
        approvals: step.approvals.at(now_ms),
        ..step.clone()
    };
    step.approvals.require_all(&step.purposes)?;
    let cgroup = crate::fence::own_cgroup();
    let read_booted = || {
        let os_image = os_image.as_ref().context("no [os_image] configuration")?;
        crate::os_image::read_booted_with(os_image)
    };
    let (started, advanced) = match step.action {
        HostAction::Reboot => {
            let booted = read_booted()?;
            let boot_id = crate::os_image::boot_id(paths)?;
            record.admit_reboot(&step, cgroup, now_ms, &booted, boot_id)?
        }
        HostAction::Verify => {
            return verify(
                paths,
                &scope,
                &record,
                &step,
                cgroup,
                &read_booted()?,
                now_ms,
            )
            .map(Admission::Recorded);
        }
        HostAction::Confirm => {
            let expected = &step
                .os_image
                .as_ref()
                .context("confirm without [os_image]")?
                .digest;
            let admitted = record.admit(&step, cgroup, now_ms)?;
            check_confirmable(expected, &read_booted()?)?;
            admitted
        }
        HostAction::Install | HostAction::Uninstall | HostAction::Health | HostAction::Stage => {
            record.admit(&step, cgroup, now_ms)?
        }
    };
    write_record(paths, &scope, &advanced)?;
    write_json(paths, &started_path, &started)?;
    Ok(Admission::Run(Box::new(Running {
        paths: paths.clone(),
        scope,
        started,
        record: advanced,
        _lock: lock,
    })))
}

/// Settle the `reboot` that `record` awaits from `booted`, the image the
/// updater reports now, and record `step` (a `verify`) with the same
/// outcome. Refuses, writing nothing, while the host has not rebooted. The
/// reboot's result is written first, so a crash before the verify's own
/// records leaves a verify that a new plan can run again.
fn verify(
    paths: &ApplierPaths,
    scope: &Scope,
    record: &AppliedStateRecord,
    step: &VerifiedHostStep,
    cgroup: Option<String>,
    booted: &tenkai::host_apply::os_image::BootedImage,
    now_ms: i64,
) -> Result<HostApplyResult> {
    let (started, advanced) = record.admit(step, cgroup, now_ms)?;
    let awaiting = record
        .awaiting_boot
        .as_ref()
        .context("no reboot awaits verification")?;
    let reboot = match recorded_result(paths, &awaiting.instance)? {
        Some(result) => result,
        None => {
            let reboot_started = read_json::<HostApplyStarted>(
                &instance_dir(&paths.state_dir, &awaiting.instance).join(STARTED_FILE),
            )?
            .with_context(|| format!("the reboot {} has no started record", awaiting.instance))?;
            let (outcome, detail) =
                awaiting.judge(booted, &crate::os_image::boot_id(paths)?, now_ms)?;
            reboot_started.result(outcome, None, detail, now_ms)
        }
    };
    write_record(paths, scope, &advanced)?;
    write_json(
        paths,
        &instance_dir(&paths.state_dir, &step.instance).join(STARTED_FILE),
        &started,
    )?;
    write_result(paths, &reboot)?;
    let result = started.result(
        reboot.outcome,
        None,
        format!("{}: {}", reboot.instance, reboot.detail),
        now_ms,
    );
    write_record(paths, scope, &advanced.complete(&started, &result))?;
    write_result(paths, &result)?;
    Ok(result)
}

/// Make sure the step that last started for `record` has a result file:
/// the one its completion recorded, or, once nothing of it is left running
/// ([`crate::fence::execution_gone`]), interrupted. A `reboot` awaiting its
/// boot is left alone: only `verify` settles it. A `confirm` is settled by
/// what the updater reports, as its completion would have been.
fn settle_last(
    paths: &ApplierPaths,
    scope: &Scope,
    record: &mut AppliedStateRecord,
    now_ms: i64,
) -> Result<()> {
    let Some(last) = record.last_started.clone() else {
        return Ok(());
    };
    if recorded_result(paths, &last.instance)?.is_some()
        || awaiting(record, &last.instance).is_some()
    {
        return Ok(());
    }
    let result = match &record.last_result {
        Some(result) if result.instance == last.instance => result.clone(),
        _ => {
            crate::fence::execution_gone(Path::new(crate::fence::CGROUP_ROOT), &last)?;
            let result = match (last.action, &last.image_digest) {
                (HostAction::Confirm, Some(expected)) => {
                    let (outcome, detail) =
                        confirm_verdict(expected, &crate::os_image::read_booted(paths)?);
                    last.result(
                        outcome,
                        None,
                        format!("settled after the applier stopped: {detail}"),
                        now_ms,
                    )
                }
                _ => interrupted(&last, now_ms),
            };
            *record = record.complete(&last, &result);
            write_record(paths, scope, record)?;
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
    let scope = Scope::of(false, environment, product);
    read_record_in(paths, &scope, environment, product)
}

/// The host-wide OS image record, if any OS image step ever started.
pub fn read_os_image_record(paths: &ApplierPaths) -> Result<Option<AppliedStateRecord>> {
    read_json(&os_image_record_path(&paths.state_dir))
}

/// The record `scope` names, or a fresh `empty` one for `environment` and
/// `product`. A product record must belong to them; the host-wide record
/// belongs to whichever OS image release first started, and
/// [`AppliedStateRecord::admit`] refuses a step of another one.
fn read_record_in(
    paths: &ApplierPaths,
    scope: &Scope,
    environment: &str,
    product: &str,
) -> Result<AppliedStateRecord> {
    let path = scope.path(&paths.state_dir);
    let record = read_json::<AppliedStateRecord>(&path)?
        .unwrap_or_else(|| AppliedStateRecord::empty(environment, product));
    if matches!(scope, Scope::Product { .. })
        && (record.environment != environment || record.product != product)
    {
        anyhow::bail!("{} belongs to another product", path.display());
    }
    Ok(record)
}

fn write_record(paths: &ApplierPaths, scope: &Scope, record: &AppliedStateRecord) -> Result<()> {
    write_json(paths, &scope.path(&paths.state_dir), record)
}

fn write_result(paths: &ApplierPaths, result: &HostApplyResult) -> Result<()> {
    write_json(
        paths,
        &instance_dir(&paths.state_dir, &result.instance).join(RESULT_FILE),
        result,
    )
}

/// The workload certificate recorded for `instance` in `environment`, if
/// one was installed. Read under the product lock to decide a renewal.
pub fn identity_record(
    paths: &ApplierPaths,
    environment: &str,
    instance: &str,
) -> Result<Option<HostIdentityRecord>> {
    let path = identity_record_path(&paths.state_dir, environment, instance);
    let record = read_json::<HostIdentityRecord>(&path)?;
    if let Some(record) = &record
        && (record.schema != IDENTITY_RECORD_SCHEMA
            || record.environment != environment
            || record.instance != instance)
    {
        anyhow::bail!(
            "{} is not the record of {instance} in {environment}",
            path.display()
        );
    }
    Ok(record)
}

/// Record the workload certificate just installed, for renewal to read.
/// Written after the certificate itself, under the product lock.
pub fn write_identity_record(paths: &ApplierPaths, record: &HostIdentityRecord) -> Result<()> {
    write_json(
        paths,
        &identity_record_path(&paths.state_dir, &record.environment, &record.instance),
        record,
    )
}

/// Forget the workload certificate of `instance`: a step installed a
/// release without one, or removed it.
pub fn remove_identity_record(
    paths: &ApplierPaths,
    environment: &str,
    instance: &str,
) -> Result<()> {
    let path = identity_record_path(&paths.state_dir, environment, instance);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Take the exclusive per-product lock, waiting for a running step.
pub(crate) fn lock_product(
    paths: &ApplierPaths,
    environment: &str,
    product: &str,
) -> Result<OwnedFd> {
    lock(paths, &Scope::of(false, environment, product))
}

/// Take the exclusive lock of `scope`, waiting for a running step.
fn lock(paths: &ApplierPaths, scope: &Scope) -> Result<OwnedFd> {
    let dir = paths.run_dir.join("locks");
    create_dirs(&dir)?;
    let path = dir.join(format!("{}.lock", scope.lock_name()));
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

/// Replace `path`, under the state directory, atomically and durably,
/// readable by everyone and writable only by the applier.
fn write_json(paths: &ApplierPaths, path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("record path has no parent")?;
    durable_dirs(&paths.state_dir, parent)?;
    tenkai::atomic_state::write_file(path, &serde_json::to_vec_pretty(value)?, Some(0o644))
        .with_context(|| format!("replacing {}", path.display()))
}

/// Create `dir` and every missing directory between it and `root`, and sync
/// each one's parent so its entry survives a power loss, also when it already
/// existed: an earlier applier may have died between creating it and syncing.
/// `root` itself must already exist (the unit's `StateDirectory=` provisions
/// it): a missing state root fails closed instead of silently starting over.
fn durable_dirs(root: &Path, dir: &Path) -> Result<()> {
    if !root.is_dir() {
        anyhow::bail!(
            "state directory {} does not exist; it must be provisioned before the applier runs",
            root.display()
        );
    }
    let relative = dir
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", dir.display(), root.display()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let parent = current.clone();
        current.push(component);
        match std::fs::create_dir(&current) {
            Ok(()) => std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", current.display()));
            }
        }
        std::fs::File::open(&parent)?.sync_all()?;
    }
    Ok(())
}

/// Create the run directory's lock directory; it holds no durable state.
fn create_dirs(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

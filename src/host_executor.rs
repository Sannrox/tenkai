//! Server side of privileged host releases (ADR 0041 §2).
//!
//! The unprivileged server spools a host step's [`HostApplyRequest`] and the
//! release workdir under `<spool_dir>/<instance>/`, starts
//! `tenkai-host-apply@<instance>.service`, stops it on lease loss or
//! cancellation, and accepts only a result record that names the instance it
//! started. The root-side applier writes every record under `state_dir`; this
//! side only reads them. Starting is behind [`HostUnits`], so tests and the
//! systemd drill run the same code with or without systemd.
//!
//! Configuration: `TENKAI_HOST_SPOOL_DIR` enables the host executor and must
//! equal the applier's `spool_dir`; `TENKAI_HOST_STATE_DIR` is the applier's
//! state directory (default `/var/lib/tenkai-host`).

use std::future::Future;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};

use crate::host_apply::state::{
    APPLIED_STATE_SCHEMA, AppliedStateRecord, HostApplyRefused, HostApplyResult, HostApplyStarted,
    REFUSED_FILE, REFUSED_SCHEMA, RESULT_FILE, RESULT_SCHEMA, STARTED_FILE, instance_dir,
    record_path,
};
use crate::host_apply::{ARTIFACTS_DIR, HostApplyRequest, REQUEST_FILE, validate_instance_name};

/// Enables the host executor: the spool directory the server writes requests
/// to, which must be the applier's `spool_dir`.
pub const SPOOL_DIR_ENV: &str = "TENKAI_HOST_SPOOL_DIR";
/// The applier's state directory, which the server only reads.
pub const STATE_DIR_ENV: &str = "TENKAI_HOST_STATE_DIR";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/tenkai-host";
/// Largest record the server reads from the applier's state directory.
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
/// `PATH` `systemctl` is looked up in; the server's own environment, which
/// holds its credentials, never reaches it.
const SYSTEMCTL_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// A boxed future that borrows its receiver.
pub type UnitFuture<'a, T = ()> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Starts and stops instances of `tenkai-host-apply@.service`: the only two
/// systemd verbs the polkit rule grants the server's user.
pub trait HostUnits: Send + Sync {
    /// Start `instance` and resolve once its start job ended, that is once
    /// the applier exited. An error only explains a missing result; the
    /// caller decides from the records.
    fn start<'a>(&'a self, instance: &'a str) -> UnitFuture<'a>;
    /// Ask systemd to stop `instance` without waiting. The pending
    /// [`Self::start`] resolves once the applier recorded the stop and exited.
    fn stop(&self, instance: &str) -> Result<()>;
    /// The instances whose unit is starting, running, or stopping. Reading
    /// unit state needs no authorization.
    fn running(&self) -> UnitFuture<'_, Vec<String>>;
}

/// [`HostUnits`] through `systemctl`, as the server's user.
#[derive(Debug, Default, Clone, Copy)]
pub struct Systemctl;

/// `tenkai-host-apply@<instance>.service`.
pub fn unit_name(instance: &str) -> String {
    format!("tenkai-host-apply@{instance}.service")
}

impl HostUnits for Systemctl {
    fn start<'a>(&'a self, instance: &'a str) -> UnitFuture<'a> {
        Box::pin(async move {
            // Blocking start: the template unit is a oneshot, so the job ends
            // when the applier exits. The caller keeps the fence fresh and
            // stops the unit concurrently.
            let output = tokio::process::Command::new("systemctl")
                .args(["start", "--no-ask-password"])
                .arg(unit_name(instance))
                .env_clear()
                .env("PATH", SYSTEMCTL_PATH)
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output()
                .await
                .context("running systemctl start")?;
            if !output.status.success() {
                bail!(
                    "systemctl start {} ended with {}: {}",
                    unit_name(instance),
                    output.status,
                    crate::software_executor::sanitize_diagnostic_text(
                        String::from_utf8_lossy(&output.stderr).trim()
                    )
                );
            }
            Ok(())
        })
    }

    fn running(&self) -> UnitFuture<'_, Vec<String>> {
        Box::pin(async move {
            let output = tokio::process::Command::new("systemctl")
                .args([
                    "list-units",
                    "--plain",
                    "--no-legend",
                    "--no-pager",
                    "--state=activating,active,deactivating,reloading",
                    "tenkai-host-apply@*.service",
                ])
                .env_clear()
                .env("PATH", SYSTEMCTL_PATH)
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output()
                .await
                .context("running systemctl list-units")?;
            if !output.status.success() {
                bail!("systemctl list-units ended with {}", output.status);
            }
            Ok(String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    line.split_whitespace()
                        .next()?
                        .strip_prefix("tenkai-host-apply@")?
                        .strip_suffix(".service")
                        .filter(|instance| validate_instance_name(instance).is_ok())
                        .map(str::to_string)
                })
                .collect())
        })
    }

    fn stop(&self, instance: &str) -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .args(["stop", "--no-block", "--no-ask-password"])
            .arg(unit_name(instance))
            .env_clear()
            .env("PATH", SYSTEMCTL_PATH)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .context("running systemctl stop")?;
        if !status.success() {
            bail!("systemctl stop {} ended with {status}", unit_name(instance));
        }
        Ok(())
    }
}

/// The host executor of one process: where it spools, where the applier
/// records, and how it starts units.
#[derive(Clone)]
pub struct HostExecutor {
    spool_dir: PathBuf,
    state_dir: PathBuf,
    units: Arc<dyn HostUnits>,
}

impl std::fmt::Debug for HostExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostExecutor")
            .field("spool_dir", &self.spool_dir)
            .field("state_dir", &self.state_dir)
            .finish()
    }
}

/// What the server expects a host step's result to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedResult<'a> {
    pub instance: &'a str,
    pub environment: &'a str,
    pub product: &'a str,
    pub action: crate::host_apply::HostAction,
    /// The step's `release_digest`: bare sha256 hex of the signed manifest.
    pub release_digest: &'a str,
}

impl HostExecutor {
    pub fn new(spool_dir: PathBuf, state_dir: PathBuf, units: Arc<dyn HostUnits>) -> Self {
        Self {
            spool_dir,
            state_dir,
            units,
        }
    }

    /// The host executor `TENKAI_HOST_SPOOL_DIR` configures, driving
    /// `systemctl`; `None` when it is unset.
    pub fn from_env() -> Result<Option<Self>> {
        let Some(spool_dir) = std::env::var_os(SPOOL_DIR_ENV).filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let spool_dir = PathBuf::from(spool_dir);
        let state_dir = std::env::var_os(STATE_DIR_ENV)
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from(DEFAULT_STATE_DIR), PathBuf::from);
        for (name, path) in [(SPOOL_DIR_ENV, &spool_dir), (STATE_DIR_ENV, &state_dir)] {
            if !path.is_absolute() {
                bail!("{name} must be an absolute path, got {}", path.display());
            }
        }
        Ok(Some(Self::new(spool_dir, state_dir, Arc::new(Systemctl))))
    }

    pub fn units(&self) -> &dyn HostUnits {
        self.units.as_ref()
    }

    /// Whether this process can run host steps: the spool directory is a
    /// directory this user owns, others cannot write, and this user can
    /// write, and `systemctl` is installed. `/readyz` reports the result.
    pub fn check_ready(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.spool_dir)
            .with_context(|| format!("reading {SPOOL_DIR_ENV} {}", self.spool_dir.display()))?;
        if !metadata.is_dir() {
            bail!(
                "{SPOOL_DIR_ENV} {} is not a directory",
                self.spool_dir.display()
            );
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!(
                "{SPOOL_DIR_ENV} {} is not owned by the server's user",
                self.spool_dir.display()
            );
        }
        if metadata.mode() & 0o022 != 0 {
            bail!(
                "{SPOOL_DIR_ENV} {} is writable by group or others",
                self.spool_dir.display()
            );
        }
        let probe = self
            .spool_dir
            .join(format!(".ready-{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&probe)
            .with_context(|| format!("writing to {}", self.spool_dir.display()))?;
        let _ = std::fs::remove_dir(&probe);
        if !std::env::split_paths(SYSTEMCTL_PATH).any(|dir| dir.join("systemctl").is_file()) {
            bail!("systemctl is not in {SYSTEMCTL_PATH}");
        }
        Ok(())
    }

    /// The applier's record for `environment` and `product`, or the empty
    /// record of a product it never touched. Planning reads it to put the
    /// expected generation and source release into each host step.
    pub fn applied_state(&self, environment: &str, product: &str) -> Result<AppliedStateRecord> {
        let path = record_path(&self.state_dir, environment, product);
        let Some(bytes) = read_record(&path)? else {
            return Ok(AppliedStateRecord::empty(environment, product));
        };
        let record: AppliedStateRecord = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing host applied-state record {}", path.display()))?;
        if record.schema != APPLIED_STATE_SCHEMA
            || record.environment != environment
            || record.product != product
        {
            bail!(
                "host applied-state record {} is not the {APPLIED_STATE_SCHEMA} record of {product} in {environment}",
                path.display()
            );
        }
        Ok(record)
    }

    /// Spool `request` with the release workdir: `request.json`, and the
    /// manifest's `inputs` copied from `release_root` under `artifacts/`.
    /// Checks the copy against `artifact_digest` and replaces whatever an
    /// earlier attempt of the same instance spooled. Returns the instance.
    pub fn spool(
        &self,
        request: &HostApplyRequest,
        release_root: &Path,
        inputs: &[String],
        artifact_digest: &str,
    ) -> Result<String> {
        let instance = request.instance()?;
        let staging = self
            .spool_dir
            .join(format!(".staging-{}", uuid::Uuid::new_v4().simple()));
        let written = (|| {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&staging)
                .with_context(|| format!("creating {}", staging.display()))?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(staging.join(REQUEST_FILE))?;
            serde_json::to_writer(&mut file, request)?;
            file.sync_all()?;
            let artifacts = staging.join(ARTIFACTS_DIR);
            std::fs::DirBuilder::new().mode(0o700).create(&artifacts)?;
            for input in inputs {
                let relative = Path::new(input);
                let target = artifacts.join(relative);
                if let Some(parent) = target.parent() {
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)?;
                }
                copy_input(&release_root.join(relative), &target)?;
            }
            let copied = crate::manifest::artifact_digest(&artifacts, inputs)
                .context("hashing the spooled release workdir")?;
            if copied != artifact_digest {
                bail!(
                    "the spooled release workdir does not match its signed artifact digest: signed {artifact_digest}, spooled {copied}"
                );
            }
            anyhow::Ok(())
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error.context(format!("spooling host step {instance}")));
        }
        let target = self.spool_dir.join(&instance);
        if target.exists() {
            // A retry: move the earlier spool aside. An applier still reading
            // it keeps its open directory.
            let stale = self
                .spool_dir
                .join(format!(".stale-{}", uuid::Uuid::new_v4().simple()));
            std::fs::rename(&target, &stale)
                .with_context(|| format!("replacing {}", target.display()))?;
            let _ = std::fs::remove_dir_all(&stale);
        }
        std::fs::rename(&staging, &target)
            .with_context(|| format!("spooling host step into {}", target.display()))?;
        Ok(instance)
    }

    /// Stop every running host unit that acts on `environment`, and wait
    /// until it is gone. Only the environment lease's holder may have one
    /// running, so a unit still running when the lease is claimed belongs to
    /// a holder that died or lost the lease; stopping it fences that holder
    /// out even though the unit outlived the process that started it. A unit
    /// is attributed by the applier's started record, else by its spooled
    /// request. Fails closed when a unit does not stop within `patience`.
    pub async fn fence_environment(
        &self,
        environment: &str,
        patience: std::time::Duration,
    ) -> Result<Vec<String>> {
        let mut stale = Vec::new();
        for instance in self.units.running().await? {
            if self.instance_environment(&instance).as_deref() == Some(environment) {
                self.units.stop(&instance)?;
                stale.push(instance);
            }
        }
        let deadline = tokio::time::Instant::now() + patience;
        while !stale.is_empty() {
            let running = self.units.running().await?;
            if !stale.iter().any(|instance| running.contains(instance)) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "host units of {environment} from an earlier lease holder are still running: {}",
                    stale
                        .iter()
                        .map(|instance| unit_name(instance))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Ok(stale)
    }

    /// The environment a running instance acts on, if it can be told.
    fn instance_environment(&self, instance: &str) -> Option<String> {
        let started = instance_dir(&self.state_dir, instance).join(STARTED_FILE);
        if let Ok(Some(bytes)) = read_record(&started)
            && let Ok(started) = serde_json::from_slice::<HostApplyStarted>(&bytes)
        {
            return Some(started.environment);
        }
        let request = self.spool_dir.join(instance).join(REQUEST_FILE);
        let bytes = read_bounded(&request, crate::host_apply::MAX_REQUEST_BYTES).ok()??;
        Some(HostApplyRequest::parse(&bytes).ok()?.plan.environment)
    }

    /// Remove an instance's spool once the step ended; the applier keeps its
    /// own copy and records.
    pub fn discard_spool(&self, instance: &str) {
        if validate_instance_name(instance).is_ok() {
            let _ = std::fs::remove_dir_all(self.spool_dir.join(instance));
        }
    }

    /// The instance's result record, if the applier wrote one. A record that
    /// names another instance, environment, product, action, or release is
    /// an error: the step fails rather than accept it.
    pub fn result(&self, expected: &ExpectedResult<'_>) -> Result<Option<HostApplyResult>> {
        validate_instance_name(expected.instance)?;
        let path = instance_dir(&self.state_dir, expected.instance).join(RESULT_FILE);
        let Some(bytes) = read_record(&path)? else {
            return Ok(None);
        };
        let result: HostApplyResult = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing host result {}", path.display()))?;
        if result.schema != RESULT_SCHEMA
            || result.instance != expected.instance
            || result.environment != expected.environment
            || result.product != expected.product
            || result.action != expected.action
            || result.release_digest != expected.release_digest
        {
            bail!(
                "host result {} does not match the step it started: instance {}, {} {} in {}, release {}",
                path.display(),
                result.instance,
                result.action,
                result.product,
                result.environment,
                result.release_digest
            );
        }
        Ok(Some(result))
    }

    /// Why the applier last refused `instance` before anything ran, when that
    /// refusal is at or after `since_ms`. A refusal is not terminal for the
    /// applier; it ends only this attempt.
    pub fn refusal_since(&self, instance: &str, since_ms: i64) -> Result<Option<String>> {
        validate_instance_name(instance)?;
        let path = instance_dir(&self.state_dir, instance).join(REFUSED_FILE);
        let Some(bytes) = read_record(&path)? else {
            return Ok(None);
        };
        let refused: HostApplyRefused = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing host refusal {}", path.display()))?;
        if refused.schema != REFUSED_SCHEMA || refused.instance != instance {
            bail!("host refusal {} names another instance", path.display());
        }
        Ok((refused.refused_at >= since_ms).then_some(refused.reason))
    }
}

/// Read one record of at most `MAX_RECORD_BYTES`; `None` when it does not
/// exist.
fn read_record(path: &Path) -> Result<Option<Vec<u8>>> {
    read_bounded(path, MAX_RECORD_BYTES)
}

/// Read a file of at most `max` bytes; `None` when it does not exist.
fn read_bounded(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    Ok(Some(bytes))
}

/// Copy one deploy input (a file or a directory tree) with its permission
/// bits, which the artifact digest covers. Links and special files are
/// refused, as the applier refuses them.
fn copy_input(from: &Path, to: &Path) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(from).with_context(|| format!("reading {}", from.display()))?;
    if metadata.is_file() {
        std::fs::copy(from, to)
            .with_context(|| format!("copying {} into the spool", from.display()))?;
        return Ok(());
    }
    if !metadata.is_dir() {
        bail!(
            "deploy input {} is not a regular file or directory",
            from.display()
        );
    }
    std::fs::DirBuilder::new().mode(0o700).create(to)?;
    for entry in std::fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry?;
        copy_input(&entry.path(), &to.join(entry.file_name()))?;
    }
    // Last, so a read-only directory can still be filled.
    std::fs::set_permissions(to, metadata.permissions())?;
    Ok(())
}

#[cfg(test)]
mod tests;

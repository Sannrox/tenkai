//! Server-mode backups of the operational SQLite store (#672).
//!
//! A [`Backups`] set writes consistent online backups into one directory:
//! `tenkai-backup-<ms>.db` next to a `tenkai-backup-<ms>.json` manifest that
//! carries its sha256 and size. A backup is written as a partial file and
//! synced; its manifest is durable before the database is hard-linked into
//! place, so a crash never leaves a half-written backup under a final name,
//! and a database without a manifest is never one of ours. The
//! newest `retain` backups are kept. `status.json` records the last success
//! and the last failure; it lives beside the backups, not in the database, so
//! it never describes a database it was restored over. Each restore drill
//! writes its own file under `drills/`, so a drill run from another process
//! never races the server on `status.json`. Manifests, status and drill
//! evidence are synced before they are renamed into place.
//!
//! The store holds no management or runtime secrets (they are environment-only),
//! so neither does a backup.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::storage::SqliteStore;

pub const MANIFEST_SCHEMA: &str = "tenkai.backup.v1";
pub const STATUS_SCHEMA: &str = "tenkai.backup-status.v1";
pub const DRILL_SCHEMA: &str = "tenkai.backup-drill.v1";
const STATUS_FILE: &str = "status.json";
const DRILL_DIR: &str = "drills";
const LOCK_FILE: &str = ".lock";
const PREFIX: &str = "tenkai-backup-";

/// Where backups go, how many to keep, and when the last one is too old.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPolicy {
    pub dir: PathBuf,
    pub retain: usize,
    pub max_age_ms: i64,
}

/// One completed backup, as its manifest records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub schema: String,
    /// File name inside the backup directory.
    pub file: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub taken_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupFailure {
    pub at_ms: i64,
    pub error: String,
}

/// Evidence that one backup restored into a scratch store and opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrillEvidence {
    pub schema: String,
    pub file: String,
    pub sha256: String,
    pub restored_at_ms: i64,
    /// `PRAGMA integrity_check` of the restored store.
    pub integrity: String,
    pub environments: u64,
    pub releases: u64,
    pub plans: u64,
}

/// `GET /v1/backups`: `status.json` plus the newest drill.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupStatus {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_success: Option<BackupManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_failure: Option<BackupFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub last_drill: Option<DrillEvidence>,
}

/// Backup age as health reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct BackupHealth {
    /// `ok`, `stale` (older than the threshold), `missing` (none taken yet)
    /// or `unreadable` (the status file cannot be read).
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub age_seconds: Option<u64>,
    pub max_age_seconds: u64,
}

/// The backup set of one server. `take` holds an exclusive lock on
/// `<dir>/.lock`, so scheduled and on-demand backups, and two servers that
/// overlap during a restart, never race on the directory or the status file.
pub struct Backups {
    store: Arc<SqliteStore>,
    policy: BackupPolicy,
}

impl Backups {
    pub fn new(store: Arc<SqliteStore>, policy: BackupPolicy) -> Result<Self> {
        if policy.retain == 0 {
            bail!("backup retention must keep at least one backup");
        }
        std::fs::create_dir_all(&policy.dir)
            .with_context(|| format!("creating backup directory {}", policy.dir.display()))?;
        Ok(Self { store, policy })
    }

    pub fn policy(&self) -> &BackupPolicy {
        &self.policy
    }

    /// Take one backup now. A failure is recorded in the status and returned.
    pub fn take(&self, now_ms: i64) -> Result<BackupManifest> {
        let lock = std::fs::File::create(self.policy.dir.join(LOCK_FILE))
            .context("opening the backup lock")?;
        // Released when `lock` is dropped, including on every error path.
        lock.lock().context("taking the backup lock")?;
        remove_incomplete(&self.policy.dir)?;
        let result = self.write_backup(now_ms);
        // A damaged status file must not stop backups for good: start over.
        let mut status = read_status(&self.policy.dir).unwrap_or_else(|error| {
            eprintln!("backup status unreadable, starting a new one: {error:#}");
            empty_status()
        });
        status.last_drill = None;
        match &result {
            Ok(manifest) => status.last_success = Some(manifest.clone()),
            Err(error) => {
                status.last_failure = Some(BackupFailure {
                    at_ms: now_ms,
                    error: format!("{error:#}"),
                })
            }
        }
        write_status(&self.policy.dir, &status)?;
        let manifest = result?;
        if let Err(error) = self.prune(&manifest.file) {
            // The backup stands; a failed retention pass is still a failure
            // the status must show, or old backups fill the volume unseen.
            status.last_failure = Some(BackupFailure {
                at_ms: now_ms,
                error: format!("retention after {}: {error:#}", manifest.file),
            });
            write_status(&self.policy.dir, &status)?;
            return Err(error.context("pruning old backups"));
        }
        Ok(manifest)
    }

    pub fn status(&self) -> Result<BackupStatus> {
        let mut status = read_status(&self.policy.dir)?;
        status.last_drill = latest_drill(&self.policy.dir)?;
        Ok(status)
    }

    /// `missing` before the first backup, `stale` past `max_age_ms`, and
    /// `unreadable` when the status cannot be read.
    pub fn health(&self, now_ms: i64) -> BackupHealth {
        let max_age_seconds = (self.policy.max_age_ms / 1000).max(0) as u64;
        let last = match read_status(&self.policy.dir) {
            Ok(status) => status.last_success,
            Err(error) => {
                eprintln!("backup status unreadable: {error:#}");
                return BackupHealth {
                    state: "unreadable",
                    age_seconds: None,
                    max_age_seconds,
                };
            }
        };
        let Some(last) = last else {
            return BackupHealth {
                state: "missing",
                age_seconds: None,
                max_age_seconds,
            };
        };
        let age_ms = now_ms.saturating_sub(last.taken_at_ms).max(0);
        BackupHealth {
            state: if age_ms > self.policy.max_age_ms {
                "stale"
            } else {
                "ok"
            },
            age_seconds: Some((age_ms / 1000) as u64),
            max_age_seconds,
        }
    }

    fn write_backup(&self, now_ms: i64) -> Result<BackupManifest> {
        let dir = &self.policy.dir;
        let file = format!("{PREFIX}{now_ms}.db");
        let target = dir.join(&file);
        if target.exists() {
            bail!("backup {file} already exists");
        }
        let partial = dir.join(format!(".{file}.{}.partial", uuid::Uuid::new_v4()));
        // The manifest is durable before the database appears, so a backup
        // database without a manifest is never one this module wrote.
        let written = (|| {
            // Owner-only before any data lands: SQLite keeps an existing
            // file's mode, and the hard link shares it.
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&partial)?;
            }
            self.store.backup(&partial)?;
            std::fs::File::open(&partial)?.sync_all()?;
            let (sha256, size_bytes) = sha256_file(&partial)?;
            let manifest = BackupManifest {
                schema: MANIFEST_SCHEMA.into(),
                file: file.clone(),
                sha256,
                size_bytes,
                taken_at_ms: now_ms,
            };
            write_durable(&manifest_path(&target), &manifest)?;
            // A hard link publishes without ever replacing an existing backup.
            if let Err(error) = std::fs::hard_link(&partial, &target) {
                let _ = std::fs::remove_file(manifest_path(&target));
                return Err(
                    anyhow::Error::new(error).context(format!("backup {file} already exists"))
                );
            }
            sync_dir(dir)?;
            Ok::<_, anyhow::Error>(manifest)
        })();
        let _ = std::fs::remove_file(&partial);
        written.map_err(|error| error.context(format!("writing backup {file}")))
    }

    /// Keep `newest`, the backup just taken and reported as the last
    /// success, plus the newest `retain - 1` others. `newest` is kept even
    /// when the clock moved back and its timestamp sorts lower.
    fn prune(&self, newest: &str) -> Result<()> {
        let mut backups = list_backups(&self.policy.dir)?;
        backups.retain(|(_, path)| path.file_name().and_then(|name| name.to_str()) != Some(newest));
        backups.sort_by_key(|(taken_at, _)| std::cmp::Reverse(*taken_at));
        for (_, path) in backups.into_iter().skip(self.policy.retain - 1) {
            // Database first: a crash in between leaves a lone manifest,
            // which the next backup removes.
            std::fs::remove_file(&path)
                .with_context(|| format!("pruning backup {}", path.display()))?;
            std::fs::remove_file(manifest_path(&path))
                .with_context(|| format!("pruning manifest of {}", path.display()))?;
        }
        Ok(())
    }
}

/// Remove what an interrupted backup or prune left behind: this module's
/// partial and temporary files, and a manifest of ours whose database is
/// gone. A database without a manifest is left alone: this module never
/// writes one, so it belongs to someone else. Runs under the backup lock, so
/// no backup is in progress.
fn remove_incomplete(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // Only names this module writes: `.tenkai-*.partial`, and the
        // `.<name>.<uuid>.tmp` temporaries of `status.json` and manifests.
        let ours_temporary = (name.starts_with(&format!(".{PREFIX}"))
            || name.starts_with(&format!(".{STATUS_FILE}.")))
            && (name.ends_with(".partial") || name.ends_with(".tmp"));
        let incomplete = if ours_temporary {
            true
        } else if name.starts_with(PREFIX) && name.ends_with(".json") {
            !path.with_extension("db").is_file()
                && std::fs::read(&path)
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<BackupManifest>(&raw).ok())
                    .is_some_and(|manifest| manifest.schema == MANIFEST_SCHEMA)
        } else {
            false
        };
        if incomplete {
            std::fs::remove_file(&path)
                .with_context(|| format!("removing incomplete backup file {}", path.display()))?;
        }
    }
    Ok(())
}

/// Restore `backup` into a scratch store under `scratch_dir`, open it on this
/// version, and return the evidence. The backup's sha256 must match its
/// manifest. The evidence is also written under `drills/` beside the backup.
/// The scratch store is removed whether or not the drill passes.
pub fn drill(backup: &Path, scratch_dir: &Path, now_ms: i64) -> Result<DrillEvidence> {
    // A shared hold on the backup lock keeps retention from removing the
    // source until it is verified and copied; it ends when the drill returns.
    let _source_hold = match backup
        .parent()
        .map(|dir| std::fs::File::open(dir.join(LOCK_FILE)))
    {
        Some(Ok(lock)) => {
            lock.lock_shared().context("taking the backup lock")?;
            Some(lock)
        }
        _ => None,
    };
    let manifest: BackupManifest = serde_json::from_slice(
        &std::fs::read(manifest_path(backup))
            .with_context(|| format!("reading the manifest of {}", backup.display()))?,
    )
    .context("parsing the backup manifest")?;
    let (sha256, _) = sha256_file(backup)?;
    if sha256 != manifest.sha256 {
        bail!(
            "backup {} does not match its manifest: sha256 {sha256}, expected {}",
            backup.display(),
            manifest.sha256
        );
    }
    std::fs::create_dir_all(scratch_dir)
        .with_context(|| format!("creating scratch directory {}", scratch_dir.display()))?;
    // The restored copy holds the whole operational store: keep it in a fresh
    // owner-only directory, never loose in a shared temporary directory.
    let private = scratch_dir.join(format!("tenkai-drill-{now_ms}-{}", uuid::Uuid::new_v4()));
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .with_context(|| format!("creating private scratch directory {}", private.display()))?;
    }
    let _cleanup = ScratchStore(private.clone());
    let scratch = private.join("restored.db");
    SqliteStore::restore(backup, &scratch)?;
    // Opening runs this version's migrations: the backup must still open.
    drop(SqliteStore::open(&scratch).context("opening the restored store")?);
    let connection = rusqlite::Connection::open(&scratch)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let count = |table: &str| -> Result<u64> {
        Ok(
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })? as u64,
        )
    };
    let evidence = DrillEvidence {
        schema: DRILL_SCHEMA.into(),
        file: manifest.file,
        sha256,
        restored_at_ms: now_ms,
        integrity,
        environments: count("environments")?,
        releases: count("releases")?,
        plans: count("plans")?,
    };
    drop(connection);
    if evidence.integrity != "ok" {
        bail!(
            "restored store failed its integrity check: {}",
            evidence.integrity
        );
    }
    if let Some(dir) = backup.parent() {
        let name = format!("drill-{now_ms}-{}.json", uuid::Uuid::new_v4());
        write_durable(&dir.join(DRILL_DIR).join(name), &evidence)?;
    }
    Ok(evidence)
}

/// Removes a drill's private scratch directory, with the restored store and
/// its SQLite sidecars, on every return path.
struct ScratchStore(PathBuf);

impl Drop for ScratchStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn manifest_path(backup: &Path) -> PathBuf {
    backup.with_extension("json")
}

/// Backups with a manifest, as `(taken_at_ms, path)`.
fn list_backups(dir: &Path) -> Result<Vec<(i64, PathBuf)>> {
    let mut backups = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(taken_at) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(PREFIX))
            .and_then(|name| name.strip_suffix(".db"))
            .and_then(|stamp| stamp.parse::<i64>().ok())
        else {
            continue;
        };
        if manifest_path(&path).is_file() {
            backups.push((taken_at, path));
        }
    }
    Ok(backups)
}

fn empty_status() -> BackupStatus {
    BackupStatus {
        schema: STATUS_SCHEMA.into(),
        ..BackupStatus::default()
    }
}

fn read_status(dir: &Path) -> Result<BackupStatus> {
    let path = dir.join(STATUS_FILE);
    match std::fs::read(&path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .with_context(|| format!("parsing backup status {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(empty_status()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_status(dir: &Path, status: &BackupStatus) -> Result<()> {
    write_durable(&dir.join(STATUS_FILE), status)
}

/// The newest drill evidence under `drills/`, if any.
fn latest_drill(dir: &Path) -> Result<Option<DrillEvidence>> {
    let drills = dir.join(DRILL_DIR);
    let entries = match std::fs::read_dir(&drills) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", drills.display())),
    };
    let mut latest: Option<DrillEvidence> = None;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let evidence: DrillEvidence = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("parsing drill evidence {}", path.display()))?;
        if latest
            .as_ref()
            .is_none_or(|current| evidence.restored_at_ms > current.restored_at_ms)
        {
            latest = Some(evidence);
        }
    }
    Ok(latest)
}

/// Write JSON so it is durable before it is visible: a unique temporary file,
/// synced, renamed into place, then the directory synced. Unique temporaries
/// let two processes write side by side without removing each other's file.
fn write_durable<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        uuid::Uuid::new_v4()
    ));
    let written = (|| {
        let mut file = std::fs::File::create(&temporary)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        sync_dir(dir)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let size = std::io::copy(&mut file, &mut hasher)?;
    Ok((format!("sha256:{:x}", hasher.finalize()), size))
}

fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .with_context(|| format!("syncing backup directory {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::OperationalStore as _;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-backup-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn backups(root: &Path, retain: usize) -> (Arc<SqliteStore>, Backups) {
        let store = Arc::new(SqliteStore::open(root.join("tenkai.db")).unwrap());
        let backups = Backups::new(
            store.clone(),
            BackupPolicy {
                dir: root.join("backups"),
                retain,
                max_age_ms: 60_000,
            },
        )
        .unwrap();
        (store, backups)
    }

    fn put_environment(store: &SqliteStore, id: &str) {
        store
            .put_environment(&crate::storage::EnvironmentRecord {
                id: id.into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
    }

    /// Backups taken while another thread keeps writing each restore to a
    /// consistent store: integrity holds and every environment row is whole.
    #[test]
    fn backups_under_concurrent_writes_restore_consistently() {
        let root = temp_dir("concurrent");
        let (store, backups) = backups(&root, 10);
        let writer_store = store.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_stop = stop.clone();
        let writer = std::thread::spawn(move || {
            let mut written = 0;
            while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
                put_environment(&writer_store, &format!("env-{written}"));
                written += 1;
            }
            written
        });
        let mut taken = Vec::new();
        for at in 1..=3 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            taken.push(backups.take(at).unwrap());
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let written = writer.join().unwrap();
        let mut previous = 0;
        for manifest in &taken {
            let evidence = drill(
                &backups.policy().dir.join(&manifest.file),
                &root.join("scratch"),
                manifest.taken_at_ms,
            )
            .unwrap();
            assert_eq!(evidence.integrity, "ok");
            assert!(evidence.environments >= previous && evidence.environments <= written);
            previous = evidence.environments;
        }
        let status = backups.status().unwrap();
        assert_eq!(status.last_success.as_ref(), taken.last());
        assert_eq!(status.last_drill.unwrap().file, taken[2].file);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn health_degrades_without_a_recent_backup_and_retention_prunes() {
        let root = temp_dir("health");
        let (store, backups) = backups(&root, 2);
        put_environment(&store, "prod");
        assert_eq!(backups.health(0).state, "missing");
        let first = backups.take(1_000).unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(backups.policy().dir.join(&first.file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "a backup is readable by its owner only"
            );
        }
        assert_eq!(backups.health(30_000).state, "ok");
        let stale = backups.health(100_000);
        assert_eq!((stale.state, stale.age_seconds), ("stale", Some(99)));

        // A damaged status file is reported, and the next backup starts over.
        std::fs::write(backups.policy().dir.join(STATUS_FILE), b"{not json").unwrap();
        assert_eq!(backups.health(30_000).state, "unreadable");
        backups.take(2_000).unwrap();
        assert_eq!(backups.health(30_000).state, "ok");
        backups.take(3_000).unwrap();
        let kept = |backups: &Backups| {
            let mut kept = list_backups(&backups.policy().dir).unwrap();
            kept.sort();
            kept.iter().map(|(at, _)| *at).collect::<Vec<_>>()
        };
        assert_eq!(kept(&backups), vec![2_000, 3_000]);
        // After the clock moves back, the newest backup is still kept and
        // stays the reported last success.
        let rolled_back = backups.take(500).unwrap();
        assert_eq!(kept(&backups), vec![500, 3_000]);
        assert_eq!(backups.status().unwrap().last_success, Some(rolled_back));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_tampered_backup_fails_its_drill_and_a_failure_is_recorded() {
        let root = temp_dir("tamper");
        let (_store, backups) = backups(&root, 3);
        let manifest = backups.take(1_000).unwrap();
        let path = backups.policy().dir.join(&manifest.file);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[100] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        let error = drill(&path, &root.join("scratch"), 2_000).unwrap_err();
        assert!(format!("{error:#}").contains("does not match its manifest"));

        // A second backup in the same millisecond is refused and recorded.
        assert!(backups.take(1_000).is_err());
        let status = backups.status().unwrap();
        assert!(
            status
                .last_failure
                .unwrap()
                .error
                .contains("already exists")
        );
        assert_eq!(status.last_success.unwrap().file, manifest.file);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_files_are_cleaned_up_and_failed_drills_leave_no_scratch() {
        let root = temp_dir("cleanup");
        let (_store, backups) = backups(&root, 3);
        let dir = backups.policy().dir.clone();
        // Not ours: another tool's temporary and an embedded `tenkaictl backup`.
        std::fs::write(dir.join("other-app.tmp"), b"not ours").unwrap();
        std::fs::write(dir.join("tenkai-20261023.db"), b"embedded backup").unwrap();
        // Ours, left by an interrupted run: temporaries and a manifest whose
        // database never appeared.
        for leftover in [".tenkai-backup-7.db.x.partial", ".status.json.y.tmp"] {
            std::fs::write(dir.join(leftover), b"left over").unwrap();
        }
        write_durable(
            &dir.join("tenkai-backup-6.json"),
            &BackupManifest {
                schema: MANIFEST_SCHEMA.into(),
                file: "tenkai-backup-6.db".into(),
                sha256: "sha256:00".into(),
                size_bytes: 0,
                taken_at_ms: 6,
            },
        )
        .unwrap();
        let manifest = backups.take(1_000).unwrap();
        let mut names = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![
                ".lock",
                "other-app.tmp",
                "status.json",
                "tenkai-20261023.db",
                "tenkai-backup-1000.db",
                "tenkai-backup-1000.json"
            ]
        );

        // A backup whose manifest matches but which is not a database fails
        // its drill, and the scratch store is still removed.
        let path = dir.join(&manifest.file);
        std::fs::write(&path, vec![7_u8; 8192]).unwrap();
        let (sha256, size_bytes) = sha256_file(&path).unwrap();
        write_durable(
            &manifest_path(&path),
            &BackupManifest {
                sha256,
                size_bytes,
                ..manifest
            },
        )
        .unwrap();
        let scratch = root.join("scratch");
        assert!(drill(&path, &scratch, 2_000).is_err());
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }
}

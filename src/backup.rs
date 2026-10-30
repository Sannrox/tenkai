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
//!
//! With a signing key, each manifest gets a detached `tenkai-backup-<ms>.sig`
//! over its exact bytes, written before the database appears. A drill given
//! trust roots refuses a backup whose manifest signature is missing or does
//! not verify, so a copy moved off-host can be authenticated (#705).
//!
//! A tenant-mode hub keeps its state in PostgreSQL, which Tenkai does not
//! copy. Its backup set is evidence only: an operator records each
//! database-native backup (time, checksum, tool) on the host with
//! [`record_evidence`], and status and health read that evidence like a
//! backup taken here. Recording is a host action, not an API call: every
//! tenant-mode credential belongs to one tenant, and none may speak for the
//! whole hub.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::release_signing::TrustRoots;
use crate::storage::SqliteStore;

pub const MANIFEST_SCHEMA: &str = "tenkai.backup.v1";
pub const STATUS_SCHEMA: &str = "tenkai.backup-status.v1";
pub const DRILL_SCHEMA: &str = "tenkai.backup-drill.v1";
pub const SIGNATURE_SCHEMA: &str = "tenkai.backup-signature.v1";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-BACKUP-MANIFEST-V1\0";
/// How far ahead of this hub's clock recorded evidence may claim to be.
const EVIDENCE_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
const STATUS_FILE: &str = "status.json";
const DRILL_DIR: &str = "drills";
/// Restore drills kept under `drills/`: a new drill removes the oldest
/// beyond this many (#818). Only successful drills are recorded.
pub const DRILL_HISTORY: usize = 30;
const LOCK_FILE: &str = ".lock";
const PREFIX: &str = "tenkai-backup-";

/// Where backups go, how many to keep, when the last one is too old, and
/// the Ed25519 seed that signs manifests, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPolicy {
    pub dir: PathBuf,
    pub retain: usize,
    pub max_age_ms: i64,
    pub signing_key: Option<PathBuf>,
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
    /// The tool that took a recorded database-native backup. Absent on
    /// backups this module takes, so their manifests are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub tool: Option<String>,
}

/// A database-native backup an operator took of a tenant-mode hub's
/// PostgreSQL store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEvidence {
    /// The backup's file or object name where the operator keeps it.
    pub file: String,
    /// `sha256:` and 64 lowercase hexadecimal characters.
    pub sha256: String,
    pub size_bytes: u64,
    pub taken_at_ms: i64,
    /// What took it, such as the dump tool and its version.
    pub tool: String,
}

/// Detached signature over a manifest's exact bytes, beside it as
/// `tenkai-backup-<ms>.sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSignature {
    pub schema: String,
    pub key_id: String,
    pub signature: String,
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

/// `GET /v1/backups`: `status.json` plus the newest drill and the drill
/// history.
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
    /// The kept restore drills, newest first, at most [`DRILL_HISTORY`]
    /// (#818). Never written to `status.json`, so older versions read it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drills: Vec<DrillEvidence>,
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

/// The backup set of one server. `take` and `record` hold an exclusive lock
/// on `<dir>/.lock`, so scheduled and on-demand backups, and two servers that
/// overlap during a restart, never race on the directory or the status file.
pub struct Backups {
    /// `None` for an evidence-only set, whose store Tenkai does not copy.
    store: Option<Arc<SqliteStore>>,
    policy: BackupPolicy,
}

impl Backups {
    pub fn new(store: Arc<SqliteStore>, policy: BackupPolicy) -> Result<Self> {
        if policy.retain == 0 {
            bail!("backup retention must keep at least one backup");
        }
        if let Some(seed) = &policy.signing_key {
            // Fail at startup, not at the first scheduled backup.
            crate::approval_policy::load_signer_seed(seed)
                .context("loading the backup signing key")?;
        }
        Self::open(Some(store), policy)
    }

    /// A set that only records database-native backups taken elsewhere.
    pub fn evidence_only(policy: BackupPolicy) -> Result<Self> {
        if policy.signing_key.is_some() {
            bail!("an evidence-only backup set writes no manifests to sign");
        }
        Self::open(None, policy)
    }

    fn open(store: Option<Arc<SqliteStore>>, policy: BackupPolicy) -> Result<Self> {
        std::fs::create_dir_all(&policy.dir)
            .with_context(|| format!("creating backup directory {}", policy.dir.display()))?;
        Ok(Self { store, policy })
    }

    pub fn policy(&self) -> &BackupPolicy {
        &self.policy
    }

    /// Take one backup now. A failure is recorded in the status and returned.
    pub fn take(&self, now_ms: i64) -> Result<BackupManifest> {
        let Some(store) = &self.store else {
            bail!(
                "this hub's store is backed up with database-native tools; record that evidence on the host"
            );
        };
        let _lock = lock_dir(&self.policy.dir)?;
        remove_incomplete(&self.policy.dir)?;
        let result = self.write_backup(store, now_ms);
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
        status.drills = drills(&self.policy.dir)?;
        status.last_drill = status.drills.first().cloned();
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

    fn write_backup(&self, store: &SqliteStore, now_ms: i64) -> Result<BackupManifest> {
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
            store.backup(&partial)?;
            std::fs::File::open(&partial)?.sync_all()?;
            let (sha256, size_bytes) = sha256_file(&partial)?;
            let manifest = BackupManifest {
                schema: MANIFEST_SCHEMA.into(),
                file: file.clone(),
                sha256,
                size_bytes,
                taken_at_ms: now_ms,
                tool: None,
            };
            let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
            write_durable_bytes(&manifest_path(&target), &manifest_bytes)?;
            if let Some(seed) = &self.policy.signing_key {
                write_durable(
                    &signature_path(&target),
                    &sign_manifest(&manifest_bytes, seed)?,
                )?;
            }
            // A hard link publishes without ever replacing an existing backup.
            if let Err(error) = std::fs::hard_link(&partial, &target) {
                let _ = std::fs::remove_file(signature_path(&target));
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
            match std::fs::remove_file(signature_path(&path)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error)
                        .with_context(|| format!("pruning signature of {}", path.display()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Hold the exclusive backup lock of `dir` until the file is dropped,
/// including on every error path.
fn lock_dir(dir: &Path) -> Result<std::fs::File> {
    let lock = std::fs::File::create(dir.join(LOCK_FILE)).context("opening the backup lock")?;
    lock.lock().context("taking the backup lock")?;
    Ok(lock)
}

/// Evidence for the database-native backup at `path`: its file name, sha256
/// and size, taken by `tool` at `taken_at_ms`.
pub fn evidence_for_file(path: &Path, tool: &str, taken_at_ms: i64) -> Result<BackupEvidence> {
    let (sha256, size_bytes) = sha256_file(path)?;
    Ok(BackupEvidence {
        file: path
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("{} has no file name", path.display()))?
            .into(),
        sha256,
        size_bytes,
        taken_at_ms,
        tool: tool.into(),
    })
}

/// Record a database-native backup in the evidence-only backup directory
/// `dir` as its last success. Evidence older than the current last success
/// is accepted but changes nothing, so a retried or late report never makes
/// the backup age look younger or older than the newest backup known. A
/// directory holding backups this module took is refused: evidence there
/// would hide the age of the real ones.
pub fn record_evidence(
    dir: &Path,
    evidence: BackupEvidence,
    now_ms: i64,
) -> Result<BackupManifest> {
    let BackupEvidence {
        file,
        sha256,
        size_bytes,
        taken_at_ms,
        tool,
    } = evidence;
    if file.is_empty()
        || file.len() > 255
        || file.starts_with('.')
        || file
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
    {
        bail!("file must be a plain name of 1 to 255 characters");
    }
    if tool.trim().is_empty() || tool.len() > 128 || tool.chars().any(char::is_control) {
        bail!("tool must name what took the backup in 1 to 128 characters");
    }
    crate::signature_verification::validate_prefixed_digest("sha256", &sha256)?;
    if taken_at_ms <= 0 || taken_at_ms > now_ms.saturating_add(EVIDENCE_CLOCK_SKEW_MS) {
        bail!("taken_at_ms {taken_at_ms} is not a time up to now");
    }
    let manifest = BackupManifest {
        schema: MANIFEST_SCHEMA.into(),
        file,
        sha256,
        size_bytes,
        taken_at_ms,
        tool: Some(tool),
    };
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating backup directory {}", dir.display()))?;
    let _lock = lock_dir(dir)?;
    if !list_backups(dir)?.is_empty() {
        bail!(
            "{} holds backups of a SQLite store; record evidence only in a tenant-mode hub's backup directory",
            dir.display()
        );
    }
    let mut status = read_status(dir).unwrap_or_else(|error| {
        eprintln!("backup status unreadable, starting a new one: {error:#}");
        empty_status()
    });
    if status
        .last_success
        .as_ref()
        .is_none_or(|last| last.taken_at_ms <= manifest.taken_at_ms)
    {
        status.last_success = Some(manifest.clone());
        write_status(dir, &status)?;
    }
    Ok(manifest)
}

/// Remove what an interrupted backup or prune left behind: this module's
/// partial and temporary files, and a manifest or signature of ours whose
/// database is gone. A database without a manifest is left alone: this module never
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
        } else if name.starts_with(PREFIX) && name.ends_with(".sig") {
            !path.with_extension("db").is_file()
                && std::fs::read(&path)
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<BackupSignature>(&raw).ok())
                    .is_some_and(|signature| signature.schema == SIGNATURE_SCHEMA)
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
/// manifest. With `roots`, the manifest must also carry a signature by one of
/// them. The evidence is also written under `drills/` beside the backup.
/// The scratch store is removed whether or not the drill passes.
pub fn drill(
    backup: &Path,
    scratch_dir: &Path,
    now_ms: i64,
    roots: Option<&TrustRoots>,
) -> Result<DrillEvidence> {
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
    let manifest_bytes = std::fs::read(manifest_path(backup))
        .with_context(|| format!("reading the manifest of {}", backup.display()))?;
    if let Some(roots) = roots {
        verify_manifest(backup, &manifest_bytes, roots)?;
    }
    let manifest: BackupManifest =
        serde_json::from_slice(&manifest_bytes).context("parsing the backup manifest")?;
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
        prune_drills(dir)?;
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

fn signature_path(backup: &Path) -> PathBuf {
    backup.with_extension("sig")
}

fn signed_bytes(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    bytes.extend_from_slice(manifest_bytes);
    bytes
}

/// Sign a manifest's exact bytes with the Ed25519 seed at `seed` (32 bytes,
/// mode 0600). The seed is read on every backup, so a rotated key applies
/// without a restart.
fn sign_manifest(manifest_bytes: &[u8], seed: &Path) -> Result<BackupSignature> {
    let key = SigningKey::from_bytes(
        &crate::approval_policy::load_signer_seed(seed)
            .context("loading the backup signing key")?,
    );
    Ok(BackupSignature {
        schema: SIGNATURE_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
        signature: STANDARD.encode(key.sign(&signed_bytes(manifest_bytes)).to_bytes()),
    })
}

/// Refuse unless `backup`'s manifest carries a signature by one of `roots`.
fn verify_manifest(backup: &Path, manifest_bytes: &[u8], roots: &TrustRoots) -> Result<()> {
    let path = signature_path(backup);
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("backup {} has no manifest signature", backup.display())
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let signature: BackupSignature =
        serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))?;
    if signature.schema != SIGNATURE_SCHEMA {
        bail!("unsupported backup signature schema {}", signature.schema);
    }
    let signer = roots.resolve(&signature.key_id)?;
    crate::signature_verification::verify_strict(
        &signer.verifying_key,
        "backup manifest signature",
        &signature.signature,
        &signed_bytes(manifest_bytes),
    )
    .with_context(|| {
        format!(
            "backup {} manifest signature does not verify",
            backup.display()
        )
    })
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

/// `status.json` of the backup directory `dir`, without drill evidence.
pub fn read_status(dir: &Path) -> Result<BackupStatus> {
    let path = dir.join(STATUS_FILE);
    match std::fs::read(&path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .with_context(|| format!("parsing backup status {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(empty_status()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_status(dir: &Path, status: &BackupStatus) -> Result<()> {
    // Drill evidence lives under `drills/`; `status.json` keeps its old shape.
    let on_disk = BackupStatus {
        last_drill: None,
        drills: Vec::new(),
        ..status.clone()
    };
    write_durable(&dir.join(STATUS_FILE), &on_disk)
}

/// Every drill file under `drills/` with its evidence, newest first.
fn drill_files(dir: &Path) -> Result<Vec<(PathBuf, DrillEvidence)>> {
    let drills = dir.join(DRILL_DIR);
    let entries = match std::fs::read_dir(&drills) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", drills.display())),
    };
    let mut found = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            // Pruned by a concurrent drill between listing and reading.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let evidence: DrillEvidence = serde_json::from_slice(&raw)
            .with_context(|| format!("parsing drill evidence {}", path.display()))?;
        found.push((path, evidence));
    }
    found.sort_by(|(left_path, left), (right_path, right)| {
        right
            .restored_at_ms
            .cmp(&left.restored_at_ms)
            .then_with(|| right_path.cmp(left_path))
    });
    Ok(found)
}

/// The kept drills, newest first.
fn drills(dir: &Path) -> Result<Vec<DrillEvidence>> {
    Ok(drill_files(dir)?
        .into_iter()
        .take(DRILL_HISTORY)
        .map(|(_, evidence)| evidence)
        .collect())
}

/// Remove drills beyond [`DRILL_HISTORY`], oldest first. Idempotent: a file
/// another drill removed first is already gone.
fn prune_drills(dir: &Path) -> Result<()> {
    for (path, _) in drill_files(dir)?.into_iter().skip(DRILL_HISTORY) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("removing {}", path.display()));
            }
        }
    }
    Ok(())
}

/// Write JSON so it is durable before it is visible: a unique temporary file,
/// synced, renamed into place, then the directory synced. Unique temporaries
/// let two processes write side by side without removing each other's file.
fn write_durable<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_durable_bytes(path, &serde_json::to_vec_pretty(value)?)
}

fn write_durable_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
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
        std::io::Write::write_all(&mut file, bytes)?;
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
                signing_key: None,
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
                None,
            )
            .unwrap();
            assert_eq!(evidence.integrity, "ok");
            assert!(evidence.environments >= previous && evidence.environments <= written);
            previous = evidence.environments;
        }
        let status = backups.status().unwrap();
        assert_eq!(status.last_success.as_ref(), taken.last());
        assert_eq!(status.last_drill.unwrap().file, taken[2].file);
        // #818: three drills, three history entries, newest first; the
        // status file itself still carries no drill.
        let files: Vec<_> = status
            .drills
            .iter()
            .map(|drill| drill.file.as_str())
            .collect();
        assert_eq!(files, [&taken[2].file, &taken[1].file, &taken[0].file]);
        let on_disk = std::fs::read_to_string(backups.policy().dir.join(STATUS_FILE)).unwrap();
        assert!(!on_disk.contains("drill"), "{on_disk}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// #818: drill history keeps the newest [`DRILL_HISTORY`] drills, and a
    /// prune that finds a file already gone (another drill pruned it) is fine.
    #[test]
    fn drill_history_keeps_the_newest_drills() {
        let root = temp_dir("drill-history");
        let dir = root.join(DRILL_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        for at in 1..=(DRILL_HISTORY as i64 + 2) {
            let evidence = DrillEvidence {
                schema: DRILL_SCHEMA.into(),
                file: format!("backup-{at}"),
                sha256: "abc".into(),
                restored_at_ms: at,
                integrity: "ok".into(),
                environments: 0,
                releases: 0,
                plans: 0,
            };
            write_durable(&dir.join(format!("drill-{at}.json")), &evidence).unwrap();
        }
        prune_drills(&root).unwrap();
        prune_drills(&root).unwrap();
        let kept = drills(&root).unwrap();
        assert_eq!(kept.len(), DRILL_HISTORY);
        assert_eq!(kept[0].restored_at_ms, DRILL_HISTORY as i64 + 2);
        assert_eq!(kept.last().unwrap().restored_at_ms, 3);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), DRILL_HISTORY);
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
        let error = drill(&path, &root.join("scratch"), 2_000, None).unwrap_err();
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
                tool: None,
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
        assert!(drill(&path, &scratch, 2_000, None).is_err());
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    fn signing_seed(dir: &Path, byte: u8) -> (PathBuf, TrustRoots) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(format!("backup-{byte}.seed"));
        std::fs::write(&path, [byte; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let public = SigningKey::from_bytes(&[byte; 32])
            .verifying_key()
            .to_bytes();
        let roots = TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: crate::signature_verification::key_id(&public),
                identity: "backup".into(),
                public_key: STANDARD.encode(public),
                not_before: None,
                not_after: None,
            }],
        };
        (path, roots)
    }

    /// A drill given trust roots runs only on a backup whose manifest is
    /// signed by one of them, as written.
    #[test]
    fn a_drill_with_trust_roots_refuses_a_manifest_signature_that_does_not_verify() {
        let root = temp_dir("signed");
        let (seed, roots) = signing_seed(&root, 42);
        let (_, other_roots) = signing_seed(&root, 7);
        let store = Arc::new(SqliteStore::open(root.join("tenkai.db")).unwrap());
        let policy = BackupPolicy {
            dir: root.join("backups"),
            retain: 1,
            max_age_ms: 60_000,
            signing_key: Some(seed),
        };
        let signed = Backups::new(store.clone(), policy.clone()).unwrap();
        let manifest = signed.take(1_000).unwrap();
        let path = policy.dir.join(&manifest.file);
        let scratch = root.join("scratch");
        drill(&path, &scratch, 2_000, Some(&roots)).unwrap();
        let error = drill(&path, &scratch, 2_000, Some(&other_roots)).unwrap_err();
        assert!(format!("{error:#}").contains("not trusted"), "{error:#}");

        // A changed manifest no longer verifies, even with a matching sha256.
        let original = std::fs::read(manifest_path(&path)).unwrap();
        let changed = String::from_utf8(original.clone())
            .unwrap()
            .replace("\"taken_at_ms\": 1000", "\"taken_at_ms\": 1001");
        std::fs::write(manifest_path(&path), changed).unwrap();
        let error = drill(&path, &scratch, 2_000, Some(&roots)).unwrap_err();
        assert!(
            format!("{error:#}").contains("does not verify"),
            "{error:#}"
        );
        std::fs::write(manifest_path(&path), original).unwrap();

        // Retention removes the signature with its backup, and a backup taken
        // without a key is refused once trust roots are required.
        let unsigned = Backups::new(
            store,
            BackupPolicy {
                signing_key: None,
                ..policy.clone()
            },
        )
        .unwrap();
        let next = unsigned.take(3_000).unwrap();
        assert!(!signature_path(&path).exists());
        let next = policy.dir.join(&next.file);
        let error = drill(&next, &scratch, 4_000, Some(&roots)).unwrap_err();
        assert!(
            format!("{error:#}").contains("no manifest signature"),
            "{error:#}"
        );
        drill(&next, &scratch, 4_000, None).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    /// A tenant-mode hub's backup set only reads recorded evidence: its
    /// health is `missing` until evidence arrives and `stale` once it ages.
    #[test]
    fn evidence_only_backups_report_the_age_of_recorded_evidence() {
        let root = temp_dir("evidence");
        let dir = root.join("backups");
        let evidence_set = Backups::evidence_only(BackupPolicy {
            dir: dir.clone(),
            retain: 1,
            max_age_ms: 60_000,
            signing_key: None,
        })
        .unwrap();
        assert_eq!(evidence_set.health(1_000).state, "missing");
        assert!(evidence_set.take(1_000).is_err());

        let dump = root.join("hub-1000.dump");
        std::fs::write(&dump, b"database-native dump").unwrap();
        let recorded = record_evidence(
            &dir,
            evidence_for_file(&dump, "dump tool 17", 1_000).unwrap(),
            1_000,
        )
        .unwrap();
        assert_eq!(recorded.file, "hub-1000.dump");
        assert_eq!(evidence_set.health(30_000).state, "ok");
        assert_eq!(evidence_set.health(100_000).state, "stale");
        assert_eq!(
            evidence_set.status().unwrap().last_success,
            Some(recorded.clone())
        );

        // A late report of an older backup does not replace the newest one.
        let older = BackupEvidence {
            file: "hub-500.dump".into(),
            taken_at_ms: 500,
            ..evidence_for_file(&dump, "dump tool 17", 500).unwrap()
        };
        record_evidence(&dir, older.clone(), 2_000).unwrap();
        assert_eq!(evidence_set.status().unwrap().last_success, Some(recorded));
        for refused in [
            BackupEvidence {
                file: "../escape".into(),
                ..older.clone()
            },
            BackupEvidence {
                sha256: "sha256:00".into(),
                ..older.clone()
            },
            BackupEvidence {
                taken_at_ms: 10_000_000,
                ..older
            },
        ] {
            assert!(record_evidence(&dir, refused, 2_000).is_err());
        }

        // Evidence never goes beside backups of a SQLite store.
        std::fs::create_dir_all(root.join("community")).unwrap();
        let (_store, sqlite) = backups(&root.join("community"), 1);
        sqlite.take(1_000).unwrap();
        let error = record_evidence(
            &sqlite.policy().dir,
            evidence_for_file(&dump, "dump tool 17", 1_000).unwrap(),
            1_000,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("SQLite store"), "{error:#}");
        let _ = std::fs::remove_dir_all(root);
    }
}

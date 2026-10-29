//! Exports an operator creates and downloads over HTTP (#682).
//!
//! Support bundles (#638), audit exports (#644), recovery bundles (ADR 0027)
//! and accepted offline receipts are produced by the server and kept in one
//! directory, so an operator without shell access can fetch them and see what
//! was exported, when and by whom. The artifact bytes are exactly what the CLI
//! writes, so the CLI verifiers accept a downloaded file unchanged.
//!
//! Each export is a directory `<id>/` holding `artifact.json`, `export.json`
//! (the [`ExportRecord`]) and `events/`, one file per creation or download
//! with its actor and reason. An export is assembled in a hidden staging
//! directory, synced, and renamed into place, so a crash never leaves a
//! partial export under its id. Events are append-only files, so concurrent
//! downloads never rewrite each other's record.
//!
//! With a retention (`TENKAI_EXPORT_RETENTION_DAYS`, #818) an export expires
//! that long after it was created: it can no longer be downloaded, its
//! artifact is removed the next time exports are listed, and its record and
//! events stay, so it is still listed, as expired. Removal deletes only
//! `<id>/artifact.json`, never the audit chain or anything else, and is
//! idempotent, so overlapping processes may both run it. Expiry is derived
//! from the creation time and the configured retention, not stored, so the
//! on-disk records keep the shape older versions read.
//!
//! A ranged audit export (#825) is an `audit-export` too: a
//! `tenkai.audit-range.v1` of the chain's exports `from..=to`, named
//! `audit-range-<from>-<to>.json`. Every audit export's entry carries the
//! sequences it covers, read from that name for the same reason.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const EXPORT_SCHEMA: &str = "tenkai.export.v1";
const ARTIFACT_FILE: &str = "artifact.json";
const RECORD_FILE: &str = "export.json";
const EVENTS_DIR: &str = "events";
const AUDIT_CHAIN_DIR: &str = "audit-chain";
const AUDIT_LOCK_FILE: &str = ".audit-chain.lock";
/// Longest reason accepted for a creation or download.
pub const MAX_REASON: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExportKind {
    /// Hub-wide: redacted, signed `tenkai.support-bundle.v1`.
    SupportBundle,
    /// Hub-wide: the next signed `tenkai.audit-export.v1` of this host's
    /// chain, or a `tenkai.audit-range.v1` of exports already in it.
    AuditExport,
    /// One environment's plan: `tenkai.recovery_bundle.v1`.
    RecoveryBundle,
    /// One isolated environment's accepted `tenkai.offline-receipt.v1`.
    OfflineReceipt,
}

impl ExportKind {
    /// Whether the export belongs to one environment, so an
    /// environment-scoped credential may create and read it.
    pub fn is_environment_scoped(self) -> bool {
        matches!(self, Self::RecoveryBundle | Self::OfflineReceipt)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SupportBundle => "support-bundle",
            Self::AuditExport => "audit-export",
            Self::RecoveryBundle => "recovery-bundle",
            Self::OfflineReceipt => "offline-receipt",
        }
    }
}

/// One stored export, as `export.json` records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRecord {
    pub schema: String,
    pub id: String,
    pub kind: ExportKind,
    /// Set exactly for environment-scoped kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub environment: Option<String>,
    /// The name the download carries, as the CLI would name the file.
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExportAction {
    Created,
    Downloaded,
}

/// Who created or downloaded an export, when, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportEvent {
    pub at_ms: i64,
    pub principal: String,
    pub action: ExportAction,
    pub reason: String,
}

/// An export with its events, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ExportEntry {
    #[serde(flatten)]
    pub export: ExportRecord,
    pub events: Vec<ExportEvent>,
    /// When it stops being downloadable, with a retention configured (#818).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub expires_at_ms: Option<i64>,
    /// The chain sequences an audit export covers (#825); one for the next
    /// entry, `from..=to` for a range.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub audit_range: Option<AuditSequences>,
    /// Past `expires_at_ms`, or its artifact already removed (a retention
    /// that was later raised or unset does not bring it back): listed, never
    /// downloadable.
    pub expired: bool,
}

/// Inclusive chain sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct AuditSequences {
    pub from: u64,
    pub to: u64,
}

impl AuditSequences {
    /// From `audit-<sequence>.json` or `audit-range-<from>-<to>.json`.
    fn from_file_name(name: &str) -> Option<Self> {
        if let Some(sequence) = crate::audit_export::chain_sequence(name) {
            return Some(Self {
                from: sequence,
                to: sequence,
            });
        }
        let (from, to) = name
            .strip_prefix("audit-range-")?
            .strip_suffix(".json")?
            .split_once('-')?;
        Some(Self {
            from: from.parse().ok()?,
            to: to.parse().ok()?,
        })
    }
}

/// `GET /v1/exports`, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ExportList {
    pub exports: Vec<ExportEntry>,
}

/// The export directory and the Ed25519 seed that signs support bundles and
/// audit exports.
#[derive(Debug)]
pub struct Exports {
    dir: PathBuf,
    seed: PathBuf,
    /// Signers of audit exports made before a key rotation.
    rotated: Option<crate::release_signing::TrustRoots>,
    /// How long an export stays downloadable; `None` keeps it for good.
    retention_ms: Option<i64>,
}

impl Exports {
    /// `rotated` names the signers of earlier audit exports in the chain, so
    /// it can continue after `seed` is rotated.
    pub fn new(
        dir: PathBuf,
        seed: PathBuf,
        rotated: Option<crate::release_signing::TrustRoots>,
    ) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating export directory {}", dir.display()))?;
        // Fail at startup, not on the first request.
        crate::approval_policy::load_signer_seed(&seed)?;
        Ok(Self {
            dir,
            seed,
            rotated,
            retention_ms: None,
        })
    }

    /// Expire exports `retention_ms` after creation (#818).
    pub fn with_retention(mut self, retention_ms: i64) -> Self {
        self.retention_ms = Some(retention_ms);
        self
    }

    pub fn seed(&self) -> &Path {
        &self.seed
    }

    /// Store the next audit export of this host's chain under
    /// `audit-chain/`, created by `event`.
    ///
    /// The chain advances durably before the export is stored, so a crash or
    /// a failed store in between leaves a chain entry without an export. Such
    /// entries are stored, oldest first, before the chain advances again, so
    /// every entry stays downloadable and the downloaded chain has no gap. An
    /// exclusive lock on the export directory serializes this across server
    /// processes that share it.
    pub fn next_audit_export(
        &self,
        store: &dyn crate::storage::OperationalStore,
        event: &ExportEvent,
    ) -> Result<ExportEntry> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(AUDIT_LOCK_FILE))?;
        lock.lock().context("locking the audit export chain")?;
        let chain = self.dir.join(AUDIT_CHAIN_DIR);
        let stored: std::collections::HashSet<String> = self
            .list()?
            .exports
            .into_iter()
            .filter(|entry| entry.export.kind == ExportKind::AuditExport)
            .map(|entry| entry.export.file_name)
            .collect();
        let entries = chain_entries(&chain)?;
        let missing = entries.iter().find(|name| !stored.contains(*name)).cloned();
        let name = match missing {
            Some(name) => name,
            None => {
                // Taken under the lock, and never before the newest entry's
                // end: requests may take the lock out of timestamp order.
                let previous_end = match entries.last() {
                    Some(newest) => {
                        crate::audit_export::AuditExport::load(&chain.join(newest))?
                            .statement
                            .period_end_ms
                    }
                    None => 0,
                };
                let next = crate::audit_export::export_next(
                    store,
                    &chain,
                    crate::now_millis().max(previous_end),
                    &self.seed,
                    self.rotated.as_ref(),
                )?;
                format!("audit-{:08}.json", next.statement.sequence)
            }
        };
        // The chain file itself, byte for byte what the CLI exporter writes.
        let artifact = std::fs::read(chain.join(&name))?;
        self.store(ExportKind::AuditExport, None, &name, &artifact, event)
    }

    /// Store the chain's exports `from..=to` as one ranged audit export,
    /// created by `event`. The chain must already hold the whole range and
    /// verify; the next-entry export is not advanced.
    pub fn audit_range_export(
        &self,
        from: u64,
        to: u64,
        event: &ExportEvent,
    ) -> Result<ExportEntry> {
        let roots = crate::audit_export::exporter_roots(&self.seed, self.rotated.as_ref())?;
        let range = crate::audit_export::range(&self.dir.join(AUDIT_CHAIN_DIR), from, to, &roots)?;
        self.store(
            ExportKind::AuditExport,
            None,
            &crate::audit_export::range_file_name(from, to),
            &serde_json::to_vec_pretty(&range)?,
            event,
        )
    }

    /// Store `artifact` as a new export, created by `event`.
    pub fn store(
        &self,
        kind: ExportKind,
        environment: Option<&str>,
        file_name: &str,
        artifact: &[u8],
        event: &ExportEvent,
    ) -> Result<ExportEntry> {
        let id = uuid::Uuid::new_v4().to_string();
        let export = ExportRecord {
            schema: EXPORT_SCHEMA.into(),
            id: id.clone(),
            kind,
            environment: environment.map(Into::into),
            file_name: safe_file_name(file_name),
            sha256: format!("{:x}", Sha256::digest(artifact)),
            size_bytes: artifact.len() as u64,
            created_at_ms: event.at_ms,
        };
        let staging = self.dir.join(format!(".staging-{id}"));
        let written = (|| {
            std::fs::create_dir(&staging)?;
            std::fs::create_dir(staging.join(EVENTS_DIR))?;
            write_new_synced(&staging.join(ARTIFACT_FILE), artifact)?;
            write_new_synced(
                &staging.join(RECORD_FILE),
                &serde_json::to_vec_pretty(&export)?,
            )?;
            write_new_synced(
                &staging.join(EVENTS_DIR).join(event_file(event)),
                &serde_json::to_vec_pretty(event)?,
            )?;
            sync_dir(&staging.join(EVENTS_DIR))?;
            sync_dir(&staging)?;
            std::fs::rename(&staging, self.dir.join(&id))?;
            sync_dir(&self.dir)
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error.context("storing export"));
        }
        Ok(self.with_expiry(
            ExportEntry {
                export,
                events: vec![event.clone()],
                expires_at_ms: None,
                audit_range: None,
                expired: false,
            },
            crate::now_millis(),
        ))
    }

    /// `entry` with its expiry as of `now_ms` and its audit range.
    fn with_expiry(&self, mut entry: ExportEntry, now_ms: i64) -> ExportEntry {
        entry.audit_range = (entry.export.kind == ExportKind::AuditExport)
            .then(|| AuditSequences::from_file_name(&entry.export.file_name))
            .flatten();
        entry.expires_at_ms = self
            .retention_ms
            .map(|retention| entry.export.created_at_ms.saturating_add(retention));
        entry.expired = entry.expires_at_ms.is_some_and(|at| now_ms >= at)
            || !self.dir.join(&entry.export.id).join(ARTIFACT_FILE).exists();
        entry
    }

    /// Every export, newest first. Staging directories are not exports.
    /// Expired artifacts are removed on the way.
    pub fn list(&self) -> Result<ExportList> {
        self.list_at(crate::now_millis())
    }

    pub fn list_at(&self, now_ms: i64) -> Result<ExportList> {
        let mut exports = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if uuid::Uuid::try_parse(&id).is_ok() {
                let entry = self.with_expiry(self.read_entry(&id)?, now_ms);
                if entry.expired {
                    self.remove_artifact(&id)?;
                }
                exports.push(entry);
            }
        }
        exports.sort_by(|a, b| {
            (b.export.created_at_ms, &b.export.id).cmp(&(a.export.created_at_ms, &a.export.id))
        });
        Ok(ExportList { exports })
    }

    /// One export; `None` for an id that is not a stored export.
    pub fn get(&self, id: &str) -> Result<Option<ExportEntry>> {
        if uuid::Uuid::try_parse(id).is_err() || !self.dir.join(id).join(RECORD_FILE).is_file() {
            return Ok(None);
        }
        Ok(Some(
            self.with_expiry(self.read_entry(id)?, crate::now_millis()),
        ))
    }

    /// Delete an expired export's artifact; its record and events stay.
    fn remove_artifact(&self, id: &str) -> Result<()> {
        match std::fs::remove_file(self.dir.join(id).join(ARTIFACT_FILE)) {
            Ok(()) => sync_dir(&self.dir.join(id)),
            // Already removed, by this or an overlapping process.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("removing expired export {id}")),
        }
    }

    /// Record `event` as a download, then return the artifact. The event is
    /// durable before any byte is handed out, so no download goes unrecorded.
    pub fn download(
        &self,
        id: &str,
        event: &ExportEvent,
    ) -> Result<Option<(ExportRecord, Vec<u8>)>> {
        let Some(entry) = self.get(id)? else {
            return Ok(None);
        };
        if entry.expired {
            bail!("{}", expired_message(&entry));
        }
        // Open before recording: an open handle keeps the bytes readable even
        // if a concurrent listing prunes the file now. Already pruned means
        // expired, and nothing is recorded.
        let Some(mut artifact_file) = self.open_artifact(id)? else {
            bail!("{}", expired_message(&entry));
        };
        // Readers see only `*.json`: write under a temporary name, then
        // rename, so no reader or crash ever meets a partial event.
        let events = self.dir.join(id).join(EVENTS_DIR);
        let temporary = events.join(format!(".event-{}.tmp", uuid::Uuid::new_v4()));
        let published = (|| {
            write_new_synced(&temporary, &serde_json::to_vec_pretty(event)?)?;
            std::fs::rename(&temporary, events.join(event_file(event)))?;
            sync_dir(&events)
        })();
        if published.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        published?;
        let mut artifact = Vec::new();
        std::io::Read::read_to_end(&mut artifact_file, &mut artifact)?;
        if format!("{:x}", Sha256::digest(&artifact)) != entry.export.sha256 {
            bail!("export {id} does not match its recorded digest");
        }
        Ok(Some((entry.export, artifact)))
    }

    /// The artifact opened for reading; `None` once it was pruned.
    fn open_artifact(&self, id: &str) -> Result<Option<std::fs::File>> {
        match std::fs::File::open(self.dir.join(id).join(ARTIFACT_FILE)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("opening export {id}")),
        }
    }

    fn read_entry(&self, id: &str) -> Result<ExportEntry> {
        let root = self.dir.join(id);
        let export: ExportRecord = serde_json::from_slice(&std::fs::read(root.join(RECORD_FILE))?)
            .with_context(|| format!("reading export {id}"))?;
        let mut events = Vec::new();
        for entry in std::fs::read_dir(root.join(EVENTS_DIR))? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                events.push(
                    serde_json::from_slice::<ExportEvent>(&std::fs::read(&path)?)
                        .with_context(|| format!("reading an event of export {id}"))?,
                );
            }
        }
        events.sort_by_key(|event| event.at_ms);
        Ok(ExportEntry {
            export,
            events,
            expires_at_ms: None,
            audit_range: None,
            expired: false,
        })
    }
}

/// Why an expired export cannot be downloaded.
pub fn expired_message(entry: &ExportEntry) -> String {
    match entry.expires_at_ms {
        Some(at) => format!("export {} expired at {at}", entry.export.id),
        None => format!(
            "export {} expired; its artifact was removed",
            entry.export.id
        ),
    }
}

/// The `audit-<sequence>.json` file names in `chain`, oldest first.
fn chain_entries(chain: &Path) -> Result<Vec<String>> {
    if !chain.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(chain)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(sequence) = crate::audit_export::chain_sequence(&name) {
            entries.push((sequence, name));
        }
    }
    entries.sort();
    Ok(entries.into_iter().map(|(_, name)| name).collect())
}

/// A reason of 1..=[`MAX_REASON`] bytes, trimmed.
pub fn validate_reason(reason: &str) -> Result<&str> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON {
        bail!("a reason of 1..={MAX_REASON} bytes is required");
    }
    Ok(reason)
}

/// The download name with anything but `[A-Za-z0-9._-]` replaced, so it
/// is safe in a `Content-Disposition` header and as a local file name.
fn safe_file_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn event_file(event: &ExportEvent) -> String {
    format!("{:013}-{}.json", event.at_ms, uuid::Uuid::new_v4())
}

/// Write a new file and sync it; an existing file is never replaced.
fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file =
        std::fs::File::create_new(path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exports(name: &str) -> (Exports, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-exports-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let seed = root.join("seed");
        std::fs::write(&seed, [7u8; 32]).unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (
            Exports::new(root.join("exports"), seed, None).unwrap(),
            root,
        )
    }

    fn event(at_ms: i64, action: ExportAction) -> ExportEvent {
        ExportEvent {
            at_ms,
            principal: "operator".into(),
            action,
            reason: "case 42".into(),
        }
    }

    #[test]
    fn stored_export_downloads_unchanged_and_records_every_download() {
        let (exports, root) = exports("roundtrip");
        let stored = exports
            .store(
                ExportKind::RecoveryBundle,
                Some("prod"),
                "recovery-prod-plan.json",
                b"{\"a\":1}",
                &event(1, ExportAction::Created),
            )
            .unwrap();
        let id = stored.export.id.clone();

        let (record, bytes) = exports
            .download(&id, &event(2, ExportAction::Downloaded))
            .unwrap()
            .unwrap();
        exports
            .download(&id, &event(3, ExportAction::Downloaded))
            .unwrap()
            .unwrap();

        assert_eq!(bytes, b"{\"a\":1}");
        assert_eq!(record, stored.export);
        let listed = exports.list().unwrap().exports;
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0]
                .events
                .iter()
                .map(|event| (event.at_ms, event.action))
                .collect::<Vec<_>>(),
            [
                (1, ExportAction::Created),
                (2, ExportAction::Downloaded),
                (3, ExportAction::Downloaded)
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// #818: past its retention an export is listed as expired, its
    /// artifact is gone and it cannot be downloaded; the audit chain and the
    /// record stay. A second sweep, as by an overlapping process, is a no-op.
    #[test]
    fn an_export_past_its_retention_is_listed_as_expired_and_not_downloadable() {
        let (exports, root) = exports("retention");
        let exports = exports.with_retention(1_000);
        // Created five seconds ago, with a one-second retention.
        let created = event(crate::now_millis() - 5_000, ExportAction::Created);
        let entry = exports
            .store(
                ExportKind::SupportBundle,
                None,
                "support.json",
                b"{}",
                &created,
            )
            .unwrap();
        assert_eq!(entry.expires_at_ms, Some(created.at_ms + 1_000));
        let chain = root.join("exports").join(AUDIT_CHAIN_DIR);
        std::fs::create_dir_all(&chain).unwrap();
        std::fs::write(chain.join("audit-00000001.json"), "{}").unwrap();

        let fresh = exports.list_at(created.at_ms + 999).unwrap();
        assert!(!fresh.exports[0].expired);
        let later = created.at_ms + 1_000;
        let listed = exports.list_at(later).unwrap();
        assert!(listed.exports[0].expired);
        assert_eq!(listed.exports[0].events.len(), 1);
        exports.list_at(later).unwrap();
        let id = &entry.export.id;
        let dir = root.join("exports").join(id);
        assert!(!dir.join(ARTIFACT_FILE).exists());
        assert!(dir.join(RECORD_FILE).exists());
        assert!(
            chain.join("audit-00000001.json").exists(),
            "the chain is never removed"
        );
        // Expired by the clock now, so the download is refused before any
        // event is recorded.
        let refused = exports
            .download(id, &event(later, ExportAction::Downloaded))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("expired"), "{refused}");
        assert_eq!(exports.get(id).unwrap().unwrap().events.len(), 1);

        // Retention raised, or unset, after the prune: still expired, and a
        // download records nothing.
        let unset = Exports::new(root.join("exports"), root.join("seed"), None).unwrap();
        for reopened in [unset, exports.with_retention(i64::MAX / 2)] {
            let listed = reopened.list_at(later).unwrap();
            assert!(listed.exports[0].expired, "{listed:?}");
            let refused = reopened
                .download(id, &event(later, ExportAction::Downloaded))
                .unwrap_err()
                .to_string();
            assert!(refused.contains("expired"), "{refused}");
            assert_eq!(reopened.get(id).unwrap().unwrap().events.len(), 1);
        }
        let body = serde_json::to_value(&listed.exports[0]).unwrap();
        assert_eq!(body["expired"], true);
        let fresh_body = serde_json::to_value(&fresh.exports[0]).unwrap();
        assert_eq!(fresh_body["expired"], false, "always serialized");
        let _ = std::fs::remove_dir_all(root);
    }

    /// #818: a download that opened its artifact still delivers every byte
    /// when a concurrent listing prunes the file before it is read.
    #[test]
    fn an_opened_artifact_survives_a_concurrent_prune() {
        let (exports, root) = exports("pinned");
        let created = event(crate::now_millis(), ExportAction::Created);
        let entry = exports
            .store(
                ExportKind::SupportBundle,
                None,
                "support.json",
                b"{\"bundle\":1}",
                &created,
            )
            .unwrap();
        let id = &entry.export.id;
        let mut opened = exports.open_artifact(id).unwrap().unwrap();
        exports.remove_artifact(id).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut opened, &mut bytes).unwrap();
        assert_eq!(bytes, b"{\"bundle\":1}");
        assert!(
            exports.open_artifact(id).unwrap().is_none(),
            "pruned for later downloads"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_ids_and_leftover_staging_are_not_exports() {
        let (exports, root) = exports("unknown");
        std::fs::create_dir(root.join("exports").join(".staging-x")).unwrap();
        assert!(exports.list().unwrap().exports.is_empty());
        assert!(exports.get("../seed").unwrap().is_none());
        assert!(
            exports
                .download(
                    &uuid::Uuid::new_v4().to_string(),
                    &event(1, ExportAction::Downloaded)
                )
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_partial_event_left_by_a_crash_is_not_read() {
        let (exports, root) = exports("partial");
        let id = exports
            .store(
                ExportKind::SupportBundle,
                None,
                "support.json",
                b"{}",
                &event(1, ExportAction::Created),
            )
            .unwrap()
            .export
            .id;
        let events = root.join("exports").join(&id).join(EVENTS_DIR);
        std::fs::write(events.join(".event-x.tmp"), b"{\"at_").unwrap();
        assert_eq!(exports.get(&id).unwrap().unwrap().events.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_chain_entry_left_without_an_export_is_stored_before_the_chain_advances() {
        let (exports, root) = exports("chain");
        let store = crate::storage::SqliteStore::open_in_memory().unwrap();
        // A crash after the chain advanced, before the export was stored.
        crate::audit_export::export_next(
            &store,
            &root.join("exports").join(AUDIT_CHAIN_DIR),
            1,
            exports.seed(),
            None,
        )
        .unwrap();

        // Another process advanced past it before the first stored its export.
        crate::audit_export::export_next(
            &store,
            &root.join("exports").join(AUDIT_CHAIN_DIR),
            2,
            exports.seed(),
            None,
        )
        .unwrap();

        let names: Vec<String> = (3..6)
            .map(|at| {
                exports
                    .next_audit_export(&store, &event(at, ExportAction::Created))
                    .unwrap()
                    .export
                    .file_name
            })
            .collect();

        assert_eq!(
            names,
            [
                "audit-00000001.json",
                "audit-00000002.json",
                "audit-00000003.json"
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_chain_advances_after_an_entry_that_ends_later_than_now() {
        let (exports, root) = exports("reorder");
        let store = crate::storage::SqliteStore::open_in_memory().unwrap();
        // A request that took the lock first with a later clock.
        let later = crate::now_millis() + 3_600_000;
        exports
            .next_audit_export(&store, &event(later, ExportAction::Created))
            .unwrap();
        crate::audit_export::export_next(
            &store,
            &root.join("exports").join(AUDIT_CHAIN_DIR),
            later,
            exports.seed(),
            None,
        )
        .unwrap();
        let stored = exports.list().unwrap().exports.len();
        // Store the entry above, then advance past it.
        exports
            .next_audit_export(&store, &event(1, ExportAction::Created))
            .unwrap();
        let next = exports
            .next_audit_export(&store, &event(1, ExportAction::Created))
            .unwrap();
        assert_eq!(stored, 1);
        assert_eq!(next.export.file_name, "audit-00000003.json");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_tampered_artifact_is_refused() {
        let (exports, root) = exports("tampered");
        let id = exports
            .store(
                ExportKind::SupportBundle,
                None,
                "support.json",
                b"{}",
                &event(1, ExportAction::Created),
            )
            .unwrap()
            .export
            .id;
        std::fs::write(root.join("exports").join(&id).join(ARTIFACT_FILE), b"{ }").unwrap();
        assert!(
            exports
                .download(&id, &event(2, ExportAction::Downloaded))
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

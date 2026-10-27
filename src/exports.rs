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
    /// Hub-wide: the next signed `tenkai.audit-export.v1` of this host's chain.
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
        Ok(Self { dir, seed, rotated })
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
        Ok(ExportEntry {
            export,
            events: vec![event.clone()],
        })
    }

    /// Every export, newest first. Staging directories are not exports.
    pub fn list(&self) -> Result<ExportList> {
        let mut exports = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if uuid::Uuid::try_parse(&id).is_ok() {
                exports.push(self.read_entry(&id)?);
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
        self.read_entry(id).map(Some)
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
        let artifact = std::fs::read(self.dir.join(id).join(ARTIFACT_FILE))?;
        if format!("{:x}", Sha256::digest(&artifact)) != entry.export.sha256 {
            bail!("export {id} does not match its recorded digest");
        }
        Ok(Some((entry.export, artifact)))
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
        Ok(ExportEntry { export, events })
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
        let sequence = name
            .strip_prefix("audit-")
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|digits| digits.parse::<u64>().ok());
        if let Some(sequence) = sequence {
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

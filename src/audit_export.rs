//! Signed, chained audit exports (#644) with derived usage records (#639).
//!
//! An export lists every audit record (who did which management action,
//! with what outcome) and every change event (approvals, plans, holds,
//! receipts and other delivery transitions) written since the previous
//! export, plus a documented `usage` record kind of Tenkai's own
//! deployment activity in that period. Entries carry identities, outcomes
//! and integer quantities only: no credentials, request bodies, payloads
//! or billing.
//!
//! Exports are bounded by durable insertion cursors, not by time: each
//! starts at the audit and change cursors where the previous one ended, so a
//! record that commits late, or under a clock that moved back, lands in the
//! next export instead of falling between two. The period times are the
//! previous export's end and this export's time, for reading. Usage records
//! are derived from the audit and change entries of this export; they are
//! not a second chain.
//!
//! Exports chain: each names the digest of the one before it, with a
//! sequence number one higher. [`verify_chain`] refuses a cursor gap, a
//! reordered or missing export, and any change to a signed statement. The
//! first export of a chain has sequence 1 and no predecessor. The same
//! period exported twice is byte-identical.
//!
//! A ranged export (#825) is an [`AuditRange`]: the existing signed exports
//! with sequences `from..=to`, unchanged. There is no new signed statement:
//! each export verifies on its own with [`verify_chain`]'s rules, and
//! [`verify_range`] adds that they are exactly the range, contiguous, and
//! chain to each other. Range files are named `audit-range-<from>-<to>.json`,
//! never taken for chain entries. The range bounds sit outside any signature, so a
//! range shortened at either end reads as a different range; the export
//! record that delivered it names the range it was asked for.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::release_signing::TrustRoots;
use crate::storage::OperationalStore;

pub const AUDIT_EXPORT_SCHEMA: &str = "tenkai.audit-export.v1";
pub const AUDIT_RANGE_SCHEMA: &str = "tenkai.audit-range.v1";
/// Most exports one ranged export carries.
pub const MAX_RANGE_EXPORTS: u64 = 1_000;
const SIGNING_DOMAIN: &[u8] = b"TENKAI-AUDIT-EXPORT-V1\0";
const PAGE: usize = 1_000;
const USAGE_SOURCE: &str = "usage";
const USAGE_ENVIRONMENTS: &str = "environments.managed";
const USAGE_PLANS: &str = "plans.applied";
const USAGE_RELEASES: &str = "releases.deployed";
const USAGE_EXECUTOR_HOURS: &str = "executor.hours";
const USAGE_RUNTIME_HOURS: &str = "runtime.hours";

/// One audited fact. Identities and outcomes only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub at_ms: i64,
    /// `audit` (a management action), `change` (a delivery transition), or
    /// `usage` (a period quantity of Tenkai's own deployment activity).
    pub source: String,
    /// The audit record or change event id.
    pub id: String,
    /// Insertion cursor in its source: audit row or change event sequence.
    pub cursor: i64,
    /// The audit operation, or the change event kind.
    pub action: String,
    /// The acting principal for an audit record; empty for a change event.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub principal: String,
    pub resource: String,
    /// `requested`, `completed`, `failed`, ...; empty for a change event.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outcome: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStatement {
    pub sequence: u64,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    /// Audit cursors covered: after `audit_after`, through `audit_through`.
    pub audit_after: i64,
    pub audit_through: i64,
    /// Change event cursors covered: after `change_after`, through `change_through`.
    pub change_after: i64,
    pub change_through: i64,
    /// Identity of the record at `audit_through` and of the change event at
    /// `change_through` (empty at cursor 0), carried through empty exports,
    /// so the next export can tell the store still holds what was covered.
    pub audit_last: String,
    pub change_last: String,
    /// Digest of the previous export; absent for the first of a chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExport {
    pub schema: String,
    pub key_id: String,
    pub statement: AuditStatement,
    pub signature: String,
}

impl AuditExport {
    /// The digest the next export names: over the signed bytes.
    pub fn digest(&self) -> Result<String> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(canonical_bytes(&self.statement)?)
        ))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading audit export {}", path.display()))?;
        serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))
    }
}

/// The signed exports with sequences `from..=to` of one chain, oldest
/// first, each byte-for-byte as the chain holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRange {
    pub schema: String,
    pub from: u64,
    pub to: u64,
    pub exports: Vec<AuditExport>,
}

impl AuditRange {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading audit range {}", path.display()))?;
        serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))
    }
}

/// Whether `from..=to` is a range a ranged export may cover.
fn check_bounds(from: u64, to: u64) -> Result<()> {
    if from == 0 || to < from {
        bail!("an audit range runs from sequence 1 or later through a sequence no lower");
    }
    if to - from + 1 > MAX_RANGE_EXPORTS {
        bail!("an audit range covers at most {MAX_RANGE_EXPORTS} exports");
    }
    Ok(())
}

/// The exports `from..=to` of the chain in `dir`, verified against `roots`.
/// Refuses a range the chain does not hold in full.
pub fn range(dir: &Path, from: u64, to: u64, roots: &TrustRoots) -> Result<AuditRange> {
    check_bounds(from, to)?;
    let exports = (from..=to)
        .map(|sequence| {
            let path = dir.join(format!("audit-{sequence:08}.json"));
            if !path.is_file() {
                bail!("the audit chain holds no export {sequence}");
            }
            AuditExport::load(&path)
        })
        .collect::<Result<Vec<_>>>()?;
    let range = AuditRange {
        schema: AUDIT_RANGE_SCHEMA.into(),
        from,
        to,
        exports,
    };
    verify_range(&range, roots, None)?;
    Ok(range)
}

/// Verify a ranged export: exactly the exports `from..=to`, each signed by a
/// trusted key, contiguous and chained as [`verify_chain`] checks. With
/// `anchor` the first export must name that digest (the export before
/// `from`); without it the range is anchored on itself.
pub fn verify_range(range: &AuditRange, roots: &TrustRoots, anchor: Option<&str>) -> Result<()> {
    if range.schema != AUDIT_RANGE_SCHEMA {
        bail!("unsupported audit range schema {}", range.schema);
    }
    check_bounds(range.from, range.to)?;
    let first = range
        .exports
        .first()
        .context("an audit range holds no exports")?;
    if first.statement.sequence != range.from
        || range.exports.len() as u64 != range.to - range.from + 1
    {
        bail!(
            "the audit range {}..={} does not hold exactly those exports",
            range.from,
            range.to
        );
    }
    let anchor = anchor.or(first.statement.previous_digest.as_deref());
    verify_chain(&range.exports, roots, anchor)
}

fn canonical_bytes(statement: &AuditStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

/// Audit records and change events written after the given cursors, with
/// the cursors they end at, oldest first by time.
fn entries_after(
    store: &dyn OperationalStore,
    audit_after: i64,
    change_after: i64,
) -> Result<(Vec<AuditEntry>, i64, i64)> {
    let mut entries = Vec::new();
    let mut audit_through = audit_after;
    loop {
        let page = store.audit_events_after(audit_through, PAGE)?;
        for (cursor, record) in &page {
            audit_through = *cursor;
            entries.push(AuditEntry {
                at_ms: record.occurred_at,
                source: "audit".into(),
                id: record.id.clone(),
                cursor: *cursor,
                action: record.operation.clone(),
                principal: record.principal.clone(),
                resource: record.resource.clone(),
                outcome: record.outcome.clone(),
                environment: String::new(),
            });
        }
        if page.len() < PAGE {
            break;
        }
    }
    let mut change_through = change_after;
    loop {
        let page = store.list_change_events_after(change_through, PAGE)?;
        for event in &page {
            let cursor: i64 = event
                .cursor
                .parse()
                .with_context(|| format!("change event cursor {}", event.cursor))?;
            change_through = cursor;
            entries.push(AuditEntry {
                at_ms: event.occurred_at,
                source: "change".into(),
                id: event.cursor.clone(),
                cursor,
                action: event.kind.as_str().into(),
                principal: String::new(),
                resource: event.resource.clone(),
                outcome: String::new(),
                environment: event.environment.clone().unwrap_or_default(),
            });
        }
        if page.len() < PAGE {
            break;
        }
    }
    sort_entries(&mut entries);
    Ok((entries, audit_through, change_through))
}

fn sort_entries(entries: &mut [AuditEntry]) {
    entries.sort_by(|left, right| {
        (
            left.at_ms,
            left.source.as_str(),
            left.cursor,
            left.action.as_str(),
            left.id.as_str(),
        )
            .cmp(&(
                right.at_ms,
                right.source.as_str(),
                right.cursor,
                right.action.as_str(),
                right.id.as_str(),
            ))
    });
}

/// Period quantities of Tenkai's own deployment activity. Counts only;
/// millihours stay 0 until execution interval evidence exists. Nothing is priced.
fn usage_records(period_end_ms: i64, entries: &[AuditEntry]) -> Vec<AuditEntry> {
    let mut environments = std::collections::BTreeSet::new();
    let mut plans = 0_u64;
    for entry in entries {
        if entry.source != "change" {
            continue;
        }
        if !entry.environment.is_empty() {
            environments.insert(entry.environment.as_str());
        }
        if entry.action == "plan_applied" {
            plans += 1;
        }
    }
    [
        (USAGE_ENVIRONMENTS, environments.len().to_string()),
        (USAGE_PLANS, plans.to_string()),
        (USAGE_RELEASES, plans.to_string()),
        (USAGE_EXECUTOR_HOURS, "0".into()),
        (USAGE_RUNTIME_HOURS, "0".into()),
    ]
    .into_iter()
    .map(|(action, outcome)| AuditEntry {
        at_ms: period_end_ms,
        source: USAGE_SOURCE.into(),
        id: format!("usage:{action}"),
        cursor: 0,
        action: action.into(),
        principal: String::new(),
        resource: "tenkai".into(),
        outcome,
        environment: String::new(),
    })
    .collect()
}

/// Sign the export of everything written since `previous` (or since the
/// beginning), stamped `end_ms`.
pub fn export(
    store: &dyn OperationalStore,
    previous: Option<&AuditExport>,
    end_ms: i64,
    seed_path: &Path,
) -> Result<AuditExport> {
    let (sequence, previous_digest, start_ms, audit_after, change_after, audit_last, change_last) =
        match previous {
            Some(previous) => (
                previous.statement.sequence + 1,
                Some(previous.digest()?),
                previous.statement.period_end_ms,
                previous.statement.audit_through,
                previous.statement.change_through,
                previous.statement.audit_last.clone(),
                previous.statement.change_last.clone(),
            ),
            None => (1, None, 0, 0, 0, String::new(), String::new()),
        };
    if end_ms < start_ms {
        bail!("an audit export cannot end before the previous one ended");
    }
    if let Some(previous) = previous {
        require_store_continues(store, previous)?;
    }
    let (mut entries, audit_through, change_through) =
        entries_after(store, audit_after, change_after)?;
    let newest = |source: &str, cursor: i64| {
        entries
            .iter()
            .find(|entry| entry.source == source && entry.cursor == cursor)
            .map(fingerprint)
    };
    let audit_last = newest("audit", audit_through).unwrap_or(audit_last);
    let change_last = newest("change", change_through).unwrap_or(change_last);
    entries.extend(usage_records(end_ms, &entries));
    sort_entries(&mut entries);
    let statement = AuditStatement {
        audit_last,
        change_last,
        sequence,
        period_start_ms: start_ms,
        period_end_ms: end_ms,
        audit_after,
        audit_through,
        change_after,
        change_through,
        previous_digest,
        entries,
    };
    let key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let signature = key.sign(&canonical_bytes(&statement)?);
    Ok(AuditExport {
        schema: AUDIT_EXPORT_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

/// Identity of one entry, to recognize the same record later.
fn fingerprint(entry: &AuditEntry) -> String {
    format!(
        "{}|{}|{}|{}",
        entry.id, entry.action, entry.resource, entry.at_ms
    )
}

/// Refuse to continue a chain the store no longer holds: after a restore
/// from an older backup, cursors the chain already covered are reused by new
/// records, which a continuation would skip. The record at each of the
/// previous export's last cursors must still be the one it recorded.
fn require_store_continues(store: &dyn OperationalStore, previous: &AuditExport) -> Result<()> {
    let statement = &previous.statement;
    for (source, cursor, last) in [
        ("audit", statement.audit_through, &statement.audit_last),
        ("change", statement.change_through, &statement.change_last),
    ] {
        if cursor > 0
            && stored_at(store, source, cursor)?
                .as_ref()
                .map(fingerprint)
                .as_ref()
                != Some(last)
        {
            bail!(
                "the operational store no longer holds what audit export {} covered (restored from an older backup?); start a new audit chain in a new directory",
                statement.sequence
            );
        }
    }
    Ok(())
}

/// The entry of `source` stored at exactly `cursor`, if any.
fn stored_at(
    store: &dyn OperationalStore,
    source: &str,
    cursor: i64,
) -> Result<Option<AuditEntry>> {
    Ok(match source {
        "audit" => store
            .audit_events_after(cursor - 1, 1)?
            .into_iter()
            .find(|(at, _)| *at == cursor)
            .map(|(cursor, record)| AuditEntry {
                at_ms: record.occurred_at,
                source: "audit".into(),
                id: record.id,
                cursor,
                action: record.operation,
                principal: record.principal,
                resource: record.resource,
                outcome: record.outcome,
                environment: String::new(),
            }),
        _ => store
            .list_change_events_after(cursor - 1, 1)?
            .into_iter()
            .find(|event| event.cursor == cursor.to_string())
            .map(|event| AuditEntry {
                at_ms: event.occurred_at,
                source: "change".into(),
                id: event.cursor,
                cursor,
                action: event.kind.as_str().into(),
                principal: String::new(),
                resource: event.resource,
                outcome: String::new(),
                environment: event.environment.unwrap_or_default(),
            }),
    })
}

/// Write the next export of a directory chain: everything written since the
/// newest `audit-<sequence>.json` in `dir` (or since the beginning).
///
/// The existing chain is verified first, signed by this seed's key or by a
/// key in `extra_roots` (for exports made before a key rotation), so a
/// damaged or incomplete directory is never continued.
pub fn export_next(
    store: &dyn OperationalStore,
    dir: &Path,
    end: i64,
    seed_path: &Path,
    extra_roots: Option<&TrustRoots>,
) -> Result<AuditExport> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut chain = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let is_export = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(chain_sequence)
            .is_some();
        if is_export {
            chain.push(AuditExport::load(&path)?);
        }
    }
    chain.sort_by_key(|export| export.statement.sequence);
    let roots = exporter_roots(seed_path, extra_roots)?;
    if !chain.is_empty() {
        verify_chain(&chain, &roots, None)
            .with_context(|| format!("the audit chain in {} does not verify", dir.display()))?;
    }
    let next = export(store, chain.last(), end, seed_path)?;
    let path = dir.join(format!("audit-{:08}.json", next.statement.sequence));
    publish_new(&path, &serde_json::to_vec_pretty(&next)?)?;
    Ok(next)
}

/// The sequence of a chain entry file, `audit-<digits>.json`. Anything
/// else, such as an `audit-range-<from>-<to>.json` beside the chain, is not
/// part of it.
pub fn chain_sequence(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("audit-")?.strip_suffix(".json")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The file name of the ranged export `from..=to`.
pub fn range_file_name(from: u64, to: u64) -> String {
    format!("audit-range-{from:08}-{to:08}.json")
}

/// Write `range` to `path` as [`export_next`] writes a chain entry: whole
/// and synced before it appears, never replacing an existing file.
pub fn write_range(range: &AuditRange, path: &Path) -> Result<()> {
    publish_new(path, &serde_json::to_vec_pretty(range)?)
}

/// Publish `bytes` at `path`: written and synced under a unique temporary
/// name beside it, then hard-linked into place, so a crash never leaves a
/// partial file at `path`, a leftover temporary never blocks a retry, and a
/// file another writer published is never replaced.
fn publish_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let temporary = dir.join(format!(".audit-{}.tmp", uuid::Uuid::new_v4()));
    let written = (|| {
        use std::io::Write as _;
        let mut file = std::fs::File::create_new(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)
            .with_context(|| format!("{} already exists", path.display()))?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    let _ = std::fs::remove_file(&temporary);
    written
}

/// The roots a chain signed with `seed_path` verifies against: its key, plus
/// `extra_roots` for exports made before a key rotation.
pub fn exporter_roots(seed_path: &Path, extra_roots: Option<&TrustRoots>) -> Result<TrustRoots> {
    let key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let public = key.verifying_key().to_bytes();
    let mut roots = extra_roots.cloned().unwrap_or(TrustRoots {
        version: crate::release_signing::TRUST_ROOT_VERSION,
        signers: Vec::new(),
    });
    roots.signers.push(crate::release_signing::TrustedSigner {
        key_id: crate::signature_verification::key_id(&public),
        identity: "this audit exporter".into(),
        public_key: STANDARD.encode(public),
    });
    Ok(roots)
}

/// Verify one chain of exports, in order: every signature by a trusted key,
/// contiguous periods, increasing sequence, and each export naming its
/// predecessor's digest. The first export may continue an earlier chain:
/// pass that chain's last digest as `anchor`, or `None` when it starts at 1.
pub fn verify_chain(
    exports: &[AuditExport],
    roots: &TrustRoots,
    anchor: Option<&str>,
) -> Result<()> {
    if exports.is_empty() {
        bail!("no audit exports to verify");
    }
    let mut previous: Option<&AuditExport> = None;
    for export in exports {
        let statement = &export.statement;
        if export.schema != AUDIT_EXPORT_SCHEMA {
            bail!("unsupported audit export schema {}", export.schema);
        }
        let signer = roots.resolve(&export.key_id)?;
        crate::signature_verification::verify_strict(
            &signer.verifying_key,
            "audit export signature",
            &export.signature,
            &canonical_bytes(statement)?,
        )
        .with_context(|| format!("audit export {} was changed", statement.sequence))?;
        let in_range = |entry: &AuditEntry| match entry.source.as_str() {
            "audit" => {
                statement.audit_after < entry.cursor && entry.cursor <= statement.audit_through
            }
            "change" => {
                statement.change_after < entry.cursor && entry.cursor <= statement.change_through
            }
            USAGE_SOURCE => {
                entry.cursor == 0
                    && entry.at_ms == statement.period_end_ms
                    && entry.id == format!("usage:{}", entry.action)
                    && matches!(
                        entry.action.as_str(),
                        USAGE_ENVIRONMENTS
                            | USAGE_PLANS
                            | USAGE_RELEASES
                            | USAGE_EXECUTOR_HOURS
                            | USAGE_RUNTIME_HOURS
                    )
            }
            _ => false,
        };
        if statement.period_end_ms < statement.period_start_ms
            || statement.audit_through < statement.audit_after
            || statement.change_through < statement.change_after
            || !statement.entries.iter().all(in_range)
        {
            bail!(
                "audit export {} holds entries outside its cursors",
                statement.sequence
            );
        }
        match previous {
            Some(previous) => {
                if statement.sequence != previous.statement.sequence + 1 {
                    bail!(
                        "audit export {} follows {}: an export is missing or out of order",
                        statement.sequence,
                        previous.statement.sequence
                    );
                }
                if statement.audit_after != previous.statement.audit_through
                    || statement.change_after != previous.statement.change_through
                    || statement.period_start_ms != previous.statement.period_end_ms
                {
                    bail!(
                        "gap between audit exports {} and {}: records between them are not covered",
                        previous.statement.sequence,
                        statement.sequence
                    );
                }
                if statement.previous_digest.as_deref() != Some(previous.digest()?.as_str()) {
                    bail!(
                        "audit export {} does not chain to export {}",
                        statement.sequence,
                        previous.statement.sequence
                    );
                }
            }
            None => match anchor {
                Some(anchor) => {
                    if statement.previous_digest.as_deref() != Some(anchor) {
                        bail!(
                            "audit export {} does not chain to the given anchor",
                            statement.sequence
                        );
                    }
                }
                None => {
                    if statement.sequence != 1 || statement.previous_digest.is_some() {
                        bail!(
                            "audit export {} continues an earlier chain; pass its anchor",
                            statement.sequence
                        );
                    }
                }
            },
        }
        previous = Some(export);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AuditRecord, SqliteStore};

    fn seed(dir: &Path) -> (std::path::PathBuf, TrustRoots) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("audit.seed");
        std::fs::write(&path, [42_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key = SigningKey::from_bytes(&[42_u8; 32]);
        let public = key.verifying_key().to_bytes();
        let roots = TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: crate::signature_verification::key_id(&public),
                identity: "audit".into(),
                public_key: STANDARD.encode(public),
            }],
        };
        (path, roots)
    }

    fn audit(store: &SqliteStore, at: i64, operation: &str) {
        store
            .append_audit(&AuditRecord {
                id: format!("a-{at}"),
                occurred_at: at,
                principal: "management".into(),
                operation: operation.into(),
                resource: "*".into(),
                outcome: operation.rsplit('.').next().unwrap().into(),
            })
            .unwrap();
    }

    #[test]
    fn chained_exports_detect_gaps_reordering_and_tampering() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-audit-export-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (seed_path, roots) = seed(&dir);
        let store = SqliteStore::open(dir.join("tenkai.db")).unwrap();
        audit(&store, 100, "plan.approve.completed");

        let first = export(&store, None, 200, &seed_path).unwrap();
        assert_eq!(observed(&first).len(), 1);
        assert_eq!(usage_outcome(&first, USAGE_ENVIRONMENTS), "0");
        assert_eq!(usage_outcome(&first, USAGE_PLANS), "0");
        let again = export(&store, None, 200, &seed_path).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&again).unwrap()
        );
        // A record stamped before the first export but committed after it
        // (a slow write, or a clock that moved back) lands in the next one.
        audit(&store, 150, "plan.apply.completed");
        store
            .append_change_event(260, "plan_applied", "plan-1", "prod")
            .unwrap();
        let second = export(&store, Some(&first), 300, &seed_path).unwrap();
        assert_eq!(observed(&second).len(), 2);
        assert_eq!(observed(&second)[0].at_ms, 150);
        assert_eq!(observed(&second)[1].environment, "prod");
        assert_eq!(usage_outcome(&second, USAGE_ENVIRONMENTS), "1");
        assert_eq!(usage_outcome(&second, USAGE_PLANS), "1");
        verify_chain(&[first.clone(), second.clone()], &roots, None).unwrap();

        // A cursor gap between exports.
        let third = export(&store, Some(&second), 400, &seed_path).unwrap();
        let mut gapped = third.clone();
        gapped.statement.audit_after += 1;
        let error =
            verify_chain(&[first.clone(), second.clone(), gapped], &roots, None).unwrap_err();
        assert!(format!("{error:#}").contains("was changed") || error.to_string().contains("gap"));
        // A missing or reordered export.
        let error = verify_chain(&[second.clone(), first.clone()], &roots, None).unwrap_err();
        assert!(
            error.to_string().contains("continues an earlier chain"),
            "{error}"
        );
        let error = verify_chain(&[first.clone(), third.clone()], &roots, None).unwrap_err();
        assert!(
            error.to_string().contains("missing or out of order"),
            "{error}"
        );
        // A later chain verifies against its anchor.
        verify_chain(&[third], &roots, Some(&second.digest().unwrap())).unwrap();
        // Tampering with a signed entry.
        let mut tampered = second.clone();
        tampered.statement.entries[0].principal = "someone-else".into();
        let error = verify_chain(&[first.clone(), tampered], &roots, None).unwrap_err();
        assert!(format!("{error:#}").contains("was changed"), "{error:#}");

        // The directory chain continues from the newest export.
        let chain = dir.join("exports");
        let a = export_next(&store, &chain, 500, &seed_path, None).unwrap();
        audit(&store, 510, "backup.take.completed");
        let b = export_next(&store, &chain, 600, &seed_path, None).unwrap();
        assert_eq!((a.statement.sequence, observed(&b).len()), (1, 1));
        verify_chain(&[a.clone(), b], &roots, None).unwrap();
        // A damaged directory chain is not continued.
        let mut edited = a;
        edited.statement.audit_through += 5;
        std::fs::write(
            chain.join("audit-00000001.json"),
            serde_json::to_vec(&edited).unwrap(),
        )
        .unwrap();
        assert!(export_next(&store, &chain, 700, &seed_path, None).is_err());

        // A store restored to before the chain's last cursor is refused, even
        // after exports that added nothing.
        let empty = export(&store, Some(&second), 450, &seed_path).unwrap();
        let empty = export(&store, Some(&empty), 460, &seed_path).unwrap();
        assert!(observed(&empty).is_empty());
        let restored = SqliteStore::open(dir.join("restored.db")).unwrap();
        audit(&restored, 100, "plan.approve.completed");
        audit(&restored, 700, "someone.else.completed");
        restored
            .append_change_event(710, "plan_applied", "plan-9", "prod")
            .unwrap();
        let error = export(&restored, Some(&empty), 800, &seed_path).unwrap_err();
        assert!(
            error.to_string().contains("start a new audit chain"),
            "{error}"
        );

        let mut usage_tampered = second.clone();
        let plans = usage_tampered
            .statement
            .entries
            .iter_mut()
            .find(|entry| entry.source == USAGE_SOURCE && entry.action == USAGE_PLANS)
            .unwrap();
        plans.outcome = "99".into();
        let error = verify_chain(&[first.clone(), usage_tampered], &roots, None).unwrap_err();
        assert!(format!("{error:#}").contains("was changed"), "{error:#}");

        let body = serde_json::to_string(&second).unwrap();
        for leak in ["price", "invoice", "currency", "bill"] {
            assert!(!body.contains(leak), "{leak} in {body}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_ranged_export_holds_exactly_its_range_and_refuses_gaps_and_edits() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-audit-range-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (seed_path, roots) = seed(&dir);
        let store = SqliteStore::open(dir.join("tenkai.db")).unwrap();
        let chain = dir.join("chain");
        let mut written = Vec::new();
        for at in [100, 200, 300, 400] {
            audit(&store, at, &format!("step-{at}.completed"));
            written.push(export_next(&store, &chain, at + 50, &seed_path, None).unwrap());
        }

        let range = range(&chain, 2, 3, &roots).unwrap();
        assert_eq!(range.exports, written[1..3]);
        assert_eq!(
            range
                .exports
                .iter()
                .flat_map(observed)
                .map(|entry| entry.action.as_str())
                .collect::<Vec<_>>(),
            ["step-200.completed", "step-300.completed"]
        );
        verify_range(&range, &roots, None).unwrap();
        verify_range(&range, &roots, Some(&written[0].digest().unwrap())).unwrap();
        assert!(verify_range(&range, &roots, Some(&written[1].digest().unwrap())).is_err());
        assert!(
            super::range(&chain, 3, 5, &roots).is_err(),
            "beyond the chain"
        );
        assert!(super::range(&chain, 0, 1, &roots).is_err());

        // A range file beside the chain is not a chain entry: the chain
        // still continues.
        let beside = chain.join(range_file_name(2, 3));
        write_range(&range, &beside).unwrap();
        audit(&store, 500, "step-500.completed");
        let next = export_next(&store, &chain, 550, &seed_path, None).unwrap();
        assert_eq!(next.statement.sequence, 5);

        // Written like a chain entry: a leftover partial temporary does not
        // block it, and an existing file is refused, not truncated.
        let out_dir = dir.join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(out_dir.join(".audit-crashed.tmp"), b"{\"part").unwrap();
        let out = out_dir.join("range.json");
        write_range(&range, &out).unwrap();
        assert_eq!(AuditRange::load(&out).unwrap(), range);
        let before = std::fs::read(&out).unwrap();
        let other = super::range(&chain, 1, 1, &roots).unwrap();
        let error = write_range(&other, &out).unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error:#}");
        assert_eq!(std::fs::read(&out).unwrap(), before);

        // An export missing from inside the range.
        let wide = super::range(&chain, 1, 4, &roots).unwrap();
        let mut missing = wide.clone();
        missing.exports.remove(2);
        assert!(verify_range(&missing, &roots, None).is_err());
        missing.to = 3;
        let error = verify_range(&missing, &roots, None).unwrap_err();
        assert!(error.to_string().contains("out of order"), "{error:#}");
        // An altered or dropped record inside an export.
        let mut altered = wide.clone();
        altered.exports[1].statement.entries[0].principal = "someone-else".into();
        let error = verify_range(&altered, &roots, None).unwrap_err();
        assert!(format!("{error:#}").contains("was changed"), "{error:#}");
        let mut dropped = wide;
        dropped.exports[2].statement.entries.remove(0);
        let error = verify_range(&dropped, &roots, None).unwrap_err();
        assert!(format!("{error:#}").contains("was changed"), "{error:#}");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn observed(export: &AuditExport) -> Vec<&AuditEntry> {
        export
            .statement
            .entries
            .iter()
            .filter(|entry| entry.source != USAGE_SOURCE)
            .collect()
    }

    fn usage_outcome(export: &AuditExport, action: &str) -> String {
        export
            .statement
            .entries
            .iter()
            .find(|entry| entry.source == USAGE_SOURCE && entry.action == action)
            .map(|entry| entry.outcome.clone())
            .unwrap()
    }

    #[test]
    fn usage_records_count_applies_not_catalog_or_event_gaps() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-audit-usage-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (seed_path, roots) = seed(&dir);
        let store = SqliteStore::open(dir.join("tenkai.db")).unwrap();
        store
            .append_change_event(1_000, "release_published", "rel-1", "")
            .unwrap();
        store
            .append_change_event(1_100, "release_promoted", "rel-1", "")
            .unwrap();
        store
            .append_change_event(2_000, "plan_applied", "plan-a", "lab")
            .unwrap();
        store
            .append_change_event(2_000 + 3_600_000, "plan_applied", "plan-b", "lab")
            .unwrap();
        audit(&store, 500, "environment.configure.set_fact.requested");
        let exported = export(&store, None, 10_000_000, &seed_path).unwrap();
        verify_chain(std::slice::from_ref(&exported), &roots, None).unwrap();
        assert_eq!(usage_outcome(&exported, USAGE_ENVIRONMENTS), "1");
        assert_eq!(usage_outcome(&exported, USAGE_PLANS), "2");
        assert_eq!(usage_outcome(&exported, USAGE_RELEASES), "2");
        assert_eq!(usage_outcome(&exported, USAGE_EXECUTOR_HOURS), "0");
        assert_eq!(usage_outcome(&exported, USAGE_RUNTIME_HOURS), "0");
        let again = export(&store, None, 10_000_000, &seed_path).unwrap();
        assert_eq!(
            serde_json::to_vec(&exported).unwrap(),
            serde_json::to_vec(&again).unwrap()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

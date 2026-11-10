//! The runtime's own record of workload certificate renewal attempts
//! (ADR 0046 §3).
//!
//! Renewal runs without the server, so the runtime audits each attempt
//! itself, in `identity-renewals-<environment>.jsonl` beside its sealing key.
//! Every renewal is recorded; a failure is recorded when it differs from the
//! instance's last entry, so a renewal failing every pass for the same
//! reason is one entry. The file keeps the latest [`MAX_ENTRIES`] entries and
//! is replaced whole, by rename, so a crash leaves the old or the new file.
//! The last entry of each instance is what the runtime reports to the
//! server ([`crate::certificate_reports`]).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::certificate_reports::{MAX_REASON_BYTES, RenewalEvent, RenewalOutcome};

/// Entries the audit keeps, newest last.
pub const MAX_ENTRIES: usize = 4096;
/// An entry is a few hundred bytes; a longer line is not one.
const MAX_LINE_BYTES: usize = 4096;

fn path(dir: &Path, environment: &str) -> PathBuf {
    dir.join(format!("identity-renewals-{environment}.jsonl"))
}

/// Every entry audited for `environment`, oldest first. A line that is not
/// an entry is skipped, so one damaged line never hides the rest.
pub fn entries(dir: &Path, environment: &str) -> Result<Vec<RenewalEvent>> {
    let path = path(dir, environment);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    Ok(text
        .lines()
        .filter(|line| line.len() <= MAX_LINE_BYTES)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// The last audited entry of each instance in `environment`.
pub fn last(dir: &Path, environment: &str) -> Result<BTreeMap<String, RenewalEvent>> {
    Ok(entries(dir, environment)?
        .into_iter()
        .map(|event| (event.instance.clone(), event))
        .collect())
}

/// Audit the attempts of one pass. Failure reasons are cut to
/// [`MAX_REASON_BYTES`]. Writes nothing when every attempt repeats its
/// instance's last failure.
pub fn record(dir: &Path, environment: &str, attempts: Vec<RenewalEvent>) -> Result<()> {
    let path = path(dir, environment);
    crate::fenced_mutation::with_mutation_lock(&path.with_extension("lock"), || {
        let mut all = entries(dir, environment)?;
        let mut last: BTreeMap<String, RenewalOutcome> = all
            .iter()
            .map(|event| (event.instance.clone(), event.outcome.clone()))
            .collect();
        let before = all.len();
        for mut attempt in attempts {
            if let RenewalOutcome::Failed { reason } = &mut attempt.outcome {
                truncate(reason, MAX_REASON_BYTES);
            }
            let repeated = matches!(attempt.outcome, RenewalOutcome::Failed { .. })
                && last.get(&attempt.instance) == Some(&attempt.outcome);
            if repeated {
                continue;
            }
            last.insert(attempt.instance.clone(), attempt.outcome.clone());
            all.push(attempt);
        }
        if all.len() == before {
            return Ok(());
        }
        let keep = all.len().saturating_sub(MAX_ENTRIES);
        let staging = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        let written = (|| {
            let mut file = std::fs::File::create(&staging)?;
            for event in &all[keep..] {
                serde_json::to_writer(&mut file, event)?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
            std::fs::rename(&staging, &path)?;
            anyhow::Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        written.with_context(|| format!("writing {}", path.display()))
    })?
}

fn truncate(text: &mut String, max: usize) {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(at: i64, reason: &str) -> RenewalEvent {
        RenewalEvent {
            at,
            instance: "api".into(),
            outcome: RenewalOutcome::Failed {
                reason: reason.into(),
            },
        }
    }

    /// Every renewal is kept; a failure repeating the last one is not, and
    /// the latest entry per instance is what gets reported.
    #[test]
    fn repeated_failures_are_audited_once() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-renewal-audit-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        record(&dir, "prod", vec![failed(1, "unreachable")]).unwrap();
        record(&dir, "prod", vec![failed(2, "unreachable")]).unwrap();
        let renewed = RenewalEvent {
            at: 3,
            instance: "api".into(),
            outcome: RenewalOutcome::Renewed { not_after: 100 },
        };
        record(&dir, "prod", vec![renewed.clone()]).unwrap();
        record(&dir, "prod", vec![failed(4, "unreachable")]).unwrap();
        let long = "é".repeat(MAX_REASON_BYTES);
        record(&dir, "prod", vec![failed(5, &long)]).unwrap();

        let audited = entries(&dir, "prod").unwrap();
        assert_eq!(
            audited.iter().map(|event| event.at).collect::<Vec<_>>(),
            [1, 3, 4, 5]
        );
        let RenewalOutcome::Failed { reason } = &last(&dir, "prod").unwrap()["api"].outcome else {
            panic!("the last entry is the failure");
        };
        assert!(reason.len() <= MAX_REASON_BYTES);
        assert!(entries(&dir, "staging").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}

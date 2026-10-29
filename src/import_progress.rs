//! Per-entry progress of a running bundle import (#821).
//!
//! An import reports each content entry it stores: an OCI layer or a model
//! weight, by digest, with bytes done and bytes total. Progress is written
//! to a sidecar file beside the import job (`<id>.progress.json`), so the
//! job file keeps the format earlier versions read, and a client polling
//! `GET /v1/imports/{id}` sees it while the import's own request is still
//! running. Writes are throttled; reaching an entry's total is always
//! written. Progress is a view only: a failed write never fails the import.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Progress is written at most this often, besides each entry's completion.
const WRITE_INTERVAL: Duration = Duration::from_millis(250);

/// One content entry of an import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntryProgress {
    pub digest: String,
    /// `layer` or `weights`.
    pub kind: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

/// Where a running import records its progress; see the module docs.
pub struct ImportProgress {
    path: PathBuf,
    state: Mutex<(BTreeMap<String, EntryProgress>, Option<Instant>)>,
}

impl ImportProgress {
    /// Progress written to `path`, starting empty (replacing an earlier
    /// attempt's).
    pub fn new(path: PathBuf) -> Self {
        let progress = Self {
            path,
            state: Mutex::new((BTreeMap::new(), None)),
        };
        progress.write(&BTreeMap::new());
        progress
    }

    /// Record `done` of `total` bytes for entry `digest`.
    pub fn report(&self, digest: &str, kind: &str, done: u64, total: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (entries, written) = &mut *state;
        entries.insert(
            digest.to_string(),
            EntryProgress {
                digest: digest.to_string(),
                kind: kind.to_string(),
                bytes_done: done.min(total),
                bytes_total: total,
            },
        );
        let due = written.is_none_or(|at| at.elapsed() >= WRITE_INTERVAL);
        if due || done >= total {
            *written = Some(Instant::now());
            self.write(entries);
        }
    }

    fn write(&self, entries: &BTreeMap<String, EntryProgress>) {
        let list: Vec<&EntryProgress> = entries.values().collect();
        if let Err(error) =
            crate::atomic_state::write_json_verified(&self.path, &list, |_: &serde_json::Value| {
                Ok(())
            })
        {
            eprintln!("recording import progress failed (continuing): {error:#}");
        }
    }
}

/// The progress recorded at `path`, empty when there is none.
pub fn read(path: &Path) -> Vec<EntryProgress> {
    crate::atomic_state::read_json_optional::<Vec<EntryProgress>>(path)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// A reader that reports each read to `progress` as entry `digest`.
pub(crate) struct Counted<'a, R> {
    pub(crate) inner: R,
    pub(crate) progress: &'a ImportProgress,
    pub(crate) digest: &'a str,
    pub(crate) kind: &'static str,
    pub(crate) done: u64,
    pub(crate) total: u64,
}

impl<R: std::io::Read> std::io::Read for Counted<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.done = self.done.saturating_add(read as u64);
        self.progress
            .report(self.digest, self.kind, self.done, self.total);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_written_and_completion_always_lands() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-progress-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let progress = ImportProgress::new(path.clone());
        assert!(read(&path).is_empty());
        progress.report("sha256:a", "layer", 10, 100);
        // Throttled: the next partial update may not be written yet, but
        // reaching the total always is.
        progress.report("sha256:a", "layer", 50, 100);
        progress.report("sha256:a", "layer", 100, 100);
        progress.report("sha256:b", "weights", 7, 7);
        let entries = read(&path);
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.digest.as_str(), entry.bytes_done, entry.bytes_total))
                .collect::<Vec<_>>(),
            [("sha256:a", 100, 100), ("sha256:b", 7, 7)]
        );
        let _ = std::fs::remove_file(path);
    }
}

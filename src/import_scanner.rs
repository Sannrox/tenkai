//! External content scanner for offline imports (#634).
//!
//! `TENKAI_IMPORT_SCANNER` names an executable that scans incoming media. When
//! it is set, bind and first install run it once the bundle signature
//! verifies and before anything is written: no revocation list, layer,
//! weight or record. The scanner gets a private snapshot of the archive and
//! of its chunk store as arguments, and the import then reads that same
//! snapshot. It runs without a shell, with a minimal environment, and must
//! exit within `TENKAI_IMPORT_SCANNER_TIMEOUT_SECS` (default 600). Exit 0
//! admits the import; anything else, a timeout or a launch failure refuses
//! it. The outcome is recorded with the import evidence.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SCANNER_ENV: &str = "TENKAI_IMPORT_SCANNER";
pub const TIMEOUT_ENV: &str = "TENKAI_IMPORT_SCANNER_TIMEOUT_SECS";
/// Writable directory for scanner snapshots (default: the temp directory).
pub const SNAPSHOT_DIR_ENV: &str = "TENKAI_IMPORT_SCANNER_SNAPSHOT_DIR";
const SUMMARY_BYTES: usize = 200;

/// What the scanner said about one import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanEvidence {
    pub scanner: String,
    pub exit_code: i32,
    /// SHA-256 of the scanner's standard output and standard error, so the
    /// full report can be matched to the scanner's own logs.
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    /// The first line of output (standard output, else standard error), at
    /// most 200 bytes.
    pub summary: String,
    pub scanned_at_ms: i64,
}

/// The private copy of an archive and its chunk store that was scanned and
/// that the import must read. Removed when dropped.
pub struct ScanSnapshot {
    dir: PathBuf,
    archive: PathBuf,
}

impl ScanSnapshot {
    /// The snapshot archive; its chunk store sits beside it.
    pub fn archive(&self) -> &Path {
        &self.archive
    }
}

impl Drop for ScanSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Run the configured scanner; `None` when none is configured. A refusal
/// names the scanner's exit and summary.
///
/// The scanner reads a private snapshot: the archive written from the bundle
/// already verified in memory, and a copy of its signed chunks. The
/// import then reads the same snapshot, so the bytes scanned are the bytes
/// imported even if the staged files change. The snapshot goes in
/// `TENKAI_IMPORT_SCANNER_SNAPSHOT_DIR` (default: the temp directory) and
/// needs free space equal to the bundle.
pub fn scan_from_env(
    bundle: &crate::offline_bundle::BundleEnvelope,
    bundle_path: Option<&Path>,
) -> Result<Option<(ScanEvidence, ScanSnapshot)>> {
    let Some(scanner) = configured() else {
        return Ok(None);
    };
    let timeout = match std::env::var(TIMEOUT_ENV) {
        Ok(value) => Duration::from_secs(
            value
                .parse()
                .with_context(|| format!("{TIMEOUT_ENV} must be a whole number of seconds"))?,
        ),
        Err(_) => Duration::from_secs(600),
    };
    let bundle_path =
        bundle_path.context("the import scanner needs the archive path; pass the bundle file")?;
    let snapshot = snapshot(bundle, bundle_path)?;
    let chunks = crate::offline_chunk_store::chunk_dir_beside(snapshot.archive())
        .ok()
        .filter(|chunks| chunks.is_dir());
    let evidence = scan(
        Path::new(&scanner),
        snapshot.archive(),
        chunks.as_deref(),
        timeout,
    )?;
    if evidence.exit_code != 0 {
        bail!(
            "import scanner {} refused the bundle (exit {}): {}",
            evidence.scanner,
            evidence.exit_code,
            evidence.summary
        );
    }
    Ok(Some((evidence, snapshot)))
}

fn snapshot(
    bundle: &crate::offline_bundle::BundleEnvelope,
    bundle_path: &Path,
) -> Result<ScanSnapshot> {
    // Local writable storage: the media itself may be read-only.
    let parent = std::env::var_os(SNAPSHOT_DIR_ENV)
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = parent.join(format!("tenkai-scan-{}", uuid::Uuid::new_v4()));
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .context("creating the scanner snapshot directory")?;
    }
    let snapshot = ScanSnapshot {
        archive: dir.join(
            bundle_path
                .file_name()
                .context("the archive path has no file name")?,
        ),
        dir,
    };
    // Written from the bundle verified in memory, so the scanned archive is
    // the imported one; the staged file is not read again.
    bundle
        .save(&snapshot.archive)
        .context("writing the scanner snapshot")?;
    if let Ok(chunks) = crate::offline_chunk_store::chunk_dir_beside(bundle_path)
        && chunks.is_dir()
    {
        // Only the chunks the signed manifest names, each bounded by its size.
        let copy = crate::offline_chunk_store::chunk_dir_beside(&snapshot.archive)?;
        crate::offline_chunk_store::copy_referenced_chunks(bundle, &chunks, &copy)
            .context("copying chunks into the scanner snapshot")?;
    }
    Ok(snapshot)
}

/// The configured scanner. Tests set a per-thread override instead of the
/// process-wide variable, so parallel tests do not see each other's scanner.
pub(crate) fn configured() -> Option<std::ffi::OsString> {
    #[cfg(test)]
    if let Some(scanner) = TEST_SCANNER.with(|scanner| scanner.borrow().clone()) {
        return Some(scanner.into_os_string());
    }
    std::env::var_os(SCANNER_ENV).filter(|value| !value.is_empty())
}

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SCANNER: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// One drained output stream: its digest and the start of its first line.
struct Drained {
    sha256: String,
    first_line: String,
}

/// Hash `stream` to its end, keeping only the first line's first bytes, so a
/// verbose scanner costs no memory.
fn drain(mut stream: impl std::io::Read) -> Drained {
    let mut hasher = Sha256::new();
    let mut head = Vec::new();
    let mut line_done = false;
    let mut buffer = [0_u8; 8192];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if !line_done {
            for &byte in &buffer[..read] {
                if byte == b'\n' || head.len() >= SUMMARY_BYTES {
                    line_done = true;
                    break;
                }
                head.push(byte);
            }
        }
    }
    let mut first_line = String::from_utf8_lossy(&head).into_owned();
    while first_line.len() > SUMMARY_BYTES {
        first_line.pop();
    }
    Drained {
        sha256: format!("sha256:{:x}", hasher.finalize()),
        first_line: first_line.trim_end_matches('\r').to_string(),
    }
}

/// Run `scanner` on the archive and its chunk store. The deadline covers the
/// scanner and anything it leaves holding its output: on timeout its whole
/// process group is killed.
pub fn scan(
    scanner: &Path,
    archive: &Path,
    chunks: Option<&Path>,
    timeout: Duration,
) -> Result<ScanEvidence> {
    use std::os::unix::process::CommandExt as _;
    if !scanner.is_absolute() {
        bail!("{SCANNER_ENV} must be an absolute path");
    }
    let mut command = Command::new(scanner);
    command
        .arg(archive)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(chunks) = chunks {
        command.arg(chunks);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("starting import scanner {}", scanner.display()))?;
    let group = child.id() as i32;
    let (sender, receiver) = std::sync::mpsc::channel();
    for (index, stream) in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .enumerate()
    {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let drained = stream.map(drain);
            let _ = sender.send((index, drained));
        });
    }
    drop(sender);
    let deadline = Instant::now() + timeout;
    let kill = |child: &mut std::process::Child| {
        // SAFETY: signals only the process group this function created.
        unsafe { libc::kill(-group, libc::SIGKILL) };
        let _ = child.wait();
    };
    let mut streams: [Option<Drained>; 2] = [None, None];
    for _ in 0..2 {
        let left = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left) {
            Ok((index, drained)) => streams[index] = drained,
            Err(_) => {
                kill(&mut child);
                bail!(
                    "import scanner {} did not finish within {} s",
                    scanner.display(),
                    timeout.as_secs()
                );
            }
        }
    }
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            kill(&mut child);
            bail!(
                "import scanner {} did not finish within {} s",
                scanner.display(),
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let [stdout, stderr] = streams.map(|stream| {
        stream.unwrap_or(Drained {
            sha256: format!("sha256:{:x}", Sha256::digest(b"")),
            first_line: String::new(),
        })
    });
    let summary = if stdout.first_line.is_empty() {
        stderr.first_line.clone()
    } else {
        stdout.first_line.clone()
    };
    Ok(ScanEvidence {
        scanner: scanner.display().to_string(),
        // A signal ends the scanner without a code: report it as a refusal.
        exit_code: status.code().unwrap_or(-1),
        stdout_sha256: stdout.sha256,
        stderr_sha256: stderr.sha256,
        summary,
        scanned_at_ms: crate::now_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn scanner_exit_codes_admit_refuse_and_time_out() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-scanner-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(dir.join("site.chunks")).unwrap();
        let bundle = dir.join("site.json");
        std::fs::write(&bundle, b"{}").unwrap();

        // The scanner sees the archive and the chunk store, nothing else.
        let clean = script(
            &dir,
            "clean",
            "echo \"clean $# $(basename \"$1\") $(basename \"$2\")\"",
        );
        let evidence = scan(
            &clean,
            &bundle,
            Some(&dir.join("site.chunks")),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(evidence.exit_code, 0);
        assert_eq!(evidence.summary, "clean 2 site.json site.chunks");

        let infected = script(&dir, "infected", "echo 'FOUND: test-signature'; exit 3");
        let refused = scan(&infected, &bundle, None, Duration::from_secs(10)).unwrap();
        assert_eq!(
            (refused.exit_code, refused.summary.as_str()),
            (3, "FOUND: test-signature")
        );

        // A wrapper that exits but leaves a child holding its output is still
        // bounded by the deadline.
        let lingering = script(&dir, "lingering", "sleep 30 & exit 0");
        let started = Instant::now();
        assert!(scan(&lingering, &bundle, None, Duration::from_millis(300)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));

        let slow = script(&dir, "slow", "sleep 5");
        let error = scan(&slow, &bundle, None, Duration::from_millis(200)).unwrap_err();
        assert!(error.to_string().contains("did not finish"), "{error}");
        assert!(
            scan(
                Path::new("relative/scanner"),
                &bundle,
                None,
                Duration::from_secs(1)
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

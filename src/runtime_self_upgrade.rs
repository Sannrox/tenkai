//! The runtime agent as a managed component (#685).
//!
//! The agent ships as an ordinary signed release of [`SELF_PRODUCT`]: its
//! workdir holds `tenkai-runtime` and `tenkai-runtime-guard`. Release,
//! compatibility, plan, rollback and receipts work as for any component; the
//! agent runs its own step itself, by switching versions under its home:
//!
//! ```text
//! <home>/versions/<digest>/tenkai-runtime, tenkai-runtime-guard
//! <home>/current  -> versions/<digest>   (the supervisor runs current/tenkai-runtime)
//! <home>/previous -> versions/<digest>
//! <home>/pending.json                    (a switch not yet reported)
//! ```
//!
//! A switch writes `pending.json`, repoints `current`, and exits so the
//! supervisor starts the new version. The new version reports the step and
//! clears the marker. One that cannot start is reverted by `tenkai-runtime
//! prestart`, which the supervisor runs from a known-good version before
//! every start and which reverts after [`MAX_START_ATTEMPTS`] unreported
//! starts; the previous version then reports the step as failed. Every write is a rename, so a crash at any
//! point leaves either the old or the new layout.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::runtime_delivery::RuntimeStepReceipt;

/// The product whose releases are the runtime agent itself.
pub const SELF_PRODUCT: &str = "tenkai-runtime";
/// The binaries a version holds.
pub const BINARIES: [&str; 2] = ["tenkai-runtime", "tenkai-runtime-guard"];

/// The runtime protocol a version speaks, as `tenkai-runtime protocol`
/// prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol {
    pub major: u32,
    pub minors: Vec<u32>,
}

impl Protocol {
    /// The answer of `tenkai-runtime protocol`.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// The protocol of this build.
    pub fn this() -> Self {
        Self {
            major: crate::pb::runtime_v1::PROTOCOL_MAJOR,
            minors: crate::pb::runtime_v1::SUPPORTED_PROTOCOL_MINORS.to_vec(),
        }
    }

    /// Whether a version speaking `self` can keep talking to the server this
    /// agent talks to: the same major, and the minor this build speaks.
    fn compatible_with_this(&self) -> bool {
        self.major == crate::pb::runtime_v1::PROTOCOL_MAJOR
            && self.minors.contains(&crate::pb::runtime_v1::PROTOCOL_MINOR)
    }
}

/// Refuse a downloaded release whose content in `workdir` is not what the
/// signed release names (#685). The agent's release ships exactly [`BINARIES`] as
/// its deploy inputs, so its artifact digest is the digest of those two
/// files, which must equal `artifact_digest`, the digest the plan step
/// carries from the signed release. Checked before staging.
pub fn verify_release(workdir: &Path, artifact_digest: &str) -> Result<()> {
    let inputs = BINARIES.map(String::from);
    let actual = crate::manifest::artifact_digest(workdir, &inputs)
        .with_context(|| format!("reading the runtime agent release in {}", workdir.display()))?;
    if actual != artifact_digest {
        bail!(
            "runtime agent release content does not match the signed release (expected {artifact_digest}, found {actual})"
        );
    }
    Ok(())
}

const PENDING: &str = "pending.json";
/// Starts of a switched-to version not yet reported, counted by `prestart`.
const ATTEMPTS: &str = "start-attempts";
/// Starts a switched-to version gets before `prestart` reverts it.
pub const MAX_START_ATTEMPTS: u32 = 3;
/// Marks a version that did not start here; it is not switched to again.
const FAILED: &str = "FAILED";

/// A switch whose plan step is not yet reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub plan_id: String,
    pub generation: u64,
    pub step_id: String,
    /// The instance identity that holds the claim, kept across the restart.
    pub instance_id: String,
    /// Receipts of the plan's earlier steps.
    pub receipts: Vec<RuntimeStepReceipt>,
    pub from: String,
    pub to: String,
    pub reverted: bool,
}

/// A release download directory, removed on drop.
pub struct Download(PathBuf);

impl Download {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The agent's home: its versions and which one runs.
pub struct Home {
    root: PathBuf,
}

impl Home {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn versions(&self) -> PathBuf {
        self.root.join("versions")
    }

    fn link(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The version `name` (`current` or `previous`) points at, if any.
    fn target(&self, name: &str) -> Result<Option<String>> {
        match std::fs::read_link(self.link(name)) {
            Ok(target) => Ok(target
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("reading {name}")),
        }
    }

    pub fn current(&self) -> Result<Option<String>> {
        self.target("current")
    }

    pub fn previous(&self) -> Result<Option<String>> {
        self.target("previous")
    }

    /// Copy the binaries in `source` into a version named by the digest of
    /// `tenkai-runtime`, unless it is already there, and check it starts.
    pub fn stage(&self, source: &Path, expected: &str) -> Result<String> {
        // Named by the digest of both binaries, the signed artifact digest,
        // so a release that changes only the guard is a new version too.
        let id = version_id(source)?;
        if id != expected {
            bail!("runtime agent release content does not match the signed release");
        }
        let version = self.versions().join(&id);
        if version.join(FAILED).exists() {
            bail!("runtime agent version {id} did not start on this host before");
        }
        if version.exists() {
            // Reused: it must still hold exactly what its name says.
            if version_id(&version)? != id {
                bail!("staged runtime agent {id} no longer matches its name");
            }
        } else {
            let staging = self
                .versions()
                .join(format!(".{id}.{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&staging)?;
            // `copy` keeps each file's mode, which is part of the identity.
            let copied = BINARIES.iter().try_for_each(|name| {
                let to = staging.join(name);
                std::fs::copy(source.join(name), &to)
                    .with_context(|| format!("copying {name} from {}", source.display()))?;
                std::fs::File::open(&to)?.sync_all()?;
                Ok::<_, anyhow::Error>(())
            });
            // The copy itself must be the signed release before it is
            // published, and its entries durable.
            let published = copied
                .and_then(|()| {
                    if version_id(&staging)? != id {
                        bail!("staged copy of runtime agent {id} does not match it");
                    }
                    Ok(())
                })
                .and_then(|()| sync_dir(&staging))
                .and_then(|()| Ok(std::fs::rename(&staging, &version)?));
            if let Err(error) = published {
                let _ = std::fs::remove_dir_all(&staging);
                // A concurrent stage of the same bytes already published it.
                if !version.exists() {
                    return Err(error);
                }
            }
            sync_dir(&self.versions())?;
        }
        let started = probe(&version.join(BINARIES[0]), &["--version".as_ref()])
            .with_context(|| format!("starting staged runtime agent {id}"))?;
        if !started.status.success() {
            bail!(
                "staged runtime agent {id} does not start: {}",
                started.status
            );
        }
        // A version that cannot speak this server's runtime protocol is
        // refused before any switch.
        let answered = probe(&version.join(BINARIES[0]), &["protocol".as_ref()])
            .with_context(|| format!("asking staged runtime agent {id} its protocol"))?;
        let protocol: Option<Protocol> = answered
            .status
            .success()
            .then(|| serde_json::from_slice(&answered.stdout).ok())
            .flatten();
        match protocol {
            Some(protocol) if protocol.compatible_with_this() => {}
            Some(protocol) => bail!(
                "staged runtime agent {id} speaks runtime protocol {}.{:?}; this server needs {}.{}",
                protocol.major,
                protocol.minors,
                crate::pb::runtime_v1::PROTOCOL_MAJOR,
                crate::pb::runtime_v1::PROTOCOL_MINOR
            ),
            None => bail!("staged runtime agent {id} does not report its runtime protocol"),
        }
        // The guard runs every ordinary step: it must be present, executable
        // and start. `--help` is answered without waiting on a parent.
        let guarded = probe(&version.join(BINARIES[1]), &["--help".as_ref()])
            .with_context(|| format!("starting the guard of staged runtime agent {id}"))?;
        if !guarded.status.success() {
            bail!(
                "the guard of staged runtime agent {id} does not start: {}",
                guarded.status
            );
        }
        Ok(id)
    }

    /// Make `id` current and the current one previous.
    pub fn switch(&self, id: &str) -> Result<()> {
        if !self.versions().join(id).join(BINARIES[0]).is_file() {
            bail!("runtime agent version {id} is not staged");
        }
        if let Some(current) = self.current()?
            && current != id
        {
            self.point("previous", &current)?;
        }
        self.point("current", id)
    }

    /// Repoint link `name` at version `id` with one rename.
    fn point(&self, name: &str, id: &str) -> Result<()> {
        let temporary = self
            .root
            .join(format!(".{name}.{}", uuid::Uuid::new_v4().simple()));
        std::os::unix::fs::symlink(Path::new("versions").join(id), &temporary)?;
        if let Err(error) = std::fs::rename(&temporary, self.link(name)) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        sync_dir(&self.root)
    }

    /// Install the running binaries as the first version, when there is none.
    pub fn install_running(&self) -> Result<String> {
        let exe = std::env::current_exe()?;
        let source = exe.parent().context("runtime agent has no directory")?;
        let id = self.stage(source, &version_id(source)?)?;
        if self.current()?.is_none() {
            self.point("current", &id)?;
        }
        Ok(id)
    }

    /// A fresh private directory for a release download, removed when the
    /// returned owner drops, however the download ends. Downloads left by an
    /// agent that crashed are removed first: one agent owns a home.
    pub fn download_dir(&self) -> Result<Download> {
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".download.")
                {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
        let dir = self
            .root
            .join(format!(".download.{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Download(dir))
    }

    pub fn pending(&self) -> Result<Option<Pending>> {
        match std::fs::read(self.root.join(PENDING)) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("decoding pending runtime switch")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn write_pending(&self, pending: &Pending) -> Result<()> {
        let temporary = self
            .root
            .join(format!(".{PENDING}.{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&temporary, serde_json::to_vec(pending)?)?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, self.root.join(PENDING))?;
        sync_dir(&self.root)
    }

    /// Run before every start of the agent, from a version known to run
    /// (`previous`, else `current`). While a switch is unreported, each start
    /// of the new version is counted durably; after [`MAX_START_ATTEMPTS`]
    /// it is reverted, however slowly it fails. A healthy start reports the
    /// switch and clears the count. Returns the version reverted to, if any.
    pub fn prestart(&self) -> Result<Option<String>> {
        let Some(pending) = self.pending()? else {
            return Ok(None);
        };
        if pending.reverted {
            self.finish_revert(&pending)?;
            return Ok(None);
        }
        if self.current()?.as_deref() != Some(pending.to.as_str()) {
            return Ok(None);
        }
        let attempts = std::fs::read_to_string(self.root.join(ATTEMPTS))
            .ok()
            .and_then(|count| count.trim().parse::<u32>().ok())
            .unwrap_or(0)
            .saturating_add(1);
        if attempts > MAX_START_ATTEMPTS {
            return self.revert();
        }
        let temporary = self
            .root
            .join(format!(".{ATTEMPTS}.{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&temporary, attempts.to_string())?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, self.root.join(ATTEMPTS))?;
        sync_dir(&self.root)?;
        Ok(None)
    }

    pub fn clear_pending(&self) -> Result<()> {
        let _ = std::fs::remove_file(self.root.join(ATTEMPTS));
        match std::fs::remove_file(self.root.join(PENDING)) {
            Ok(()) => sync_dir(&self.root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Switch back to the version a pending switch came from, for the
    /// operator by hand, or [`Self::prestart`]. Repeating it changes nothing.
    pub fn revert(&self) -> Result<Option<String>> {
        let Some(mut pending) = self.pending()? else {
            return Ok(None);
        };
        // The intent is durable first, so a crash part-way is finished by
        // [`Self::finish_revert`], never read as a successful switch.
        if !pending.reverted {
            pending.reverted = true;
            self.write_pending(&pending)?;
        }
        self.finish_revert(&pending)?;
        Ok(Some(pending.from))
    }

    /// Complete a revert whose intent is recorded: the failed version is
    /// marked, and `current` points back at the one it came from. Repeating
    /// it changes nothing.
    pub fn finish_revert(&self, pending: &Pending) -> Result<()> {
        if !pending.reverted {
            return Ok(());
        }
        // A restart of one version did not start a new one: nothing to
        // mark as failed.
        if pending.to != pending.from {
            let failed = self.versions().join(&pending.to).join(FAILED);
            if !failed.exists() {
                std::fs::write(&failed, b"")?;
                sync_dir(&self.versions().join(&pending.to))?;
            }
        }
        if self.current()?.as_deref() != Some(pending.from.as_str()) {
            self.point("current", &pending.from)?;
        }
        Ok(())
    }
}

/// A version's identity: the digest of its two binaries, the same digest a
/// signed release of the agent carries as its artifact digest.
fn version_id(dir: &Path) -> Result<String> {
    crate::manifest::artifact_digest(dir, &BINARIES.map(String::from))
}

/// How long a staged version may take to answer a probe.
const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Most output a probe may write; it is only a version or a protocol.
const PROBE_OUTPUT: u64 = 64 * 1024;

/// Run `binary arg` in its own process group, reading at most
/// [`PROBE_OUTPUT`] of its output while it runs. The whole group is killed
/// if it has not finished within [`PROBE_DEADLINE`], so a stuck candidate, or
/// a descendant holding its output open, cannot stall the agent.
pub(crate) fn probe(binary: &Path, args: &[&std::ffi::OsStr]) -> Result<std::process::Output> {
    probe_within(binary, args, PROBE_DEADLINE)
}

/// [`probe`] with its own deadline, for checks that take longer than a
/// version answer.
pub(crate) fn probe_within(
    binary: &Path,
    args: &[&std::ffi::OsStr],
    within: std::time::Duration,
) -> Result<std::process::Output> {
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;
    let arg = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    // An open stdin the probe can watch, as the guard watches its parent;
    // it closes when the probe is done.
    let mut child = std::process::Command::new(binary)
        .args(args)
        .process_group(0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let group = child.id() as i32;
    let stdout = child.stdout.take().context("probe output")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let read = stdout.take(PROBE_OUTPUT).read_to_end(&mut output);
        let _ = sender.send(read.map(|_| output));
    });
    let kill = |child: &mut std::process::Child| {
        // SAFETY: signalling our own child's process group.
        unsafe { libc::killpg(group, libc::SIGKILL) };
        let _ = child.wait();
    };
    let deadline = std::time::Instant::now() + within;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            kill(&mut child);
            bail!("did not answer `{arg}` within {}s", within.as_secs());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let stdout = match receiver.recv_timeout(remaining) {
        Ok(read) => read?,
        Err(_) => {
            // A descendant still holds the output open.
            kill(&mut child);
            bail!("did not finish `{arg}` within {}s", within.as_secs());
        }
    };
    // Nothing of the probe may outlive it.
    unsafe { libc::killpg(group, libc::SIGKILL) };
    Ok(std::process::Output {
        status,
        stdout,
        stderr: Vec::new(),
    })
}

pub(crate) fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(dir: &Path, marker: &str) {
        agent_speaking(
            dir,
            marker,
            &serde_json::to_string(&Protocol::this()).unwrap(),
        );
    }

    fn agent_speaking(dir: &Path, marker: &str, protocol: &str) {
        std::fs::create_dir_all(dir).unwrap();
        for name in BINARIES {
            let script = format!(
                "#!/bin/sh\n# {marker}\nif [ \"$1\" = protocol ]; then echo '{protocol}'; exit 0; fi\necho {name}\n"
            );
            std::fs::write(dir.join(name), script).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
    }

    /// Stage `dir` as the signed release it is.
    fn stage(home: &Home, dir: &Path) -> Result<String> {
        home.stage(dir, &version_id(dir).unwrap_or_default())
    }

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-self-upgrade-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn a_switch_keeps_the_previous_version_and_a_revert_restores_it() {
        let root = scratch();
        let home = Home::new(root.join("home"));
        std::fs::create_dir_all(root.join("home")).unwrap();
        agent(&root.join("v1"), "one");
        agent(&root.join("v2"), "two");
        let v1 = stage(&home, &root.join("v1")).unwrap();
        assert_eq!(
            stage(&home, &root.join("v1")).unwrap(),
            v1,
            "staging is idempotent"
        );
        home.switch(&v1).unwrap();
        let v2 = stage(&home, &root.join("v2")).unwrap();
        assert_ne!(v1, v2);
        home.write_pending(&Pending {
            plan_id: "plan-1".into(),
            generation: 1,
            step_id: "step-1".into(),
            instance_id: "instance-a".into(),
            receipts: Vec::new(),
            from: v1.clone(),
            to: v2.clone(),
            reverted: false,
        })
        .unwrap();
        home.switch(&v2).unwrap();
        assert_eq!(home.current().unwrap(), Some(v2.clone()));
        assert_eq!(home.previous().unwrap(), Some(v1.clone()));
        assert!(
            std::fs::read_to_string(root.join("home/current/tenkai-runtime"))
                .unwrap()
                .contains("two")
        );

        assert_eq!(home.revert().unwrap(), Some(v1.clone()));
        assert_eq!(
            home.revert().unwrap(),
            Some(v1.clone()),
            "revert is idempotent"
        );
        assert_eq!(home.current().unwrap(), Some(v1));
        assert!(home.pending().unwrap().unwrap().reverted);
        home.clear_pending().unwrap();
        assert_eq!(home.revert().unwrap(), None);
        let refused = stage(&home, &root.join("v2")).unwrap_err().to_string();
        assert!(refused.contains("did not start"), "{refused}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn release_content_must_match_the_signed_artifact_digest() {
        let root = scratch();
        agent(&root.join("release"), "one");
        let inputs = BINARIES.map(String::from);
        let signed = crate::manifest::artifact_digest(&root.join("release"), &inputs).unwrap();
        verify_release(&root.join("release"), &signed).unwrap();
        let mut bytes = std::fs::read(root.join("release/tenkai-runtime")).unwrap();
        bytes.extend_from_slice(b"# tampered\n");
        std::fs::write(root.join("release/tenkai-runtime"), bytes).unwrap();
        let refused = verify_release(&root.join("release"), &signed)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("does not match the signed release"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn prestart_reverts_a_switch_that_never_reports_after_bounded_attempts() {
        let root = scratch();
        let home = Home::new(root.join("home"));
        std::fs::create_dir_all(root.join("home")).unwrap();
        agent(&root.join("v1"), "one");
        agent(&root.join("v2"), "two");
        let v1 = stage(&home, &root.join("v1")).unwrap();
        home.switch(&v1).unwrap();
        let v2 = stage(&home, &root.join("v2")).unwrap();
        home.write_pending(&Pending {
            plan_id: "plan-1".into(),
            generation: 1,
            step_id: "step-1".into(),
            instance_id: "instance-a".into(),
            receipts: Vec::new(),
            from: v1.clone(),
            to: v2.clone(),
            reverted: false,
        })
        .unwrap();
        home.switch(&v2).unwrap();
        for _ in 0..MAX_START_ATTEMPTS {
            assert_eq!(home.prestart().unwrap(), None);
            assert_eq!(home.current().unwrap(), Some(v2.clone()));
        }
        assert_eq!(home.prestart().unwrap(), Some(v1.clone()));
        assert_eq!(home.current().unwrap(), Some(v1));
        assert!(home.pending().unwrap().unwrap().reverted);
        // Nothing pending: nothing counted.
        home.clear_pending().unwrap();
        assert_eq!(home.prestart().unwrap(), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_interrupted_revert_is_finished_not_read_as_a_switch() {
        let root = scratch();
        let home = Home::new(root.join("home"));
        std::fs::create_dir_all(root.join("home")).unwrap();
        agent(&root.join("v1"), "one");
        agent(&root.join("v2"), "two");
        let v1 = stage(&home, &root.join("v1")).unwrap();
        home.switch(&v1).unwrap();
        let v2 = stage(&home, &root.join("v2")).unwrap();
        home.switch(&v2).unwrap();
        // The intent is recorded but the crash came before `current` moved.
        let pending = Pending {
            plan_id: "plan-1".into(),
            generation: 1,
            step_id: "step-1".into(),
            instance_id: "instance-a".into(),
            receipts: Vec::new(),
            from: v1.clone(),
            to: v2.clone(),
            reverted: true,
        };
        home.write_pending(&pending).unwrap();
        assert_eq!(home.current().unwrap(), Some(v2.clone()));
        home.finish_revert(&pending).unwrap();
        assert_eq!(home.current().unwrap(), Some(v1));
        assert!(stage(&home, &root.join("v2")).is_err(), "marked failed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_version_that_does_not_start_is_not_staged_for_use() {
        let root = scratch();
        let home = Home::new(root.join("home"));
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("bad")).unwrap();
        for name in BINARIES {
            std::fs::write(root.join("bad").join(name), "#!/bin/sh\nexit 3\n").unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                root.join("bad").join(name),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        assert!(stage(&home, &root.join("bad")).is_err());
        assert!(home.switch("missing").is_err());
        // A release whose guard does not start is not staged either.
        agent(&root.join("noguard"), "noguard");
        std::fs::write(
            root.join("noguard").join(BINARIES[1]),
            "#!/bin/sh\nexit 3\n",
        )
        .unwrap();
        let refused = stage(&home, &root.join("noguard")).unwrap_err().to_string();
        assert!(refused.contains("guard"), "{refused}");
        // Content that is not the signed release is not staged.
        agent(&root.join("v3"), "three");
        let refused = home
            .stage(&root.join("v3"), &"0".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("does not match the signed release"),
            "{refused}"
        );
        // One that starts but speaks another protocol major is refused too.
        agent_speaking(&root.join("v2"), "next", r#"{"major":2,"minors":[0]}"#);
        let refused = stage(&home, &root.join("v2")).unwrap_err().to_string();
        assert!(refused.contains("runtime protocol"), "{refused}");
        let _ = std::fs::remove_dir_all(root);
    }
}

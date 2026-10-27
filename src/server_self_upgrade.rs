//! Verified upgrade and rollback of `tenkai-server` on one host (#678).
//!
//! The host binaries come from a signed offline bundle (#640) and live in
//! versions, as the runtime agent's do (#685):
//!
//! ```text
//! <home>/versions/<digest>/tenkai-server, tenkai-executor-guard, tenkaictl
//! <home>/current  -> versions/<digest>   (the service runs current/tenkai-server)
//! <home>/previous -> versions/<digest>
//! <home>/upgrade.json                    (the last switch, until the next one)
//! <home>/backups/<ms>-<digest>.db        (the store as it was before that switch)
//! ```
//!
//! A candidate is refused before any switch unless its own
//! `tenkai-server --check-store` opens a private copy of the store. A switch
//! records [`Upgrade`] and takes a backup first. Reverting points `current`
//! back. An older binary refuses a store a newer one migrated, so when the
//! schema moved, a revert also restores the backup, which needs the server
//! stopped and loses what was written since: that takes an explicit choice.
//! Every write is a rename, and the intent to revert is durable before the
//! revert, so a crash at any point leaves a state the next command finishes.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::runtime_self_upgrade::{probe, probe_within, sync_dir};

/// The binaries a version holds, as `tenkaictl upgrade install-hosts`
/// writes them.
pub const BINARIES: [&str; 3] = ["tenkai-server", "tenkai-executor-guard", "tenkaictl"];

const RECORD: &str = "upgrade.json";

/// What `tenkai-server --check-store` reports: the schema version the store
/// holds (0 when there is no store yet) and the one this binary supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreCheck {
    pub stored: u32,
    pub supported: u32,
}

impl StoreCheck {
    /// Whether this binary would migrate the store on start.
    pub fn migrates(&self) -> bool {
        self.stored != 0 && self.stored < self.supported
    }
}

/// Whether this binary can open the SQLite store at `database`, checked on a
/// private copy so the live store is neither changed nor migrated. A store
/// newer than this binary, or one it cannot open, is an error.
pub fn check_store(database: &Path) -> Result<StoreCheck> {
    let supported = crate::storage::SCHEMA_VERSION;
    if !database.exists() {
        return Ok(StoreCheck {
            stored: 0,
            supported,
        });
    }
    let private = std::env::temp_dir().join(format!("tenkai-check-store-{}", uuid::Uuid::new_v4()));
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .context("creating the store check directory")?;
    }
    let checked = (|| {
        let copy = private.join("tenkai.db");
        crate::storage::SqliteStore::restore(database, &copy)
            .with_context(|| format!("copying the store at {}", database.display()))?;
        let stored = schema_version(&copy)?;
        if stored > supported {
            bail!("the store has schema {stored}; this binary supports up to {supported}");
        }
        // Opening migrates the copy, which is what this binary would do.
        crate::storage::SqliteStore::open(&copy).context("this binary cannot open the store")?;
        Ok(StoreCheck { stored, supported })
    })();
    let _ = std::fs::remove_dir_all(&private);
    checked
}

fn schema_version(database: &Path) -> Result<u32> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("opening {}", database.display()))?;
    Ok(connection.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

/// The last switch on a home. Kept after it is confirmed, so a later
/// rollback knows the backup and the version before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    /// The version switched from; `None` for the first install.
    pub from: Option<String>,
    pub to: String,
    pub database: PathBuf,
    /// The store before the switch; `None` when there was no store yet.
    pub backup: Option<PathBuf>,
    pub schema_before: u32,
    /// The new version answered readiness.
    pub confirmed: bool,
    /// A revert is recorded and may not have finished.
    pub reverted: bool,
    /// That revert began restoring the store (or moving a created one
    /// aside); until `restored`, the next command finishes it.
    #[serde(default)]
    pub restoring: bool,
    /// The backup was restored over the store by that revert. It is never
    /// restored twice: the older server may have written since.
    #[serde(default)]
    pub restored: bool,
}

/// How a revert ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reverted {
    pub to: String,
    /// The pre-upgrade backup was restored over the store.
    pub restored_backup: bool,
}

/// A server home: its versions and which one runs.
pub struct Home {
    root: PathBuf,
}

/// Exclusive hold on a home for one self-upgrade command; released on drop.
pub struct HomeLock {
    _file: std::fs::File,
}

impl Home {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn versions(&self) -> PathBuf {
        self.root.join("versions")
    }

    /// Where `id`'s binaries live.
    pub fn version(&self, id: &str) -> PathBuf {
        self.versions().join(id)
    }

    fn target(&self, name: &str) -> Result<Option<String>> {
        match std::fs::read_link(self.root.join(name)) {
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

    /// Hold the home for one command, so two commands never interleave
    /// their record and link changes. Refused while another holds it.
    pub fn lock(&self) -> Result<HomeLock> {
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("creating {}", self.root.display()))?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.root.join(".lock"))?;
        if file.try_lock().is_err() {
            bail!(
                "another self-upgrade command is using {}",
                self.root.display()
            );
        }
        Ok(HomeLock { _file: file })
    }

    pub fn previous(&self) -> Result<Option<String>> {
        self.target("previous")
    }

    /// A fresh private directory under the home, for verified binaries
    /// before they are staged. The caller removes it.
    pub fn scratch(&self) -> Result<PathBuf> {
        let dir = self
            .root
            .join(format!(".scratch.{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(dir)
    }

    /// Copy the binaries in `source` into a version named by their digest,
    /// unless it is already there, and check it starts.
    pub fn stage(&self, source: &Path) -> Result<String> {
        let id = version_id(source)?;
        let version = self.version(&id);
        if version.exists() {
            if version_id(&version)? != id {
                bail!("staged server version {id} no longer matches its name");
            }
        } else {
            std::fs::create_dir_all(self.versions())?;
            let staging = self
                .versions()
                .join(format!(".{id}.{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&staging)?;
            let published = BINARIES
                .iter()
                .try_for_each(|name| {
                    let to = staging.join(name);
                    std::fs::copy(source.join(name), &to)
                        .with_context(|| format!("copying {name} from {}", source.display()))?;
                    std::fs::File::open(&to)?.sync_all()?;
                    Ok::<_, anyhow::Error>(())
                })
                .and_then(|()| {
                    if version_id(&staging)? != id {
                        bail!("staged copy of server version {id} does not match it");
                    }
                    Ok(())
                })
                .and_then(|()| sync_dir(&staging))
                .and_then(|()| Ok(std::fs::rename(&staging, &version)?));
            if let Err(error) = published {
                let _ = std::fs::remove_dir_all(&staging);
                if !version.exists() {
                    return Err(error);
                }
            }
            sync_dir(&self.versions())?;
        }
        let started = probe(&version.join(BINARIES[0]), &["--version".as_ref()])
            .with_context(|| format!("starting staged server version {id}"))?;
        if !started.status.success() {
            bail!(
                "staged server version {id} does not start: {}",
                started.status
            );
        }
        Ok(id)
    }

    /// Run the candidate's own store check against `database`, within
    /// `within`: it copies and migrates the whole store, so it can take a
    /// while. A candidate that cannot open the store is refused here,
    /// before any switch.
    pub fn check_candidate(
        &self,
        id: &str,
        database: &Path,
        within: std::time::Duration,
    ) -> Result<StoreCheck> {
        let binary = self.version(id).join(BINARIES[0]);
        let answered = probe_within(
            &binary,
            &[
                "--check-store".as_ref(),
                "--database".as_ref(),
                database.as_os_str(),
            ],
            within,
        )
        .with_context(|| format!("running the store check of server version {id}"))?;
        let check: Option<StoreCheck> = answered
            .status
            .success()
            .then(|| serde_json::from_slice(&answered.stdout).ok())
            .flatten();
        check.with_context(|| {
            let said = String::from_utf8_lossy(&answered.stdout);
            format!(
                "server version {id} cannot open the store {}: {}",
                database.display(),
                said.lines().next().unwrap_or("no answer")
            )
        })
    }

    pub fn record(&self) -> Result<Option<Upgrade>> {
        match std::fs::read(self.root.join(RECORD)) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("decoding the server upgrade record")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_record(&self, record: &Upgrade) -> Result<()> {
        let temporary = self
            .root
            .join(format!(".{RECORD}.{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, self.root.join(RECORD))?;
        sync_dir(&self.root)
    }

    /// Back up the store, record the switch, and make `id` current. Refused
    /// while an earlier switch is neither confirmed nor reverted.
    pub fn switch(&self, id: &str, database: &Path, now_ms: i64) -> Result<Upgrade> {
        if !self.version(id).join(BINARIES[0]).is_file() {
            bail!("server version {id} is not staged");
        }
        let from = self.current()?;
        if from.as_deref() == Some(id) {
            bail!("server version {id} is already current");
        }
        if let Some(open) = self.record()? {
            // A first install that crashed before publishing `current` left
            // nothing to confirm or roll back: it is simply switched again.
            let unpublished = open.from.is_none() && from.is_none();
            if !open.confirmed && !open.reverted && !unpublished {
                bail!(
                    "the switch to {} is not confirmed; confirm or roll it back first",
                    open.to
                );
            }
            // A rollback whose intent is recorded but not finished keeps
            // its record until it is: run it again first.
            if open.reverted && (from != open.from || (open.restoring && !open.restored)) {
                bail!(
                    "the rollback of {} has not finished; run self-upgrade rollback again first",
                    open.to
                );
            }
        }
        // Recovery reads these paths later, maybe from another directory.
        let database = &std::path::absolute(database)
            .with_context(|| format!("resolving {}", database.display()))?;
        let (backup, schema_before) = if database.exists() {
            let backups = std::path::absolute(self.root.join("backups"))?;
            private_dir(&backups)?;
            let backup = backups.join(format!("{now_ms}-{id}.db"));
            // Private before any content is copied into it.
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&backup)
                    .with_context(|| format!("creating {}", backup.display()))?;
            }
            crate::storage::SqliteStore::restore(database, &backup)
                .with_context(|| format!("backing up the store to {}", backup.display()))?;
            // Durable before the record that names it.
            std::fs::File::open(&backup)?.sync_all()?;
            sync_dir(&backups)?;
            if let Some(parent) = backups.parent() {
                sync_dir(parent)?;
            }
            let schema = schema_version(&backup)?;
            (Some(backup), schema)
        } else {
            (None, 0)
        };
        let record = Upgrade {
            from: from.clone(),
            to: id.into(),
            database: database.into(),
            backup,
            schema_before,
            confirmed: false,
            reverted: false,
            restoring: false,
            restored: false,
        };
        // The record is durable before `current` moves, so a crash between
        // the two is read as a switch to roll back or confirm.
        self.write_record(&record)?;
        if let Some(from) = from {
            self.point("previous", &from)?;
        }
        self.point("current", id)?;
        Ok(record)
    }

    /// The new version answered readiness: the switch stands.
    pub fn confirm(&self) -> Result<Upgrade> {
        let mut record = self.record()?.context("no server switch to confirm")?;
        if record.reverted {
            bail!("the switch to {} was rolled back", record.to);
        }
        if self.current()?.as_deref() != Some(record.to.as_str()) {
            bail!("the current version is not {}", record.to);
        }
        if !record.confirmed {
            record.confirmed = true;
            self.write_record(&record)?;
        }
        Ok(record)
    }

    /// Whether the store moved past the schema it had before the switch.
    pub fn store_migrated(&self, record: &Upgrade) -> Result<bool> {
        Ok(record.database.exists() && schema_version(&record.database)? > record.schema_before)
    }

    /// Point `current` back at the version before the last switch. When the
    /// new version migrated the store, the older binary cannot open it: the
    /// backup must be restored, which needs `restore_backup` (the server is
    /// stopped, and writes since the switch are given up). The backup is
    /// restored at most once, and only over a migrated store. Repeating a
    /// revert changes nothing.
    pub fn revert(&self, restore_backup: bool) -> Result<Reverted> {
        let mut record = self.record()?.context("no server switch to roll back")?;
        let from = record
            .from
            .clone()
            .context("the first installed version has nothing to roll back to")?;
        // A restore that was interrupted is finished first. A backup copy is
        // redone only while the store is still migrated: once it is not, the
        // copy completed and the older version may have written since. A
        // move aside completed once the store file itself moved (it moves
        // last); a store at the original path then is the older version's.
        if record.reverted && record.restoring && !record.restored {
            // The older version is selected first here too.
            if self.current()?.as_deref() != Some(from.as_str()) {
                self.point("current", &from)?;
            }
            match record.backup.clone() {
                Some(backup) if self.store_migrated(&record)? => {
                    crate::storage::SqliteStore::restore(&backup, &record.database)
                        .with_context(|| format!("restoring {}", backup.display()))?;
                }
                Some(_) => {}
                None if !aside_path(&record.database, &record.to).exists() => {
                    set_aside(&record.database, &record.to)?;
                }
                None => {}
            }
            record.restored = true;
            self.write_record(&record)?;
        }
        let migrated = !record.restored && self.store_migrated(&record)?;
        if migrated && !restore_backup {
            bail!(
                "server version {} migrated the store past schema {}; stop the server and roll back with --restore-backup, which {} and gives up what was written since",
                record.to,
                record.schema_before,
                record.backup.as_deref().map_or(
                    "moves the store it created aside".into(),
                    |path| format!("restores {}", path.display())
                )
            );
        }
        if !record.reverted {
            record.reverted = true;
            self.write_record(&record)?;
        }
        if migrated {
            record.restoring = true;
            self.write_record(&record)?;
        }
        // The older version is selected before the store is restored, so a
        // crash between the two never lets the new version start and migrate
        // the restored store again; the older one refuses a migrated store.
        if self.current()?.as_deref() != Some(from.as_str()) {
            self.point("current", &from)?;
        }
        if migrated {
            match record.backup.clone() {
                Some(backup) => {
                    crate::storage::SqliteStore::restore(&backup, &record.database).with_context(
                        || {
                            format!(
                                "restoring {} over {}",
                                backup.display(),
                                record.database.display()
                            )
                        },
                    )?;
                }
                // There was no store before the switch: the one the new
                // version created is moved aside, not deleted.
                None => set_aside(&record.database, &record.to)?,
            }
            record.restored = true;
            self.write_record(&record)?;
        }
        Ok(Reverted {
            to: from,
            restored_backup: record.restored,
        })
    }

    /// Repoint link `name` at version `id` with one rename.
    fn point(&self, name: &str, id: &str) -> Result<()> {
        let temporary = self
            .root
            .join(format!(".{name}.{}", uuid::Uuid::new_v4().simple()));
        std::os::unix::fs::symlink(Path::new("versions").join(id), &temporary)?;
        if let Err(error) = std::fs::rename(&temporary, self.root.join(name)) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        sync_dir(&self.root)
    }
}

/// Move a store created by version `by` (and its SQLite side files) to
/// `<store>.created-by-<by>`, so the version before it starts empty again.
/// The side files go first and the store last, so an interrupted move
/// leaves the store in place and a retry finishes it; the moved names
/// still pair the store with its write-ahead log.
fn set_aside(database: &Path, by: &str) -> Result<()> {
    let aside = aside_path(database, by);
    for suffix in ["-wal", "-shm", ""] {
        let from = PathBuf::from(format!("{}{suffix}", database.display()));
        let to = PathBuf::from(format!("{}{suffix}", aside.display()));
        match std::fs::rename(&from, &to) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("moving {} aside", from.display()));
            }
        }
    }
    match database
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => sync_dir(parent),
        None => Ok(()),
    }
}

/// Where [`set_aside`] moves a store created by version `by`.
fn aside_path(database: &Path, by: &str) -> PathBuf {
    let short: String = by.trim_start_matches("sha256:").chars().take(12).collect();
    PathBuf::from(format!("{}.created-by-{short}", database.display()))
}

/// Create `dir` owner-only, or make an existing one so.
fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", dir.display()))
}

/// A version's identity: the digest of its binaries.
fn version_id(dir: &Path) -> Result<String> {
    crate::manifest::artifact_digest(dir, &BINARIES.map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Server binaries whose store check answers `check` (or fails when it
    /// is `None`), marked so each set has its own digest.
    fn server(dir: &Path, marker: &str, check: Option<StoreCheck>) {
        std::fs::create_dir_all(dir).unwrap();
        let answer = match check {
            Some(check) => format!("echo '{}'; exit 0", serde_json::to_string(&check).unwrap()),
            None => "echo 'the store has schema 99; this binary supports up to 1'; exit 1".into(),
        };
        for name in BINARIES {
            let script = format!(
                "#!/bin/sh\n# {marker}\nif [ \"$1\" = --check-store ]; then {answer}; fi\necho {name}\n"
            );
            std::fs::write(dir.join(name), script).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
    }

    fn root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-server-upgrade-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn set_schema(database: &Path, version: u32) {
        rusqlite::Connection::open(database)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {version}"))
            .unwrap();
    }

    /// N-1 to N and back: the store is backed up before the switch, a
    /// revert after a migration needs the backup restored, and restoring it
    /// brings back the store and the earlier version.
    #[test]
    fn upgrade_and_rollback_restore_the_backup_only_when_the_schema_moved() {
        let root = root("rehearsal");
        let home = Home::new(root.join("home"));
        let database = root.join("state").join("tenkai.db");
        std::fs::create_dir_all(database.parent().unwrap()).unwrap();
        crate::storage::SqliteStore::open(&database).unwrap();
        let schema = schema_version(&database).unwrap();
        let ok = StoreCheck {
            stored: schema,
            supported: schema,
        };
        server(&root.join("n-1"), "n-1", Some(ok));
        server(&root.join("n"), "n", Some(ok));

        let old = home.stage(&root.join("n-1")).unwrap();
        let first = home.switch(&old, &database, 1).unwrap();
        assert_eq!(first.from, None);
        home.confirm().unwrap();

        let new = home.stage(&root.join("n")).unwrap();
        assert_eq!(
            home.check_candidate(&new, &database, std::time::Duration::from_secs(30))
                .unwrap(),
            ok
        );
        let upgrade = home.switch(&new, &database, 2).unwrap();
        assert_eq!(upgrade.from.as_deref(), Some(old.as_str()));
        let backup = upgrade.backup.as_deref().unwrap();
        assert!(backup.is_file() && backup.is_absolute());
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(backup), 0o600);
            assert_eq!(mode(backup.parent().unwrap()), 0o700);
        }
        assert_eq!(home.current().unwrap().as_deref(), Some(new.as_str()));
        assert_eq!(home.previous().unwrap().as_deref(), Some(old.as_str()));
        // A second switch waits for this one to be confirmed or reverted,
        // and the current version is never switched to again.
        assert!(home.switch(&old, &database, 3).is_err());
        assert!(
            home.switch(&new, &database, 3)
                .unwrap_err()
                .to_string()
                .contains("already current")
        );

        // The new version migrated the store: a plain revert is refused.
        set_schema(&database, schema + 1);
        let refused = home.revert(false).unwrap_err().to_string();
        assert!(refused.contains("--restore-backup"), "{refused}");
        assert_eq!(home.current().unwrap().as_deref(), Some(new.as_str()));

        let reverted = home.revert(true).unwrap();
        assert_eq!(
            reverted,
            Reverted {
                to: old.clone(),
                restored_backup: true
            }
        );
        assert_eq!(schema_version(&database).unwrap(), schema);
        assert_eq!(home.current().unwrap().as_deref(), Some(old.as_str()));
        // Repeating it changes nothing: the older server's writes since are
        // never overwritten by the backup again.
        set_schema(&database, schema + 2);
        assert_eq!(home.revert(true).unwrap().to, old);
        assert_eq!(schema_version(&database).unwrap(), schema + 2);
        // One command at a time holds the home.
        let held = home.lock().unwrap();
        assert!(home.lock().is_err());
        drop(held);
        home.lock().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    /// A revert interrupted after its intent was recorded is finished by the
    /// next one; without a migration no backup is restored.
    #[test]
    fn an_interrupted_revert_is_finished_and_an_unmigrated_store_is_kept() {
        let root = root("resume");
        let home = Home::new(root.join("home"));
        let database = root.join("tenkai.db");
        crate::storage::SqliteStore::open(&database).unwrap();
        let schema = schema_version(&database).unwrap();
        let ok = StoreCheck {
            stored: schema,
            supported: schema,
        };
        server(&root.join("a"), "a", Some(ok));
        server(&root.join("b"), "b", Some(ok));
        let a = home.stage(&root.join("a")).unwrap();
        home.switch(&a, &database, 1).unwrap();
        home.confirm().unwrap();
        let b = home.stage(&root.join("b")).unwrap();
        let mut record = home.switch(&b, &database, 2).unwrap();
        record.reverted = true;
        home.write_record(&record).unwrap();
        // Crashed before `current` moved back: no new switch until it ends.
        assert_eq!(home.current().unwrap().as_deref(), Some(b.as_str()));
        assert!(
            home.switch(&a, &database, 3)
                .unwrap_err()
                .to_string()
                .contains("not finished")
        );
        let reverted = home.revert(false).unwrap();
        assert_eq!(
            reverted,
            Reverted {
                to: a.clone(),
                restored_backup: false
            }
        );
        assert_eq!(home.current().unwrap().as_deref(), Some(a.as_str()));
        assert!(
            home.confirm().is_err(),
            "a rolled-back switch cannot be confirmed"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A store first created by the new version is moved aside on a
    /// restoring rollback, so the version before it starts as it did.
    #[test]
    fn a_store_created_by_the_new_version_is_set_aside() {
        let root = root("created");
        let home = Home::new(root.join("home"));
        let database = root.join("tenkai.db");
        let fresh = StoreCheck {
            stored: 0,
            supported: crate::storage::SCHEMA_VERSION,
        };
        server(&root.join("a"), "a", Some(fresh));
        server(&root.join("b"), "b", Some(fresh));
        let a = home.stage(&root.join("a")).unwrap();
        home.switch(&a, &database, 1).unwrap();
        home.confirm().unwrap();
        let b = home.stage(&root.join("b")).unwrap();
        let record = home.switch(&b, &database, 2).unwrap();
        assert_eq!(record.backup, None);
        crate::storage::SqliteStore::open(&database).unwrap();
        assert!(
            home.revert(false)
                .unwrap_err()
                .to_string()
                .contains("aside")
        );
        let reverted = home.revert(true).unwrap();
        assert!(reverted.restored_backup);
        assert!(!database.exists());
        let short: String = b.trim_start_matches("sha256:").chars().take(12).collect();
        assert!(root.join(format!("tenkai.db.created-by-{short}")).is_file());
        assert_eq!(home.current().unwrap().as_deref(), Some(a.as_str()));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A set-aside interrupted part-way is finished by the retry and
    /// recorded, so the older version's own new store is never moved.
    #[test]
    fn an_interrupted_set_aside_is_finished_without_moving_a_newer_store() {
        let root = root("aside");
        let home = Home::new(root.join("home"));
        let database = root.join("tenkai.db");
        let fresh = StoreCheck {
            stored: 0,
            supported: crate::storage::SCHEMA_VERSION,
        };
        server(&root.join("a"), "a", Some(fresh));
        server(&root.join("b"), "b", Some(fresh));
        let a = home.stage(&root.join("a")).unwrap();
        home.switch(&a, &database, 1).unwrap();
        home.confirm().unwrap();
        let b = home.stage(&root.join("b")).unwrap();
        let mut record = home.switch(&b, &database, 2).unwrap();
        crate::storage::SqliteStore::open(&database).unwrap();
        // Crashed after only the write-ahead log moved.
        record.reverted = true;
        record.restoring = true;
        home.write_record(&record).unwrap();
        let aside = aside_path(&database, &b);
        let wal = PathBuf::from(format!("{}-wal", database.display()));
        std::fs::write(&wal, b"log").unwrap();
        std::fs::rename(&wal, format!("{}-wal", aside.display())).unwrap();
        assert!(home.revert(true).unwrap().restored_backup);
        assert!(
            !database.exists() && aside.is_file(),
            "the move was finished"
        );
        assert_eq!(home.current().unwrap().as_deref(), Some(a.as_str()));
        // The older version creates its own store; rolling back again
        // leaves it alone.
        crate::storage::SqliteStore::open(&database).unwrap();
        home.revert(true).unwrap();
        assert!(
            database.exists(),
            "the older version's store was moved aside"
        );
        // Nor does a retry of a move that had completed.
        let mut completed = home.record().unwrap().unwrap();
        completed.restored = false;
        home.write_record(&completed).unwrap();
        home.revert(true).unwrap();
        assert!(database.exists(), "a completed move was redone");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A first install that crashed after recording its switch but before
    /// publishing `current` does not block the next switch.
    #[test]
    fn an_unpublished_first_install_is_switched_again() {
        let root = root("unpublished");
        let home = Home::new(root.join("home"));
        let database = root.join("tenkai.db");
        let fresh = StoreCheck {
            stored: 0,
            supported: crate::storage::SCHEMA_VERSION,
        };
        server(&root.join("a"), "a", Some(fresh));
        let a = home.stage(&root.join("a")).unwrap();
        home.write_record(&Upgrade {
            from: None,
            to: a.clone(),
            database: database.clone(),
            backup: None,
            schema_before: 0,
            confirmed: false,
            reverted: false,
            restoring: false,
            restored: false,
        })
        .unwrap();
        assert_eq!(home.current().unwrap(), None);
        home.switch(&a, &database, 2).unwrap();
        assert_eq!(home.current().unwrap().as_deref(), Some(a.as_str()));
        home.confirm().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_candidate_that_cannot_open_the_store_is_refused_before_any_switch() {
        let root = root("refused");
        let home = Home::new(root.join("home"));
        let database = root.join("tenkai.db");
        crate::storage::SqliteStore::open(&database).unwrap();
        server(&root.join("bad"), "bad", None);
        let bad = home.stage(&root.join("bad")).unwrap();
        let refused = home
            .check_candidate(&bad, &database, std::time::Duration::from_secs(30))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("schema 99"), "{refused}");
        assert_eq!(home.current().unwrap(), None);
        assert_eq!(home.record().unwrap(), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn this_binary_checks_a_private_copy_and_refuses_a_newer_store() {
        let root = root("check");
        let database = root.join("tenkai.db");
        assert_eq!(check_store(&database).unwrap().stored, 0);
        crate::storage::SqliteStore::open(&database).unwrap();
        let check = check_store(&database).unwrap();
        assert_eq!(check.stored, check.supported);
        assert!(!check.migrates());
        set_schema(&database, crate::storage::SCHEMA_VERSION + 1);
        let refused = check_store(&database).unwrap_err().to_string();
        assert!(refused.contains("supports up to"), "{refused}");
        // The live store was not touched.
        assert_eq!(
            schema_version(&database).unwrap(),
            crate::storage::SCHEMA_VERSION + 1
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

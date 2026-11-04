//! A verified copy of a SQLite store before this binary migrates it (#906).
//!
//! Whatever replaced the binary, the first start that moves a store to a newer
//! schema first leaves `<db>.pre-v<found>.<ms>.db` beside it: a consistent,
//! self-contained single file at the old schema that the previous binary can
//! open. A copy that cannot be written and verified refuses the start before
//! the store is touched.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, ensure};

use super::*;

/// Pre-migration copies kept beside one store. The newest is never deleted.
const KEPT: usize = 3;

/// A temporary copy older than this was left by a start that crashed.
const STALE_TEMPORARY: Duration = Duration::from_secs(60 * 60);

/// Before `migrate` moves the store at `database` from an older schema, leave
/// a verified copy of it beside the store and return its path. Nothing is
/// copied for a new store, a current one, or one a newer binary wrote (which
/// `migrate` refuses). `exe` is this process's canonical executable: a
/// self-upgrade switch to it that already backed up this transition needs no
/// second copy.
///
/// A crash at any point leaves the store untouched: the copy is written under
/// a temporary name and published under its own once verified, and a retry reuses the newest
/// copy for the same schema when its bytes are what this start would write.
pub(crate) fn copy_before_migrate(
    connection: &Connection,
    database: &Path,
    exe: Option<&Path>,
) -> Result<Option<PathBuf>> {
    let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found == 0 || found >= SCHEMA_VERSION {
        return Ok(None);
    }
    if let Some(backup) =
        exe.and_then(|exe| crate::server_self_upgrade::switch_backup(exe, database, found))
    {
        eprintln!(
            "migrating the schema-{found} store {} to schema {SCHEMA_VERSION}; \
             the self-upgrade backup {} holds it as it was",
            database.display(),
            backup.display()
        );
        return Ok(None);
    }
    let copy = take_copy(connection, database, found).map_err(|error| {
        StoreError::PreMigrationCopy(format!(
            "the schema-{found} store {} was not copied before migrating it to schema \
             {SCHEMA_VERSION}, so it was left as it is: {error:#}",
            database.display()
        ))
    })?;
    eprintln!(
        "migrating the schema-{found} store {} to schema {SCHEMA_VERSION}; \
         the pre-migration copy {} holds it as it was",
        database.display(),
        copy.display()
    );
    Ok(Some(copy))
}

/// One pre-migration copy beside a store, parsed from its name.
struct Copy {
    path: PathBuf,
    found: u32,
    taken_ms: i64,
}

fn take_copy(connection: &Connection, database: &Path, found: u32) -> anyhow::Result<PathBuf> {
    let dir = match database.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = database
        .file_name()
        .and_then(|name| name.to_str())
        .context("the store's file name is not UTF-8")?;
    let now_ms = crate::now_millis();
    let temporary = dir.join(format!(
        ".{name}.pre-v{found}.{now_ms}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let written = write_copy(connection, &temporary, found);
    let kept = written.and_then(|()| {
        let newest = copies(dir, name)?
            .into_iter()
            .filter(|copy| copy.found == found)
            .max_by_key(|copy| copy.taken_ms);
        if let Some(newest) = newest
            && same_bytes(&newest.path, &temporary)?
        {
            std::fs::remove_file(&temporary)?;
            return Ok(newest.path);
        }
        // A link never replaces a copy another start took in the same
        // millisecond; the temporary name goes once the copy has its own.
        let mut taken_ms = now_ms;
        let copy = loop {
            let copy = dir.join(format!("{name}.pre-v{found}.{taken_ms}.db"));
            match std::fs::hard_link(&temporary, &copy) {
                Ok(()) => break copy,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => taken_ms += 1,
                Err(error) => {
                    return Err(error).with_context(|| format!("publishing {}", copy.display()));
                }
            }
        };
        std::fs::remove_file(&temporary)?;
        crate::runtime_self_upgrade::sync_dir(dir)?;
        Ok(copy)
    });
    let copy = kept.inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })?;
    // Pruning is housekeeping: a failure leaves an extra file, not a risk.
    if let Err(error) = prune(dir, name, &copy) {
        eprintln!(
            "pruning pre-migration copies of {}: {error:#}",
            database.display()
        );
    }
    Ok(copy)
}

/// Write a consistent, owner-only, rollback-journal copy of the store to
/// `temporary`, durable on disk and verified to open at `found`.
fn write_copy(connection: &Connection, temporary: &Path, found: u32) -> anyhow::Result<()> {
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
    }
    {
        let mut target = Connection::open(temporary)?;
        rusqlite::backup::Backup::new(connection, &mut target)?.run_to_completion(
            1024,
            Duration::from_millis(10),
            None,
        )?;
        // One self-contained file the previous binary opens as it is.
        let mode: String =
            target.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
        ensure!(mode == "delete", "the copy stayed in {mode} journal mode");
    }
    std::fs::File::open(temporary)?.sync_all()?;
    let copy = Connection::open_with_flags(temporary, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let copied: u32 = copy.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    ensure!(
        copied == found,
        "the store moved to schema {copied} while it was copied; start again"
    );
    let check: String = copy.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(
        check == "ok",
        "the copy failed its integrity check: {check}"
    );
    Ok(())
}

/// The pre-migration copies of the store `name` in `dir`.
fn copies(dir: &Path, name: &str) -> anyhow::Result<Vec<Copy>> {
    let prefix = format!("{name}.pre-v");
    let mut copies = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(rest) = file_name
            .to_str()
            .and_then(|file_name| file_name.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix(".db"))
        else {
            continue;
        };
        let Some((found, taken_ms)) = rest.split_once('.') else {
            continue;
        };
        if let (Ok(found), Ok(taken_ms)) = (found.parse(), taken_ms.parse()) {
            copies.push(Copy {
                path: entry.path(),
                found,
                taken_ms,
            });
        }
    }
    Ok(copies)
}

/// Keep the newest [`KEPT`] copies, always including `keep`, and remove
/// temporary copies a crashed start left behind.
fn prune(dir: &Path, name: &str, keep: &Path) -> anyhow::Result<()> {
    let mut older: Vec<Copy> = copies(dir, name)?
        .into_iter()
        .filter(|copy| copy.path != keep)
        .collect();
    older.sort_by_key(|copy| std::cmp::Reverse(copy.taken_ms));
    for copy in older.iter().skip(KEPT - 1) {
        std::fs::remove_file(&copy.path)
            .with_context(|| format!("removing {}", copy.path.display()))?;
    }
    let temporary = format!(".{name}.pre-v");
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let stale = entry
            .file_name()
            .to_str()
            .is_some_and(|file| file.starts_with(&temporary) && file.ends_with(".tmp"))
            && entry
                .metadata()?
                .modified()?
                .elapsed()
                .is_ok_and(|age| age > STALE_TEMPORARY);
        if stale {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn same_bytes(left: &Path, right: &Path) -> anyhow::Result<bool> {
    let (mut left, mut right) = (std::fs::File::open(left)?, std::fs::File::open(right)?);
    if left.metadata()?.len() != right.metadata()?.len() {
        return Ok(false);
    }
    let (mut a, mut b) = (vec![0; 1 << 16], vec![0; 1 << 16]);
    loop {
        let read = left.read(&mut a)?;
        if read == 0 {
            return Ok(true);
        }
        right.read_exact(&mut b[..read])?;
        if a[..read] != b[..read] {
            return Ok(false);
        }
    }
}

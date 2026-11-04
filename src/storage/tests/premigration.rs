use super::*;

use std::path::PathBuf;

/// A private directory for one test, unique across processes.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-906-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The previous release's state database (schema 12), written to `dir`.
fn previous_release_store(dir: &Path) -> PathBuf {
    let database = dir.join("tenkai.db");
    Connection::open(&database)
        .unwrap()
        .execute_batch(include_str!("fixtures/state-schema-12.sql"))
        .unwrap();
    database
}

fn version(database: &Path) -> u32 {
    Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

/// The pre-migration copies in `dir`, oldest name first.
fn copies(dir: &Path) -> Vec<PathBuf> {
    let mut copies: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("tenkai.db.pre-v") && name.ends_with(".db"))
        })
        .collect();
    copies.sort();
    copies
}

fn environment_ids(database: &Path) -> Vec<String> {
    Connection::open(database)
        .unwrap()
        .prepare("SELECT id FROM environments ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// A copy that cannot be written refuses the start, and the store keeps its
/// schema, so the previous binary still opens it.
#[test]
fn a_copy_that_cannot_be_written_refuses_the_start_and_leaves_the_store() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch("refused");
    let database = previous_release_store(&dir);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    // A superuser writes anyway; there is nothing to refuse then.
    let writable = std::fs::write(dir.join("probe"), b"").is_ok();
    let opened = (!writable).then(|| SqliteStore::open(&database));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    if let Some(opened) = opened {
        assert!(
            matches!(opened, Err(StoreError::PreMigrationCopy(_))),
            "{:?}",
            opened.err()
        );
        assert_eq!(version(&database), 12);
        assert!(copies(&dir).is_empty());
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A crash after the copy and before the migration: the restart reuses the
/// copy, so there is one, and migrates the store once.
#[test]
fn a_restart_after_a_crash_between_copy_and_migration_reuses_the_copy() {
    let dir = scratch("retry");
    let database = previous_release_store(&dir);
    let first = {
        let connection = Connection::open(&database).unwrap();
        copy_before_migrate(&connection, &database, None)
            .unwrap()
            .unwrap()
    };
    assert_eq!(version(&database), 12);

    drop(SqliteStore::open(&database).unwrap());
    assert_eq!(copies(&dir), vec![first.clone()]);
    assert_eq!(version(&first), 12);
    assert_eq!(version(&database), SCHEMA_VERSION);
    let _ = std::fs::remove_dir_all(dir);
}

/// A copy older than what the store holds now is not reused: the previous
/// binary wrote after it, and rolling back to it would lose that write.
#[test]
fn a_copy_the_store_moved_past_is_not_reused() {
    let dir = scratch("stale");
    let database = previous_release_store(&dir);
    {
        let connection = Connection::open(&database).unwrap();
        copy_before_migrate(&connection, &database, None).unwrap();
        connection
            .execute(
                "INSERT INTO environments(id,revision,configuration_json) VALUES('env-late',1,'{}')",
                [],
            )
            .unwrap();
    }

    drop(SqliteStore::open(&database).unwrap());
    let copies = copies(&dir);
    assert_eq!(copies.len(), 2);
    let newest = copies
        .iter()
        .find(|copy| environment_ids(copy).contains(&"env-late".to_owned()));
    assert!(newest.is_some(), "the new copy holds the later write");
    let _ = std::fs::remove_dir_all(dir);
}

/// At most three copies stay beside a store, the new one always among them,
/// and a temporary copy a crashed start left behind is removed once stale.
#[test]
fn copies_are_bounded_and_crashed_temporaries_removed() {
    let dir = scratch("bound");
    let database = previous_release_store(&dir);
    // Older copies, one stamped in the future: the new copy is kept anyway.
    for taken_ms in [1, 2, 3, i64::MAX] {
        std::fs::write(dir.join(format!("tenkai.db.pre-v11.{taken_ms}.db")), b"old").unwrap();
    }
    let stale = dir.join(".tenkai.db.pre-v12.1.crashed.tmp");
    std::fs::write(&stale, b"partial").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60))
        .unwrap();
    let running = dir.join(".tenkai.db.pre-v12.2.running.tmp");
    std::fs::write(&running, b"in progress").unwrap();

    drop(SqliteStore::open(&database).unwrap());
    let kept = copies(&dir);
    assert_eq!(kept.len(), 3, "{kept:?}");
    assert!(kept.contains(&dir.join(format!("tenkai.db.pre-v11.{}.db", i64::MAX))));
    assert!(kept.contains(&dir.join("tenkai.db.pre-v11.3.db")));
    let new = kept
        .iter()
        .find(|copy| copy.to_str().unwrap().contains(".pre-v12."))
        .expect("the new copy is kept");
    assert_eq!(version(new), 12);
    assert!(!stale.exists());
    assert!(running.exists(), "another start may still be writing it");
    let _ = std::fs::remove_dir_all(dir);
}

/// A new store and a current one need no copy.
#[test]
fn no_copy_without_a_schema_upgrade() {
    let dir = scratch("none");
    let database = dir.join("tenkai.db");
    drop(SqliteStore::open(&database).unwrap());
    drop(SqliteStore::open(&database).unwrap());
    assert!(copies(&dir).is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

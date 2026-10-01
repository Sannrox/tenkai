//! `TENKAI_POSTGRES_URL` handling for SQLite store opens.
//!
//! These checks set a process-wide environment variable, so they live in their
//! own test binary: the library suite opens embedded stores in parallel and
//! must never observe the variable.

use tenkai::storage::SqliteStore;

#[test]
fn postgres_url_refuses_embedded_open_and_allows_hub_control_plane() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-postgres-url-refusal-{}",
        std::process::id()
    ));
    // SAFETY: this binary has exactly one test, so no other thread reads the
    // environment while it is modified.
    unsafe { std::env::set_var("TENKAI_POSTGRES_URL", "postgres://hub.example/tenkai") };

    let embedded = SqliteStore::open_embedded(root.join("embedded.db"), "tenkai");
    let control_plane = SqliteStore::open_control_plane(root.join("hub.db"), "tenkai");

    unsafe { std::env::remove_var("TENKAI_POSTGRES_URL") };
    let _ = std::fs::remove_dir_all(&root);

    match embedded {
        Ok(_) => panic!("embedded open must refuse TENKAI_POSTGRES_URL"),
        Err(error) => assert!(error.to_string().contains("TENKAI_POSTGRES_URL"), "{error}"),
    }
    control_plane.expect("hub control-plane SQLite must allow TENKAI_POSTGRES_URL");
}

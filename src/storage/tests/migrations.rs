use super::*;

#[test]
fn newer_schema_fails_closed() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    let mut connection = connection;
    assert!(matches!(
        migrate(&mut connection),
        Err(StoreError::UnsupportedSchema { .. })
    ));
}

#[test]
fn version_one_schema_migrates_provider_outbox_transactionally() {
    let mut connection = Connection::open_in_memory().unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    migrate(&mut connection).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    connection
        .execute(
            "INSERT INTO provider_events(id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,last_error)
             VALUES('event-1','audit','sha256:x','{}',0,0,'')",
            [],
        )
        .unwrap();
}

#[test]
fn migrates_shared_legacy_provider_events_from_version_zero() {
    let mut connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE provider_events (
                 id TEXT NOT NULL, provider_kind TEXT NOT NULL,
                 binding_digest TEXT NOT NULL, payload_json TEXT NOT NULL,
                 attempts INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL,
                 delivered_at INTEGER, last_error TEXT NOT NULL,
                 claim_token TEXT, claim_until INTEGER,
                 PRIMARY KEY(provider_kind,id)
             );",
        )
        .unwrap();

    migrate(&mut connection).unwrap();

    let columns: Vec<String> = connection
        .prepare("PRAGMA table_info(provider_events)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(columns.iter().any(|column| column == "environment_id"));
    assert!(columns.iter().any(|column| column == "observed_at"));
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        SCHEMA_VERSION
    );
}

#[test]
fn provider_event_inspection_uses_immutable_observation_time() {
    let store = SqliteStore::open_in_memory().unwrap();
    let old_event = crate::providers::terminal_outcome_event(
        "deployment-old",
        "plan-prod",
        "sha256:plan",
        "release-api",
        "sha256:release",
        "api",
        "prod",
        "environment-prod",
        "sha256:config",
        crate::providers::TerminalOutcomeState::DeploymentSucceeded,
        100,
    )
    .unwrap();
    let mut old_record = crate::providers::provider_event_record(
        crate::providers::OUTCOME_PROVIDER_KIND,
        &old_event,
        100,
    )
    .unwrap();
    old_record.next_attempt_at = 10_000;
    store.enqueue_provider_event(&old_record).unwrap();

    let new_event = crate::providers::terminal_outcome_event(
        "deployment-new",
        "plan-prod",
        "sha256:plan",
        "release-api",
        "sha256:release",
        "api",
        "prod",
        "environment-prod",
        "sha256:config",
        crate::providers::TerminalOutcomeState::DeploymentSucceeded,
        200,
    )
    .unwrap();
    let new_record = crate::providers::provider_event_record(
        crate::providers::OUTCOME_PROVIDER_KIND,
        &new_event,
        200,
    )
    .unwrap();
    store.enqueue_provider_event(&new_record).unwrap();

    let selected = store
        .list_provider_events(crate::providers::OUTCOME_PROVIDER_KIND, "prod", 1)
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].id, new_event.id);
}

#[test]
fn schema_eleven_backfills_environment_retirement_column() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-457-retirement-{}-{}.db",
        std::process::id(),
        crate::now_millis()
    ));
    {
        let mut connection = Connection::open(&path).unwrap();
        migrate(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP INDEX environments_active;
                 ALTER TABLE environments DROP COLUMN retired_at;
                 PRAGMA user_version = 11;",
            )
            .unwrap();
        let retired_properties = r#"{"properties":{"tenkai.retirement.reason":"decommissioned","tenkai.retirement.actor":"ops","tenkai.retirement.at":"7"}}"#;
        let retired_tenant =
            r#"{"_tenkai_retirement":{"reason":"decommissioned","actor":"ops","retired_at":9}}"#;
        for (id, configuration) in [
            ("active", "{}"),
            ("gone", "{}"),
            ("tenkai:env:gone", retired_properties),
            ("tenant-retired", retired_tenant),
        ] {
            connection
                .execute(
                    "INSERT INTO environments(id,revision,configuration_json) VALUES(?1,1,?2)",
                    rusqlite::params![id, configuration],
                )
                .unwrap();
        }
    }

    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(
        store.list_active_catalog_environment_ids().unwrap(),
        vec!["active"],
        "retired rows and the legacy alias of a retired catalog row stay hidden"
    );
    assert_eq!(
        store.list_active_environment_ids().unwrap(),
        vec!["active", "gone"],
        "tenant listing filters on the row's own retirement"
    );
    drop(store);
    let _ = std::fs::remove_file(path);
}

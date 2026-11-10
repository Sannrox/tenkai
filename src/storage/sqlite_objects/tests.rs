use super::*;
use crate::embedded::EmbeddedStore;
use crate::ontology::plan_id;
use crate::plan::{Action, DesiredStateInput, PLAN_FORMAT_VERSION, PlanState, Step};
use crate::storage::OperationalStore;
use prost::Message;

#[test]
fn create_once_conflict_is_store_already_exists() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-743-create-{}-{}.db",
        std::process::id(),
        crate::now_millis()
    ));
    let _ = std::fs::remove_file(&path);
    let store = SqliteStore::open(&path).unwrap();
    let object = Object {
        id: "tenkai:conformance:object".into(),
        kind: "tenkai.conformance".into(),
        name: "original".into(),
        ..Object::default()
    };
    store.create(object.clone()).unwrap();
    let error = store.create(object).unwrap_err();
    assert!(error.is_already_exists(), "{error}");
    let _ = std::fs::remove_file(path);
}

#[test]
fn catalog_history_older_than_retention_is_pruned() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-874-prune-{}-{}.db",
        std::process::id(),
        crate::now_millis()
    ));
    let _ = std::fs::remove_file(&path);
    let store = SqliteStore::open(&path).unwrap();
    let claim = Object {
        id: "tenkai:env:lab:execution:v2".into(),
        kind: crate::ontology::KIND_ENVIRONMENT_EXECUTION.into(),
        name: "apply lease".into(),
        properties: [("expires_at".into(), "1".into())].into_iter().collect(),
        ..Object::default()
    };
    let other = Object {
        id: "tenkai:conformance:object".into(),
        kind: "tenkai.conformance".into(),
        name: "original".into(),
        properties: [("k".into(), "v1".into())].into_iter().collect(),
        ..Object::default()
    };
    store.create(claim.clone()).unwrap();
    store.create(other.clone()).unwrap();
    let old_ts = crate::now_millis() - crate::storage::CATALOG_HISTORY_RETENTION_MS - 1;
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO catalog_changes(id,object_id,timestamp,payload) VALUES(?1,?2,?3,?4)",
            rusqlite::params!["old-claim-change", claim.id, old_ts, vec![0_u8]],
        )
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO catalog_changes(id,object_id,timestamp,payload) VALUES(?1,?2,?3,?4)",
            rusqlite::params!["old-other-change", other.id, old_ts, vec![0_u8]],
        )
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO catalog_decisions(id,timestamp,actor,action,payload) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params!["old-decision", old_ts, "tenkai", "x", vec![0_u8]],
        )
        .unwrap();
    let mut heartbeat = claim;
    heartbeat.properties.insert("expires_at".into(), "2".into());
    store.put(heartbeat).unwrap();
    let leftover_claim: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM catalog_changes WHERE id='old-claim-change'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let leftover_other: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM catalog_changes WHERE id='old-other-change'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let leftover_decisions: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM catalog_decisions WHERE id='old-decision'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        leftover_claim, 0,
        "expired execution-claim changes must be deleted"
    );
    assert_eq!(
        leftover_other, 1,
        "other object change history must be kept"
    );
    assert_eq!(leftover_decisions, 1, "decision rows must be kept");
    let _ = std::fs::remove_file(path);
}

#[test]
fn leftover_graph_cannot_authorize_apply_after_migration() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-382-graph-{}-{}.db",
        std::process::id(),
        crate::now_millis()
    ));
    let _ = std::fs::remove_file(&path);
    let graph = EmbeddedStore::open(&path, "tenkai".into()).unwrap();
    let env = Object {
        id: env_id("lab"),
        kind: KIND_ENVIRONMENT.into(),
        name: "lab".into(),
        namespace: NS.into(),
        properties: [("description".into(), "fixture".into())]
            .into_iter()
            .collect(),
        created: 1,
        updated: 1,
        ..Object::default()
    };
    graph.put(env).unwrap();
    let plan = sample_plan("lab", 10);
    let object = plan.to_object().unwrap();
    graph.put(object).unwrap();
    drop(graph);

    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        crate::storage::SCHEMA_VERSION
    );
    assert!(!store.leftover_graph_tables().unwrap());
    let record = store.get_plan(&plan.id).unwrap().expect("typed plan");
    assert_eq!(record.content_digest, plan.executable_digest().unwrap());
    assert_eq!(record.status, PlanStatus::Computed);
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO catalog_objects(id,kind,payload) VALUES(?1,?2,?3)",
            rusqlite::params![
                "tenkai:plan:residual",
                KIND_PLAN,
                Object {
                    id: "tenkai:plan:residual".into(),
                    kind: KIND_PLAN.into(),
                    name: "residual".into(),
                    namespace: NS.into(),
                    properties: [("plan".into(), "{}".into())].into_iter().collect(),
                    ..Object::default()
                }
                .encode_to_vec()
            ],
        )
        .unwrap();
    assert!(
        store.get("tenkai:plan:residual").unwrap().is_none(),
        "catalog leftover must not grant plan authority"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn legacy_graph_import_skips_copied_rows_and_does_not_bump_revision() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-516-resume-{}-{}.db",
        std::process::id(),
        crate::now_millis()
    ));
    let _ = std::fs::remove_file(&path);
    let graph = EmbeddedStore::open(&path, "tenkai".into()).unwrap();
    for name in ["alpha", "beta"] {
        graph
            .put(Object {
                id: env_id(name),
                kind: KIND_ENVIRONMENT.into(),
                name: name.into(),
                namespace: NS.into(),
                properties: [("description".into(), "fixture".into())]
                    .into_iter()
                    .collect(),
                created: 1,
                updated: 1,
                ..Object::default()
            })
            .unwrap();
    }
    drop(graph);

    let mut connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    ensure_typed_schema_tables(&connection).unwrap();
    ensure_environment_retirement_column(&mut connection).unwrap();
    ensure_catalog(&connection).unwrap();
    let first_id = env_id("alpha");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM embedded_objects WHERE id=?1",
            [&first_id],
            |row| row.get(0),
        )
        .unwrap();
    let object = Object::decode(payload.as_slice()).unwrap();
    {
        let tx = connection.transaction().unwrap();
        upsert_object_in(&tx, &object, "tenkai").unwrap();
        tx.commit().unwrap();
    }
    let revision_before: u64 = connection
        .query_row(
            "SELECT revision FROM environments WHERE id=?1",
            [&first_id],
            |row| row.get(0),
        )
        .unwrap();

    import_legacy_graph(&mut connection).unwrap();

    let leftover: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='embedded_objects')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!leftover, "graph tables must drop after a resumed import");
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM environments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
    let revision_after: u64 = connection
        .query_row(
            "SELECT revision FROM environments WHERE id=?1",
            [&first_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        revision_before, revision_after,
        "a restarted import must not rewrite already-copied environments"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn embedded_backup_restore_stays_on_typed_schema() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-382-backup-{}-{}",
        std::process::id(),
        crate::now_millis()
    ));
    let _ = std::fs::create_dir_all(&root);
    let database = root.join("tenkai.db");
    let backup = root.join("backup.db");
    let restored = root.join("restored.db");
    let store = SqliteStore::open_embedded(&database, "tenkai").unwrap();
    let env = Object {
        id: env_id("lab"),
        kind: KIND_ENVIRONMENT.into(),
        name: "lab".into(),
        namespace: NS.into(),
        properties: [("description".into(), "fixture".into())]
            .into_iter()
            .collect(),
        created: 1,
        updated: 1,
        ..Object::default()
    };
    store.put(env).unwrap();
    let plan = sample_plan("lab", 11);
    store.put(plan.to_object().unwrap()).unwrap();
    store.backup(&backup).unwrap();
    drop(store);
    SqliteStore::restore(&backup, &restored).unwrap();
    let restored_store = SqliteStore::open_embedded(&restored, "tenkai").unwrap();
    assert_eq!(
        restored_store.schema_version().unwrap(),
        crate::storage::SCHEMA_VERSION
    );
    assert!(!restored_store.leftover_graph_tables().unwrap());
    assert!(restored_store.get_plan(&plan.id).unwrap().is_some());
    let _ = std::fs::remove_dir_all(root);
}

fn sample_plan(env: &str, created_at: i64) -> Plan {
    let content_id = String::from("digest-a");
    Plan {
        format_version: PLAN_FORMAT_VERSION,
        id: plan_id(env, created_at, &content_id),
        content_id,
        environment: env.into(),
        created_at,
        inputs: vec![DesiredStateInput {
            product: "api".into(),

            instance: String::new(),
            channel: "stable".into(),
            channel_id: "tenkai:channel:api/stable".into(),
            desired_version: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "abc".into(),
            artifact_digest: "abc".into(),
            deployed_version: None,
            providers: Default::default(),
        }],
        steps: vec![Step {
            id: format!("{}:step:0", plan_id(env, created_at, "digest-a")),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "abc".into(),
            artifact_digest: "abc".into(),
            workdir: ".".into(),
            host: None,
            sealed: Vec::new(),
            restore: None,
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
        }],
        state: PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
        recalled_recovery_reason: None,
        credential_runway: None,
    }
}

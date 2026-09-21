use super::*;
use crate::embedded::EmbeddedStore;
use crate::ontology::plan_id;
use crate::plan::{Action, DesiredStateInput, PLAN_FORMAT_VERSION, PlanState, Step};
use crate::storage::OperationalStore;

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
    assert_eq!(store.schema_version().unwrap(), 11);
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
    assert_eq!(restored_store.schema_version().unwrap(), 11);
    assert!(!restored_store.leftover_graph_tables().unwrap());
    assert!(restored_store.get_plan(&plan.id).unwrap().is_some());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn postgres_url_fails_closed_on_embedded_open() {
    let previous = std::env::var_os("TENKAI_POSTGRES_URL");
    unsafe {
        std::env::set_var("TENKAI_POSTGRES_URL", "postgres://hub.example/tenkai");
    }
    let error = match SqliteStore::open_embedded(
        std::env::temp_dir().join("tenkai-382-pg-refuse.db"),
        "tenkai",
    ) {
        Ok(_) => panic!("embedded open must refuse TENKAI_POSTGRES_URL"),
        Err(error) => error,
    };
    match previous {
        Some(value) => unsafe { std::env::set_var("TENKAI_POSTGRES_URL", value) },
        None => unsafe { std::env::remove_var("TENKAI_POSTGRES_URL") },
    }
    assert!(error.to_string().contains("TENKAI_POSTGRES_URL"), "{error}");
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
            channel: "stable".into(),
            channel_id: "tenkai:channel:api/stable".into(),
            desired_version: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "abc".into(),
            artifact_digest: "abc".into(),
            deployed_version: None,
        }],
        steps: vec![Step {
            id: format!("{}:step:0", plan_id(env, created_at, "digest-a")),
            order: 0,
            product: "api".into(),
            action: Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "abc".into(),
            artifact_digest: "abc".into(),
            workdir: ".".into(),
            restore: None,
        }],
        state: PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
        recalled_recovery_reason: None,
    }
}

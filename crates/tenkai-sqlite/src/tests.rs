use super::*;

mod contention;
mod feedback;
mod fencing;
mod lifecycle;
mod migrations;
mod premigration;

fn environment(store: &SqliteStore) {
    store
        .put_environment(&EnvironmentRecord {
            id: "prod".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
}

fn plan(store: &SqliteStore) -> PlanRecord {
    let plan = PlanRecord {
        id: "plan-1".into(),
        environment_id: "prod".into(),
        format_version: 1,
        content_digest: "sha256:plan".into(),
        plan_json: "{}".into(),
        status: PlanStatus::Computed,
        status_detail: String::new(),
    };
    store.create_plan(&plan).unwrap();
    plan
}

#[test]
fn sqlite_catalog_logs_every_write() {
    let store = SqliteStore::open_in_memory().unwrap();
    tenkai::storage::write_log_contract::assert_write_log(&store, None);
}

use super::*;

mod fencing;
mod lifecycle;
mod migrations;

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

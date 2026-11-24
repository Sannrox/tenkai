//! `ci-hub-postgres` fleet measurement (#1084).
//!
//! The synthetic workload, with signing, approval, and gates enabled, runs on
//! one tenant schema of the hub store. CPU and peak memory are this
//! process's (#1235), so the scheduled job runs this test alone with
//! `--exact`. `TENKAI_HUB_FLEET_ENVIRONMENTS` sets the fleet size (default
//! 1000). Under `TENKAI_ROLLOUT_GATE=regression`, as in
//! `scripts/check-rollout-time.sh`, every tick is also checked against
//! `perf/hub-fleet-baseline.json`.

use super::super::*;
use std::sync::Arc;
use tenkai::fleet_budget::{self, Profile};
use tenkai::fleet_workload::{self, WORKLOAD_SIZE, WorkloadSpec};

const BASELINE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/hub-fleet-baseline.json"
);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Postgres; run alone: cargo test --features postgres --lib -- --ignored --exact tests::live_hub_fleet::live_hub_fleet_measure"]
async fn live_hub_fleet_measure() {
    let environments = std::env::var("TENKAI_HUB_FLEET_ENVIRONMENTS")
        .map(|value| value.parse().expect("TENKAI_HUB_FLEET_ENVIRONMENTS"))
        .unwrap_or(WORKLOAD_SIZE);
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let tenants = super::LiveTenants::new(&config);
    let tenant = tenants.tenant("fleet");
    let store = config.open().expect("connect");
    let mut ctx = tenkai::client::Ctx::tenant_hub_catalog(Arc::new(store.clone()))
        .with_catalog_tenant(&tenant);
    let root = std::env::temp_dir().join(format!(
        "tenkai-hub-fleet-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let spec = WorkloadSpec {
        seed: "hub-fleet-seed".into(),
        product: "scale-app".into(),
        channel: "stable".into(),
        current_version: "1.1.0".into(),
        behind_version: "1.0.0".into(),
        environments,
    };
    fleet_budget::seed_signed_channel(&mut ctx, &root, &spec)
        .await
        .unwrap();
    let probe = HubTenantProbe::new(store, &tenant).unwrap();
    let (plan, report) = fleet_budget::measure(&mut ctx, &spec, Profile::CiHubPostgres, &probe)
        .await
        .unwrap();
    println!("{}", fleet_workload::format_workload(&plan));
    println!("{}", fleet_budget::format_report(&report));
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(report.profile, "ci-hub-postgres");
    assert!(!report.skip_gates);
    assert!(report.samples.iter().all(|sample| {
        sample.environments == environments as usize && sample.storage_bytes > 0
    }));
    let load = report.database_load.expect("hub reports database load");
    assert!(load.transactions > 0 && load.rows_read > 0, "{load:?}");
    if tenkai::rollout_time::Gate::from_env() == tenkai::rollout_time::Gate::Regression {
        let baseline = fleet_budget::load_baseline(std::path::Path::new(BASELINE)).unwrap();
        fleet_budget::check_baseline(&report, &baseline).unwrap();
    }
}

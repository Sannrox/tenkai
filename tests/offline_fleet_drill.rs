//! Isolated-process drill so `TENKAI_SOFTWARE_EXECUTOR=fake` does not leak
//! into the shared unit-test binary.

use tenkai::auth_context::{AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind};
use tenkai::client::Ctx;
use tenkai::offline_fleet_drill::{ROLLBACK_COUNT, SPOKE_COUNT, rehearse};

#[tokio::test]
async fn fifty_isolated_spokes_upgrade_and_partial_rollback_match_hub_status() {
    unsafe {
        std::env::set_var("TENKAI_SOFTWARE_EXECUTOR", "fake");
    }
    let actor = AuthenticatedRequestContextBuilder::new(
        "offline-drill",
        PrincipalIdentity {
            id: "management".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .expect("management context");
    let root = std::env::temp_dir().join(format!(
        "tenkai-offline-fifty-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    let report = rehearse(&mut ctx, &root, &actor).await.unwrap();
    assert_eq!(report.upgraded.len(), SPOKE_COUNT - ROLLBACK_COUNT);
    assert_eq!(report.rolled_back.len(), ROLLBACK_COUNT);
    assert_eq!(report.spoke_deployed, report.hub_deployed);
    let _ = std::fs::remove_dir_all(root);
}

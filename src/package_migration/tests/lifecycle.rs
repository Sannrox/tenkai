use super::super::types::MIGRATION_EXEC_NAMESPACE;
use super::super::*;
use super::helpers::{deploy_source, publish_pins};

#[tokio::test]
async fn compatible_migration_approves_executes_resumes_and_rolls_back() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-migration-{}-{}",
        std::process::id(),
        crate::now_millis()
    ));
    let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    crate::ontology::register(&mut ctx).await.unwrap();
    crate::plan::env_add(&mut ctx, "local", "fixture")
        .await
        .unwrap();
    let declaration = publish_pins(&mut ctx, &root).await;
    deploy_source(&mut ctx).await;
    let auth = MigrationAuthorization::LocalDevelopment {
        reason: "package migration e2e",
    };
    let previewed = preview(&mut ctx, "cutover", "local", declaration.clone(), None)
        .await
        .unwrap();
    let created = create(&mut ctx, "cutover", "local", declaration.clone(), None)
        .await
        .unwrap();
    assert_eq!(previewed.identity_digest, created.identity_digest);
    approve(&mut ctx, "cutover", auth).await.unwrap();
    let first = execute(&mut ctx, "cutover", auth, None).await.unwrap();
    assert_eq!(first.receipts.len(), 1);
    assert_eq!(first.status, MigrationStatus::Running);
    let sneak = crate::plan::create_from_steps(
        &mut ctx,
        "local",
        vec![crate::plan::Step {
            id: String::new(),
            order: 0,
            product: "pkg".into(),
            action: crate::plan::Action::Upgrade,
            from: Some("1.0.0".into()),
            to: "1.1.0".into(),
            release_id: crate::ontology::release_id("pkg", "1.1.0"),
            release_digest: declaration.target.digest.clone(),
            artifact_digest: declaration.target.digest.clone(),
            workdir: root.join("1.1.0").to_string_lossy().into(),
            restore: None,
        }],
    )
    .await
    .unwrap();
    let err = crate::apply::execute_with_options(
        &mut ctx,
        &sneak.id,
        crate::apply::ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                reason: "sneak apply during migration",
            },
            software_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("package migration"), "{err}");
    let held = ctx
        .acquire_lease(MIGRATION_EXEC_NAMESPACE, "cutover", "tester", 60_000)
        .await
        .unwrap();
    let err = resume(&mut ctx, "cutover", auth, Some(first.fence_generation))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("already has an execution"), "{err}");
    ctx.release_lease(MIGRATION_EXEC_NAMESPACE, "cutover", &held.fencing_token)
        .await
        .unwrap();
    let resumed = resume(&mut ctx, "cutover", auth, Some(first.fence_generation))
        .await
        .unwrap();
    assert_eq!(resumed.receipts.len(), 2);
    assert_eq!(resumed.status, MigrationStatus::Succeeded);
    assert_eq!(resumed.receipts[1].effect, "apply_target");
    let env = crate::environment::environment(&mut ctx, "local")
        .await
        .unwrap();
    assert_eq!(
        env.properties.get("deployed.pkg").map(String::as_str),
        Some("1.1.0")
    );
    let again = resume(&mut ctx, "cutover", auth, Some(resumed.fence_generation))
        .await
        .unwrap();
    assert_eq!(again.receipts, resumed.receipts);
    let rolled = rollback(&mut ctx, "cutover", auth, Some(again.fence_generation))
        .await
        .unwrap();
    assert_eq!(rolled.status, MigrationStatus::RolledBack);
    assert!(
        rolled
            .receipts
            .iter()
            .all(|receipt| receipt.result == "rolled_back")
    );
    let _ = std::fs::remove_dir_all(root);
}

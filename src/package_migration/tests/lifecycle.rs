use super::super::types::{MIGRATION_EXEC_NAMESPACE, record_catalog_id};
use super::super::*;
use super::helpers::{deploy_source, publish_pins, temp_root};

#[tokio::test]
async fn compatible_migration_approves_executes_resumes_and_rolls_back() {
    let root = temp_root("lifecycle");
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
    // Backdate the stored object: every later update must keep `created`.
    let id = record_catalog_id(&created);
    let mut stored = ctx.get(&id).await.unwrap().unwrap();
    stored.created = 1;
    ctx.put(stored).await.unwrap();
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
            instance: String::new(),
            action: crate::plan::Action::Upgrade,
            from: Some("1.0.0".into()),
            to: "1.1.0".into(),
            release_id: crate::ontology::release_id("pkg", "1.1.0"),
            release_digest: declaration.target.digest.clone(),
            artifact_digest: declaration.target.digest.clone(),
            workdir: root.join("1.1.0").to_string_lossy().into(),
            host: None,
            sealed: Vec::new(),
            restore: None,
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
            target_changes: Vec::new(),
            reason: String::new(),
            cluster_namespace: None,
        }],
    )
    .await
    .unwrap();
    let err = crate::apply::execute_with_options(
        &mut ctx,
        &sneak.id,
        crate::apply::ExecutionOptions {
            rollback_hold: true,
            skip_gates: false,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                reason: "sneak apply during migration",
            },
            software_executors: crate::software_executor::SoftwareExecutors::default(),
            model_runtime_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
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
    assert_eq!(ctx.get(&id).await.unwrap().unwrap().created, 1);
    assert!(
        rolled
            .receipts
            .iter()
            .all(|receipt| receipt.result == "rolled_back")
    );
    let _ = std::fs::remove_dir_all(root);
}

// #1294: approval holds the execution lease from read to write, so a held
// lease refuses it and a write under a taken-over lease commits nothing.
#[tokio::test]
async fn approval_is_fenced_to_the_execution_lease() {
    let root = temp_root("approve-fence");
    let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    crate::ontology::register(&mut ctx).await.unwrap();
    crate::plan::env_add(&mut ctx, "local", "fixture")
        .await
        .unwrap();
    let declaration = publish_pins(&mut ctx, &root).await;
    deploy_source(&mut ctx).await;
    create(&mut ctx, "cutover", "local", declaration, None)
        .await
        .unwrap();
    let auth = MigrationAuthorization::LocalDevelopment {
        reason: "approval fence",
    };

    let held = ctx
        .acquire_lease(MIGRATION_EXEC_NAMESPACE, "cutover", "tester", 60_000)
        .await
        .unwrap();
    let err = approve(&mut ctx, "cutover", auth).await.unwrap_err();
    assert!(
        err.to_string().contains("already has an execution"),
        "{err}"
    );
    ctx.release_lease(MIGRATION_EXEC_NAMESPACE, "cutover", &held.fencing_token)
        .await
        .unwrap();

    let stale = super::super::leases::acquire_execution_lease(&mut ctx, "cutover", None)
        .await
        .unwrap();
    ctx.release_lease(MIGRATION_EXEC_NAMESPACE, "cutover", &stale)
        .await
        .unwrap();
    let current = super::super::leases::acquire_execution_lease(&mut ctx, "cutover", None)
        .await
        .unwrap();
    let mut record = load(&mut ctx, "cutover").await.unwrap();
    record.approval_digest = "sha256:stale".into();
    super::super::persist::persist_fenced(&mut ctx, &record, "cutover", &stale)
        .await
        .unwrap_err();
    assert!(
        load(&mut ctx, "cutover")
            .await
            .unwrap()
            .approval_digest
            .is_empty()
    );
    ctx.release_lease(MIGRATION_EXEC_NAMESPACE, "cutover", &current)
        .await
        .unwrap();

    let approved = approve(&mut ctx, "cutover", auth).await.unwrap();
    assert!(!approved.approval_digest.is_empty());
    let _ = std::fs::remove_dir_all(root);
}

/// A signed migration approval for `record`, with the trust roots that admit
/// it, both written under `root`.
fn signed_migration_approval(
    root: &std::path::Path,
    record: &MigrationRecord,
) -> (std::path::PathBuf, std::path::PathBuf) {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key();
    let key_id = crate::signature_verification::key_id(&public.to_bytes());
    let statement = MigrationApprovalStatement {
        identity_digest: record.identity_digest.clone(),
        environment: record.environment.clone(),
        purpose: super::super::types::APPROVAL_PURPOSE.into(),
        issued_at: 1,
        expires_at: i64::MAX / 4,
    };
    let signature = base64::engine::general_purpose::STANDARD.encode(
        key.sign(&crate::plan_approval::SignedApproval::canonical_bytes(&statement).unwrap())
            .to_bytes(),
    );
    let dir = root.join("approvals");
    std::fs::create_dir_all(&dir).unwrap();
    let approval = dir.join("migration.json");
    std::fs::write(
        &approval,
        serde_json::to_vec(&MigrationApprovalEnvelope {
            schema: super::super::types::APPROVAL_SCHEMA.into(),
            key_id: key_id.clone(),
            statement,
            signature,
        })
        .unwrap(),
    )
    .unwrap();
    let trust = root.join("migration-trust.toml");
    std::fs::write(
        &trust,
        format!(
            "version = 1\n[[signers]]\nkey_id = \"{key_id}\"\nidentity = \"approver\"\npublic_key = \"{}\"\n",
            base64::engine::general_purpose::STANDARD.encode(public.to_bytes())
        ),
    )
    .unwrap();
    (approval, trust)
}

// #1309: a signed rollback whose source-restore plan has no approval yet is
// waiting, not failed: the record keeps its status, names the pending plan,
// refuses forward execution, and a second run takes no new generation.
#[tokio::test]
async fn signed_rollback_awaiting_plan_approval_stays_resumable() {
    let root = temp_root("rollback-await");
    let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    crate::ontology::register(&mut ctx).await.unwrap();
    crate::plan::env_add(&mut ctx, "local", "fixture")
        .await
        .unwrap();
    let declaration = publish_pins(&mut ctx, &root).await;
    deploy_source(&mut ctx).await;
    let local = MigrationAuthorization::LocalDevelopment {
        reason: "rollback await",
    };
    create(&mut ctx, "cutover", "local", declaration, None)
        .await
        .unwrap();
    approve(&mut ctx, "cutover", local).await.unwrap();
    execute(&mut ctx, "cutover", local, None).await.unwrap();
    let done = execute(&mut ctx, "cutover", local, None).await.unwrap();
    assert_eq!(done.status, MigrationStatus::Succeeded);

    // The same executed migration, as if it had been approved by signature.
    let (approval, trust_roots) = signed_migration_approval(&root, &done);
    let signed = MigrationAuthorization::Signed {
        approval: &approval,
        trust_roots: &trust_roots,
    };
    let mut record = load(&mut ctx, "cutover").await.unwrap();
    record.approval_digest = super::super::approval::approval_digest(&record, signed).unwrap();
    super::super::persist::persist(&mut ctx, &record)
        .await
        .unwrap();

    let waiting = rollback(&mut ctx, "cutover", signed, None).await.unwrap();
    assert_eq!(waiting.status, MigrationStatus::Succeeded);
    let plan_id = waiting.pending_rollback_plan_id.clone().unwrap();
    assert_eq!(load(&mut ctx, "cutover").await.unwrap(), waiting);

    let err = resume(&mut ctx, "cutover", signed, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("rolling back") && err.contains(&plan_id),
        "{err}"
    );

    let again = rollback(&mut ctx, "cutover", signed, None).await.unwrap();
    assert_eq!(
        again.pending_rollback_plan_id.as_deref(),
        Some(plan_id.as_str())
    );
    assert_eq!(again.fence_generation, waiting.fence_generation);
    let _ = std::fs::remove_dir_all(root);
}

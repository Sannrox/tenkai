use base64::Engine as _;

use super::super::*;
use super::helpers::{deploy_source, digest, publish_pins};

#[tokio::test]
async fn denial_stale_fence_conflict_and_irreversible_recovery() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-migration-deny-{}-{}",
        std::process::id(),
        crate::now_millis()
    ));
    let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    crate::ontology::register(&mut ctx).await.unwrap();
    crate::plan::env_add(&mut ctx, "local", "fixture")
        .await
        .unwrap();
    let mut declaration = publish_pins(&mut ctx, &root).await;
    deploy_source(&mut ctx).await;
    declaration.compatibility.status = CompatibilityStatus::Incompatible;
    let err = create(&mut ctx, "bad", "local", declaration.clone(), None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not compatible"), "{err}");
    let mut cross = declaration.clone();
    cross.compatibility.status = CompatibilityStatus::Compatible;
    cross.target.product = "other".into();
    let err = create(&mut ctx, "cross", "local", cross, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("same product"), "{err}");

    declaration.compatibility.status = CompatibilityStatus::Compatible;
    create(&mut ctx, "cutover", "local", declaration.clone(), None)
        .await
        .unwrap();
    let err = execute(
        &mut ctx,
        "cutover",
        MigrationAuthorization::LocalDevelopment { reason: "nope" },
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("not approved"), "{err}");

    let auth = MigrationAuthorization::LocalDevelopment {
        reason: "package migration deny",
    };
    approve(&mut ctx, "cutover", auth).await.unwrap();
    execute(&mut ctx, "cutover", auth, None).await.unwrap();
    create(&mut ctx, "other", "local", declaration.clone(), None)
        .await
        .unwrap();
    approve(
        &mut ctx,
        "other",
        MigrationAuthorization::LocalDevelopment {
            reason: "concurrent",
        },
    )
    .await
    .unwrap();
    let err = execute(
        &mut ctx,
        "other",
        MigrationAuthorization::LocalDevelopment {
            reason: "concurrent",
        },
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("already has package migration")
            || err.contains("has package migration cutover"),
        "{err}"
    );
    let err = resume(&mut ctx, "cutover", auth, Some(99))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("stale fencing"), "{err}");
    rollback(&mut ctx, "cutover", auth, None).await.unwrap();

    let mut changed = declaration.clone();
    changed.checkpoints.pop();
    let err = create(&mut ctx, "cutover", "local", changed, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("different identity"), "{err}");

    let mut irreversible = declaration.clone();
    irreversible.checkpoints.push(CheckpointDecl {
        id: "drop-old".into(),
        class: CheckpointClass::Irreversible,
        pre_admission: Some("require_backup_receipt".into()),
    });
    let err = create(&mut ctx, "drop", "local", irreversible.clone(), None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("backup receipt"), "{err}");
    create(&mut ctx, "drop", "local", irreversible, Some(&digest('b')))
        .await
        .unwrap();
    let drop_auth = MigrationAuthorization::LocalDevelopment {
        reason: "irreversible",
    };
    approve(&mut ctx, "drop", drop_auth).await.unwrap();
    execute(&mut ctx, "drop", drop_auth, None).await.unwrap();
    execute(&mut ctx, "drop", drop_auth, None).await.unwrap();
    let finished = execute(&mut ctx, "drop", drop_auth, None).await.unwrap();
    assert_eq!(finished.status, MigrationStatus::Succeeded);
    let err = rollback(&mut ctx, "drop", drop_auth, Some(finished.fence_generation))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("irreversible"), "{err}");
    let stored = load(&mut ctx, "drop").await.unwrap();
    assert_eq!(stored.status, MigrationStatus::RecoveryRequired);
    assert_eq!(
        stored.backup_receipt_digest.as_deref(),
        Some(digest('b').as_str())
    );

    let signed = create(&mut ctx, "signed", "local", declaration.clone(), None)
        .await
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public = key.verifying_key();
    let key_id = crate::signature_verification::key_id(&public.to_bytes());
    let mut statement = MigrationApprovalStatement {
        identity_digest: signed.identity_digest.clone(),
        environment: signed.environment.clone(),
        purpose: APPROVAL_PURPOSE.into(),
        issued_at: 1,
        expires_at: i64::MAX / 4,
    };
    statement.identity_digest = digest('a');
    let bad_sig = {
        use ed25519_dalek::Signer as _;
        base64::engine::general_purpose::STANDARD.encode(
            key.sign(&canonical_approval_bytes(&statement).unwrap())
                .to_bytes(),
        )
    };
    let bad = root.join("bad-approval.json");
    std::fs::write(
        &bad,
        serde_json::to_vec(&MigrationApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: key_id.clone(),
            statement,
            signature: bad_sig,
        })
        .unwrap(),
    )
    .unwrap();
    let roots = root.join("migration-trust.toml");
    std::fs::write(
        &roots,
        format!(
            "version = 1\n[[signers]]\nkey_id = \"{key_id}\"\nidentity = \"approver\"\npublic_key = \"{}\"\n",
            base64::engine::general_purpose::STANDARD.encode(public.to_bytes())
        ),
    )
    .unwrap();
    let err = approve(
        &mut ctx,
        "signed",
        MigrationAuthorization::Signed {
            approval: &bad,
            trust_roots: &roots,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("different identity"), "{err}");
    let statement = MigrationApprovalStatement {
        identity_digest: signed.identity_digest.clone(),
        environment: signed.environment.clone(),
        purpose: APPROVAL_PURPOSE.into(),
        issued_at: 1,
        expires_at: i64::MAX / 4,
    };
    let signature = {
        use ed25519_dalek::Signer as _;
        base64::engine::general_purpose::STANDARD.encode(
            key.sign(&canonical_approval_bytes(&statement).unwrap())
                .to_bytes(),
        )
    };
    let good = root.join("good-approval.json");
    std::fs::write(
        &good,
        serde_json::to_vec(&MigrationApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id,
            statement,
            signature,
        })
        .unwrap(),
    )
    .unwrap();
    approve(
        &mut ctx,
        "signed",
        MigrationAuthorization::Signed {
            approval: &good,
            trust_roots: &roots,
        },
    )
    .await
    .unwrap();

    crate::plan::env_add(&mut ctx, "stage", "fixture")
        .await
        .unwrap();
    create(&mut ctx, "remote", "stage", declaration, None)
        .await
        .unwrap();
    let err = approve(
        &mut ctx,
        "remote",
        MigrationAuthorization::LocalDevelopment { reason: "stage" },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("built-in local"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

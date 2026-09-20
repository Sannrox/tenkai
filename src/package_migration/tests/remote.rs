use std::collections::BTreeMap;

use super::super::approval_files::validate_plan_approval_filename;
use super::super::types::record_catalog_id;
use super::super::*;
use super::helpers::{digest, publish_pins};

#[tokio::test]
async fn partitions_keep_separate_records_for_the_same_migration_name() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-migration-partition-{}-{}",
        std::process::id(),
        crate::now_millis()
    ));
    let mut ctx = crate::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    crate::ontology::register(&mut ctx).await.unwrap();
    crate::plan::env_add(&mut ctx, "prod", "fixture")
        .await
        .unwrap();
    let declaration = publish_pins(&mut ctx, &root).await;
    create_in(
        &mut ctx,
        "cutover",
        "prod",
        declaration.clone(),
        None,
        Some("tenant-a"),
    )
    .await
    .unwrap();
    let missing = load_in(&mut ctx, "cutover", Some("tenant-b"))
        .await
        .unwrap_err()
        .to_string();
    assert!(missing.contains("is not stored"), "{missing}");
    assert!(!missing.contains("tenant-a"), "{missing}");
    create_in(
        &mut ctx,
        "cutover",
        "prod",
        declaration,
        None,
        Some("tenant-b"),
    )
    .await
    .unwrap();
    let a = load_in(&mut ctx, "cutover", Some("tenant-a"))
        .await
        .unwrap();
    let b = load_in(&mut ctx, "cutover", Some("tenant-b"))
        .await
        .unwrap();
    assert_eq!(a.partition.as_deref(), Some("tenant-a"));
    assert_eq!(b.partition.as_deref(), Some("tenant-b"));
    assert_ne!(record_catalog_id(&a), record_catalog_id(&b));
    let unscoped = load(&mut ctx, "cutover").await.unwrap_err().to_string();
    assert!(unscoped.contains("is not stored"), "{unscoped}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn remote_api_version_and_unknown_fields_fail_closed() {
    require_migration_api_version(MIGRATION_API_VERSION).unwrap();
    let err = require_migration_api_version(99).unwrap_err().to_string();
    assert!(
        err.contains("unsupported package migration API version 99"),
        "{err}"
    );
    let err = serde_json::from_str::<PackageMigrationPreviewRequest>(
        r#"{"version":1,"environment":"local","declaration":{"version":1,"profile":"tenkai.package_migration.v1","source":{"product":"pkg","version":"1.0.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"target":{"product":"pkg","version":"1.1.0","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"compatibility":{"version":1,"status":"compatible","evidence_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"checkpoints":[{"id":"preflight","class":"reversible"}]},"allow_unapproved_development":true}"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown field"), "{err}");
    let err = RemoteApprovalFiles::materialize(
        &MigrationApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: "k".into(),
            statement: MigrationApprovalStatement {
                identity_digest: digest('a'),
                environment: "stage".into(),
                purpose: APPROVAL_PURPOSE.into(),
                issued_at: 1,
                expires_at: 2,
            },
            signature: "c2ln".into(),
        },
        &ApprovalTrustRoots {
            version: 1,
            signers: vec![ApprovalTrustedSigner {
                key_id: "k".into(),
                identity: "approver".into(),
                public_key: "cA==".into(),
            }],
        },
        &BTreeMap::from([(
            "../escape".into(),
            crate::plan_approval::ApprovalEnvelope {
                schema: crate::plan_approval::APPROVAL_SCHEMA.into(),
                key_id: "k".into(),
                statement: crate::plan_approval::ApprovalStatement {
                    plan_digest: digest('p'),
                    environment: "stage".into(),
                    purpose: "execute_plan".into(),
                    skip_gates: false,
                    issued_at: 1,
                    expires_at: 2,
                    policy_provider: "none".into(),
                    policy_evidence_id: "none".into(),
                    policy_digest: digest('q'),
                },
                signature: "c2ln".into(),
            },
        )]),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("safe file name"), "{err}");
    validate_plan_approval_filename("tenkai:plan:stage:1:sha256:abc").unwrap();
}

#[tokio::test]
async fn remote_approval_files_materialize_on_the_blocking_pool() {
    let files = RemoteApprovalFiles::materialize_async(
        MigrationApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: "k".into(),
            statement: MigrationApprovalStatement {
                identity_digest: digest('a'),
                environment: "stage".into(),
                purpose: APPROVAL_PURPOSE.into(),
                issued_at: 1,
                expires_at: 2,
            },
            signature: "c2ln".into(),
        },
        ApprovalTrustRoots {
            version: 1,
            signers: vec![ApprovalTrustedSigner {
                key_id: "k".into(),
                identity: "approver".into(),
                public_key: "cA==".into(),
            }],
        },
        BTreeMap::new(),
    )
    .await
    .unwrap();
    assert!(files.approval.is_file(), "{:?}", files.approval);
    assert!(files.trust_roots.is_file(), "{:?}", files.trust_roots);
}

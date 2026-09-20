use std::path::Path;

use crate::catalog::{self, PublishOptions};
use crate::client::Ctx;

use super::super::admit::catalog_digest;
use super::super::*;

pub(super) fn digest(nibble: char) -> String {
    format!("sha256:{}", nibble.to_string().repeat(64))
}

pub(super) fn declaration(irreversible: bool) -> MigrationDeclaration {
    let mut checkpoints = vec![
        CheckpointDecl {
            id: "preflight".into(),
            class: CheckpointClass::Reversible,
            pre_admission: None,
        },
        CheckpointDecl {
            id: "switch".into(),
            class: CheckpointClass::Compensating,
            pre_admission: None,
        },
    ];
    if irreversible {
        checkpoints.push(CheckpointDecl {
            id: "drop-old".into(),
            class: CheckpointClass::Irreversible,
            pre_admission: Some("require_backup_receipt".into()),
        });
    }
    MigrationDeclaration {
        version: 1,
        profile: MIGRATION_PROFILE.into(),
        source: PackagePin {
            product: "pkg".into(),
            version: "1.0.0".into(),
            digest: String::new(),
        },
        target: PackagePin {
            product: "pkg".into(),
            version: "1.1.0".into(),
            digest: String::new(),
        },
        compatibility: CompatibilityEvidence {
            version: 1,
            status: CompatibilityStatus::Compatible,
            evidence_digest: digest('e'),
        },
        checkpoints,
    }
}

pub(super) async fn publish_pins(ctx: &mut Ctx, root: &Path) -> MigrationDeclaration {
    let mut doc = declaration(false);
    for (version, body) in [("1.0.0", "one"), ("1.1.0", "two")] {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload.txt"), body).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "pkg"
version = "{version}"
[deploy]
install = "true"
inputs = ["payload.txt"]
"#
            ),
        )
        .unwrap();
        catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
                artifact_registry: None,
            },
        )
        .await
        .unwrap();
    }
    let source = ctx
        .get(&crate::ontology::release_id("pkg", "1.0.0"))
        .await
        .unwrap()
        .unwrap();
    let target = ctx
        .get(&crate::ontology::release_id("pkg", "1.1.0"))
        .await
        .unwrap()
        .unwrap();
    doc.source.digest = catalog_digest(source.properties.get("digest").unwrap()).unwrap();
    doc.target.digest = catalog_digest(target.properties.get("digest").unwrap()).unwrap();
    doc
}

pub(super) async fn deploy_source(ctx: &mut Ctx) {
    let actor = crate::auth_context::test_management_context("package-migration");
    catalog::promote(ctx, &actor, "pkg@1.0.0", "stable")
        .await
        .unwrap();
    crate::plan::subscribe(ctx, "local", "pkg", "stable")
        .await
        .unwrap();
    let plan = crate::plan::create(ctx, "local").await.unwrap();
    crate::apply::execute_with_options(
        ctx,
        &plan.id,
        crate::apply::ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                reason: "seed source package",
            },
            software_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
            delivery_fence: None,
        },
    )
    .await
    .unwrap();
    let env = crate::environment::environment(ctx, "local").await.unwrap();
    assert_eq!(
        env.properties.get("deployed.pkg").map(String::as_str),
        Some("1.0.0")
    );
}

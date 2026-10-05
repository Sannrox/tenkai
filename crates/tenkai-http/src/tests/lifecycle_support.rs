use super::*;

pub(super) fn migration_preview_body(environment: &str, version: u32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "environment": environment,
        "declaration": {
            "version": 1,
            "profile": "tenkai.package_migration.v1",
            "source": {
                "product": "pkg",
                "version": "1.0.0",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "target": {
                "product": "pkg",
                "version": "1.1.0",
                "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "compatibility": {
                "version": 1,
                "status": "compatible",
                "evidence_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            },
            "checkpoints": [{ "id": "preflight", "class": "reversible" }]
        }
    }))
    .unwrap()
}

pub(super) fn signed_catalog_fixture(
    root: &std::path::Path,
    version: &str,
) -> tenkai::management_lifecycle::PublishRequest {
    let manifest = root.join("tenkai.toml");
    std::fs::write(
        &manifest,
        format!(
            "[product]\nname = \"api\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n"
        ),
    )
    .unwrap();
    let keys = root.join("keys");
    let signature = root.join("signature.json");
    let trust_roots = root.join("trust-roots.toml");
    tenkai::dev_sign::sign_release(&keys, &manifest, &signature, &trust_roots).unwrap();
    tenkai::management_lifecycle::load_publish_request(&manifest, &signature, &trust_roots).unwrap()
}

pub(super) async fn catalog_router(root: &std::path::Path) -> (Router, ServerConfig) {
    let (app, config, _) = lifecycle_router(root).await;
    (app, config)
}

pub(super) async fn lifecycle_router(
    root: &std::path::Path,
) -> (Router, ServerConfig, Arc<tenkai::storage::SqliteStore>) {
    let database = root.join("tenkai.db");
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    tenkai::plan::env_add(&mut ctx, "stage", "fixture")
        .await
        .unwrap();
    tenkai::plan::env_add(&mut ctx, "prod", "other")
        .await
        .unwrap();
    let reconciler =
        tenkai::reconciler::Reconciler::new(ctx, tenkai::reconciler::Config::default()).unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(&database).unwrap());
    for name in ["stage", "prod"] {
        store
            .put_environment(&tenkai::storage::EnvironmentRecord {
                id: name.into(),
                revision: 0,
                configuration_json: "{}".into(),
            })
            .unwrap();
    }
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "stage".into())]),
    );
    config
        .environment_management_assignments
        .insert("stage-secret".into(), "stage".into());
    let app = router(config.clone(), Arc::new(reconciler), store.clone()).unwrap();
    (app, config, store)
}

pub(super) fn signed_plan_requests(
    root: &std::path::Path,
    label: &str,
    environment: &str,
    digest: &str,
    expected_generation: u64,
) -> (
    tenkai::management_lifecycle::ApproveRequest,
    tenkai::management_lifecycle::ApplyRequest,
) {
    let dir = root.join(label);
    std::fs::create_dir_all(&dir).unwrap();
    let keys = dir.join("keys");
    let approval = dir.join("approval.json");
    let trust_roots = dir.join("trust.toml");
    tenkai::dev_sign::sign_plan_approval_for_digest(
        &keys,
        digest,
        environment,
        &approval,
        &trust_roots,
        3600,
    )
    .unwrap();
    (
        tenkai::management_lifecycle::load_approve_request(
            environment,
            expected_generation,
            &approval,
            &trust_roots,
        )
        .unwrap(),
        tenkai::management_lifecycle::load_apply_request(
            environment,
            expected_generation,
            &approval,
            &trust_roots,
            false,
            None,
        )
        .unwrap(),
    )
}

pub(super) async fn deployed_version(
    client: &RemoteClient,
    environment: &str,
    product: &str,
) -> String {
    let rows = client.environment_status(environment).await.unwrap();
    rows.into_iter()
        .find(|row| row.product == product)
        .and_then(|row| row.deployed)
        .unwrap_or_else(|| "-".into())
}

/// Embedded store with environment `local`, published `pkg` 1.0.0 and 1.1.0,
/// and a migration declaration between the two releases.
pub(super) struct MigrationFixture {
    pub root: std::path::PathBuf,
    pub database: std::path::PathBuf,
    pub ctx: tenkai::client::Ctx,
    pub declaration: tenkai::package_migration::MigrationDeclaration,
}

pub(super) async fn migration_fixture(label: &str) -> MigrationFixture {
    let root = std::env::temp_dir().join(format!(
        "tenkai-migration-{label}-{}-{}",
        std::process::id(),
        tenkai::now_millis()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("tenkai.db");
    let mut ctx = tenkai::client::Ctx::embedded(&database).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    tenkai::plan::env_add(&mut ctx, "local", "fixture")
        .await
        .unwrap();
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
        tenkai::catalog::publish(
            &mut ctx,
            &dir.join("tenkai.toml"),
            &tenkai::catalog::PublishOptions {
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
        .get(&tenkai::ontology::release_id("pkg", "1.0.0"))
        .await
        .unwrap()
        .unwrap();
    let target = ctx
        .get(&tenkai::ontology::release_id("pkg", "1.1.0"))
        .await
        .unwrap()
        .unwrap();
    let pin_digest = |raw: &str| {
        if raw.starts_with("sha256:") {
            raw.to_string()
        } else {
            format!("sha256:{raw}")
        }
    };
    let declaration = tenkai::package_migration::MigrationDeclaration {
        version: 1,
        profile: tenkai::package_migration::MIGRATION_PROFILE.into(),
        source: tenkai::package_migration::PackagePin {
            product: "pkg".into(),
            version: "1.0.0".into(),
            digest: pin_digest(source.properties.get("digest").unwrap()),
        },
        target: tenkai::package_migration::PackagePin {
            product: "pkg".into(),
            version: "1.1.0".into(),
            digest: pin_digest(target.properties.get("digest").unwrap()),
        },
        compatibility: tenkai::package_migration::CompatibilityEvidence {
            version: 1,
            status: tenkai::package_migration::CompatibilityStatus::Compatible,
            evidence_digest: format!("sha256:{}", "e".repeat(64)),
        },
        checkpoints: vec![tenkai::package_migration::CheckpointDecl {
            id: "preflight".into(),
            class: tenkai::package_migration::CheckpointClass::Reversible,
            pre_admission: None,
        }],
    };
    MigrationFixture {
        root,
        database,
        ctx,
        declaration,
    }
}

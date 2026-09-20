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
) -> crate::management_lifecycle::PublishRequest {
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
    crate::dev_sign::sign_release(&keys, &manifest, &signature, &trust_roots).unwrap();
    crate::management_lifecycle::load_publish_request(&manifest, &signature, &trust_roots).unwrap()
}

pub(super) async fn catalog_router(root: &std::path::Path) -> (Router, ServerConfig) {
    let (app, config, _) = lifecycle_router(root).await;
    (app, config)
}

pub(super) async fn lifecycle_router(
    root: &std::path::Path,
) -> (Router, ServerConfig, Arc<crate::storage::SqliteStore>) {
    let database = root.join("tenkai.db");
    let mut ctx = crate::client::Ctx::embedded(&database).unwrap();
    crate::ontology::register(&mut ctx).await.unwrap();
    crate::plan::env_add(&mut ctx, "stage", "fixture")
        .await
        .unwrap();
    crate::plan::env_add(&mut ctx, "prod", "other")
        .await
        .unwrap();
    let reconciler =
        crate::reconciler::Reconciler::new(ctx, crate::reconciler::Config::default()).unwrap();
    let store = Arc::new(crate::storage::SqliteStore::open(&database).unwrap());
    for name in ["stage", "prod"] {
        store
            .put_environment(&crate::storage::EnvironmentRecord {
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
    crate::management_lifecycle::ApproveRequest,
    crate::management_lifecycle::ApplyRequest,
) {
    let dir = root.join(label);
    std::fs::create_dir_all(&dir).unwrap();
    let keys = dir.join("keys");
    let approval = dir.join("approval.json");
    let trust_roots = dir.join("trust.toml");
    crate::dev_sign::sign_plan_approval_for_digest(
        &keys,
        digest,
        environment,
        &approval,
        &trust_roots,
        3600,
    )
    .unwrap();
    (
        crate::management_lifecycle::load_approve_request(
            environment,
            expected_generation,
            &approval,
            &trust_roots,
        )
        .unwrap(),
        crate::management_lifecycle::load_apply_request(
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

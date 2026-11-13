//! Tenkai delivers `tenkai-server` (console included in the ui-enabled host)
//! as a signed software product through an environment runtime (#1080).
//!
//! The coordinating server refuses to apply that product itself. This test is
//! the second-hub path: a loopback server, the real `tenkai-runtime --executor
//! builtin`, a healthy release, then a bad release whose health probe fails
//! so the previous pin is restored, then recall of the bad build.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tenkai::auth_context::{
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, PrincipalIdentity,
    PrincipalKind,
};
use tenkai::catalog::PublishOptions;
use tenkai::client::Ctx;
use tenkai::plan::{self, PlanState};
use tenkai::reconciler::{Config as ReconcilerConfig, Reconciler};
use tenkai::server_self_upgrade::SELF_PRODUCT;

const AGENT: &str = env!("CARGO_BIN_EXE_tenkai-runtime");
const EXECUTOR_GUARD: &str = env!("CARGO_BIN_EXE_tenkai-executor-guard");

fn operator() -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        "self-delivery",
        PrincipalIdentity {
            id: "operator".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .unwrap()
}

/// Sign and publish `tenkai-server` `version`. Install writes `marks/<version>`;
/// `healthy: false` fails health after that write.
async fn publish(ctx: &mut Ctx, root: &Path, version: &str, marks: &Path, healthy: bool) {
    let dir = root.join("releases").join(version);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::write(dir.join("bin/version"), version).unwrap();
    let mark = marks.join(version);
    std::fs::write(
        dir.join("tenkai.toml"),
        format!(
            r#"
[product]
name = "{SELF_PRODUCT}"
version = "{version}"
description = "Tenkai control-plane host, including the web console"

[deploy]
install = "cat bin/version > {mark}"
uninstall = "rm -f {mark}"
health = "{health}"
inputs = ["bin"]
"#,
            mark = mark.display(),
            health = if healthy {
                format!("test -f {}", mark.display())
            } else {
                "false".into()
            },
        ),
    )
    .unwrap();
    let signature = dir.join("release.sig.json");
    let trust = dir.join("release-trust.toml");
    tenkai::dev_sign::sign_release(
        &root.join("keys"),
        &dir.join("tenkai.toml"),
        &signature,
        &trust,
    )
    .unwrap();
    tenkai::catalog::publish(
        ctx,
        &dir.join("tenkai.toml"),
        &PublishOptions {
            signature: Some(signature),
            trust_roots: Some(trust),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

fn install_trust(root: &Path, trust: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = root.join(format!("runtime-trust-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let installed = dir.join("release-trust.toml");
    std::fs::copy(trust, &installed).unwrap();
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o600)).unwrap();
    installed
}

fn poll(root: &Path, url: &str, trust: &Path) -> std::process::Output {
    std::process::Command::new(AGENT)
        .arg("--once")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TENKAI_SERVER_URL", url)
        .env("TENKAI_RUNTIME_ENVIRONMENT", "hub")
        .env("TENKAI_RUNTIME_EXECUTOR", "builtin")
        .env("TENKAI_RUNTIME_WORK_DIR", root.join("work"))
        .env("TENKAI_EXECUTOR_GUARD", EXECUTOR_GUARD)
        .env("TENKAI_RUNTIME_TOKEN", "runtime-secret")
        .env("TENKAI_RUNTIME_INVENTORY", "off")
        .env("TENKAI_RUNTIME_RELEASE_TRUST_ROOTS", trust)
        .output()
        .unwrap()
}

async fn finished(ctx: &mut Ctx, plan_id: &str) -> plan::Plan {
    plan::load(ctx, plan_id).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_upgrades_tenkai_server_and_restores_a_bad_build() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-self-delivery-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let marks = root.join("marks");
    std::fs::create_dir_all(&marks).unwrap();
    let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap());
    let reconciler = Arc::new(
        Reconciler::new(ctx.clone(), ReconcilerConfig::default())
            .unwrap()
            .with_runtime_environments(["hub".into()].into()),
    );
    let app = tenkai_http::router(
        tenkai_http::ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "hub".into())]),
        ),
        reconciler,
        store,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let actor = operator();
    plan::env_add(&mut ctx, "hub", "second hub").await.unwrap();
    publish(&mut ctx, &root, "1.0.0", &marks, true).await;
    publish(&mut ctx, &root, "1.1.0", &marks, false).await;
    let trust = install_trust(&root, &root.join("releases/1.0.0/release-trust.toml"));

    tenkai::catalog::promote(&mut ctx, &actor, &format!("{SELF_PRODUCT}@1.0.0"), "stable")
        .await
        .unwrap();
    plan::subscribe(&mut ctx, "hub", SELF_PRODUCT, "stable")
        .await
        .unwrap();
    let first = plan::create(&mut ctx, "hub").await.unwrap();
    let output = poll(&root, &url, &trust);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first = finished(&mut ctx, &first.id).await;
    assert_eq!(first.state, PlanState::Succeeded, "{}", first.status_detail);
    assert_eq!(
        std::fs::read_to_string(marks.join("1.0.0")).unwrap(),
        "1.0.0"
    );

    tenkai::catalog::promote(&mut ctx, &actor, &format!("{SELF_PRODUCT}@1.1.0"), "stable")
        .await
        .unwrap();
    let upgrade = plan::create(&mut ctx, "hub").await.unwrap();
    let output = poll(&root, &url, &trust);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let upgrade = finished(&mut ctx, &upgrade.id).await;
    assert_ne!(
        upgrade.state,
        PlanState::Succeeded,
        "a bad Tenkai build must not stay applied: {} / {stderr}",
        upgrade.status_detail
    );
    assert!(
        stderr.contains("restored"),
        "rollback through the plan path must restore 1.0.0: {} / {stderr}",
        upgrade.status_detail
    );
    assert_eq!(
        std::fs::read_to_string(marks.join("1.0.0")).unwrap(),
        "1.0.0"
    );
    assert!(
        !marks.join("1.1.0").exists(),
        "the bad build's install must not remain after restore"
    );
    let environment = ctx
        .get(&tenkai::ontology::env_id("hub"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        environment
            .properties
            .get(&format!("deployed.{SELF_PRODUCT}"))
            .map(String::as_str),
        Some("1.0.0"),
        "{environment:?}"
    );

    tenkai::catalog::recall(&mut ctx, &actor, &format!("{SELF_PRODUCT}@1.1.0"))
        .await
        .unwrap();
    let recalled = plan::create(&mut ctx, "hub").await.unwrap_err().to_string();
    assert!(
        recalled.contains("recalled"),
        "a recalled Tenkai build must not plan: {recalled}"
    );

    let _ = std::fs::remove_dir_all(root);
}

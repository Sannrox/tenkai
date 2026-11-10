//! An environment runtime in built-in mode (ADR 0048): a server on loopback,
//! the real `tenkai-runtime --executor builtin` applying a signed shell
//! release itself, and a runtime that does not trust the release's signer
//! refusing it before anything runs.

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

const AGENT: &str = env!("CARGO_BIN_EXE_tenkai-runtime");
const EXECUTOR_GUARD: &str = env!("CARGO_BIN_EXE_tenkai-executor-guard");

fn operator() -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        "builtin",
        PrincipalIdentity {
            id: "operator".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .unwrap()
}

/// Sign and publish `api` `version`, whose install, uninstall and health
/// commands work on its file in `marks`; `healthy: false` fails health.
/// Returns the release's trust-root file.
async fn publish(
    ctx: &mut Ctx,
    root: &Path,
    version: &str,
    marks: &Path,
    healthy: bool,
) -> PathBuf {
    let dir = root.join("releases").join(version);
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(dir.join("app/config"), version).unwrap();
    let mark = marks.join(version);
    std::fs::write(
        dir.join("tenkai.toml"),
        format!(
            r#"
[product]
name = "api"
version = "{version}"

[deploy]
install = "cat app/config > {mark}"
uninstall = "rm -f {mark}"
health = "{health}"
inputs = ["app"]
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
            trust_roots: Some(trust.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    trust
}

/// Install `trust` as the runtime's owner-only release trust roots.
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

/// One built-in poll trusting `trust`.
fn poll(root: &Path, url: &str, trust: Option<&Path>) -> std::process::Output {
    let mut command = std::process::Command::new(AGENT);
    command
        .arg("--once")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TENKAI_SERVER_URL", url)
        .env("TENKAI_RUNTIME_ENVIRONMENT", "prod")
        .env("TENKAI_RUNTIME_EXECUTOR", "builtin")
        .env("TENKAI_RUNTIME_WORK_DIR", root.join("work"))
        .env("TENKAI_EXECUTOR_GUARD", EXECUTOR_GUARD)
        .env("TENKAI_RUNTIME_TOKEN", "runtime-secret")
        .env("TENKAI_RUNTIME_INVENTORY", "off");
    if let Some(trust) = trust {
        command.env("TENKAI_RUNTIME_RELEASE_TRUST_ROOTS", trust);
    }
    command.output().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_builtin_runtime_applies_releases_it_trusts_and_refuses_others() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-builtin-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let marks = root.join("marks");
    std::fs::create_dir_all(&marks).unwrap();
    let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap());
    let reconciler = Arc::new(
        Reconciler::new(
            ctx.clone(),
            ReconcilerConfig {
                instance_id: "builtin".into(),
                ..ReconcilerConfig::default()
            },
        )
        .unwrap()
        .with_runtime_environments(["prod".into()].into()),
    );
    let app = tenkai_http::router(
        tenkai_http::ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        ),
        reconciler,
        store,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let actor = operator();
    plan::env_add(&mut ctx, "prod", "runtime host")
        .await
        .unwrap();
    let trust = publish(&mut ctx, &root, "1.0.0", &marks, true).await;
    publish(&mut ctx, &root, "1.1.0", &marks, false).await;

    // Built-in mode without local release trust does not start.
    let refused = poll(&root, &url, None);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("TENKAI_RUNTIME_RELEASE_TRUST_ROOTS")
    );

    // A runtime trusting a different signer refuses the release: the
    // server's own trust does not count here.
    let stranger = root.join("stranger");
    std::fs::create_dir_all(stranger.join("release/app")).unwrap();
    std::fs::write(stranger.join("release/tenkai.toml"), "[product]\nname = \"other\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"app\"]\n").unwrap();
    std::fs::write(stranger.join("release/app/x"), "x").unwrap();
    tenkai::dev_sign::sign_release(
        &stranger.join("keys"),
        &stranger.join("release/tenkai.toml"),
        &stranger.join("release.sig.json"),
        &stranger.join("release-trust.toml"),
    )
    .unwrap();
    tenkai::catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
        .await
        .unwrap();
    plan::subscribe(&mut ctx, "prod", "api", "stable")
        .await
        .unwrap();
    let untrusted = plan::create(&mut ctx, "prod").await.unwrap();
    let stranger_trust = install_trust(&root, &stranger.join("release-trust.toml"));
    let output = poll(&root, &url, Some(&stranger_trust));
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("trust roots"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let untrusted = plan::load(&mut ctx, &untrusted.id).await.unwrap();
    assert_eq!(
        untrusted.state,
        PlanState::Failed,
        "{}",
        untrusted.status_detail
    );
    assert!(!marks.join("1.0.0").exists(), "nothing ran");

    // Trusting the signer, the runtime places the release and runs its
    // install and health itself.
    let trusted = install_trust(&root, &trust);
    let applied = plan::create(&mut ctx, "prod").await.unwrap();
    let output = poll(&root, &url, Some(&trusted));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let applied = plan::load(&mut ctx, &applied.id).await.unwrap();
    assert_eq!(
        applied.state,
        PlanState::Succeeded,
        "{}",
        applied.status_detail
    );
    assert_eq!(
        std::fs::read_to_string(marks.join("1.0.0")).unwrap(),
        "1.0.0"
    );

    // Unsubscribing removes it: the runtime runs the release's uninstall.
    tenkai::environment::unsubscribe(
        &mut ctx,
        "prod",
        "api",
        Some("1.0.0"),
        &tenkai::software_executor::SoftwareExecutors::default(),
        |_| Ok(()),
    )
    .await
    .unwrap();
    let removed = plan::create(&mut ctx, "prod").await.unwrap();
    let output = poll(&root, &url, Some(&trusted));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let removed = plan::load(&mut ctx, &removed.id).await.unwrap();
    assert_eq!(
        removed.state,
        PlanState::Succeeded,
        "{}",
        removed.status_detail
    );
    assert!(!marks.join("1.0.0").exists(), "uninstall ran");
    let environment = ctx
        .get(&tenkai::ontology::env_id("prod"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(environment.properties.get("deployed.api"), None);

    let _ = std::fs::remove_dir_all(root);
}

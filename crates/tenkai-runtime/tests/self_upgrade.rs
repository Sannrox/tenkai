//! The runtime agent upgraded and rolled back by Tenkai like any component
//! (#685), with no route out: a server on loopback, the real `tenkai-runtime`
//! pulling its own signed releases, and this test playing the supervisor
//! that runs `prestart` and then `<home>/current/tenkai-runtime`, as the
//! example unit does. Each plan ends with the runtime's receipts.

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
const GUARD: &str = env!("CARGO_BIN_EXE_tenkai-runtime-guard");
const PRODUCT: &str = "tenkai-runtime";

fn operator() -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        "self-upgrade",
        PrincipalIdentity {
            id: "operator".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .unwrap()
}

fn executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A signed release of the agent whose workdir holds `binaries`.
async fn publish(ctx: &mut Ctx, root: &Path, version: &str, binaries: impl Fn(&Path)) {
    let dir = root.join("releases").join(version);
    std::fs::create_dir_all(&dir).unwrap();
    binaries(&dir);
    std::fs::write(
        dir.join("tenkai.toml"),
        format!(
            r#"
[product]
name = "{PRODUCT}"
version = "{version}"

[deploy]
install = "true"
inputs = ["tenkai-runtime", "tenkai-runtime-guard"]
"#
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

/// The agent's own build.
fn real(dir: &Path) {
    std::fs::copy(AGENT, dir.join("tenkai-runtime")).unwrap();
    std::fs::copy(GUARD, dir.join("tenkai-runtime-guard")).unwrap();
}

/// Another version: wrappers around that build, so their bytes differ.
fn wrapped(tag: &'static str) -> impl Fn(&Path) {
    move |dir: &Path| {
        executable(
            &dir.join("tenkai-runtime"),
            &format!("#!/bin/sh\n# {tag}\nexec {AGENT} \"$@\"\n"),
        );
        executable(
            &dir.join("tenkai-runtime-guard"),
            &format!("#!/bin/sh\n# {tag}\nexec {GUARD} \"$@\"\n"),
        );
    }
}

/// A version that passes its start and protocol checks but cannot run.
fn broken(dir: &Path) {
    let protocol = tenkai::runtime_self_upgrade::Protocol::this()
        .to_json()
        .unwrap();
    let body = format!(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo broken; exit 0; fi\nif [ \"$1\" = protocol ]; then echo '{protocol}'; exit 0; fi\nexit 1\n"
    );
    executable(&dir.join("tenkai-runtime"), &body);
    executable(
        &dir.join("tenkai-runtime-guard"),
        &format!("#!/bin/sh\nexec {GUARD} \"$@\"\n"),
    );
}

/// One poll of the agent the supervisor runs: `<home>/current/tenkai-runtime`.
fn poll(home: &Path, url: &str) -> std::process::ExitStatus {
    std::process::Command::new(home.join("current/tenkai-runtime"))
        .arg("--once")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TENKAI_SERVER_URL", url)
        .env("TENKAI_RUNTIME_ENVIRONMENT", "prod")
        .env("TENKAI_RUNTIME_EXECUTOR", "/usr/bin/true")
        .env("TENKAI_RUNTIME_TOKEN", "runtime-secret")
        .env("TENKAI_RUNTIME_HOME", home)
        .env("TENKAI_RUNTIME_INVENTORY", "off")
        .status()
        .unwrap()
}

fn current(home: &Path) -> String {
    std::fs::read_link(home.join("current"))
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

async fn finished(ctx: &mut Ctx, plan_id: &str) -> plan::Plan {
    plan::load(ctx, plan_id).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn tenkai_upgrades_rolls_back_and_reverts_its_runtime_agent() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-self-upgrade-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let home: PathBuf = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap());
    let reconciler = Arc::new(
        Reconciler::new(
            ctx.clone(),
            ReconcilerConfig {
                instance_id: "self-upgrade".into(),
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

    // The host: the agent installed once, under its home.
    let status = std::process::Command::new(AGENT)
        .args(["install", "--home"])
        .arg(&home)
        .status()
        .unwrap();
    assert!(status.success());
    let installed = current(&home);

    let actor = operator();
    plan::env_add(&mut ctx, "prod", "agent host").await.unwrap();
    publish(&mut ctx, &root, "1.0.0", real).await;
    publish(&mut ctx, &root, "1.1.0", wrapped("1.1.0")).await;
    publish(&mut ctx, &root, "1.2.0", broken).await;

    // 1.0.0 is what runs: recorded, nothing switched.
    tenkai::catalog::promote(&mut ctx, &actor, "tenkai-runtime@1.0.0", "stable")
        .await
        .unwrap();
    plan::subscribe(&mut ctx, "prod", PRODUCT, "stable")
        .await
        .unwrap();
    let first = plan::create(&mut ctx, "prod").await.unwrap();
    assert!(poll(&home, &url).success());
    let first = finished(&mut ctx, &first.id).await;
    assert_eq!(first.state, PlanState::Succeeded, "{}", first.status_detail);
    assert_eq!(current(&home), installed);

    // Upgrade: the old version switches and stops, the new one reports.
    tenkai::catalog::promote(&mut ctx, &actor, "tenkai-runtime@1.1.0", "stable")
        .await
        .unwrap();
    let upgrade = plan::create(&mut ctx, "prod").await.unwrap();
    assert!(poll(&home, &url).success());
    // Switched but not yet reported: the plan waits for the new version.
    assert_ne!(
        finished(&mut ctx, &upgrade.id).await.state,
        PlanState::Succeeded
    );
    let upgraded = current(&home);
    assert_ne!(upgraded, installed);
    assert!(poll(&home, &url).success());
    let upgrade = finished(&mut ctx, &upgrade.id).await;
    assert_eq!(
        upgrade.state,
        PlanState::Succeeded,
        "{}",
        upgrade.status_detail
    );

    // Rollback, like any component: back to 1.0.0 through the same switch.
    let step = plan::rollback_step(&mut ctx, "prod", PRODUCT)
        .await
        .unwrap();
    let rollback = plan::create_from_steps(&mut ctx, "prod", vec![step])
        .await
        .unwrap();
    assert!(poll(&home, &url).success());
    assert!(poll(&home, &url).success());
    let rollback = finished(&mut ctx, &rollback.id).await;
    assert_eq!(
        rollback.state,
        PlanState::Succeeded,
        "{}",
        rollback.status_detail
    );
    assert_eq!(current(&home), installed);

    // A version that cannot run: the supervisor's hook reverts it, the
    // previous version reports the failure, and it is not tried again.
    tenkai::catalog::promote(&mut ctx, &actor, "tenkai-runtime@1.2.0", "stable")
        .await
        .unwrap();
    let broken_plan = plan::create(&mut ctx, "prod").await.unwrap();
    assert!(poll(&home, &url).success());
    // The supervisor runs `prestart` from the previous version before every
    // start; after a few starts that never report, it reverts.
    let prestart = || {
        let status = std::process::Command::new(home.join("previous/tenkai-runtime"))
            .args(["prestart", "--home"])
            .arg(&home)
            .status()
            .unwrap();
        assert!(status.success());
    };
    for _ in 0..tenkai::runtime_self_upgrade::MAX_START_ATTEMPTS {
        prestart();
        assert!(!poll(&home, &url).success(), "the new version does not run");
    }
    prestart();
    assert_eq!(current(&home), installed);
    assert!(poll(&home, &url).success());
    let broken_plan = finished(&mut ctx, &broken_plan.id).await;
    assert_eq!(
        broken_plan.state,
        PlanState::Failed,
        "{}",
        broken_plan.status_detail
    );

    // Planned again, it fails without switching: it did not start here.
    let again = plan::create(&mut ctx, "prod").await.unwrap();
    assert!(poll(&home, &url).success());
    let again = finished(&mut ctx, &again.id).await;
    assert_eq!(again.state, PlanState::Failed, "{}", again.status_detail);
    assert_eq!(current(&home), installed);

    // Release content changed after it was signed is refused before anything
    // is staged or switched: by the server before delivery, or by the agent.
    publish(&mut ctx, &root, "1.3.0", wrapped("1.3.0")).await;
    tenkai::catalog::promote(&mut ctx, &actor, "tenkai-runtime@1.3.0", "stable")
        .await
        .unwrap();
    let tampered = plan::create(&mut ctx, "prod").await.unwrap();
    let snapshot = PathBuf::from(&tampered.steps.last().unwrap().workdir).join("tenkai-runtime");
    let mut bytes = std::fs::read(&snapshot).unwrap();
    bytes.extend_from_slice(b"# tampered\n");
    std::fs::write(&snapshot, bytes).unwrap();
    let staged_before = std::fs::read_dir(home.join("versions")).unwrap().count();
    assert!(poll(&home, &url).success());
    let tampered = finished(&mut ctx, &tampered.id).await;
    assert_ne!(
        tampered.state,
        PlanState::Succeeded,
        "{}",
        tampered.status_detail
    );
    assert_eq!(current(&home), installed);
    assert_eq!(
        std::fs::read_dir(home.join("versions")).unwrap().count(),
        staged_before,
        "nothing staged from tampered content"
    );

    let _ = std::fs::remove_dir_all(root);
}

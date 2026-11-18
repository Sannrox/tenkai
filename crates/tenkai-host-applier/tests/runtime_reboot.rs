//! An OS image plan through an environment runtime across a reboot (ADR
//! 0051 §3): a loopback server, a built-in runtime whose host units run this
//! crate's applier binary, and a fake on-host updater. The reboot is a new
//! boot id, a cleared run directory, a lapsed claim, and a fresh runtime
//! instance of the same enrolled runner.

mod common;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use common::Host;
use tenkai::auth_context::{AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind};
use tenkai::catalog::PublishOptions;
use tenkai::client::Ctx;
use tenkai::host_apply::state::AppliedState;
use tenkai::host_apply::{HostAction, HostApprovalPolicy, HostTrust};
use tenkai::host_executor::{HostExecutor, HostUnits, UnitFuture};
use tenkai::plan::{self, PlanState};
use tenkai::reconciler::{Config as ReconcilerConfig, Reconciler};
use tenkai::runtime_agent::{RuntimeClient, StepExecutor};
use tenkai_host_applier::config::OsImageConfig;
use tenkai_host_applier::store;

const OLD: char = 'a';
const NEW: char = 'b';

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

/// Host units that run the applier binary in the foreground, as systemd
/// would run its unit; a non-zero exit fails the start.
struct Units {
    host: Arc<Host>,
}

impl HostUnits for Units {
    fn start<'a>(&'a self, instance: &'a str) -> UnitFuture<'a> {
        let paths = &self.host.paths;
        let output = Command::new(env!("CARGO_BIN_EXE_tenkai-host-applier"))
            .arg("run")
            .arg(instance)
            .arg("--config-dir")
            .arg(&paths.config_dir)
            .arg("--state-dir")
            .arg(&paths.state_dir)
            .arg("--run-dir")
            .arg(&paths.run_dir)
            .arg("--boot-id")
            .arg(&paths.boot_id)
            .output();
        Box::pin(async move {
            let output = output?;
            anyhow::ensure!(
                output.status.success(),
                "applier exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        })
    }

    fn stop(&self, _instance: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn running(&self) -> UnitFuture<'_, Vec<String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct Rig {
    root: PathBuf,
    ctx: Ctx,
    url: String,
    host: Arc<Host>,
    updater: PathBuf,
}

impl Rig {
    async fn new() -> Self {
        let mut host = Host::new(Vec::new());
        let root = host.root.join("server");
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        tenkai::ontology::register(&mut ctx).await.unwrap();
        let store = Arc::new(tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap());
        let reconciler = Arc::new(
            Reconciler::new(ctx.clone(), ReconcilerConfig::default())
                .unwrap()
                .with_runtime_environments(["prod".into()].into()),
        );
        let app = tenkai_http::router(
            tenkai_http::ServerConfig::community(
                "management-secret",
                HashMap::from([
                    ("runtime-secret".into(), "prod".into()),
                    ("other-runner".into(), "prod".into()),
                ]),
            ),
            reconciler,
            store,
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        plan::env_add(&mut ctx, "prod", "image host").await.unwrap();

        // One set of dev keys signs the release and approves the plan, and
        // the applier trusts them as the server does.
        let release = root.join("os");
        std::fs::create_dir_all(&release).unwrap();
        let updater = host.root.join("updater.json");
        let count = |name: &str| format!("echo x >> {}", host.root.join(name).display());
        for (name, body) in [
            ("install.sh", count("staged")),
            (
                "confirm.sh",
                format!(
                    "{}\nprintf '{{\"booted_digest\":\"{}\",\"state\":\"confirmed\"}}' > {}",
                    count("confirmed"),
                    digest(NEW),
                    updater.display()
                ),
            ),
        ] {
            std::fs::write(release.join(name), format!("#!/bin/sh\n{body}\n")).unwrap();
        }
        let manifest = release.join("tenkai.toml");
        std::fs::write(
            &manifest,
            format!(
                "[product]\nname = \"os\"\nversion = \"2.0.0\"\n\n[deploy]\nexecutor = \"host\"\ninstall = \"sh ./install.sh\"\nconfirm = \"sh ./confirm.sh\"\ninputs = [\"install.sh\", \"confirm.sh\"]\n\n[os_image]\ndigest = \"{}\"\nboot_deadline_seconds = 900\n",
                digest(NEW)
            ),
        )
        .unwrap();
        let signature = release.join("signature.json");
        let release_roots = root.join("release-trust.toml");
        tenkai::dev_sign::sign_release(&root.join("keys"), &manifest, &signature, &release_roots)
            .unwrap();
        tenkai::catalog::publish(
            &mut ctx,
            &manifest,
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(release_roots.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let operator = AuthenticatedRequestContextBuilder::new(
            "runtime-reboot",
            PrincipalIdentity {
                id: "operator".into(),
                kind: PrincipalKind::Management,
            },
            "test-auth",
        )
        .build()
        .unwrap();
        tenkai::catalog::promote(&mut ctx, &operator, "os@2.0.0", "stable")
            .await
            .unwrap();
        plan::subscribe(&mut ctx, "prod", "os", "stable")
            .await
            .unwrap();
        // Signs nothing yet: writes the approver key and its trust roots.
        let approvers = root.join("approvers.toml");
        tenkai::dev_sign::sign_plan_approval_for_digest(
            &root.join("keys"),
            &format!("sha256:{}", "0".repeat(64)),
            "prod",
            &root.join("bootstrap-approval.json"),
            &approvers,
            3600,
        )
        .unwrap();

        let script = |name: &str, body: String| {
            let path = host.root.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.display().to_string()
        };
        host.config.os_image = Some(OsImageConfig {
            reader: vec![script("reader", format!("exec cat {}", updater.display()))],
            reboot: vec![script("reboot", count("rebooted"))],
        });
        host.fixture.trust = HostTrust {
            release_roots: tenkai::release_signing::TrustRoots::load(
                &release_roots,
                tenkai::release_signing::TrustRootKind::Release,
            )
            .unwrap(),
            policy: HostApprovalPolicy {
                version: 1,
                max_approval_ttl_ms: None,
                signers: tenkai::plan_approval::TrustRoots::load(
                    &approvers,
                    tenkai::plan_approval::TrustRootKind::PlanApproval,
                )
                .unwrap()
                .signers,
                quorum: Vec::new(),
            },
        };
        host.write_config();
        let rig = Self {
            root,
            ctx,
            url,
            host: Arc::new(host),
            updater,
        };
        rig.boots(OLD, "pending", "boot-1");
        rig
    }

    /// What the updater reports, and the current boot.
    fn boots(&self, image: char, state: &str, boot: &str) {
        std::fs::write(
            &self.updater,
            format!(
                r#"{{"booted_digest":"{}","state":"{state}"}}"#,
                digest(image)
            ),
        )
        .unwrap();
        std::fs::write(&self.host.paths.boot_id, format!("{boot}\n")).unwrap();
    }

    /// A fresh runtime instance with `token`, whose host units run the
    /// applier when `applier` is set.
    fn runtime(&self, token: &str, applier: bool) -> RuntimeClient {
        let mut executors = tenkai::software_executor::SoftwareExecutors::default();
        if applier {
            executors = executors.with_host(Arc::new(HostExecutor::new(
                self.host.config.spool_dir.clone(),
                self.host.paths.state_dir.clone(),
                Arc::new(Units {
                    host: self.host.clone(),
                }),
            )));
        }
        let config = tenkai::runtime_builtin::BuiltinConfig {
            executors,
            release_roots: tenkai::release_signing::TrustRoots::load(
                &self.root.join("release-trust.toml"),
                tenkai::release_signing::TrustRootKind::Release,
            )
            .unwrap(),
            cluster_config: None,
            secret_dir: None,
            sealing_dir: None,
            work_root: self
                .root
                .join(format!("work-{}", uuid::Uuid::new_v4().simple())),
        };
        RuntimeClient::new_with_options(
            self.url.clone(),
            "prod",
            token,
            StepExecutor::Builtin(Arc::new(config)),
            false,
        )
        .unwrap()
    }

    /// An approved plan that updates the image: stage, reboot, verify and
    /// confirm, each at the generation the one before it leaves.
    async fn image_plan(&mut self) -> plan::Plan {
        // No planner path makes the four image steps yet: they are made
        // from the bound host step of the release and planned as given.
        let base = plan::compute(&mut self.ctx, "prod")
            .await
            .unwrap()
            .into_iter()
            .find(|step| step.product == "os")
            .expect("a host step for the image release");
        let steps = [
            (HostAction::Stage, 0),
            (HostAction::Reboot, 1),
            (HostAction::Verify, 2),
            (HostAction::Confirm, 2),
        ]
        .into_iter()
        .map(|(action, expected_generation)| {
            let mut step = base.clone();
            step.host = Some(plan::HostStep {
                action,
                expected_generation,
            });
            step
        })
        .collect();
        let image = plan::create_from_steps(&mut self.ctx, "prod", steps)
            .await
            .unwrap();
        let approval = self.root.join(format!("approval-{}.json", image.id));
        let approvers = self.root.join("approvers.toml");
        tenkai::dev_sign::sign_plan_approval_for_digest(
            &self.root.join("keys"),
            &format!("sha256:{}", image.executable_digest().unwrap()),
            "prod",
            &approval,
            &approvers,
            3600,
        )
        .unwrap();
        let roots = tenkai::plan_approval::TrustRoots::load(
            &approvers,
            tenkai::plan_approval::TrustRootKind::PlanApproval,
        )
        .unwrap();
        for envelope in tenkai::plan_approval::load_envelopes(&approval).unwrap() {
            tenkai::plan_approval::collect_envelope(
                &mut self.ctx,
                &image,
                &envelope,
                &roots,
                tenkai::now_millis(),
            )
            .await
            .unwrap();
        }
        image
    }

    async fn state(&mut self, image: &plan::Plan) -> (PlanState, String) {
        let image = plan::load(&mut self.ctx, &image.id).await.unwrap();
        (image.state, image.status_detail)
    }

    /// How many times the updater's or the release's command `name` ran.
    fn ran(&self, name: &str) -> usize {
        std::fs::read_to_string(self.host.root.join(name))
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    /// Lapse every runtime claim, as the reboot outlasting the lease does.
    fn lapse_claims(&self) {
        rusqlite::Connection::open(self.root.join("tenkai.db"))
            .unwrap()
            .execute("UPDATE runtime_claims SET expires_at = 1", [])
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_image_plan_runs_each_step_once_across_the_reboot() {
    let mut rig = Rig::new().await;
    let before = rig.runtime("runtime-secret", true);
    before.report_host_records().await.unwrap();
    let image = rig.image_plan().await;

    // Stage, then reboot: the plan stays open while the host goes down.
    assert!(before.run_once().await.unwrap());
    assert_eq!((rig.ran("staged"), rig.ran("rebooted")), (1, 1));
    assert_eq!(rig.state(&image).await.0, PlanState::Computed);
    let awaiting = store::read_os_image_record(&rig.host.paths)
        .unwrap()
        .unwrap()
        .awaiting_boot
        .expect("the reboot awaits its boot");
    assert_eq!(awaiting.expected_digest, digest(NEW));

    // Polled again before the host is down, the plan continues at verify,
    // which the applier refuses in the same boot: nothing runs twice.
    assert!(before.run_once().await.unwrap());
    assert_eq!((rig.ran("staged"), rig.ran("rebooted")), (1, 1));
    assert_eq!(rig.state(&image).await.0, PlanState::Computed);

    // The host boots the new image, held until confirm; the old instance's
    // claim lapses.
    rig.boots(NEW, "pending", "boot-2");
    rig.host.reboot();
    rig.lapse_claims();

    // Another runner of the environment cannot verify this host's boot: it
    // does not take the plan.
    let other = rig.runtime("other-runner", true);
    assert!(!other.run_once().await.unwrap());
    assert_eq!(rig.state(&image).await.0, PlanState::Computed);
    // Nor does a runtime without the capability block it mid-reboot.
    let older = rig.runtime("other-runner", false);
    assert!(!older.run_once().await.unwrap());
    assert_eq!(rig.state(&image).await.0, PlanState::Computed);

    // A fresh instance of the same runner resumes at verify and confirms.
    let after = rig.runtime("runtime-secret", true);
    assert!(after.run_once().await.unwrap());
    let (state, detail) = rig.state(&image).await;
    assert_eq!(state, PlanState::Succeeded, "{detail}");
    assert_eq!(
        (rig.ran("staged"), rig.ran("rebooted"), rig.ran("confirmed")),
        (1, 1, 1)
    );
    let record = store::read_os_image_record(&rig.host.paths)
        .unwrap()
        .unwrap();
    assert!(record.awaiting_boot.is_none());
    assert!(
        matches!(&record.state, AppliedState::Applied { release } if release.version == "2.0.0"),
        "{:?}",
        record.state
    );
    assert!(!after.run_once().await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_without_the_os_image_capability_fails_the_plan_closed() {
    let mut rig = Rig::new().await;
    rig.runtime("runtime-secret", true)
        .report_host_records()
        .await
        .unwrap();
    let image = rig.image_plan().await;

    // No host applier: the runtime does not name os_image.
    assert!(
        !rig.runtime("runtime-secret", false)
            .run_once()
            .await
            .unwrap()
    );
    let (state, detail) = rig.state(&image).await;
    assert_eq!(state, PlanState::Blocked, "{detail}");
    assert!(detail.contains("os_image capability"), "{detail}");
    assert_eq!(rig.ran("staged"), 0);
}

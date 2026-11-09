//! Host releases on an environment runtime in built-in mode (ADR 0048 §2):
//! a server on loopback, a runtime that reports its host applier's
//! applied-state records, and host steps planned from those records and run
//! through the runtime's applier. The applier is emulated: it verifies and
//! admits each request exactly as the root side does, without systemd or
//! root.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use tenkai::auth_context::{AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind};
use tenkai::catalog::PublishOptions;
use tenkai::client::Ctx;
use tenkai::host_apply::state::{
    AppliedStateRecord, HostApplyOutcome, HostApplyRefused, REFUSED_FILE, REFUSED_SCHEMA,
    RESULT_FILE, instance_dir, record_path,
};
use tenkai::host_apply::{
    ARTIFACTS_DIR, HostApplyRequest, HostApprovalPolicy, HostTrust, REQUEST_FILE,
};
use tenkai::host_executor::{HostExecutor, HostUnits, UnitFuture};
use tenkai::plan::{self, PlanState};
use tenkai::reconciler::{Config as ReconcilerConfig, Reconciler};
use tenkai::runtime_agent::{RuntimeClient, StepExecutor};

/// Plays the root side for one environment: verifies the spooled request,
/// admits it against the applied-state record, "runs" the command, and
/// records the result. An instance with a result never runs again.
struct Applier {
    root: PathBuf,
    spool: PathBuf,
    state: PathBuf,
    /// Every command that ran, as `action product@version`.
    runs: Mutex<Vec<String>>,
    /// Every stopped unit, with how many commands had run by then.
    stops: Mutex<Vec<(String, usize)>>,
    running: Mutex<BTreeSet<String>>,
}

impl Applier {
    fn trust(&self) -> Result<HostTrust> {
        let approvers = tenkai::plan_approval::TrustRoots::load(&self.root.join("approvers.toml"))?;
        Ok(HostTrust {
            release_roots: tenkai::release_signing::TrustRoots::load(
                &self.root.join("release-trust.toml"),
            )?,
            policy: HostApprovalPolicy {
                version: 1,
                max_approval_ttl_ms: None,
                signers: approvers.signers,
                quorum: Vec::new(),
            },
        })
    }

    fn write(path: &Path, bytes: Vec<u8>) -> Result<()> {
        std::fs::create_dir_all(path.parent().context("record has a parent")?)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn run(&self, instance: &str) -> Result<()> {
        let result_path = instance_dir(&self.state, instance).join(RESULT_FILE);
        if result_path.exists() {
            return Ok(());
        }
        let now = tenkai::now_millis();
        let spooled = self.spool.join(instance);
        let request = HostApplyRequest::parse(&std::fs::read(spooled.join(REQUEST_FILE))?)?;
        let admitted = (|| {
            let verified =
                tenkai::host_apply::verify_request(&request, instance, &self.trust()?, now)?;
            verified.verify_artifacts(&spooled.join(ARTIFACTS_DIR))?;
            let path = record_path(&self.state, &verified.environment, &verified.product);
            let record = self.record_at(&path, &verified.environment, &verified.product)?;
            let (started, next) = record.admit(&verified, None, now)?;
            Self::write(&path, serde_json::to_vec(&next)?)?;
            anyhow::Ok((verified, path, started, next))
        })();
        let (verified, path, started, next) = match admitted {
            Ok(admitted) => admitted,
            Err(error) => {
                Self::write(
                    &instance_dir(&self.state, instance).join(REFUSED_FILE),
                    serde_json::to_vec(&HostApplyRefused {
                        schema: REFUSED_SCHEMA.into(),
                        instance: instance.into(),
                        reason: format!("{error:#}"),
                        refused_at: now,
                    })?,
                )?;
                anyhow::bail!("refused: {error:#}");
            }
        };
        self.runs.lock().unwrap().push(format!(
            "{} {}@{}",
            verified.action, verified.product, verified.release.version
        ));
        let result = started.result(
            HostApplyOutcome::Succeeded,
            Some(0),
            "emulated",
            tenkai::now_millis(),
        );
        Self::write(
            &path,
            serde_json::to_vec(&next.complete(&started, &result))?,
        )?;
        Self::write(&result_path, serde_json::to_vec(&result)?)?;
        Ok(())
    }

    fn record_at(
        &self,
        path: &Path,
        environment: &str,
        product: &str,
    ) -> Result<AppliedStateRecord> {
        Ok(match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(_) => AppliedStateRecord::empty(environment, product),
        })
    }

    fn record(&self) -> AppliedStateRecord {
        let path = record_path(&self.state, "prod", "cluster");
        self.record_at(&path, "prod", "cluster").unwrap()
    }
}

/// [`HostUnits`] over the emulated applier, as `systemctl` would drive it.
struct Units(Arc<Applier>);

impl HostUnits for Units {
    fn start<'a>(&'a self, instance: &'a str) -> UnitFuture<'a> {
        self.0.running.lock().unwrap().insert(instance.into());
        let ran = self.0.run(instance);
        self.0.running.lock().unwrap().remove(instance);
        Box::pin(async move { ran })
    }

    fn stop(&self, instance: &str) -> Result<()> {
        let ran = self.0.runs.lock().unwrap().len();
        self.0.stops.lock().unwrap().push((instance.into(), ran));
        self.0.running.lock().unwrap().remove(instance);
        Ok(())
    }

    fn running(&self) -> UnitFuture<'_, Vec<String>> {
        Box::pin(async { Ok(self.0.running.lock().unwrap().iter().cloned().collect()) })
    }
}

/// Sign, publish, promote, and subscribe `prod` to host release
/// `cluster@version`.
async fn publish(ctx: &mut Ctx, root: &Path, version: &str) {
    let dir = root.join(format!("cluster-{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("install.sh"), "echo install\n").unwrap();
    let manifest = dir.join("tenkai.toml");
    std::fs::write(
        &manifest,
        format!(
            "[product]\nname = \"cluster\"\nversion = \"{version}\"\n\n[deploy]\nexecutor = \"host\"\ninstall = \"sh install.sh\"\nuninstall = \"true\"\ninputs = [\"install.sh\"]\n"
        ),
    )
    .unwrap();
    let signature = dir.join("signature.json");
    let roots = root.join("release-trust.toml");
    tenkai::dev_sign::sign_release(&root.join("keys"), &manifest, &signature, &roots).unwrap();
    tenkai::catalog::publish(
        ctx,
        &manifest,
        &PublishOptions {
            signature: Some(signature),
            trust_roots: Some(roots),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let operator = AuthenticatedRequestContextBuilder::new(
        "builtin-host",
        PrincipalIdentity {
            id: "operator".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .unwrap();
    tenkai::catalog::promote(ctx, &operator, &format!("cluster@{version}"), "stable")
        .await
        .unwrap();
    plan::subscribe(ctx, "prod", "cluster", "stable")
        .await
        .unwrap();
}

/// Approve `plan` with the dev approver, as an operator would submit it.
async fn approve(ctx: &mut Ctx, root: &Path, plan: &plan::Plan) {
    let approval = root.join(format!("approval-{}.json", plan.id));
    let approvers = root.join("approvers.toml");
    tenkai::dev_sign::sign_plan_approval_for_digest(
        &root.join("keys"),
        &format!("sha256:{}", plan.executable_digest().unwrap()),
        "prod",
        &approval,
        &approvers,
        3600,
    )
    .unwrap();
    let roots = tenkai::plan_approval::TrustRoots::load(&approvers).unwrap();
    for envelope in tenkai::plan_approval::load_envelopes(&approval).unwrap() {
        tenkai::plan_approval::collect_envelope(ctx, plan, &envelope, &roots, tenkai::now_millis())
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn host_steps_are_planned_from_reported_records_and_run_once_through_the_runtime() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-builtin-host-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let spool = root.join("spool");
    std::fs::create_dir_all(&spool).unwrap();
    let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::ontology::register(&mut ctx).await.unwrap();
    let store = Arc::new(tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap());
    let reconciler = Arc::new(
        Reconciler::new(
            ctx.clone(),
            ReconcilerConfig {
                instance_id: "builtin-host".into(),
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

    plan::env_add(&mut ctx, "prod", "runtime host")
        .await
        .unwrap();
    publish(&mut ctx, &root, "1.0.0").await;

    // The server has no applier of its own and nothing is reported yet:
    // it plans no host step for the environment.
    let error = plan::create(&mut ctx, "prod").await.unwrap_err();
    assert!(
        format!("{error:#}").contains("no host applied-state records are reported for prod"),
        "{error:#}"
    );

    let applier = Arc::new(Applier {
        root: root.clone(),
        spool: spool.clone(),
        state: root.join("state"),
        runs: Mutex::default(),
        stops: Mutex::default(),
        running: Mutex::default(),
    });
    let host = HostExecutor::new(
        spool,
        applier.state.clone(),
        Arc::new(Units(applier.clone())),
    );
    let config = tenkai::runtime_builtin::BuiltinConfig {
        executors: tenkai::software_executor::SoftwareExecutors::default()
            .with_host(Arc::new(host)),
        release_roots: tenkai::release_signing::TrustRoots::load(&root.join("release-trust.toml"))
            .unwrap(),
        cluster_config: None,
        secret_dir: None,
        sealing_dir: None,
        work_root: root.join("work"),
    };
    let runtime = RuntimeClient::new_with_options(
        url,
        "prod",
        "runtime-secret",
        StepExecutor::Builtin(Arc::new(config)),
        false,
    )
    .unwrap();

    // Reported, the empty record plans a first install at generation 0.
    runtime.report_host_records().await.unwrap();
    let install = plan::create(&mut ctx, "prod").await.unwrap();
    let step = install.steps[0].clone();
    assert_eq!(step.host.unwrap().expected_generation, 0);
    approve(&mut ctx, &root, &install).await;

    // An earlier holder's unit is still running for prod: it is stopped
    // before anything of the claimed plan runs.
    let orphan = "e".repeat(64);
    let started = tenkai::host_apply::state::HostApplyStarted {
        schema: tenkai::host_apply::state::STARTED_SCHEMA.into(),
        instance: orphan.clone(),
        plan_id: "earlier".into(),
        plan_digest: format!("sha256:{}", "f".repeat(64)),
        step_id: "earlier:step:0".into(),
        environment: "prod".into(),
        product: "cluster".into(),
        action: tenkai::host_apply::HostAction::Install,
        release: tenkai::host_apply::HostRelease {
            version: "0.9.0".into(),
            manifest_digest: "f".repeat(64),
        },
        generation: 0,
        started_at: 1,
        cgroup: None,
    };
    Applier::write(
        &instance_dir(&applier.state, &orphan).join(tenkai::host_apply::state::STARTED_FILE),
        serde_json::to_vec(&started).unwrap(),
    )
    .unwrap();
    applier.running.lock().unwrap().insert(orphan.clone());

    assert!(runtime.run_once().await.unwrap());
    assert_eq!(*applier.stops.lock().unwrap(), [(orphan, 0)]);
    let install = plan::load(&mut ctx, &install.id).await.unwrap();
    assert_eq!(
        install.state,
        PlanState::Succeeded,
        "{}",
        install.status_detail
    );
    assert_eq!(*applier.runs.lock().unwrap(), ["install cluster@1.0.0"]);
    // Nothing more to do, and nothing runs twice.
    assert!(!runtime.run_once().await.unwrap());
    assert_eq!(applier.runs.lock().unwrap().len(), 1);

    // The runtime reported what the install left: the next plan expects it.
    publish(&mut ctx, &root, "1.1.0").await;
    let upgrade = plan::create(&mut ctx, "prod").await.unwrap();
    let step = upgrade.steps[0].clone();
    assert_eq!(step.host.unwrap().expected_generation, 1);
    assert_eq!(step.from.as_deref(), Some("1.0.0"));
    approve(&mut ctx, &root, &upgrade).await;

    // The record moves on the host before the step runs: the plan's record
    // is stale, and the applier's generation check refuses it.
    let moved = AppliedStateRecord {
        generation: 2,
        ..applier.record()
    };
    Applier::write(
        &record_path(&applier.state, "prod", "cluster"),
        serde_json::to_vec(&moved).unwrap(),
    )
    .unwrap();
    assert!(runtime.run_once().await.unwrap());
    let upgrade = plan::load(&mut ctx, &upgrade.id).await.unwrap();
    assert_eq!(
        upgrade.state,
        PlanState::Failed,
        "{}",
        upgrade.status_detail
    );
    assert_eq!(*applier.runs.lock().unwrap(), ["install cluster@1.0.0"]);
    let instance = tenkai::host_apply::instance_key(
        &format!("sha256:{}", upgrade.executable_digest().unwrap()),
        &step.id,
        tenkai::host_apply::HostAction::Install,
    );
    let refused: HostApplyRefused = serde_json::from_slice(
        &std::fs::read(instance_dir(&applier.state, &instance).join(REFUSED_FILE)).unwrap(),
    )
    .unwrap();
    assert!(
        refused.reason.contains("expects generation 1"),
        "{}",
        refused.reason
    );

    let _ = std::fs::remove_dir_all(root);
}

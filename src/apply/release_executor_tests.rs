//! Per-release software executor selection through apply (ADR 0041).

use std::sync::{Arc, Mutex};

use crate::client::Ctx;
use crate::software_executor::{
    SoftwareApplyRequest, SoftwareExecutor, SoftwareExecutorKind as Kind, SoftwareExecutors,
    SoftwareObserveStatus, TargetUnavailable,
};

use super::{ExecutionAuthorization, ExecutionOptions, Outcome, StepOutcomeStatus};

/// Records what it applied as `product@version` and every call it got,
/// refuses versions in `fail`, and reports its target missing while
/// `target_missing` is set.
#[derive(Default)]
struct Recorder {
    applied: Mutex<Vec<String>>,
    calls: Mutex<Vec<String>>,
    fail: Mutex<Vec<String>>,
    target_missing: Mutex<bool>,
}

impl Recorder {
    fn applied(&self) -> Vec<String> {
        self.applied.lock().unwrap().clone()
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn fail_version(&self, version: &str) {
        self.fail.lock().unwrap().push(version.into());
    }
}

impl SoftwareExecutor for Recorder {
    fn require_target(&self, _request: &SoftwareApplyRequest) -> Result<(), TargetUnavailable> {
        if *self.target_missing.lock().unwrap() {
            return Err(TargetUnavailable("no cluster config yet".into()));
        }
        Ok(())
    }

    fn apply(&self, request: &SoftwareApplyRequest) -> anyhow::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("apply {}@{}", request.product, request.version));
        if self.fail.lock().unwrap().contains(&request.version) {
            anyhow::bail!("recorder refused {}", request.version);
        }
        let key = format!("{}@{}", request.product, request.version);
        let mut applied = self.applied.lock().unwrap();
        applied.retain(|entry| !entry.starts_with(&format!("{}@", request.product)));
        applied.push(key);
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> anyhow::Result<()> {
        let key = format!("{}@{}", request.product, request.version);
        self.calls.lock().unwrap().push(format!("remove {key}"));
        self.applied.lock().unwrap().retain(|entry| entry != &key);
        Ok(())
    }

    fn observe(&self, _request: &SoftwareApplyRequest) -> anyhow::Result<SoftwareObserveStatus> {
        Ok(SoftwareObserveStatus::Present)
    }
}

struct Fixture {
    root: std::path::PathBuf,
    ctx: Ctx,
}

impl Fixture {
    async fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "tenkai-release-executor-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "executors")
            .await
            .unwrap();
        Self { root, ctx }
    }

    /// Publish and promote `product@version` with `deploy` lines appended to
    /// `[deploy]`, and subscribe the environment to it.
    async fn release(&mut self, product: &str, version: &str, deploy: &str) {
        let dir = self.root.join(format!("{product}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                "[product]\nname = \"{product}\"\nversion = \"{version}\"\n\n[deploy]\nuninstall = \"true\"\n{deploy}\n"
            ),
        )
        .unwrap();
        crate::catalog::publish(
            &mut self.ctx,
            &dir.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("release-executor");
        crate::catalog::promote(
            &mut self.ctx,
            &actor,
            &format!("{product}@{version}"),
            "stable",
        )
        .await
        .unwrap();
        crate::plan::subscribe(&mut self.ctx, "local", product, "stable")
            .await
            .unwrap();
    }

    async fn apply(&mut self, executors: &SoftwareExecutors) -> anyhow::Result<Vec<Outcome>> {
        let plan = crate::plan::create(&mut self.ctx, "local").await?;
        super::execute_with_options(
            &mut self.ctx,
            &plan.id,
            ExecutionOptions {
                skip_gates: true,
                emergency_reason: None,
                authorization: ExecutionAuthorization::LocalDevelopment {
                    reason: "per-release executor fixture",
                },
                software_executors: executors.clone(),
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
    }

    async fn deployed(&mut self, product: &str) -> Option<String> {
        crate::environment::environment(&mut self.ctx, "local")
            .await
            .unwrap()
            .properties
            .get(&format!("deployed.{product}"))
            .cloned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn statuses(outcomes: &[Outcome]) -> Vec<StepOutcomeStatus> {
    outcomes
        .iter()
        .map(|outcome| outcome.classified_status().unwrap())
        .collect()
}

#[tokio::test]
async fn one_apply_runs_each_release_with_its_own_executor() {
    let mut fixture = Fixture::new("mixed").await;
    let default = Arc::new(Recorder::default());
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(default.clone())
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("host-app", "1.0.0", "install = \"true\"")
        .await;
    // A Kubernetes release needs no placeholder deploy.install.
    fixture
        .release(
            "cluster-app",
            "1.0.0",
            "executor = \"kubernetes-inprocess\"",
        )
        .await;

    let outcomes = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Succeeded, StepOutcomeStatus::Succeeded],
        "{outcomes:?}"
    );
    assert_eq!(default.applied(), ["host-app@1.0.0"]);
    assert_eq!(in_process.applied(), ["cluster-app@1.0.0"]);
}

#[tokio::test]
async fn a_failed_upgrade_restores_through_the_previous_release_executor() {
    let mut fixture = Fixture::new("restore").await;
    let default = Arc::new(Recorder::default());
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(default.clone())
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("api", "1.0.0", "executor = \"kubernetes-inprocess\"")
        .await;
    fixture.apply(&executors).await.unwrap();
    // Same executor as `kubernetes-inprocess`, written differently.
    fixture
        .release("api", "2.0.0", "executor = \"KUBERNETES-INPROCESS\"")
        .await;
    in_process.fail_version("2.0.0");

    let outcomes = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::RolledBack],
        "{outcomes:?}"
    );
    assert!(
        outcomes[0].detail.contains("restored 1.0.0"),
        "{outcomes:?}"
    );
    let cause = outcomes[0].cause.as_ref().expect("original cause");
    assert_eq!(cause.phase, super::DeploymentCausePhase::Activate);
    assert_eq!(cause.kind, super::DeploymentCauseKind::CommandExited);
    let restore = outcomes[0].restore.as_ref().expect("restore result");
    assert_eq!(restore.phase, super::DeploymentCausePhase::Restore);
    assert_eq!(restore.kind, super::DeploymentCauseKind::Restored);
    assert_eq!(
        in_process.calls(),
        [
            "apply api@1.0.0",
            "apply api@2.0.0",
            "remove api@2.0.0",
            "apply api@1.0.0"
        ]
    );
    assert!(default.calls().is_empty());
    assert_eq!(fixture.deployed("api").await.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn an_unavailable_target_leaves_the_deployment_as_it_was_until_it_exists() {
    let mut fixture = Fixture::new("target").await;
    let in_process = Arc::new(Recorder::default());
    *in_process.target_missing.lock().unwrap() = true;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("app", "1.0.0", "executor = \"kubernetes-inprocess\"")
        .await;

    let error = fixture.apply(&executors).await.unwrap_err();

    assert!(
        error.downcast_ref::<TargetUnavailable>().is_some(),
        "{error:#}"
    );
    // Nothing ran, so nothing was cleaned up and nothing is unknown.
    assert!(in_process.calls().is_empty(), "{:?}", in_process.calls());
    let environment = crate::environment::environment(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert_eq!(environment.properties.get("deployed.app"), None);
    assert_eq!(environment.properties.get("deployment_health.app"), None);

    // Once the target exists, the next plan installs it.
    *in_process.target_missing.lock().unwrap() = false;
    let outcomes = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Succeeded],
        "{outcomes:?}"
    );
    assert_eq!(fixture.deployed("app").await.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn a_plan_that_changes_a_product_executor_is_refused() {
    let mut fixture = Fixture::new("change").await;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, Arc::new(Recorder::default()));
    fixture.release("api", "1.0.0", "install = \"true\"").await;
    fixture.apply(&executors).await.unwrap();
    fixture
        .release("api", "2.0.0", "executor = \"kubernetes-inprocess\"")
        .await;

    let error = fixture.apply(&executors).await.unwrap_err().to_string();

    assert!(
        error.contains("installed with the shell executor")
            && error.contains("resolves to kubernetes-inprocess"),
        "{error}"
    );
    assert_eq!(fixture.deployed("api").await.as_deref(), Some("1.0.0"));
}

/// A plan made by a process whose default differs (a rolling deploy) is
/// refused again when it is applied.
#[tokio::test]
async fn apply_refuses_an_executor_change_its_plan_did_not_see() {
    let mut fixture = Fixture::new("apply-fence").await;
    let default = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(default.clone());
    fixture.release("api", "1.0.0", "install = \"true\"").await;
    fixture.apply(&executors).await.unwrap();
    // Planning sees the shell default for both; this apply runs 1.0.0 on the
    // test default, so declaring shell changes the executor here.
    fixture
        .release("api", "2.0.0", "install = \"true\"\nexecutor = \"shell\"")
        .await;

    let error = fixture.apply(&executors).await.unwrap_err().to_string();

    assert!(
        error.contains("installed with the fake executor") && error.contains("resolves to shell"),
        "{error}"
    );
    assert_eq!(default.calls(), ["apply api@1.0.0"]);
    assert_eq!(fixture.deployed("api").await.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn a_declared_executor_that_is_not_installed_fails_closed() {
    for (declared, expected) in [
        ("docker", "\"docker\", and that executor is not installed"),
        ("host", "the host executor is not available"),
    ] {
        let mut fixture = Fixture::new(declared).await;
        let default = Arc::new(Recorder::default());
        let executors = SoftwareExecutors::with_default(default.clone());
        fixture
            .release(
                "api",
                "1.0.0",
                &format!("install = \"true\"\nexecutor = \"{declared}\""),
            )
            .await;

        let error = fixture.apply(&executors).await.unwrap_err().to_string();

        assert!(error.contains(expected), "{declared}: {error}");
        assert!(default.calls().is_empty(), "{declared} fell back");
        assert_eq!(fixture.deployed("api").await, None);
    }
}

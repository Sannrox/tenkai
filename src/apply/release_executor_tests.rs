//! Per-release software executor selection through apply (ADR 0041).

use std::sync::{Arc, Mutex};

use crate::client::Ctx;
use crate::software_executor::{
    SoftwareApplyRequest, SoftwareExecutor, SoftwareExecutorKind as Kind, SoftwareExecutors,
    SoftwareObserveStatus, TargetUnavailable,
};

use super::{ExecutionAuthorization, ExecutionOptions, Outcome, StepOutcomeStatus};

/// Records what it applied as `product@version` and every call it got,
/// refuses versions in `fail`, fails the next removal while `fail_remove`
/// is set, and reports its target missing while `target_missing` is set.
#[derive(Default)]
struct Recorder {
    applied: Mutex<Vec<String>>,
    calls: Mutex<Vec<String>>,
    fail: Mutex<Vec<String>>,
    fail_remove: Mutex<bool>,
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
        if std::mem::take(&mut *self.fail_remove.lock().unwrap()) {
            anyhow::bail!("recorder refused removing {key}");
        }
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
async fn the_coordinating_server_refuses_tenkai_server_and_releases_the_fence() {
    let mut fixture = Fixture::new("self-delivery").await;
    let default = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(default.clone());
    fixture
        .release(
            crate::server_self_upgrade::SELF_PRODUCT,
            "1.0.0",
            "install = \"true\"",
        )
        .await;

    let error = fixture.apply(&executors).await.unwrap_err().to_string();
    assert!(error.contains("coordinating server"), "{error}");
    assert!(
        error.contains(crate::server_self_upgrade::SELF_PRODUCT),
        "{error}"
    );
    assert!(
        default.applied().is_empty(),
        "the coordinating host must not run the product: {:?}",
        default.applied()
    );
    let lease = crate::apply::inspect_environment_lease(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert!(
        !lease.held,
        "refusing the coordinating apply must not leave the environment fenced: {lease:?}"
    );
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

async fn unsubscribe(
    fixture: &mut Fixture,
    product: &str,
    version: Option<&str>,
    executors: &SoftwareExecutors,
) -> anyhow::Result<String> {
    crate::environment::unsubscribe(
        &mut fixture.ctx,
        "local",
        product,
        version,
        executors,
        |_| Ok(()),
    )
    .await
}

#[tokio::test]
async fn an_unsubscribed_release_is_removed_through_its_own_executor() {
    let mut fixture = Fixture::new("remove").await;
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("app", "1.0.0", "executor = \"kubernetes-inprocess\"")
        .await;
    fixture.apply(&executors).await.unwrap();
    // The caller names what it removes; anything else changes nothing.
    let mismatch = unsubscribe(&mut fixture, "app", Some("2.0.0"), &executors)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        mismatch.contains("recorded at 1.0.0, not 2.0.0"),
        "{mismatch}"
    );
    let unnamed = unsubscribe(&mut fixture, "app", None, &executors)
        .await
        .unwrap_err()
        .to_string();
    assert!(unnamed.contains("--version 1.0.0"), "{unnamed}");
    assert!(
        crate::environment::subscribes(&mut fixture.ctx, "local", "app")
            .await
            .unwrap()
    );

    unsubscribe(&mut fixture, "app", Some("1.0.0"), &executors)
        .await
        .unwrap();
    let outcomes = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Succeeded],
        "{outcomes:?}"
    );
    assert_eq!(in_process.calls(), ["apply app@1.0.0", "remove app@1.0.0"]);
    assert_eq!(fixture.deployed("app").await, None);
    let next = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert!(next.steps.is_empty(), "{:?}", next.steps);
}

#[tokio::test]
async fn a_provider_is_unsubscribed_only_after_its_bound_dependents() {
    let mut fixture = Fixture::new("dependents").await;
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    for product in ["db", "web"] {
        fixture
            .release(product, "1.0.0", "executor = \"kubernetes-inprocess\"")
            .await;
    }
    fixture.apply(&executors).await.unwrap();
    let mut environment = crate::environment::environment(&mut fixture.ctx, "local")
        .await
        .unwrap();
    environment.properties.insert(
        crate::environment_bindings::binding_key("web", "database"),
        "db".into(),
    );
    fixture.ctx.put(environment).await.unwrap();

    let error = unsubscribe(&mut fixture, "db", Some("1.0.0"), &executors)
        .await
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("still has subscribed dependents: web"),
        "{error}"
    );
    unsubscribe(&mut fixture, "web", Some("1.0.0"), &executors)
        .await
        .unwrap();
    unsubscribe(&mut fixture, "db", Some("1.0.0"), &executors)
        .await
        .unwrap();
    // Declared contracts order the removals dependents first; a binding
    // alone only gates the unsubscribe.
    let plan = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();
    let mut removals: Vec<_> = plan
        .steps
        .iter()
        .map(|step| (step.action, step.product.as_str()))
        .collect();
    removals.sort_by_key(|(_, product)| *product);
    assert_eq!(
        removals,
        [
            (crate::plan::Action::Remove, "db"),
            (crate::plan::Action::Remove, "web")
        ]
    );
}

#[tokio::test]
async fn a_release_whose_provider_is_gone_can_still_be_removed() {
    let mut fixture = Fixture::new("provider-gone").await;
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    let pin = "a".repeat(40);
    fixture
        .release(
            "web",
            "1.0.0",
            &format!(
                "executor = \"kubernetes-inprocess\"\n[compatibility]\nversion = 1\nmax_evidence_age_ms = 60000\n[compatibility.components.web.pin]\nkind = \"revision\"\nvalue = \"{pin}\"\n[compatibility.components.web.requires]\ndatabase = \"1.0.0\""
            ),
        )
        .await;
    // Deployed while its provider ran; nothing provides database now.
    let mut environment = crate::environment::environment(&mut fixture.ctx, "local")
        .await
        .unwrap();
    environment
        .properties
        .insert("deployed.web".into(), "1.0.0".into());
    fixture.ctx.put(environment).await.unwrap();
    unsubscribe(&mut fixture, "web", Some("1.0.0"), &executors)
        .await
        .unwrap();

    let outcomes = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Succeeded],
        "{outcomes:?}"
    );
    assert_eq!(in_process.calls(), ["remove web@1.0.0"]);
}

#[tokio::test]
async fn a_failed_removal_is_retried_by_the_next_plan() {
    let mut fixture = Fixture::new("remove-retry").await;
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("app", "1.0.0", "executor = \"kubernetes-inprocess\"")
        .await;
    fixture.apply(&executors).await.unwrap();
    unsubscribe(&mut fixture, "app", Some("1.0.0"), &executors)
        .await
        .unwrap();
    *in_process.fail_remove.lock().unwrap() = true;
    let failed = fixture.apply(&executors).await.unwrap();
    assert_eq!(statuses(&failed), [StepOutcomeStatus::Failed], "{failed:?}");

    let retried = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&retried),
        [StepOutcomeStatus::Succeeded],
        "{retried:?}"
    );
    assert_eq!(
        in_process.calls(),
        ["apply app@1.0.0", "remove app@1.0.0", "remove app@1.0.0"]
    );
    let environment = crate::environment::environment(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert_eq!(environment.properties.get("deployed.app"), None);
    assert_eq!(
        environment.properties.get("deployment_health.app"),
        None,
        "{:?}",
        environment.properties
    );
    let next = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert!(next.steps.is_empty(), "{:?}", next.steps);
}

#[tokio::test]
async fn a_failed_first_install_is_removed_after_unsubscribing() {
    let mut fixture = Fixture::new("failed-install").await;
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("app", "1.0.0", "executor = \"kubernetes-inprocess\"")
        .await;
    in_process.fail_version("1.0.0");
    let failed = fixture.apply(&executors).await.unwrap();
    assert_eq!(statuses(&failed), [StepOutcomeStatus::Failed], "{failed:?}");
    assert_eq!(fixture.deployed("app").await, None);
    unsubscribe(&mut fixture, "app", Some("1.0.0"), &executors)
        .await
        .unwrap();
    let before = in_process.calls().len();

    let removed = fixture.apply(&executors).await.unwrap();

    assert_eq!(
        statuses(&removed),
        [StepOutcomeStatus::Succeeded],
        "{removed:?}"
    );
    assert_eq!(in_process.calls()[before..], ["remove app@1.0.0"]);
    let next = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert!(next.steps.is_empty(), "{:?}", next.steps);
}

#[tokio::test]
async fn a_failure_an_older_server_keyed_by_product_removes_no_other_instance() {
    let mut fixture = Fixture::new("legacy-key").await;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()));
    fixture.release("api", "1.0.0", "install = \"true\"").await;
    crate::environment::subscribe_instance(
        &mut fixture.ctx,
        "local",
        "api",
        "stable",
        Some("blue"),
    )
    .await
    .unwrap();
    unsubscribe(&mut fixture, "api", None, &executors)
        .await
        .unwrap();
    // The plan that failed installs instance blue; the record names the product.
    let failed = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();
    assert_eq!(failed.steps[0].instance_name(), "blue");
    let mut environment = crate::environment::environment(&mut fixture.ctx, "local")
        .await
        .unwrap();
    for (key, value) in [
        ("failed_target.api", "tenkai:release:api@1.0.0"),
        ("failed_target_plan.api", failed.id.as_str()),
    ] {
        environment.properties.insert(key.into(), value.into());
    }
    fixture.ctx.put(environment).await.unwrap();

    let plan = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();

    assert!(
        plan.steps
            .iter()
            .all(|step| step.action != crate::plan::Action::Remove),
        "{:?}",
        plan.steps
    );
}

#[tokio::test]
async fn a_runtime_gets_no_removal_package_once_the_instance_is_subscribed_again() {
    let mut fixture = Fixture::new("runtime-resubscribe").await;
    let in_process = Arc::new(Recorder::default());
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::KubernetesInProcess, in_process.clone());
    fixture
        .release("app", "1.0.0", "executor = \"kubernetes-inprocess\"")
        .await;
    fixture.apply(&executors).await.unwrap();
    unsubscribe(&mut fixture, "app", Some("1.0.0"), &executors)
        .await
        .unwrap();
    let removal = crate::plan::create(&mut fixture.ctx, "local")
        .await
        .unwrap();
    crate::plan::subscribe(&mut fixture.ctx, "local", "app", "stable")
        .await
        .unwrap();

    let error = super::runtime_release(&mut fixture.ctx, &removal, &removal.steps[0], false)
        .await
        .unwrap_err();

    assert!(
        error.downcast_ref::<super::ReleaseRefused>().is_some()
            && error.to_string().contains("subscribes to app again"),
        "{error:#}"
    );
}

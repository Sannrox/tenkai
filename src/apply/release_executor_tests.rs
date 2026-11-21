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

    /// Publish and promote a model_runtime release and subscribe to it.
    async fn model_release(&mut self, product: &str, version: &str, engine: &str) {
        let dir = self.root.join(format!("{product}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let digest = format!("sha256:{}", "ab".repeat(32));
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "{product}"
version = "{version}"
kind = "model_runtime"
description = "engine fixture"

[model]
source = "file:///tmp/weights.bin"
revision = "fixture"
format = "gguf"
quantization = "Q4_K_M"
artifact_digest = "{digest}"
license = "apache-2.0"

[runtime]
engine = "{engine}"
port = 8080
context_length = 8192

[requirements]
architecture = ["arm64"]
memory_gib = 16
accelerator = ["apple-metal"]

[health]
endpoint = "http://127.0.0.1:8080/v1/models"
smoke_prompt = "OK"
max_startup_seconds = 60
"#
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
        crate::model_release_evidence::record_passing_evaluation_for_release(
            &mut self.ctx,
            &format!("{product}@{version}"),
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
        crate::environment::set_environment_fact(&mut self.ctx, "local", "architecture", "arm64")
            .await
            .unwrap();
        crate::environment::set_environment_fact(
            &mut self.ctx,
            "local",
            "accelerator",
            "apple-metal",
        )
        .await
        .unwrap();
        crate::environment::set_environment_fact(&mut self.ctx, "local", "memory_gib", "32")
            .await
            .unwrap();
    }

    async fn apply(&mut self, executors: &SoftwareExecutors) -> anyhow::Result<Vec<Outcome>> {
        let plan = crate::plan::create_with(&mut self.ctx, "local", executors).await?;
        super::execute_with_options(
            &mut self.ctx,
            &plan.id,
            ExecutionOptions {
                rollback_hold: true,
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
        error.contains("installed with the fake executor")
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
        (
            "apple-container",
            "\"apple-container\", and that executor is not installed",
        ),
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
    let next = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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
    let plan = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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
    let next = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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
    let next = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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
    let failed = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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

    let plan = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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
    let removal = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
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

/// ADR 0051 §2: a host release carries `[os_image]` inside the content its
/// signature covers; publication refuses the section on any other executor.
#[tokio::test]
async fn publication_binds_os_image_to_host_releases_only() {
    let mut fixture = Fixture::new("os-image").await;
    let os_image = format!(
        "\n[os_image]\ndigest = \"sha256:{}\"\nboot_deadline_seconds = 900\n",
        "a".repeat(64)
    );
    let publish = |executor: &str, version: &str| {
        let dir = fixture.root.join(format!("os-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = format!(
            "[product]\nname = \"os\"\nversion = \"{version}\"\n\n[deploy]\nexecutor = \"{executor}\"\ninstall = \"true\"\nconfirm = \"true\"\n{os_image}"
        );
        std::fs::write(dir.join("tenkai.toml"), &raw).unwrap();
        (dir.join("tenkai.toml"), raw)
    };
    let options = crate::catalog::PublishOptions {
        allow_unsigned_development: true,
        ..Default::default()
    };

    let (host, raw) = publish("host", "1.0.0");
    crate::catalog::publish(&mut fixture.ctx, &host, &options)
        .await
        .unwrap();
    let release = fixture
        .ctx
        .get(&crate::ontology::release_id("os", "1.0.0"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(release.properties["manifest"], raw);
    assert_eq!(
        release.properties["digest"],
        crate::manifest::digest(&raw),
        "the signed digest covers [os_image]"
    );

    let (shell, _) = publish("shell", "2.0.0");
    let error = crate::catalog::publish(&mut fixture.ctx, &shell, &options)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}")
            .contains("[os_image] is only supported on releases with deploy.executor = \"host\""),
        "{error:#}"
    );
}

/// Executor sets a host would read from replica and runtime check-ins
/// (ADR 0057), set directly by the test.
#[derive(Default)]
struct CheckIns {
    replicas: Mutex<crate::execution_capabilities::ReplicaView>,
    runtimes: Mutex<Vec<(String, crate::execution_capabilities::ProcessExecutors)>>,
}

impl crate::execution_capabilities::ExecutionCapabilitySource for CheckIns {
    fn replicas(&self) -> crate::execution_capabilities::ReplicaView {
        self.replicas.lock().unwrap().clone()
    }

    fn runtimes(
        &self,
    ) -> anyhow::Result<Vec<(String, crate::execution_capabilities::ProcessExecutors)>> {
        Ok(self.runtimes.lock().unwrap().clone())
    }
}

fn checked_in(
    kind: crate::execution_capabilities::ProcessKind,
    id: &str,
    executors: Option<&str>,
    checked_in_at: i64,
) -> crate::execution_capabilities::ProcessExecutors {
    crate::execution_capabilities::ProcessExecutors {
        kind,
        id: id.into(),
        version: None,
        executors: executors.map(crate::execution_capabilities::parse_names),
        engines: None,
        checked_in_at,
    }
}

fn checked_in_engines(
    kind: crate::execution_capabilities::ProcessKind,
    id: &str,
    executors: Option<&str>,
    engines: Option<&str>,
    checked_in_at: i64,
) -> crate::execution_capabilities::ProcessExecutors {
    crate::execution_capabilities::ProcessExecutors {
        kind,
        id: id.into(),
        version: None,
        executors: executors.map(crate::execution_capabilities::parse_names),
        engines: engines.map(crate::execution_capabilities::parse_engine_names),
        checked_in_at,
    }
}

/// A fixture whose planner reads `check_ins`, with a `docker` release and
/// a docker adapter in this process.
async fn docker_fixture(name: &str, check_ins: &Arc<CheckIns>) -> (Fixture, SoftwareExecutors) {
    let mut fixture = Fixture::new(name).await;
    fixture.ctx = fixture
        .ctx
        .clone()
        .with_execution_capabilities(check_ins.clone());
    fixture
        .release("api", "1.0.0", "install = \"true\"\nexecutor = \"docker\"")
        .await;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()))
        .with_adapter(Kind::Docker, Arc::new(Recorder::default()));
    (fixture, executors)
}

#[tokio::test]
async fn a_plan_is_refused_until_every_replica_has_the_declared_executor() {
    use crate::execution_capabilities::{ProcessKind::Replica, ReplicaView};
    let check_ins = Arc::new(CheckIns::default());
    *check_ins.replicas.lock().unwrap() = ReplicaView {
        this: Some("leader".into()),
        leader: Some("leader".into()),
        replicas: vec![
            checked_in(Replica, "leader", Some("shell,docker"), 0),
            checked_in(Replica, "standby", Some("shell"), 0),
        ],
    };
    let (mut fixture, executors) = docker_fixture("replicas", &check_ins).await;

    // This process has docker; the standby that may take over does not.
    let error = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("tenkai:release:api@1.0.0")
            && error.contains("\"docker\"")
            && error.contains("not installed on standby that"),
        "{error}"
    );

    check_ins.replicas.lock().unwrap().replicas[1] =
        checked_in(Replica, "standby", Some("docker,shell"), 0);
    crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap();
}

/// A plan for a model release whose engine one replica lacks is refused
/// and names that replica; it is accepted once the replica checks in with
/// the engine.
#[tokio::test]
async fn a_plan_is_refused_until_every_replica_has_the_declared_engine() {
    use crate::execution_capabilities::{ProcessKind::Replica, ReplicaView};
    let check_ins = Arc::new(CheckIns::default());
    *check_ins.replicas.lock().unwrap() = ReplicaView {
        this: Some("leader".into()),
        leader: Some("leader".into()),
        replicas: vec![
            checked_in_engines(Replica, "leader", Some("shell"), Some("llama.cpp"), 0),
            checked_in_engines(Replica, "standby", Some("shell"), Some("mlx"), 0),
        ],
    };
    let mut fixture = Fixture::new("engines").await;
    fixture.ctx = fixture
        .ctx
        .clone()
        .with_execution_capabilities(check_ins.clone());
    fixture.model_release("qwen", "1.0.0", "llama.cpp").await;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()));

    let error = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("tenkai:release:qwen@1.0.0")
            && error.contains("\"llama.cpp\"")
            && error.contains("not configured on standby that"),
        "{error}"
    );

    check_ins.replicas.lock().unwrap().replicas[1] =
        checked_in_engines(Replica, "standby", Some("shell"), Some("llama.cpp,mlx"), 0);
    crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap();
}

/// A process that recorded no engines leaves the engine check to apply.
#[tokio::test]
async fn an_unrecorded_engine_set_leaves_the_check_to_apply() {
    use crate::execution_capabilities::{ProcessKind::Replica, ReplicaView};
    let check_ins = Arc::new(CheckIns::default());
    *check_ins.replicas.lock().unwrap() = ReplicaView {
        this: Some("new".into()),
        leader: Some("new".into()),
        replicas: vec![
            checked_in_engines(Replica, "new", Some("shell"), Some("llama.cpp"), 0),
            checked_in(Replica, "old", Some("shell"), 0),
        ],
    };
    let mut fixture = Fixture::new("old-engines").await;
    fixture.ctx = fixture
        .ctx
        .clone()
        .with_execution_capabilities(check_ins.clone());
    fixture.model_release("qwen", "1.0.0", "llama.cpp").await;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()));

    crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap();
}

/// A leader that recorded no set runs a version before ADR 0057, so
/// planning cannot tell and leaves the check to apply.
#[tokio::test]
async fn an_unrecorded_leader_leaves_the_executor_check_to_apply() {
    use crate::execution_capabilities::{ProcessKind::Replica, ReplicaView};
    let check_ins = Arc::new(CheckIns::default());
    *check_ins.replicas.lock().unwrap() = ReplicaView {
        this: Some("new".into()),
        leader: Some("old".into()),
        replicas: vec![checked_in(Replica, "new", Some("shell"), 0)],
    };
    let (mut fixture, executors) = docker_fixture("old-leader", &check_ins).await;

    crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap();
}

/// A runtime-run environment is checked against its runtime, not this
/// process; a runtime that has not checked in recently makes it unknown.
#[tokio::test]
async fn a_runtime_environment_is_checked_against_its_fresh_runtime() {
    use crate::execution_capabilities::ProcessKind::Runtime;
    let check_ins = Arc::new(CheckIns::default());
    let now = crate::now_millis();
    *check_ins.runtimes.lock().unwrap() = vec![(
        "local".into(),
        checked_in(Runtime, "runner/instance", Some("shell,helm"), now),
    )];
    let (mut fixture, executors) = docker_fixture("runtime", &check_ins).await;

    let error = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not installed on runner/instance"),
        "{error}"
    );

    check_ins.runtimes.lock().unwrap()[0].1.checked_in_at =
        now - crate::execution_capabilities::RUNTIME_CHECK_IN_WINDOW_MS - 1;
    crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap();
}

/// Without a host source, embedded planning refuses on its own set, as
/// apply in the same process would.
#[tokio::test]
async fn embedded_planning_refuses_an_executor_this_process_lacks() {
    let mut fixture = Fixture::new("embedded-plan").await;
    fixture
        .release("api", "1.0.0", "install = \"true\"\nexecutor = \"docker\"")
        .await;
    let executors = SoftwareExecutors::with_default(Arc::new(Recorder::default()));

    let error = crate::plan::create_with(&mut fixture.ctx, "local", &executors)
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("not installed on this process"), "{error}");
}

#[tokio::test]
async fn identical_adopt_records_deployed_without_applying_and_retries_once() {
    use crate::software_executor::FakeSoftwareExecutor;
    let mut fixture = Fixture::new("adopt").await;
    let executor = Arc::new(FakeSoftwareExecutor::new());
    let executors = SoftwareExecutors::with_default(executor.clone());
    fixture.release("api", "1.0.0", "install = \"true\"").await;

    let step = crate::plan::adopt_step_with(&mut fixture.ctx, "local", "api@1.0.0", &executors)
        .await
        .unwrap();
    assert_eq!(step.action, crate::plan::Action::Adopt);
    let plan = crate::plan::create_from_steps(&mut fixture.ctx, "local", vec![step.clone()])
        .await
        .unwrap();
    let outcomes = super::execute_with_options(
        &mut fixture.ctx,
        &plan.id,
        ExecutionOptions {
            rollback_hold: true,
            skip_gates: true,
            emergency_reason: None,
            authorization: ExecutionAuthorization::LocalDevelopment {
                reason: "adopt fixture",
            },
            software_executors: executors.clone(),
            model_runtime_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(statuses(&outcomes), [StepOutcomeStatus::Succeeded]);
    assert!(
        executor.applied_keys().is_empty(),
        "{:?}",
        executor.applied_keys()
    );
    assert_eq!(fixture.deployed("api").await.as_deref(), Some("1.0.0"));

    let retry = crate::plan::create_from_steps(&mut fixture.ctx, "local", vec![step])
        .await
        .unwrap();
    let retried = super::execute_with_options(
        &mut fixture.ctx,
        &retry.id,
        ExecutionOptions {
            rollback_hold: true,
            skip_gates: true,
            emergency_reason: None,
            authorization: ExecutionAuthorization::LocalDevelopment {
                reason: "adopt retry fixture",
            },
            software_executors: executors,
            model_runtime_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(statuses(&retried), [StepOutcomeStatus::Succeeded]);
    assert!(executor.applied_keys().is_empty());
    let history = crate::deployment_history::list_deployment_history(
        &mut fixture.ctx,
        "local",
        &crate::deployment_history::DeploymentHistoryQuery::default(),
    )
    .await
    .unwrap();
    assert_eq!(history.items.len(), 1, "{history:?}");
}

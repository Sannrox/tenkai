//! Digest-pinned image pre-pull for plans waiting on a maintenance window (#1093).
//!
//! Pre-pull is not a plan step and does not change serving workloads. It is
//! recorded as a durable preparation event. A failed or timed-out pull is
//! reported on the plan; apply still runs when the window opens.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::apply::EnvironmentLease;
use crate::client::Ctx;
use crate::ontology::{KIND_IMAGE_PRE_PULL, NS, image_pre_pull_id};
use crate::pb::sekai::Object;
use crate::plan::{self, Action, Plan, PlanState};
use crate::product_kind::ProductTarget;
use crate::software_executor::{
    PrePullImage, PrePullReport, SoftwareExecutors, request_from_parts, with_overlays,
};

pub const EVENT_SCHEMA: &str = "tenkai.image_pre_pull.v1";
pub const TIMEOUT_PROPERTY: &str = "pre_pull.timeout_ms";
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000;
const PRE_PULL_DETAIL_PREFIX: &str = "pre-pull ";

/// Durable preparation event for one plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrePullEvent {
    pub schema: String,
    pub plan_id: String,
    pub environment: String,
    pub status: PrePullStatus,
    #[serde(default)]
    pub images: Vec<PrePullImage>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrePullStatus {
    Running,
    Succeeded,
    Failed,
}

impl PrePullStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Environment pre-pull timeout, or the default when unset.
pub fn timeout_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Result<Duration> {
    let Some(raw) = properties.get(TIMEOUT_PROPERTY) else {
        return Ok(Duration::from_millis(DEFAULT_TIMEOUT_MS));
    };
    let ms: u64 = raw.parse().map_err(|_| {
        anyhow::anyhow!("{TIMEOUT_PROPERTY} must be a positive millisecond count, got {raw:?}")
    })?;
    if ms == 0 {
        bail!("{TIMEOUT_PROPERTY} must be a positive millisecond count");
    }
    Ok(Duration::from_millis(ms))
}

/// Store the per-environment pre-pull timeout.
pub async fn set_timeout_ms(ctx: &mut Ctx, env: &str, timeout_ms: u64) -> Result<String> {
    crate::ontology::validate_identifier("environment", env)?;
    if timeout_ms == 0 {
        bail!("{TIMEOUT_PROPERTY} must be a positive millisecond count");
    }
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    env_obj
        .properties
        .insert(TIMEOUT_PROPERTY.into(), timeout_ms.to_string());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("set {env} {TIMEOUT_PROPERTY} {timeout_ms}"))
}

/// Load the preparation event for `plan_id`, if one was recorded.
pub async fn load(ctx: &mut Ctx, plan_id: &str) -> Result<Option<PrePullEvent>> {
    let Some(object) = ctx.get(&image_pre_pull_id(plan_id)).await? else {
        return Ok(None);
    };
    decode_event(&object)
}

fn decode_event(object: &Object) -> Result<Option<PrePullEvent>> {
    let Some(raw) = object.properties.get("event") else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(raw)?))
}

/// Pull images for a maintenance-blocked plan. Pull failures are recorded on
/// the event and the plan; they do not fail this call unless storage does.
pub(crate) async fn prepare_waiting_plan(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    executors: &SoftwareExecutors,
) -> Result<()> {
    if plan.state != PlanState::Blocked || !plan.maintenance_blocked {
        return Ok(());
    }
    if let Some(existing) = load(ctx, &plan.id).await?
        && existing.status == PrePullStatus::Succeeded
    {
        return Ok(());
    }
    let env_obj = crate::environment::environment(ctx, &plan.environment).await?;
    let timeout = timeout_from_properties(&env_obj.properties)?;
    persist(
        ctx,
        &PrePullEvent {
            schema: EVENT_SCHEMA.into(),
            plan_id: plan.id.clone(),
            environment: plan.environment.clone(),
            status: PrePullStatus::Running,
            images: Vec::new(),
            updated_at_ms: crate::now_millis(),
        },
    )
    .await?;

    let mut images = Vec::new();
    let deadline = Instant::now() + timeout;
    for step in &plan.steps {
        if !matches!(
            step.action,
            Action::Install | Action::Upgrade | Action::Downgrade
        ) {
            continue;
        }
        let manifest = match crate::plan::stored_release_manifest(ctx, &step.release_id).await {
            Ok(manifest) => manifest,
            Err(error) => {
                images.push(PrePullImage {
                    image: step.release_id.clone(),
                    ok: false,
                    detail: format!("release unavailable: {error:#}"),
                });
                continue;
            }
        };
        if manifest.product.kind.policy().target() != ProductTarget::Software {
            continue;
        }
        let executor = match executors.resolve(manifest.deploy.executor) {
            Ok(Some(executor)) => executor,
            Ok(None) => continue,
            Err(error) => {
                images.push(PrePullImage {
                    image: step.release_id.clone(),
                    ok: false,
                    detail: format!("{error:#}"),
                });
                continue;
            }
        };
        let request = match step_request(&env_obj, plan, step, &manifest.product.version) {
            Ok(request) => request,
            Err(error) => {
                images.push(PrePullImage {
                    image: step.release_id.clone(),
                    ok: false,
                    detail: crate::software_executor::sanitize_diagnostic_text(&format!(
                        "{error:#}"
                    )),
                });
                continue;
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            images.push(PrePullImage {
                image: step.release_id.clone(),
                ok: false,
                detail: "timed out".into(),
            });
            continue;
        }
        let cleanup = executor.clone();
        let cleanup_request = request.clone();
        let _ = crate::apply::run_with_lease_renewal(ctx, lease, move |stop| {
            let _ = stop;
            cleanup.cleanup_pre_pull(&cleanup_request)
        })
        .await;
        let puller = executor.clone();
        let pull_request = request.clone();
        let pulled = crate::apply::run_with_lease_renewal(ctx, lease, move |stop| {
            puller.pre_pull(&pull_request, remaining, stop)
        })
        .await;
        match pulled {
            Ok(Ok(report)) => images.extend(report.images),
            Ok(Err(error)) => images.push(PrePullImage {
                image: step.release_id.clone(),
                ok: false,
                detail: crate::software_executor::sanitize_diagnostic_text(&format!("{error:#}")),
            }),
            Err(error) => images.push(PrePullImage {
                image: step.release_id.clone(),
                ok: false,
                detail: crate::software_executor::sanitize_diagnostic_text(&format!("{error:#}")),
            }),
        }
        let _ = crate::apply::run_with_lease_renewal(ctx, lease, {
            let cleanup = executor;
            move |stop| {
                let _ = stop;
                cleanup.cleanup_pre_pull(&request)
            }
        })
        .await;
    }

    let report = PrePullReport {
        images: images.clone(),
    };
    let status = if report.succeeded() {
        PrePullStatus::Succeeded
    } else {
        PrePullStatus::Failed
    };
    persist(
        ctx,
        &PrePullEvent {
            schema: EVENT_SCHEMA.into(),
            plan_id: plan.id.clone(),
            environment: plan.environment.clone(),
            status,
            images,
            updated_at_ms: crate::now_millis(),
        },
    )
    .await?;
    report_on_plan(ctx, lease, plan, &report).await
}

fn step_request(
    env_obj: &Object,
    plan: &Plan,
    step: &plan::Step,
    version: &str,
) -> Result<crate::software_executor::SoftwareApplyRequest> {
    let overlays = crate::environment::product_overlays(env_obj, &step.product)?;
    let mut request = with_overlays(
        request_from_parts(
            step.product.clone(),
            version,
            plan.environment.clone(),
            &step.workdir,
            step.release_id.clone(),
        ),
        overlays,
    );
    request.instance = step.instance.clone();
    request.cluster_config_path =
        crate::software_executor::cluster_config_path_from_properties(&env_obj.properties)?;
    request.secret_dir_path =
        crate::software_executor::secret_dir_from_properties(&env_obj.properties)?;
    request.apply_attempt = format!("pre-pull-{}", plan.id);
    Ok(request)
}

async fn persist(ctx: &mut Ctx, event: &PrePullEvent) -> Result<()> {
    let now = event.updated_at_ms;
    ctx.put(Object {
        id: image_pre_pull_id(&event.plan_id),
        kind: KIND_IMAGE_PRE_PULL.into(),
        name: format!("image pre-pull for {}", event.plan_id),
        namespace: NS.into(),
        external_id: String::new(),
        properties: std::collections::HashMap::from([
            ("plan_id".into(), event.plan_id.clone()),
            ("environment".into(), event.environment.clone()),
            ("status".into(), event.status.as_str().into()),
            ("event".into(), serde_json::to_string(event)?),
        ]),
        created: now,
        updated: now,
    })
    .await?;
    Ok(())
}

async fn report_on_plan(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    plan: &mut Plan,
    report: &PrePullReport,
) -> Result<()> {
    let window = plan
        .status_detail
        .lines()
        .next()
        .filter(|line| !line.starts_with(PRE_PULL_DETAIL_PREFIX))
        .unwrap_or(plan.status_detail.as_str())
        .to_string();
    let summary = if report.images.is_empty() {
        format!("{window}\n{PRE_PULL_DETAIL_PREFIX}succeeded")
    } else if let Some(failure) = report.failures().next() {
        format!(
            "{window}\n{PRE_PULL_DETAIL_PREFIX}failed for {}: {}",
            failure.image, failure.detail
        )
    } else {
        format!("{window}\n{PRE_PULL_DETAIL_PREFIX}succeeded")
    };
    let skip_gates = plan.gates_skipped.unwrap_or(false);
    plan::transition(
        ctx,
        plan,
        plan::Transition::maintenance_blocked(skip_gates, summary),
        plan::Persistence::Guarded {
            namespace: crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            key: &lease.environment,
            fencing_token: &lease.fencing_token,
            confirm_ambiguous: false,
            observations: &[],
        },
    )
    .await
}

/// Operator-safe pre-pull clause taken from plan status detail, if any.
pub fn operator_pre_pull_clause(status_detail: &str) -> Option<&str> {
    status_detail
        .lines()
        .find(|line| line.starts_with(PRE_PULL_DETAIL_PREFIX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{ExecutionAuthorization, ExecutionOptions};
    use crate::client::Ctx;
    use crate::software_executor::{
        SoftwareApplyRequest, SoftwareExecutor, SoftwareExecutorKind as Kind,
        SoftwareObserveStatus, TargetUnavailable,
    };
    use chrono::Datelike as _;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    struct Recorder {
        calls: Mutex<Vec<String>>,
        fail: Mutex<Option<String>>,
        leftovers: Mutex<Vec<String>>,
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                fail: Mutex::new(None),
                leftovers: Mutex::new(Vec::new()),
            })
        }

        fn fail_missing(self: &Arc<Self>, image: &str) {
            *self.fail.lock().unwrap() = Some(image.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn leftovers(&self) -> Vec<String> {
            self.leftovers.lock().unwrap().clone()
        }
    }

    impl SoftwareExecutor for Recorder {
        fn require_target(&self, _request: &SoftwareApplyRequest) -> Result<(), TargetUnavailable> {
            Ok(())
        }

        fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("apply {}", request.product));
            Ok(())
        }

        fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("remove {}", request.product));
            Ok(())
        }

        fn observe(&self, _request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
            Ok(SoftwareObserveStatus::Present)
        }

        fn pre_pull(
            &self,
            request: &SoftwareApplyRequest,
            _timeout: Duration,
            _stop: &AtomicBool,
        ) -> Result<PrePullReport> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("pre_pull {}", request.product));
            self.leftovers
                .lock()
                .unwrap()
                .push(format!("pod:{}", request.product));
            let image = format!(
                "registry.example/{}@sha256:{}",
                request.product,
                "ab".repeat(32)
            );
            if self.fail.lock().unwrap().as_deref() == Some(image.as_str())
                || self.fail.lock().unwrap().is_some()
            {
                return Ok(PrePullReport {
                    images: vec![PrePullImage {
                        image,
                        ok: false,
                        detail: "not found".into(),
                    }],
                });
            }
            Ok(PrePullReport {
                images: vec![PrePullImage {
                    image,
                    ok: true,
                    detail: String::new(),
                }],
            })
        }

        fn cleanup_pre_pull(&self, request: &SoftwareApplyRequest) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("cleanup {}", request.product));
            self.leftovers.lock().unwrap().clear();
            Ok(())
        }
    }

    struct Fixture {
        root: std::path::PathBuf,
        ctx: Ctx,
    }

    impl Fixture {
        async fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "tenkai-pre-pull-{name}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
            crate::ontology::register(&mut ctx).await.unwrap();
            crate::plan::env_add(&mut ctx, "local", "pre-pull")
                .await
                .unwrap();
            let today = chrono::Utc::now().weekday().number_from_monday();
            let other = if today == 1 { 2 } else { 1 };
            crate::maintenance::set(
                &mut ctx,
                "local",
                crate::maintenance::Window::new("off", "UTC", vec![other], "00:00", 1).unwrap(),
            )
            .await
            .unwrap();
            Self { root, ctx }
        }

        async fn release(&mut self, product: &str) {
            let dir = self.root.join(product);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("tenkai.toml"),
                format!(
                    "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\nkind = \"software\"\n\n[deploy]\ninstall = \"true\"\nuninstall = \"true\"\nexecutor = \"docker\"\n"
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
            let actor = crate::auth_context::test_management_context("pre-pull");
            crate::catalog::promote(&mut self.ctx, &actor, &format!("{product}@1.0.0"), "stable")
                .await
                .unwrap();
            crate::plan::subscribe(&mut self.ctx, "local", product, "stable")
                .await
                .unwrap();
        }

        async fn apply(
            &mut self,
            executors: &SoftwareExecutors,
        ) -> anyhow::Result<Vec<crate::apply::Outcome>> {
            let plan = crate::plan::create(&mut self.ctx, "local").await?;
            crate::apply::execute_with_options(
                &mut self.ctx,
                &plan.id,
                ExecutionOptions {
                    skip_gates: true,
                    emergency_reason: None,
                    authorization: ExecutionAuthorization::LocalDevelopment {
                        reason: "pre-pull fixture",
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
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// A plan waiting for a window pre-pulls its images and records success.
    #[tokio::test]
    async fn a_plan_waiting_for_a_window_pre_pulls_its_images_and_records_success() {
        let mut fixture = Fixture::new("success").await;
        let recorder = Recorder::new();
        let executors = SoftwareExecutors::with_default(recorder.clone())
            .with_adapter(Kind::Docker, recorder.clone());
        fixture.release("api").await;

        let error = fixture.apply(&executors).await.unwrap_err().to_string();
        assert!(error.contains("maintenance window"), "{error}");

        let plan = crate::plan::load_oldest_for_environment(
            &mut fixture.ctx,
            "local",
            &[PlanState::Blocked],
        )
        .await
        .unwrap()
        .expect("blocked plan");
        assert!(plan.maintenance_blocked);
        assert!(
            plan.status_detail.contains("pre-pull succeeded"),
            "{}",
            plan.status_detail
        );
        let summary = crate::environment::environment_plan_summary(plan.clone()).unwrap();
        assert!(
            summary
                .status_detail
                .contains("blocked outside the configured maintenance window")
                && summary.status_detail.contains("pre-pull succeeded"),
            "{}",
            summary.status_detail
        );
        let event = load(&mut fixture.ctx, &plan.id)
            .await
            .unwrap()
            .expect("preparation event");
        assert_eq!(event.status, PrePullStatus::Succeeded);
        assert!(event.images.iter().all(|image| image.ok), "{event:?}");
        assert!(
            recorder
                .calls()
                .iter()
                .any(|call| call.starts_with("pre_pull")),
            "{:?}",
            recorder.calls()
        );
        assert!(
            !recorder
                .calls()
                .iter()
                .any(|call| call.starts_with("apply")),
            "pre-pull must not apply: {:?}",
            recorder.calls()
        );
    }

    /// A missing image is reported on the plan before the window opens.
    #[tokio::test]
    async fn a_missing_image_is_reported_before_the_window_opens() {
        let mut fixture = Fixture::new("missing").await;
        let recorder = Recorder::new();
        recorder.fail_missing("any");
        let executors = SoftwareExecutors::with_default(recorder.clone())
            .with_adapter(Kind::Docker, recorder.clone());
        fixture.release("api").await;

        let error = fixture.apply(&executors).await.unwrap_err().to_string();
        assert!(error.contains("maintenance window"), "{error}");

        let plan = crate::plan::load_oldest_for_environment(
            &mut fixture.ctx,
            "local",
            &[PlanState::Blocked],
        )
        .await
        .unwrap()
        .expect("blocked plan");
        assert!(
            plan.status_detail.contains("pre-pull failed for")
                && plan.status_detail.contains("not found"),
            "{}",
            plan.status_detail
        );
        let event = load(&mut fixture.ctx, &plan.id)
            .await
            .unwrap()
            .expect("preparation event");
        assert_eq!(event.status, PrePullStatus::Failed);
        assert_eq!(plan.state, PlanState::Blocked);
        assert!(plan.maintenance_blocked);
    }

    /// Cleanup after a crash mid-pull drops leftover pull pods.
    #[tokio::test]
    async fn a_runtime_restart_during_pre_pull_does_not_leave_pull_pods_behind() {
        let mut fixture = Fixture::new("restart").await;
        let recorder = Recorder::new();
        let executors = SoftwareExecutors::with_default(recorder.clone())
            .with_adapter(Kind::Docker, recorder.clone());
        fixture.release("api").await;
        let _ = fixture.apply(&executors).await;
        assert!(
            recorder.leftovers().is_empty(),
            "cleanup must drop pull pods: {:?}",
            recorder.leftovers()
        );
        assert!(
            recorder
                .calls()
                .iter()
                .any(|call| call.starts_with("cleanup")),
            "{:?}",
            recorder.calls()
        );
    }
}

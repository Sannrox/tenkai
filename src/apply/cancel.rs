//! Fenced cancel of an in-flight apply, recorded on the environment hold.

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::delivery_hold::{self, DeliveryHold, HoldScope};

use super::execution_lease::{EnvironmentLease, inspect_environment_lease};

pub const DEFAULT_REASON: &str = "apply cancelled";
pub const ROLLBACK_REASON: &str = "rollback";
const SKIP_DETAIL: &str = "not executed after apply cancelled";
const CANCEL_DETAIL: &str = "deployment command interrupted: apply cancelled";

/// Result of asking a live apply to stop after the current step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelApplyReport {
    /// False when the requested generation was not the live apply.
    pub matched: bool,
    pub generation: Option<u64>,
    pub hold: Option<DeliveryHold>,
    pub message: String,
}

/// Record a cancel for the live apply-lease generation and hold the environment.
///
/// A cancel aimed at an older generation is a no-op. No live apply is an error.
pub async fn request(
    ctx: &mut Ctx,
    environment: &str,
    expected_generation: Option<u64>,
    reason: Option<&str>,
    actor: &str,
) -> Result<CancelApplyReport> {
    crate::ontology::validate_identifier("environment", environment)?;
    // Runtime-owned work has no catalog apply lease while it runs. Cancel names
    // the lease holder; the hold already withholds new pull-only work (#1061).
    let Some(lease) = ctx
        .get_lease(super::ENVIRONMENT_LEASE_NAMESPACE, environment)
        .await?
    else {
        bail!("environment {environment} has no apply in progress");
    };
    if lease.status != "active" {
        bail!("environment {environment} has no apply in progress");
    }
    let generation = lease.generation;
    if expected_generation.is_some_and(|expected| expected != generation) {
        return Ok(stale_cancel_report(generation, expected_generation));
    }
    let reason = reason.map(str::trim).filter(|reason| !reason.is_empty());
    let reason = reason.unwrap_or(DEFAULT_REASON);
    let Some(hold) = delivery_hold::set_cancel(
        ctx,
        &HoldScope::environment(environment),
        reason,
        actor,
        generation,
        &lease.fencing_token,
    )
    .await?
    else {
        let live = inspect_environment_lease(ctx, environment)
            .await?
            .generation
            .unwrap_or(generation);
        return Ok(stale_cancel_report(live, Some(generation)));
    };
    Ok(CancelApplyReport {
        matched: true,
        generation: Some(generation),
        hold: Some(hold),
        message: format!(
            "asked apply generation {generation} to stop after the current step and held {environment}"
        ),
    })
}

fn stale_cancel_report(
    live_generation: u64,
    expected_generation: Option<u64>,
) -> CancelApplyReport {
    CancelApplyReport {
        matched: false,
        generation: Some(live_generation),
        hold: None,
        message: format!(
            "cancel generation {} does not match live apply {live_generation}; nothing changed",
            expected_generation.unwrap_or(live_generation)
        ),
    }
}

/// Whether the live lease should skip remaining steps.
///
/// The marker lives on the hold. Clearing that hold is the operator resuming
/// delivery, including remaining steps of this apply.
pub(super) async fn matches_lease(ctx: &mut Ctx, lease: &EnvironmentLease) -> Result<bool> {
    Ok(delivery_hold::cancel_generation(ctx, &lease.environment).await? == Some(lease.generation))
}

pub(super) fn skip_detail() -> &'static str {
    SKIP_DETAIL
}

pub(super) fn plan_detail() -> &'static str {
    CANCEL_DETAIL
}

/// After a successful rollback-only apply, hold the environment.
///
/// Holds persist on the operational catalog (`delivery_hold::set`). Remote
/// catalogs already refuse hold writes; skip rather than fail the completed
/// rollback.
pub(crate) async fn hold_after_rollback(
    ctx: &mut Ctx,
    environment: &str,
    actor: &str,
    generation: u64,
    fencing_token: &str,
) -> Result<()> {
    if !ctx.is_embedded() {
        return Ok(());
    }
    delivery_hold::set_if_absent_fenced(
        ctx,
        environment,
        ROLLBACK_REASON,
        actor,
        generation,
        fencing_token,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::execution_lease::claim_environment;
    use crate::client::Ctx;

    async fn fixture(name: &str) -> (std::path::PathBuf, Ctx) {
        let root = std::env::temp_dir().join(format!(
            "tenkai-apply-cancel-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "cancel")
            .await
            .unwrap();
        (root, ctx)
    }

    #[tokio::test]
    async fn unknown_apply_is_refused() {
        let (root, mut ctx) = fixture("none").await;
        let err = request(&mut ctx, "local", None, None, "alice")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no apply in progress"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn older_generation_is_a_noop() {
        let (root, mut ctx) = fixture("stale").await;
        let lease = claim_environment(&mut ctx, "local", "plan-1")
            .await
            .unwrap();
        let report = request(
            &mut ctx,
            "local",
            Some(lease.generation.saturating_sub(1)),
            None,
            "alice",
        )
        .await
        .unwrap();
        assert!(!report.matched);
        assert!(
            delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
                .await
                .unwrap()
                .is_none()
        );
        crate::apply::release_environment(&mut ctx, &lease)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn matching_generation_holds_and_matches_the_lease() {
        let (root, mut ctx) = fixture("match").await;
        let lease = claim_environment(&mut ctx, "local", "plan-1")
            .await
            .unwrap();
        let report = request(
            &mut ctx,
            "local",
            Some(lease.generation),
            Some("stop"),
            "alice",
        )
        .await
        .unwrap();
        assert!(report.matched);
        assert_eq!(report.hold.as_ref().unwrap().reason, "stop");
        assert!(matches_lease(&mut ctx, &lease).await.unwrap());
        crate::apply::release_environment(&mut ctx, &lease)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn successful_rollback_sets_a_hold() {
        let (root, mut ctx) = fixture("rollback-hold").await;
        let lease = claim_environment(&mut ctx, "local", "plan-1")
            .await
            .unwrap();
        hold_after_rollback(
            &mut ctx,
            "local",
            "alice",
            lease.generation,
            &lease.fencing_token,
        )
        .await
        .unwrap();
        let hold = delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hold.reason, ROLLBACK_REASON);
        hold_after_rollback(
            &mut ctx,
            "local",
            "bob",
            lease.generation,
            &lease.fencing_token,
        )
        .await
        .unwrap();
        let still = delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still.actor, "alice");
        crate::apply::release_environment(&mut ctx, &lease)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rollback_hold_without_the_live_fence_is_a_noop() {
        let (root, mut ctx) = fixture("rollback-fence").await;
        hold_after_rollback(&mut ctx, "local", "alice", 1, "not-the-token")
            .await
            .unwrap();
        assert!(
            delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
                .await
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    struct CancelOnNth {
        db: std::path::PathBuf,
        applied: std::sync::Mutex<Vec<String>>,
        n: std::sync::Mutex<usize>,
        cancel_on: usize,
        then_fail: bool,
    }

    impl crate::software_executor::SoftwareExecutor for CancelOnNth {
        fn apply(
            &self,
            request: &crate::software_executor::SoftwareApplyRequest,
        ) -> anyhow::Result<()> {
            self.applied
                .lock()
                .unwrap()
                .push(format!("{}@{}", request.product, request.version));
            let mut n = self.n.lock().unwrap();
            *n += 1;
            let hit = *n == self.cancel_on;
            drop(n);
            if hit {
                tokio::runtime::Handle::current().block_on(async {
                    let mut ctx = Ctx::embedded(&self.db).unwrap();
                    super::request(&mut ctx, "local", None, Some("stop"), "alice")
                        .await
                        .unwrap();
                });
                if self.then_fail {
                    anyhow::bail!("crashed after cancel");
                }
            }
            Ok(())
        }

        fn remove(
            &self,
            _request: &crate::software_executor::SoftwareApplyRequest,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn observe(
            &self,
            _request: &crate::software_executor::SoftwareApplyRequest,
        ) -> anyhow::Result<crate::software_executor::SoftwareObserveStatus> {
            Ok(crate::software_executor::SoftwareObserveStatus::Present)
        }
    }

    async fn publish_three(ctx: &mut Ctx, root: &std::path::Path) {
        for product in ["alpha", "beta", "gamma"] {
            let dir = root.join(product);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("tenkai.toml"),
                format!(
                    "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n"
                ),
            )
            .unwrap();
            crate::catalog::publish(
                ctx,
                &dir.join("tenkai.toml"),
                &crate::catalog::PublishOptions {
                    allow_unsigned_development: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let actor = crate::auth_context::test_management_context("cancel-apply");
            crate::catalog::promote(ctx, &actor, &format!("{product}@1.0.0"), "stable")
                .await
                .unwrap();
            crate::plan::subscribe(ctx, "local", product, "stable")
                .await
                .unwrap();
        }
    }

    fn execute_options(
        executors: crate::software_executor::SoftwareExecutors,
    ) -> crate::apply::ExecutionOptions<'static> {
        crate::apply::ExecutionOptions {
            skip_gates: true,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                reason: "apply cancel fixture",
            },
            software_executors: executors,
            model_runtime_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
        }
    }

    #[tokio::test]
    async fn cancel_during_the_second_of_three_skips_the_rest() {
        let (root, mut ctx) = fixture("skip-rest").await;
        publish_three(&mut ctx, &root).await;
        let db = root.join("tenkai.db");
        let executor = std::sync::Arc::new(CancelOnNth {
            db,
            applied: std::sync::Mutex::new(Vec::new()),
            n: std::sync::Mutex::new(0),
            cancel_on: 2,
            then_fail: false,
        });
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 3, "{plan:?}");
        let outcomes = crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            execute_options(crate::software_executor::SoftwareExecutors::with_default(
                executor.clone(),
            )),
        )
        .await
        .unwrap();
        assert_eq!(outcomes.len(), 3, "{outcomes:?}");
        assert_eq!(outcomes[0].status, "succeeded");
        assert_eq!(outcomes[1].status, "succeeded");
        assert_eq!(outcomes[2].status, "failed");
        assert_eq!(outcomes[2].detail, SKIP_DETAIL);
        assert_eq!(executor.applied.lock().unwrap().len(), 2);
        let hold = delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hold.reason, "stop");
        assert!(
            !crate::apply::inspect_environment_lease(&mut ctx, "local")
                .await
                .unwrap()
                .held
        );
        let blocked = crate::plan::create(&mut ctx, "local").await.unwrap();
        let err = crate::apply::execute_with_options(
            &mut ctx,
            &blocked.id,
            execute_options(crate::software_executor::SoftwareExecutors::with_default(
                std::sync::Arc::new(CancelOnNth {
                    db: root.join("tenkai.db"),
                    applied: std::sync::Mutex::new(Vec::new()),
                    n: std::sync::Mutex::new(0),
                    cancel_on: 0,
                    then_fail: false,
                }),
            )),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("paused by delivery hold"), "{err}");
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert!(
            !env.properties
                .keys()
                .any(|key| key.starts_with("failed_target"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn crash_after_cancel_keeps_the_hold_and_does_not_run_later_steps() {
        let (root, mut ctx) = fixture("crash").await;
        publish_three(&mut ctx, &root).await;
        let executor = std::sync::Arc::new(CancelOnNth {
            db: root.join("tenkai.db"),
            applied: std::sync::Mutex::new(Vec::new()),
            n: std::sync::Mutex::new(0),
            cancel_on: 2,
            then_fail: true,
        });
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        let result = crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            execute_options(crate::software_executor::SoftwareExecutors::with_default(
                executor.clone(),
            )),
        )
        .await;
        match result {
            Ok(outcomes) => {
                assert!(
                    outcomes
                        .iter()
                        .all(|outcome| outcome.step.product != "gamma"
                            || outcome.status != "succeeded"),
                    "{outcomes:?}"
                );
            }
            Err(error) => {
                assert!(
                    error.to_string().contains("crashed after cancel"),
                    "{error:#}"
                );
            }
        }
        assert_eq!(executor.applied.lock().unwrap().len(), 2);
        assert!(
            delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
                .await
                .unwrap()
                .is_some()
        );
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(env.properties.get("deployed.gamma"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn successful_rollback_apply_holds_without_a_failed_target() {
        let (root, mut ctx) = fixture("rollback-apply").await;
        let dir = root.join("api");
        std::fs::create_dir_all(&dir).unwrap();
        for version in ["1.0.0", "2.0.0"] {
            std::fs::write(
                dir.join("tenkai.toml"),
                format!(
                    "[product]\nname = \"api\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\nuninstall = \"true\"\n"
                ),
            )
            .unwrap();
            crate::catalog::publish(
                &mut ctx,
                &dir.join("tenkai.toml"),
                &crate::catalog::PublishOptions {
                    allow_unsigned_development: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let actor = crate::auth_context::test_management_context("cancel-rollback");
            crate::catalog::promote(&mut ctx, &actor, &format!("api@{version}"), "stable")
                .await
                .unwrap();
            if version == "1.0.0" {
                crate::plan::subscribe(&mut ctx, "local", "api", "stable")
                    .await
                    .unwrap();
            }
            let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
            crate::apply::execute_with_options(
                &mut ctx,
                &plan.id,
                execute_options(crate::software_executor::SoftwareExecutors::with_default(
                    std::sync::Arc::new(CancelOnNth {
                        db: root.join("tenkai.db"),
                        applied: std::sync::Mutex::new(Vec::new()),
                        n: std::sync::Mutex::new(0),
                        cancel_on: 0,
                        then_fail: false,
                    }),
                )),
            )
            .await
            .unwrap();
        }
        let step = crate::plan::rollback_step(&mut ctx, "local", "api")
            .await
            .unwrap();
        let stored = crate::plan::create_from_steps(&mut ctx, "local", vec![step])
            .await
            .unwrap();
        let outcomes = crate::apply::execute_with_options(
            &mut ctx,
            &stored.id,
            execute_options(crate::software_executor::SoftwareExecutors::with_default(
                std::sync::Arc::new(CancelOnNth {
                    db: root.join("tenkai.db"),
                    applied: std::sync::Mutex::new(Vec::new()),
                    n: std::sync::Mutex::new(0),
                    cancel_on: 0,
                    then_fail: false,
                }),
            )),
        )
        .await
        .unwrap();
        assert!(
            outcomes.iter().all(|outcome| outcome.status == "succeeded"),
            "{outcomes:?}"
        );
        let hold = delivery_hold::get(&mut ctx, &HoldScope::environment("local"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hold.reason, ROLLBACK_REASON);
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert!(
            !env.properties
                .keys()
                .any(|key| key.starts_with("failed_target"))
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

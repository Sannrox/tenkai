//! External delivery adapters (#292 / ADR 0022).
//!
//! Adapters apply and observe bounded effects. Apply acknowledgement is never
//! success. Terminal evidence is admitted only as a Tenkai runtime completion.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::delivery_manifest;
use crate::environment;
use crate::plan::{self, Plan, PlanState};
use crate::reconcile_fence::{FenceAdmission, ReconcileTickFence};
use crate::runtime_delivery::{RuntimeCompletion, RuntimeStepReceipt};

const PROPERTY_CORRELATION: &str = "bridge.correlation";
const PROPERTY_RECOVERY: &str = "deployment_recovery";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeAck {
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeObservation {
    Pending,
    TimedOut,
    Completion(RuntimeCompletion),
}

pub trait DeliveryAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BTreeSet<String>;
    fn apply(&self, plan: &Plan) -> Result<BridgeAck>;
    fn observe(&self, plan: &Plan) -> Result<BridgeObservation>;
    fn rollback_fails(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeMode {
    Succeed,
    Timeout,
    HealthFail,
    RollbackFail,
}

#[derive(Debug)]
pub struct PollingAdapter {
    mode: FakeMode,
    applied: AtomicBool,
}

#[derive(Debug)]
pub struct CallbackAdapter {
    mode: FakeMode,
    applied: AtomicBool,
}

impl PollingAdapter {
    pub fn new(mode: FakeMode) -> Self {
        Self {
            mode,
            applied: AtomicBool::new(false),
        }
    }
}

impl CallbackAdapter {
    pub fn new(mode: FakeMode) -> Self {
        Self {
            mode,
            applied: AtomicBool::new(false),
        }
    }
}

impl DeliveryAdapter for PollingAdapter {
    fn name(&self) -> &'static str {
        "polling-fake"
    }
    fn capabilities(&self) -> BTreeSet<String> {
        ["plan.execute".into()].into_iter().collect()
    }
    fn apply(&self, plan: &Plan) -> Result<BridgeAck> {
        ensure_plan(plan)?;
        self.applied.store(true, Ordering::SeqCst);
        Ok(BridgeAck { accepted: true })
    }
    fn observe(&self, plan: &Plan) -> Result<BridgeObservation> {
        if !self.applied.load(Ordering::SeqCst) {
            bail!("observe before apply acknowledgement");
        }
        Ok(observation(self.mode, plan))
    }
    fn rollback_fails(&self) -> bool {
        matches!(self.mode, FakeMode::HealthFail | FakeMode::RollbackFail)
    }
}

impl DeliveryAdapter for CallbackAdapter {
    fn name(&self) -> &'static str {
        "callback-fake"
    }
    fn capabilities(&self) -> BTreeSet<String> {
        ["plan.execute".into()].into_iter().collect()
    }
    fn apply(&self, plan: &Plan) -> Result<BridgeAck> {
        ensure_plan(plan)?;
        self.applied.store(true, Ordering::SeqCst);
        Ok(BridgeAck { accepted: true })
    }
    fn observe(&self, plan: &Plan) -> Result<BridgeObservation> {
        if !self.applied.load(Ordering::SeqCst) {
            bail!("callback presented before apply acknowledgement");
        }
        Ok(observation(self.mode, plan))
    }
    fn rollback_fails(&self) -> bool {
        matches!(self.mode, FakeMode::HealthFail | FakeMode::RollbackFail)
    }
}

pub fn selected_delivery_adapter() -> Option<Arc<dyn DeliveryAdapter>> {
    match std::env::var("TENKAI_DELIVERY_ADAPTER") {
        Ok(value) if value.eq_ignore_ascii_case("polling-fake") => {
            Some(Arc::new(PollingAdapter::new(FakeMode::Succeed)))
        }
        Ok(value) if value.eq_ignore_ascii_case("polling-timeout") => {
            Some(Arc::new(PollingAdapter::new(FakeMode::Timeout)))
        }
        Ok(value) if value.eq_ignore_ascii_case("callback-fake") => {
            Some(Arc::new(CallbackAdapter::new(FakeMode::Succeed)))
        }
        _ => None,
    }
}

#[derive(Clone)]
pub struct BridgeExecution<'a> {
    pub expected_environment: &'a str,
    pub approval: Option<(&'a Path, &'a Path)>,
    pub skip_gates: bool,
    pub now: i64,
    pub fence: Option<Arc<dyn ReconcileTickFence>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeReport {
    pub state: PlanState,
    pub receipts: Vec<RuntimeStepReceipt>,
    pub recovery_required: bool,
    pub rollback_triggered: bool,
    pub detail: String,
    pub correlation: String,
}

pub async fn execute_bridged_plan(
    ctx: &mut Ctx,
    adapter: &dyn DeliveryAdapter,
    plan: &Plan,
    options: BridgeExecution<'_>,
) -> Result<BridgeReport> {
    admit_before_delegation(ctx, adapter, plan, &options).await?;
    let correlation = persist_correlation(ctx, adapter, plan).await?;
    if plan.state == PlanState::Succeeded {
        return Ok(BridgeReport {
            state: PlanState::Succeeded,
            receipts: existing_success_receipts(plan),
            recovery_required: false,
            rollback_triggered: false,
            detail: "idempotent replay of accepted bridge receipts".into(),
            correlation,
        });
    }
    let before = plan::load(ctx, &plan.id).await?;
    let ack = adapter.apply(plan)?;
    if !ack.accepted {
        bail!("adapter refused apply for {}", plan.id);
    }
    let after_ack = plan::load(ctx, &plan.id).await?;
    if after_ack.state != before.state {
        bail!("apply acknowledgement must not complete the plan");
    }
    match adapter.observe(plan)? {
        BridgeObservation::Pending | BridgeObservation::TimedOut => Ok(BridgeReport {
            state: after_ack.state,
            receipts: Vec::new(),
            recovery_required: false,
            rollback_triggered: false,
            detail: "adapter observation is non-terminal".into(),
            correlation,
        }),
        BridgeObservation::Completion(completion) => {
            if !completion.succeeded {
                complete_under_optional_lease(ctx, &plan.environment, &completion).await?;
                let (rollback_triggered, recovery_required, detail) =
                    rollback_after_health_failure(ctx, adapter, plan).await?;
                return Ok(BridgeReport {
                    state: plan::load(ctx, &plan.id).await?.state,
                    receipts: completion.receipts.clone(),
                    recovery_required,
                    rollback_triggered,
                    detail,
                    correlation,
                });
            }
            complete_under_optional_lease(ctx, &plan.environment, &completion).await?;
            Ok(BridgeReport {
                state: plan::load(ctx, &plan.id).await?.state,
                receipts: completion.receipts.clone(),
                recovery_required: false,
                rollback_triggered: false,
                detail: "adapter observed success".into(),
                correlation,
            })
        }
    }
}

async fn admit_before_delegation(
    ctx: &mut Ctx,
    adapter: &dyn DeliveryAdapter,
    plan: &Plan,
    options: &BridgeExecution<'_>,
) -> Result<()> {
    if plan.environment != options.expected_environment {
        bail!(
            "foreign environment: plan belongs to {}, not {}",
            plan.environment,
            options.expected_environment
        );
    }
    delivery_manifest::admit_required_capabilities(
        &["plan.execute".into()],
        &adapter.capabilities().into_iter().collect::<Vec<_>>(),
    )?;
    if let Some((approval, trust_roots)) = options.approval {
        delivery_manifest::admit_signed_plan(plan, approval, trust_roots, options.now)?;
        let apply_already_admitted_gates =
            crate::apply::environment_lease_status(ctx, &plan.environment)
                .await?
                .is_some();
        if !options.skip_gates && !apply_already_admitted_gates {
            for step in &plan.steps {
                let gate = ctx
                    .evaluation_gate_evidence(crate::pb::chisei::GetEvaluationGateEvidenceRequest {
                        suite_id: format!("required-gate:{}", step.product),
                        release_digest: step.release_digest.clone(),
                        artifact_digest: step.artifact_digest.clone(),
                        max_timestamp_ms: options.now.saturating_add(60_000),
                    })
                    .await;
                if let Err(error) = gate {
                    let detail = error.to_string();
                    if detail.contains("no governance provider") {
                        bail!("required gate evidence is unavailable: {detail}");
                    }
                    bail!("required gate evidence failed: {detail}");
                }
            }
        }
    }
    for step in &plan.steps {
        if let Some(release) = ctx.get(&step.release_id).await?
            && release
                .properties
                .get("recalled_at")
                .is_some_and(|value| !value.is_empty())
        {
            bail!("recalled release {} cannot be delegated", step.release_id);
        }
    }
    if let Some(fence) = &options.fence {
        match fence.try_begin(&plan.environment, "delivery-bridge", options.now, 60_000)? {
            FenceAdmission::Started { .. } => {}
            other => bail!("stale fencing generation rejected late callback: {other:?}"),
        }
    }
    Ok(())
}

async fn persist_correlation(
    ctx: &mut Ctx,
    adapter: &dyn DeliveryAdapter,
    plan: &Plan,
) -> Result<String> {
    let correlation = format!("{}:{}:1", plan.id, adapter.name());
    let mut object = environment::environment(ctx, &plan.environment).await?;
    object
        .properties
        .insert(PROPERTY_CORRELATION.into(), correlation.clone());
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(correlation)
}

async fn rollback_after_health_failure(
    ctx: &mut Ctx,
    adapter: &dyn DeliveryAdapter,
    plan: &Plan,
) -> Result<(bool, bool, String)> {
    let mut rollback_triggered = false;
    for step in &plan.steps {
        let Some(previous) = step.from.as_deref() else {
            record_recovery_required(ctx, &plan.environment, &step.product).await?;
            return Ok((
                false,
                true,
                "health failure with no previous release is recovery-required".into(),
            ));
        };
        let mut object = environment::environment(ctx, &plan.environment).await?;
        object
            .properties
            .insert(format!("deployed.{}", step.product), step.to.clone());
        object
            .properties
            .insert(format!("deployed_prev.{}", step.product), previous.into());
        object.updated = crate::now_millis();
        ctx.put(object).await?;
        let rollback = plan::rollback_step(ctx, &plan.environment, &step.product).await?;
        rollback_triggered = true;
        if adapter.rollback_fails() {
            record_recovery_required(ctx, &plan.environment, &step.product).await?;
            return Ok((
                true,
                true,
                format!(
                    "Tenkai rollback plan {} failed on the adapter; recovery-required",
                    rollback.id
                ),
            ));
        }
        let _ = rollback;
    }
    Ok((
        rollback_triggered,
        false,
        "health failure triggered the Tenkai rollback plan".into(),
    ))
}

async fn record_recovery_required(ctx: &mut Ctx, environment: &str, product: &str) -> Result<()> {
    let mut object = environment::environment(ctx, environment).await?;
    object.properties.insert(
        format!("{PROPERTY_RECOVERY}.{product}"),
        "recovery_required".into(),
    );
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(())
}

async fn complete_under_optional_lease(
    ctx: &mut Ctx,
    environment: &str,
    completion: &RuntimeCompletion,
) -> Result<()> {
    if crate::apply::environment_lease_status(ctx, environment)
        .await?
        .is_some()
    {
        let mut stored = plan::load(ctx, &completion.plan_id).await?;
        if stored.state == PlanState::Computed {
            plan::transition(
                ctx,
                &mut stored,
                plan::Transition::new(PlanState::Running, "bridged adapter claimed the plan"),
                plan::Persistence::Standard,
            )
            .await?;
        }
        if completion.succeeded {
            for step in &stored.steps {
                let mut object = environment::environment(ctx, environment).await?;
                object
                    .properties
                    .insert(format!("deployed.{}", step.product), step.to.clone());
                object.properties.insert(
                    format!("deployment_health.{}", step.product),
                    "healthy".into(),
                );
                object.updated = crate::now_millis();
                ctx.put(object).await?;
            }
        }
        let terminal = if completion.succeeded {
            PlanState::Succeeded
        } else {
            PlanState::Failed
        };
        if !matches!(stored.state, PlanState::Succeeded | PlanState::Failed) {
            plan::transition(
                ctx,
                &mut stored,
                plan::Transition::new(terminal, completion.detail.clone()),
                plan::Persistence::Standard,
            )
            .await?;
        }
        return Ok(());
    }
    crate::delivery_manifest::admit_runtime_completion(ctx, environment, completion).await
}

fn existing_success_receipts(plan: &Plan) -> Vec<RuntimeStepReceipt> {
    plan.steps
        .iter()
        .map(|step| RuntimeStepReceipt {
            step_id: step.id.clone(),
            succeeded: true,
            detail: "idempotent replay".into(),
        })
        .collect()
}

fn ensure_plan(plan: &Plan) -> Result<()> {
    if plan.environment.trim().is_empty() || plan.id.trim().is_empty() || plan.steps.is_empty() {
        bail!("adapter request is missing environment, plan, or steps");
    }
    Ok(())
}

fn observation(mode: FakeMode, plan: &Plan) -> BridgeObservation {
    match mode {
        FakeMode::Timeout => BridgeObservation::TimedOut,
        FakeMode::Succeed => BridgeObservation::Completion(completion(plan, true)),
        FakeMode::HealthFail | FakeMode::RollbackFail => {
            BridgeObservation::Completion(completion(plan, false))
        }
    }
}

fn completion(plan: &Plan, succeeded: bool) -> RuntimeCompletion {
    RuntimeCompletion {
        plan_id: plan.id.clone(),
        generation: 1,
        succeeded,
        detail: if succeeded {
            "adapter observed success".into()
        } else {
            "adapter observed health failure".into()
        },
        receipts: plan
            .steps
            .iter()
            .map(|step| RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded,
                detail: if succeeded {
                    "adapter observed success".into()
                } else {
                    "adapter observed health failure".into()
                },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;
    use crate::plan_approval::{
        APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, canonical_bytes,
    };
    use crate::reconcile_fence::SharedReconcileFence;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    struct Fixture {
        ctx: Ctx,
        plan: Plan,
        approval: std::path::PathBuf,
        trust: std::path::PathBuf,
        root: std::path::PathBuf,
    }

    async fn signed_upgrade(label: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "tenkai-bridge-{label}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "bridge fixture")
            .await
            .unwrap();
        for version in ["1.0.0", "1.1.0"] {
            publish_signed(&mut ctx, &root, version).await;
        }
        let actor = crate::auth_context::test_management_context(label);
        crate::catalog::promote(&mut ctx, &actor, "bridge-app@1.1.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "prod", "bridge-app", "stable")
            .await
            .unwrap();
        crate::environment::reconcile_deployment(&mut ctx, "prod", "bridge-app", Some("1.0.0"))
            .await
            .unwrap();
        let plan = crate::plan::create_for_reconcile(&mut ctx, "prod")
            .await
            .unwrap();
        assert!(!plan.steps.is_empty(), "{plan:?}");
        let approval = root.join("approval.json");
        let trust = root.join("approval-trust.toml");
        write_plan_approval(&plan, &approval, &trust, crate::now_millis(), 60_000);
        Fixture {
            ctx,
            plan,
            approval,
            trust,
            root,
        }
    }

    async fn publish_signed(ctx: &mut Ctx, root: &Path, version: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "bridge-app"
version = "{version}"

[deploy]
install = "true"
"#
            ),
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = dir.join("release.sig.json");
        let trust = dir.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &dir.join("tenkai.toml"), &signature, &trust).unwrap();
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                allow_unsigned_development: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    fn write_plan_approval(plan: &Plan, approval: &Path, trust: &Path, now: i64, ttl: i64) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let public = key.verifying_key().to_bytes();
        let kid = crate::release_signing::key_id(&public);
        let statement = ApprovalStatement {
            plan_digest: format!("sha256:{}", plan.executable_digest().unwrap()),
            environment: plan.environment.clone(),
            purpose: "execute_plan".into(),
            skip_gates: false,
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(ttl),
            policy_provider: "builtin".into(),
            policy_evidence_id: "bridge-decision".into(),
            policy_digest: format!("sha256:{}", "ef".repeat(32)),
        };
        let signature = key.sign(&canonical_bytes(&statement).unwrap());
        let envelope = ApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: kid.clone(),
            statement,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };
        std::fs::write(approval, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        std::fs::write(
            trust,
            format!(
                "version = 1\n\n[[signers]]\nkey_id = \"{kid}\"\nidentity = \"bridge-approver@localhost\"\npublic_key = \"{}\"\n",
                base64::engine::general_purpose::STANDARD.encode(public)
            ),
        )
        .unwrap();
    }

    fn opts<'a>(
        approval: &'a Path,
        trust: &'a Path,
        now: i64,
        skip_gates: bool,
    ) -> BridgeExecution<'a> {
        BridgeExecution {
            expected_environment: "prod",
            approval: Some((approval, trust)),
            skip_gates,
            now,
            fence: None,
        }
    }

    #[tokio::test]
    async fn two_independent_adapters_return_equivalent_receipts() {
        let mut left = signed_upgrade("eq-a").await;
        let mut right = signed_upgrade("eq-b").await;
        let now = crate::now_millis();
        let polling = PollingAdapter::new(FakeMode::Succeed);
        let callback = CallbackAdapter::new(FakeMode::Succeed);
        let left_approval = left.approval.clone();
        let left_trust = left.trust.clone();
        let left_plan = left.plan.clone();
        let first = execute_bridged_plan(
            &mut left.ctx,
            &polling,
            &left_plan,
            opts(&left_approval, &left_trust, now, true),
        )
        .await
        .unwrap();
        let right_approval = right.approval.clone();
        let right_trust = right.trust.clone();
        let right_plan = right.plan.clone();
        let second = execute_bridged_plan(
            &mut right.ctx,
            &callback,
            &right_plan,
            opts(&right_approval, &right_trust, now, true),
        )
        .await
        .unwrap();
        assert_eq!(first.state, PlanState::Succeeded);
        assert_eq!(second.state, PlanState::Succeeded);
        assert_eq!(first.receipts.len(), second.receipts.len());
        assert!(first.receipts.iter().all(|receipt| receipt.succeeded));
        assert!(second.receipts.iter().all(|receipt| receipt.succeeded));
        assert_ne!(first.correlation, second.correlation);
        let _ = std::fs::remove_dir_all(left.root);
        let _ = std::fs::remove_dir_all(right.root);
    }

    #[tokio::test]
    async fn expired_foreign_recalled_gated_and_stale_fence_fail_before_apply() {
        let mut fixture = signed_upgrade("deny").await;
        let now = crate::now_millis();
        let adapter = PollingAdapter::new(FakeMode::Succeed);
        let approval = fixture.approval.clone();
        let trust = fixture.trust.clone();
        let plan = fixture.plan.clone();
        write_plan_approval(&plan, &approval, &trust, now.saturating_sub(80_000), 1);
        let err = execute_bridged_plan(
            &mut fixture.ctx,
            &adapter,
            &plan,
            opts(&approval, &trust, now, true),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("expir") || err.contains("not valid"), "{err}");

        write_plan_approval(&plan, &approval, &trust, now, 60_000);
        let mut foreign = opts(&approval, &trust, now, true);
        foreign.expected_environment = "other";
        let err = execute_bridged_plan(&mut fixture.ctx, &adapter, &plan, foreign)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("foreign environment"), "{err}");

        let actor = crate::auth_context::test_management_context("recall");
        crate::catalog::recall(&mut fixture.ctx, &actor, "bridge-app@1.1.0")
            .await
            .unwrap();
        let err = execute_bridged_plan(
            &mut fixture.ctx,
            &adapter,
            &plan,
            opts(&approval, &trust, now, true),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("recalled"), "{err}");

        let mut gated = signed_upgrade("gate").await;
        let gated_approval = gated.approval.clone();
        let gated_trust = gated.trust.clone();
        let gated_plan = gated.plan.clone();
        let gated_now = crate::now_millis();
        let err = execute_bridged_plan(
            &mut gated.ctx,
            &adapter,
            &gated_plan,
            opts(&gated_approval, &gated_trust, gated_now, false),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("gate"), "{err}");

        let mut fenced = signed_upgrade("fence").await;
        let fence = SharedReconcileFence::new().into_arc();
        let fenced_now = crate::now_millis();
        fence
            .try_begin("prod", "holder", fenced_now, 60_000)
            .unwrap();
        let fenced_approval = fenced.approval.clone();
        let fenced_trust = fenced.trust.clone();
        let fenced_plan = fenced.plan.clone();
        let mut late = opts(&fenced_approval, &fenced_trust, fenced_now, true);
        late.fence = Some(fence);
        let err = execute_bridged_plan(&mut fenced.ctx, &adapter, &fenced_plan, late)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("stale fencing") || err.contains("Busy"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(fixture.root);
        let _ = std::fs::remove_dir_all(gated.root);
        let _ = std::fs::remove_dir_all(fenced.root);
    }

    #[tokio::test]
    async fn timeout_stays_non_terminal_and_repeated_apply_is_idempotent() {
        let mut fixture = signed_upgrade("idem").await;
        let now = crate::now_millis();
        let approval = fixture.approval.clone();
        let trust = fixture.trust.clone();
        let plan = fixture.plan.clone();
        let timeout = PollingAdapter::new(FakeMode::Timeout);
        let pending = execute_bridged_plan(
            &mut fixture.ctx,
            &timeout,
            &plan,
            opts(&approval, &trust, now, true),
        )
        .await
        .unwrap();
        assert_eq!(pending.state, PlanState::Computed);
        assert!(pending.receipts.is_empty());
        let succeed = PollingAdapter::new(FakeMode::Succeed);
        let first = execute_bridged_plan(
            &mut fixture.ctx,
            &succeed,
            &plan,
            opts(&approval, &trust, now, true),
        )
        .await
        .unwrap();
        assert_eq!(first.state, PlanState::Succeeded);
        let stored = plan::load(&mut fixture.ctx, &plan.id).await.unwrap();
        let replay = execute_bridged_plan(
            &mut fixture.ctx,
            &succeed,
            &stored,
            opts(&approval, &trust, now, true),
        )
        .await
        .unwrap();
        assert_eq!(replay.state, PlanState::Succeeded);
        assert_eq!(replay.correlation, first.correlation);
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[tokio::test]
    async fn health_failure_triggers_rollback_and_failed_rollback_is_recovery_required() {
        let mut fixture = signed_upgrade("health").await;
        let now = crate::now_millis();
        let approval = fixture.approval.clone();
        let trust = fixture.trust.clone();
        let plan = fixture.plan.clone();
        let fail = PollingAdapter::new(FakeMode::HealthFail);
        let report = execute_bridged_plan(
            &mut fixture.ctx,
            &fail,
            &plan,
            opts(&approval, &trust, now, true),
        )
        .await
        .unwrap();
        assert!(report.rollback_triggered, "{report:?}");
        assert!(report.recovery_required, "{report:?}");
        let env = environment::environment(&mut fixture.ctx, "prod")
            .await
            .unwrap();
        assert_eq!(
            env.properties
                .get("deployment_recovery.bridge-app")
                .map(String::as_str),
            Some("recovery_required")
        );
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    fn apply_opts<'a>(
        approval: &'a Path,
        trust: &'a Path,
        adapter: Arc<dyn DeliveryAdapter>,
        fence: Option<Arc<dyn crate::reconcile_fence::ReconcileTickFence>>,
    ) -> crate::apply::ExecutionOptions<'a> {
        crate::apply::ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::Signed {
                approval,
                trust_roots: trust,
            },
            software_executor: None,
            delivery_adapter: Some(adapter),
            delivery_fence: fence,
        }
    }

    #[tokio::test]
    async fn apply_path_timeout_is_blocked_and_records_correlation() {
        let mut fixture = signed_upgrade("apply").await;
        let approval = fixture.approval.clone();
        let trust = fixture.trust.clone();
        let plan_id = fixture.plan.id.clone();
        let outcomes = crate::apply::execute_with_options(
            &mut fixture.ctx,
            &plan_id,
            apply_opts(
                &approval,
                &trust,
                Arc::new(PollingAdapter::new(FakeMode::Timeout)),
                None,
            ),
        )
        .await
        .unwrap();
        assert!(
            outcomes.iter().all(|outcome| {
                matches!(
                    outcome.classified_status().unwrap(),
                    crate::apply::StepOutcomeStatus::Blocked
                ) && outcome.detail.contains("non-terminal")
            }),
            "{outcomes:?}"
        );
        let stored = plan::load(&mut fixture.ctx, &plan_id).await.unwrap();
        assert!(
            matches!(stored.state, PlanState::Computed | PlanState::Running),
            "{stored:?}"
        );
        let env = environment::environment(&mut fixture.ctx, "prod")
            .await
            .unwrap();
        let correlation = env
            .properties
            .get("bridge.correlation")
            .expect("adapter correlation missing");
        assert!(
            correlation.contains(&plan_id) && correlation.contains("polling-fake"),
            "{correlation}"
        );
        let _ = std::fs::remove_dir_all(fixture.root);
    }

    #[tokio::test]
    async fn apply_path_fail_closes_expired_recalled_and_stale_fence() {
        let mut fixture = signed_upgrade("apply-deny").await;
        let approval = fixture.approval.clone();
        let trust = fixture.trust.clone();
        let plan_id = fixture.plan.id.clone();
        write_plan_approval(
            &fixture.plan,
            &approval,
            &trust,
            crate::now_millis().saturating_sub(80_000),
            1,
        );
        let err = crate::apply::execute_with_options(
            &mut fixture.ctx,
            &plan_id,
            apply_opts(
                &approval,
                &trust,
                Arc::new(PollingAdapter::new(FakeMode::Succeed)),
                None,
            ),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("expired") || err.contains("not valid"),
            "{err}"
        );

        write_plan_approval(
            &fixture.plan,
            &approval,
            &trust,
            crate::now_millis(),
            60_000,
        );
        let actor = crate::auth_context::test_management_context("apply-recall");
        crate::catalog::recall(&mut fixture.ctx, &actor, "bridge-app@1.1.0")
            .await
            .unwrap();
        let err = crate::apply::execute_with_options(
            &mut fixture.ctx,
            &plan_id,
            apply_opts(
                &approval,
                &trust,
                Arc::new(PollingAdapter::new(FakeMode::Succeed)),
                None,
            ),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("recalled"), "{err}");

        let mut fenced = signed_upgrade("apply-fence").await;
        let fence = SharedReconcileFence::new().into_arc();
        fence
            .try_begin("prod", "holder", crate::now_millis(), 60_000)
            .unwrap();
        let fenced_approval = fenced.approval.clone();
        let fenced_trust = fenced.trust.clone();
        let fenced_id = fenced.plan.id.clone();
        let err = crate::apply::execute_with_options(
            &mut fenced.ctx,
            &fenced_id,
            apply_opts(
                &fenced_approval,
                &fenced_trust,
                Arc::new(PollingAdapter::new(FakeMode::Succeed)),
                Some(fence),
            ),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("stale fencing") || err.contains("Busy"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(fixture.root);
        let _ = std::fs::remove_dir_all(fenced.root);
    }
}

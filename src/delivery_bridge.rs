//! External delivery adapters (#292 / ADR 0022).
//!
//! Adapters apply and observe bounded effects. Apply acknowledgement is never
//! success. Terminal evidence is admitted only as a Tenkai runtime completion.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};

use crate::client::Ctx;
use crate::delivery_manifest;
use crate::plan::{self, Plan, PlanState};
use crate::runtime_delivery::{RuntimeCompletion, RuntimeStepReceipt};

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

pub trait DeliveryAdapter {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BTreeSet<String>;
    fn apply(&mut self, plan: &Plan) -> Result<BridgeAck>;
    fn observe(&mut self, plan: &Plan) -> Result<BridgeObservation>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeMode {
    Succeed,
    Timeout,
    HealthFail,
}

#[derive(Debug)]
pub struct PollingAdapter {
    mode: FakeMode,
    applied: bool,
}

#[derive(Debug)]
pub struct CallbackAdapter {
    mode: FakeMode,
    applied: bool,
}

impl PollingAdapter {
    pub fn new(mode: FakeMode) -> Self {
        Self {
            mode,
            applied: false,
        }
    }
}

impl CallbackAdapter {
    pub fn new(mode: FakeMode) -> Self {
        Self {
            mode,
            applied: false,
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
    fn apply(&mut self, plan: &Plan) -> Result<BridgeAck> {
        ensure_plan(plan)?;
        self.applied = true;
        Ok(BridgeAck { accepted: true })
    }
    fn observe(&mut self, plan: &Plan) -> Result<BridgeObservation> {
        if !self.applied {
            bail!("observe before apply acknowledgement");
        }
        Ok(observation(self.mode, plan))
    }
}

impl DeliveryAdapter for CallbackAdapter {
    fn name(&self) -> &'static str {
        "callback-fake"
    }
    fn capabilities(&self) -> BTreeSet<String> {
        ["plan.execute".into()].into_iter().collect()
    }
    fn apply(&mut self, plan: &Plan) -> Result<BridgeAck> {
        ensure_plan(plan)?;
        self.applied = true;
        Ok(BridgeAck { accepted: true })
    }
    fn observe(&mut self, plan: &Plan) -> Result<BridgeObservation> {
        if !self.applied {
            bail!("callback presented before apply acknowledgement");
        }
        Ok(observation(self.mode, plan))
    }
}

pub async fn execute_bridged_plan(
    ctx: &mut Ctx,
    adapter: &mut dyn DeliveryAdapter,
    plan: &Plan,
    approval: &Path,
    trust_roots: &Path,
    required_capabilities: &[&str],
    now: i64,
) -> Result<PlanState> {
    delivery_manifest::admit_required_capabilities(
        &required_capabilities
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        &adapter.capabilities().into_iter().collect::<Vec<_>>(),
    )?;
    delivery_manifest::admit_signed_plan(plan, approval, trust_roots, now)?;
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
        BridgeObservation::Pending | BridgeObservation::TimedOut => Ok(after_ack.state),
        BridgeObservation::Completion(completion) => {
            crate::delivery_manifest::admit_runtime_completion(ctx, &plan.environment, &completion)
                .await?;
            Ok(plan::load(ctx, &plan.id).await?.state)
        }
    }
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
        FakeMode::HealthFail => BridgeObservation::Completion(completion(plan, false)),
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
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    async fn signed_plan(
        root: &std::path::Path,
    ) -> (Ctx, Plan, std::path::PathBuf, std::path::PathBuf) {
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "bridge fixture")
            .await
            .unwrap();
        let product = root.join("1.0.0");
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            r#"
[product]
name = "bridge-app"
version = "1.0.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = product.join("release.sig.json");
        let trust = product.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &product.join("tenkai.toml"), &signature, &trust)
            .unwrap();
        crate::catalog::publish(
            &mut ctx,
            &product.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                allow_unsigned_development: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("bridge");
        crate::catalog::promote(&mut ctx, &actor, "bridge-app@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "prod", "bridge-app", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create_for_reconcile(&mut ctx, "prod")
            .await
            .unwrap();
        let approval = root.join("approval.json");
        let approval_trust = root.join("approval-trust.toml");
        write_plan_approval(&plan, &approval, &approval_trust);
        (ctx, plan, approval, approval_trust)
    }

    fn write_plan_approval(plan: &Plan, approval: &Path, trust: &Path) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let public = key.verifying_key().to_bytes();
        let kid = crate::release_signing::key_id(&public);
        let now = crate::now_millis();
        let statement = ApprovalStatement {
            plan_digest: format!("sha256:{}", plan.executable_digest().unwrap()),
            environment: plan.environment.clone(),
            purpose: "execute_plan".into(),
            skip_gates: false,
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(60_000),
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

    fn temp_root(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-bridge-{label}-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn two_adapters_complete_the_same_signed_plan_equivalently() {
        let root = temp_root("eq");
        let (mut ctx, plan, approval, trust) = signed_plan(&root).await;
        let now = crate::now_millis();
        let mut polling = PollingAdapter::new(FakeMode::Succeed);
        let first = execute_bridged_plan(
            &mut ctx,
            &mut polling,
            &plan,
            &approval,
            &trust,
            &["plan.execute"],
            now,
        )
        .await
        .unwrap();
        assert_eq!(first, PlanState::Succeeded);
        let mut callback = CallbackAdapter::new(FakeMode::Succeed);
        let second = execute_bridged_plan(
            &mut ctx,
            &mut callback,
            &plan,
            &approval,
            &trust,
            &["plan.execute"],
            now,
        )
        .await
        .unwrap();
        assert_eq!(second, PlanState::Succeeded);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn ack_timeout_conflict_and_unknown_capability_fail_closed() {
        let root = temp_root("fail");
        let (mut ctx, plan, approval, trust) = signed_plan(&root).await;
        let now = crate::now_millis();
        let mut timeout = PollingAdapter::new(FakeMode::Timeout);
        let state = execute_bridged_plan(
            &mut ctx,
            &mut timeout,
            &plan,
            &approval,
            &trust,
            &["plan.execute"],
            now,
        )
        .await
        .unwrap();
        assert_eq!(state, PlanState::Computed);
        let mut polling = PollingAdapter::new(FakeMode::Succeed);
        execute_bridged_plan(
            &mut ctx,
            &mut polling,
            &plan,
            &approval,
            &trust,
            &["plan.execute"],
            now,
        )
        .await
        .unwrap();
        let mut fail = CallbackAdapter::new(FakeMode::HealthFail);
        let err = execute_bridged_plan(
            &mut ctx,
            &mut fail,
            &plan,
            &approval,
            &trust,
            &["plan.execute"],
            now,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("conflict"), "{err}");
        let mut unknown = PollingAdapter::new(FakeMode::Succeed);
        let err = execute_bridged_plan(
            &mut ctx,
            &mut unknown,
            &plan,
            &approval,
            &trust,
            &["adapter.unknown"],
            now,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown required capability"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn health_failure_is_terminal_failure_and_rollback_needs_previous() {
        let root = temp_root("health");
        let (mut ctx, plan, approval, trust) = signed_plan(&root).await;
        let mut fail = PollingAdapter::new(FakeMode::HealthFail);
        let state = execute_bridged_plan(
            &mut ctx,
            &mut fail,
            &plan,
            &approval,
            &trust,
            &["plan.execute"],
            crate::now_millis(),
        )
        .await
        .unwrap();
        assert_eq!(state, PlanState::Failed);
        let err = crate::plan::rollback_step(&mut ctx, "prod", "bridge-app")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("nothing to roll back") || err.contains("not found"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

//! Runtime delivery application operations.
//!
//! This deep module owns runtime credential admission, Environment scope,
//! claim fencing, completion ordering, heartbeat renewal, and inventory
//! admission. Transport adapters only extract and serialize protocol values.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::client::Ctx;
use crate::environment_dependencies::EnvironmentDependencies;
use crate::plan::PlanState;
use crate::plan::{
    EnvironmentInspectReport, EnvironmentListEntry, FleetStatusReport, Plan, StatusRow,
};
use crate::reconciler::{ReconcileDiagnostics, Reconciler, TickReport};
use crate::storage::{OperationalStore, RuntimeClaim};

pub type ReconcileFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<TickReport>> + Send + 'a>>;
pub type WorkFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<Option<Plan>>> + Send + 'a>>;
pub type HealthFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
pub type CompletionFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
pub type ListEnvFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Vec<EnvironmentListEntry>>> + Send + 'a>>;
pub type InspectEnvFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<EnvironmentInspectReport>> + Send + 'a>>;
pub type StatusEnvFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Vec<StatusRow>>> + Send + 'a>>;
pub type DependenciesEnvFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<EnvironmentDependencies>> + Send + 'a>>;
pub type FleetStatusFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<FleetStatusReport>> + Send + 'a>>;
pub type InventoryFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Vec<String>>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStepReceipt {
    pub step_id: String,
    pub succeeded: bool,
    pub detail: String,
    /// The wraps a re-wrap step made for its recipient (ADR 0045 §5). The
    /// server keeps only those the claimed, approved step names. Omitted
    /// otherwise, so older servers read every other receipt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wraps: Vec<crate::sealed_secret::RecipientWrap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCompletion {
    pub plan_id: String,
    pub generation: u64,
    pub succeeded: bool,
    pub detail: String,
    pub receipts: Vec<RuntimeStepReceipt>,
}

/// Shared application view used by embedded and remote hosts.
pub trait ReconcilePort: Send + Sync {
    fn reconcile(&self) -> ReconcileFuture<'_>;
    fn reconcile_environments(&self, _environments: Vec<String>) -> ReconcileFuture<'_> {
        Box::pin(async {
            anyhow::bail!("tenant-bounded reconciliation is not supported by this host")
        })
    }
    fn pending_work(&self, environment: String) -> WorkFuture<'_>;
    fn check_health(&self) -> HealthFuture<'_>;
    fn complete_work(
        &self,
        environment: String,
        completion: RuntimeCompletion,
    ) -> CompletionFuture<'_>;
    fn validate_completion(
        &self,
        environment: String,
        completion: RuntimeCompletion,
    ) -> CompletionFuture<'_>;
    fn list_environments(&self) -> ListEnvFuture<'_>;
    fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_>;
    fn inspect_environment_without_outcome_export(
        &self,
        environment: String,
    ) -> InspectEnvFuture<'_> {
        let inspection = self.inspect_environment(environment);
        Box::pin(async move {
            let mut report = inspection.await?;
            report.terminal_outcomes.clear();
            Ok(report)
        })
    }
    fn environment_status(&self, environment: String) -> StatusEnvFuture<'_>;
    fn environment_dependencies(&self, environment: String) -> DependenciesEnvFuture<'_> {
        Box::pin(async move { Ok(EnvironmentDependencies::empty(environment)) })
    }
    fn fleet_status(&self) -> FleetStatusFuture<'_>;
    fn fleet_status_without_outcome_export(&self) -> FleetStatusFuture<'_> {
        Box::pin(async {
            anyhow::bail!("tenant-bounded fleet inspection is not supported by this host")
        })
    }
    fn apply_inventory_facts(
        &self,
        environment: String,
        facts: BTreeMap<String, String>,
    ) -> InventoryFuture<'_>;
    fn diagnostics_snapshot(&self) -> ReconcileDiagnostics;
    fn application_ctx(&self) -> Option<Ctx> {
        None
    }
}

impl ReconcilePort for Reconciler {
    fn reconcile(&self) -> ReconcileFuture<'_> {
        Box::pin(self.run_once())
    }

    fn reconcile_environments(&self, environments: Vec<String>) -> ReconcileFuture<'_> {
        Box::pin(async move { self.run_once_for(&environments).await })
    }

    fn pending_work(&self, environment: String) -> WorkFuture<'_> {
        Box::pin(async move { self.pending_work(&environment).await })
    }

    fn check_health(&self) -> HealthFuture<'_> {
        Box::pin(self.check_provider_health())
    }

    fn complete_work(
        &self,
        environment: String,
        completion: RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            complete_runtime_work(&mut ctx, &environment, &completion).await
        })
    }

    fn validate_completion(
        &self,
        environment: String,
        completion: RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            validate_runtime_completion(&mut ctx, &environment, &completion).await
        })
    }

    fn list_environments(&self) -> ListEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::list_environments(&mut ctx).await
        })
    }

    fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::inspect_environment_for_policy(
                &mut ctx,
                &environment,
                self.execution_policy(),
            )
            .await
        })
    }

    fn inspect_environment_without_outcome_export(
        &self,
        environment: String,
    ) -> InspectEnvFuture<'_> {
        Box::pin(self.inspect_environment_without_outcome_export(environment))
    }

    fn environment_status(&self, environment: String) -> StatusEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::status(&mut ctx, &environment).await
        })
    }

    fn environment_dependencies(&self, environment: String) -> DependenciesEnvFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::environment_dependencies::for_environment(&mut ctx, &environment).await
        })
    }

    fn fleet_status(&self) -> FleetStatusFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::fleet_status(&mut ctx).await
        })
    }

    fn fleet_status_without_outcome_export(&self) -> FleetStatusFuture<'_> {
        Box::pin(self.fleet_status_without_outcome_export())
    }

    fn apply_inventory_facts(
        &self,
        environment: String,
        facts: BTreeMap<String, String>,
    ) -> InventoryFuture<'_> {
        Box::pin(async move {
            let mut ctx = self.ctx_clone();
            crate::plan::apply_runtime_inventory_facts(&mut ctx, &environment, &facts).await
        })
    }

    fn diagnostics_snapshot(&self) -> ReconcileDiagnostics {
        Reconciler::diagnostics_snapshot(self)
    }

    fn application_ctx(&self) -> Option<Ctx> {
        Some(self.ctx_clone())
    }
}

/// Refuses runtime work whose releases' topologies the replicas' placement
/// facts now violate (#689).
async fn require_runtime_placement(
    ctx: &mut Ctx,
    environment: &str,
    plan: &crate::plan::Plan,
) -> Result<(), RuntimeDeliveryError> {
    // A removal deploys nothing, so it is never refused for placement.
    for step in plan
        .steps
        .iter()
        .filter(|step| step.deploys_release() && step.action != crate::plan::Action::Remove)
    {
        crate::topology::require_placement(ctx, environment, &step.release_id)
            .await
            .map_err(
                |error| match error.downcast_ref::<crate::topology::PlacementRefused>() {
                    Some(refused) => RuntimeDeliveryError::InvalidRequest(refused.to_string()),
                    None => RuntimeDeliveryError::Unavailable(
                        "topology placement preflight unavailable".into(),
                    ),
                },
            )?;
    }
    Ok(())
}

pub(crate) async fn complete_runtime_work(
    ctx: &mut Ctx,
    environment: &str,
    completion: &RuntimeCompletion,
) -> anyhow::Result<()> {
    validate_runtime_completion(ctx, environment, completion).await?;
    let mut stored = crate::plan::load(ctx, &completion.plan_id).await?;
    let terminal = if completion.succeeded {
        PlanState::Succeeded
    } else {
        PlanState::Failed
    };
    if matches!(stored.state, PlanState::Succeeded | PlanState::Failed) {
        return Ok(());
    }
    if stored.state == PlanState::Computed {
        crate::plan::transition(
            ctx,
            &mut stored,
            crate::plan::Transition::new(
                PlanState::Running,
                "claimed by assigned environment runtime",
            ),
            crate::plan::Persistence::Standard,
        )
        .await?;
    }
    // A re-wrap or issuer step deploys nothing: it never touches the
    // deployment record or the failed targets, and it exports no delivery
    // outcome.
    let deploying: Vec<crate::plan::Step> = stored
        .steps
        .iter()
        .filter(|step| step.deploys_release())
        .cloned()
        .collect();
    // A plan of re-wrap and issuer steps only, as `secret rewrap` and
    // `env issuer plan` build, changes no environment state here: its wraps
    // and issuer were stored under the environment lease before this ran.
    // Rewriting the environment here could restore wraps a revocation
    // dropped meanwhile, so only the plan moves on.
    if deploying.is_empty() {
        crate::plan::transition(
            ctx,
            &mut stored,
            crate::plan::Transition::new(terminal, completion.detail.clone()),
            crate::plan::Persistence::Standard,
        )
        .await?;
        return Ok(());
    }
    // The completion holds the environment lease from its first read of the
    // environment to its fenced write, so it never overwrites a change made
    // under the lease meanwhile: a secret, a binding, or a revocation's
    // dropped wraps (#1139). A held lease fails the completion, which is
    // retried, and a durable one is replayed, until it applies.
    let lease =
        crate::apply::claim_environment_for_completion(ctx, environment, &stored.id).await?;
    let applied = async {
        let observed_at = crate::now_millis();
        let mut environment_object = None;
        // The releases held as failed before this completion changes them, so
        // each step's observation can say whether it retried one (#803).
        let held_before: std::collections::HashMap<String, String> = ctx
            .get(&crate::ontology::env_id(environment))
            .await?
            .map(|object| {
                object
                    .properties
                    .into_iter()
                    .filter_map(|(key, value)| {
                        key.strip_prefix("failed_target.")
                            .map(|instance| (instance.to_string(), value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if completion.succeeded {
            let mut object = ctx
                .get(&crate::ontology::env_id(environment))
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("environment {environment} disappeared during outcome enqueue")
                })?;
            crate::plan::update_runtime_deployments_object(
                ctx,
                &mut object,
                &deploying,
                observed_at,
            )
            .await?;
            environment_object = Some(object);
        }
        if environment_object.is_none() {
            environment_object = Some(
                ctx.get(&crate::ontology::env_id(environment))
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!("environment {environment} disappeared during completion")
                    })?,
            );
        }
        let object = environment_object
            .as_mut()
            .expect("completion loads the environment");
        if !completion.succeeded {
            let succeeded_steps = deploying
                .iter()
                .filter(|step| {
                    completion
                        .receipts
                        .iter()
                        .any(|receipt| receipt.step_id == step.id && receipt.succeeded)
                })
                .cloned()
                .collect::<Vec<_>>();
            crate::plan::update_runtime_deployments_object(
                ctx,
                object,
                &succeeded_steps,
                observed_at,
            )
            .await?;
        }
        let subscribed: std::collections::HashSet<String> =
            crate::environment::list_subscriptions(ctx, object)
                .await?
                .into_iter()
                .map(|subscription| subscription.instance)
                .collect();
        for step in &stored.steps {
            let Some(receipt) = completion
                .receipts
                .iter()
                .find(|receipt| receipt.step_id == step.id)
            else {
                continue;
            };
            // Its wraps or issuer were stored before, under the environment
            // lease (`sealed_secret::store_completion_wraps`,
            // `identity_issuer::record_activated`).
            if !step.deploys_release() {
                continue;
            }
            // Keyed by instance, as the server records failures.
            let instance = step.instance_name();
            let key = format!("failed_target.{instance}");
            if crate::terminal_outcome::classify(
                step.action,
                crate::terminal_outcome::Observation::Runtime {
                    succeeded: receipt.succeeded,
                    detail: &receipt.detail,
                },
            )
            .is_none()
            {
                continue;
            }
            // An executed removal that failed may have removed part of the
            // instance, as the server records it; one refused because the
            // instance is subscribed again removed nothing.
            if !receipt.succeeded
                && step.action == crate::plan::Action::Remove
                && step.host.is_none()
                && !subscribed.contains(instance)
            {
                crate::environment::record_removal_unknown(
                    object,
                    step,
                    &receipt.detail,
                    observed_at,
                );
            }
            if !receipt.succeeded && step.action != crate::plan::Action::Rollback {
                object.properties.insert(key, step.release_id.clone());
                object
                    .properties
                    .insert(format!("failed_target_plan.{instance}"), stored.id.clone());
                object.properties.insert(
                    format!("failed_target_at.{instance}"),
                    observed_at.to_string(),
                );
                crate::environment::record_failed_target_error(
                    &mut object.properties,
                    instance,
                    &step.release_id,
                    &receipt.detail,
                );
            } else if receipt.succeeded && object.properties.get(&key) == Some(&step.release_id) {
                object.properties.remove(&key);
                object
                    .properties
                    .remove(&format!("failed_target_plan.{instance}"));
            }
        }
        let provider_events = if ctx.outcome_export_enabled() {
            if environment_object.is_none() {
                environment_object = Some(
                    ctx.get(&crate::ontology::env_id(environment))
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "environment {environment} disappeared during outcome enqueue"
                            )
                        })?,
                );
            }
            let environment_object = environment_object
                .as_ref()
                .expect("outcome export always loads the environment");
            deploying
                .iter()
                .filter_map(|step| {
                    completion
                        .receipts
                        .iter()
                        .find(|receipt| receipt.step_id == step.id)
                        .map(|receipt| (step, receipt))
                })
                .filter_map(|(step, receipt)| {
                    crate::terminal_outcome::classify(
                        step.action,
                        crate::terminal_outcome::Observation::Runtime {
                            succeeded: receipt.succeeded,
                            detail: &receipt.detail,
                        },
                    )
                    .map(|terminal_state| (step, terminal_state))
                })
                .map(|(step, terminal_state)| {
                    crate::providers::terminal_outcome_record(
                        &stored,
                        step,
                        &format!(
                            "tenkai:runtime-deployment:{}:{}:{}",
                            stored.id, completion.generation, step.id
                        ),
                        terminal_state,
                        environment_object,
                        observed_at,
                    )
                    .map_err(anyhow::Error::from)
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        // One observation per step the runtime reports a terminal result for,
        // committed with the completion (#802). The runtime's start time is not
        // observed here, so no duration is recorded.
        let observations = stored
            .steps
            .iter()
            .filter_map(|step| {
                let receipt = completion
                    .receipts
                    .iter()
                    .find(|receipt| receipt.step_id == step.id)?;
                crate::terminal_outcome::classify(
                    step.action,
                    crate::terminal_outcome::Observation::Runtime {
                        succeeded: receipt.succeeded,
                        detail: &receipt.detail,
                    },
                )?;
                Some(crate::feedback_observation::FeedbackObservation::capture(
                    crate::feedback_observation::Capture {
                        id: &format!(
                            "tenkai:runtime-deployment:{}:{}:{}",
                            stored.id, completion.generation, step.id
                        ),
                        operation: crate::feedback_observation::Operation::RuntimeCompletion,
                        environment,
                        product: &step.product,
                        plan_id: &stored.id,
                        step_id: &step.id,
                        action: Some(step.action),
                        release_id: &step.release_id,
                        status: if receipt.succeeded {
                            "succeeded"
                        } else {
                            "failed"
                        },
                        reason: crate::feedback_observation::runtime_reason(receipt.succeeded),
                        started_at_ms: None,
                        lease_generation: completion.generation,
                        observed_at_ms: observed_at,
                        context: crate::feedback_observation::RetryContext {
                            runtime_claim_generation: Some(completion.generation),
                            failed_target_retry: held_before.get(step.instance_name())
                                == Some(&step.release_id),
                            recovery_reason: stored.recalled_recovery_reason.clone(),
                            ..Default::default()
                        },
                    },
                ))
            })
            .collect::<Vec<_>>();
        if let Some(environment) = environment_object {
            if !ctx.is_embedded() {
                ctx.guarded_update(
                    environment,
                    crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
                    &lease.environment,
                    &lease.fencing_token,
                )
                .await?;
                crate::plan::transition(
                    ctx,
                    &mut stored,
                    crate::plan::Transition::new(terminal, completion.detail.clone()),
                    crate::plan::Persistence::Standard,
                )
                .await?;
                return Ok(());
            }
            crate::plan::transition(
                ctx,
                &mut stored,
                crate::plan::Transition::new(terminal, completion.detail.clone()),
                crate::plan::Persistence::WithFencedEnvironment {
                    environment,
                    fencing_token: &lease.fencing_token,
                    provider_events: &provider_events,
                    observations: &observations,
                },
            )
            .await?;
        } else {
            crate::plan::transition(
                ctx,
                &mut stored,
                crate::plan::Transition::new(terminal, completion.detail.clone()),
                crate::plan::Persistence::WithProviderEvents {
                    provider_events: &provider_events,
                    observations: &observations,
                },
            )
            .await?;
        }
        anyhow::Ok(())
    }
    .await;
    let released = crate::apply::release_environment(ctx, &lease).await;
    match (applied, released) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.context("releasing the environment lease")),
    }
}

pub(crate) async fn validate_runtime_completion(
    ctx: &mut Ctx,
    environment: &str,
    completion: &RuntimeCompletion,
) -> anyhow::Result<()> {
    let stored = crate::plan::load(ctx, &completion.plan_id).await?;
    anyhow::ensure!(
        stored.environment == environment,
        "plan {} belongs to {}, not {environment}",
        completion.plan_id,
        stored.environment
    );
    let expected = stored
        .steps
        .iter()
        .map(|step| step.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let received = completion
        .receipts
        .iter()
        .map(|receipt| receipt.step_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    anyhow::ensure!(
        expected == received && received.len() == completion.receipts.len(),
        "runtime completion receipts must cover every plan step exactly once"
    );
    anyhow::ensure!(
        !completion.succeeded || completion.receipts.iter().all(|receipt| receipt.succeeded),
        "a successful runtime completion cannot contain a failed step receipt"
    );
    for receipt in &completion.receipts {
        let step = stored
            .steps
            .iter()
            .find(|step| step.id == receipt.step_id)
            .expect("receipts cover the plan's steps");
        require_approved_wraps(environment, step, receipt)?;
    }
    let terminal = if completion.succeeded {
        PlanState::Succeeded
    } else {
        PlanState::Failed
    };
    if matches!(stored.state, PlanState::Succeeded | PlanState::Failed) {
        anyhow::ensure!(
            stored.state == terminal,
            "runtime completion conflicts with terminal plan state"
        );
        return Ok(());
    }
    anyhow::ensure!(
        matches!(stored.state, PlanState::Computed | PlanState::Running),
        "runtime plan is not executable"
    );
    // A stale issuer step is refused before its completion is recorded, so
    // the current issuer stays (ADR 0046 §2). Checked only for a completion
    // not yet applied: a replay of an applied one must not depend on a
    // later rotation.
    for receipt in completion
        .receipts
        .iter()
        .filter(|receipt| receipt.succeeded)
    {
        let step = stored
            .steps
            .iter()
            .find(|step| step.id == receipt.step_id)
            .expect("receipts cover the plan's steps");
        if step.issuer.is_some() {
            let env_obj = crate::environment::environment(ctx, environment).await?;
            crate::identity_issuer::require_current(&env_obj, step)?;
        }
    }
    Ok(())
}

/// The wraps of a completion's succeeded re-wrap steps, by instance.
fn completion_wraps(
    plan: &crate::plan::Plan,
    completion: &RuntimeCompletion,
) -> Vec<(String, Vec<crate::sealed_secret::RecipientWrap>)> {
    completion
        .receipts
        .iter()
        .filter(|receipt| receipt.succeeded && !receipt.wraps.is_empty())
        .filter_map(|receipt| {
            let step = plan
                .steps
                .iter()
                .find(|step| step.id == receipt.step_id && step.rewrap.is_some())?;
            Some((step.instance_name().to_owned(), receipt.wraps.clone()))
        })
        .collect()
}

/// The recipients a completion carries wraps for.
fn wrapped_recipients(completion: &RuntimeCompletion) -> std::collections::BTreeSet<String> {
    completion
        .receipts
        .iter()
        .flat_map(|receipt| &receipt.wraps)
        .map(|wrap| wrap.wrap.fingerprint.clone())
        .collect()
}

/// Keep only wraps for `current` recipients: a recipient revoked after the
/// runtime fetched its key gets none back.
fn retain_recipient_wraps(
    completion: &mut RuntimeCompletion,
    current: &std::collections::BTreeSet<String>,
) {
    for receipt in &mut completion.receipts {
        receipt
            .wraps
            .retain(|wrap| current.contains(&wrap.wrap.fingerprint));
    }
}

/// Refuse wraps the approved plan does not name (ADR 0045 §5): only a
/// succeeded re-wrap step carries them, each for the step's recipient and
/// for a value of the step's bindings, or its issuer key, at its approved
/// digest. A server can therefore not attach a wrap a runtime did not make
/// for an approved step.
fn require_approved_wraps(
    environment: &str,
    step: &crate::plan::Step,
    receipt: &RuntimeStepReceipt,
) -> anyhow::Result<()> {
    if receipt.wraps.is_empty() {
        return Ok(());
    }
    let Some(rewrap) = step.rewrap.as_ref().filter(|_| receipt.succeeded) else {
        anyhow::bail!(
            "step {} carries wraps but is not a succeeded re-wrap step",
            step.id
        );
    };
    for wrap in &receipt.wraps {
        crate::sealed_secret::check_wrap(&wrap.wrap)?;
        anyhow::ensure!(
            wrap.wrap.fingerprint == rewrap.fingerprint,
            "step {} wraps for {}, not its recipient {}",
            step.id,
            wrap.wrap.fingerprint,
            rewrap.fingerprint
        );
        let issuer = match &step.issuer {
            Some(issuer) => {
                wrap.secret == crate::identity_issuer::WRAP_SECRET
                    && wrap.key == issuer.key.wrap_key()
                    && wrap.digest == issuer.key.digest(environment)?
            }
            None => false,
        };
        anyhow::ensure!(
            issuer
                || step.sealed.iter().any(|sealed| sealed.secret == wrap.secret
                    && sealed.key == wrap.key
                    && sealed.digest == wrap.digest),
            "step {} has no sealed {}/{} at that digest",
            step.id,
            wrap.secret,
            wrap.key
        );
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWork {
    pub environment: String,
    pub plan: Option<Plan>,
    pub claim: Option<RuntimeClaim>,
    /// Plan-approval envelopes the runtime verifies locally for sealed
    /// steps (ADR 0045 §4). Omitted when empty so a runtime that predates
    /// the field keeps decoding idle work and plans without sealed steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<crate::plan_approval::ApprovalEnvelope>,
    /// Set when the environment asks for an identity issuer candidate
    /// (ADR 0046 §2), and only for a runtime that names the
    /// `workload_identity` capability: an older one would refuse the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_candidate: Option<crate::identity_issuer::CandidateRequest>,
    /// The approved rotation plans that prove the next issuer, while it
    /// waits for its issue step, and the previous issuer, while it is
    /// kept, so this runtime trusts both in every bundle it issues (ADR
    /// 0046 §7). On idle and claimed work alike, and only for a runtime
    /// that names `issuer_take_up`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_proofs: Vec<crate::identity_issuer::IssuerProof>,
}

fn idle_work(environment: &str) -> RuntimeWork {
    RuntimeWork {
        environment: environment.into(),
        plan: None,
        claim: None,
        approvals: Vec::new(),
        issuer_candidate: None,
        issuer_proofs: Vec::new(),
    }
}

async fn delivered_work(
    ctx: &mut Ctx,
    environment: &str,
    plan: Plan,
    claim: RuntimeClaim,
) -> Result<RuntimeWork, RuntimeDeliveryError> {
    // Sealed steps are verified against the runtime's local policy, and a
    // host step's approvals go to the applier (ADR 0048 §2).
    let approvals = if plan
        .steps
        .iter()
        .any(|step| step.requires_local_approval_policy() || step.host.is_some())
    {
        // Keep envelopes whose digest does not match so the runtime can
        // refuse a forged plan instead of treating it as "not yet approved".
        let mut envelopes = crate::plan_approval::list_collected_envelopes(ctx, &plan.id)
            .await
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        let mut seen = std::collections::BTreeSet::new();
        envelopes.retain(|envelope| seen.insert(envelope.signature.clone()));
        envelopes
    } else {
        Vec::new()
    };
    Ok(RuntimeWork {
        environment: environment.into(),
        plan: Some(plan),
        claim: Some(claim),
        approvals,
        issuer_candidate: None,
        issuer_proofs: Vec::new(),
    })
}

/// Which binary of which agent self-upgrade step a runtime asks for (#685).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelfReleaseFile {
    pub plan_id: String,
    pub generation: u64,
    pub step_id: String,
    pub name: String,
}

/// Refuse a non-host removal's package to a runtime that did not say it
/// removes one: an older runtime would install the release, and the server
/// would then record it removed (ADR 0049 §7).
fn refuse_removal_by_older_runtime(
    step: &crate::plan::Step,
    request: &RuntimeReleaseRequest,
) -> Result<(), RuntimeDeliveryError> {
    if step.action == crate::plan::Action::Remove && step.host.is_none() && !request.removal {
        return Err(RuntimeDeliveryError::ReleaseRefused(
            "this runtime agent predates removing releases; upgrade it to run this removal".into(),
        ));
    }
    Ok(())
}

/// Which step's release a runtime in built-in mode asks for (ADR 0048 §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReleaseRequest {
    pub plan_id: String,
    pub generation: u64,
    pub step_id: String,
    /// The step's restore pin, the release a failure restores and a
    /// rollback removes, instead of its target.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restore: bool,
    /// Set by a runtime that removes a non-host removal step's release
    /// (ADR 0049), only for such a step. An older runtime would install it
    /// instead, so the server refuses that package without it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removal: bool,
}

/// The signed release of one claimed step, for a runtime that applies it
/// itself. The runtime trusts none of it until the signature verifies
/// against its own trust roots and the entries hash to the step's artifact
/// digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRelease {
    /// The release manifest text exactly as signed.
    pub manifest: String,
    pub signature: crate::release_signing::SignatureEnvelope,
    /// The executor request the server computed: overlays, configuration
    /// digest, admitted mirror pulls, and the dependency document. Its
    /// host-local fields (workdir, cluster configuration, secret directory)
    /// are empty; the runtime fills them from its own configuration.
    pub request: crate::software_executor::SoftwareApplyRequest,
    /// Every file and directory of the immutable deploy inputs, parents first.
    pub entries: Vec<RuntimeReleaseEntry>,
    /// The release this step replaces, when the step has no restore pin to
    /// read it from, so the runtime keeps the product on one executor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<RuntimeReplacedRelease>,
    /// The sealed values the step names, in its order, with every wrap. The
    /// runtime opens the one wrapped for its own key (ADR 0045 §4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed: Vec<RuntimeSealedValue>,
    /// For a re-wrap step, the public key of the recipient it names. The
    /// runtime checks its fingerprint against the approved step before it
    /// wraps anything for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap_recipient: Option<String>,
    /// For a step that issues a workload certificate, the environment's
    /// current identity issuer, sealed. The runtime uses it only if its
    /// generation and fingerprint are the ones the approved step grants
    /// (ADR 0046 §3). Sent only to a runtime that names `workload_identity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_issuer: Option<crate::identity_issuer::IssuerKey>,
}

/// One sealed value a step writes. The plan step names its digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSealedValue {
    pub secret: String,
    pub key: String,
    pub sealed: crate::sealed_secret::SealedValue,
}

/// The installed release a step replaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReplacedRelease {
    /// Its declared `deploy.executor`, by name. Absent: it declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
}

/// One file or directory of a release's deploy inputs, relative to the
/// release root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReleaseEntry {
    pub path: String,
    /// Permission bits; they are part of the artifact digest.
    pub mode: u32,
    /// Standard base64 of the file's bytes. Absent for a directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHeartbeat {
    pub plan_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryReport {
    pub facts: BTreeMap<String, String>,
    #[serde(default = "default_inventory_source")]
    pub source: String,
}

fn default_inventory_source() -> String {
    crate::inventory::RUNTIME_INVENTORY_SOURCE.into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeInventoryResponse {
    pub environment: String,
    pub source: String,
    pub applied: Vec<String>,
}

/// Every applied-state record the runtime's host applier keeps for the
/// environment (ADR 0048 §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHostRecordsReport {
    pub records: Vec<crate::host_apply::state::AppliedStateRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeHostRecordsResponse {
    /// Products whose reported record was not stored before.
    pub stored: Vec<String>,
}

/// The workload certificates a runtime's targets hold, each with the last
/// renewal attempt it audited (ADR 0046 §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCertificatesReport {
    pub certificates: Vec<crate::certificate_reports::CertificateReport>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeCertificatesResponse {
    /// Instances whose report was further on than the stored one.
    pub stored: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeDeliveryError {
    #[error("missing bearer token")]
    MissingCredential,
    #[error("invalid runtime credential")]
    InvalidCredential,
    #[error("missing runtime instance identity")]
    InvalidInstance,
    #[error("runtime credential is not assigned to this environment")]
    ForeignEnvironment,
    #[error("{0}")]
    InvalidRequest(String),
    /// The server will not hand this step's release to a built-in runtime;
    /// the step fails with this reason.
    #[error("{0}")]
    ReleaseRefused(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Internal(String),
    /// A runner attestation refusal (#675), named by its code.
    #[error(transparent)]
    Attestation(#[from] crate::runner_attestation::AttestationRefusal),
}

struct RuntimeIdentity {
    owner: String,
    /// Digest of the credential or static token: the runner registry id.
    runner_id: String,
    instance: String,
}

/// Who is calling: the `x-tenkai-runtime-instance` header and, when the
/// agent sends one, its `x-tenkai-runtime-version` (#673).
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeCaller<'a> {
    pub instance: Option<&'a str>,
    pub version: Option<&'a str>,
    /// The verified client certificate (DER) of the connection, which names
    /// the runner when the runner CA issued it (#674).
    pub certificate: Option<&'a [u8]>,
    /// The agent named the `workload_identity` capability in
    /// `x-tenkai-runtime-capabilities` (ADR 0046): it runs identity issuer
    /// steps and generates issuer candidates.
    pub workload_identity: bool,
    /// The agent named the `peer_grants` capability: it reads certificate
    /// grants that name peers (ADR 0046 §5), which an older runtime refuses
    /// to decode.
    pub peer_grants: bool,
    /// The agent named the `issuer_rotation` capability: it runs issuer
    /// steps with a rotation phase (ADR 0046 §7), which an older runtime
    /// refuses to decode.
    pub issuer_rotation: bool,
    /// The agent named the `issuer_take_up` capability: it reads the next
    /// issuer's approved add plan in idle work (ADR 0046 §7), which an
    /// older runtime refuses to decode.
    pub issuer_take_up: bool,
    /// The agent named the `issuer_removal` capability: it reads remove
    /// steps and the remove plan's proof (ADR 0046 §7), which an older
    /// runtime refuses to decode.
    pub issuer_removal: bool,
}

/// The capability a runtime names to be offered identity issuer work.
pub const WORKLOAD_IDENTITY_CAPABILITY: &str = "workload_identity";
/// The capability a runtime names to be offered grants with peers.
pub const PEER_GRANTS_CAPABILITY: &str = "peer_grants";
/// The capability a runtime names to be offered issuer rotation steps.
pub const ISSUER_ROTATION_CAPABILITY: &str = "issuer_rotation";
/// The capability a runtime names to be handed the next issuer's proof.
pub const ISSUER_TAKE_UP_CAPABILITY: &str = "issuer_take_up";
/// The capability a runtime names to be offered issuer remove steps.
pub const ISSUER_REMOVAL_CAPABILITY: &str = "issuer_removal";
/// The header a server sends on runtime work naming what it accepts, so a
/// runtime keeps to what an older server decodes.
pub const SERVER_CAPABILITIES_HEADER: &str = "x-tenkai-server-capabilities";
/// The server admits certificate reports with `trust`, `restart_pending`
/// and `observed_at` (ADR 0046 §7).
pub const CERTIFICATE_OBSERVATIONS_CAPABILITY: &str = "certificate_observations";

impl<'a> From<Option<&'a str>> for RuntimeCaller<'a> {
    fn from(instance: Option<&'a str>) -> Self {
        Self {
            instance,
            ..Self::default()
        }
    }
}

/// The runner activity [`RuntimeDeliveryOperations`] records (#673).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Activity {
    Work,
    Heartbeat,
    Inventory,
}

/// Activity is written at most this often per runner instance and kind, so
/// polling does not become a store write per request.
const ACTIVITY_INTERVAL_MS: i64 = 30_000;

/// Last written activity per `(runner, instance, kind)`, with its version.
type ActivityWrites = HashMap<(String, String, Activity), (i64, Option<String>)>;

/// Deep runtime delivery module used after transport extraction.
pub struct RuntimeDeliveryOperations {
    assignments: HashMap<String, String>,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
    /// Last written activity per `(runner, instance, kind)`, with the version
    /// it carried: a write cache only, so each replica keeps its own.
    activity: std::sync::Mutex<ActivityWrites>,
    /// Issues runner certificates at enrollment and binds presented ones to
    /// a runner (#674). Without it, certificates name no runner.
    runner_ca: Option<Arc<crate::runner_ca::RunnerCa>>,
}

impl RuntimeDeliveryOperations {
    pub fn new(
        assignments: HashMap<String, String>,
        reconciler: Arc<dyn ReconcilePort>,
        store: Arc<dyn OperationalStore>,
    ) -> Self {
        Self {
            assignments,
            reconciler,
            store,
            activity: std::sync::Mutex::new(HashMap::new()),
            runner_ca: None,
        }
    }

    /// Issue and accept runner certificates from `ca` (#674).
    pub fn with_runner_ca(mut self, ca: Arc<crate::runner_ca::RunnerCa>) -> Self {
        self.runner_ca = Some(ca);
        self
    }

    /// Record what an admitted runner instance did, throttled. Activity is
    /// an operator view, not delivery state: a failed write is reported and
    /// the request goes on.
    fn note_activity(
        &self,
        identity: &RuntimeIdentity,
        environment: &str,
        version: Option<&str>,
        kind: Activity,
    ) {
        let version = version
            .filter(|version| !version.is_empty() && version.len() <= 64 && version.is_ascii())
            .map(str::to_string);
        let now = crate::now_millis();
        let key = (identity.runner_id.clone(), identity.instance.clone(), kind);
        {
            let mut written = self
                .activity
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some((at, recorded)) = written.get(&key)
                && now - at < ACTIVITY_INTERVAL_MS
                && (version.is_none() || version == *recorded)
            {
                return;
            }
            written.insert(key, (now, version.clone()));
        }
        let at = Some(now);
        let record = crate::storage::RuntimeActivityRecord {
            runner_id: identity.runner_id.clone(),
            instance_id: identity.instance.clone(),
            environment_id: environment.into(),
            owner: identity.owner.clone(),
            runtime_version: version,
            last_work_at: at.filter(|_| kind == Activity::Work),
            last_heartbeat_at: at.filter(|_| kind == Activity::Heartbeat),
            last_inventory_at: at.filter(|_| kind == Activity::Inventory),
        };
        if let Err(error) = self.store.record_runtime_activity(&record) {
            eprintln!("recording runtime activity failed (continuing): {error}");
        }
    }

    /// Record that `runner_id` was issued a certificate, which the registry
    /// reports as its `auth` (#809). Like activity it is an operator view:
    /// a failed write is reported, the certificate still returned, and the
    /// runner reads as `bearer` until its next renewal records it.
    fn note_certificate(&self, runner_id: &str, environment: &str) {
        if let Err(error) =
            self.store
                .record_runtime_certificate(runner_id, environment, crate::now_millis())
        {
            eprintln!("recording a runner certificate failed (continuing): {error}");
        }
    }

    pub async fn claim_work(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
    ) -> Result<RuntimeWork, RuntimeDeliveryError> {
        let caller = caller.into();
        let mut work = self.claim_plan(token, &caller, environment).await?;
        if caller.workload_identity && work.plan.is_none() {
            work.issuer_candidate = self.issuer_candidate_request(environment).await?;
        }
        // With claimed work too: a runtime must trust both issuers before
        // a step issues a certificate.
        if caller.issuer_take_up {
            work.issuer_proofs = self.issuer_proofs(environment, caller.issuer_removal).await;
        }
        Ok(work)
    }

    /// The approved add plan of `environment`'s next issuer, while one
    /// waits. Optional: a runtime that misses it keeps the bundles it has,
    /// and the next idle poll retries.
    async fn issuer_proofs(
        &self,
        environment: &str,
        removal: bool,
    ) -> Vec<crate::identity_issuer::IssuerProof> {
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Vec::new();
        };
        let proofs = async {
            let env_obj = crate::environment::environment(&mut ctx, environment).await?;
            // The issue plan travels with the issuer as it is now, so a
            // runtime wrapped since opens it.
            // The remove plan tells each runtime to drop the issuer it
            // removed from its bundles.
            let plan_ids = [
                (crate::identity_issuer::next_plan(&env_obj), None),
                (
                    crate::identity_issuer::previous_plan(&env_obj),
                    crate::identity_issuer::current(&env_obj)?,
                ),
                (
                    crate::identity_issuer::removed_plan(&env_obj).filter(|_| removal),
                    None,
                ),
            ];
            let mut proofs = Vec::new();
            for (plan_id, current) in plan_ids {
                let Some(plan_id) = plan_id else {
                    continue;
                };
                let plan = crate::plan::load(&mut ctx, plan_id).await?;
                let mut approvals =
                    crate::plan_approval::list_collected_envelopes(&mut ctx, &plan.id).await?;
                let mut seen = std::collections::BTreeSet::new();
                approvals.retain(|envelope| seen.insert(envelope.signature.clone()));
                proofs.push(crate::identity_issuer::IssuerProof {
                    plan,
                    approvals,
                    current,
                });
            }
            anyhow::Ok(proofs)
        }
        .await;
        proofs.unwrap_or_else(|error| {
            eprintln!("reading the identity issuer proofs of {environment} failed: {error:#}");
            Vec::new()
        })
    }

    /// What an idle runtime that names `workload_identity` should generate:
    /// a candidate for the requested issuer generation, while none is
    /// uploaded (ADR 0046 §2).
    async fn issuer_candidate_request(
        &self,
        environment: &str,
    ) -> Result<Option<crate::identity_issuer::CandidateRequest>, RuntimeDeliveryError> {
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Ok(None);
        };
        let unavailable =
            |error: anyhow::Error| RuntimeDeliveryError::Unavailable(error.to_string());
        let env_obj = crate::environment::environment(&mut ctx, environment)
            .await
            .map_err(unavailable)?;
        Ok(crate::identity_issuer::wanted_generation(&env_obj)
            .map_err(unavailable)?
            .map(|generation| crate::identity_issuer::CandidateRequest { generation }))
    }

    /// Store a runtime's identity issuer candidate (ADR 0046 §2). The first
    /// candidate for the requested generation is kept and returned to every
    /// later upload, so a runtime whose candidate lost discards its key.
    pub async fn upload_issuer_candidate(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        candidate: crate::identity_issuer::IssuerKey,
    ) -> Result<crate::identity_issuer::IssuerKey, RuntimeDeliveryError> {
        let caller = caller.into();
        let identity = self.admit_work(token, &caller, environment).await?;
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "identity issuer unavailable".into(),
            ));
        };
        // The uploader's own key is read inside the lease, so a revocation
        // that finished before it is never undone by this upload.
        crate::identity_issuer::store_candidate(&mut ctx, environment, candidate, || {
            self.own_recipient_fingerprint(&identity, environment)
                .map_err(|error| anyhow::anyhow!("{error}"))
        })
        .await
        .map_err(|error| RuntimeDeliveryError::Conflict(format!("{error:#}")))
    }

    async fn claim_plan(
        &self,
        token: Option<&str>,
        caller: &RuntimeCaller<'_>,
        environment: &str,
    ) -> Result<RuntimeWork, RuntimeDeliveryError> {
        let caller = *caller;
        let identity = self.admit_work(token, &caller, environment).await?;
        self.note_activity(&identity, environment, caller.version, Activity::Work);
        // While the server may still run a plan it began before a runtime
        // enrolled (#630), no plan is handed out. Checked before the plan is
        // chosen, so one the server finished meanwhile is seen as finished.
        // The server checks enrollment under that lease, so the two never
        // execute one environment together.
        {
            let Some(mut ctx) = self.reconciler.application_ctx() else {
                return Err(RuntimeDeliveryError::Unavailable(
                    "application core is not available on this host".into(),
                ));
            };
            match crate::apply::runtime_may_take_over(&mut ctx, environment).await {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(idle_work(environment));
                }
                Err(error) => return Err(RuntimeDeliveryError::Unavailable(error.to_string())),
            }
        }
        let plan = self
            .reconciler
            .pending_work(environment.to_string())
            .await
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        let Some(plan) = plan else {
            return Ok(idle_work(environment));
        };
        // Only a runtime that names `workload_identity` runs an identity
        // issuer step; an older one waits, so it never fails the plan.
        // Blocking an issuer plan no runtime can open executes nothing, so
        // any runtime does it, whatever its capability.
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "software compatibility preflight unavailable".into(),
            ));
        };
        if let Some(reason) = self.issuer_unrunnable(&mut ctx, &plan, environment).await? {
            return self
                .retire_unrunnable(&mut ctx, environment, plan, &identity.owner, reason)
                .await;
        }
        if !caller.workload_identity && plan.steps.iter().any(needs_workload_identity) {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        // An older runtime cannot decode a grant that names peers, so it
        // waits while a newer one takes the plan.
        let names_peers =
            |step: &crate::plan::Step| step.identity_grants().any(|grant| !grant.peers.is_empty());
        if !caller.peer_grants && plan.steps.iter().any(names_peers) {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        // Likewise for an issuer step with a rotation phase.
        let rotates = |step: &crate::plan::Step| {
            step.issuer
                .as_ref()
                .is_some_and(|issuer| issuer.phase.is_some())
        };
        if !caller.issuer_rotation && plan.steps.iter().any(rotates) {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        // And for an issue step naming the issuer it replaces.
        let replaces = |step: &crate::plan::Step| {
            step.issuer
                .as_ref()
                .is_some_and(|issuer| issuer.replaces.is_some())
        };
        if !caller.issuer_take_up && plan.steps.iter().any(replaces) {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        // And for a remove step, whose phase an older runtime cannot read.
        let removes = |step: &crate::plan::Step| {
            step.issuer.as_ref().is_some_and(|issuer| {
                issuer.phase == Some(crate::identity_issuer::RotationPhase::Remove)
            })
        };
        if !caller.issuer_removal && plan.steps.iter().any(removes) {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        // A re-wrap step or a removal deploys nothing, so it needs no
        // deployment preflight.
        for step in plan
            .steps
            .iter()
            .filter(|step| step.deploys_release() && step.action != crate::plan::Action::Remove)
        {
            crate::software_compatibility::require_release(
                &mut ctx,
                environment,
                &step.release_id,
                step.instance_name(),
            )
            .await
            .map_err(|error| match error
                .downcast_ref::<crate::software_compatibility::CompatibilityBlocked>(
            ) {
                Some(blocked) => RuntimeDeliveryError::InvalidRequest(blocked.to_string()),
                None => RuntimeDeliveryError::Unavailable(
                    "software compatibility preflight unavailable".into(),
                ),
            })?;
        }
        // A held queued plan stays queued; a claimed Running plan finishes.
        let held = plan.state == crate::plan::PlanState::Computed
            && crate::delivery_hold::active_for_plan(&mut ctx, &plan)
                .await
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?
                .is_some();
        if held {
            return Ok(idle_work(environment));
        }
        // Recovered wraps open only for the runtime whose key the step names
        // (ADR 0045 §7); another runtime would fail the plan, so it waits.
        if !self
            .may_run_recovery(&mut ctx, &plan, &identity, environment)
            .await?
        {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        // A drifted clock must not touch leases: it could expire or take
        // over another runtime's claim. Only a durable completion this owner
        // already holds may replay, which reads and grants nothing.
        if let Err(refusal) = crate::clock_guard::require_trusted_time("runtime lease claim") {
            return match self
                .store
                .durable_runtime_completion(&plan.id, &identity.owner)
            {
                Ok(Some(claim)) => Ok(RuntimeWork {
                    environment: environment.into(),
                    plan: Some(plan),
                    claim: Some(claim),
                    approvals: Vec::new(),
                    issuer_candidate: None,
                    issuer_proofs: Vec::new(),
                }),
                _ => Err(RuntimeDeliveryError::Unavailable(refusal.to_string())),
            };
        }
        let expires_at = crate::now_millis().saturating_add(2 * 60 * 1000);
        let claim = self
            .store
            .claim_runtime_plan(environment, &plan.id, &identity.owner, expires_at)
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        match claim {
            Some(claim) => {
                // A runtime's plan stays Computed until its completion is
                // durable, so a fresh claim on a Running plan means the server
                // began it, before a runtime enrolled (#630). No server lease
                // is left (checked above, an expired one taken over), so it
                // stopped: fail the plan as server recovery does, rather than
                // run it again from its first step. Recovery, such as a
                // rollback, is the next plan.
                if claim.completion_json.is_none() && plan.state == crate::plan::PlanState::Running
                {
                    let mut abandoned = plan;
                    crate::plan::transition(
                        &mut ctx,
                        &mut abandoned,
                        crate::plan::Transition::new(
                            crate::plan::PlanState::Failed,
                            "controller stopped after execution began; lease expired before recovery",
                        ),
                        crate::plan::Persistence::Standard,
                    )
                    .await
                    .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
                    return Ok(idle_work(environment));
                }
                // Placement admits new execution only: a claim holding a
                // durable completion is replayed whatever the facts say now.
                if claim.completion_json.is_none() {
                    require_runtime_placement(&mut ctx, environment, &plan).await?;
                }
                delivered_work(&mut ctx, environment, plan, claim).await
            }
            None => self.idle_after_lapsed(environment, &plan.id).await,
        }
    }

    /// Why `plan` has an issuer or workload certificate step no runtime can
    /// run to completion, if it has one: every key wrapping the issuer key
    /// was revoked, so no runtime claims it; or the issuer changed since it
    /// was planned (a re-wrap planned before a rotation finished, or a
    /// certificate granted from the previous issuer), so its completion or
    /// issuance would be refused. Either would block the environment.
    async fn issuer_unrunnable(
        &self,
        ctx: &mut Ctx,
        plan: &crate::plan::Plan,
        environment: &str,
    ) -> Result<Option<&'static str>, RuntimeDeliveryError> {
        if !plan.steps.iter().any(needs_workload_identity) {
            return Ok(None);
        }
        let env_obj = crate::environment::environment(ctx, environment)
            .await
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        let current = crate::identity_issuer::current(&env_obj)
            .map_err(|error| RuntimeDeliveryError::Internal(error.to_string()))?;
        let stale_issuer = plan
            .steps
            .iter()
            .filter(|step| step.issuer.is_some())
            .any(|step| crate::identity_issuer::require_current(&env_obj, step).is_err());
        // A certificate is issued only from the granted issuer; once it
        // rotated, the grant names a key the runtime will not use.
        let stale_grant = plan
            .steps
            .iter()
            .flat_map(|step| step.identity_grants())
            .any(|grant| {
                current.as_ref().is_none_or(|issuer| {
                    issuer.generation != grant.issuer_generation
                        || issuer.fingerprint != grant.issuer_fingerprint
                })
            });
        if stale_issuer || stale_grant {
            return Ok(Some(
                "the identity issuer changed since this plan was made; plan again",
            ));
        }
        if !self
            .environment_recipient_keys(environment)?
            .iter()
            .any(|record| {
                recovery_claimable(plan, Some(record.fingerprint.as_str()), current.as_ref())
            })
        {
            return Ok(Some(
                "no unrevoked runtime holds the identity issuer key; prepare a new candidate",
            ));
        }
        Ok(None)
    }

    /// Block an [`issuer_unrunnable`](Self::issuer_unrunnable) plan, which
    /// takes it out of the queue so the environment moves on. The caller
    /// first takes the plan's runtime claim, which it gets only when no
    /// other claim is live and none holds a durable completion, so a stored
    /// completion is applied, never discarded.
    async fn retire_unrunnable(
        &self,
        ctx: &mut Ctx,
        environment: &str,
        mut plan: crate::plan::Plan,
        owner: &str,
        reason: &str,
    ) -> Result<RuntimeWork, RuntimeDeliveryError> {
        if crate::clock_guard::require_trusted_time("runtime lease claim").is_err() {
            return Ok(idle_work(environment));
        }
        let claim = self
            .store
            .claim_runtime_plan(
                environment,
                &plan.id,
                owner,
                crate::now_millis().saturating_add(2 * 60 * 1000),
            )
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        if claim.is_none_or(|claim| claim.completion_json.is_some()) {
            return self.idle_after_lapsed(environment, &plan.id).await;
        }
        crate::plan::transition(
            ctx,
            &mut plan,
            crate::plan::Transition::new(crate::plan::PlanState::Blocked, reason),
            crate::plan::Persistence::Standard,
        )
        .await
        .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        Ok(idle_work(environment))
    }

    /// Idle work for a runtime that may not run `plan_id`. Another runtime's
    /// claim may hold a durable completion: if it stopped, or was revoked,
    /// before the completion was applied, the server applies it once that
    /// claim lapses (#630). This runs before any capability or key check
    /// would turn the caller away, since replaying executes nothing, so a
    /// plan only its lost runtime could run never blocks the environment.
    async fn idle_after_lapsed(
        &self,
        environment: &str,
        plan_id: &str,
    ) -> Result<RuntimeWork, RuntimeDeliveryError> {
        // A drifted clock cannot tell that a claim lapsed.
        if crate::clock_guard::require_trusted_time("runtime lease claim").is_ok() {
            let lapsed = self
                .store
                .lapsed_runtime_completion(environment, plan_id, crate::now_millis())
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
            if let Some(completion_json) = lapsed {
                let completion: RuntimeCompletion = serde_json::from_str(&completion_json)
                    .map_err(|error| RuntimeDeliveryError::Internal(error.to_string()))?;
                self.apply_completion(environment, completion).await?;
            }
        }
        Ok(idle_work(environment))
    }

    pub async fn complete(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        completion: RuntimeCompletion,
    ) -> Result<(), RuntimeDeliveryError> {
        let caller = caller.into();
        let identity = self.admit_work(token, &caller, environment).await?;
        let completion_json = serde_json::to_string(&completion)
            .map_err(|error| RuntimeDeliveryError::InvalidRequest(error.to_string()))?;
        self.reconciler
            .validate_completion(environment.to_string(), completion.clone())
            .await
            .map_err(|error| RuntimeDeliveryError::InvalidRequest(format!("{error:#}")))?;
        self.store
            .complete_runtime_plan(
                &completion.plan_id,
                &identity.owner,
                completion.generation,
                &completion_json,
            )
            .map_err(|error| RuntimeDeliveryError::Conflict(error.to_string()))?;
        self.apply_completion(environment, completion).await
    }

    /// Apply a completion, keeping only wraps for recipients that are still
    /// unrevoked (ADR 0045 §5). Revocation records itself before it drops a
    /// key's wraps, so a recipient revoked while this runs is caught by the
    /// check after it, and its wraps are dropped again: whichever finishes
    /// last leaves none. A replayed completion runs the same checks.
    async fn apply_completion(
        &self,
        environment: &str,
        mut completion: RuntimeCompletion,
    ) -> Result<(), RuntimeDeliveryError> {
        if !wrapped_recipients(&completion).is_empty() {
            let Some(mut ctx) = self.reconciler.application_ctx() else {
                return Err(RuntimeDeliveryError::Unavailable(
                    "sealed values unavailable".into(),
                ));
            };
            let plan = crate::plan::load(&mut ctx, &completion.plan_id)
                .await
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
            let wraps = completion_wraps(&plan, &completion);
            crate::sealed_secret::store_completion_wraps(&mut ctx, environment, &wraps, || {
                self.recipient_fingerprints(environment)
                    .map_err(|error| anyhow::anyhow!("{error}"))
            })
            .await
            .map_err(|error| {
                RuntimeDeliveryError::Unavailable(format!(
                    "storing the re-wrapped sealed values: {error:#}"
                ))
            })?;
            // Stored; the plan's completion carries nothing more to apply.
            retain_recipient_wraps(&mut completion, &Default::default());
        }
        if completion.succeeded {
            self.record_activated_issuers(environment, &completion)
                .await?;
        }
        self.reconciler
            .complete_work(environment.to_string(), completion)
            .await
            .map_err(|error| RuntimeDeliveryError::Internal(format!("{error:#}")))
    }

    /// Record the issuers a succeeded completion's steps activated, under
    /// the environment lease, before the plan finishes (ADR 0046 §2).
    async fn record_activated_issuers(
        &self,
        environment: &str,
        completion: &RuntimeCompletion,
    ) -> Result<(), RuntimeDeliveryError> {
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "identity issuer unavailable".into(),
            ));
        };
        let plan = crate::plan::load(&mut ctx, &completion.plan_id)
            .await
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        // An applied completion recorded its issuer already; a later
        // rotation must not turn its replay into a stale refusal.
        if matches!(
            plan.state,
            crate::plan::PlanState::Succeeded | crate::plan::PlanState::Failed
        ) {
            return Ok(());
        }
        let activated: Vec<&crate::plan::Step> = plan
            .steps
            .iter()
            .filter(|step| step.issuer.is_some() && step.rewrap.is_none())
            .collect();
        crate::identity_issuer::record_activated(&mut ctx, environment, &plan.id, &activated)
            .await
            .map_err(|error| {
                RuntimeDeliveryError::Unavailable(format!(
                    "recording the identity issuer: {error:#}"
                ))
            })
    }

    /// Fingerprints of `environment`'s unrevoked recipient keys.
    fn recipient_fingerprints(
        &self,
        environment: &str,
    ) -> Result<std::collections::BTreeSet<String>, RuntimeDeliveryError> {
        Ok(self
            .environment_recipient_keys(environment)?
            .into_iter()
            .filter_map(|record| {
                crate::sealing_key::SealingPublicKey::from_wire(&record.public_key)
                    .ok()
                    .map(|key| key.fingerprint())
            })
            .collect())
    }

    pub async fn renew(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        heartbeat: &RuntimeHeartbeat,
    ) -> Result<RuntimeClaim, RuntimeDeliveryError> {
        let caller = caller.into();
        let identity = self.admit_work(token, &caller, environment).await?;
        self.note_activity(&identity, environment, caller.version, Activity::Heartbeat);
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "software compatibility preflight unavailable".into(),
            ));
        };
        let plan = crate::plan::load(&mut ctx, &heartbeat.plan_id)
            .await
            .map_err(|_| {
                RuntimeDeliveryError::Unavailable(
                    "software compatibility preflight unavailable".into(),
                )
            })?;
        if plan.environment != environment {
            return Err(RuntimeDeliveryError::ForeignEnvironment);
        }
        // A re-wrap step or a removal deploys nothing, so it needs no
        // deployment preflight.
        for step in plan
            .steps
            .iter()
            .filter(|step| step.deploys_release() && step.action != crate::plan::Action::Remove)
        {
            crate::software_compatibility::require_release(
                &mut ctx,
                environment,
                &step.release_id,
                step.instance_name(),
            )
            .await
            .map_err(|error| match error
                .downcast_ref::<crate::software_compatibility::CompatibilityBlocked>(
            ) {
                Some(blocked) => RuntimeDeliveryError::InvalidRequest(blocked.to_string()),
                None => RuntimeDeliveryError::Unavailable(
                    "software compatibility preflight unavailable".into(),
                ),
            })?;
        }
        let expires_at = crate::now_millis().saturating_add(2 * 60 * 1000);
        let claim = self
            .store
            .renew_runtime_plan(
                &heartbeat.plan_id,
                &identity.owner,
                heartbeat.generation,
                expires_at,
            )
            .map_err(|error| RuntimeDeliveryError::Conflict(error.to_string()))?
            .ok_or_else(|| {
                RuntimeDeliveryError::Conflict("runtime claim is no longer active".into())
            })?;
        // A placement change during execution withdraws permission for the
        // remaining steps; a recorded completion still replays.
        if claim.completion_json.is_none() {
            require_runtime_placement(&mut ctx, environment, &plan).await?;
        }
        Ok(claim)
    }

    /// One binary of the agent's own release, for the claimed runtime that
    /// runs that plan step (#685): pull-only, so an agent on another host
    /// needs no access to the server's files. The claim is renewed first, so
    /// only its current holder is served. Returns the bytes and their mode;
    /// the agent checks both against the signed artifact digest.
    pub async fn self_release_file(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        request: &RuntimeSelfReleaseFile,
    ) -> Result<(Vec<u8>, u32), RuntimeDeliveryError> {
        if !crate::runtime_self_upgrade::BINARIES.contains(&request.name.as_str()) {
            return Err(RuntimeDeliveryError::InvalidRequest(
                "not a runtime agent binary".into(),
            ));
        }
        self.renew(
            token,
            caller.into(),
            environment,
            &RuntimeHeartbeat {
                plan_id: request.plan_id.clone(),
                generation: request.generation,
            },
        )
        .await?;
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "plans unavailable".into(),
            ));
        };
        let plan = crate::plan::load(&mut ctx, &request.plan_id)
            .await
            .map_err(|_| RuntimeDeliveryError::Unavailable("plans unavailable".into()))?;
        let step = plan
            .steps
            .iter()
            .find(|step| {
                step.id == request.step_id
                    && step.product == crate::runtime_self_upgrade::SELF_PRODUCT
            })
            .ok_or_else(|| {
                RuntimeDeliveryError::InvalidRequest(
                    "the plan has no runtime agent step with that id".into(),
                )
            })?;
        let path = std::path::Path::new(&step.workdir).join(&request.name);
        let read = || -> std::io::Result<(Vec<u8>, u32)> {
            use std::os::unix::fs::PermissionsExt as _;
            let file = std::fs::File::open(&path)?;
            let mode = file.metadata()?.permissions().mode() & 0o7777;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut &file, &mut bytes)?;
            Ok((bytes, mode))
        };
        read().map_err(|_| {
            RuntimeDeliveryError::Unavailable("runtime agent release content unavailable".into())
        })
    }

    /// The signed release of a step of the plan this runtime holds (ADR 0048
    /// §3). Renews the claim first, so a fenced runtime gets nothing.
    pub async fn release(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        request: &RuntimeReleaseRequest,
    ) -> Result<RuntimeRelease, RuntimeDeliveryError> {
        self.renew(
            token,
            caller.into(),
            environment,
            &RuntimeHeartbeat {
                plan_id: request.plan_id.clone(),
                generation: request.generation,
            },
        )
        .await?;
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "plans unavailable".into(),
            ));
        };
        let plan = crate::plan::load(&mut ctx, &request.plan_id)
            .await
            .map_err(|_| RuntimeDeliveryError::Unavailable("plans unavailable".into()))?;
        let Some(step) = plan.steps.iter().find(|step| step.id == request.step_id) else {
            return Err(RuntimeDeliveryError::ReleaseRefused(
                "the plan has no step with that id".into(),
            ));
        };
        refuse_removal_by_older_runtime(step, request)?;
        let mut release = crate::apply::runtime_release(&mut ctx, &plan, step, request.restore)
            .await
            .map_err(
                |error| match error.downcast_ref::<crate::apply::ReleaseRefused>() {
                    Some(refused) => RuntimeDeliveryError::ReleaseRefused(refused.to_string()),
                    // May pass: the runtime keeps its claim and asks again.
                    None => {
                        eprintln!("building a runtime release package failed: {error:#}");
                        RuntimeDeliveryError::Unavailable("release package unavailable".into())
                    }
                },
            )?;
        // A re-wrap step names its recipient by fingerprint; the runtime
        // needs the public key, which only an unrevoked recipient or the
        // current recovery key (ADR 0045 §7) still has.
        if let Some(rewrap) = &step.rewrap {
            let recovery = crate::sealed_secret::stored_recovery_key(&mut ctx, environment)
                .await
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
            let recipient = self
                .environment_recipient_keys(environment)?
                .into_iter()
                .filter_map(|record| {
                    crate::sealing_key::SealingPublicKey::from_wire(&record.public_key).ok()
                })
                .chain(recovery)
                .find(|key| key.fingerprint() == rewrap.fingerprint)
                .map(|key| key.to_wire())
                .ok_or_else(|| {
                    RuntimeDeliveryError::ReleaseRefused(format!(
                        "{} is no longer an unrevoked recipient key of {environment}",
                        rewrap.fingerprint
                    ))
                })?;
            release.rewrap_recipient = Some(recipient);
        }
        Ok(release)
    }

    /// Admit the host applier's applied-state records a runtime reports for
    /// its environment (ADR 0048 §2). Returns the products whose record was
    /// new; planning uses the most advanced record of each product.
    pub async fn report_host_records(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        report: &RuntimeHostRecordsReport,
    ) -> Result<RuntimeHostRecordsResponse, RuntimeDeliveryError> {
        let caller = caller.into();
        let identity = self.admit_work(token, &caller, environment).await?;
        self.note_activity(&identity, environment, caller.version, Activity::Inventory);
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "environment state unavailable".into(),
            ));
        };
        let stored = crate::host_records::admit(&mut ctx, environment, &report.records)
            .await
            .map_err(|error| RuntimeDeliveryError::InvalidRequest(format!("{error:#}")))?;
        Ok(RuntimeHostRecordsResponse { stored })
    }

    /// Admit the workload certificate state a runtime reports for its
    /// environment (ADR 0046 §3), which `status` shows.
    pub async fn report_certificates(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        report: &RuntimeCertificatesReport,
    ) -> Result<RuntimeCertificatesResponse, RuntimeDeliveryError> {
        let caller = caller.into();
        let identity = self.admit_work(token, &caller, environment).await?;
        self.note_activity(&identity, environment, caller.version, Activity::Inventory);
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "environment state unavailable".into(),
            ));
        };
        let stored = crate::certificate_reports::admit(&mut ctx, environment, &report.certificates)
            .await
            .map_err(|error| RuntimeDeliveryError::InvalidRequest(format!("{error:#}")))?;
        Ok(RuntimeCertificatesResponse { stored })
    }

    pub async fn report_inventory(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'_>>,
        environment: &str,
        report: RuntimeInventoryReport,
    ) -> Result<RuntimeInventoryResponse, RuntimeDeliveryError> {
        let caller = caller.into();
        let identity = self.admit_work(token, &caller, environment).await?;
        self.note_activity(&identity, environment, caller.version, Activity::Inventory);
        validate_inventory_source(&report.source)?;
        let applied = self
            .reconciler
            .apply_inventory_facts(environment.to_string(), report.facts)
            .await;
        let applied = match applied {
            Ok(applied) => applied,
            Err(error) => {
                if let Some(refusal) =
                    error.downcast_ref::<crate::runner_attestation::AttestationRefusal>()
                {
                    let refusal = refusal.clone();
                    self.refuse_attestation(environment, Some(&identity.runner_id), &refusal)
                        .await;
                    return Err(refusal.into());
                }
                return Err(RuntimeDeliveryError::InvalidRequest(format!("{error:#}")));
            }
        };
        Ok(RuntimeInventoryResponse {
            environment: environment.into(),
            source: report.source,
            applied,
        })
    }

    /// [`Self::admit`] for the work routes (claim, heartbeat and with it
    /// self-release, completion, inventory). While the environment requires
    /// runner attestation (#675), only a runner certificate admits: a bearer
    /// alone, enrolled or static, is refused with
    /// `attestation_requires_client_certificate`, so a copied bearer cannot
    /// outlive one certificate. The bearer still renews a certificate.
    async fn admit_work(
        &self,
        token: Option<&str>,
        caller: &RuntimeCaller<'_>,
        environment: &str,
    ) -> Result<RuntimeIdentity, RuntimeDeliveryError> {
        let identity = self.admit(token, caller, environment)?;
        let certified = caller.certificate.is_some() && self.runner_ca.is_some();
        // The policy lives in the application core; a host without one (a
        // custom port) holds no policy, and its work routes are unchanged.
        let has_core = self.reconciler.application_ctx().is_some();
        if !certified && has_core && self.attestation_policy(environment).await?.is_some() {
            let refusal = crate::runner_attestation::AttestationRefusal::ClientCertificateRequired;
            self.refuse_attestation(environment, Some(&identity.runner_id), &refusal)
                .await;
            return Err(refusal.into());
        }
        Ok(identity)
    }

    fn admit(
        &self,
        token: Option<&str>,
        caller: &RuntimeCaller<'_>,
        environment: &str,
    ) -> Result<RuntimeIdentity, RuntimeDeliveryError> {
        let instance = caller.instance;
        // A runner-CA certificate names the runner, and is preferred to any
        // bearer the request also carries (#674).
        if let (Some(certificate), Some(ca)) = (caller.certificate, &self.runner_ca) {
            return self.admit_certificate(ca, certificate, instance, environment);
        }
        let token = token
            .filter(|token| !token.is_empty())
            .ok_or(RuntimeDeliveryError::MissingCredential)?;
        let assigned = match runtime_assignment(&self.assignments, token) {
            Some(environment) => environment,
            None => self.enrolled_environment(token)?,
        };
        let instance = instance
            .filter(|instance| !instance.is_empty() && instance.len() <= 128 && instance.is_ascii())
            .ok_or(RuntimeDeliveryError::InvalidInstance)?;
        if assigned != environment {
            return Err(RuntimeDeliveryError::ForeignEnvironment);
        }
        Ok(RuntimeIdentity {
            owner: runtime_owner(token, instance),
            runner_id: crate::runtime_credentials::digest(token),
            instance: instance.into(),
        })
    }
}

impl RuntimeDeliveryOperations {
    /// The runner a runner-CA certificate names: issued by the runner CA,
    /// valid now, for this environment, and its credential enrolled and not
    /// revoked in the registry. Anything else is refused, not retried as a
    /// bearer: a presented runner certificate is the claimed identity.
    fn admit_certificate(
        &self,
        ca: &crate::runner_ca::RunnerCa,
        certificate: &[u8],
        instance: Option<&str>,
        environment: &str,
    ) -> Result<RuntimeIdentity, RuntimeDeliveryError> {
        let named = ca
            .verify(certificate, crate::now_millis() / 1_000)
            .map_err(|_| RuntimeDeliveryError::InvalidCredential)?;
        let instance = instance
            .filter(|instance| !instance.is_empty() && instance.len() <= 128 && instance.is_ascii())
            .ok_or(RuntimeDeliveryError::InvalidInstance)?;
        match self.store.runtime_credential(&named.runner_id) {
            Ok(Some(record))
                if record.revoked_at.is_none() && record.environment_id == named.environment => {}
            Ok(_) => return Err(RuntimeDeliveryError::InvalidCredential),
            Err(error) => return Err(RuntimeDeliveryError::Unavailable(error.to_string())),
        }
        if named.environment != environment {
            return Err(RuntimeDeliveryError::ForeignEnvironment);
        }
        Ok(RuntimeIdentity {
            // The lease owner follows the runner, not one certificate, so a
            // renewed certificate keeps the claims of its runner.
            owner: runtime_owner(&named.runner_id, instance),
            runner_id: named.runner_id,
            instance: instance.into(),
        })
    }
}

/// A renewal of a runner certificate (#674): a CSR over the agent's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCertificateRequest {
    pub csr: String,
    /// Host evidence signed with the CSR key (#675). Sent only once the
    /// server asked for it with `attestation_missing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<crate::runner_attestation::RunnerAttestation>,
    /// HPKE P-256 sealing public key (ADR 0045). Absent on older runtimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing_public_key: Option<String>,
}

/// A renewed runner certificate and the runner CA that issued it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCertificate {
    pub certificate: String,
    pub ca: String,
}

impl RuntimeDeliveryOperations {
    /// A new runner certificate for the runner calling: named by its current
    /// runner certificate, or, once that has expired, by its enrolled bearer
    /// credential. Static tokens name no registry runner and get none.
    ///
    /// Under the environment's runner attestation policy (#675), the request
    /// must carry evidence signed by the CSR key, and that key must be the
    /// presented certificate's, or, on the bearer path, the runner's last
    /// bound key: no key rotation under the policy.
    pub async fn renew_certificate<'a>(
        &self,
        token: Option<&str>,
        caller: impl Into<RuntimeCaller<'a>>,
        environment: &str,
        request: &RuntimeCertificateRequest,
    ) -> Result<RuntimeCertificate, RuntimeDeliveryError> {
        let caller = caller.into();
        let ca = self.runner_ca.as_ref().ok_or_else(|| {
            RuntimeDeliveryError::InvalidRequest("this server has no runner CA".into())
        })?;
        let identity = self.admit(token, &caller, environment)?;
        if caller.certificate.is_none()
            && token.is_some_and(|token| runtime_assignment(&self.assignments, token).is_some())
        {
            return Err(RuntimeDeliveryError::InvalidRequest(
                "a static runtime token names no enrolled runner to certify".into(),
            ));
        }
        let binding = match self
            .renewal_binding(
                environment,
                &identity.runner_id,
                caller.certificate,
                request,
            )
            .await
        {
            Ok(binding) => binding,
            Err(RuntimeDeliveryError::Attestation(refusal)) => {
                self.refuse_attestation(environment, Some(&identity.runner_id), &refusal)
                    .await;
                return Err(refusal.into());
            }
            Err(error) => return Err(error),
        };
        if let Some(binding) = &binding {
            self.bind_attestation(environment, &identity.runner_id, binding)?;
        }
        let sealing = parse_sealing_key(request.sealing_public_key.as_deref())?;
        let certificate = ca
            .issue_bound(
                &request.csr,
                &crate::runner_ca::RunnerIdentity {
                    environment: environment.into(),
                    runner_id: identity.runner_id.clone(),
                },
                crate::now_millis() / 1_000,
                binding.as_ref(),
            )
            .map_err(|error| RuntimeDeliveryError::InvalidRequest(format!("{error:#}")))?;
        self.note_certificate(&identity.runner_id, environment);
        if let Some(key) = sealing {
            self.record_sealing_key(environment, &identity.runner_id, key)?;
        }
        Ok(RuntimeCertificate {
            certificate,
            ca: ca.trust_bundle(),
        })
    }

    fn record_sealing_key(
        &self,
        environment: &str,
        runner_id: &str,
        key: crate::sealing_key::SealingPublicKey,
    ) -> Result<(), RuntimeDeliveryError> {
        self.store
            .record_runtime_sealing_key(&crate::storage::RuntimeSealingKeyRecord {
                runner_id: runner_id.into(),
                environment_id: environment.into(),
                public_key: key.to_wire(),
                fingerprint: key.fingerprint(),
                recorded_at: crate::now_millis(),
            })
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))
    }

    /// Unrevoked runtimes of `environment` that advertised a sealing key.
    /// Whether `identity` may claim `plan` ([`recovery_claimable`]).
    async fn may_run_recovery(
        &self,
        ctx: &mut Ctx,
        plan: &crate::plan::Plan,
        identity: &RuntimeIdentity,
        environment: &str,
    ) -> Result<bool, RuntimeDeliveryError> {
        if !plan.steps.iter().any(|step| {
            needs_workload_identity(step)
                || step
                    .rewrap
                    .as_ref()
                    .is_some_and(|rewrap| !rewrap.recovered.is_empty())
        }) {
            return Ok(true);
        }
        let current = if plan
            .steps
            .iter()
            .any(|step| step.identity_grants().next().is_some())
        {
            let env_obj = crate::environment::environment(ctx, environment)
                .await
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
            crate::identity_issuer::current(&env_obj)
                .map_err(|error| RuntimeDeliveryError::Internal(error.to_string()))?
        } else {
            None
        };
        let own = self.own_recipient_fingerprint(identity, environment)?;
        Ok(recovery_claimable(plan, own.as_deref(), current.as_ref()))
    }

    /// Fingerprint of the caller's unrevoked sealing key, if it has one.
    fn own_recipient_fingerprint(
        &self,
        identity: &RuntimeIdentity,
        environment: &str,
    ) -> Result<Option<String>, RuntimeDeliveryError> {
        Ok(self
            .environment_recipient_keys(environment)?
            .into_iter()
            .find(|record| record.runner_id == identity.runner_id)
            .and_then(|record| {
                crate::sealing_key::SealingPublicKey::from_wire(&record.public_key).ok()
            })
            .map(|key| key.fingerprint()))
    }

    pub fn environment_recipient_keys(
        &self,
        environment: &str,
    ) -> Result<Vec<crate::storage::RuntimeSealingKeyRecord>, RuntimeDeliveryError> {
        self.store
            .runtime_sealing_keys(environment)
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))
    }
}

/// A plan whose re-wrap steps carry recovered wraps (ADR 0045 §7) may be
/// claimed only by the runtime with sealing key `own`, their recipient, and
/// a plan with identity issuer steps only by a runtime whose key wraps each
/// step's issuer key (ADR 0046 §2): another runtime cannot open them and
/// would fail the plan. Any other plan may be claimed by any runtime.
/// Whether `step` needs a runtime that names `workload_identity` and opens
/// the identity issuer: it activates or re-wraps the issuer, or issues a
/// workload certificate from it (ADR 0046).
fn needs_workload_identity(step: &crate::plan::Step) -> bool {
    step.issuer.is_some() || step.identity_grants().next().is_some()
}

fn recovery_claimable(
    plan: &crate::plan::Plan,
    own: Option<&str>,
    current_issuer: Option<&crate::identity_issuer::IssuerKey>,
) -> bool {
    let recovered = plan
        .steps
        .iter()
        .filter_map(|step| step.rewrap.as_ref())
        .filter(|rewrap| !rewrap.recovered.is_empty())
        .all(|rewrap| Some(rewrap.fingerprint.as_str()) == own);
    let issuer = plan
        .steps
        .iter()
        .filter_map(|step| step.issuer.as_ref())
        // A remove step opens nothing: it names the old issuer only by its
        // public half, so a lost key never blocks its removal.
        .filter(|issuer| issuer.phase != Some(crate::identity_issuer::RotationPhase::Remove))
        .all(|issuer| {
            issuer
                .key
                .sealed_key
                .wraps
                .iter()
                .any(|wrap| Some(wrap.fingerprint.as_str()) == own)
        });
    // A certificate is issued with the current issuer key, so only a
    // runtime holding a wrap of it issues one.
    let certificate = !plan
        .steps
        .iter()
        .any(|step| step.identity_grants().next().is_some())
        || current_issuer.is_some_and(|issuer| {
            issuer
                .sealed_key
                .wraps
                .iter()
                .any(|wrap| Some(wrap.fingerprint.as_str()) == own)
        });
    recovered && issuer && certificate
}

fn parse_sealing_key(
    raw: Option<&str>,
) -> Result<Option<crate::sealing_key::SealingPublicKey>, RuntimeDeliveryError> {
    crate::sealing_key::parse_offered(raw)
        .map_err(|error| RuntimeDeliveryError::InvalidRequest(error.to_string()))
}

/// What a runtime agent sends to exchange its enrollment token (#630).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnrollRequest {
    pub token: String,
    /// A PEM certificate request over a key the agent generated and keeps;
    /// the response then carries its runner certificate (#674).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
    /// Host evidence signed with the CSR key (#675). Sent only once the
    /// server asked for it with `attestation_missing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<crate::runner_attestation::RunnerAttestation>,
    /// HPKE P-256 sealing public key (ADR 0045). Absent on older runtimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing_public_key: Option<String>,
}

/// The agent's own credential, shown only in this response. `credential_id`
/// is what an operator revokes it by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEnrolled {
    pub environment: String,
    pub credential: String,
    pub credential_id: String,
    /// The runner certificate (PEM) issued for the request's CSR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The runner CA certificate (PEM) that issued it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

impl RuntimeDeliveryOperations {
    /// Exchange a single-use enrollment token of `environment` for a runtime
    /// credential. An unknown, spent, expired or foreign token is refused
    /// alike, and a refused token is not spent. Under the environment's
    /// runner attestation policy (#675), evidence signed by the CSR key is
    /// verified before the token is spent.
    pub async fn enroll(
        &self,
        environment: &str,
        request: &RuntimeEnrollRequest,
    ) -> Result<RuntimeEnrolled, RuntimeDeliveryError> {
        use crate::runtime_credentials::{
            CREDENTIAL_PREFIX, ENROLLMENT_TOKEN_PREFIX, digest, mint,
        };
        if !request.token.starts_with(ENROLLMENT_TOKEN_PREFIX) {
            return Err(RuntimeDeliveryError::InvalidCredential);
        }
        // A sealing key this server cannot record is refused before the token
        // is spent, so a malformed offer does not consume enrollment.
        let sealing = parse_sealing_key(request.sealing_public_key.as_deref())?;
        // A drifted clock must not stretch a token's expiry.
        crate::clock_guard::require_trusted_time("runtime enrollment")
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        // A CSR this server cannot sign is refused before the token is spent.
        let ca = match &request.csr {
            None => None,
            Some(csr) => {
                let ca = self.runner_ca.as_ref().ok_or_else(|| {
                    RuntimeDeliveryError::InvalidRequest(
                        "this server has no runner CA to sign a certificate request".into(),
                    )
                })?;
                rcgen::CertificateSigningRequestParams::from_pem(csr).map_err(|_| {
                    RuntimeDeliveryError::InvalidRequest(
                        "the CSR is not a valid, self-signed certificate request".into(),
                    )
                })?;
                Some(ca)
            }
        };
        // The token is checked, without spending it, before any evidence is
        // judged: an unauthenticated caller gets the token error and causes
        // no refusal event or registry write.
        match self.store.runtime_enrollment_usable(
            environment,
            &digest(&request.token),
            crate::now_millis(),
        ) {
            Ok(true) => {}
            Ok(false) => return Err(RuntimeDeliveryError::InvalidCredential),
            Err(error) => return Err(RuntimeDeliveryError::Unavailable(error.to_string())),
        }
        let credential = mint(CREDENTIAL_PREFIX)
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        let binding = match self.enrollment_binding(environment, request).await {
            Ok(binding) => binding,
            Err(RuntimeDeliveryError::Attestation(refusal)) => {
                self.refuse_attestation(environment, None, &refusal).await;
                return Err(refusal.into());
            }
            Err(error) => return Err(error),
        };
        // Spent, registered and bound in one transaction: a failure leaves
        // the token usable and no runner.
        let now = crate::now_millis();
        let credential_digest = digest(&credential);
        let bound = binding
            .as_ref()
            .map(|binding| binding_record(environment, &credential_digest, binding, now));
        let sealing_record = sealing.map(|key| crate::storage::RuntimeSealingKeyRecord {
            runner_id: credential_digest.clone(),
            environment_id: environment.into(),
            public_key: key.to_wire(),
            fingerprint: key.fingerprint(),
            recorded_at: now,
        });
        let record = match self.store.redeem_runtime_enrollment(
            environment,
            &digest(&request.token),
            &credential_digest,
            now,
            bound.as_ref(),
            sealing_record.as_ref(),
        ) {
            Ok(record) => record,
            Err(crate::storage::StoreError::InvalidData { .. }) => {
                return Err(RuntimeDeliveryError::InvalidCredential);
            }
            Err(error) => return Err(RuntimeDeliveryError::Unavailable(error.to_string())),
        };
        let certificate = match (ca, &request.csr) {
            (Some(ca), Some(csr)) => Some(
                ca.issue_bound(
                    csr,
                    &crate::runner_ca::RunnerIdentity {
                        environment: record.environment_id.clone(),
                        runner_id: record.credential_digest.clone(),
                    },
                    crate::now_millis() / 1_000,
                    binding.as_ref(),
                )
                .map_err(|error| RuntimeDeliveryError::Internal(format!("{error:#}")))?,
            ),
            _ => None,
        };
        if certificate.is_some() {
            self.note_certificate(&record.credential_digest, &record.environment_id);
        }
        Ok(RuntimeEnrolled {
            environment: record.environment_id,
            credential,
            credential_id: record.credential_digest,
            ca: certificate
                .as_ref()
                .and_then(|_| ca.map(|ca| ca.trust_bundle())),
            certificate,
        })
    }

    /// The environment of an enrolled, unrevoked runtime credential. A store
    /// that cannot answer refuses: admission fails closed.
    fn enrolled_environment(&self, token: &str) -> Result<String, RuntimeDeliveryError> {
        use crate::runtime_credentials::{CREDENTIAL_PREFIX, digest};
        if !token.starts_with(CREDENTIAL_PREFIX) {
            return Err(RuntimeDeliveryError::InvalidCredential);
        }
        match self.store.runtime_credential(&digest(token)) {
            Ok(Some(record)) if record.revoked_at.is_none() => Ok(record.environment_id),
            Ok(_) => Err(RuntimeDeliveryError::InvalidCredential),
            Err(error) => Err(RuntimeDeliveryError::Unavailable(error.to_string())),
        }
    }
}

/// Runner attestation (#675) on enrollment, renewal and inventory.
impl RuntimeDeliveryOperations {
    /// The environment's policy and operator-declared facts. Without the
    /// application core the policy is unknown, so the caller is refused.
    async fn attestation_policy(
        &self,
        environment: &str,
    ) -> Result<
        Option<(
            crate::runner_attestation::RunnerAttestationPolicy,
            BTreeMap<String, String>,
        )>,
        RuntimeDeliveryError,
    > {
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "application core is not available on this host".into(),
            ));
        };
        crate::runner_attestation::environment_policy(&mut ctx, environment)
            .await
            .map_err(|error| RuntimeDeliveryError::Unavailable(format!("{error:#}")))
    }

    /// `None` with the policy off; else the verified binding of the
    /// enrollment's evidence over its CSR key.
    async fn enrollment_binding(
        &self,
        environment: &str,
        request: &RuntimeEnrollRequest,
    ) -> Result<Option<crate::runner_attestation::Binding>, RuntimeDeliveryError> {
        use crate::runner_attestation::AttestationRefusal;
        let Some((policy, declared)) = self.attestation_policy(environment).await? else {
            return Ok(None);
        };
        let csr = request
            .csr
            .as_deref()
            .ok_or(AttestationRefusal::CertificateRequired)?;
        crate::runner_attestation::verify(
            request.attestation.as_ref(),
            csr,
            environment,
            &declared,
            &policy,
            crate::now_millis(),
        )
        .map(Some)
        .map_err(Into::into)
    }

    /// `None` with the policy off; else the verified binding of a renewal:
    /// evidence present, the CSR key the presented certificate's (or, on
    /// the bearer path, the last bound one), and the evidence valid.
    async fn renewal_binding(
        &self,
        environment: &str,
        runner_id: &str,
        certificate: Option<&[u8]>,
        request: &RuntimeCertificateRequest,
    ) -> Result<Option<crate::runner_attestation::Binding>, RuntimeDeliveryError> {
        use crate::runner_attestation::AttestationRefusal;
        let Some((policy, declared)) = self.attestation_policy(environment).await? else {
            return Ok(None);
        };
        if request.attestation.is_none() {
            return Err(AttestationRefusal::Missing.into());
        }
        let malformed = |error: anyhow::Error| AttestationRefusal::Malformed(format!("{error:#}"));
        let requested =
            crate::runner_attestation::csr_fingerprint(&request.csr).map_err(malformed)?;
        let expected = match certificate {
            Some(certificate) => crate::runner_attestation::certificate_fingerprint(certificate)
                .map_err(malformed)?,
            None => self
                .store
                .runtime_attestations()
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?
                .into_iter()
                .find(|record| record.runner_id == runner_id)
                .and_then(|record| record.key_fingerprint)
                .ok_or(AttestationRefusal::NoBoundKey)?,
        };
        if requested != expected {
            return Err(AttestationRefusal::KeyChanged.into());
        }
        crate::runner_attestation::verify(
            request.attestation.as_ref(),
            &request.csr,
            environment,
            &declared,
            &policy,
            crate::now_millis(),
        )
        .map(Some)
        .map_err(Into::into)
    }

    /// Record `binding` as the runner's latest bound attestation. A store
    /// that cannot record it refuses: no unrecorded binding is certified.
    fn bind_attestation(
        &self,
        environment: &str,
        runner_id: &str,
        binding: &crate::runner_attestation::Binding,
    ) -> Result<(), RuntimeDeliveryError> {
        self.store
            .record_runtime_attestation(&binding_record(
                environment,
                runner_id,
                binding,
                crate::now_millis(),
            ))
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))
    }

    /// Show a refusal: as the runner's last refusal in the registry, and
    /// as one `runner.attestation_refused` event per runner, reason and
    /// binding, since the agent retries every poll. `attestation_missing`
    /// is how the policy is advertised, so it is not announced. Best
    /// effort: the refusal stands whatever happens here.
    async fn refuse_attestation(
        &self,
        environment: &str,
        runner_id: Option<&str>,
        refusal: &crate::runner_attestation::AttestationRefusal,
    ) {
        let now = crate::now_millis();
        let mut bound = "none".to_string();
        if let Some(runner_id) = runner_id {
            if let Ok(records) = self.store.runtime_attestations()
                && let Some(digest) = records
                    .into_iter()
                    .find(|record| record.runner_id == runner_id)
                    .and_then(|record| record.evidence_digest)
            {
                bound = digest;
            }
            let record = crate::storage::RuntimeAttestationRecord {
                runner_id: runner_id.into(),
                environment_id: environment.into(),
                refusal_reason: Some(refusal.code().into()),
                refused_at: Some(now),
                ..Default::default()
            };
            if let Err(error) = self.store.record_runtime_attestation(&record) {
                eprintln!("recording a runner attestation refusal failed: {error}");
            }
        }
        eprintln!(
            "tenkai.runner_attestation outcome=refused environment={environment} runner={} code={}",
            runner_id.unwrap_or("enrollment"),
            refusal.code()
        );
        if matches!(
            refusal,
            crate::runner_attestation::AttestationRefusal::Missing
        ) {
            return;
        }
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return;
        };
        let Ok(endpoints) =
            crate::deploy_webhook::list_environment_webhooks(&mut ctx, environment).await
        else {
            return;
        };
        let resource = runner_id.unwrap_or("enrollment");
        let key = format!("{resource}|{}|{bound}", refusal.code());
        crate::operational_events::announce(
            self.store.as_ref(),
            &endpoints,
            &crate::operational_events::Transition {
                event: crate::deploy_webhook::OperationalEvent::RunnerAttestationRefused,
                scope: environment,
                resource,
                code: refusal.code(),
                key: &key,
            },
            now,
        );
    }
}

/// The registry record that binds `binding` to `runner_id` at `now`.
fn binding_record(
    environment: &str,
    runner_id: &str,
    binding: &crate::runner_attestation::Binding,
    now: i64,
) -> crate::storage::RuntimeAttestationRecord {
    crate::storage::RuntimeAttestationRecord {
        runner_id: runner_id.into(),
        environment_id: environment.into(),
        evidence_digest: Some(binding.evidence_digest.clone()),
        key_fingerprint: Some(binding.key_fingerprint.clone()),
        checked_at: Some(binding.checked_at),
        bound_at: Some(now),
        refusal_reason: None,
        refused_at: None,
    }
}

fn validate_inventory_source(source: &str) -> Result<(), RuntimeDeliveryError> {
    if source.trim().is_empty() || source.len() > 64 {
        return Err(RuntimeDeliveryError::InvalidRequest(
            "inventory source must be 1..=64 characters".into(),
        ));
    }
    let source_lower = source.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token="] {
        if source_lower.contains(needle) {
            return Err(RuntimeDeliveryError::InvalidRequest(
                "inventory source must not contain credential material".into(),
            ));
        }
    }
    Ok(())
}

fn runtime_owner(token: &str, instance: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    digest.update([0]);
    digest.update(instance.as_bytes());
    format!("runtime:{:x}", digest.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}

fn runtime_assignment(assignments: &HashMap<String, String>, token: &str) -> Option<String> {
    let mut matched = None;
    for (candidate, environment) in assignments {
        if constant_time_eq(candidate.as_bytes(), token.as_bytes()) {
            matched = Some(environment.clone());
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_older_runtime_gets_no_removal_package() {
        let mut step = crate::plan::Step {
            id: "plan:step:0".into(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: crate::plan::Action::Remove,
            from: Some("1.0.0".into()),
            to: "1.0.0".into(),
            release_id: crate::ontology::release_id("api", "1.0.0"),
            release_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            workdir: String::new(),
            restore: None,
            host: None,
            sealed: Vec::new(),
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
        };
        // What an older runtime sends: no removal field.
        let older: super::RuntimeReleaseRequest =
            serde_json::from_str(r#"{"plan_id":"plan","generation":1,"step_id":"plan:step:0"}"#)
                .unwrap();
        let current = super::RuntimeReleaseRequest {
            removal: true,
            ..older.clone()
        };

        assert!(matches!(
            super::refuse_removal_by_older_runtime(&step, &older),
            Err(super::RuntimeDeliveryError::ReleaseRefused(_))
        ));
        assert!(super::refuse_removal_by_older_runtime(&step, &current).is_ok());
        // Host removals and every other step predate the flag.
        step.host = Some(crate::plan::HostStep {
            action: crate::host_apply::HostAction::Uninstall,
            expected_generation: 1,
        });
        assert!(super::refuse_removal_by_older_runtime(&step, &older).is_ok());
        step.host = None;
        step.action = crate::plan::Action::Upgrade;
        assert!(super::refuse_removal_by_older_runtime(&step, &older).is_ok());
    }

    /// Completing a re-wrap plan stores the new wraps on the values it named
    /// and leaves the deployment record, rollback history and failed targets
    /// alone: a re-wrap deploys nothing (ADR 0045 §5).
    #[tokio::test]
    async fn a_completed_rewrap_stores_wraps_and_deploys_nothing() {
        use crate::sealed_secret::{RecipientWrap, SealedRecord, SealedWrap};
        let database = std::env::temp_dir().join(format!(
            "tenkai-rewrap-complete-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "rewrap")
            .await
            .unwrap();
        let wrap = |fingerprint: &str| SealedWrap {
            fingerprint: fingerprint.into(),
            encapsulated_key: "AA==".into(),
            wrapped_key: "AA==".into(),
        };
        let (old, new) = (
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        );
        let record = SealedRecord {
            sealed: crate::sealed_secret::SealedValue {
                format_version: 1,
                ciphertext: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [0_u8; 40],
                ),
                wraps: vec![wrap(&old)],
            },
            digest: "sha256:value".into(),
            set_by: "operator".into(),
            set_at: 1,
        };
        let mut env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        for (key, value) in [
            ("deployed.api", "1.0.0".to_string()),
            ("deployed_prev.api", "0.9.0".to_string()),
            (
                "sealed.api",
                serde_json::to_string(&BTreeMap::from([("db/password", record)])).unwrap(),
            ),
        ] {
            env_obj.properties.insert(key.into(), value);
        }
        ctx.put(env_obj).await.unwrap();

        let now = crate::now_millis();
        let id = format!("tenkai:plan:prod:{now}");
        let mut plan = Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: id.clone(),
            content_id: format!("content-{now}"),
            environment: "prod".into(),
            created_at: now,
            inputs: Vec::new(),
            steps: vec![crate::plan::Step {
                id: format!("{id}:step:0"),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: crate::plan::Action::Restart,
                from: Some("1.0.0".into()),
                to: "1.0.0".into(),
                release_id: crate::ontology::release_id("api", "1.0.0"),
                release_digest: "manifest".into(),
                artifact_digest: "artifact".into(),
                workdir: String::new(),
                restore: None,
                host: None,
                sealed: vec![crate::plan::SealedStep {
                    secret: "db".into(),
                    key: "password".into(),
                    digest: "sha256:value".into(),
                }],
                issuer: None,
                identity: None,
                restore_identity: None,
                rewrap: Some(crate::plan::RewrapStep {
                    fingerprint: new.clone(),
                    recovered: Vec::new(),
                }),
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        plan.bind_content_identity().unwrap();
        let (id, step_id) = (plan.id.clone(), plan.steps[0].id.clone());
        ctx.put(plan.to_object().unwrap()).await.unwrap();
        let before = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();

        // As the runtime's completion does: wraps under the environment
        // lease first, then the plan.
        crate::sealed_secret::store_completion_wraps(
            &mut ctx,
            "prod",
            &[(
                "api".to_string(),
                vec![
                    RecipientWrap {
                        secret: "db".into(),
                        key: "password".into(),
                        digest: "sha256:value".into(),
                        wrap: wrap(&new),
                    },
                    // Revoked after the runtime fetched its key: not kept.
                    RecipientWrap {
                        secret: "db".into(),
                        key: "password".into(),
                        digest: "sha256:value".into(),
                        wrap: wrap(&format!("sha256:{}", "c".repeat(64))),
                    },
                ],
            )],
            || Ok([old.clone(), new.clone()].into()),
        )
        .await
        .unwrap();
        complete_runtime_work(
            &mut ctx,
            "prod",
            &RuntimeCompletion {
                plan_id: id.clone(),
                generation: 1,
                succeeded: true,
                detail: "done".into(),
                receipts: vec![RuntimeStepReceipt {
                    step_id,
                    succeeded: true,
                    detail: "re-wrapped".into(),
                    wraps: vec![RecipientWrap {
                        secret: "db".into(),
                        key: "password".into(),
                        digest: "sha256:value".into(),
                        wrap: wrap(&new),
                    }],
                }],
            },
        )
        .await
        .unwrap();

        let listed = crate::sealed_secret::list(&mut ctx, "prod", false)
            .await
            .unwrap();
        assert_eq!(listed.secrets[0].recipients, [old, new]);
        assert_eq!(listed.secrets[0].digest, "sha256:value");
        let after = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        for key in ["deployed.api", "deployed_prev.api"] {
            assert_eq!(
                after.properties.get(key),
                before.properties.get(key),
                "{key}"
            );
        }
        assert!(
            !after
                .properties
                .keys()
                .any(|key| key.starts_with("failed_target")),
            "{:?}",
            after.properties
        );
        assert_eq!(
            crate::plan::load(&mut ctx, &id).await.unwrap().state,
            PlanState::Succeeded
        );
        let _ = std::fs::remove_file(database);
    }

    /// Only the recipient runtime may claim a plan carrying recovered
    /// wraps; any runtime may claim a plain re-wrap.
    #[test]
    fn a_recovery_plan_goes_only_to_its_recipient_runtime() {
        let (recipient, other) = (
            format!("sha256:{}", "b".repeat(64)),
            format!("sha256:{}", "c".repeat(64)),
        );
        let step = |recovered: Vec<crate::sealed_secret::RecipientWrap>| crate::plan::Step {
            id: "step".into(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: crate::plan::Action::Restart,
            from: Some("1.0.0".into()),
            to: "1.0.0".into(),
            release_id: crate::ontology::release_id("api", "1.0.0"),
            release_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            workdir: String::new(),
            restore: None,
            host: None,
            sealed: Vec::new(),
            issuer: None,
            identity: None,
            restore_identity: None,
            rewrap: Some(crate::plan::RewrapStep {
                fingerprint: recipient.clone(),
                recovered,
            }),
        };
        let plan = |step| Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: "plan".into(),
            content_id: "content".into(),
            environment: "prod".into(),
            created_at: 0,
            inputs: Vec::new(),
            steps: vec![step],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        let recovered = plan(step(vec![crate::sealed_secret::RecipientWrap {
            secret: "db".into(),
            key: "password".into(),
            digest: "sha256:value".into(),
            wrap: crate::sealed_secret::SealedWrap {
                fingerprint: recipient.clone(),
                encapsulated_key: "AA==".into(),
                wrapped_key: "AA==".into(),
            },
        }]));
        assert!(recovery_claimable(&recovered, Some(&recipient), None));
        assert!(!recovery_claimable(&recovered, Some(&other), None));
        assert!(!recovery_claimable(&recovered, None, None));
        let plain = plan(step(Vec::new()));
        assert!(recovery_claimable(&plain, Some(&other), None));
        assert!(recovery_claimable(&plain, None, None));
        // A remove step needs no wrap of the issuer it removes.
        let dir = std::env::temp_dir().join(format!(
            "tenkai-removal-claim-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sealing = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        let mut lost = crate::identity_issuer::generate(
            "prod",
            1,
            sealing.public(),
            crate::now_millis() / 1000,
        )
        .unwrap();
        lost.sealed_key.wraps.clear();
        let _ = std::fs::remove_dir_all(&dir);
        let mut removal = plain.clone();
        removal.steps[0].issuer = Some(crate::plan::IssuerStep {
            key: lost,
            recipient: None,
            phase: Some(crate::identity_issuer::RotationPhase::Remove),
            replaces: None,
        });
        assert!(recovery_claimable(&removal, Some(&other), None));
    }

    /// A recipient revoked after the runtime fetched its key gets no wraps
    /// back from the completion.
    #[test]
    fn wraps_of_a_revoked_recipient_are_not_kept() {
        let wrap = |fingerprint: &str| crate::sealed_secret::RecipientWrap {
            secret: "db".into(),
            key: "password".into(),
            digest: "sha256:value".into(),
            wrap: crate::sealed_secret::SealedWrap {
                fingerprint: fingerprint.into(),
                encapsulated_key: "AA==".into(),
                wrapped_key: "AA==".into(),
            },
        };
        let mut completion = RuntimeCompletion {
            plan_id: "plan".into(),
            generation: 1,
            succeeded: true,
            detail: String::new(),
            receipts: vec![RuntimeStepReceipt {
                step_id: "plan:step:0".into(),
                succeeded: true,
                detail: String::new(),
                wraps: vec![wrap("sha256:kept"), wrap("sha256:revoked")],
            }],
        };
        assert_eq!(
            wrapped_recipients(&completion),
            ["sha256:kept".to_string(), "sha256:revoked".to_string()].into()
        );
        retain_recipient_wraps(&mut completion, &["sha256:kept".to_string()].into());
        assert_eq!(completion.receipts[0].wraps, [wrap("sha256:kept")]);
    }

    /// Only a succeeded re-wrap step carries wraps, each for the step's
    /// recipient and for a value it names at its approved digest.
    #[test]
    fn wraps_are_accepted_only_as_the_approved_rewrap_step_names_them() {
        let sealed = crate::plan::SealedStep {
            secret: "db".into(),
            key: "password".into(),
            digest: "sha256:approved".into(),
        };
        let recipient = format!("sha256:{}", "b".repeat(64));
        let step = crate::plan::Step {
            id: "plan:step:0".into(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: crate::plan::Action::Restart,
            from: Some("1.0.0".into()),
            to: "1.0.0".into(),
            release_id: crate::ontology::release_id("api", "1.0.0"),
            release_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            workdir: String::new(),
            restore: None,
            host: None,
            sealed: vec![sealed.clone()],
            issuer: None,
            identity: None,
            restore_identity: None,
            rewrap: Some(crate::plan::RewrapStep {
                fingerprint: recipient.clone(),
                recovered: Vec::new(),
            }),
        };
        let wrap = |fingerprint: &str, digest: &str| crate::sealed_secret::RecipientWrap {
            secret: "db".into(),
            key: "password".into(),
            digest: digest.into(),
            wrap: crate::sealed_secret::SealedWrap {
                fingerprint: fingerprint.into(),
                encapsulated_key: "AA==".into(),
                wrapped_key: "AA==".into(),
            },
        };
        let receipt = |succeeded: bool, wraps| RuntimeStepReceipt {
            step_id: step.id.clone(),
            succeeded,
            detail: String::new(),
            wraps,
        };
        require_approved_wraps(
            "prod",
            &step,
            &receipt(true, vec![wrap(&recipient, "sha256:approved")]),
        )
        .unwrap();
        for (refused, receipt) in [
            (
                "another recipient",
                receipt(
                    true,
                    vec![wrap(
                        &format!("sha256:{}", "c".repeat(64)),
                        "sha256:approved",
                    )],
                ),
            ),
            (
                "another digest",
                receipt(true, vec![wrap(&recipient, "sha256:changed")]),
            ),
            (
                "a failed step",
                receipt(false, vec![wrap(&recipient, "sha256:approved")]),
            ),
            ("a malformed wrap", {
                let mut malformed = wrap(&recipient, "sha256:approved");
                malformed.wrap.encapsulated_key = "not base64!".into();
                receipt(true, vec![malformed])
            }),
        ] {
            assert!(
                require_approved_wraps("prod", &step, &receipt).is_err(),
                "{refused}"
            );
        }
        let mut deploy = step.clone();
        deploy.rewrap = None;
        assert!(
            require_approved_wraps(
                "prod",
                &deploy,
                &receipt(true, vec![wrap(&recipient, "sha256:approved")])
            )
            .is_err(),
            "a step that is not a re-wrap step"
        );
    }
    use std::sync::Mutex;

    use super::*;

    struct Port {
        store: Arc<dyn OperationalStore>,
        calls: Mutex<Vec<&'static str>>,
        ctx: Option<Ctx>,
        plan: tokio::sync::OnceCell<Plan>,
    }

    impl ReconcilePort for Port {
        fn reconcile(&self) -> ReconcileFuture<'_> {
            Box::pin(async { unreachable!() })
        }

        fn pending_work(&self, environment: String) -> WorkFuture<'_> {
            Box::pin(async move {
                let plan = if let Some(mut ctx) = self.ctx.clone() {
                    let created = self
                        .plan
                        .get_or_try_init(|| async {
                            let mut ctx = ctx.clone();
                            crate::ontology::register(&mut ctx).await?;
                            crate::environment::env_add(&mut ctx, &environment, "runtime-test")
                                .await?;
                            crate::plan::create_from_steps(&mut ctx, &environment, Vec::new()).await
                        })
                        .await?
                        .clone();
                    // As the reconciler does, hand out the plan as stored now.
                    crate::plan::load(&mut ctx, &created.id).await?
                } else {
                    Plan {
                        format_version: 1,
                        id: "plan-1".into(),
                        content_id: "sha256:plan".into(),
                        environment,
                        created_at: 1,
                        inputs: Vec::new(),
                        steps: Vec::new(),
                        state: crate::plan::PlanState::Computed,
                        gates_skipped: None,
                        status_detail: String::new(),
                        maintenance_blocked: false,
                        prior_warnings: Vec::new(),
                        recalled_recovery_reason: None,
                        credential_runway: None,
                    }
                };
                Ok(Some(plan))
            })
        }

        fn application_ctx(&self) -> Option<Ctx> {
            self.ctx.clone()
        }

        fn check_health(&self) -> HealthFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn complete_work(
            &self,
            environment: String,
            completion: RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            let owner = runtime_owner("runtime-secret", "instance-a");
            let persisted = self.store.claim_runtime_plan(
                &environment,
                &completion.plan_id,
                &owner,
                crate::now_millis() + 60_000,
            );
            self.calls.lock().unwrap().push("complete");
            Box::pin(async move {
                let claim = persisted?.expect("completed owner can observe its claim");
                anyhow::ensure!(
                    claim.completion_json.is_some(),
                    "completion was not persisted"
                );
                Ok(())
            })
        }

        fn validate_completion(
            &self,
            _environment: String,
            _completion: RuntimeCompletion,
        ) -> CompletionFuture<'_> {
            self.calls.lock().unwrap().push("validate");
            Box::pin(async { Ok(()) })
        }

        fn list_environments(&self) -> ListEnvFuture<'_> {
            Box::pin(async { unreachable!() })
        }

        fn inspect_environment(&self, _environment: String) -> InspectEnvFuture<'_> {
            Box::pin(async { unreachable!() })
        }

        fn environment_status(&self, _environment: String) -> StatusEnvFuture<'_> {
            Box::pin(async { unreachable!() })
        }

        fn fleet_status(&self) -> FleetStatusFuture<'_> {
            Box::pin(async { unreachable!() })
        }

        fn apply_inventory_facts(
            &self,
            _environment: String,
            facts: BTreeMap<String, String>,
        ) -> InventoryFuture<'_> {
            Box::pin(async move {
                for key in facts.keys() {
                    anyhow::ensure!(
                        crate::plan::ENVIRONMENT_FACT_KEYS.contains(&key.as_str()),
                        "unknown environment fact {key:?}"
                    );
                }
                Ok(facts.into_keys().collect())
            })
        }

        fn diagnostics_snapshot(&self) -> ReconcileDiagnostics {
            unreachable!()
        }
    }

    fn operations() -> (RuntimeDeliveryOperations, Arc<Port>) {
        let store = Arc::new(crate::storage::SqliteStore::open_in_memory().unwrap());
        let port = Arc::new(Port {
            store: store.clone(),
            calls: Mutex::new(Vec::new()),
            ctx: Some(Ctx::embedded(":memory:").unwrap()),
            plan: tokio::sync::OnceCell::new(),
        });
        (
            RuntimeDeliveryOperations::new(
                HashMap::from([("runtime-secret".into(), "prod".into())]),
                port.clone(),
                store,
            ),
            port,
        )
    }

    /// Certificate identity (#674): enrollment with a CSR issues a runner
    /// certificate; it admits its runner only in its environment and only
    /// until the credential is revoked; one from another CA claims nothing;
    /// a CSR the server cannot sign is refused before the token is spent.
    #[tokio::test]
    async fn a_runner_certificate_admits_only_its_runner_in_its_environment() {
        use crate::runtime_credentials::{ENROLLMENT_TOKEN_PREFIX, digest, mint};
        let (operations, _) = operations();
        let issue = |operations: &RuntimeDeliveryOperations| {
            let token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
            operations
                .store
                .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                    token_digest: digest(&token),
                    environment_id: "prod".into(),
                    expires_at: i64::MAX,
                    created_by: "operator".into(),
                })
                .unwrap();
            token
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();

        // Without a runner CA, a CSR is refused and the token stays unspent.
        let token = issue(&operations);
        let request = RuntimeEnrollRequest {
            token,
            csr: Some(csr.clone()),
            attestation: None,
            sealing_public_key: None,
        };
        assert!(matches!(
            operations.enroll("prod", &request).await,
            Err(RuntimeDeliveryError::InvalidRequest(_))
        ));
        let (cert, ca_key) = crate::runner_ca::RunnerCa::generate("runner CA").unwrap();
        let ca = Arc::new(crate::runner_ca::RunnerCa::from_pem(&cert, &ca_key).unwrap());
        let operations = operations.with_runner_ca(ca);
        let enrolled = operations.enroll("prod", &request).await.unwrap();
        assert_eq!(enrolled.ca.as_deref(), Some(cert.as_str()));
        let leaf = x509_parser::pem::parse_x509_pem(enrolled.certificate.unwrap().as_bytes())
            .unwrap()
            .1
            .contents;

        let admit = |certificate: &[u8], environment: &str| {
            let caller = RuntimeCaller {
                instance: Some("instance-a"),
                version: None,
                certificate: Some(certificate),
                workload_identity: false,
                peer_grants: false,
                issuer_rotation: false,
                issuer_take_up: false,
                issuer_removal: false,
            };
            operations.admit(None, &caller, environment)
        };
        let admitted = admit(&leaf, "prod").unwrap();
        assert_eq!(admitted.runner_id, enrolled.credential_id);
        assert!(matches!(
            admit(&leaf, "stage"),
            Err(RuntimeDeliveryError::ForeignEnvironment)
        ));
        // A certificate from another CA names no runner, whatever it says.
        let (other_cert, other_key) = crate::runner_ca::RunnerCa::generate("other").unwrap();
        let other = crate::runner_ca::RunnerCa::from_pem(&other_cert, &other_key).unwrap();
        let forged = other
            .issue(
                &csr,
                &crate::runner_ca::RunnerIdentity {
                    environment: "prod".into(),
                    runner_id: enrolled.credential_id.clone(),
                },
                crate::now_millis() / 1_000,
            )
            .unwrap();
        let forged = x509_parser::pem::parse_x509_pem(forged.as_bytes())
            .unwrap()
            .1
            .contents;
        assert!(matches!(
            admit(&forged, "prod"),
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        // Renewal (#674): by the current certificate, or by the enrolled
        // bearer once it has expired; static tokens name no runner.
        let renew = async |token: Option<&str>, certificate: Option<&[u8]>| {
            let request = RuntimeCertificateRequest {
                csr: csr.clone(),
                attestation: None,
                sealing_public_key: None,
            };
            operations
                .renew_certificate(
                    token,
                    RuntimeCaller {
                        instance: Some("instance-a"),
                        version: None,
                        certificate,
                        workload_identity: false,
                        peer_grants: false,
                        issuer_rotation: false,
                        issuer_take_up: false,
                        issuer_removal: false,
                    },
                    "prod",
                    &request,
                )
                .await
        };
        let renewed = renew(None, Some(&leaf)).await.unwrap();
        let renewed_leaf = x509_parser::pem::parse_x509_pem(renewed.certificate.as_bytes())
            .unwrap()
            .1
            .contents;
        assert_eq!(
            admit(&renewed_leaf, "prod").unwrap().owner,
            admitted.owner,
            "a renewed certificate keeps its runner's lease identity"
        );
        renew(Some(&enrolled.credential), None).await.unwrap();
        assert!(matches!(
            renew(Some("runtime-secret"), None).await,
            Err(RuntimeDeliveryError::InvalidRequest(_))
        ));
        // Revoked in the registry, the certificate is refused from the next request.
        operations
            .store
            .revoke_runtime_credential(
                &enrolled.credential_id,
                1,
                &crate::storage::RuntimeRevocation {
                    reason: "host retired".into(),
                    revoked_by: "operator".into(),
                },
            )
            .unwrap();
        assert!(matches!(
            admit(&leaf, "prod"),
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        assert!(renew(None, Some(&leaf)).await.is_err());
        assert!(renew(Some(&enrolled.credential), None).await.is_err());
    }

    /// Runner attestation (#675): under the policy, enrollment and renewal
    /// need evidence signed by the CSR key that is fresh, passed and agrees
    /// with the operator-declared facts; the certificate binds it, the
    /// registry keeps it, and every refusal is named. Cleared, renewal is
    /// as before.
    #[tokio::test]
    async fn attested_enrollment_and_renewal_bind_host_evidence() {
        use crate::runner_attestation::tests::{attest, runner_key};
        use crate::runner_attestation::{AttestationRefusal, certificate_binding};
        use crate::runtime_credentials::{ENROLLMENT_TOKEN_PREFIX, digest, mint};
        let (operations, port) = operations();
        let (cert, ca_key) = crate::runner_ca::RunnerCa::generate("runner CA").unwrap();
        let operations = operations.with_runner_ca(Arc::new(
            crate::runner_ca::RunnerCa::from_pem(&cert, &ca_key).unwrap(),
        ));
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "attested")
            .await
            .unwrap();
        crate::environment::set_environment_fact(&mut ctx, "prod", "architecture", "arm64")
            .await
            .unwrap();
        crate::runner_attestation::set_policy(&mut ctx, "prod", 600_000, false)
            .await
            .unwrap();
        fn code<T>(result: Result<T, RuntimeDeliveryError>) -> &'static str {
            match result {
                Err(RuntimeDeliveryError::Attestation(refusal)) => refusal.code(),
                Err(other) => panic!("not an attestation refusal: {other}"),
                Ok(_) => panic!("not refused"),
            }
        }
        let der = |pem: &str| {
            x509_parser::pem::parse_x509_pem(pem.as_bytes())
                .unwrap()
                .1
                .contents
        };
        let key = runner_key();
        let other = runner_key();
        let arm =
            |key: &(String, String), at: i64| attest("prod", &[("architecture", "arm64")], key, at);
        let now = crate::now_millis();

        let token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
        operations
            .store
            .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                token_digest: digest(&token),
                environment_id: "prod".into(),
                expires_at: i64::MAX,
                created_by: "operator".into(),
            })
            .unwrap();
        let enroll = |attestation| RuntimeEnrollRequest {
            token: token.clone(),
            csr: Some(key.1.clone()),
            attestation,
            sealing_public_key: None,
        };
        // Refused enrollments spend no token: missing, then contradicting.
        assert_eq!(
            code(operations.enroll("prod", &enroll(None)).await),
            "attestation_missing"
        );
        let x86 = attest("prod", &[("architecture", "x86_64")], &key, now);
        assert_eq!(
            code(operations.enroll("prod", &enroll(Some(x86))).await),
            "fact_mismatch"
        );
        // A forged token is refused as a token before any evidence is
        // judged: missing, contradicting or valid-looking, no attestation
        // refusal (so no event) and no attestation row.
        let forged_token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
        for attestation in [
            None,
            Some(attest("prod", &[("architecture", "x86_64")], &key, now)),
            Some(arm(&key, now)),
        ] {
            let forged = RuntimeEnrollRequest {
                token: forged_token.clone(),
                csr: Some(key.1.clone()),
                attestation,
                sealing_public_key: None,
            };
            assert!(matches!(
                operations.enroll("prod", &forged).await,
                Err(RuntimeDeliveryError::InvalidCredential)
            ));
        }
        // Nor for another environment's valid token.
        assert!(matches!(
            operations.enroll("stage", &enroll(None)).await,
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        assert!(operations.store.runtime_attestations().unwrap().is_empty());
        let enrolled = operations
            .enroll("prod", &enroll(Some(arm(&key, now))))
            .await
            .unwrap();
        let leaf = der(enrolled.certificate.as_deref().unwrap());
        let (bound, fingerprint) = certificate_binding(&leaf).unwrap().unwrap();
        assert_eq!(
            fingerprint,
            crate::runner_attestation::csr_fingerprint(&key.1).unwrap()
        );
        let registry = || {
            operations
                .store
                .runtime_attestations()
                .unwrap()
                .into_iter()
                .find(|record| record.runner_id == enrolled.credential_id)
                .unwrap()
        };
        assert_eq!(registry().evidence_digest.as_deref(), Some(bound.as_str()));

        let renew =
            async |certificate: Option<&[u8]>,
                   csr: &str,
                   attestation: Option<crate::runner_attestation::RunnerAttestation>| {
                let request = RuntimeCertificateRequest {
                    csr: csr.into(),
                    attestation,
                    sealing_public_key: None,
                };
                let token = certificate
                    .is_none()
                    .then_some(enrolled.credential.as_str());
                operations
                    .renew_certificate(
                        token,
                        RuntimeCaller {
                            instance: Some("instance-a"),
                            version: None,
                            certificate,
                            workload_identity: false,
                            peer_grants: false,
                            issuer_rotation: false,
                            issuer_take_up: false,
                            issuer_removal: false,
                        },
                        "prod",
                        &request,
                    )
                    .await
            };
        let renewed = renew(Some(&leaf), &key.1, Some(arm(&key, now)))
            .await
            .unwrap();
        assert!(
            certificate_binding(&der(&renewed.certificate))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            code(renew(Some(&leaf), &key.1, None).await),
            "attestation_missing"
        );
        // Evidence signed by a key other than the certificate key.
        assert_eq!(
            code(renew(Some(&leaf), &key.1, Some(arm(&other, now))).await),
            "signature_invalid"
        );
        // A CSR over another key: no key rotation under the policy.
        assert_eq!(
            code(renew(Some(&leaf), &other.1, Some(arm(&other, now))).await),
            "key_changed"
        );
        // Architecture drift blocks renewal with a named reason.
        let moved = attest("prod", &[("architecture", "x86_64")], &key, now);
        let refusal = renew(Some(&leaf), &key.1, Some(moved)).await.unwrap_err();
        assert!(matches!(
            refusal,
            RuntimeDeliveryError::Attestation(AttestationRefusal::FactMismatch { ref key })
                if key == "architecture"
        ));
        assert_eq!(registry().refusal_reason.as_deref(), Some("fact_mismatch"));
        assert!(
            registry().evidence_digest.is_some(),
            "a refusal keeps the binding"
        );
        assert_eq!(
            code(renew(Some(&leaf), &key.1, Some(arm(&key, now - 700_000))).await),
            "evidence_stale"
        );
        let failed = crate::runner_attestation::sign(
            crate::runner_attestation::AttestationSchema::V2,
            crate::runner_attestation::HostEvidence {
                environment: "prod".into(),
                checks: vec![crate::host_preflight::CheckResult {
                    check: "disk /var".into(),
                    passed: false,
                    reason: "full".into(),
                }],
                facts: BTreeMap::new(),
                checked_at: now,
            },
            &key.0,
            &key.1,
        )
        .unwrap();
        assert_eq!(
            code(renew(Some(&leaf), &key.1, Some(failed)).await),
            "evidence_failed"
        );
        // The expired-certificate bearer path needs the last bound key.
        renew(None, &key.1, Some(arm(&key, now))).await.unwrap();
        assert_eq!(registry().refusal_reason, None, "a binding clears it");
        assert_eq!(
            code(renew(None, &other.1, Some(arm(&other, now))).await),
            "key_changed"
        );
        // Under the policy only the certificate admits work routes; the
        // bearer is refused with a named reason (it only renews).
        let inventory = async |token: Option<&str>, certificate: Option<&[u8]>| {
            operations
                .report_inventory(
                    token,
                    RuntimeCaller {
                        instance: Some("instance-a"),
                        version: None,
                        certificate,
                        workload_identity: false,
                        peer_grants: false,
                        issuer_rotation: false,
                        issuer_take_up: false,
                        issuer_removal: false,
                    },
                    "prod",
                    RuntimeInventoryReport {
                        facts: BTreeMap::from([("architecture".into(), "arm64".into())]),
                        source: "runtime-probe".into(),
                    },
                )
                .await
        };
        assert_eq!(
            code(inventory(Some(&enrolled.credential), None).await),
            "attestation_requires_client_certificate"
        );
        inventory(None, Some(&leaf)).await.unwrap();
        // With the policy cleared, renewal is as before: no evidence, no binding.
        crate::runner_attestation::clear_policy(&mut ctx, "prod")
            .await
            .unwrap();
        inventory(Some(&enrolled.credential), None).await.unwrap();
        let plain = renew(Some(&leaf), &other.1, None).await.unwrap();
        assert!(
            certificate_binding(&der(&plain.certificate))
                .unwrap()
                .is_none()
        );
    }

    /// While the policy is on, a runtime inventory report cannot overwrite
    /// an operator-declared fact; with it off, inventory is as before.
    #[tokio::test]
    async fn inventory_under_the_policy_never_overwrites_a_declared_fact() {
        use crate::runner_attestation::AttestationRefusal;
        let (_, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "attested")
            .await
            .unwrap();
        crate::environment::set_environment_fact(&mut ctx, "prod", "architecture", "arm64")
            .await
            .unwrap();
        crate::runner_attestation::set_policy(&mut ctx, "prod", 600_000, false)
            .await
            .unwrap();
        let report = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect()
        };
        let refused = crate::environment::apply_runtime_inventory_facts(
            &mut ctx,
            "prod",
            &report(&[("architecture", "x86_64"), ("memory_gib", "8")]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused.downcast_ref::<AttestationRefusal>(),
            Some(&AttestationRefusal::InventoryContradictsDeclaredFact {
                key: "architecture".into()
            })
        );
        let facts = crate::environment::list_environment_facts(&mut ctx, "prod")
            .await
            .unwrap();
        assert_eq!(facts.get("architecture").map(String::as_str), Some("arm64"));
        assert!(!facts.contains_key("memory_gib"), "refused whole");
        crate::environment::apply_runtime_inventory_facts(
            &mut ctx,
            "prod",
            &report(&[("architecture", "arm64"), ("memory_gib", "8")]),
        )
        .await
        .unwrap();
        let object = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        assert_eq!(
            crate::runner_attestation::declared_facts(&object.properties),
            report(&[("architecture", "arm64")]),
            "an agreeing report keeps the declaration; reported facts are not declarations"
        );
        crate::runner_attestation::clear_policy(&mut ctx, "prod")
            .await
            .unwrap();
        crate::environment::apply_runtime_inventory_facts(
            &mut ctx,
            "prod",
            &report(&[("architecture", "x86_64")]),
        )
        .await
        .unwrap();
        let facts = crate::environment::list_environment_facts(&mut ctx, "prod")
            .await
            .unwrap();
        assert_eq!(
            facts.get("architecture").map(String::as_str),
            Some("x86_64")
        );
    }

    #[tokio::test]
    async fn an_enrolled_agent_is_admitted_to_its_environment_until_revoked() {
        use crate::runtime_credentials::{ENROLLMENT_TOKEN_PREFIX, digest, mint};
        let (operations, _) = operations();
        let issue = || {
            let token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
            operations
                .store
                .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                    token_digest: digest(&token),
                    environment_id: "prod".into(),
                    expires_at: i64::MAX,
                    created_by: "operator".into(),
                })
                .unwrap();
            RuntimeEnrollRequest {
                token,
                csr: None,
                attestation: None,
                sealing_public_key: None,
            }
        };
        let request = issue();
        // Presented to another environment, the token is refused and kept.
        assert!(matches!(
            operations.enroll("stage", &request).await,
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        let enrolled = operations.enroll("prod", &request).await.unwrap();
        assert_eq!(enrolled.credential_id, digest(&enrolled.credential));
        assert!(matches!(
            operations.enroll("prod", &request).await,
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        let admit = |token: &str, environment: &str| {
            operations
                .admit(Some(token), &Some("instance-a").into(), environment)
                .map(|_| ())
        };
        admit(&enrolled.credential, "prod").unwrap();
        assert!(matches!(
            admit(&enrolled.credential, "stage"),
            Err(RuntimeDeliveryError::ForeignEnvironment)
        ));
        operations
            .store
            .revoke_runtime_credential(
                &enrolled.credential_id,
                1,
                &crate::storage::RuntimeRevocation {
                    reason: "test".into(),
                    revoked_by: "operator".into(),
                },
            )
            .unwrap();
        assert!(matches!(
            admit(&enrolled.credential, "prod"),
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        // Token-configured runtimes keep working.
        admit("runtime-secret", "prod").unwrap();
        assert!(matches!(
            operations
                .enroll(
                    "prod",
                    &RuntimeEnrollRequest {
                        token: "runtime-secret".into(),
                        csr: None,
                        attestation: None,
                        sealing_public_key: None,
                    }
                )
                .await,
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
    }

    #[tokio::test]
    async fn unavailable_application_context_refuses_claim_and_renewal() {
        let (mut operations, _) = operations();
        operations.reconciler = Arc::new(Port {
            store: operations.store.clone(),
            calls: Mutex::new(Vec::new()),
            ctx: None,
            plan: tokio::sync::OnceCell::new(),
        });
        assert!(matches!(
            operations
                .claim_work(Some("runtime-secret"), Some("instance-a"), "prod")
                .await,
            Err(RuntimeDeliveryError::Unavailable(_))
        ));
        assert!(matches!(
            operations
                .renew(
                    Some("runtime-secret"),
                    Some("instance-a"),
                    "prod",
                    &RuntimeHeartbeat {
                        plan_id: "plan-1".into(),
                        generation: 1,
                    }
                )
                .await,
            Err(RuntimeDeliveryError::Unavailable(_))
        ));
    }

    /// Only a runtime that names `workload_identity` is asked for an
    /// issuer candidate or offered an issuer step (ADR 0046 §2); an older
    /// one claims nothing, so it never fails the plan.
    #[tokio::test]
    async fn only_a_workload_identity_runtime_is_offered_issuer_work() {
        let (operations, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "tenkai-issuer-claim-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let runtime = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        let token =
            crate::runtime_credentials::mint(crate::runtime_credentials::ENROLLMENT_TOKEN_PREFIX)
                .unwrap();
        operations
            .store
            .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                token_digest: crate::runtime_credentials::digest(&token),
                environment_id: "prod".into(),
                expires_at: i64::MAX,
                created_by: "operator".into(),
            })
            .unwrap();
        let enrolled = operations
            .enroll(
                "prod",
                &RuntimeEnrollRequest {
                    token,
                    csr: None,
                    attestation: None,
                    sealing_public_key: Some(runtime.public().to_wire()),
                },
            )
            .await
            .unwrap();
        crate::identity_issuer::request_candidate(&mut ctx, "prod")
            .await
            .unwrap();
        let wanted = operations.issuer_candidate_request("prod").await.unwrap();
        assert_eq!(wanted.map(|request| request.generation), Some(1));
        let key = crate::identity_issuer::generate(
            "prod",
            1,
            runtime.public(),
            crate::now_millis() / 1000,
        )
        .unwrap();
        let own = runtime.fingerprint();
        crate::identity_issuer::store_candidate(&mut ctx, "prod", key, || Ok(Some(own)))
            .await
            .unwrap();
        assert!(
            operations
                .issuer_candidate_request("prod")
                .await
                .unwrap()
                .is_none()
        );

        let env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        let step = crate::identity_issuer::activation_step(&env_obj, "prod").unwrap();
        let plan = crate::plan::create_from_steps(&mut ctx, "prod", vec![step])
            .await
            .unwrap();
        port.plan.set(plan.clone()).unwrap();
        let credential = Some(enrolled.credential.as_str());
        let older = operations
            .claim_work(credential, Some("instance-a"), "prod")
            .await
            .unwrap();
        assert!(older.plan.is_none() && older.claim.is_none());
        let capable = RuntimeCaller {
            instance: Some("instance-a"),
            workload_identity: true,
            peer_grants: true,
            issuer_rotation: true,
            issuer_take_up: true,
            issuer_removal: true,
            ..RuntimeCaller::default()
        };
        // The static runtime holds no wrap of the issuer key.
        let unwrapped = operations
            .claim_work(Some("runtime-secret"), capable, "prod")
            .await
            .unwrap();
        assert!(unwrapped.plan.is_none() && unwrapped.claim.is_none());
        let work = operations
            .claim_work(credential, capable, "prod")
            .await
            .unwrap();
        assert_eq!(work.plan.map(|plan| plan.id), Some(plan.id));
        assert!(work.claim.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A runtime turned away from an issuer plan (no capability, or no wrap
    /// of the key) still has the server apply the durable completion of a
    /// lost claimant once its claim lapses, so the plan never blocks.
    #[tokio::test]
    async fn a_lapsed_issuer_completion_is_applied_for_a_runtime_that_may_not_run_it() {
        let (operations, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "tenkai-issuer-lapsed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let runtime = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        crate::identity_issuer::request_candidate(&mut ctx, "prod")
            .await
            .unwrap();
        let key = crate::identity_issuer::generate(
            "prod",
            1,
            runtime.public(),
            crate::now_millis() / 1000,
        )
        .unwrap();
        let own = runtime.fingerprint();
        crate::identity_issuer::store_candidate(&mut ctx, "prod", key, || Ok(Some(own)))
            .await
            .unwrap();
        let env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        let step = crate::identity_issuer::activation_step(&env_obj, "prod").unwrap();
        let plan = crate::plan::create_from_steps(&mut ctx, "prod", vec![step])
            .await
            .unwrap();
        port.plan.set(plan.clone()).unwrap();

        // The generating runtime stored its completion, then was lost.
        let gone = runtime_owner("runtime-secret", "instance-a");
        let lease_until = crate::now_millis() + 2_000;
        let claim = operations
            .store
            .claim_runtime_plan("prod", &plan.id, &gone, lease_until)
            .unwrap()
            .unwrap();
        let completion = RuntimeCompletion {
            plan_id: plan.id.clone(),
            generation: claim.generation,
            succeeded: true,
            detail: "done".into(),
            receipts: Vec::new(),
        };
        operations
            .store
            .complete_runtime_plan(
                &plan.id,
                &gone,
                claim.generation,
                &serde_json::to_string(&completion).unwrap(),
            )
            .unwrap();
        let remaining = lease_until - crate::now_millis() + 20;
        tokio::time::sleep(std::time::Duration::from_millis(remaining.max(0) as u64)).await;

        let capable = RuntimeCaller {
            instance: Some("instance-b"),
            workload_identity: true,
            peer_grants: true,
            issuer_rotation: true,
            issuer_take_up: true,
            issuer_removal: true,
            ..RuntimeCaller::default()
        };
        for caller in [RuntimeCaller::from(Some("instance-b")), capable] {
            let work = operations
                .claim_work(Some("runtime-secret"), caller, "prod")
                .await
                .unwrap();
            assert!(work.plan.is_none() && work.claim.is_none());
        }
        assert!(port.calls.lock().unwrap().contains(&"complete"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An issuer plan whose key only a revoked runtime holds is blocked by
    /// the next runtime that polls, so it does not block the environment.
    #[tokio::test]
    async fn an_issuer_plan_no_runtime_can_open_is_blocked() {
        let (operations, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "tenkai-issuer-orphan-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Generated by a runtime that is no longer an unrevoked recipient.
        let revoked = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        crate::identity_issuer::request_candidate(&mut ctx, "prod")
            .await
            .unwrap();
        let key = crate::identity_issuer::generate(
            "prod",
            1,
            revoked.public(),
            crate::now_millis() / 1000,
        )
        .unwrap();
        let own = revoked.fingerprint();
        crate::identity_issuer::store_candidate(&mut ctx, "prod", key, || Ok(Some(own)))
            .await
            .unwrap();
        let env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        let step = crate::identity_issuer::activation_step(&env_obj, "prod").unwrap();
        let plan = crate::plan::create_from_steps(&mut ctx, "prod", vec![step])
            .await
            .unwrap();
        port.plan.set(plan.clone()).unwrap();

        // An older runtime, which never runs issuer steps, blocks it too.
        let work = operations
            .claim_work(Some("runtime-secret"), Some("instance-b"), "prod")
            .await
            .unwrap();
        assert!(work.plan.is_none() && work.claim.is_none());
        let stored = crate::plan::load(&mut ctx, &plan.id).await.unwrap();
        assert_eq!(stored.state, crate::plan::PlanState::Blocked);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A replay of an applied issuer completion is accepted after a later
    /// rotation; a completion not yet applied is still checked as stale.
    /// Run the issue step of a rotation whose add step was recorded.
    async fn issue_next(ctx: &mut Ctx) {
        let env_obj = crate::environment::environment(ctx, "prod").await.unwrap();
        let issue = crate::identity_issuer::issue_step(ctx, &env_obj, crate::now_millis() / 1000)
            .await
            .unwrap();
        crate::identity_issuer::record_activated(ctx, "prod", "plan-test", &[&issue])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_applied_issuer_completion_replays_after_a_rotation() {
        let (_, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "tenkai-issuer-replay-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let runtime = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        let mut plans = Vec::new();
        for generation in 1..=2 {
            crate::identity_issuer::request_candidate(&mut ctx, "prod")
                .await
                .unwrap();
            let key = crate::identity_issuer::generate(
                "prod",
                generation,
                runtime.public(),
                crate::now_millis() / 1000,
            )
            .unwrap();
            let own = runtime.fingerprint();
            crate::identity_issuer::store_candidate(&mut ctx, "prod", key, || Ok(Some(own)))
                .await
                .unwrap();
            let env_obj = crate::environment::environment(&mut ctx, "prod")
                .await
                .unwrap();
            let step = crate::identity_issuer::activation_step(&env_obj, "prod").unwrap();
            let mut plan = crate::plan::create_from_steps(&mut ctx, "prod", vec![step.clone()])
                .await
                .unwrap();
            crate::identity_issuer::record_activated(&mut ctx, "prod", "plan-test", &[&step])
                .await
                .unwrap();
            if generation == 2 {
                issue_next(&mut ctx).await;
            }
            for state in [
                crate::plan::PlanState::Running,
                crate::plan::PlanState::Succeeded,
            ] {
                crate::plan::transition(
                    &mut ctx,
                    &mut plan,
                    crate::plan::Transition::new(state, "applied"),
                    crate::plan::Persistence::Standard,
                )
                .await
                .unwrap();
            }
            plans.push(plan);
        }
        let completion = |plan: &crate::plan::Plan| RuntimeCompletion {
            plan_id: plan.id.clone(),
            generation: 1,
            succeeded: true,
            detail: "done".into(),
            receipts: vec![RuntimeStepReceipt {
                step_id: plan.steps[0].id.clone(),
                succeeded: true,
                detail: "done".into(),
                wraps: Vec::new(),
            }],
        };
        validate_runtime_completion(&mut ctx, "prod", &completion(&plans[0]))
            .await
            .unwrap();

        // The same generation-1 step in a plan not yet applied is stale.
        let stale = crate::plan::create_from_steps(&mut ctx, "prod", plans[0].steps.clone())
            .await
            .unwrap();
        let error = validate_runtime_completion(&mut ctx, "prod", &completion(&stale))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("stale"), "{error:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An issuer plan made before the issuer rotated past it is blocked
    /// before it is handed out: its completion would be refused as stale,
    /// so it would otherwise block the environment.
    #[tokio::test]
    async fn a_stale_issuer_plan_is_blocked_before_dispatch() {
        let (operations, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "tenkai-issuer-stale-plan-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let runtime = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        let mut stale = None;
        for generation in 1..=2 {
            crate::identity_issuer::request_candidate(&mut ctx, "prod")
                .await
                .unwrap();
            let key = crate::identity_issuer::generate(
                "prod",
                generation,
                runtime.public(),
                crate::now_millis() / 1000,
            )
            .unwrap();
            let own = runtime.fingerprint();
            crate::identity_issuer::store_candidate(&mut ctx, "prod", key, || Ok(Some(own)))
                .await
                .unwrap();
            let env_obj = crate::environment::environment(&mut ctx, "prod")
                .await
                .unwrap();
            let step = crate::identity_issuer::activation_step(&env_obj, "prod").unwrap();
            if generation == 1 {
                stale = Some(
                    crate::plan::create_from_steps(&mut ctx, "prod", vec![step.clone()])
                        .await
                        .unwrap(),
                );
            }
            crate::identity_issuer::record_activated(&mut ctx, "prod", "plan-test", &[&step])
                .await
                .unwrap();
            if generation == 2 {
                issue_next(&mut ctx).await;
            }
        }
        let stale = stale.unwrap();
        port.plan.set(stale.clone()).unwrap();

        let work = operations
            .claim_work(Some("runtime-secret"), Some("instance-a"), "prod")
            .await
            .unwrap();
        assert!(work.plan.is_none() && work.claim.is_none());
        let stored = crate::plan::load(&mut ctx, &stale.id).await.unwrap();
        assert_eq!(stored.state, crate::plan::PlanState::Blocked);
        assert!(
            stored.status_detail.contains("changed"),
            "{}",
            stored.status_detail
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While a next issuer waits, idle work can hand out its approved add
    /// plan with the approvals collected for it; once it issues, the issue
    /// plan instead; without a rotation there is none.
    #[tokio::test]
    async fn issuer_proofs_are_the_approved_rotation_plans() {
        let (operations, port) = operations();
        let mut ctx = port.ctx.clone().unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "issuer")
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "tenkai-next-proof-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let runtime = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        let mut add_plan = None;
        for generation in 1..=2 {
            crate::identity_issuer::request_candidate(&mut ctx, "prod")
                .await
                .unwrap();
            let key = crate::identity_issuer::generate(
                "prod",
                generation,
                runtime.public(),
                crate::now_millis() / 1000,
            )
            .unwrap();
            let own = runtime.fingerprint();
            crate::identity_issuer::store_candidate(&mut ctx, "prod", key, || Ok(Some(own)))
                .await
                .unwrap();
            let env_obj = crate::environment::environment(&mut ctx, "prod")
                .await
                .unwrap();
            let step = crate::identity_issuer::activation_step(&env_obj, "prod").unwrap();
            let plan = crate::plan::create_from_steps(&mut ctx, "prod", vec![step.clone()])
                .await
                .unwrap();
            crate::identity_issuer::record_activated(&mut ctx, "prod", &plan.id, &[&step])
                .await
                .unwrap();
            add_plan = Some(plan);
        }
        let add_plan = add_plan.unwrap();
        let ids = |proofs: Vec<crate::identity_issuer::IssuerProof>| {
            proofs
                .into_iter()
                .map(|proof| proof.plan.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(operations.issuer_proofs("prod", true).await),
            [add_plan.id]
        );
        assert!(operations.issuer_proofs("staging", true).await.is_empty());
        // Once the next issuer issues, its issue plan proves the issuer it
        // replaced, for a runtime that joins later.
        let env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        let step =
            crate::identity_issuer::issue_step(&mut ctx, &env_obj, crate::now_millis() / 1000)
                .await
                .unwrap();
        let issue_plan = crate::plan::create_from_steps(&mut ctx, "prod", vec![step.clone()])
            .await
            .unwrap();
        crate::identity_issuer::record_activated(&mut ctx, "prod", &issue_plan.id, &[&step])
            .await
            .unwrap();
        let proofs = operations.issuer_proofs("prod", true).await;
        let env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        assert_eq!(
            proofs[0].current,
            crate::identity_issuer::current(&env_obj).unwrap()
        );
        assert_eq!(ids(proofs), [issue_plan.id]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_runtime_claims_nothing_while_the_server_holds_the_environment() {
        let (operations, port) = operations();
        // The plan exists before the server takes the environment.
        port.pending_work("prod".into()).await.unwrap().unwrap();
        let mut ctx = port.ctx.clone().unwrap();
        ctx.acquire_lease(
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            "prod",
            "plan-0",
            60_000,
        )
        .await
        .unwrap();
        let work = operations
            .claim_work(Some("runtime-secret"), Some("instance-a"), "prod")
            .await
            .unwrap();
        assert!(work.claim.is_none() && work.plan.is_none());
    }

    #[tokio::test]
    async fn a_plan_the_server_stopped_is_failed_not_run_again_by_a_runtime() {
        let (operations, port) = operations();
        let mut plan = port.pending_work("prod".into()).await.unwrap().unwrap();
        let mut ctx = port.ctx.clone().unwrap();
        crate::plan::transition(
            &mut ctx,
            &mut plan,
            crate::plan::Transition::new(PlanState::Running, "server execution"),
            crate::plan::Persistence::Standard,
        )
        .await
        .unwrap();
        let work = operations
            .claim_work(Some("runtime-secret"), Some("instance-a"), "prod")
            .await
            .unwrap();
        assert!(work.plan.is_none() && work.claim.is_none());
        assert_eq!(
            crate::plan::load(&mut ctx, &plan.id).await.unwrap().state,
            PlanState::Failed
        );
    }

    #[tokio::test]
    async fn a_lapsed_runtime_completion_is_applied_by_the_server() {
        let (operations, port) = operations();
        let plan = port.pending_work("prod".into()).await.unwrap().unwrap();
        // A runtime stored its completion, then stopped before applying it.
        let gone = runtime_owner("runtime-secret", "instance-a");
        // Long enough that the check before the lapse runs inside it on a
        // loaded machine; a 20 ms lease lapsed before it under parallel runs.
        let lease_until = crate::now_millis() + 2_000;
        let claim = operations
            .store
            .claim_runtime_plan("prod", &plan.id, &gone, lease_until)
            .unwrap()
            .unwrap();
        let completion = RuntimeCompletion {
            plan_id: plan.id.clone(),
            generation: claim.generation,
            succeeded: true,
            detail: "done".into(),
            receipts: Vec::new(),
        };
        operations
            .store
            .complete_runtime_plan(
                &plan.id,
                &gone,
                claim.generation,
                &serde_json::to_string(&completion).unwrap(),
            )
            .unwrap();
        let before_lapse = operations
            .claim_work(Some("runtime-secret"), Some("instance-b"), "prod")
            .await
            .unwrap();
        assert!(before_lapse.claim.is_none());
        assert!(!port.calls.lock().unwrap().contains(&"complete"));

        let remaining = lease_until - crate::now_millis() + 20;
        tokio::time::sleep(std::time::Duration::from_millis(remaining.max(0) as u64)).await;
        let work = operations
            .claim_work(Some("runtime-secret"), Some("instance-b"), "prod")
            .await
            .unwrap();
        assert!(work.claim.is_none());
        assert!(port.calls.lock().unwrap().contains(&"complete"));
    }

    #[tokio::test]
    async fn a_runtime_takes_over_after_the_server_lease_expires() {
        let (operations, port) = operations();
        port.pending_work("prod".into()).await.unwrap().unwrap();
        let mut ctx = port.ctx.clone().unwrap();
        // A server that crashed while executing: its lease lapses.
        ctx.acquire_lease(
            crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
            "prod",
            "plan-0",
            1,
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let work = operations
            .claim_work(Some("runtime-secret"), Some("instance-a"), "prod")
            .await
            .unwrap();
        assert!(work.claim.is_some());
    }

    #[tokio::test]
    async fn interface_concentrates_admission_claim_fencing_and_completion_order() {
        let (operations, port) = operations();

        assert!(matches!(
            operations
                .claim_work(None, Some("instance-a"), "prod")
                .await,
            Err(RuntimeDeliveryError::MissingCredential)
        ));
        assert!(matches!(
            operations
                .claim_work(Some("runtime-secret"), Some("instance-a"), "other")
                .await,
            Err(RuntimeDeliveryError::ForeignEnvironment)
        ));

        let first = operations
            .claim_work(Some("runtime-secret"), Some("instance-a"), "prod")
            .await
            .unwrap();
        let claim = first.claim.unwrap();
        assert_eq!(claim.generation, 1);
        let overlapping = operations
            .claim_work(Some("runtime-secret"), Some("instance-b"), "prod")
            .await
            .unwrap();
        assert!(overlapping.claim.is_none());

        let renewed = operations
            .renew(
                Some("runtime-secret"),
                Some("instance-a"),
                "prod",
                &RuntimeHeartbeat {
                    plan_id: claim.plan_id.clone(),
                    generation: claim.generation,
                },
            )
            .await
            .unwrap();
        assert_eq!(renewed.generation, claim.generation);

        operations
            .complete(
                Some("runtime-secret"),
                Some("instance-a"),
                "prod",
                RuntimeCompletion {
                    plan_id: claim.plan_id.clone(),
                    generation: claim.generation,
                    succeeded: true,
                    detail: "deployed".into(),
                    receipts: Vec::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(*port.calls.lock().unwrap(), vec!["validate", "complete"]);
    }

    #[tokio::test]
    async fn interface_rejects_invalid_inventory_before_application_mutation() {
        let (operations, _) = operations();
        let error = operations
            .report_inventory(
                Some("runtime-secret"),
                Some("instance-a"),
                "prod",
                RuntimeInventoryReport {
                    facts: BTreeMap::from([("architecture".into(), "arm64".into())]),
                    source: "token=secret".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeDeliveryError::InvalidRequest(_)));

        let response = operations
            .report_inventory(
                Some("runtime-secret"),
                Some("instance-a"),
                "prod",
                RuntimeInventoryReport {
                    facts: BTreeMap::from([("architecture".into(), "arm64".into())]),
                    source: "runtime-probe".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(response.applied, vec!["architecture"]);
    }

    /// #809: a runner enrolled without a CSR, or before certificates were
    /// recorded, reads as certified once a renewal issues it one.
    #[tokio::test]
    async fn a_renewal_records_the_runner_as_certified() {
        use crate::runtime_credentials::{ENROLLMENT_TOKEN_PREFIX, digest, mint};
        let (operations, _) = operations();
        let (cert, key) = crate::runner_ca::RunnerCa::generate("test runner CA").unwrap();
        let operations = operations.with_runner_ca(Arc::new(
            crate::runner_ca::RunnerCa::from_pem(&cert, &key).unwrap(),
        ));
        let token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
        operations
            .store
            .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                token_digest: digest(&token),
                environment_id: "prod".into(),
                expires_at: i64::MAX,
                created_by: "operator".into(),
            })
            .unwrap();
        let enrolled = operations
            .enroll(
                "prod",
                &RuntimeEnrollRequest {
                    token,
                    csr: None,
                    attestation: None,
                    sealing_public_key: None,
                },
            )
            .await
            .unwrap();
        assert!(
            operations
                .store
                .certified_runtime_runners()
                .unwrap()
                .is_empty()
        );
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        operations
            .renew_certificate(
                Some(&enrolled.credential),
                RuntimeCaller {
                    instance: Some("instance-a"),
                    version: None,
                    certificate: None,
                    workload_identity: false,
                    peer_grants: false,
                    issuer_rotation: false,
                    issuer_take_up: false,
                    issuer_removal: false,
                },
                "prod",
                &RuntimeCertificateRequest {
                    csr,
                    attestation: None,
                    sealing_public_key: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            operations.store.certified_runtime_runners().unwrap(),
            [enrolled.credential_id]
        );
    }

    #[tokio::test]
    async fn sealing_keys_are_bound_to_one_runtime_and_dropped_on_revoke() {
        use crate::runtime_credentials::{ENROLLMENT_TOKEN_PREFIX, digest, mint};
        let (operations, _) = operations();
        let first =
            crate::sealing_key::SealingKey::open_or_generate(&std::env::temp_dir().join(format!(
                "tenkai-sealing-first-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            )))
            .unwrap();
        let second =
            crate::sealing_key::SealingKey::open_or_generate(&std::env::temp_dir().join(format!(
                "tenkai-sealing-second-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            )))
            .unwrap();
        let rotated =
            crate::sealing_key::SealingKey::open_or_generate(&std::env::temp_dir().join(format!(
                "tenkai-sealing-rotated-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            )))
            .unwrap();
        let issue = || {
            let token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
            operations
                .store
                .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                    token_digest: digest(&token),
                    environment_id: "prod".into(),
                    expires_at: i64::MAX,
                    created_by: "operator".into(),
                })
                .unwrap();
            token
        };
        let a = operations
            .enroll(
                "prod",
                &RuntimeEnrollRequest {
                    token: issue(),
                    csr: None,
                    attestation: None,
                    sealing_public_key: Some(first.to_wire()),
                },
            )
            .await
            .unwrap();
        let b = operations
            .enroll(
                "prod",
                &RuntimeEnrollRequest {
                    token: issue(),
                    csr: None,
                    attestation: None,
                    sealing_public_key: Some(second.to_wire()),
                },
            )
            .await
            .unwrap();
        let offered: Vec<_> = operations
            .environment_recipient_keys("prod")
            .unwrap()
            .into_iter()
            .map(|record| record.fingerprint)
            .collect();
        assert!(offered.contains(&first.fingerprint()));
        assert!(offered.contains(&second.fingerprint()));

        operations
            .store
            .revoke_runtime_credential(
                &b.credential_id,
                1,
                &crate::storage::RuntimeRevocation {
                    reason: "lost".into(),
                    revoked_by: "operator".into(),
                },
            )
            .unwrap();
        let offered: Vec<_> = operations
            .environment_recipient_keys("prod")
            .unwrap()
            .into_iter()
            .map(|record| record.fingerprint)
            .collect();
        assert_eq!(offered, vec![first.fingerprint()]);

        operations
            .renew_certificate(
                Some(&a.credential),
                RuntimeCaller {
                    instance: Some("instance-a"),
                    version: None,
                    certificate: None,
                    workload_identity: false,
                    peer_grants: false,
                    issuer_rotation: false,
                    issuer_take_up: false,
                    issuer_removal: false,
                },
                "prod",
                &RuntimeCertificateRequest {
                    csr: rcgen::CertificateParams::new(Vec::<String>::new())
                        .unwrap()
                        .serialize_request(&rcgen::KeyPair::generate().unwrap())
                        .unwrap()
                        .pem()
                        .unwrap(),
                    attestation: None,
                    sealing_public_key: Some(rotated.to_wire()),
                },
            )
            .await
            .unwrap_err();
        // Renewal without a runner CA is refused; the recorded key is unchanged.
        let offered: Vec<_> = operations
            .environment_recipient_keys("prod")
            .unwrap()
            .into_iter()
            .map(|record| record.fingerprint)
            .collect();
        assert_eq!(offered, vec![first.fingerprint()]);

        let (cert, ca_key) = crate::runner_ca::RunnerCa::generate("runner CA").unwrap();
        let ca = Arc::new(crate::runner_ca::RunnerCa::from_pem(&cert, &ca_key).unwrap());
        let operations = operations.with_runner_ca(ca);
        operations
            .renew_certificate(
                Some(&a.credential),
                RuntimeCaller {
                    instance: Some("instance-a"),
                    version: None,
                    certificate: None,
                    workload_identity: false,
                    peer_grants: false,
                    issuer_rotation: false,
                    issuer_take_up: false,
                    issuer_removal: false,
                },
                "prod",
                &RuntimeCertificateRequest {
                    csr: rcgen::CertificateParams::new(Vec::<String>::new())
                        .unwrap()
                        .serialize_request(&rcgen::KeyPair::generate().unwrap())
                        .unwrap()
                        .pem()
                        .unwrap(),
                    attestation: None,
                    sealing_public_key: Some(rotated.to_wire()),
                },
            )
            .await
            .unwrap();
        let offered = operations.environment_recipient_keys("prod").unwrap();
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].runner_id, a.credential_id);
        assert_eq!(offered[0].fingerprint, rotated.fingerprint());
        assert_ne!(offered[0].fingerprint, first.fingerprint());
        assert_ne!(offered[0].fingerprint, second.fingerprint());
    }

    #[tokio::test]
    async fn a_malformed_sealing_key_is_refused_before_the_token_is_spent() {
        use crate::runtime_credentials::{ENROLLMENT_TOKEN_PREFIX, digest, mint};
        let (operations, _) = operations();
        let token = mint(ENROLLMENT_TOKEN_PREFIX).unwrap();
        operations
            .store
            .create_runtime_enrollment(&crate::storage::RuntimeEnrollmentRecord {
                token_digest: digest(&token),
                environment_id: "prod".into(),
                expires_at: i64::MAX,
                created_by: "operator".into(),
            })
            .unwrap();
        assert!(matches!(
            operations
                .enroll(
                    "prod",
                    &RuntimeEnrollRequest {
                        token: token.clone(),
                        csr: None,
                        attestation: None,
                        sealing_public_key: Some("not-a-key".into()),
                    },
                )
                .await,
            Err(RuntimeDeliveryError::InvalidRequest(_))
        ));
        operations
            .enroll(
                "prod",
                &RuntimeEnrollRequest {
                    token,
                    csr: None,
                    attestation: None,
                    sealing_public_key: None,
                },
            )
            .await
            .unwrap();
    }
}

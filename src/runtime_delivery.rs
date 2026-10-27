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
    for step in &plan.steps {
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
    let observed_at = crate::now_millis();
    let mut environment_object = None;
    if crate::apply::environment_lease_status(ctx, environment)
        .await?
        .is_some()
    {
        anyhow::bail!("environment {environment} has an apply in progress");
    }
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
            &stored.steps,
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
        let succeeded_steps = stored
            .steps
            .iter()
            .filter(|step| {
                completion
                    .receipts
                    .iter()
                    .any(|receipt| receipt.step_id == step.id && receipt.succeeded)
            })
            .cloned()
            .collect::<Vec<_>>();
        crate::plan::update_runtime_deployments_object(ctx, object, &succeeded_steps, observed_at)
            .await?;
    }
    for step in &stored.steps {
        let Some(receipt) = completion
            .receipts
            .iter()
            .find(|receipt| receipt.step_id == step.id)
        else {
            continue;
        };
        let key = format!("failed_target.{}", step.product);
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
        if !receipt.succeeded && step.action != crate::plan::Action::Rollback {
            object.properties.insert(key, step.release_id.clone());
            object.properties.insert(
                format!("failed_target_plan.{}", step.product),
                stored.id.clone(),
            );
            object.properties.insert(
                format!("failed_target_at.{}", step.product),
                observed_at.to_string(),
            );
        } else if receipt.succeeded && object.properties.get(&key) == Some(&step.release_id) {
            object.properties.remove(&key);
            object
                .properties
                .remove(&format!("failed_target_plan.{}", step.product));
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
        stored
            .steps
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
    if let Some(environment) = environment_object {
        if !ctx.is_embedded() {
            ctx.put(environment).await?;
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
            crate::plan::Persistence::WithEnvironmentAndProviderEvents {
                environment,
                provider_events: &provider_events,
            },
        )
        .await?;
    } else {
        crate::plan::transition(
            ctx,
            &mut stored,
            crate::plan::Transition::new(terminal, completion.detail.clone()),
            crate::plan::Persistence::WithProviderEvents(&provider_events),
        )
        .await?;
    }
    Ok(())
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
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWork {
    pub environment: String,
    pub plan: Option<Plan>,
    pub claim: Option<RuntimeClaim>,
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
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Internal(String),
}

struct RuntimeIdentity {
    owner: String,
}

/// Deep runtime delivery module used after transport extraction.
pub struct RuntimeDeliveryOperations {
    assignments: HashMap<String, String>,
    reconciler: Arc<dyn ReconcilePort>,
    store: Arc<dyn OperationalStore>,
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
        }
    }

    pub async fn claim_work(
        &self,
        token: Option<&str>,
        instance: Option<&str>,
        environment: &str,
    ) -> Result<RuntimeWork, RuntimeDeliveryError> {
        let identity = self.admit(token, instance, environment)?;
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
                    return Ok(RuntimeWork {
                        environment: environment.into(),
                        plan: None,
                        claim: None,
                    });
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
            return Ok(RuntimeWork {
                environment: environment.into(),
                plan: None,
                claim: None,
            });
        };
        let Some(mut ctx) = self.reconciler.application_ctx() else {
            return Err(RuntimeDeliveryError::Unavailable(
                "software compatibility preflight unavailable".into(),
            ));
        };
        for step in &plan.steps {
            crate::software_compatibility::require_release(&mut ctx, environment, &step.release_id)
                .await
                .map_err(|error| {
                    match error
                        .downcast_ref::<crate::software_compatibility::CompatibilityBlocked>()
                    {
                        Some(blocked) => RuntimeDeliveryError::InvalidRequest(blocked.to_string()),
                        None => RuntimeDeliveryError::Unavailable(
                            "software compatibility preflight unavailable".into(),
                        ),
                    }
                })?;
        }
        // A held queued plan stays queued; a claimed Running plan finishes.
        let held = plan.state == crate::plan::PlanState::Computed
            && crate::delivery_hold::active_for_plan(&mut ctx, &plan)
                .await
                .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?
                .is_some();
        if held {
            return Ok(RuntimeWork {
                environment: environment.into(),
                plan: None,
                claim: None,
            });
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
                    return Ok(RuntimeWork {
                        environment: environment.into(),
                        plan: None,
                        claim: None,
                    });
                }
                // Placement admits new execution only: a claim holding a
                // durable completion is replayed whatever the facts say now.
                if claim.completion_json.is_none() {
                    require_runtime_placement(&mut ctx, environment, &plan).await?;
                }
                Ok(RuntimeWork {
                    environment: environment.into(),
                    plan: Some(plan),
                    claim: Some(claim),
                })
            }
            None => {
                // Another runtime's claim. If it stored its completion and
                // then stopped, or was revoked, before it was applied, the
                // server applies it once that claim lapses (#630).
                let lapsed = self
                    .store
                    .lapsed_runtime_completion(environment, &plan.id, crate::now_millis())
                    .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
                if let Some(completion_json) = lapsed {
                    let completion: RuntimeCompletion = serde_json::from_str(&completion_json)
                        .map_err(|error| RuntimeDeliveryError::Internal(error.to_string()))?;
                    self.reconciler
                        .complete_work(environment.to_string(), completion)
                        .await
                        .map_err(|error| RuntimeDeliveryError::Internal(format!("{error:#}")))?;
                }
                Ok(RuntimeWork {
                    environment: environment.into(),
                    plan: None,
                    claim: None,
                })
            }
        }
    }

    pub async fn complete(
        &self,
        token: Option<&str>,
        instance: Option<&str>,
        environment: &str,
        completion: RuntimeCompletion,
    ) -> Result<(), RuntimeDeliveryError> {
        let identity = self.admit(token, instance, environment)?;
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
        self.reconciler
            .complete_work(environment.to_string(), completion)
            .await
            .map_err(|error| RuntimeDeliveryError::Internal(format!("{error:#}")))
    }

    pub async fn renew(
        &self,
        token: Option<&str>,
        instance: Option<&str>,
        environment: &str,
        heartbeat: &RuntimeHeartbeat,
    ) -> Result<RuntimeClaim, RuntimeDeliveryError> {
        let identity = self.admit(token, instance, environment)?;
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
        for step in &plan.steps {
            crate::software_compatibility::require_release(&mut ctx, environment, &step.release_id)
                .await
                .map_err(|error| {
                    match error
                        .downcast_ref::<crate::software_compatibility::CompatibilityBlocked>()
                    {
                        Some(blocked) => RuntimeDeliveryError::InvalidRequest(blocked.to_string()),
                        None => RuntimeDeliveryError::Unavailable(
                            "software compatibility preflight unavailable".into(),
                        ),
                    }
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
        instance: Option<&str>,
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
            instance,
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

    pub async fn report_inventory(
        &self,
        token: Option<&str>,
        instance: Option<&str>,
        environment: &str,
        report: RuntimeInventoryReport,
    ) -> Result<RuntimeInventoryResponse, RuntimeDeliveryError> {
        self.admit(token, instance, environment)?;
        validate_inventory_source(&report.source)?;
        let applied = self
            .reconciler
            .apply_inventory_facts(environment.to_string(), report.facts)
            .await
            .map_err(|error| RuntimeDeliveryError::InvalidRequest(format!("{error:#}")))?;
        Ok(RuntimeInventoryResponse {
            environment: environment.into(),
            source: report.source,
            applied,
        })
    }

    fn admit(
        &self,
        token: Option<&str>,
        instance: Option<&str>,
        environment: &str,
    ) -> Result<RuntimeIdentity, RuntimeDeliveryError> {
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
        })
    }
}

/// What a runtime agent sends to exchange its enrollment token (#630).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnrollRequest {
    pub token: String,
}

/// The agent's own credential, shown only in this response. `credential_id`
/// is what an operator revokes it by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEnrolled {
    pub environment: String,
    pub credential: String,
    pub credential_id: String,
}

impl RuntimeDeliveryOperations {
    /// Exchange a single-use enrollment token of `environment` for a runtime
    /// credential. An unknown, spent, expired or foreign token is refused
    /// alike, and a refused token is not spent.
    pub fn enroll(
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
        // A drifted clock must not stretch a token's expiry.
        crate::clock_guard::require_trusted_time("runtime enrollment")
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        let credential = mint(CREDENTIAL_PREFIX)
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        let record = match self.store.redeem_runtime_enrollment(
            environment,
            &digest(&request.token),
            &digest(&credential),
            crate::now_millis(),
        ) {
            Ok(record) => record,
            Err(crate::storage::StoreError::InvalidData { .. }) => {
                return Err(RuntimeDeliveryError::InvalidCredential);
            }
            Err(error) => return Err(RuntimeDeliveryError::Unavailable(error.to_string())),
        };
        Ok(RuntimeEnrolled {
            environment: record.environment_id,
            credential,
            credential_id: record.credential_digest,
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

    #[test]
    fn an_enrolled_agent_is_admitted_to_its_environment_until_revoked() {
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
            RuntimeEnrollRequest { token }
        };
        let request = issue();
        // Presented to another environment, the token is refused and kept.
        assert!(matches!(
            operations.enroll("stage", &request),
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        let enrolled = operations.enroll("prod", &request).unwrap();
        assert_eq!(enrolled.credential_id, digest(&enrolled.credential));
        assert!(matches!(
            operations.enroll("prod", &request),
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        let admit = |token: &str, environment: &str| {
            operations
                .admit(Some(token), Some("instance-a"), environment)
                .map(|_| ())
        };
        admit(&enrolled.credential, "prod").unwrap();
        assert!(matches!(
            admit(&enrolled.credential, "stage"),
            Err(RuntimeDeliveryError::ForeignEnvironment)
        ));
        operations
            .store
            .revoke_runtime_credential(&enrolled.credential_id, 1)
            .unwrap();
        assert!(matches!(
            admit(&enrolled.credential, "prod"),
            Err(RuntimeDeliveryError::InvalidCredential)
        ));
        // Token-configured runtimes keep working.
        admit("runtime-secret", "prod").unwrap();
        assert!(matches!(
            operations.enroll(
                "prod",
                &RuntimeEnrollRequest {
                    token: "runtime-secret".into()
                }
            ),
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
        let claim = operations
            .store
            .claim_runtime_plan("prod", &plan.id, &gone, crate::now_millis() + 20)
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

        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
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
}

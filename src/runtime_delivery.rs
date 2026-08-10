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

use crate::plan::{
    EnvironmentInspectReport, EnvironmentListEntry, FleetStatusReport, Plan, StatusRow,
};
use crate::reconciler::{ReconcileDiagnostics, Reconciler, RuntimeCompletion, TickReport};
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
        Box::pin(async move { self.complete_runtime_work(&environment, &completion).await })
    }

    fn validate_completion(
        &self,
        environment: String,
        completion: RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async move {
            self.validate_runtime_completion(&environment, &completion)
                .await
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
            crate::plan::inspect_environment_with_outcomes(&mut ctx, &environment).await
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeWork {
    pub environment: String,
    pub plan: Option<Plan>,
    pub claim: Option<RuntimeClaim>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeHeartbeat {
    pub plan_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let expires_at = crate::now_millis().saturating_add(2 * 60 * 1000);
        let claim = self
            .store
            .claim_runtime_plan(environment, &plan.id, &identity.owner, expires_at)
            .map_err(|error| RuntimeDeliveryError::Unavailable(error.to_string()))?;
        match claim {
            Some(claim) => Ok(RuntimeWork {
                environment: environment.into(),
                plan: Some(plan),
                claim: Some(claim),
            }),
            None => Ok(RuntimeWork {
                environment: environment.into(),
                plan: None,
                claim: None,
            }),
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

    pub fn renew(
        &self,
        token: Option<&str>,
        instance: Option<&str>,
        environment: &str,
        heartbeat: &RuntimeHeartbeat,
    ) -> Result<RuntimeClaim, RuntimeDeliveryError> {
        let identity = self.admit(token, instance, environment)?;
        let expires_at = crate::now_millis().saturating_add(2 * 60 * 1000);
        self.store
            .renew_runtime_plan(
                &heartbeat.plan_id,
                &identity.owner,
                heartbeat.generation,
                expires_at,
            )
            .map_err(|error| RuntimeDeliveryError::Conflict(error.to_string()))?
            .ok_or_else(|| {
                RuntimeDeliveryError::Conflict("runtime claim is no longer active".into())
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
        let assigned = runtime_assignment(&self.assignments, token)
            .ok_or(RuntimeDeliveryError::InvalidCredential)?;
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
    }

    impl ReconcilePort for Port {
        fn reconcile(&self) -> ReconcileFuture<'_> {
            Box::pin(async { unreachable!() })
        }

        fn pending_work(&self, environment: String) -> WorkFuture<'_> {
            Box::pin(async move {
                Ok(Some(Plan {
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
                }))
            })
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
                    plan_id: "plan-1".into(),
                    generation: claim.generation,
                },
            )
            .unwrap();
        assert_eq!(renewed.generation, claim.generation);

        operations
            .complete(
                Some("runtime-secret"),
                Some("instance-a"),
                "prod",
                RuntimeCompletion {
                    plan_id: "plan-1".into(),
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

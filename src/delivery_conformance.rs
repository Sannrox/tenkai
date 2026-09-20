//! Callable, bounded PostgreSQL delivery-effect conformance (#183).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: &str = "tenkai.delivery-conformance/v1";
pub const SCHEMA_JSON: &str = include_str!("../tests/fixtures/delivery_conformance/v1.json");
pub const MAX_CHECKS: usize = 10;

const IMPLEMENTATION_SOURCES: &[&str] = &[
    include_str!("delivery_conformance.rs"),
    include_str!("bin/tenkai-delivery-conformance.rs"),
    include_str!("postgres_tenant.rs"),
    include_str!("storage.rs"),
    include_str!("runtime_capabilities.rs"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Current,
    Replayed,
    Reconciled,
    Rejected,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub operation_ref: String,
    pub passed: bool,
    pub scenarios: Vec<Outcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEvidence {
    pub shared_replica_state: bool,
    pub high_availability: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub evidence_ref: String,
    pub passed: bool,
    pub runtime_instances: u8,
    pub capabilities: CapabilityEvidence,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationError {
    Missing,
    Unsafe,
}

/// Configuration for an isolated caller-owned local PostgreSQL test database.
///
/// The URL is accepted only from `TENKAI_CONFORMANCE_POSTGRES_URL`; the CLI
/// never accepts it as an argument or includes it in output.
#[derive(Clone)]
pub struct Config {
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigurationError> {
        let url = std::env::var("TENKAI_CONFORMANCE_POSTGRES_URL")
            .map_err(|_| ConfigurationError::Missing)?;
        Self::new(url)
    }

    pub fn new(url: impl Into<String>) -> Result<Self, ConfigurationError> {
        let url = url.into();
        let parsed = url::Url::parse(&url).map_err(|_| ConfigurationError::Unsafe)?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") {
            return Err(ConfigurationError::Unsafe);
        }
        let local_host = parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
        });
        let database = parsed.path().trim_matches('/');
        if !local_host
            || database.is_empty()
            || !database.to_ascii_lowercase().contains("test")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ConfigurationError::Unsafe);
        }
        Ok(Self { url })
    }
}

pub fn require_version(candidate: &str) -> Result<(), &'static str> {
    if candidate == VERSION {
        Ok(())
    } else {
        Err("unsupported delivery conformance version")
    }
}

pub fn run_from_env() -> Report {
    match Config::from_env() {
        Ok(config) => run(&config),
        Err(_) => unavailable_report(),
    }
}

pub fn run(config: &Config) -> Report {
    #[cfg(feature = "postgres")]
    {
        run_postgres(config)
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = config;
        unavailable_report()
    }
}

fn evidence_ref() -> String {
    let mut hasher = Sha256::new();
    for source in std::iter::once(SCHEMA_JSON).chain(IMPLEMENTATION_SOURCES.iter().copied()) {
        hasher.update((source.len() as u64).to_be_bytes());
        hasher.update(source.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn unavailable_report() -> Report {
    Report {
        version: VERSION.into(),
        evidence_ref: evidence_ref(),
        passed: false,
        runtime_instances: 0,
        capabilities: CapabilityEvidence {
            shared_replica_state: false,
            high_availability: false,
        },
        checks: vec![check(
            "adapter_startup",
            "tenkai.delivery.adapter/v1",
            false,
            vec![Outcome::Unavailable],
        )],
    }
}

fn check(id: &str, operation_ref: &str, passed: bool, scenarios: Vec<Outcome>) -> Check {
    Check {
        id: id.into(),
        operation_ref: operation_ref.into(),
        passed,
        scenarios,
    }
}

#[cfg(feature = "postgres")]
struct SchemaCleanup {
    partition: Option<crate::postgres_tenant::PostgresTenantPartition>,
}

#[cfg(feature = "postgres")]
impl SchemaCleanup {
    fn new(partition: crate::postgres_tenant::PostgresTenantPartition) -> Self {
        Self {
            partition: Some(partition),
        }
    }

    fn finish(mut self) -> bool {
        self.partition
            .take()
            .is_some_and(|partition| partition.cleanup_conformance_schema().is_ok())
    }

    fn retain_partition(&mut self, partition: crate::postgres_tenant::PostgresTenantPartition) {
        self.partition = Some(partition);
    }
}

#[cfg(feature = "postgres")]
impl Drop for SchemaCleanup {
    fn drop(&mut self) {
        if let Some(partition) = self.partition.take() {
            let _ = partition.cleanup_conformance_schema();
        }
    }
}

#[cfg(feature = "postgres")]
fn run_postgres(config: &Config) -> Report {
    use crate::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use crate::postgres_tenant::{PostgresTenantConfig, tenant_postgres_store_capabilities};
    use crate::runtime_capabilities::CapabilityName;
    use crate::storage::{
        ChannelRecord, EnvironmentRecord, OperationalStore as _, PlanRecord, PlanStatus,
        ReceiptRecord, ReleaseRecord, RollbackRecord, RollbackStatus, StoreError,
    };
    use std::sync::{Arc, Barrier};

    let capabilities = tenant_postgres_store_capabilities();
    let shared = capabilities
        .capabilities
        .iter()
        .any(|capability| capability.name == CapabilityName::SharedReplicaState);
    let ha = capabilities
        .capabilities
        .iter()
        .any(|capability| capability.name == CapabilityName::HighAvailability);
    let mut checks = vec![check(
        "capability_honesty",
        "tenkai.runtime-capabilities/v1",
        shared && !ha,
        vec![
            if shared {
                Outcome::Current
            } else {
                Outcome::Unavailable
            },
            if ha {
                Outcome::Unknown
            } else {
                Outcome::Rejected
            },
        ],
    )];

    let result = (|| -> Result<bool, ()> {
        let store_config = PostgresTenantConfig::new(config.url.clone()).map_err(|_| ())?;
        let replica_a = store_config.open().map_err(|_| ())?;
        let replica_b = store_config.open().map_err(|_| ())?;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let authority = TenantDerivationAuthority::new("delivery-conformance");
        let context = AuthenticatedRequestContextBuilder::new(
            format!("delivery-conformance-{suffix}"),
            PrincipalIdentity {
                id: "synthetic-conformance".into(),
                kind: PrincipalKind::Service,
            },
            "local-test",
        )
        .with_tenant(format!("delivery-test-{suffix}"), &authority)
        .map_err(|_| ())?
        .build()
        .map_err(|_| ())?;
        let a = replica_a.partition_for(&context).map_err(|_| ())?;
        let mut cleanup = SchemaCleanup::new(a.clone());
        let b = replica_b.partition_for(&context).map_err(|_| ())?;
        cleanup.retain_partition(b.clone());

        let release = ReleaseRecord {
            id: format!("release-{suffix}"),
            product: "synthetic-api".into(),
            version: "1.0.0".into(),
            content_digest: format!("sha256:{suffix}"),
            descriptor_json: "{}".into(),
        };
        let barrier = Arc::new(Barrier::new(2));
        let (publish_a, publish_b) = std::thread::scope(|scope| {
            let left = {
                let a = a.clone();
                let release = release.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    a.publish_release(&release)
                })
            };
            let right = {
                let b = b.clone();
                let release = release.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    b.publish_release(&release)
                })
            };
            (left.join(), right.join())
        });
        let published = publish_a.is_ok_and(|value| value.is_ok())
            && publish_b.is_ok_and(|value| value.is_ok())
            && b.get_release(&release.id).map_err(|_| ())? == Some(release.clone());
        checks.push(check(
            "publication_replay",
            "tenkai.delivery.publish/v1",
            published,
            vec![Outcome::Current, Outcome::Replayed],
        ));

        let channel = ChannelRecord {
            id: format!("channel-{suffix}"),
            product: release.product.clone(),
            name: "stable".into(),
            release_id: release.id.clone(),
            revision: 0,
        };
        let barrier = Arc::new(Barrier::new(2));
        let (promotion_a, promotion_b) = std::thread::scope(|scope| {
            let left = {
                let a = a.clone();
                let channel = channel.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    a.promote_channel(&channel)
                })
            };
            let right = {
                let b = b.clone();
                let channel = channel.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    b.promote_channel(&channel)
                })
            };
            (left.join(), right.join())
        });
        let promoted = promotion_a
            .ok()
            .and_then(|value| value.ok())
            .is_some_and(|value| value.revision == 1)
            && promotion_b
                .ok()
                .and_then(|value| value.ok())
                .is_some_and(|value| value.revision == 1);
        checks.push(check(
            "promotion_replay",
            "tenkai.delivery.promote/v1",
            promoted,
            vec![Outcome::Current, Outcome::Replayed],
        ));

        let environment = EnvironmentRecord {
            id: format!("environment-{suffix}"),
            revision: 0,
            configuration_json: "{}".into(),
        };
        a.put_environment(&environment).map_err(|_| ())?;
        let plan = PlanRecord {
            id: format!("plan-{suffix}"),
            environment_id: environment.id.clone(),
            format_version: 1,
            content_digest: format!("sha256:plan-{suffix}"),
            plan_json: "{}".into(),
            status: PlanStatus::Computed,
            status_detail: String::new(),
        };
        let plan_replayed = a.create_plan(&plan).is_ok()
            && b.create_plan(&plan).is_ok()
            && b.get_plan(&plan.id).map_err(|_| ())? == Some(plan.clone());
        checks.push(check(
            "plan_replay",
            "tenkai.delivery.plan/v1",
            plan_replayed,
            vec![Outcome::Current, Outcome::Replayed],
        ));

        let lease_a = a
            .acquire_lease(
                &environment.id,
                "replica-a",
                crate::now_millis().saturating_add(60_000),
            )
            .map_err(|_| ())?;

        // A process disappears before committing the protected effect. A new
        // connection records it once, and replay converges on the same receipt.
        let before_commit = ReceiptRecord {
            id: format!("receipt-before-{suffix}"),
            environment_id: environment.id.clone(),
            plan_id: plan.id.clone(),
            step_id: "prepare".into(),
            lease_generation: lease_a.generation,
            payload_json: r#"{"outcome":"prepared"}"#.into(),
        };
        drop(a);
        drop(replica_a);
        let restarted_before_store = store_config.open().map_err(|_| ())?;
        let restarted_before = restarted_before_store
            .partition_for(&context)
            .map_err(|_| ())?;
        let before_reconciled = restarted_before
            .record_receipt("replica-a", &before_commit)
            .is_ok()
            && restarted_before
                .record_receipt("replica-a", &before_commit)
                .is_ok()
            && restarted_before
                .get_receipt(&before_commit.id)
                .map_err(|_| ())?
                == Some(before_commit);
        checks.push(check(
            "process_loss_before_commit",
            "tenkai.delivery.receipt/v1",
            before_reconciled,
            vec![Outcome::Unknown, Outcome::Reconciled, Outcome::Replayed],
        ));

        restarted_before
            .transition_plan(
                &plan.id,
                "replica-a",
                lease_a.generation,
                PlanStatus::Running,
                "started",
            )
            .map_err(|_| ())?;
        let receipt = ReceiptRecord {
            id: format!("receipt-after-{suffix}"),
            environment_id: environment.id.clone(),
            plan_id: plan.id.clone(),
            step_id: "apply".into(),
            lease_generation: lease_a.generation,
            payload_json: r#"{"outcome":"succeeded"}"#.into(),
        };
        restarted_before
            .record_receipt("replica-a", &receipt)
            .map_err(|_| ())?;
        drop(restarted_before);
        drop(restarted_before_store);
        let restarted_after_store = store_config.open().map_err(|_| ())?;
        let restarted_after = restarted_after_store
            .partition_for(&context)
            .map_err(|_| ())?;
        let after_reconciled = restarted_after
            .record_receipt("replacement-after", &receipt)
            .is_ok()
            && restarted_after.get_receipt(&receipt.id).map_err(|_| ())? == Some(receipt.clone());
        checks.push(check(
            "unknown_outcome_reconciliation",
            "tenkai.delivery.receipt/v1",
            after_reconciled,
            vec![Outcome::Unknown, Outcome::Replayed, Outcome::Current],
        ));

        let rollback = RollbackRecord {
            id: format!("rollback-{suffix}"),
            environment_id: environment.id.clone(),
            plan_id: plan.id.clone(),
            lease_generation: lease_a.generation,
            checkpoint_json: r#"{"step":0}"#.into(),
            status: RollbackStatus::Pending,
            status_detail: "prepared".into(),
        };
        restarted_after
            .create_rollback("replica-a", &rollback)
            .map_err(|_| ())?;
        let mut conflict = rollback.clone();
        conflict.checkpoint_json = r#"{"step":1}"#.into();
        let immutable_conflict = matches!(
            restarted_after.create_rollback("replacement-after", &conflict),
            Err(StoreError::ImmutableConflict {
                kind: "rollback",
                ..
            })
        );
        checks.push(check(
            "rollback_replay",
            "tenkai.delivery.rollback/v1",
            immutable_conflict,
            vec![Outcome::Replayed, Outcome::Rejected],
        ));

        b.expire_lease_for_conformance(&environment.id)
            .map_err(|_| ())?;
        let lease_b = b
            .acquire_lease(
                &environment.id,
                "replica-b",
                crate::now_millis().saturating_add(60_000),
            )
            .map_err(|_| ())?;
        let handoff = lease_b.generation == lease_a.generation + 1 && lease_b.owner == "replica-b";
        checks.push(check(
            "lease_handoff",
            "tenkai.delivery.lease/v1",
            handoff,
            vec![Outcome::Reconciled, Outcome::Current],
        ));

        let stale_plan = restarted_after.transition_plan(
            &plan.id,
            "replica-a",
            lease_a.generation,
            PlanStatus::Succeeded,
            "stale",
        );
        let stale_receipt = restarted_after.record_receipt(
            "replica-a",
            &ReceiptRecord {
                id: format!("stale-receipt-{suffix}"),
                ..receipt.clone()
            },
        );
        let stale_rollback = restarted_after.transition_rollback(
            &rollback.id,
            "replica-a",
            lease_a.generation,
            RollbackStatus::Running,
            r#"{"step":1}"#,
            "stale",
        );
        let stale_rejected = matches!(stale_plan, Err(StoreError::StaleLease { .. }))
            && matches!(stale_receipt, Err(StoreError::StaleLease { .. }))
            && matches!(stale_rollback, Err(StoreError::StaleLease { .. }));
        checks.push(check(
            "stale_generation_fencing",
            "tenkai.delivery.fence/v1",
            stale_rejected,
            vec![Outcome::Rejected],
        ));

        let recovered = b
            .transition_rollback(
                &rollback.id,
                "replica-b",
                lease_b.generation,
                RollbackStatus::Running,
                r#"{"step":1}"#,
                "resumed",
            )
            .and_then(|_| {
                b.transition_rollback(
                    &rollback.id,
                    "replica-b",
                    lease_b.generation,
                    RollbackStatus::Succeeded,
                    r#"{"step":2}"#,
                    "completed",
                )
            })
            .and_then(|_| {
                b.transition_plan(
                    &plan.id,
                    "replica-b",
                    lease_b.generation,
                    PlanStatus::Succeeded,
                    "completed",
                )
            })
            .is_ok()
            && b.get_plan(&plan.id)
                .map_err(|_| ())?
                .is_some_and(|stored| stored.status == PlanStatus::Succeeded);
        checks.push(check(
            "recovery_completion",
            "tenkai.delivery.recovery/v1",
            recovered,
            vec![Outcome::Reconciled, Outcome::Current],
        ));
        Ok(cleanup.finish())
    })();

    let execution_succeeded = matches!(result, Ok(true));
    if !execution_succeeded && checks.len() < MAX_CHECKS {
        checks.push(check(
            "adapter_execution",
            "tenkai.delivery.adapter/v1",
            false,
            vec![Outcome::Unavailable],
        ));
    }
    let passed = execution_succeeded
        && checks.len() == MAX_CHECKS
        && checks.iter().all(|item| item.passed)
        && checks.iter().all(|item| item.scenarios.len() <= 4);
    Report {
        version: VERSION.into(),
        evidence_ref: evidence_ref(),
        passed,
        runtime_instances: if execution_succeeded { 2 } else { 0 },
        capabilities: CapabilityEvidence {
            shared_replica_state: shared,
            high_availability: ha,
        },
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_only_explicit_local_test_databases() {
        assert!(Config::new("postgresql://localhost/tenkai_test").is_ok());
        assert!(Config::new("postgres://127.0.0.1:5432/ci_test").is_ok());
        assert!(Config::new("postgresql://db.example/tenkai_test").is_err());
        assert!(Config::new("postgresql://localhost/production").is_err());
        assert!(Config::new("postgresql://localhost/tenkai_test?dbname=production").is_err());
        assert!(Config::new("postgresql://localhost/tenkai_test?host=db.example").is_err());
        assert!(Config::new("mysql://localhost/tenkai_test").is_err());
    }

    #[test]
    fn version_is_exact_and_unavailable_report_is_bounded() {
        assert!(require_version(VERSION).is_ok());
        assert!(require_version("tenkai.delivery-conformance/v2").is_err());
        let report = unavailable_report();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!report.passed);
        assert!(json.len() < 4_096);
        assert!(!json.contains("postgres://"));
        assert!(!json.contains("password"));
    }
}

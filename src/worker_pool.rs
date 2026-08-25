//! Fixed-replica Shikigami worker-pool lifecycle owned by Tenkai.
//!
//! Tenkai admits pool desired state, capacity, drain, health, and recovery.
//! Sekai Chisei remains the work-admission authority; Shikigami executes runs.
//! Unknown intake adapters and non-`plane` pools fail closed.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, ProductKind, WorkerPoolSection};

pub const LIFECYCLE_PROTOCOL: &str = "shikigami.worker_lifecycle";
pub const LIFECYCLE_SCHEMA_VERSION: u32 = 1;
pub const INTAKE_PLANE: &str = "plane";
pub const MAX_REPLICAS: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPoolSpec {
    pub product: String,
    pub version: String,
    pub intake: String,
    pub replicas: u32,
    pub drain_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLifecycleSnapshot {
    pub schema_version: u32,
    pub protocol: String,
    pub product: String,
    pub version: String,
    pub worker_id: String,
    pub namespace: String,
    pub runtime_id: String,
    pub intake: String,
    pub state: String,
    pub accepting_claims: bool,
    pub active_claims: u32,
    pub active_runs: u32,
    pub configured_concurrency: u32,
    pub governance_ok: bool,
    pub fencing_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPoolObservation {
    pub product: String,
    pub version: String,
    pub intake: String,
    pub desired_replicas: u32,
    pub observed_replicas: u32,
    pub state: String,
    pub degraded: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerPoolDecision {
    Apply { replicas: u32 },
    WaitDrain,
    Degraded { reason: String },
    Deny { reason: String },
}

pub fn spec_from_manifest(manifest: &Manifest) -> Result<WorkerPoolSpec> {
    if manifest.product.kind != ProductKind::WorkerPool {
        bail!(
            "worker pool spec requires kind worker_pool, got {:?}",
            manifest.product.kind
        );
    }
    let section = manifest
        .worker_pool
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("worker_pool needs a [worker_pool] section"))?;
    spec_from_section(
        manifest.product.name.clone(),
        manifest.product.version.clone(),
        section,
    )
}

pub fn spec_from_section(
    product: String,
    version: String,
    section: &WorkerPoolSection,
) -> Result<WorkerPoolSpec> {
    crate::ontology::validate_identifier("worker_pool.product", &product)?;
    crate::ontology::validate_identifier("worker_pool.version", &version)?;
    if section.intake != INTAKE_PLANE {
        bail!(
            "unknown worker-pool intake {:?}; managed pools require {INTAKE_PLANE}",
            section.intake
        );
    }
    if section.replicas > MAX_REPLICAS {
        bail!("worker-pool replicas exceed the supported maximum of {MAX_REPLICAS}");
    }
    if section.drain_timeout_ms == 0 || section.drain_timeout_ms > 3_600_000 {
        bail!("worker-pool drain_timeout_ms is missing or unbounded");
    }
    Ok(WorkerPoolSpec {
        product,
        version,
        intake: section.intake.clone(),
        replicas: section.replicas,
        drain_timeout_ms: section.drain_timeout_ms,
    })
}

pub fn validate_snapshot(snapshot: &WorkerLifecycleSnapshot, spec: &WorkerPoolSpec) -> Result<()> {
    if snapshot.schema_version != LIFECYCLE_SCHEMA_VERSION {
        bail!(
            "unknown worker-host lifecycle schema {}; expected {LIFECYCLE_SCHEMA_VERSION}",
            snapshot.schema_version
        );
    }
    if snapshot.protocol != LIFECYCLE_PROTOCOL {
        bail!(
            "unknown worker-host protocol {:?}; expected {LIFECYCLE_PROTOCOL}",
            snapshot.protocol
        );
    }
    if snapshot.intake != INTAKE_PLANE {
        bail!(
            "worker-host intake {:?} is not {INTAKE_PLANE}; Tenkai rejects unmanaged pools",
            snapshot.intake
        );
    }
    if snapshot.product != spec.product {
        bail!(
            "worker-host product {} does not match pool {}",
            snapshot.product,
            spec.product
        );
    }
    match snapshot.state.as_str() {
        "unhealthy" | "governance_unavailable" | "fence_lost" | "draining" | "active" | "ready" => {
        }
        other => bail!("unknown worker-host lifecycle state {other:?}"),
    }
    if snapshot.configured_concurrency != 1 {
        bail!("worker-host v1 concurrency must be 1");
    }
    Ok(())
}

pub fn reconcile(
    spec: &WorkerPoolSpec,
    observed: &[WorkerLifecycleSnapshot],
    previous_replicas: u32,
    drain_started_at_ms: Option<i64>,
    now_ms: i64,
) -> Result<WorkerPoolDecision> {
    if spec.intake != INTAKE_PLANE {
        return Ok(WorkerPoolDecision::Deny {
            reason: format!("unknown worker-pool intake {:?}", spec.intake),
        });
    }
    for snapshot in observed {
        validate_snapshot(snapshot, spec)?;
        if snapshot.state == "fence_lost" {
            return Ok(WorkerPoolDecision::Deny {
                reason: "worker-host fence was lost; stale lifecycle completions are rejected"
                    .into(),
            });
        }
        if snapshot.state == "unhealthy" {
            return Ok(WorkerPoolDecision::Deny {
                reason: "worker-host is unhealthy; the pool is not ready".into(),
            });
        }
        if !snapshot.governance_ok || snapshot.state == "governance_unavailable" {
            if spec.replicas > previous_replicas {
                return Ok(WorkerPoolDecision::Deny {
                    reason: "plane outage cannot authorize scale-up or healthy rollout completion"
                        .into(),
                });
            }
            return Ok(WorkerPoolDecision::Degraded {
                reason: "worker-host governance is unavailable; pool is not ready".into(),
            });
        }
        if !snapshot.fencing_ok {
            return Ok(WorkerPoolDecision::Deny {
                reason: "worker-host fencing is not healthy".into(),
            });
        }
    }

    let scaling_down = spec.replicas < previous_replicas;
    let replacing = observed
        .iter()
        .any(|snapshot| snapshot.version != spec.version)
        && previous_replicas > 0;
    if scaling_down || replacing {
        let busy = observed
            .iter()
            .any(|snapshot| snapshot.active_claims > 0 || snapshot.state == "active");
        if busy {
            if let Some(started) = drain_started_at_ms
                && now_ms.saturating_sub(started) as u64 >= spec.drain_timeout_ms
            {
                return Ok(WorkerPoolDecision::Degraded {
                    reason:
                        "drain timed out; pool stays degraded and active work is not acknowledged"
                            .into(),
                });
            }
            return Ok(WorkerPoolDecision::WaitDrain);
        }
    }

    if pool_is_converged(spec, observed) {
        return Ok(WorkerPoolDecision::Apply {
            replicas: spec.replicas,
        });
    }

    if scaling_down || replacing {
        return Ok(WorkerPoolDecision::Apply {
            replicas: spec.replicas,
        });
    }

    Ok(WorkerPoolDecision::Degraded {
        reason: format!(
            "pool is not at the desired replica count and version (observed {}, desired {}, version {})",
            observed.len(),
            spec.replicas,
            spec.version
        ),
    })
}

pub fn pool_is_converged(spec: &WorkerPoolSpec, observed: &[WorkerLifecycleSnapshot]) -> bool {
    !observed.is_empty()
        && observed.len() as u32 == spec.replicas
        && observed.iter().all(|snapshot| {
            snapshot.version == spec.version
                && matches!(snapshot.state.as_str(), "ready" | "active")
                && snapshot.intake == INTAKE_PLANE
        })
}

pub fn observation(
    spec: &WorkerPoolSpec,
    observed: &[WorkerLifecycleSnapshot],
    decision: &WorkerPoolDecision,
) -> WorkerPoolObservation {
    let (state, degraded, detail) = match decision {
        WorkerPoolDecision::Apply { replicas }
            if pool_is_converged(spec, observed) && *replicas == spec.replicas =>
        {
            ("healthy".into(), false, "pool converged".into())
        }
        WorkerPoolDecision::Apply { .. } => {
            ("applying".into(), false, "capacity change admitted".into())
        }
        WorkerPoolDecision::WaitDrain => {
            ("draining".into(), false, "waiting for bounded drain".into())
        }
        WorkerPoolDecision::Degraded { reason } => ("degraded".into(), true, reason.clone()),
        WorkerPoolDecision::Deny { reason } => ("denied".into(), true, reason.clone()),
    };
    WorkerPoolObservation {
        product: spec.product.clone(),
        version: spec.version.clone(),
        intake: spec.intake.clone(),
        desired_replicas: spec.replicas,
        observed_replicas: observed.len() as u32,
        state,
        degraded,
        detail,
    }
}

pub fn persist_observation(
    properties: &mut std::collections::HashMap<String, String>,
    observation: &WorkerPoolObservation,
) {
    let prefix = format!("worker_pool.{}", observation.product);
    properties.insert(format!("{prefix}.version"), observation.version.clone());
    properties.insert(format!("{prefix}.intake"), observation.intake.clone());
    properties.insert(
        format!("{prefix}.replicas"),
        observation.desired_replicas.to_string(),
    );
    properties.insert(
        format!("{prefix}.observed_replicas"),
        observation.observed_replicas.to_string(),
    );
    properties.insert(format!("{prefix}.state"), observation.state.clone());
    properties.insert(format!("{prefix}.detail"), observation.detail.clone());
}

pub fn previous_replicas(
    properties: &std::collections::HashMap<String, String>,
    product: &str,
) -> u32 {
    properties
        .get(&format!("worker_pool.{product}.replicas"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

pub fn drain_started_at(
    properties: &std::collections::HashMap<String, String>,
    product: &str,
) -> Option<i64> {
    properties
        .get(&format!("worker_pool.{product}.drain_started_at"))
        .and_then(|value| value.parse().ok())
}

pub fn load_snapshots(
    dir: &std::path::Path,
    spec: &WorkerPoolSpec,
) -> Result<Vec<WorkerLifecycleSnapshot>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut snapshots = Vec::new();
    let mut entries = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let raw = std::fs::read(&path)?;
        let snapshot: WorkerLifecycleSnapshot = serde_json::from_slice(&raw)?;
        validate_snapshot(&snapshot, spec)?;
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

pub fn ready_snapshot(spec: &WorkerPoolSpec, worker_id: &str) -> WorkerLifecycleSnapshot {
    WorkerLifecycleSnapshot {
        schema_version: LIFECYCLE_SCHEMA_VERSION,
        protocol: LIFECYCLE_PROTOCOL.into(),
        product: spec.product.clone(),
        version: spec.version.clone(),
        worker_id: worker_id.into(),
        namespace: "default".into(),
        runtime_id: "runtime-1".into(),
        intake: INTAKE_PLANE.into(),
        state: "ready".into(),
        accepting_claims: true,
        active_claims: 0,
        active_runs: 0,
        configured_concurrency: 1,
        governance_ok: true,
        fencing_ok: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(replicas: u32) -> WorkerPoolSpec {
        WorkerPoolSpec {
            product: "edge-workers".into(),
            version: "1.0.0".into(),
            intake: INTAKE_PLANE.into(),
            replicas,
            drain_timeout_ms: 1_000,
        }
    }

    #[test]
    fn unknown_intake_is_rejected_before_planning() {
        let section = WorkerPoolSection {
            intake: "filesystem".into(),
            replicas: 1,
            drain_timeout_ms: 1_000,
        };
        let err = spec_from_section("edge-workers".into(), "1.0.0".into(), &section)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown worker-pool intake"), "{err}");
    }

    #[test]
    fn plane_outage_cannot_authorize_scale_up() {
        let desired = spec(2);
        let mut host = ready_snapshot(&desired, "w1");
        host.governance_ok = false;
        host.state = "governance_unavailable".into();
        host.accepting_claims = false;
        let decision = reconcile(&desired, &[host], 1, None, 10).unwrap();
        assert!(
            matches!(decision, WorkerPoolDecision::Deny { ref reason } if reason.contains("scale-up")),
            "{decision:?}"
        );
    }

    #[test]
    fn drain_timeout_leaves_pool_degraded_without_acknowledging_work() {
        let desired = spec(1);
        let mut busy = ready_snapshot(&desired, "w1");
        busy.state = "draining".into();
        busy.accepting_claims = false;
        busy.active_claims = 1;
        let previous = spec(2);
        let _ = previous;
        let decision = reconcile(&desired, &[busy], 2, Some(0), 5_000).unwrap();
        match decision {
            WorkerPoolDecision::Degraded { reason } => {
                assert!(reason.contains("drain timed out"), "{reason}");
                assert!(reason.contains("not acknowledged"), "{reason}");
            }
            other => panic!("expected degraded, got {other:?}"),
        }
    }

    #[test]
    fn under_replicated_pool_is_not_healthy_and_does_not_apply_success() {
        let desired = spec(2);
        let none = reconcile(&desired, &[], 0, None, 10).unwrap();
        match &none {
            WorkerPoolDecision::Degraded { reason } => {
                assert!(reason.contains("desired replica count"), "{reason}");
            }
            other => panic!("expected degraded for zero hosts, got {other:?}"),
        }
        let observed = observation(&desired, &[], &none);
        assert!(observed.degraded);
        assert_ne!(observed.state, "healthy");
        assert_eq!(observed.observed_replicas, 0);

        let one = ready_snapshot(&desired, "w1");
        let decision = reconcile(&desired, std::slice::from_ref(&one), 1, None, 10).unwrap();
        match &decision {
            WorkerPoolDecision::Degraded { reason } => {
                assert!(reason.contains("desired replica count"), "{reason}");
            }
            other => panic!("expected degraded for one of two hosts, got {other:?}"),
        }
        let observed = observation(&desired, std::slice::from_ref(&one), &decision);
        assert!(observed.degraded);
        assert_ne!(observed.state, "healthy");
        assert_eq!(observed.observed_replicas, 1);
        assert!(!pool_is_converged(&desired, &[]));
        assert!(!pool_is_converged(&desired, std::slice::from_ref(&one)));
    }

    #[test]
    fn drained_replacement_admits_apply_without_reporting_healthy() {
        let desired = WorkerPoolSpec {
            product: "edge-workers".into(),
            version: "2.0.0".into(),
            intake: INTAKE_PLANE.into(),
            replicas: 1,
            drain_timeout_ms: 1_000,
        };
        let previous = spec(1);
        let mut drained = ready_snapshot(&previous, "w1");
        drained.state = "ready".into();
        drained.accepting_claims = true;
        drained.active_claims = 0;
        let decision = reconcile(&desired, std::slice::from_ref(&drained), 1, Some(0), 10).unwrap();
        assert_eq!(decision, WorkerPoolDecision::Apply { replicas: 1 });
        let observed = observation(&desired, std::slice::from_ref(&drained), &decision);
        assert!(!observed.degraded);
        assert_eq!(observed.state, "applying");
        assert!(!pool_is_converged(&desired, std::slice::from_ref(&drained)));
    }

    #[test]
    fn drain_success_admits_scale_down() {
        let desired = spec(1);
        let drained = ready_snapshot(&desired, "w1");
        let decision = reconcile(&desired, &[drained], 2, Some(0), 10).unwrap();
        assert_eq!(decision, WorkerPoolDecision::Apply { replicas: 1 });
    }

    #[test]
    fn fence_loss_rejects_stale_lifecycle_completion() {
        let desired = spec(1);
        let mut lost = ready_snapshot(&desired, "w1");
        lost.state = "fence_lost".into();
        lost.fencing_ok = false;
        lost.accepting_claims = false;
        let decision = reconcile(&desired, &[lost], 1, None, 10).unwrap();
        assert!(
            matches!(decision, WorkerPoolDecision::Deny { ref reason } if reason.contains("fence")),
            "{decision:?}"
        );
    }

    #[test]
    fn filesystem_snapshot_is_an_ownership_violation() {
        let desired = spec(1);
        let mut host = ready_snapshot(&desired, "w1");
        host.intake = "filesystem".into();
        let err = reconcile(&desired, &[host], 1, None, 10)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not plane"), "{err}");
    }

    #[test]
    fn restart_of_a_ready_pool_is_idempotent() {
        let desired = spec(2);
        let hosts = vec![
            ready_snapshot(&desired, "w1"),
            ready_snapshot(&desired, "w2"),
        ];
        let first = reconcile(&desired, &hosts, 2, None, 10).unwrap();
        let second = reconcile(&desired, &hosts, 2, None, 20).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, WorkerPoolDecision::Apply { replicas: 2 });
    }

    #[test]
    fn disconnected_recovery_uses_local_snapshots_without_chisei() {
        let desired = spec(1);
        let host = ready_snapshot(&desired, "w1");
        let decision = reconcile(&desired, std::slice::from_ref(&host), 1, None, 10).unwrap();
        let observed = observation(&desired, std::slice::from_ref(&host), &decision);
        assert!(!observed.degraded);
        assert_eq!(observed.state, "healthy");
        assert_eq!(observed.desired_replicas, 1);
    }

    #[test]
    fn wait_drain_when_active_claims_remain() {
        let desired = spec(1);
        let mut busy = ready_snapshot(&desired, "w1");
        busy.state = "active".into();
        busy.active_claims = 1;
        let decision = reconcile(&desired, &[busy], 2, Some(50), 100).unwrap();
        assert_eq!(decision, WorkerPoolDecision::WaitDrain);
    }

    #[tokio::test]
    async fn publish_plan_apply_and_inspect_a_plane_pool() {
        use crate::catalog::{self, CatalogReader, PublishOptions};
        use crate::client::Ctx;

        let root = std::env::temp_dir().join(format!(
            "tenkai-worker-pool-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "edge-workers"
version = "1.0.0"
kind = "worker_pool"

[worker_pool]
intake = "plane"
replicas = 1
drain_timeout_ms = 1000
"#,
        )
        .unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let filesystem = catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(filesystem.contains("already published"), "{filesystem}");

        let denied = {
            std::fs::write(
                root.join("bad.toml"),
                r#"
[product]
name = "bad-pool"
version = "1.0.0"
kind = "worker_pool"

[worker_pool]
intake = "filesystem"
replicas = 1
"#,
            )
            .unwrap();
            catalog::publish(
                &mut ctx,
                &root.join("bad.toml"),
                &PublishOptions {
                    allow_unsigned_development: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err()
            .to_string()
        };
        assert!(denied.contains("unknown worker-pool intake"), "{denied}");

        let actor = crate::auth_context::test_management_context("worker-pool");
        catalog::promote(&mut ctx, &actor, "edge-workers@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "edge-workers", "stable")
            .await
            .unwrap();

        let release = ctx
            .get(&crate::ontology::release_id("edge-workers", "1.0.0"))
            .await
            .unwrap()
            .unwrap();
        let snapshot = std::path::PathBuf::from(release.properties.get("workdir").unwrap());
        let artifact_digest = release.properties.get("artifact_digest").unwrap();
        let workdir = crate::manifest::execution_workdir(
            &snapshot,
            &[],
            artifact_digest,
            "local",
            "edge-workers",
        )
        .unwrap();
        std::fs::create_dir_all(workdir.join("worker")).unwrap();
        let spec = spec(1);
        std::fs::write(
            workdir.join("worker/w1.json"),
            serde_json::to_vec_pretty(&ready_snapshot(&spec, "w1")).unwrap(),
        )
        .unwrap();

        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "worker pool apply",
                },
                software_executor: None,
                delivery_adapter: None,
            },
        )
        .await
        .unwrap();
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        assert_eq!(
            env.properties
                .get("worker_pool.edge-workers.state")
                .map(String::as_str),
            Some("healthy")
        );
        assert_eq!(
            env.properties
                .get("worker_pool.edge-workers.replicas")
                .map(String::as_str),
            Some("1")
        );
        let _ = crate::catalog::EmbeddedCatalog::new(&mut ctx)
            .lookup_release("tenkai:release:edge-workers@1.0.0", "local")
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
}

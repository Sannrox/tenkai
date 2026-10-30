use anyhow::{Context as _, Result, bail};
use tenkai::dark_site::{self, ReadyReport};
use tenkai::offline_bundle::OfflineStackManifest;
use tenkai::worker_pool::{WorkerLifecycleSnapshot, WorkerPoolDecision};

use crate::args::DarkSiteCommand;

/// Dark-site profile commands need no Tenkai operational store.
pub(crate) fn run(command: &DarkSiteCommand) -> Result<()> {
    match command {
        DarkSiteCommand::Validate { profile } => {
            let profile = dark_site::DarkSiteProfile::load(profile)?;
            println!(
                "dark-site profile {}@{} with site-agent {}@{}",
                profile.model_runtime.product,
                profile.model_runtime.version,
                profile.site_agent.product,
                profile.site_agent.version
            );
        }
        DarkSiteCommand::Activate {
            profile,
            stack,
            state,
        } => {
            let loaded = dark_site::DarkSiteProfile::load(profile)?;
            let raw = std::fs::read(stack)
                .with_context(|| format!("reading offline stack {}", stack.display()))?;
            let stack: OfflineStackManifest = serde_json::from_slice(&raw)
                .with_context(|| format!("parsing offline stack {}", stack.display()))?;
            let jwks_root = profile
                .parent()
                .context("dark-site profile path has no parent")?;
            let activation =
                dark_site::activate(&loaded, &stack, state, jwks_root, tenkai::now_millis())?;
            println!(
                "dark-site active {} (model {} worker {})",
                activation.profile_digest,
                activation.profile.model_runtime.digest,
                activation.profile.site_agent.image_digest
            );
        }
        DarkSiteCommand::Ready {
            state,
            model_health,
            ready_replicas,
        } => {
            let activation = require_activation(state)?;
            let model_healthy = match model_health.as_str() {
                "healthy" => true,
                "unhealthy" => false,
                other => bail!("model-health must be healthy or unhealthy, got {other}"),
            };
            let workers = synthetic_workers(&activation.profile, *ready_replicas, 0);
            let report = dark_site::ready(&activation.profile, model_healthy, &workers)?;
            print_ready(&report);
            if !report.ready {
                bail!("{}", report.detail);
            }
        }
        DarkSiteCommand::Rollback {
            state,
            active_claims,
        } => {
            let activation = require_activation(state)?;
            let workers = synthetic_workers(&activation.profile, 1, *active_claims);
            let decision = dark_site::rollback_decision(
                &activation,
                &workers,
                Some(tenkai::now_millis()),
                tenkai::now_millis(),
            )?;
            match decision {
                WorkerPoolDecision::WaitDrain => {
                    println!("wait_drain");
                }
                WorkerPoolDecision::Apply { replicas } => {
                    println!("apply {replicas}");
                }
                WorkerPoolDecision::Degraded { reason } | WorkerPoolDecision::Deny { reason } => {
                    bail!("{reason}");
                }
            }
        }
    }
    Ok(())
}

fn require_activation(state: &std::path::Path) -> Result<dark_site::DarkSiteActivation> {
    dark_site::load_activation(state)?.context("no active dark-site profile in --state")
}

fn synthetic_workers(
    profile: &dark_site::DarkSiteProfile,
    ready_replicas: u32,
    active_claims: u32,
) -> Vec<WorkerLifecycleSnapshot> {
    let version = if active_claims > 0 {
        profile.site_agent.image_digest.clone()
    } else {
        profile.site_agent.version.clone()
    };
    (0..ready_replicas.max(1))
        .map(|index| WorkerLifecycleSnapshot {
            schema_version: tenkai::worker_pool::LIFECYCLE_SCHEMA_VERSION,
            protocol: tenkai::worker_pool::LIFECYCLE_PROTOCOL.into(),
            product: profile.site_agent.product.clone(),
            version: version.clone(),
            worker_id: format!("w{index}"),
            namespace: "local".into(),
            runtime_id: "local".into(),
            intake: tenkai::worker_pool::INTAKE_PLANE.into(),
            state: if active_claims > 0 && index == 0 {
                "active".into()
            } else {
                "ready".into()
            },
            accepting_claims: active_claims == 0,
            active_claims: if index == 0 { active_claims } else { 0 },
            active_runs: if index == 0 { active_claims } else { 0 },
            configured_concurrency: 1,
            governance_ok: true,
            fencing_ok: true,
        })
        .collect()
}

fn print_ready(report: &ReadyReport) {
    println!(
        "{} model_healthy={} workers={}/{}",
        if report.ready { "ready" } else { "not-ready" },
        report.model_healthy,
        report.workers_ready,
        report.workers_desired
    );
}

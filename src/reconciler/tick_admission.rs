//! Private reconciler tick admission and scheduling.
//!
//! The interface admits environments, coordinates optional multi-host fencing,
//! spawns per-environment reconcile work, and records diagnostics. Callers
//! remain on `Reconciler::run_once` / `run_once_for`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::Semaphore;

use super::environment_lifecycle;
use super::*;
use crate::ontology::KIND_ENVIRONMENT;
use crate::reconcile_fence::{FenceAdmission, FenceGuard};

#[derive(Default)]
pub(super) struct SchedulerState {
    in_flight: HashSet<String>,
    retries: HashMap<String, RetryState>,
}

struct RetryState {
    failures: u32,
    retry_at: i64,
}

pub(super) enum Admission {
    Started,
    Busy,
    Deferred(i64),
}

impl SchedulerState {
    pub(super) fn begin(&mut self, environment: &str, now: i64) -> Admission {
        if self.in_flight.contains(environment) {
            return Admission::Busy;
        }
        if let Some(retry) = self.retries.get(environment)
            && retry.retry_at > now
        {
            return Admission::Deferred(retry.retry_at);
        }
        self.in_flight.insert(environment.into());
        Admission::Started
    }

    pub(super) fn finish(&mut self, environment: &str, succeeded: bool, now: i64, config: &Config) {
        self.in_flight.remove(environment);
        if succeeded {
            self.retries.remove(environment);
            return;
        }
        let failures = self
            .retries
            .get(environment)
            .map_or(1, |retry| retry.failures.saturating_add(1));
        let multiplier = 1_u32 << failures.saturating_sub(1).min(31);
        let delay = config
            .initial_backoff
            .saturating_mul(multiplier)
            .min(config.max_backoff);
        let delay = i64::try_from(delay.as_millis()).unwrap_or(i64::MAX);
        self.retries.insert(
            environment.into(),
            RetryState {
                failures,
                retry_at: now.saturating_add(delay),
            },
        );
    }
}

struct AdmissionGuard {
    environment: String,
    state: Arc<Mutex<SchedulerState>>,
    config: Config,
    completed: bool,
}

impl AdmissionGuard {
    fn finish(mut self, succeeded: bool) {
        self.state.lock().expect("reconciler state lock").finish(
            &self.environment,
            succeeded,
            crate::now_millis(),
            &self.config,
        );
        self.completed = true;
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.state.lock().expect("reconciler state lock").finish(
                &self.environment,
                false,
                crate::now_millis(),
                &self.config,
            );
        }
    }
}

pub(super) struct TickRequest<'a> {
    pub ctx: Ctx,
    pub config: Config,
    pub state: Arc<Mutex<SchedulerState>>,
    pub tick_lock: &'a tokio::sync::Mutex<()>,
    pub runtime_environments: Arc<HashSet<String>>,
    pub diagnostics: Arc<Mutex<ReconcileDiagnostics>>,
    pub shared_fence: Option<Arc<dyn ReconcileTickFence>>,
    pub allowed_environments: Option<HashSet<String>>,
}

pub(super) async fn run(request: TickRequest<'_>) -> Result<TickReport> {
    // Periodic and requested ticks share this lock so a successful request
    // always represents a complete tick rather than a transient Busy report.
    let _tick = request.tick_lock.lock().await;
    let mut listing = request.ctx.clone();
    let mut environments = listing.list_kind(KIND_ENVIRONMENT).await?;
    if let Some(allowed) = &request.allowed_environments {
        // Scope work selection before admission, fencing, planning, leasing,
        // or execution. Unknown identities are silently excluded.
        environments.retain(|environment| allowed.contains(&environment.name));
    }
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    let permits = Arc::new(Semaphore::new(request.config.max_concurrency));
    let mut jobs = tokio::task::JoinSet::new();
    let mut report = TickReport::default();

    for environment in environments {
        let name = environment.name;
        match request
            .state
            .lock()
            .expect("reconciler state lock")
            .begin(&name, crate::now_millis())
        {
            Admission::Busy => report.environments.push(EnvironmentResult {
                environment: name,
                status: EnvironmentStatus::Busy,
            }),
            Admission::Deferred(retry_at) => report.environments.push(EnvironmentResult {
                environment: name,
                status: EnvironmentStatus::Deferred { retry_at },
            }),
            Admission::Started => {
                let fence_guard = if let Some(fence) = &request.shared_fence {
                    let now = crate::now_millis();
                    match fence.try_begin(
                        &name,
                        &request.config.instance_id,
                        now,
                        request.config.fence_ttl_ms,
                    ) {
                        Ok(FenceAdmission::Started { generation }) => Some(FenceGuard::new(
                            Arc::clone(fence),
                            name.clone(),
                            request.config.instance_id.clone(),
                            generation,
                        )),
                        Ok(FenceAdmission::Busy { .. }) | Ok(FenceAdmission::Stale) => {
                            request.state.lock().expect("reconciler state lock").finish(
                                &name,
                                true, // not a local failure; clear in_flight
                                crate::now_millis(),
                                &request.config,
                            );
                            report.environments.push(EnvironmentResult {
                                environment: name,
                                status: EnvironmentStatus::Busy,
                            });
                            continue;
                        }
                        Err(error) => {
                            request.state.lock().expect("reconciler state lock").finish(
                                &name,
                                false,
                                crate::now_millis(),
                                &request.config,
                            );
                            report.environments.push(EnvironmentResult {
                                environment: name,
                                status: EnvironmentStatus::Failed {
                                    error: format!("reconcile fence: {error}"),
                                },
                            });
                            continue;
                        }
                    }
                } else {
                    None
                };

                let mut ctx = request.ctx.clone();
                let config = request.config.clone();
                let runtime_managed = request.runtime_environments.contains(&name);
                let guard = AdmissionGuard {
                    environment: name.clone(),
                    state: Arc::clone(&request.state),
                    config: config.clone(),
                    completed: false,
                };
                let permits = Arc::clone(&permits);
                jobs.spawn(async move {
                    let _permit = permits
                        .acquire_owned()
                        .await
                        .expect("semaphore remains open");
                    let _fence = fence_guard;
                    let result = environment_lifecycle::reconcile(
                        &mut ctx,
                        environment_lifecycle::Request {
                            environment: &name,
                            runtime_managed,
                            policy: environment_lifecycle::Policy {
                                skip_gates: config.skip_gates,
                                unapproved_development_reason: config
                                    .unapproved_development_reason
                                    .as_deref(),
                                approval_directory: config.approval_directory.as_deref(),
                                approval_trust_roots: config.approval_trust_roots.as_deref(),
                            },
                        },
                    )
                    .await;
                    guard.finish(result.is_ok());
                    (name, result)
                });
            }
        }
    }

    while let Some(job) = jobs.join_next().await {
        let (environment, status) = match job {
            Ok((environment, Ok(status))) => (environment, status),
            Ok((environment, Err(error))) => (
                environment,
                EnvironmentStatus::Failed {
                    error: format!("{error:#}"),
                },
            ),
            Err(error) => (
                "unknown".into(),
                EnvironmentStatus::Failed {
                    error: format!("reconciler environment task failed: {error}"),
                },
            ),
        };
        report.environments.push(EnvironmentResult {
            environment,
            status,
        });
    }
    report
        .environments
        .sort_by(|left, right| left.environment.cmp(&right.environment));
    request
        .diagnostics
        .lock()
        .expect("reconciler diagnostics lock")
        .record_tick(&report);
    Ok(report)
}

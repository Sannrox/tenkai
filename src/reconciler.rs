//! Concurrent, retrying convergence of registered environments.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};

use crate::apply;
use crate::client::Ctx;
use crate::ontology::{KIND_ENVIRONMENT, NS};
use crate::plan;

#[derive(Debug, Clone)]
pub struct Config {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_concurrency: usize,
    pub skip_gates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(5 * 60),
            max_concurrency: 8,
            skip_gates: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentStatus {
    Current,
    Applied { plan_id: String, steps: usize },
    Failed { error: String },
    Deferred { retry_at: i64 },
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentResult {
    pub environment: String,
    pub status: EnvironmentStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    pub environments: Vec<EnvironmentResult>,
}

impl TickReport {
    pub fn failures(&self) -> usize {
        self.environments
            .iter()
            .filter(|result| matches!(result.status, EnvironmentStatus::Failed { .. }))
            .count()
    }
}

#[derive(Default)]
struct SchedulerState {
    in_flight: HashSet<String>,
    retries: HashMap<String, RetryState>,
}

struct RetryState {
    failures: u32,
    retry_at: i64,
}

enum Admission {
    Started,
    Busy,
    Deferred(i64),
}

impl SchedulerState {
    fn begin(&mut self, environment: &str, now: i64) -> Admission {
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

    fn finish(&mut self, environment: &str, succeeded: bool, now: i64, config: &Config) {
        self.in_flight.remove(environment);
        if succeeded {
            self.retries.remove(environment);
            return;
        }
        let failures = self
            .retries
            .get(environment)
            .map_or(1, |retry| retry.failures.saturating_add(1));
        let exponent = failures.saturating_sub(1).min(31);
        let multiplier = 1_u32 << exponent;
        let delay = config
            .initial_backoff
            .saturating_mul(multiplier)
            .min(config.max_backoff);
        let delay_millis = i64::try_from(delay.as_millis()).unwrap_or(i64::MAX);
        self.retries.insert(
            environment.into(),
            RetryState {
                failures,
                retry_at: now.saturating_add(delay_millis),
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

#[derive(Clone)]
pub struct Reconciler {
    ctx: Ctx,
    config: Config,
    state: Arc<Mutex<SchedulerState>>,
    cursor: Arc<Mutex<usize>>,
    permits: Arc<tokio::sync::Semaphore>,
}

impl Reconciler {
    pub fn new(ctx: Ctx, config: Config) -> Result<Self> {
        if config.initial_backoff.is_zero() {
            bail!("initial reconciler backoff must be greater than zero");
        }
        if config.max_backoff < config.initial_backoff {
            bail!("maximum reconciler backoff must not be smaller than the initial backoff");
        }
        if config.max_concurrency == 0 {
            bail!("reconciler maximum concurrency must be greater than zero");
        }
        let max_concurrency = config.max_concurrency;
        Ok(Self {
            ctx,
            config,
            state: Arc::new(Mutex::new(SchedulerState::default())),
            cursor: Arc::new(Mutex::new(0)),
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrency)),
        })
    }

    /// Reconcile every registered environment once. Environments run concurrently.
    pub async fn tick(&self) -> Result<TickReport> {
        let signals = apply::monitor_shutdown_signals()?;
        self.tick_with_shutdown(Some(signals)).await
    }

    async fn tick_with_shutdown(
        &self,
        shutdown: Option<apply::ShutdownSignals>,
    ) -> Result<TickReport> {
        let mut jobs = tokio::task::JoinSet::new();
        let mut processed = HashSet::new();
        let mut report = self
            .schedule_environments(shutdown.clone(), &mut jobs, Some(&mut processed))
            .await?;
        let mut scheduling_error = None;
        while let Some(job) = jobs.join_next().await {
            let result = environment_job_result(job);
            processed.insert(result.environment.clone());
            report.environments.push(result);
            match self
                .schedule_environments(shutdown.clone(), &mut jobs, Some(&mut processed))
                .await
            {
                Ok(scheduled) => report.environments.extend(scheduled.environments),
                Err(error) => {
                    scheduling_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = scheduling_error {
            while let Some(job) = jobs.join_next().await {
                report.environments.push(environment_job_result(job));
            }
            return Err(error.context("listing environments while active jobs were drained"));
        }
        report
            .environments
            .sort_by(|left, right| left.environment.cmp(&right.environment));
        Ok(report)
    }

    async fn schedule_environments(
        &self,
        shutdown: Option<apply::ShutdownSignals>,
        jobs: &mut tokio::task::JoinSet<(String, Result<EnvironmentStatus>)>,
        mut processed: Option<&mut HashSet<String>>,
    ) -> Result<TickReport> {
        let mut listing = self.ctx.clone();
        let mut environments = listing.list_kind(KIND_ENVIRONMENT, NS).await?;
        environments.sort_by(|left, right| left.name.cmp(&right.name));
        let continuous = processed.is_none();
        let environment_count = environments.len();
        let start = if continuous && environment_count > 0 {
            *self.cursor.lock().expect("reconciler cursor lock") % environment_count
        } else {
            0
        };
        environments.rotate_left(start);

        let mut report = TickReport::default();
        let mut considered = 0;
        for environment in environments {
            let name = environment.name;
            if processed
                .as_ref()
                .is_some_and(|processed| processed.contains(&name))
            {
                continue;
            }
            if jobs.len() >= self.config.max_concurrency {
                break;
            }
            considered += 1;
            if let Some(processed) = processed.as_deref_mut() {
                processed.insert(name.clone());
            }
            let admission = self
                .state
                .lock()
                .expect("reconciler state lock")
                .begin(&name, crate::now_millis());
            match admission {
                Admission::Busy => report.environments.push(EnvironmentResult {
                    environment: name,
                    status: EnvironmentStatus::Busy,
                }),
                Admission::Deferred(retry_at) => report.environments.push(EnvironmentResult {
                    environment: name,
                    status: EnvironmentStatus::Deferred { retry_at },
                }),
                Admission::Started => {
                    let mut ctx = self.ctx.clone();
                    let config = self.config.clone();
                    let guard = AdmissionGuard {
                        environment: name.clone(),
                        state: Arc::clone(&self.state),
                        config: config.clone(),
                        completed: false,
                    };
                    let task_name = name.clone();
                    let shutdown = shutdown.clone();
                    let permits = Arc::clone(&self.permits);
                    jobs.spawn(async move {
                        let _permit = permits
                            .acquire_owned()
                            .await
                            .expect("reconciler semaphore remains open");
                        let result = reconcile_environment(
                            &mut ctx,
                            &task_name,
                            config.skip_gates,
                            shutdown.as_ref(),
                        )
                        .await;
                        guard.finish(result.is_ok());
                        (task_name, result)
                    });
                }
            }
        }
        if continuous && environment_count > 0 {
            *self.cursor.lock().expect("reconciler cursor lock") =
                (start + considered) % environment_count;
        }

        Ok(report)
    }

    /// Reconcile every registered environment once and return the complete report.
    pub async fn run_once(&self) -> Result<TickReport> {
        self.tick().await
    }

    /// Run bounded ticks until shutdown; each tick reconciles environments concurrently.
    pub async fn run_until<H>(
        &self,
        interval: Duration,
        signals: apply::ShutdownSignals,
        mut handle_report: H,
    ) -> Result<()>
    where
        H: FnMut(Result<TickReport>),
    {
        if interval.is_zero() {
            bail!("reconciler interval must be greater than zero");
        }
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = timer.tick() => {
                    match self.schedule_environments(Some(signals.clone()), &mut jobs, None).await {
                        Ok(mut report) => {
                            report.environments.sort_by(|left, right| left.environment.cmp(&right.environment));
                            if !report.environments.is_empty() {
                                handle_report(Ok(report));
                            }
                        }
                        Err(error) => handle_report(Err(error)),
                    }
                }
                job = jobs.join_next(), if !jobs.is_empty() => {
                    if let Some(job) = job {
                        handle_report(Ok(TickReport {
                            environments: vec![environment_job_result(job)],
                        }));
                    }
                }
                _ = signals.wait() => break,
            }
        }
        while let Some(job) = jobs.join_next().await {
            handle_report(Ok(TickReport {
                environments: vec![environment_job_result(job)],
            }));
        }
        Ok(())
    }
}

fn environment_job_result(
    job: std::result::Result<(String, Result<EnvironmentStatus>), tokio::task::JoinError>,
) -> EnvironmentResult {
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
    EnvironmentResult {
        environment,
        status,
    }
}

async fn reconcile_environment(
    ctx: &mut Ctx,
    environment: &str,
    skip_gates: bool,
    shutdown: Option<&apply::ShutdownSignals>,
) -> Result<EnvironmentStatus> {
    let uncancelled = crate::executor::Cancellation::default();
    let cancellation = shutdown
        .map(apply::ShutdownSignals::forward)
        .unwrap_or(&uncancelled);
    if let Some(shutdown) = shutdown
        && let Some(reason) = shutdown.forward().reason()
    {
        bail!(reason);
    }
    match apply::recover_reconciler_execution(ctx, environment, cancellation).await? {
        apply::ReconcilerRecovery::Busy => return Ok(EnvironmentStatus::Busy),
        apply::ReconcilerRecovery::None => {}
    }
    let Some(stored) = plan::create_reconciliation(ctx, environment, cancellation).await? else {
        return Ok(EnvironmentStatus::Current);
    };
    let plan_id = stored.id;
    let steps = stored.steps.len();
    let outcomes = match shutdown {
        Some(shutdown) => {
            apply::execute_for_reconciler(ctx, &plan_id, skip_gates, shutdown).await?
        }
        None => apply::execute(ctx, &plan_id, skip_gates).await?,
    };
    if let Some(failed) = outcomes
        .iter()
        .find(|outcome| outcome.status != "succeeded")
    {
        bail!(
            "environment {environment} failed while reconciling {}: {}",
            failed.step.product,
            failed.detail
        );
    }
    Ok(EnvironmentStatus::Applied { plan_id, steps })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(250),
            max_concurrency: 2,
            skip_gates: false,
        }
    }

    #[test]
    fn concurrent_ticks_serialize_an_environment() {
        let mut state = SchedulerState::default();
        assert!(matches!(state.begin("prod", 1_000), Admission::Started));
        assert!(matches!(state.begin("prod", 1_000), Admission::Busy));
        assert!(matches!(state.begin("staging", 1_000), Admission::Started));
    }

    #[test]
    fn failures_back_off_independently_and_success_resets() {
        let mut state = SchedulerState::default();
        let config = config();

        assert!(matches!(state.begin("prod", 1_000), Admission::Started));
        state.finish("prod", false, 1_000, &config);
        assert!(matches!(
            state.begin("prod", 1_099),
            Admission::Deferred(1_100)
        ));
        assert!(matches!(state.begin("staging", 1_099), Admission::Started));

        assert!(matches!(state.begin("prod", 1_100), Admission::Started));
        state.finish("prod", false, 1_100, &config);
        assert!(matches!(
            state.begin("prod", 1_299),
            Admission::Deferred(1_300)
        ));
        assert!(matches!(state.begin("prod", 1_300), Admission::Started));
        state.finish("prod", true, 1_300, &config);
        assert!(matches!(state.begin("prod", 1_300), Admission::Started));
    }

    #[test]
    fn retry_delay_is_capped() {
        let mut state = SchedulerState::default();
        let config = config();
        for now in [0, 100, 300, 550] {
            assert!(matches!(state.begin("prod", now), Admission::Started));
            state.finish("prod", false, now, &config);
        }
        assert!(matches!(state.begin("prod", 799), Admission::Deferred(800)));
    }

    #[test]
    fn abandoned_worker_guard_records_a_failure() {
        let state = Arc::new(Mutex::new(SchedulerState::default()));
        assert!(matches!(
            state.lock().unwrap().begin("prod", crate::now_millis()),
            Admission::Started
        ));
        let guard = AdmissionGuard {
            environment: "prod".into(),
            state: Arc::clone(&state),
            config: config(),
            completed: false,
        };
        drop(guard);
        assert!(matches!(
            state.lock().unwrap().begin("prod", crate::now_millis()),
            Admission::Deferred(_)
        ));
    }
}

//! Private reconciler tick admission and scheduling.
//!
//! The interface admits environments, coordinates optional multi-host fencing,
//! spawns per-environment reconcile work, and records diagnostics. Callers
//! remain on `Reconciler::run_once` / `run_once_for`.
//!
//! Fleet membership is kept as an environment-name index on the reconciler so a
//! tick does not `list_kind` every environment object when nothing changed.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::Semaphore;

use super::environment_lifecycle;
use super::*;
use crate::ontology::{KIND_ENVIRONMENT, env_id};
use crate::pb::sekai::Object;
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndexEntry {
    id: String,
    updated: i64,
}

#[derive(Default)]
pub(super) struct EnvironmentIndex {
    initialized: bool,
    by_name: BTreeMap<String, IndexEntry>,
    by_id: HashMap<String, String>,
}

impl EnvironmentIndex {
    fn sorted_names(&self) -> Vec<String> {
        self.by_name.keys().cloned().collect()
    }

    fn replace_from_objects(&mut self, objects: Vec<Object>) {
        self.by_name.clear();
        self.by_id.clear();
        for object in objects {
            self.upsert(object);
        }
        self.initialized = true;
    }

    fn upsert(&mut self, object: Object) {
        if let Some(previous) = self.by_id.insert(object.id.clone(), object.name.clone())
            && previous != object.name
        {
            self.by_name.remove(&previous);
        }
        if let Some(previous) = self.by_name.insert(
            object.name.clone(),
            IndexEntry {
                id: object.id.clone(),
                updated: object.updated,
            },
        ) && previous.id != object.id
        {
            self.by_id.remove(&previous.id);
        }
    }

    fn remove_id(&mut self, id: &str) {
        if let Some(name) = self.by_id.remove(id) {
            self.by_name.remove(&name);
        }
    }

    fn membership_delta(&self, listed_ids: &[String]) -> (Vec<String>, Vec<String>) {
        let listed: HashSet<&str> = listed_ids.iter().map(String::as_str).collect();
        let appeared = listed_ids
            .iter()
            .filter(|id| !self.by_id.contains_key(*id))
            .cloned()
            .collect();
        let disappeared = self
            .by_id
            .keys()
            .filter(|id| !listed.contains(id.as_str()))
            .cloned()
            .collect();
        (appeared, disappeared)
    }
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
    pub environment_index: Arc<Mutex<EnvironmentIndex>>,
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
    let names = load_environment_names(
        &mut listing,
        &request.environment_index,
        request.allowed_environments.as_ref(),
    )
    .await?;
    let permits = Arc::new(Semaphore::new(request.config.max_concurrency));
    let mut jobs = tokio::task::JoinSet::new();
    let mut report = TickReport::default();

    for name in names {
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

async fn load_environment_names(
    ctx: &mut Ctx,
    index: &Mutex<EnvironmentIndex>,
    allowed: Option<&HashSet<String>>,
) -> Result<Vec<String>> {
    if let Some(allowed) = allowed {
        // Scope work selection before admission, fencing, planning, leasing,
        // or execution. Unknown identities are silently excluded. A bounded
        // tick never lists the fleet.
        return resolve_allowed_environments(ctx, allowed).await;
    }
    refresh_environment_index(ctx, index).await
}

async fn resolve_allowed_environments(
    ctx: &mut Ctx,
    allowed: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in allowed {
        let Some(object) = catalog_get(ctx, &env_id(name)).await? else {
            continue;
        };
        if object.kind == KIND_ENVIRONMENT && allowed.contains(&object.name) {
            names.push(object.name);
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

async fn refresh_environment_index(
    ctx: &mut Ctx,
    index: &Mutex<EnvironmentIndex>,
) -> Result<Vec<String>> {
    let initialized = index
        .lock()
        .expect("reconciler environment index lock")
        .initialized;
    if !initialized {
        let objects = catalog_list_kind(ctx, KIND_ENVIRONMENT).await?;
        let mut index = index.lock().expect("reconciler environment index lock");
        index.replace_from_objects(objects);
        return Ok(index.sorted_names());
    }

    let listed_ids = catalog_list_kind_ids(ctx, KIND_ENVIRONMENT).await?;
    let (appeared, disappeared) = index
        .lock()
        .expect("reconciler environment index lock")
        .membership_delta(&listed_ids);
    let mut loaded = Vec::new();
    for id in appeared {
        match catalog_get(ctx, &id).await? {
            Some(object) if object.kind == KIND_ENVIRONMENT => loaded.push(object),
            _ => {}
        }
    }
    let mut index = index.lock().expect("reconciler environment index lock");
    for object in loaded {
        index.upsert(object);
    }
    for id in disappeared {
        index.remove_id(&id);
    }
    Ok(index.sorted_names())
}

fn record_list_kind(kind: &str) {
    #[cfg(test)]
    admission_io::record_list_kind(kind);
    let _ = kind;
}

fn record_list_kind_ids(kind: &str) {
    #[cfg(test)]
    admission_io::record_list_kind_ids(kind);
    let _ = kind;
}

fn record_get(id: &str) {
    #[cfg(test)]
    admission_io::record_get(id);
    let _ = id;
}

async fn catalog_list_kind(ctx: &mut Ctx, kind: &str) -> Result<Vec<Object>> {
    record_list_kind(kind);
    ctx.list_kind(kind).await
}

async fn catalog_list_kind_ids(ctx: &mut Ctx, kind: &str) -> Result<Vec<String>> {
    record_list_kind_ids(kind);
    ctx.list_kind_ids(kind).await
}

async fn catalog_get(ctx: &mut Ctx, id: &str) -> Result<Option<Object>> {
    record_get(id);
    ctx.get(id).await
}

#[cfg(test)]
pub(super) mod admission_io {
    use std::cell::RefCell;

    thread_local! {
        static LOG: RefCell<Option<AdmissionIoLog>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Debug, Default)]
    pub(crate) struct AdmissionIoLog {
        pub list_kinds: Vec<String>,
        pub list_kind_ids: Vec<String>,
        pub gets: Vec<String>,
    }

    pub(super) fn record_list_kind(kind: &str) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.list_kinds.push(kind.to_string());
            }
        });
    }

    pub(super) fn record_list_kind_ids(kind: &str) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.list_kind_ids.push(kind.to_string());
            }
        });
    }

    pub(super) fn record_get(id: &str) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.gets.push(id.to_string());
            }
        });
    }

    pub(crate) async fn capture<F, Fut, T>(f: F) -> (T, AdmissionIoLog)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        LOG.with(|log| *log.borrow_mut() = Some(AdmissionIoLog::default()));
        let result = f().await;
        let recorded = LOG.with(|log| log.borrow_mut().take().unwrap_or_default());
        (result, recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ontology::{KIND_ENVIRONMENT, env_id};

    fn environment(name: &str, updated: i64) -> Object {
        Object {
            id: env_id(name),
            kind: KIND_ENVIRONMENT.into(),
            name: name.into(),
            updated,
            ..Default::default()
        }
    }

    #[test]
    fn membership_delta_gets_only_appeared_ids() {
        let mut index = EnvironmentIndex::default();
        index.replace_from_objects(vec![environment("alpha", 1), environment("beta", 2)]);
        let listed = vec![env_id("beta"), env_id("gamma")];
        let (appeared, disappeared) = index.membership_delta(&listed);
        assert_eq!(appeared, vec![env_id("gamma")]);
        assert_eq!(disappeared, vec![env_id("alpha")]);
    }

    #[test]
    fn membership_delta_is_empty_when_ids_are_unchanged() {
        let mut index = EnvironmentIndex::default();
        index.replace_from_objects(vec![environment("alpha", 1), environment("beta", 2)]);
        let listed = vec![env_id("alpha"), env_id("beta")];
        let (appeared, disappeared) = index.membership_delta(&listed);
        assert!(appeared.is_empty());
        assert!(disappeared.is_empty());
        assert_eq!(index.by_name.get("alpha").unwrap().updated, 1);
    }

    #[test]
    fn upsert_refreshes_generation_and_remove_id_drops_names() {
        let mut index = EnvironmentIndex::default();
        index.replace_from_objects(vec![environment("alpha", 1), environment("beta", 2)]);
        index.upsert(environment("alpha", 9));
        assert_eq!(index.by_name.get("alpha").unwrap().updated, 9);
        let listed = vec![env_id("beta")];
        let (appeared, disappeared) = index.membership_delta(&listed);
        assert!(appeared.is_empty());
        for id in disappeared {
            index.remove_id(&id);
        }
        assert_eq!(index.sorted_names(), vec!["beta".to_string()]);
    }
}

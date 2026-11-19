//! What each process that runs steps can execute, and the refusal of a plan
//! no such process can run (ADR 0057).
//!
//! A server replica and an environment runtime each record the executor
//! kinds they have installed when they check in. An environment's supported
//! set is derived from those records, never configured: its runtime's set
//! when a runtime runs it, otherwise the intersection over the server
//! replicas that checked in recently. A process that recorded no set (an
//! older version) makes the set `unknown`, and planning then leaves the
//! check to apply, which stays the fence on the process that runs the step.
//!
//! Hosts install an [`ExecutionCapabilitySource`] on the [`Ctx`]. Without
//! one (embedded `tenkaictl`, tests), the planning process's own executors
//! are the set, because the same process applies the plan.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::software_executor::{SoftwareExecutorKind, SoftwareExecutors};

/// A runtime counts as checked in for this long after its last request.
/// It records activity at most every 30 seconds while it polls, so this is
/// three missed records.
pub const RUNTIME_CHECK_IN_WINDOW_MS: i64 = 90_000;

/// Which kind of process a [`ProcessExecutors`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessKind {
    /// A `tenkai-server` replica, named by its writer-lease holder.
    Replica,
    /// An environment runtime instance, named by runner and instance.
    Runtime,
    /// The planning process itself, when no host source is installed.
    Local,
}

/// One process's recorded executor set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProcessExecutors {
    pub kind: ProcessKind,
    /// Writer-lease holder, or `<runner>/<instance>` for a runtime.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub version: Option<String>,
    /// Installed executor kinds. Absent when the process recorded none, as
    /// a version before ADR 0057 does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub executors: Option<BTreeSet<String>>,
    /// Last check-in, Unix milliseconds.
    pub checked_in_at: i64,
}

impl ProcessExecutors {
    fn kinds(&self) -> Option<BTreeSet<SoftwareExecutorKind>> {
        self.executors.as_ref().map(|names| {
            names
                .iter()
                .filter_map(|name| SoftwareExecutorKind::from_name(name))
                .collect()
        })
    }
}

/// The server replicas a host can see, already limited to those that
/// checked in within the host's window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaView {
    /// This replica's writer-lease holder, when it has one.
    pub this: Option<String>,
    /// The holder of a live writer lease.
    pub leader: Option<String>,
    pub replicas: Vec<ProcessExecutors>,
}

impl ReplicaView {
    /// Peers whose executor set differs from this replica's. Empty when
    /// this replica has no recorded set or no peers.
    pub fn differing_peers(&self) -> Vec<String> {
        let Some(this) = self.this.as_deref() else {
            return Vec::new();
        };
        let Some(own) = self.replicas.iter().find(|replica| replica.id == this) else {
            return Vec::new();
        };
        self.replicas
            .iter()
            .filter(|replica| replica.id != this && replica.executors != own.executors)
            .map(|replica| replica.id.clone())
            .collect()
    }
}

/// Where a host reads the executor sets of the processes that may run a
/// step. Reads are local and cheap: replicas come from the writer lease's
/// last renewal, runtimes from the operational store.
pub trait ExecutionCapabilitySource: Send + Sync {
    fn replicas(&self) -> ReplicaView;
    /// Every recorded runtime instance, fresh or not, with its environment.
    fn runtimes(&self) -> Result<Vec<(String, ProcessExecutors)>>;
    /// A runtime token configured on this host serves `environment`, so a
    /// runtime runs it even before that runtime has checked in.
    fn assigned_to_runtime(&self, _environment: &str) -> bool {
        false
    }
}

/// A server's source: runtimes from its operational store's activity
/// records, replicas from `replicas` (the writer lease's last view, or none
/// on a single-replica server).
pub struct StoreExecutionCapabilities {
    store: std::sync::Arc<dyn crate::storage::OperationalStore>,
    replicas: Box<dyn Fn() -> ReplicaView + Send + Sync>,
    /// Environments a configured runtime token serves.
    runtime_environments: std::collections::HashSet<String>,
}

impl StoreExecutionCapabilities {
    pub fn new(
        store: std::sync::Arc<dyn crate::storage::OperationalStore>,
        replicas: impl Fn() -> ReplicaView + Send + Sync + 'static,
        runtime_environments: std::collections::HashSet<String>,
    ) -> Self {
        Self {
            store,
            replicas: Box::new(replicas),
            runtime_environments,
        }
    }
}

impl ExecutionCapabilitySource for StoreExecutionCapabilities {
    fn replicas(&self) -> ReplicaView {
        (self.replicas)()
    }

    fn assigned_to_runtime(&self, environment: &str) -> bool {
        self.runtime_environments.contains(environment)
    }

    fn runtimes(&self) -> Result<Vec<(String, ProcessExecutors)>> {
        Ok(self
            .store
            .runtime_activity()?
            .into_iter()
            .map(|activity| {
                let process = ProcessExecutors {
                    kind: ProcessKind::Runtime,
                    id: format!("{}/{}", activity.runner_id, activity.instance_id),
                    version: activity.runtime_version,
                    executors: activity.executors.as_deref().map(parse_names),
                    checked_in_at: [
                        activity.last_work_at,
                        activity.last_heartbeat_at,
                        activity.last_inventory_at,
                    ]
                    .into_iter()
                    .flatten()
                    .max()
                    .unwrap_or(0),
                };
                (activity.environment_id, process)
            })
            .collect())
    }
}

/// What an environment's executing processes can run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SupportedExecutors {
    /// Every process that may run a step has these kinds installed.
    Known {
        executors: BTreeSet<String>,
        processes: Vec<ProcessExecutors>,
    },
    /// Planning cannot tell; apply checks on the process that runs it.
    Unknown {
        reason: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        processes: Vec<ProcessExecutors>,
    },
}

impl SoftwareExecutors {
    /// The kinds this process can run, by the same checks apply makes.
    pub fn installed_kinds(&self) -> BTreeSet<SoftwareExecutorKind> {
        SoftwareExecutorKind::ALL
            .into_iter()
            .filter(|kind| match kind {
                SoftwareExecutorKind::Host => self.host().is_ok(),
                kind => self.resolve(Some(*kind)).is_ok(),
            })
            .collect()
    }

    /// [`Self::installed_kinds`] as canonical names, comma-separated: what
    /// a runtime sends in `x-tenkai-runtime-executors`.
    pub fn installed_names(&self) -> String {
        let names: Vec<_> = self
            .installed_kinds()
            .into_iter()
            .map(SoftwareExecutorKind::as_str)
            .collect();
        names.join(",")
    }
}

/// Parse a comma-separated executor list. Names this version does not know
/// are dropped: no release it admits can declare them.
pub fn parse_names(names: &str) -> BTreeSet<String> {
    names
        .split(',')
        .filter_map(|name| SoftwareExecutorKind::from_name(name.trim()))
        .map(|kind| kind.as_str().to_string())
        .collect()
}

/// Derive the supported set from the fresh records of every process that
/// may run a step.
fn derive(processes: Vec<ProcessExecutors>, none_reason: &str) -> SupportedExecutors {
    if processes.is_empty() {
        return SupportedExecutors::Unknown {
            reason: none_reason.into(),
            processes,
        };
    }
    let mut supported: Option<BTreeSet<SoftwareExecutorKind>> = None;
    for process in &processes {
        let Some(kinds) = process.kinds() else {
            return SupportedExecutors::Unknown {
                reason: format!("{} recorded no executors (an older version)", process.id),
                processes,
            };
        };
        supported = Some(match supported {
            Some(supported) => supported.intersection(&kinds).copied().collect(),
            None => kinds,
        });
    }
    SupportedExecutors::Known {
        executors: supported
            .unwrap_or_default()
            .into_iter()
            .map(|kind| kind.as_str().to_string())
            .collect(),
        processes,
    }
}

fn local(own: &SoftwareExecutors) -> ProcessExecutors {
    ProcessExecutors {
        kind: ProcessKind::Local,
        id: "this process".into(),
        version: Some(crate::version_skew::SERVER_VERSION.into()),
        executors: Some(
            own.installed_kinds()
                .into_iter()
                .map(|kind| kind.as_str().to_string())
                .collect(),
        ),
        checked_in_at: crate::now_millis(),
    }
}

/// This process's installed set: embedded planning, and a tenant read
/// when this host has no application catalog.
pub fn this_process(own: &SoftwareExecutors) -> SupportedExecutors {
    derive(vec![local(own)], "")
}

/// The supported set of `environment`. `own` is the planning process's
/// executors, used when no other process runs its steps.
pub async fn supported_for(
    ctx: &mut Ctx,
    environment: &str,
    own: &SoftwareExecutors,
) -> Result<SupportedExecutors> {
    let Some(source) = ctx.execution_capabilities() else {
        return Ok(this_process(own));
    };
    let runtimes: Vec<_> = source
        .runtimes()?
        .into_iter()
        .filter_map(|(runtime_environment, runtime)| {
            (runtime_environment == environment).then_some(runtime)
        })
        .collect();
    if !runtimes.is_empty()
        || source.assigned_to_runtime(environment)
        || crate::runtime_credentials::runtime_managed(ctx, environment).await?
    {
        let now = crate::now_millis();
        let fresh = runtimes
            .into_iter()
            .filter(|runtime| now - runtime.checked_in_at <= RUNTIME_CHECK_IN_WINDOW_MS)
            .collect();
        return Ok(derive(
            fresh,
            "no runtime of this environment checked in recently",
        ));
    }
    let view = source.replicas();
    if let Some(leader) = &view.leader
        && !view.replicas.iter().any(|replica| &replica.id == leader)
    {
        return Ok(SupportedExecutors::Unknown {
            reason: format!(
                "writer-lease holder {leader} recorded no executors (an older version)"
            ),
            processes: view.replicas,
        });
    }
    if view.replicas.is_empty() {
        return Ok(this_process(own));
    }
    Ok(derive(view.replicas, ""))
}

/// Refuse a plan whose steps declare an executor outside `environment`'s
/// supported set, naming the release, the executor, and each process that
/// lacks it. An unknown set refuses nothing.
pub async fn refuse_unsupported(
    ctx: &mut Ctx,
    environment: &str,
    own: &SoftwareExecutors,
    declared: &[(String, SoftwareExecutorKind)],
) -> Result<()> {
    if declared.is_empty() {
        return Ok(());
    }
    let SupportedExecutors::Known { processes, .. } = supported_for(ctx, environment, own).await?
    else {
        return Ok(());
    };
    for (release, kind) in declared {
        let lacking: Vec<_> = processes
            .iter()
            .filter(|process| process.kinds().is_some_and(|kinds| !kinds.contains(kind)))
            .map(|process| process.id.as_str())
            .collect();
        if !lacking.is_empty() {
            bail!(
                "release {release} declares deploy.executor = \"{kind}\", and that executor is not installed on {} that may run {environment}'s steps",
                lacking.join(", ")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(id: &str, executors: Option<&str>) -> ProcessExecutors {
        ProcessExecutors {
            kind: ProcessKind::Replica,
            id: id.into(),
            version: None,
            executors: executors.map(parse_names),
            checked_in_at: 0,
        }
    }

    #[test]
    fn the_supported_set_is_the_intersection_of_every_replica() {
        let supported = derive(
            vec![
                replica("a", Some("shell,docker,helm")),
                replica("b", Some("shell,helm")),
            ],
            "",
        );
        let SupportedExecutors::Known { executors, .. } = supported else {
            panic!("{supported:?}");
        };
        assert_eq!(executors, parse_names("shell,helm"));
    }

    #[test]
    fn a_replica_without_a_record_makes_the_set_unknown() {
        let supported = derive(vec![replica("a", Some("shell")), replica("old", None)], "");
        assert!(
            matches!(&supported, SupportedExecutors::Unknown { reason, .. } if reason.contains("old")),
            "{supported:?}"
        );
        assert!(matches!(
            derive(Vec::new(), "none"),
            SupportedExecutors::Unknown { .. }
        ));
    }

    #[test]
    fn unknown_names_are_dropped_and_aliases_normalized() {
        assert_eq!(
            parse_names("k8s, Docker,warp-drive,"),
            parse_names("kubernetes,docker")
        );
    }

    #[test]
    fn differing_peers_name_replicas_whose_set_is_not_this_ones() {
        let view = ReplicaView {
            this: Some("a".into()),
            leader: Some("a".into()),
            replicas: vec![
                replica("a", Some("shell,docker")),
                replica("b", Some("shell")),
                replica("c", Some("docker,shell")),
            ],
        };
        assert_eq!(view.differing_peers(), ["b"]);
        assert!(ReplicaView::default().differing_peers().is_empty());
    }
}

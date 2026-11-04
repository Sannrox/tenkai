//! The applier's durable records (ADR 0041 §2) and their transitions.
//!
//! Only the applier writes these. The server reads the applied-state record
//! to plan host steps, and an instance's result record to learn how the
//! step it started ended. Layout under the applier's state directory:
//!
//! - `records/<product_key>.json`: [`AppliedStateRecord`];
//! - `instances/<instance>/started.json`: [`HostApplyStarted`];
//! - `instances/<instance>/result.json`: [`HostApplyResult`].

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::verify::{HostRelease, VerifiedHostStep};
use crate::approval_policy::QuorumPurpose;
use crate::plan::{Action, HostAction};

pub const APPLIED_STATE_SCHEMA: &str = "tenkai.host-applied-state.v1";
pub const STARTED_SCHEMA: &str = "tenkai.host-apply-started.v1";
pub const RESULT_SCHEMA: &str = "tenkai.host-apply-result.v1";
/// `instances/<instance>/started.json`.
pub const STARTED_FILE: &str = "started.json";
/// `instances/<instance>/result.json`.
pub const RESULT_FILE: &str = "result.json";

/// `records/<product_key>.json` under `state_dir`.
pub fn record_path(state_dir: &Path, environment: &str, product: &str) -> PathBuf {
    state_dir
        .join("records")
        .join(format!("{}.json", super::product_key(environment, product)))
}

/// `instances/<instance>` under `state_dir`.
pub fn instance_dir(state_dir: &Path, instance: &str) -> PathBuf {
    state_dir.join("instances").join(instance)
}

/// What is applied for one product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppliedState {
    Empty,
    Applied {
        release: HostRelease,
    },
    /// An install (`to` set) or uninstall (`to` absent) started and did not
    /// succeed. Either side may be the source of the next step.
    Dirty {
        from: Option<HostRelease>,
        to: Option<HostRelease>,
    },
}

/// The applier's record for one environment and product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedStateRecord {
    pub schema: String,
    pub environment: String,
    pub product: String,
    /// Advanced by every install or uninstall start. A host step runs only at
    /// the generation its approved plan names.
    pub generation: u64,
    #[serde(flatten)]
    pub state: AppliedState,
    /// The newest release ever applied; `empty` keeps it. A target that is
    /// not newer needs downgrade or rollback approvals.
    pub high_water: Option<HostRelease>,
    /// The install or uninstall that last advanced the generation, written
    /// in the same atomic replace that advanced it.
    pub last_started: Option<HostApplyStarted>,
    /// Its result, once it completed, so a crash before the instance's own
    /// result file is written loses nothing.
    pub last_result: Option<HostApplyResult>,
}

/// Written before a command runs. Without a result after a crash or reboot,
/// the instance resolves as interrupted and is never run again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostApplyStarted {
    pub schema: String,
    pub instance: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub step_id: String,
    pub environment: String,
    pub product: String,
    pub action: HostAction,
    pub release: HostRelease,
    /// The record's generation once this step started: advanced for an
    /// install or uninstall, unchanged for health.
    pub generation: u64,
    pub started_at: i64,
}

/// How a started instance ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostApplyOutcome {
    Succeeded,
    Failed,
    /// The applier's timeout killed the command's process group.
    TimedOut,
    /// `systemctl stop` killed the command's process group.
    Stopped,
    /// Started, then the applier crashed or the host rebooted.
    Interrupted,
}

impl HostApplyOutcome {
    pub fn succeeded(self) -> bool {
        self == Self::Succeeded
    }
}

/// The terminal record of one instance. The server accepts it only when
/// `instance` is the one it started; missing or mismatched is a failed step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostApplyResult {
    pub schema: String,
    pub instance: String,
    pub environment: String,
    pub product: String,
    pub action: HostAction,
    /// Bare sha256 hex of the release manifest the step acted on.
    pub release_digest: String,
    pub outcome: HostApplyOutcome,
    /// The command's exit code, when it exited.
    pub exit_status: Option<i32>,
    pub detail: String,
    /// The record's generation after the step.
    pub generation: u64,
    pub started_at: i64,
    pub finished_at: i64,
}

impl HostApplyStarted {
    /// The result of this start with `outcome`.
    pub fn result(
        &self,
        outcome: HostApplyOutcome,
        exit_status: Option<i32>,
        detail: impl Into<String>,
        finished_at: i64,
    ) -> HostApplyResult {
        HostApplyResult {
            schema: RESULT_SCHEMA.into(),
            instance: self.instance.clone(),
            environment: self.environment.clone(),
            product: self.product.clone(),
            action: self.action,
            release_digest: self.release.manifest_digest.clone(),
            outcome,
            exit_status,
            detail: detail.into(),
            generation: self.generation,
            started_at: self.started_at,
            finished_at,
        }
    }
}

impl AppliedStateRecord {
    /// The record of a product the applier never touched.
    pub fn empty(environment: &str, product: &str) -> Self {
        Self {
            schema: APPLIED_STATE_SCHEMA.into(),
            environment: environment.into(),
            product: product.into(),
            generation: 0,
            state: AppliedState::Empty,
            high_water: None,
            last_started: None,
            last_result: None,
        }
    }

    /// Admit `step` against this record, inside the per-product lock.
    ///
    /// Requires the expected generation, the source release, and, for an
    /// install whose target is not newer than the high-water release, the
    /// downgrade (or, for a rollback step, rollback) approvals. Returns the
    /// started record and, for an install or uninstall, the record to write
    /// before the command runs: generation advanced, state `dirty`.
    pub fn admit(
        &self,
        step: &VerifiedHostStep,
        now_ms: i64,
    ) -> Result<(HostApplyStarted, Option<Self>)> {
        if self.environment != step.environment || self.product != step.product {
            bail!("applied-state record belongs to another environment or product");
        }
        if step.expected_generation != self.generation {
            bail!(
                "step expects generation {} of {} in {}, but the record is at generation {}",
                step.expected_generation,
                self.product,
                self.environment,
                self.generation
            );
        }
        let source = self.source(step.from.as_deref())?;
        if matches!(step.action, HostAction::Uninstall | HostAction::Health)
            && source.is_none_or(|source| source != &step.release)
        {
            bail!(
                "the record's release {} is not the signed release this step acts on",
                step.release.version
            );
        }
        if step.action == HostAction::Health
            && !matches!(&self.state, AppliedState::Applied { release } if release == &step.release)
        {
            bail!("health runs only on an applied release");
        }
        if step.action == HostAction::Install
            && let Some(high_water) = &self.high_water
            && !is_newer(&step.release.version, &high_water.version)
        {
            let purpose = if step.step_action == Action::Rollback {
                QuorumPurpose::Rollback
            } else {
                QuorumPurpose::Downgrade
            };
            step.approvals.require(purpose).map_err(|error| {
                anyhow::anyhow!(
                    "{} is not newer than the high-water release {}: {error:#}",
                    step.release.version,
                    high_water.version
                )
            })?;
        }
        let generation = match step.action {
            HostAction::Health => self.generation,
            HostAction::Install | HostAction::Uninstall => self
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("generation overflow"))?,
        };
        let started = HostApplyStarted {
            schema: STARTED_SCHEMA.into(),
            instance: step.instance.clone(),
            plan_id: step.plan_id.clone(),
            plan_digest: step.plan_digest.clone(),
            step_id: step.step_id.clone(),
            environment: step.environment.clone(),
            product: step.product.clone(),
            action: step.action,
            release: step.release.clone(),
            generation,
            started_at: now_ms,
        };
        let advanced = (step.action != HostAction::Health).then(|| Self {
            generation,
            state: AppliedState::Dirty {
                from: source.cloned(),
                to: (step.action == HostAction::Install).then(|| step.release.clone()),
            },
            last_started: Some(started.clone()),
            last_result: None,
            ..self.clone()
        });
        Ok((started, advanced))
    }

    /// The record after `started`'s install or uninstall ended with `result`:
    /// `applied` or `empty` on success, still `dirty` otherwise.
    pub fn complete(&self, started: &HostApplyStarted, result: &HostApplyResult) -> Self {
        let mut next = self.clone();
        if result.outcome.succeeded() {
            match started.action {
                HostAction::Install => {
                    next.state = AppliedState::Applied {
                        release: started.release.clone(),
                    };
                    if next.high_water.as_ref().is_none_or(|high_water| {
                        !is_newer(&high_water.version, &started.release.version)
                    }) {
                        next.high_water = Some(started.release.clone());
                    }
                }
                HostAction::Uninstall => next.state = AppliedState::Empty,
                HostAction::Health => {}
            }
        }
        next.last_result = Some(result.clone());
        next
    }

    /// The record's release that a step from `from` starts at: the applied
    /// release, either side of a dirty pair, or nothing for `empty`.
    fn source(&self, from: Option<&str>) -> Result<Option<&HostRelease>> {
        let candidates: Vec<Option<&HostRelease>> = match &self.state {
            AppliedState::Empty => vec![None],
            AppliedState::Applied { release } => vec![Some(release)],
            AppliedState::Dirty { from, to } => vec![from.as_ref(), to.as_ref()],
        };
        candidates
            .into_iter()
            .find(|candidate| candidate.map(|release| release.version.as_str()) == from)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "step starts from {}, but the record holds {}",
                    from.unwrap_or("nothing"),
                    self.describe()
                )
            })
    }

    fn describe(&self) -> String {
        let name = |release: &Option<HostRelease>| {
            release
                .as_ref()
                .map_or("nothing".to_string(), |release| release.version.clone())
        };
        match &self.state {
            AppliedState::Empty => "nothing".into(),
            AppliedState::Applied { release } => release.version.clone(),
            AppliedState::Dirty { from, to } => format!("dirty({}, {})", name(from), name(to)),
        }
    }
}

/// `candidate` is a strictly newer semantic version than `than`. Versions
/// that are not semantic versions are never newer, so they always need
/// downgrade approvals once anything was applied.
pub fn is_newer(candidate: &str, than: &str) -> bool {
    match (
        semver::Version::parse(candidate),
        semver::Version::parse(than),
    ) {
        (Ok(candidate), Ok(than)) => candidate > than,
        _ => false,
    }
}

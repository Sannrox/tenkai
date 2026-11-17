//! The applier's durable records (ADR 0041 §2) and their transitions.
//!
//! Only the applier writes these. The server reads the applied-state record
//! to plan host steps, and an instance's result record to learn how the
//! step it started ended. Layout under the applier's state directory:
//!
//! - `records/<product_key>.json`: [`AppliedStateRecord`];
//! - `instances/<instance>/started.json`: [`HostApplyStarted`];
//! - `instances/<instance>/result.json`: [`HostApplyResult`];
//! - `instances/<instance>/refused.json`: [`HostApplyRefused`], the latest
//!   refusal before anything started. It is not terminal: the same instance
//!   may start again once the reason is fixed.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::verify::{HostRelease, VerifiedHostStep};
use crate::approval_policy::QuorumPurpose;
use crate::plan::{Action, HostAction};

pub const APPLIED_STATE_SCHEMA: &str = "tenkai.host-applied-state.v1";
pub const STARTED_SCHEMA: &str = "tenkai.host-apply-started.v1";
pub const RESULT_SCHEMA: &str = "tenkai.host-apply-result.v1";
pub const REFUSED_SCHEMA: &str = "tenkai.host-apply-refused.v1";
/// `instances/<instance>/started.json`.
pub const STARTED_FILE: &str = "started.json";
/// `instances/<instance>/result.json`.
pub const RESULT_FILE: &str = "result.json";
/// `instances/<instance>/refused.json`.
pub const REFUSED_FILE: &str = "refused.json";

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
    /// succeed, or an OS image update is between `stage` and `confirm`.
    /// Either side may be the source of the next step.
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
    /// The newest release ever applied, by semantic-version precedence (a
    /// release that does not compare never replaces it); `empty` keeps it.
    /// A target that is not newer needs downgrade or rollback approvals.
    pub high_water: Option<HostRelease>,
    /// The step that last started for this product, written in the same
    /// atomic replace that started it. Steps of one product run one at a
    /// time, so this is the only one that may still be running after a crash.
    pub last_started: Option<HostApplyStarted>,
    /// Its result, once it completed, so a crash before the instance's own
    /// result file is written loses nothing.
    pub last_result: Option<HostApplyResult>,
    /// Set with a `reboot` start and cleared by the `verify` that settles it
    /// (OS image record only, ADR 0051). While it is set, the reboot's start
    /// without a result is the expected state, not an interruption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awaiting_boot: Option<super::os_image::AwaitingBoot>,
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
    /// The applier's control group (cgroup v2 path) when it started the
    /// command. Before a start without a result is settled as interrupted,
    /// this group must hold no process but the settling applier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// `[os_image].digest` of an OS image release: the step acts on the
    /// host-wide OS image record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
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
    /// A `reboot` came back on the previous image: the updater fell back.
    FellBack,
    /// A `reboot` was not verified before its boot deadline.
    NoReturn,
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

/// Why the latest start of an instance was refused before anything ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostApplyRefused {
    pub schema: String,
    pub instance: String,
    pub reason: String,
    pub refused_at: i64,
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
            awaiting_boot: None,
        }
    }

    /// Admit `step` against this record, inside the per-product lock (the
    /// host-wide lock for an OS image release).
    ///
    /// Requires the expected generation, the source release, and, for an
    /// install or stage whose target is not newer than the high-water
    /// release, the downgrade (or, for a rollback step, rollback) approvals.
    /// Returns the started record and the record to write before the command
    /// runs: for an install, uninstall, stage, reboot or confirm the
    /// generation advanced and the state `dirty`, for health and verify both
    /// unchanged; `last_started` names the step either way. A `reboot` is
    /// admitted through [`AppliedStateRecord::admit_reboot`], which adds the
    /// `awaiting_boot` intent. `cgroup` is the applier's control group, if it
    /// knows one.
    pub fn admit(
        &self,
        step: &VerifiedHostStep,
        cgroup: Option<String>,
        now_ms: i64,
    ) -> Result<(HostApplyStarted, Self)> {
        if self.environment != step.environment || self.product != step.product {
            bail!(
                "applied-state record belongs to {} in {}, not {} in {}",
                self.product,
                self.environment,
                step.product,
                step.environment
            );
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
        match (&self.awaiting_boot, step.action) {
            (Some(awaiting), action) if action != HostAction::Verify => bail!(
                "the host awaits the boot of {} that {} started; a verify step settles it first",
                awaiting.expected_digest,
                awaiting.instance
            ),
            (None, HostAction::Verify) => {
                bail!(
                    "no reboot awaits verification at generation {}",
                    self.generation
                )
            }
            _ => {}
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
        match step.action {
            HostAction::Health if !matches!(&self.state, AppliedState::Applied { release } if release == &step.release) =>
            {
                bail!("health runs only on an applied release")
            }
            HostAction::Reboot | HostAction::Verify | HostAction::Confirm => {
                self.require_staged(step)?
            }
            // A stage over a dirty pair continues toward one side of it;
            // a third image waits until the pair is settled.
            HostAction::Stage => {
                if let AppliedState::Dirty { from, to } = &self.state
                    && from.as_ref() != Some(&step.release)
                    && to.as_ref() != Some(&step.release)
                {
                    bail!(
                        "the record holds {}; staging {} would start a third image",
                        self.describe(),
                        step.release.version
                    );
                }
            }
            _ => {}
        }
        if matches!(step.action, HostAction::Install | HostAction::Stage)
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
        let generation = if step.action.advances_generation() {
            self.generation
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("generation overflow"))?
        } else {
            self.generation
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
            cgroup,
            image_digest: step
                .os_image
                .as_ref()
                .map(|os_image| os_image.digest.clone()),
        };
        let state = match step.action {
            HostAction::Install | HostAction::Uninstall | HostAction::Stage => {
                AppliedState::Dirty {
                    from: source.cloned(),
                    to: (step.action != HostAction::Uninstall).then(|| step.release.clone()),
                }
            }
            HostAction::Health | HostAction::Reboot | HostAction::Verify | HostAction::Confirm => {
                self.state.clone()
            }
        };
        let next = Self {
            generation,
            state,
            last_started: Some(started.clone()),
            last_result: None,
            ..self.clone()
        };
        Ok((started, next))
    }

    /// The record after `started` ended with `result`: an install or a
    /// confirm moves to `applied` on success, an uninstall to `empty`, and
    /// both stay `dirty` otherwise; a stage stays `dirty` either way; health
    /// changes nothing but the recorded result. A finished reboot (its
    /// command failed) or a verify that settled it clears `awaiting_boot`.
    pub fn complete(&self, started: &HostApplyStarted, result: &HostApplyResult) -> Self {
        let mut next = self.clone();
        if result.outcome.succeeded() {
            match started.action {
                HostAction::Install | HostAction::Confirm => {
                    next.state = AppliedState::Applied {
                        release: started.release.clone(),
                    };
                    // Only a provably newer release raises it; one that does
                    // not compare keeps the mark it would otherwise erase.
                    if next.high_water.as_ref().is_none_or(|high_water| {
                        is_newer(&started.release.version, &high_water.version)
                    }) {
                        next.high_water = Some(started.release.clone());
                    }
                }
                HostAction::Uninstall => next.state = AppliedState::Empty,
                HostAction::Health
                | HostAction::Stage
                | HostAction::Reboot
                | HostAction::Verify => {}
            }
        }
        // A verify interrupted before it settled the reboot leaves it for the
        // next verify.
        let settles_boot = match started.action {
            HostAction::Reboot => true,
            HostAction::Verify => result.outcome != HostApplyOutcome::Interrupted,
            _ => false,
        };
        if settles_boot {
            next.awaiting_boot = None;
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

    pub(super) fn describe(&self) -> String {
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

/// `candidate` has strictly higher semantic-version precedence than `than`;
/// build metadata does not count. Versions that are not semantic versions
/// are never newer, so they always need downgrade approvals once anything
/// was applied, and never raise the high-water release.
pub fn is_newer(candidate: &str, than: &str) -> bool {
    match (
        semver::Version::parse(candidate),
        semver::Version::parse(than),
    ) {
        (Ok(candidate), Ok(than)) => candidate.cmp_precedence(&than).is_gt(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn newer_means_higher_precedence_of_two_semantic_versions() {
        assert!(is_newer("1.2.0", "1.1.9"));
        assert!(is_newer("1.0.0", "1.0.0-rc.1"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("1.0.0+2", "1.0.0+1"));
        assert!(!is_newer("nightly", "1.0.0"));
        assert!(!is_newer("2.0.0", "nightly"));
    }
}

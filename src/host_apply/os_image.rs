//! OS image updates across a reboot (ADR 0051): the booted-image reader
//! contract, the `awaiting_boot` intent, and the verdicts that settle a
//! `reboot` and a `confirm` from what the root side reads.
//!
//! Every step of an OS image release acts on one host-wide record, kept at
//! [`os_image_record_path`] in place of a per-product record and changed
//! under one host-wide lock, because the updater's slots belong to the host.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::state::{AppliedState, AppliedStateRecord, HostApplyOutcome, HostApplyStarted};
use super::verify::VerifiedHostStep;
use crate::plan::HostAction;

/// Name of the host-wide OS image record and of its lock. A product key is
/// a hex digest, so it never collides with this name.
pub const OS_IMAGE_KEY: &str = "os-image";

/// Most bytes the booted-image reader may print.
pub const MAX_READER_OUTPUT: usize = 4096;

/// `records/os-image.json` under `state_dir`.
pub fn os_image_record_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("records")
        .join(format!("{OS_IMAGE_KEY}.json"))
}

/// What the updater says about the booted image, as the root-owned reader
/// prints it (contract `tenkai.booted-image.v1`): one JSON object, no other
/// fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootedImage {
    /// `sha256:<hex>` digest of the booted image, in the form a release's
    /// `[os_image].digest` declares.
    pub booted_digest: String,
    pub state: BootState,
}

/// Whether the updater keeps the booted image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootState {
    /// Booted once and held until Tenkai confirms it; the next boot may
    /// fall back.
    Pending,
    /// Permanent.
    Confirmed,
    /// Marked failed; the updater falls back on the next boot.
    Bad,
}

impl BootState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Bad => "bad",
        }
    }
}

impl BootedImage {
    /// Parse the reader's whole output strictly: one object with exactly
    /// the contract's fields and a well-formed digest. Never searches the
    /// output for a digest.
    pub fn parse(output: &[u8]) -> Result<Self> {
        if output.len() > MAX_READER_OUTPUT {
            bail!("the booted-image reader printed more than {MAX_READER_OUTPUT} bytes");
        }
        let booted: Self = serde_json::from_slice(output)
            .context("the booted-image reader did not print a tenkai.booted-image.v1 object")?;
        crate::signature_verification::validate_prefixed_digest(
            "the reader's booted_digest",
            &booted.booted_digest,
        )?;
        Ok(booted)
    }
}

/// Written with the `reboot` step's start, before the updater is asked to
/// reboot: what must boot, what booted before, and how to tell a later boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitingBoot {
    /// The `reboot` instance this settles.
    pub instance: String,
    pub expected_digest: String,
    /// The image booted when the reboot started: rollback intent, and what a
    /// fallback boots.
    pub previous_digest: String,
    /// The kernel's boot id when the reboot started; `verify` refuses to
    /// judge until it changed.
    pub boot_id: String,
    /// `started_at` plus the release's `boot_deadline_seconds`.
    pub deadline_ms: i64,
}

impl AwaitingBoot {
    /// How the `reboot` ended, judged from the image booted now, in boot
    /// `boot_id`, at `now_ms`. Refuses while the host has not rebooted, so
    /// a `verify` that came too early can run again.
    pub fn judge(
        &self,
        booted: &BootedImage,
        boot_id: &str,
        now_ms: i64,
    ) -> Result<(HostApplyOutcome, String)> {
        if boot_id == self.boot_id {
            bail!(
                "the host has not rebooted since {} started; verify again after the reboot",
                self.instance
            );
        }
        let digest = &booted.booted_digest;
        let (outcome, detail) = if *digest == self.expected_digest {
            match booted.state {
                BootState::Pending => (
                    HostApplyOutcome::Succeeded,
                    format!("booted the expected image {digest}, held until confirm"),
                ),
                BootState::Confirmed => (
                    HostApplyOutcome::Failed,
                    format!(
                        "booted the expected image {digest}, but the updater confirmed it before Tenkai asked; the host must hold confirmation"
                    ),
                ),
                BootState::Bad => (
                    HostApplyOutcome::Failed,
                    format!("booted the expected image {digest}, and the updater marked it bad"),
                ),
            }
        } else if *digest == self.previous_digest {
            (
                HostApplyOutcome::FellBack,
                format!(
                    "the updater fell back to the previous image {digest} instead of {}",
                    self.expected_digest
                ),
            )
        } else {
            (
                HostApplyOutcome::Failed,
                format!(
                    "booted {digest}, which is neither the expected image {} nor the previous image {}",
                    self.expected_digest, self.previous_digest
                ),
            )
        };
        if now_ms > self.deadline_ms {
            return Ok((
                HostApplyOutcome::NoReturn,
                format!("verify came after the boot deadline; {detail}"),
            ));
        }
        Ok((outcome, detail))
    }
}

/// Before `confirm` runs: the host must boot `expected` and not have marked
/// it bad, or confirming would keep the wrong image.
pub fn check_confirmable(expected: &str, booted: &BootedImage) -> Result<()> {
    if booted.booted_digest != expected {
        bail!(
            "the host boots {}, not the expected image {expected}; confirm would keep the wrong image",
            booted.booted_digest
        );
    }
    if booted.state == BootState::Bad {
        bail!("the updater marked the expected image {expected} bad");
    }
    Ok(())
}

/// How a `confirm` ended, from what the updater reports after it: only the
/// expected image, booted and confirmed, succeeds.
pub fn confirm_verdict(expected: &str, booted: &BootedImage) -> (HostApplyOutcome, String) {
    let digest = &booted.booted_digest;
    if *digest != expected {
        return (
            HostApplyOutcome::Failed,
            format!("the host boots {digest}, not the expected image {expected}"),
        );
    }
    match booted.state {
        BootState::Confirmed => (
            HostApplyOutcome::Succeeded,
            format!("the updater confirmed {digest}"),
        ),
        state => (
            HostApplyOutcome::Failed,
            format!(
                "the updater reports {digest} {} after confirm",
                state.as_str()
            ),
        ),
    }
}

impl AppliedStateRecord {
    /// Admit a `reboot` step: [`AppliedStateRecord::admit`], plus the
    /// `awaiting_boot` intent written with its start. `booted` is the image
    /// running now and `boot_id` the current boot.
    pub fn admit_reboot(
        &self,
        step: &VerifiedHostStep,
        cgroup: Option<String>,
        now_ms: i64,
        booted: &BootedImage,
        boot_id: String,
    ) -> Result<(HostApplyStarted, Self)> {
        let os_image = step
            .os_image
            .as_ref()
            .context("a reboot step needs a release that declares [os_image]")?;
        if step.action != HostAction::Reboot {
            bail!("{} is not a reboot step", step.instance);
        }
        let (started, mut next) = self.admit(step, cgroup, now_ms)?;
        if booted.booted_digest == os_image.digest {
            bail!(
                "the host already boots {}; there is nothing to reboot into",
                os_image.digest
            );
        }
        let deadline = i64::try_from(os_image.boot_deadline_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .and_then(|millis| now_ms.checked_add(millis))
            .context("boot deadline overflow")?;
        next.awaiting_boot = Some(AwaitingBoot {
            instance: started.instance.clone(),
            expected_digest: os_image.digest.clone(),
            previous_digest: booted.booted_digest.clone(),
            boot_id,
            deadline_ms: deadline,
        });
        next.last_started = Some(started.clone());
        Ok((started, next))
    }

    /// The release a `reboot`, `verify` or `confirm` acts on: the staged
    /// side of a dirty pair.
    pub(super) fn require_staged(&self, step: &VerifiedHostStep) -> Result<()> {
        match &self.state {
            AppliedState::Dirty { to: Some(to), .. } if *to == step.release => Ok(()),
            _ => bail!(
                "a {} step acts on the staged release {}, but the record holds {}",
                step.action,
                step.release.version,
                self.describe()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

    fn awaiting() -> AwaitingBoot {
        AwaitingBoot {
            instance: "reboot-1".into(),
            expected_digest: digest('b'),
            previous_digest: digest('a'),
            boot_id: "boot-1".into(),
            deadline_ms: 1_000,
        }
    }

    fn booted(fill: char, state: BootState) -> BootedImage {
        BootedImage {
            booted_digest: digest(fill),
            state,
        }
    }

    #[test]
    fn the_reader_output_is_parsed_strictly() {
        let good = format!(r#"{{"booted_digest":"{}","state":"pending"}}"#, digest('b'));
        assert_eq!(
            BootedImage::parse(good.as_bytes()).unwrap(),
            booted('b', BootState::Pending)
        );
        for (output, refusal) in [
            (
                format!(
                    r#"{{"booted_digest":"{}","state":"pending","staged":"x"}}"#,
                    digest('b')
                ),
                "unknown field",
            ),
            (r#"{"state":"confirmed"}"#.into(), "missing field"),
            (
                r#"{"booted_digest":null,"state":"pending"}"#.to_string(),
                "tenkai.booted-image.v1",
            ),
            (
                format!(r#"{{"booted_digest":"{}","state":"unknown"}}"#, digest('b')),
                "unknown variant",
            ),
            (
                r#"{"booted_digest":"sha256:abc","state":"pending"}"#.into(),
                "booted_digest",
            ),
            (
                format!("deploying {}\n", digest('b')),
                "tenkai.booted-image.v1",
            ),
            (" ".repeat(MAX_READER_OUTPUT + 1), "more than 4096 bytes"),
        ] {
            let error = format!("{:#}", BootedImage::parse(output.as_bytes()).unwrap_err());
            assert!(error.contains(refusal), "{output:?}: {error}");
        }
    }

    #[test]
    fn a_reboot_is_judged_from_the_booted_image_after_a_new_boot() {
        let awaiting = awaiting();
        let judge = |image: &BootedImage, boot_id: &str, now: i64| {
            awaiting
                .judge(image, boot_id, now)
                .map(|(outcome, _)| outcome)
        };
        let error = judge(&booted('a', BootState::Confirmed), "boot-1", 10).unwrap_err();
        assert!(
            format!("{error:#}").contains("has not rebooted"),
            "{error:#}"
        );
        for (image, outcome) in [
            (booted('b', BootState::Pending), HostApplyOutcome::Succeeded),
            (booted('b', BootState::Confirmed), HostApplyOutcome::Failed),
            (booted('b', BootState::Bad), HostApplyOutcome::Failed),
            (
                booted('a', BootState::Confirmed),
                HostApplyOutcome::FellBack,
            ),
            (booted('c', BootState::Pending), HostApplyOutcome::Failed),
        ] {
            assert_eq!(judge(&image, "boot-2", 10).unwrap(), outcome, "{image:?}");
        }
        // After the deadline the booted image is still recorded, but the
        // reboot never succeeds.
        let (outcome, detail) = awaiting
            .judge(&booted('b', BootState::Pending), "boot-2", 1_001)
            .unwrap();
        assert_eq!(outcome, HostApplyOutcome::NoReturn);
        assert!(detail.contains(&digest('b')), "{detail}");
    }

    #[test]
    fn confirm_keeps_only_the_expected_image_once_confirmed() {
        let expected = digest('b');
        assert!(check_confirmable(&expected, &booted('b', BootState::Pending)).is_ok());
        assert!(check_confirmable(&expected, &booted('b', BootState::Bad)).is_err());
        assert!(check_confirmable(&expected, &booted('a', BootState::Confirmed)).is_err());
        assert_eq!(
            confirm_verdict(&expected, &booted('b', BootState::Confirmed)).0,
            HostApplyOutcome::Succeeded
        );
        for image in [
            booted('b', BootState::Pending),
            booted('a', BootState::Confirmed),
        ] {
            assert_eq!(
                confirm_verdict(&expected, &image).0,
                HostApplyOutcome::Failed,
                "{image:?}"
            );
        }
    }
}

//! One run of `tenkai-host-apply@<instance>.service`, end to end.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tenkai::host_apply::HostAction;
use tenkai::host_apply::os_image::{AwaitingBoot, confirm_verdict};
use tenkai::host_apply::state::{HostApplyOutcome, HostApplyResult};

use crate::store::{self, Admission, Ended};
use crate::{
    ApplierConfig, ApplierPaths, config, discard_settled_work, discard_work, intake, run, secrets,
};

/// How one run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The instance ran now, or ran before: its result record.
    Result(HostApplyResult),
    /// Refused before anything started; the server may start the instance
    /// again once the reason is fixed, for example with more approvals.
    Refused(String),
    /// A `reboot` asked the updater to reboot; a `verify` settles it after
    /// the host comes back (ADR 0051).
    AwaitingBoot(AwaitingBoot),
}

impl Applied {
    /// The unit's exit code: 0 succeeded, 1 the step failed, 2 refused, 3
    /// awaiting the boot.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Result(result) if result.outcome.succeeded() => 0,
            Self::Result(_) => 1,
            Self::Refused(_) => 2,
            Self::AwaitingBoot(_) => 3,
        }
    }
}

impl From<Ended> for Applied {
    fn from(ended: Ended) -> Self {
        match ended {
            Ended::Result(result) => Self::Result(result),
            Ended::AwaitingBoot(awaiting) => Self::AwaitingBoot(awaiting),
        }
    }
}

/// Apply `instance`: return how it ended if it already started, from
/// root-owned records alone ([`store::recover`]);
/// otherwise load root-owned config and trust, copy and verify the request,
/// admit it in the per-product critical section, run its command until it
/// exits, times out, or the future that `stop` returns resolves, and record the
/// result. `stop` is called only once the step started, so a stop signal
/// before then keeps its default action. A refusal is recorded in
/// `refused.json`, which does not block a later start.
pub async fn apply<F: Future<Output = ()>>(
    paths: &ApplierPaths,
    instance: &str,
    stop: impl FnOnce() -> Result<F>,
) -> Result<Applied> {
    tenkai::host_apply::validate_instance_name(instance)?;
    if let Some(ended) = store::recover(paths, instance)? {
        return Ok(ended.into());
    }
    let admitted = (|| {
        let config = ApplierConfig::load(paths)?;
        let trust = config::load_trust(paths)?;
        let intake = intake(paths, &config, &trust, instance, tenkai::now_millis())?;
        let admission = store::admit(paths, &intake.verified)?;
        anyhow::Ok((config, intake, admission))
    })();
    let (config, intake, admission) = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            // The refusal is recorded whatever the cleanup does; a failed
            // discard is part of the recorded reason (#1338).
            let mut reason = format!("{error:#}");
            if let Err(cleanup) = discard_work(&paths.work_dir(instance)) {
                reason.push_str(&format!(
                    "; discarding the work copy also failed: {cleanup:#}"
                ));
            }
            store::record_refusal(paths, instance, &reason, tenkai::now_millis())?;
            return Ok(Applied::Refused(reason));
        }
    };
    let running = match admission {
        Admission::Recorded(result) => {
            discard_settled_work(&paths.work_dir(instance));
            return Ok(Applied::Result(result));
        }
        Admission::AwaitingBoot(awaiting) => {
            discard_settled_work(&paths.work_dir(instance));
            return Ok(Applied::AwaitingBoot(awaiting));
        }
        Admission::Run(running) => running,
    };
    // The sealed values and the workload certificate are written before the
    // command runs and recorded with its result; a write that fails ends the
    // step as failed.
    let written = (|| {
        let secrets_dir = if intake.verified.sealed.is_empty() {
            None
        } else {
            Some(
                secrets::write(paths, &intake.verified, &intake.secrets)
                    .context("writing the step's sealed values")?,
            )
        };
        let identity_dir = match &intake.identity {
            // A health step checks the certificate its install wrote.
            None if intake.verified.action == HostAction::Health => {
                secrets::installed_identity(paths, &intake.verified)?
            }
            None => None,
            Some(issued) => {
                let step = &intake.verified;
                let instance = secrets::step_instance(step);
                let current =
                    secrets::write_instance_identity(paths, &step.environment, instance, issued)
                        .context("writing the step's workload certificate")?;
                store::write_identity_record(
                    paths,
                    &tenkai::host_apply::identity::HostIdentityRecord::new(
                        &step.environment,
                        &step.product,
                        instance,
                        issued,
                    ),
                )
                .context("recording the step's workload certificate")?;
                Some(current)
            }
        };
        anyhow::Ok(run::Written {
            secrets_dir,
            identity_dir,
        })
    })();
    // An install of a release without a certificate, or an uninstall,
    // leaves nothing to renew once it succeeds. Until then the workload may
    // still run with its certificate, so the record stays.
    let forgets_identity = intake.identity.is_none()
        && matches!(
            intake.verified.action,
            HostAction::Install | HostAction::Uninstall
        );
    drop(intake.secrets);
    drop(intake.identity);
    let action = intake.verified.action;
    // A reboot runs the updater's command from root-owned configuration;
    // every other step its signed release command.
    let command = match written {
        Ok(_) if action == HostAction::Reboot => config
            .os_image()
            .and_then(|os_image| crate::os_image::updater_command(&os_image.reboot)),
        Ok(written) => run::step_command(&intake.verified, &intake.workdir, &written),
        Err(error) => Err(error),
    };
    let end = match command {
        Ok(command) => match run::adopt_descendants().and_then(|()| stop()) {
            Ok(stop) => {
                run::run_command(command, Duration::from_secs(config.timeout_seconds), stop).await
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let (outcome, exit_status, detail) = match end {
        Ok(end) => (end.outcome, end.exit_status, end.detail),
        Err(error) => (HostApplyOutcome::Failed, None, format!("{error:#}")),
    };
    // The record already awaits the boot. Only a reboot command that failed
    // ends the step: the shutdown it starts may stop the applier, or outlast
    // its timeout, while the host goes down into the armed image, so those
    // leave the start for `verify` (or the deadline) to settle.
    if action == HostAction::Reboot && outcome != HostApplyOutcome::Failed {
        let awaiting = running.await_boot()?;
        discard_settled_work(&paths.work_dir(instance));
        return Ok(Applied::AwaitingBoot(awaiting));
    }
    // A confirm succeeds only when the updater then reports the expected
    // image booted and confirmed.
    let (outcome, detail) = match (&intake.verified.os_image, action) {
        (Some(os_image), HostAction::Confirm) if outcome.succeeded() => {
            match crate::os_image::read_booted(paths) {
                Ok(booted) => confirm_verdict(&os_image.digest, &booted),
                Err(error) => (
                    HostApplyOutcome::Failed,
                    format!("reading the booted image after confirm: {error:#}"),
                ),
            }
        }
        _ => (outcome, detail),
    };
    // Still under the product lock, before the result is recorded. The
    // step's command already ran, so a record that cannot be removed is
    // named in the result instead of leaving the step unrecorded, where it
    // would later settle as Interrupted and leave the product dirty (#1310).
    let detail = if forgets_identity && outcome.succeeded() {
        let step = &intake.verified;
        let instance = secrets::step_instance(step);
        // The record first, so renewal never reads one whose files are gone.
        // An uninstall also drops the sealed values: nothing runs to read
        // them. An install without a certificate keeps them; its command
        // may still read the ones this step wrote.
        let forgotten = store::remove_identity_record(paths, &step.environment, instance)
            .and_then(|()| {
                secrets::remove_instance(paths, secrets::IDENTITY, &step.environment, instance)
            })
            .and_then(|()| match action {
                HostAction::Uninstall => {
                    secrets::remove_instance(paths, secrets::SECRETS, &step.environment, instance)
                }
                _ => Ok(()),
            });
        match forgotten {
            Ok(()) => detail,
            Err(error) => format!(
                "{detail}{}forgetting the instance's workload certificate or sealed values failed: {error:#}",
                if detail.is_empty() { "" } else { "; " }
            ),
        }
    } else {
        detail
    };
    let result = running.finish(outcome, exit_status, detail, tenkai::now_millis())?;
    discard_settled_work(&paths.work_dir(instance));
    Ok(Applied::Result(result))
}

//! One run of `tenkai-host-apply@<instance>.service`, end to end.

use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use tenkai::host_apply::state::{HostApplyOutcome, HostApplyResult};

use crate::store::{self, Admission};
use crate::{ApplierConfig, ApplierPaths, config, discard_work, intake, run};

/// How one run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The instance ran now, or ran before: its result record.
    Result(HostApplyResult),
    /// Refused before anything started; the server may start the instance
    /// again once the reason is fixed, for example with more approvals.
    Refused(String),
}

impl Applied {
    /// The unit's exit code: 0 succeeded, 1 the step failed, 2 refused.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Result(result) if result.outcome.succeeded() => 0,
            Self::Result(_) => 1,
            Self::Refused(_) => 2,
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
    if let Some(result) = store::recover(paths, instance)? {
        return Ok(Applied::Result(result));
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
            let reason = format!("{error:#}");
            discard_work(&paths.work_dir(instance))?;
            store::record_refusal(paths, instance, &reason, tenkai::now_millis())?;
            return Ok(Applied::Refused(reason));
        }
    };
    let running = match admission {
        Admission::Recorded(result) => {
            discard_work(&paths.work_dir(instance))?;
            return Ok(Applied::Result(result));
        }
        Admission::Run(running) => running,
    };
    let end = match run::adopt_descendants().and_then(|()| stop()) {
        Ok(stop) => {
            run::run_command(
                &intake.verified,
                &intake.workdir,
                Duration::from_secs(config.timeout_seconds),
                stop,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let (outcome, exit_status, detail) = match end {
        Ok(end) => (end.outcome, end.exit_status, end.detail),
        Err(error) => (HostApplyOutcome::Failed, None, format!("{error:#}")),
    };
    let result = running.finish(outcome, exit_status, detail, tenkai::now_millis())?;
    discard_work(&paths.work_dir(instance))?;
    Ok(Applied::Result(result))
}

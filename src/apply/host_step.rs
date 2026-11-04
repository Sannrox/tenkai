//! One host plan step through the root-side applier (ADR 0041 §2), under the
//! environment fence.
//!
//! The fence works as it does for the shell executor: refreshed before the
//! unit starts, every few seconds while it runs, and again before the result
//! is recorded. Losing it stops the unit and returns the fence error;
//! SIGINT or SIGTERM to the server, or dropping this future, stops it too.
//! The applier runs each instance at most once, so a retry of the same step
//! (same plan digest, step, and action) addresses the same instance and gets
//! its recorded result instead of a second run.

use std::time::Duration;

use crate::host_apply::HostApplyRequest;
use crate::host_apply::state::HostApplyResult;
use crate::host_executor::{ExpectedResult, HostExecutor};

use super::*;

/// How often the fence is refreshed while the unit runs.
const REFRESH_EVERY: Duration = Duration::from_secs(10);
/// How long a stopped unit may take to record the stop and exit. The unit's
/// own `TimeoutStopSec` bounds it on the systemd side.
pub(super) const STOP_GRACE: Duration = Duration::from_secs(120);

/// How a host step ended, short of a fence or control-plane failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HostStepEnd {
    /// The applier recorded how the instance ended.
    Recorded(HostApplyResult),
    /// Nothing ran: the step could not be spooled, or the applier refused it
    /// before anything started.
    NotRun(String),
    /// The unit may have run, but left no result this step can accept.
    Unknown(String),
}

/// Run `request` and return how it ended. Outer errors are fence and
/// control-plane failures.
pub(super) async fn run(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    host: &HostExecutor,
    request: &HostApplyRequest,
    content: &ReleaseContent,
) -> Result<HostStepEnd> {
    refresh_environment_lease(ctx, lease).await?;
    let instance = request.instance()?;
    let expected = ExpectedResult {
        instance: &instance,
        environment: &content.environment,
        product: &content.product,
        action: request.action,
        release_digest: &content.manifest_digest,
    };
    // A retry of a step that already ended runs nothing.
    match host.result(&expected) {
        Ok(Some(result)) => return Ok(HostStepEnd::Recorded(result)),
        Ok(None) => {}
        Err(error) => return Ok(HostStepEnd::Unknown(format!("{error:#}"))),
    }
    if let Err(error) = host.spool(
        request,
        &content.content_root,
        &content.manifest.immutable_inputs(),
        &content.artifact_digest,
    ) {
        return Ok(HostStepEnd::NotRun(format!("{error:#}")));
    }
    let ended = start_and_wait(ctx, lease, host, &instance).await;
    host.discard_spool(&instance);
    let started = ended?;
    refresh_environment_lease(ctx, lease).await?;
    Ok(match host.result(&expected) {
        Ok(Some(result)) => HostStepEnd::Recorded(result),
        Err(error) => HostStepEnd::Unknown(format!("{error:#}")),
        Ok(None) => missing_result(host, &instance, started),
    })
}

/// How the unit's start ended, when it ended without the fence being lost.
struct Started {
    since_ms: i64,
    start_error: Option<String>,
    interrupted: Option<&'static str>,
}

/// Start the unit and wait for its start job, keeping the fence fresh.
async fn start_and_wait(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    host: &HostExecutor,
    instance: &str,
) -> Result<Started> {
    refresh_environment_lease(ctx, lease).await?;
    let since_ms = crate::now_millis();
    let mut stop_on_drop = StopOnDrop {
        host,
        instance,
        armed: true,
    };
    let mut start = host.units().start(instance);
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut refresh = tokio::time::interval(REFRESH_EVERY);
    refresh.tick().await;
    enum Stop {
        Interrupted(&'static str),
        FenceLost(anyhow::Error),
    }
    let (ended, stop) = loop {
        tokio::select! {
            ended = &mut start => break (Some(ended), None),
            _ = interrupt.recv() => break (None, Some(Stop::Interrupted("the server was interrupted"))),
            _ = terminate.recv() => break (None, Some(Stop::Interrupted("the server was terminated"))),
            _ = refresh.tick() => {
                if let Err(error) = refresh_environment_lease(ctx, lease).await {
                    break (None, Some(Stop::FenceLost(error)));
                }
            }
        }
    };
    let ended = match (ended, stop) {
        (Some(ended), _) => ended,
        (None, Some(stop)) => {
            // Stop the unit and wait for the applier to record it.
            let stopped = host.units().stop(instance);
            let ended = tokio::time::timeout(STOP_GRACE, &mut start).await;
            stop_on_drop.armed = stopped.is_err() || ended.is_err();
            match stop {
                Stop::FenceLost(error) => return Err(error),
                Stop::Interrupted(reason) => {
                    return Ok(Started {
                        since_ms,
                        start_error: stopped.err().map(|error| format!("{error:#}")),
                        interrupted: Some(reason),
                    });
                }
            }
        }
        (None, None) => unreachable!("the loop breaks with an end or a stop"),
    };
    stop_on_drop.armed = false;
    Ok(Started {
        since_ms,
        start_error: ended.err().map(|error| format!("{error:#}")),
        interrupted: None,
    })
}

/// How a unit that left no result ended: refused since this start, which
/// ran nothing, or unknown.
fn missing_result(host: &HostExecutor, instance: &str, started: Started) -> HostStepEnd {
    let unit = crate::host_executor::unit_name(instance);
    match host.refusal_since(instance, started.since_ms) {
        Ok(Some(reason)) => {
            return HostStepEnd::NotRun(format!("the host applier refused {unit}: {reason}"));
        }
        Err(error) => {
            return HostStepEnd::Unknown(format!("{unit} recorded no result: {error:#}"));
        }
        Ok(None) => {}
    }
    HostStepEnd::Unknown(match (started.interrupted, started.start_error) {
        (Some(reason), _) => format!("{reason}; {unit} was stopped before it recorded a result"),
        (None, Some(error)) => format!("{unit} recorded no result: {error}"),
        (None, None) => format!("{unit} recorded no result"),
    })
}

/// Stops the unit if the step is dropped while it runs (cancellation).
struct StopOnDrop<'a> {
    host: &'a HostExecutor,
    instance: &'a str,
    armed: bool,
}

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.host.units().stop(self.instance);
        }
    }
}

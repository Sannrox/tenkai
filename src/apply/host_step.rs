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
const STOP_GRACE: Duration = Duration::from_secs(120);

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
    if let Some(profile) = &content.manifest.compatibility {
        let env = crate::environment::environment(ctx, &content.environment).await?;
        match crate::dependency_document::json_for_release(
            ctx,
            &env,
            content.instance_name(),
            profile,
            &content.manifest_digest,
        )
        .await
        {
            Ok(Some(json)) => {
                if let Err(error) = host.write_spool_file(
                    &instance,
                    crate::dependency_document::HOST_FILE,
                    json.as_bytes(),
                ) {
                    return Ok(HostStepEnd::NotRun(format!("{error:#}")));
                }
            }
            Ok(None) => {}
            Err(error) => return Ok(HostStepEnd::NotRun(format!("{error:#}"))),
        }
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

/// Stop every host unit an earlier holder of `lease` left running, and wait
/// until they are gone while keeping the lease fresh. Fails closed when one
/// is still running after [`STOP_GRACE`] or the lease is lost.
pub(super) async fn fence_environment(
    ctx: &mut Ctx,
    lease: &EnvironmentLease,
    host: &HostExecutor,
) -> Result<()> {
    let stale = host.stop_environment_units(&lease.environment).await?;
    if stale.is_empty() {
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + STOP_GRACE;
    let mut refresh = tokio::time::interval(REFRESH_EVERY);
    refresh.tick().await;
    loop {
        let running = host.units().running().await?;
        let left: Vec<_> = stale
            .iter()
            .filter(|instance| running.contains(instance))
            .collect();
        if left.is_empty() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "host units of {} from an earlier lease holder are still running: {}",
                lease.environment,
                left.iter()
                    .map(|instance| crate::host_executor::unit_name(instance))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            _ = refresh.tick() => refresh_environment_lease(ctx, lease).await?,
        }
    }
}

/// How the unit's start ended, when it ended without the fence being lost.
struct Started {
    since_ms: i64,
    start_error: Option<String>,
    interrupted: Option<&'static str>,
}

/// Why the server stops a unit it started.
enum Stop {
    Interrupted(&'static str),
    FenceLost(anyhow::Error),
}

/// Start the unit and wait until it ended, keeping the fence fresh. Losing
/// the lease or a SIGINT/SIGTERM stops the unit.
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
    let mut stop: Option<Stop> = None;
    let mut ended: Option<Result<()>> = None;
    loop {
        tokio::select! {
            done = &mut start => {
                ended = Some(done);
                break;
            }
            _ = interrupt.recv() => {
                stop = Some(Stop::Interrupted("the server was interrupted"));
                break;
            }
            _ = terminate.recv() => {
                stop = Some(Stop::Interrupted("the server was terminated"));
                break;
            }
            _ = refresh.tick() => {
                if let Err(error) = refresh_environment_lease(ctx, lease).await {
                    stop = Some(Stop::FenceLost(error));
                    break;
                }
            }
        }
    }
    // A start job can end, for example cancelled by a stop, while the
    // applier is still stopping. Wait until the unit is gone as well, so the
    // applier has recorded how the step ended before it is read. After a
    // stop, stop the unit again whenever it is seen running, since its start
    // job may reach it after the stop. A lease still held stays fresh.
    let mut stopped = match stop {
        Some(_) => host.units().stop(instance),
        None => Ok(()),
    };
    let deadline = tokio::time::Instant::now() + STOP_GRACE;
    let mut poll = tokio::time::interval(Duration::from_millis(200));
    let settled = loop {
        tokio::select! {
            biased;
            done = &mut start, if ended.is_none() => ended = Some(done),
            _ = poll.tick() => {
                let running = host
                    .units()
                    .running()
                    .await
                    .map(|running| running.iter().any(|unit| unit == instance));
                match running {
                    Ok(false) if ended.is_some() => break true,
                    Ok(true) if stop.is_some() => stopped = host.units().stop(instance),
                    _ => {}
                }
                if tokio::time::Instant::now() >= deadline {
                    break false;
                }
            }
            _ = refresh.tick(), if !matches!(stop, Some(Stop::FenceLost(_))) => {
                if let Err(error) = refresh_environment_lease(ctx, lease).await {
                    stop = Some(Stop::FenceLost(error));
                    stopped = host.units().stop(instance);
                }
            }
        }
    };
    stop_on_drop.armed = !settled || stopped.is_err();
    let start_error = match (stopped, ended) {
        (Err(error), _) | (Ok(()), Some(Err(error))) => Some(format!("{error:#}")),
        _ => None,
    };
    match stop {
        Some(Stop::FenceLost(error)) => Err(error),
        Some(Stop::Interrupted(reason)) => Ok(Started {
            since_ms,
            start_error,
            interrupted: Some(reason),
        }),
        None => Ok(Started {
            since_ms,
            start_error,
            interrupted: None,
        }),
    }
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

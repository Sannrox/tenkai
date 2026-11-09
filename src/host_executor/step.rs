//! One host plan step through the root-side applier (ADR 0041 §2), under a
//! fence: the server's environment lease, or an environment runtime's claim
//! (ADR 0048 §2).
//!
//! The fence works as it does for the shell executor: refreshed before the
//! unit starts, every few seconds while it runs, and again before the result
//! is recorded. Losing it stops the unit and returns the fence error;
//! SIGINT or SIGTERM to the process, or dropping this future, stops it too.
//! The applier runs each instance at most once, so a retry of the same step
//! (same plan digest, step, and action) addresses the same instance and gets
//! its recorded result instead of a second run.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::fenced_mutation::MutationFence;
use crate::host_apply::HostApplyRequest;
use crate::host_apply::state::HostApplyResult;
use crate::host_executor::{ExpectedResult, HostExecutor};

/// Why a failed host step is left failed (ADR 0041 section 2).
pub(crate) const HOST_NOT_RESTORED: &str =
    "host releases are never restored or re-applied automatically; run an approved rollback plan";

/// How often the fence is refreshed while the unit runs.
const REFRESH_EVERY: Duration = Duration::from_secs(10);
/// How long a stopped unit may take to record the stop and exit. The unit's
/// own `TimeoutStopSec` bounds it on the systemd side.
const STOP_GRACE: Duration = Duration::from_secs(120);

/// How a host step ended, short of a fence or control-plane failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostStepEnd {
    /// The applier recorded how the instance ended.
    Recorded(HostApplyResult),
    /// Nothing ran: the step could not be spooled, or the applier refused it
    /// before anything started.
    NotRun(String),
    /// The unit may have run, but left no result this step can accept.
    Unknown(String),
}

/// The release a host step spools next to its request, already admitted
/// by the caller.
pub(crate) struct SpooledRelease<'a> {
    pub environment: &'a str,
    pub product: &'a str,
    /// Bare sha256 hex of the signed manifest.
    pub release_digest: &'a str,
    /// Where the release's deploy inputs are placed.
    pub root: &'a Path,
    pub inputs: &'a [String],
    pub artifact_digest: &'a str,
    /// The canonical dependency document the release reads, when it has one.
    pub dependency_document: Option<&'a str>,
    /// The opened sealed values the step writes, when it writes any. Only a
    /// runtime can open them.
    pub sealed: Option<&'a crate::host_apply::sealed::HostSealedValues>,
}

/// Run `request` and return how it ended. Outer errors are fence and
/// control-plane failures.
pub(crate) async fn run(
    fence: &mut dyn MutationFence,
    host: &HostExecutor,
    request: &HostApplyRequest,
    release: &SpooledRelease<'_>,
) -> Result<HostStepEnd> {
    fence.refresh().await?;
    let instance = request.instance()?;
    let expected = ExpectedResult {
        instance: &instance,
        environment: release.environment,
        product: release.product,
        action: request.action,
        release_digest: release.release_digest,
    };
    // A retry of a step that already ended runs nothing.
    match host.result(&expected) {
        Ok(Some(result)) => return Ok(HostStepEnd::Recorded(result)),
        Ok(None) => {}
        Err(error) => return Ok(HostStepEnd::Unknown(format!("{error:#}"))),
    }
    if let Err(error) = host.spool(
        request,
        release.root,
        release.inputs,
        release.artifact_digest,
    ) {
        return Ok(HostStepEnd::NotRun(format!("{error:#}")));
    }
    if let Some(json) = release.dependency_document
        && let Err(error) = host.write_spool_file(
            &instance,
            crate::dependency_document::HOST_FILE,
            json.as_bytes(),
        )
    {
        host.discard_spool(&instance);
        return Ok(HostStepEnd::NotRun(format!("{error:#}")));
    }
    if let Some(values) = release.sealed
        && let Err(error) = host.write_sealed(&instance, values)
    {
        host.discard_spool(&instance);
        return Ok(HostStepEnd::NotRun(format!("{error:#}")));
    }
    let ended = start_and_wait(fence, host, &instance).await;
    host.discard_spool(&instance);
    let started = ended?;
    fence.refresh().await?;
    Ok(match host.result(&expected) {
        Ok(Some(result)) => HostStepEnd::Recorded(result),
        Err(error) => HostStepEnd::Unknown(format!("{error:#}")),
        Ok(None) => missing_result(host, &instance, started),
    })
}

/// Stop every host unit an earlier holder of `environment`'s fence left
/// running, and wait until they are gone while keeping `fence` fresh. Fails
/// closed when one is still running after [`STOP_GRACE`] or the fence is
/// lost.
pub(crate) async fn fence_environment(
    fence: &mut dyn MutationFence,
    host: &HostExecutor,
    environment: &str,
) -> Result<()> {
    // Only a current holder may stop units: a holder that lost its fence
    // would otherwise stop its replacement's step.
    fence.refresh().await?;
    let stale = host.stop_environment_units(environment).await?;
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
                "host units of {} from an earlier fence holder are still running: {}",
                environment,
                left.iter()
                    .map(|instance| crate::host_executor::unit_name(instance))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            _ = refresh.tick() => fence.refresh().await?,
        }
    }
}

/// How the unit's start ended, when it ended without the fence being lost.
struct Started {
    since_ms: i64,
    start_error: Option<String>,
    interrupted: Option<&'static str>,
}

/// Why a unit this process started is stopped.
enum Stop {
    Interrupted(&'static str),
    FenceLost(anyhow::Error),
}

/// Start the unit and wait until it ended, keeping the fence fresh. Losing
/// the fence or a SIGINT/SIGTERM stops the unit.
async fn start_and_wait(
    fence: &mut dyn MutationFence,
    host: &HostExecutor,
    instance: &str,
) -> Result<Started> {
    fence.refresh().await?;
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
                stop = Some(Stop::Interrupted("the process was interrupted"));
                break;
            }
            _ = terminate.recv() => {
                stop = Some(Stop::Interrupted("the process was terminated"));
                break;
            }
            _ = refresh.tick() => {
                if let Err(error) = fence.refresh().await {
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
    // job may reach it after the stop. A fence still held stays fresh.
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
                if let Err(error) = fence.refresh().await {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::host_executor::{HostUnits, UnitFuture};

    /// Units that report one running instance and count every stop.
    #[derive(Default)]
    struct CountingUnits {
        stops: AtomicUsize,
    }

    impl HostUnits for CountingUnits {
        fn start<'a>(&'a self, _instance: &'a str) -> UnitFuture<'a> {
            Box::pin(async { Ok(()) })
        }

        fn stop(&self, _instance: &str) -> Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn running(&self) -> UnitFuture<'_, Vec<String>> {
            Box::pin(async { Ok(vec!["a".repeat(64)]) })
        }
    }

    /// A fence its holder has lost.
    struct LostFence;

    impl MutationFence for LostFence {
        fn generation(&self) -> u64 {
            1
        }

        fn refresh(
            &mut self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async { bail!("claim was fenced") })
        }
    }

    /// A holder that lost its fence (a runtime whose claim expired while it
    /// prepared a release) must not stop the units of its replacement.
    #[tokio::test]
    async fn a_holder_that_lost_its_fence_stops_nothing() {
        let units = Arc::new(CountingUnits::default());
        let root = std::env::temp_dir().join(format!(
            "tenkai-host-fence-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let host = HostExecutor::new(root.join("spool"), root.join("state"), units.clone());
        // The running unit is the replacement's step in `edge`.
        let instance = "a".repeat(64);
        let dir = crate::host_apply::state::instance_dir(&root.join("state"), &instance);
        std::fs::create_dir_all(&dir).unwrap();
        let started = crate::host_apply::state::HostApplyStarted {
            schema: crate::host_apply::state::STARTED_SCHEMA.into(),
            instance: instance.clone(),
            plan_id: "plan".into(),
            plan_digest: format!("sha256:{}", "c".repeat(64)),
            step_id: "plan:step:0".into(),
            environment: "edge".into(),
            product: "cluster".into(),
            action: crate::host_apply::HostAction::Install,
            release: crate::host_apply::HostRelease {
                version: "1.0.0".into(),
                manifest_digest: "d".repeat(64),
            },
            generation: 1,
            started_at: 1,
            cgroup: None,
        };
        std::fs::write(
            dir.join(crate::host_apply::state::STARTED_FILE),
            serde_json::to_vec(&started).unwrap(),
        )
        .unwrap();
        // A current holder would stop it.
        let stale = host.stop_environment_units("edge").await.unwrap();
        assert_eq!(stale, [instance]);
        units.stops.store(0, Ordering::SeqCst);

        let error = fence_environment(&mut LostFence, &host, "edge")
            .await
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("claim was fenced"),
            "{error:#}"
        );
        assert_eq!(units.stops.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(root);
    }
}

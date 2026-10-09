//! Process shutdown signals shared by long-running hosts.

use std::future::Future;
use tokio::signal::unix::{SignalKind, signal};

/// Install SIGINT and SIGTERM listeners now; the returned future resolves with
/// the name of the first signal received.
///
/// Long-running hosts (`tenkai-server`, `tenkaictl reconcile`) call this before
/// their first tick, so a SIGTERM that arrives mid-deploy is never lost to the
/// deploy command's own short-lived listener: tokio delivers each signal to
/// every live listener.
pub fn listen() -> std::io::Result<impl Future<Output = &'static str>> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        }
    })
}

//! Runs in its own process: raising SIGTERM must not reach unrelated tests.

use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};

#[tokio::test]
async fn sigterm_shuts_down_after_a_deploy_handler_was_dropped() {
    // A deploy command registers and drops its own SIGTERM listener (#550).
    drop(signal(SignalKind::terminate()).unwrap());
    let waiting = tenkai::shutdown::listen().unwrap();
    unsafe {
        libc::raise(libc::SIGTERM);
    }
    let received = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("shutdown signal observed");
    assert_eq!(received, "SIGTERM");
}

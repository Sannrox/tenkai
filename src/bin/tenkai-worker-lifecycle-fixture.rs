//! Local acceptance host for `shikigami.worker_lifecycle` schema 1.
//!
//! This process publishes live observations and honors drain/stop control
//! files. It does not admit, claim, lease, or acknowledge individual work.

fn main() -> anyhow::Result<()> {
    tenkai::worker_pool::run_fixture_worker()
}

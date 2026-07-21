//! tenkai — local-first, constraint-based delivery control plane backed by sekai-chisei.
//!
//! sekai is the system of record: every product, release, channel, environment,
//! plan, and deployment is a typed object with links and audit history. chisei
//! is the gatekeeper: eval suites gate promotions before anything is applied.

pub mod apply;
pub mod canary;
pub mod catalog;
pub mod client;
pub mod manifest;
pub mod ontology;
pub mod pb;
pub mod plan;

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

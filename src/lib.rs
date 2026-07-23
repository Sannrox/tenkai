//! tenkai — local-first, constraint-based delivery control plane.
//!
//! Current v0 uses sekai as its operational store and chisei for eval gates. The
//! accepted standalone architecture in ADR 0001 moves authority to Tenkai-owned
//! persistence and makes sekai-chisei an operation-dependent integration.

pub mod apply;
pub mod canary;
pub mod catalog;
pub mod client;
pub mod embedded;
pub mod maintenance;
pub mod manifest;
pub mod ontology;
pub mod pb;
pub mod plan;
pub mod providers;
pub mod reconciler;
pub mod release_signing;
pub mod runtime_protocol;
pub mod server;
pub mod storage;

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

//! Generated gRPC bindings for Tenkai-owned contracts and the Sekai-Chisei wire types.
//!
//! Sekai and Chisei messages come from `sekai-proto` at the same git revision
//! Tenkai pins. Tenkai-owned graph-action and runtime v1 messages are generated
//! here from `proto/tenkai/`.

pub use sekai_proto::{chisei, sekai};

/// Tenkai-owned embedded graph-action definitions (not part of the Sekai wire
/// contract after sekai-chisei removed the legacy Actions DSL).
pub mod graph_action {
    tonic::include_proto!("tenkai.graph_action.v1");
}

/// Version 1 of the server/environment-runtime pull protocol.
pub mod runtime_v1 {
    pub const PROTOCOL_MAJOR: u32 = 1;
    pub const PROTOCOL_MINOR: u32 = 0;
    pub const SUPPORTED_PROTOCOL_MINORS: &[u32] = &[PROTOCOL_MINOR];

    tonic::include_proto!("tenkai.runtime.v1");
}

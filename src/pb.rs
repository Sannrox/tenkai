//! Generated gRPC bindings for the vendored sekai-chisei protos.
//!
//! The protos in `proto/vendor/` are copied verbatim from the sekai-chisei
//! repository at commit `67157d1fa242ac2f133c88243ef23b56f88042e6`; tenkai
//! is a pure client of that contract. Legacy graph ActionTypeDef RPCs were
//! removed on that revision; remote Tenkai uses the governed Action surface,
//! while embedded hosts keep Tenkai-local graph-action definitions.

pub mod sekai {
    tonic::include_proto!("sekai");
}

pub mod chisei {
    tonic::include_proto!("chisei");
}

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

//! Generated gRPC bindings for the vendored sekai-chisei protos.
//!
//! The protos in `proto/vendor/` are copied verbatim from the sekai-chisei
//! repository at commit `11d1787b331de8af3688aaba2655d107ef9a4ef1`; tenkai
//! is a pure client of that contract. The vendored Sekai proto includes the
//! authenticated graph-action compatibility RPC retained for this client.

pub mod sekai {
    tonic::include_proto!("sekai");
}

pub mod chisei {
    tonic::include_proto!("chisei");
}

/// Version 1 of the server/environment-runtime pull protocol.
pub mod runtime_v1 {
    pub const PROTOCOL_MAJOR: u32 = 1;
    pub const PROTOCOL_MINOR: u32 = 0;
    pub const SUPPORTED_PROTOCOL_MINORS: &[u32] = &[PROTOCOL_MINOR];

    tonic::include_proto!("tenkai.runtime.v1");
}

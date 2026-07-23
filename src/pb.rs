//! Generated gRPC bindings for the vendored sekai-chisei protos.
//!
//! The protos in `proto/vendor/` are copied verbatim from the sekai-chisei
//! repository; tenkai is a pure client of that contract.

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

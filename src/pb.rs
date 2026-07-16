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

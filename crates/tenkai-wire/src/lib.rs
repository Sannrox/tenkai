//! Generated bindings for Tenkai-owned contracts in `proto/tenkai/`.

/// Catalog records (`Object`, `Link`, `Lease`, `Decision`, ...). Field numbers
/// match the records earlier releases stored, so old payloads decode unchanged.
pub mod record {
    tonic::include_proto!("tenkai.record.v1");
}

/// Embedded graph-action definitions.
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

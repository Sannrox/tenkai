//! Authenticated network host for the shared Tenkai application core.

mod auth;
mod config;
mod inspect;
mod lifecycle;
mod package_migration;
mod remote_client;
mod remote_client_lifecycle;
mod router;
mod runtime;
#[cfg(test)]
mod tests;

pub use crate::runtime_delivery::{
    CompletionFuture, FleetStatusFuture, HealthFuture, InspectEnvFuture, InventoryFuture,
    ListEnvFuture, ReconcileFuture, ReconcilePort, RuntimeHeartbeat, RuntimeInventoryReport,
    RuntimeInventoryResponse, RuntimeWork, StatusEnvFuture, WorkFuture,
};
pub use config::{DevelopmentFixtureConfig, ServerConfig};
pub use remote_client::RemoteClient;
pub use router::router;

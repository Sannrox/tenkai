//! Authenticated network host for the shared Tenkai application core.

mod auth;
mod config;
pub mod contract;
mod inspect;
mod lifecycle;
mod opening;
mod package_migration;
mod remote_client;
mod remote_client_lifecycle;
mod router;
mod runtime;
#[cfg(test)]
mod tests;
pub mod ui;

pub use config::{DevelopmentFixtureConfig, ServerConfig};
pub use opening::{HotSwap, opening_router};
pub use remote_client::{RemoteClient, RemoteFailure};
pub use router::router;
pub use tenkai::runtime_delivery::{
    CompletionFuture, FleetStatusFuture, HealthFuture, InspectEnvFuture, InventoryFuture,
    ListEnvFuture, ReconcileFuture, ReconcilePort, RuntimeHeartbeat, RuntimeInventoryReport,
    RuntimeInventoryResponse, RuntimeWork, StatusEnvFuture, WorkFuture,
};

//! Tenkai is a local-first, constraint-based delivery control plane.
//!
//! The application core owns releases, channels, environments, plans, approvals,
//! execution, rollback, and recovery state. [`storage::OperationalStore`] is the
//! persistence seam shared by embedded and server hosts. Sekai-Chisei integrations
//! are derived, retryable providers unless an operation explicitly requires their
//! evidence; they are never the recovery path.
//!
//! The crate is organized around a small set of application seams:
//!
//! - [`catalog`] owns immutable release publication, promotion, and lookup.
//! - [`plan`], [`apply`], and [`reconciler`] own convergence decisions and execution.
//! - `apply::product_execution` hides product-kind dispatch, adapter setup,
//!   integrity and health ordering, and failed-activation cleanup policy behind
//!   the apply workflow's private execution seam.
//! - [`fleet`] owns pure fleet posture aggregation, drift comparison, and
//!   baseline I/O so callers do not re-encode inspect→posture classification.
//! - [`storage`] and [`tenant_store`] provide operational persistence adapters.
//! - [`software_executor`], [`model_runtime`], [`routing`], and [`staged_artifact`]
//!   adapt typed delivery products to their target runtimes.
//! - [`staged_artifact`] also owns the private kind→schema mapping for staged
//!   JSON products so apply/publish call sites do not re-encode that dispatch.
//! - [`atomic_state`] hides verified atomic local state-file mutation shared by
//!   those local executor adapters.
//! - [`providers`] and [`client`] contain optional Sekai-Chisei integration.
//! - `signature_verification` hides shared Ed25519 key and signature mechanics
//!   while each signed-format module retains its own domain validation.
//! - `terminal_outcome` classifies embedded and runtime execution evidence in
//!   one pure module before optional provider projection.
//! - [`embedded`] and [`server`] host the same application core; transport is not
//!   a domain seam.
//!
//! See ADR 0001 for the ownership and service-evolution rules.

pub mod apply;
pub mod assertion_verifier;
pub mod atomic_state;
pub mod auth_context;
pub mod canary;
pub mod catalog;
pub mod client;
pub mod command_result;
pub mod delivery_conformance;
pub mod dev_sign;
pub mod development_fixtures;
pub mod embedded;
pub mod federated_identity;
pub mod fleet;
pub mod inventory;
pub mod maintenance;
pub mod manifest;
pub mod metrics;
pub mod model_runtime;
pub mod offline_bundle;
pub mod ontology;
pub mod pb;
pub mod plan;
pub mod plan_approval;
pub mod plan_priors;
pub mod postgres_tenant;
pub mod providers;
pub mod reconcile_fence;
pub mod reconciler;
pub mod release_provenance;
pub mod release_signing;
pub mod routing;
pub mod runtime_agent;
pub mod runtime_capabilities;
pub mod runtime_protocol;
pub mod server;
mod signature_verification;
pub mod software_executor;
pub mod staged_artifact;
pub mod storage;
pub mod tenant_isolation;
pub mod tenant_store;
mod terminal_outcome;
pub mod wave;

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

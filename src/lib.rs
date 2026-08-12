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
//!   Its private publication module concentrates content identity, provenance,
//!   trust verification, immutable replay, persistence, and graph-link ordering
//!   behind one admission interface.
//! - [`plan`], [`apply`], and [`reconciler`] own convergence decisions and execution.
//! - `canary::attempt_lifecycle` hides Canary policy snapshots, promotion-lock
//!   coordination, attempt start and finalization ordering, durable outcome
//!   evidence, and crash repair behind execution and repair interfaces.
//! - `plan::release_selection` hides version constraints, Environment capability
//!   facts, model-runtime sibling discovery, rollout ceilings, and deterministic
//!   variant selection behind one private release-selection interface.
//! - `plan::lifecycle` hides immutable Plan encoding, lifecycle transition rules,
//!   audit preservation, indexed reads, fencing, ambiguous-write confirmation,
//!   and atomic Environment/provider-event persistence behind one private interface.
//! - `plan::convergence` hides desired-vs-deployed snapshotting, model/routing
//!   rollout order, immutable plan materialization, and rollback step
//!   construction behind one private planning interface.
//! - `apply::execution_attempt` hides Plan authorization mode, Environment lease
//!   admission, maintenance authorization, Canary finalization, lease release,
//!   and failure precedence behind one typed execution-attempt interface.
//! - `apply::execution_lease` hides Environment execution admission, generation
//!   fencing, legacy claim compatibility, takeover, inspection, and release
//!   behind one private ownership interface shared by execution callers.
//! - `apply::start_admission` hides evaluation-evidence validation, maintenance
//!   authorization and timing races, emergency-override recording, and durable
//!   blocked/running Plan transitions behind one private start interface.
//! - `apply::plan_completion` hides Step outcome classification, terminal Plan
//!   state selection, execution-error persistence precedence, and ambiguous
//!   durable transition confirmation behind one private completion interface.
//! - `apply::outcome` owns the closed Step outcome vocabulary, stable serialized
//!   spellings, fail-closed persistence admission, and caller-facing lifecycle
//!   classification behind the public Outcome interface.
//! - `apply::product_execution` hides product-kind dispatch, adapter setup,
//!   integrity and health ordering, and failed-activation cleanup policy behind
//!   the apply workflow's private execution seam.
//! - `apply::step_lifecycle` hides target and restore admission, rollback cleanup,
//!   activation recovery, Environment observation, and bookkeeping compensation
//!   behind one private Plan Step execution interface.
//! - [`fleet`] owns pure fleet posture aggregation, drift comparison, and
//!   baseline I/O so callers do not re-encode inspect→posture classification.
//! - [`storage`] and [`tenant_store`] provide operational persistence adapters.
//! - [`environment`] owns Environment identity, subscriptions, constraints,
//!   facts, deployment observations, and operator readback behind one interface.
//! - [`tenant_environment`] hides authenticated tenant Environment visibility,
//!   synchronous store adaptation, fixture projections, bounded reconciliation,
//!   and non-disclosing failures behind one application interface.
//! - [`runtime_delivery`] owns environment-runtime admission, work claims,
//!   completion validation and ordering, durable Plan and Deployment effects,
//!   heartbeat renewal, and inventory admission behind one interface.
//! - [`software_executor`], [`model_runtime`], [`routing`], and [`staged_artifact`]
//!   adapt typed delivery products to their target runtimes.
//! - `product_kind` owns the closed Product-kind policy for manifest target
//!   classification, staged identity, cleanup semantics, and coordinated
//!   model/routing rollout rank without introducing a trait seam.
//! - [`staged_artifact`] also owns the private kind→schema mapping for staged
//!   JSON products so apply/publish call sites do not re-encode that dispatch.
//! - [`atomic_state`] hides verified atomic local state-file mutation shared by
//!   those local executor adapters.
//! - [`providers`] and [`client`] contain optional Sekai-Chisei integration.
//!   The client's private object-lifecycle module hides embedded/remote adapter
//!   selection, RPC paths, not-found mapping, conflict recovery, and upsert
//!   selection behind the shared `Ctx` object interface.
//!   Its private relation-lifecycle module likewise hides deterministic link
//!   identity, duplicate normalization, direction semantics, and deletion
//!   across embedded and remote adapters.
//!   Its private lease-lifecycle module hides acquire/get/refresh/release/
//!   takeover fencing, request-id binding, and not-found mapping behind the
//!   shared `Ctx` lease interface.
//!   Its private action-lifecycle module hides action-type registration,
//!   execute/preview, deferred deny, conflict recovery, and decision listing
//!   behind the shared `Ctx` governed-action interface.
//! - [`provider_event`] hides durable optional-provider event admission,
//!   claiming, fencing, sequencing, retry, poison isolation, and
//!   acknowledgement behind one delivery interface; authoritative store
//!   adapters retain transactional enqueue ownership.
//! - `signature_verification` hides shared signed-format framing, digest
//!   grammar, key-id derivation, and Ed25519 verification while each domain
//!   module retains its own statement shape and policy rules. Enterprise JWT
//!   assertion verification also uses this seam for public-key decode and
//!   strict signature checks.
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
pub mod environment;
pub mod federated_identity;
pub mod fenced_mutation;
pub mod fleet;
pub mod inventory;
pub mod maintenance;
mod management_operations;
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
mod product_kind;
pub mod provider_event;
pub mod providers;
pub mod reconcile_fence;
pub mod reconciler;
pub mod release_provenance;
pub mod release_signing;
pub mod routing;
pub mod runtime_agent;
pub mod runtime_capabilities;
pub mod runtime_delivery;
pub mod runtime_protocol;
pub mod server;
mod signature_verification;
pub mod software_executor;
pub mod staged_artifact;
pub mod storage;
pub mod tenant_environment;
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

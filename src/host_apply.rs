//! Privileged host releases: the contract between the unprivileged server and
//! the root-side `tenkai-host-applier` (ADR 0041 §2).
//!
//! The server writes a [`HostApplyRequest`] and the release workdir into a
//! spool directory it owns, under the name [`instance_key`] derives, and
//! starts `tenkai-host-apply@<instance>.service`. The applier copies the
//! request into root-owned storage and calls [`verify_request`] on the copy:
//! the release signature against root-owned trust roots (revocation and
//! signer windows included), `executor = "host"`, the plan digest and step,
//! and the approvals against the root-owned [`HostApprovalPolicy`]. Only then
//! does it copy the release workdir and check every artifact digest
//! ([`VerifiedHostStep::verify_artifacts`]). Only a verified step reaches the
//! applied-state critical section ([`state::AppliedStateRecord::admit`]) and
//! its command.

mod policy;
mod request;
pub mod sealed;
pub mod state;
mod verify;

#[cfg(any(test, feature = "test-support"))]
pub mod fixture;
#[cfg(test)]
mod tests;

pub use crate::plan::{HostAction, HostStep};
pub use policy::{HostApprovalPolicy, HostApprovals, plan_purposes};
pub use request::{
    ARTIFACTS_DIR, HostApplyRequest, MAX_REQUEST_BYTES, REQUEST_FILE, REQUEST_SCHEMA, instance_key,
    product_key, validate_instance_name,
};
pub use verify::{HostRelease, HostTrust, VerifiedHostStep, verify_copied_request, verify_request};

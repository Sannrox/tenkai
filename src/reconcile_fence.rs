//! Multi-host reconcile tick fencing (ADR 0009 / #129).
//!
//! Local `SchedulerState` only serializes environments inside one process.
//! When multiple control-plane hosts share operational state, each environment
//! tick must also acquire a generation-fenced claim so at most one host mutates
//! that environment at a time.
//!
//! First delivery: process-shared [`SharedReconcileFence`] (deterministic tests
//! and single-host multi-reconciler). Durable store-backed claims can plug the
//! same [`ReconcileTickFence`] port later.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result of attempting to begin a reconcile tick for one environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceAdmission {
    /// This host holds generation `generation` until release or expiry.
    Started { generation: u64 },
    /// Another host holds a live claim.
    Busy { owner: String },
    /// Claim rejected (stale generation on release, etc.).
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileTickClaim {
    pub environment: String,
    pub owner: String,
    pub generation: u64,
    pub expires_at: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FenceError {
    #[error("reconcile fence mutex poisoned")]
    Poisoned,
    #[error("reconcile fence owner or environment must not be empty")]
    InvalidIdentity,
    #[error("reconcile fence expiry must be in the future")]
    InvalidExpiry,
}

/// Port for inter-host (or multi-reconciler) tick fencing.
pub trait ReconcileTickFence: Send + Sync {
    fn try_begin(
        &self,
        environment: &str,
        owner: &str,
        now: i64,
        ttl_ms: i64,
    ) -> Result<FenceAdmission, FenceError>;

    fn release(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        now: i64,
    ) -> Result<(), FenceError>;
}

#[derive(Debug, Clone)]
struct LiveClaim {
    owner: String,
    generation: u64,
    expires_at: i64,
}

/// Process-shared fence: multiple [`crate::reconciler::Reconciler`] instances
/// in the same process (or test) coordinate via one `Arc`.
#[derive(Debug, Default)]
pub struct SharedReconcileFence {
    claims: Mutex<HashMap<String, LiveClaim>>,
}

impl SharedReconcileFence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl ReconcileTickFence for SharedReconcileFence {
    fn try_begin(
        &self,
        environment: &str,
        owner: &str,
        now: i64,
        ttl_ms: i64,
    ) -> Result<FenceAdmission, FenceError> {
        if environment.trim().is_empty() || owner.trim().is_empty() {
            return Err(FenceError::InvalidIdentity);
        }
        if ttl_ms <= 0 {
            return Err(FenceError::InvalidExpiry);
        }
        let expires_at = now.saturating_add(ttl_ms);
        let mut claims = self.claims.lock().map_err(|_| FenceError::Poisoned)?;
        let admission = match claims.get(environment) {
            Some(claim) if claim.expires_at > now && claim.owner != owner => {
                FenceAdmission::Busy {
                    owner: claim.owner.clone(),
                }
            }
            Some(claim) if claim.expires_at > now && claim.owner == owner => {
                // Renew for same owner.
                let generation = claim.generation;
                claims.insert(
                    environment.into(),
                    LiveClaim {
                        owner: owner.into(),
                        generation,
                        expires_at,
                    },
                );
                FenceAdmission::Started { generation }
            }
            Some(claim) => {
                let generation = claim.generation.saturating_add(1);
                claims.insert(
                    environment.into(),
                    LiveClaim {
                        owner: owner.into(),
                        generation,
                        expires_at,
                    },
                );
                FenceAdmission::Started { generation }
            }
            None => {
                claims.insert(
                    environment.into(),
                    LiveClaim {
                        owner: owner.into(),
                        generation: 1,
                        expires_at,
                    },
                );
                FenceAdmission::Started { generation: 1 }
            }
        };
        Ok(admission)
    }

    fn release(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        now: i64,
    ) -> Result<(), FenceError> {
        let mut claims = self.claims.lock().map_err(|_| FenceError::Poisoned)?;
        match claims.get(environment) {
            Some(claim) if claim.owner == owner && claim.generation == generation => {
                claims.remove(environment);
                Ok(())
            }
            Some(claim) if claim.expires_at <= now => {
                claims.remove(environment);
                Ok(())
            }
            // Stale release must not steal another host's claim.
            Some(_) | None => Ok(()),
        }
    }
}

/// Guard that releases the shared fence when dropped.
pub struct FenceGuard {
    fence: Arc<dyn ReconcileTickFence>,
    environment: String,
    owner: String,
    generation: u64,
    released: bool,
}

impl FenceGuard {
    pub fn new(
        fence: Arc<dyn ReconcileTickFence>,
        environment: String,
        owner: String,
        generation: u64,
    ) -> Self {
        Self {
            fence,
            environment,
            owner,
            generation,
            released: false,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn release_now(mut self, now: i64) {
        let _ = self
            .fence
            .release(&self.environment, &self.owner, self.generation, now);
        self.released = true;
    }
}

impl Drop for FenceGuard {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.fence.release(
                &self.environment,
                &self.owner,
                self.generation,
                crate::now_millis(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_owner_wins_live_claim() {
        let fence = SharedReconcileFence::new();
        let a = fence.try_begin("prod", "host-a", 1_000, 5_000).unwrap();
        assert!(matches!(a, FenceAdmission::Started { generation: 1 }));
        let b = fence.try_begin("prod", "host-b", 1_100, 5_000).unwrap();
        assert!(matches!(b, FenceAdmission::Busy { .. }));
        fence.release("prod", "host-a", 1, 1_200).unwrap();
        let c = fence.try_begin("prod", "host-b", 1_300, 5_000).unwrap();
        // After release the claim is gone; next owner starts at generation 1.
        assert!(matches!(c, FenceAdmission::Started { generation: 1 }));
    }

    #[test]
    fn expired_claim_can_be_taken_over() {
        let fence = SharedReconcileFence::new();
        assert!(matches!(
            fence.try_begin("stage", "host-a", 1_000, 100).unwrap(),
            FenceAdmission::Started { generation: 1 }
        ));
        // After expiry, host-b takes over with bumped generation.
        let next = fence.try_begin("stage", "host-b", 1_200, 5_000).unwrap();
        assert_eq!(next, FenceAdmission::Started { generation: 2 });
    }

    #[test]
    fn same_owner_renews_without_bumping_generation() {
        let fence = SharedReconcileFence::new();
        assert_eq!(
            fence.try_begin("dev", "host-a", 1_000, 5_000).unwrap(),
            FenceAdmission::Started { generation: 1 }
        );
        assert_eq!(
            fence.try_begin("dev", "host-a", 1_500, 5_000).unwrap(),
            FenceAdmission::Started { generation: 1 }
        );
    }
}

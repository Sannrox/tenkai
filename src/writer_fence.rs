//! The active hub writer (#748, ADR 0009).
//!
//! Replicas of a tenant-mode hub contend for one PostgreSQL-held writer
//! lease with a generation that only grows. The replica holding it is the
//! leader and may write; every other replica is a standby. A [`WriterFence`]
//! is this process's view of its role: the store refuses authoritative
//! writes unless the role is leader, and each write also checks, inside its
//! own transaction, that the lease still names this holder and generation,
//! so a writer whose lease lapsed or was taken over cannot commit.
//!
//! A single-replica hub has no fence and writes as before.

use std::sync::RwLock;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterRole {
    /// This process holds the lease at `generation`.
    Leader { holder: String, generation: u64 },
    /// Another replica holds the lease, or this one could not confirm it.
    Standby,
}

/// This process's writer role, shared by the store, readiness and workers.
///
/// A leader role carries a local deadline no later than the lease's own
/// expiry. Past it the role reads as standby, so a replica whose renewal
/// stalls stops claiming to lead even before the renewal returns.
#[derive(Debug)]
pub struct WriterFence {
    role: RwLock<(WriterRole, Option<Instant>)>,
}

impl Default for WriterFence {
    /// Starts as standby: nothing is written before the lease is acquired.
    fn default() -> Self {
        Self {
            role: RwLock::new((WriterRole::Standby, None)),
        }
    }
}

impl WriterFence {
    pub fn role(&self) -> WriterRole {
        match self.role.read() {
            Ok(current) => match current.1 {
                Some(deadline) if Instant::now() >= deadline => WriterRole::Standby,
                _ => current.0.clone(),
            },
            // A poisoned lock fails closed.
            Err(_) => WriterRole::Standby,
        }
    }

    /// Sets the role with no deadline: a standby, or a leader in tests.
    pub fn set(&self, role: WriterRole) {
        self.store(role, None);
    }

    /// Sets the role, read as standby from `deadline` on. A lease renewal
    /// passes the time it was requested plus the lease's lifetime, which is
    /// no later than the expiry the database records.
    pub fn set_until(&self, role: WriterRole, deadline: Instant) {
        self.store(role, Some(deadline));
    }

    fn store(&self, role: WriterRole, deadline: Option<Instant>) {
        if let Ok(mut current) = self.role.write() {
            *current = (role, deadline);
        }
    }

    pub fn is_leader(&self) -> bool {
        matches!(self.role(), WriterRole::Leader { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leader_past_its_deadline_reads_as_standby() {
        let fence = WriterFence::default();
        assert!(!fence.is_leader(), "starts as standby");
        let leader = WriterRole::Leader {
            holder: "hub-a".into(),
            generation: 3,
        };
        fence.set_until(
            leader.clone(),
            Instant::now() + std::time::Duration::from_secs(60),
        );
        assert_eq!(fence.role(), leader);
        fence.set_until(leader, Instant::now());
        assert_eq!(fence.role(), WriterRole::Standby);
    }
}

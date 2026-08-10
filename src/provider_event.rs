//! Durable optional-provider event persistence seam.
//!
//! The lifecycle is deliberately separate from the rest of operational
//! persistence: claiming, fencing, sequence allocation, retry, and delivery
//! acknowledgement form one contract implemented by both authoritative store
//! adapters. Enqueue remains available inside each adapter's authoritative
//! transaction; this module does not introduce a second store or transaction.

use crate::storage::{ProviderEventRecord, Result};

/// Persistence interface for one durable provider-event lifecycle.
pub trait ProviderEventStore: Send + Sync {
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()>;

    /// Read-only, bounded inspection. Callers must project and redact payloads
    /// before returning them to an operator.
    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>>;

    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>>;

    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>>;

    /// Reserve a producer sequence under the event's claim fence.
    fn reserve_provider_event_sequence(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> Result<i64>;

    /// Bind first-delivery metadata into the durable event envelope.
    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()>;

    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()>;

    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()>;
}

impl<T> ProviderEventStore for T
where
    T: crate::storage::OperationalStore + ?Sized,
{
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()> {
        crate::storage::OperationalStore::enqueue_provider_event(self, event)
    }

    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        crate::storage::OperationalStore::list_provider_events(
            self,
            provider_kind,
            environment_id,
            limit,
        )
    }

    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        crate::storage::OperationalStore::claim_provider_events(
            self,
            now,
            limit,
            claim_token,
            claim_until,
        )
    }

    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        crate::storage::OperationalStore::claim_provider_events_for_kind(
            self,
            provider_kind,
            now,
            limit,
            claim_token,
            claim_until,
        )
    }

    fn reserve_provider_event_sequence(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> Result<i64> {
        crate::storage::OperationalStore::reserve_provider_event_sequence(
            self,
            provider_kind,
            id,
            claim_token,
        )
    }

    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()> {
        crate::storage::OperationalStore::bind_provider_event_collection_time(
            self,
            provider_kind,
            id,
            claim_token,
            payload_json,
        )
    }

    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> Result<()> {
        crate::storage::OperationalStore::record_provider_failure(
            self,
            provider_kind,
            id,
            claim_token,
            next_attempt_at,
            error,
        )
    }

    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        crate::storage::OperationalStore::mark_provider_event_delivered(
            self,
            provider_kind,
            id,
            claim_token,
            delivered_at,
        )
    }
}

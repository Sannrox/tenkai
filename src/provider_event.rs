//! Durable optional-provider event lifecycle.
//!
//! This module concentrates event admission, claim fencing, first-delivery
//! metadata, retry scheduling, poison-event isolation, and acknowledgement.
//! The authoritative operational store remains the internal persistence seam;
//! enqueue can still participate in a larger store transaction.

use std::future::Future;
use std::time::Duration;

use crate::providers::{OUTCOME_PROVIDER_KIND, OutcomeProvider, ProviderError, ProviderEvent};
use crate::storage::{ProviderEventRecord, Result as StoreResult};

/// Public persistence seam retained for custom provider-event adapters.
/// Lifecycle ordering belongs to this module; adapters only supply atomic
/// storage primitives.
pub trait ProviderEventStore: Send + Sync {
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> StoreResult<()>;
    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<ProviderEventRecord>>;
    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> StoreResult<Vec<ProviderEventRecord>>;
    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> StoreResult<Vec<ProviderEventRecord>>;
    fn reserve_provider_event_sequence(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> StoreResult<i64>;
    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> StoreResult<()>;
    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> StoreResult<()>;
    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> StoreResult<()>;
}

impl<T> ProviderEventStore for T
where
    T: crate::storage::OperationalStore + ?Sized,
{
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> StoreResult<()> {
        crate::storage::OperationalStore::enqueue_provider_event(self, event)
    }

    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<ProviderEventRecord>> {
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
    ) -> StoreResult<Vec<ProviderEventRecord>> {
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
    ) -> StoreResult<Vec<ProviderEventRecord>> {
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
    ) -> StoreResult<i64> {
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
    ) -> StoreResult<()> {
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
    ) -> StoreResult<()> {
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
    ) -> StoreResult<()> {
        crate::storage::OperationalStore::mark_provider_event_delivered(
            self,
            provider_kind,
            id,
            claim_token,
            delivered_at,
        )
    }
}

pub fn enqueue_optional_event(
    store: &impl ProviderEventStore,
    kind: &str,
    event: &ProviderEvent,
    now: i64,
) -> Result<(), ProviderError> {
    store.enqueue_provider_event(&provider_event_record(kind, event, now)?)?;
    Ok(())
}

pub fn provider_event_record(
    kind: &str,
    event: &ProviderEvent,
    now: i64,
) -> Result<ProviderEventRecord, ProviderError> {
    event.validate()?;
    if event.collected_at_ms.is_some() || event.source_sequence.is_some() {
        return Err(ProviderError::InvalidEvidence(
            "new provider events must not carry delivery metadata".into(),
        ));
    }
    if kind.trim().is_empty() || kind.len() > 64 {
        return Err(ProviderError::InvalidEvidence(
            "provider event kind is empty or oversized".into(),
        ));
    }
    Ok(ProviderEventRecord {
        id: event.id.clone(),
        provider_kind: kind.into(),
        binding_digest: event.binding.digest(),
        payload_json: serde_json::to_string(event)?,
        attempts: 0,
        next_attempt_at: now,
        delivered_at: None,
        last_error: String::new(),
        claim_token: None,
        claim_until: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Delivered,
    Deferred,
}

/// Deliver one claimed event and durably complete its lifecycle transition.
///
/// The stable event ID is the adapter's idempotency key. Invalid durable
/// envelopes are isolated and retried without reaching the adapter.
pub async fn deliver_optional_event<S, F, Fut>(
    store: &S,
    record: &ProviderEventRecord,
    timeout: Duration,
    now: i64,
    delivery: F,
) -> Result<DeliveryStatus, ProviderError>
where
    S: ProviderEventStore + ?Sized,
    F: FnOnce(ProviderEvent, String) -> Fut,
    Fut: Future<Output = Result<(), ProviderError>>,
{
    let claim_token = record.claim_token.as_deref().ok_or_else(|| {
        ProviderError::InvalidEvidence("durable event is not claimed for delivery".into())
    })?;
    let parsed = serde_json::from_str::<ProviderEvent>(&record.payload_json)
        .map_err(ProviderError::from)
        .and_then(|event| {
            event.validate()?;
            if event.binding.digest() != record.binding_digest || event.id != record.id {
                return Err(ProviderError::InvalidEvidence(
                    "durable event binding or identity does not match its envelope".into(),
                ));
            }
            Ok(event)
        });
    let mut event = match parsed {
        Ok(event) => event,
        Err(error) => {
            defer(store, record, claim_token, now, 60_000, &error.to_string())?;
            return Ok(DeliveryStatus::Deferred);
        }
    };
    bind_first_delivery_metadata(store, record, claim_token, &mut event, now)?;

    let result = tokio::time::timeout(timeout, delivery(event, record.provider_kind.clone())).await;
    match result {
        Ok(Ok(())) => {
            store.mark_provider_event_delivered(
                &record.provider_kind,
                &record.id,
                claim_token,
                now,
            )?;
            Ok(DeliveryStatus::Delivered)
        }
        Ok(Err(error)) => {
            defer_after_delivery_failure(store, record, claim_token, now, &error.to_string())?;
            Ok(DeliveryStatus::Deferred)
        }
        Err(_) => {
            defer_after_delivery_failure(
                store,
                record,
                claim_token,
                now,
                &ProviderError::Timeout(timeout).to_string(),
            )?;
            Ok(DeliveryStatus::Deferred)
        }
    }
}

pub async fn deliver_outcome_batch<S, P>(
    store: &S,
    provider: &P,
    timeout: Duration,
    now: i64,
    limit: usize,
) -> Result<(usize, usize), ProviderError>
where
    S: ProviderEventStore + ?Sized,
    P: OutcomeProvider + ?Sized,
{
    let claim_token = format!("outcome-worker:{}", uuid::Uuid::new_v4());
    let claim_until = now.saturating_add(
        i64::try_from(timeout.saturating_mul(limit.max(1) as u32).as_millis())
            .unwrap_or(i64::MAX)
            .saturating_add(30_000),
    );
    let records = store.claim_provider_events_for_kind(
        OUTCOME_PROVIDER_KIND,
        now,
        limit,
        &claim_token,
        claim_until,
    )?;
    let mut delivered = 0;
    let mut deferred = 0;
    for record in &records {
        match deliver_optional_event(store, record, timeout, now, |event, kind| async move {
            if kind != OUTCOME_PROVIDER_KIND {
                return Err(ProviderError::InvalidEvidence(
                    "outcome worker claimed a different provider destination".into(),
                ));
            }
            provider.record(&event).await
        })
        .await?
        {
            DeliveryStatus::Delivered => delivered += 1,
            DeliveryStatus::Deferred => deferred += 1,
        }
    }
    Ok((delivered, deferred))
}

fn bind_first_delivery_metadata(
    store: &(impl ProviderEventStore + ?Sized),
    record: &ProviderEventRecord,
    claim_token: &str,
    event: &mut ProviderEvent,
    now: i64,
) -> Result<(), ProviderError> {
    if event.collected_at_ms.is_some() && event.source_sequence.is_some() {
        return Ok(());
    }
    if event.collected_at_ms.is_none() && now <= 0 {
        return Err(ProviderError::InvalidEvidence(
            "provider delivery timestamp must be positive".into(),
        ));
    }
    if event.source_sequence.is_none() {
        event.source_sequence = Some(store.reserve_provider_event_sequence(
            &record.provider_kind,
            &record.id,
            claim_token,
        )?);
    }
    if event.collected_at_ms.is_none() {
        event.collected_at_ms = Some(now);
    }
    store.bind_provider_event_collection_time(
        &record.provider_kind,
        &record.id,
        claim_token,
        &serde_json::to_string(event)?,
    )?;
    Ok(())
}

fn defer_after_delivery_failure(
    store: &(impl ProviderEventStore + ?Sized),
    record: &ProviderEventRecord,
    claim_token: &str,
    now: i64,
    error: &str,
) -> Result<(), ProviderError> {
    let delay_seconds = 1_i64 << record.attempts.min(10);
    defer(
        store,
        record,
        claim_token,
        now,
        delay_seconds * 1_000,
        error,
    )
}

fn defer(
    store: &(impl ProviderEventStore + ?Sized),
    record: &ProviderEventRecord,
    claim_token: &str,
    now: i64,
    delay_ms: i64,
    error: &str,
) -> Result<(), ProviderError> {
    store.record_provider_failure(
        &record.provider_kind,
        &record.id,
        claim_token,
        now.saturating_add(delay_ms),
        error,
    )?;
    Ok(())
}

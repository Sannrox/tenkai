use super::*;

/// Transactional authority used by embedded and server hosts.
pub trait OperationalStore: Send + Sync {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()>;
    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>>;
    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord>;
    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord>;
    fn create_plan(&self, plan: &PlanRecord) -> Result<()>;
    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>>;
    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord>;
    fn acquire_lease(&self, environment: &str, owner: &str, expires_at: i64)
    -> Result<LeaseRecord>;
    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>>;
    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()>;
    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>>;
    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()>;
    fn get_offline_import(&self, bundle_digest: &str) -> Result<Option<OfflineImportRecord>>;
    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()>;
    fn transition_rollback(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord>;
    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>>;
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()>;
    /// Read-only, bounded inspection of durable provider events. The caller
    /// must project and redact payloads before returning them to an operator.
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
    /// Bind the first delivery timestamp into the durable event envelope.
    /// The claim token fences this write so retries retain the same timestamp.
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
    fn append_audit(&self, event: &AuditRecord) -> Result<()>;
    fn audit_events(&self) -> Result<Vec<AuditRecord>>;
    /// Audit records after insertion `cursor` (exclusive), in insertion order,
    /// at most `limit`, each with its cursor. Insertion order, not time, is
    /// what a reader can resume from without missing a late commit.
    fn audit_events_after(&self, _cursor: i64, _limit: usize) -> Result<Vec<(i64, AuditRecord)>> {
        Err(StoreError::AdapterUnavailable(
            "ordered audit reads are not implemented by this store".into(),
        ))
    }
    /// Append a typed change event and return it with the assigned cursor.
    fn append_change_event(
        &self,
        occurred_at: i64,
        kind: &str,
        resource: &str,
        environment_id: &str,
    ) -> Result<crate::change_stream::ChangeEvent>;
    /// Append a host-scoped change event unless the latest event of `kind`
    /// already names `resource` and occurred at or after `since`, or, with
    /// `only_after_another`, unless some event of `kind` exists already.
    /// Check and append are one fenced transaction, so writers that race,
    /// restart or take over append once. `None` when nothing was appended
    /// (#784).
    fn append_change_event_once(
        &self,
        occurred_at: i64,
        kind: crate::change_stream::ChangeEventKind,
        resource: &str,
        since: i64,
        only_after_another: bool,
    ) -> Result<Option<crate::change_stream::ChangeEvent>>;
    /// Events after `cursor` (exclusive), oldest first, at most `limit` rows.
    fn list_change_events_after(
        &self,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<crate::change_stream::ChangeEvent>>;
    fn check_health(&self) -> Result<()>;
    fn import_development_fixture(
        &self,
        _fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        _actor: &str,
        _request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        Err(StoreError::AdapterUnavailable(
            "development fixture import is not implemented by this store".into(),
        ))
    }
    fn reset_development_fixture(
        &self,
        _fixture_id: &str,
        _actor: &str,
        _request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        Err(StoreError::AdapterUnavailable(
            "development fixture reset is not implemented by this store".into(),
        ))
    }
    fn development_fixture_environment(
        &self,
        _environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        Ok(None)
    }
    /// Versioned runtime capabilities this store implementation provides.
    fn runtime_capabilities(&self) -> crate::runtime_capabilities::ComponentCapabilities;
    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>>;
    /// `owner`'s claim on `plan_id` when it already holds a durable
    /// completion. Read-only: nothing about the lease changes.
    fn durable_runtime_completion(
        &self,
        _plan_id: &str,
        _owner: &str,
    ) -> Result<Option<RuntimeClaim>> {
        Err(StoreError::AdapterUnavailable(
            "durable completion lookup is not implemented by this store".into(),
        ))
    }
    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>>;
    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()>;
    /// The durable completion of `plan_id` in `environment` whose claim has
    /// lapsed: its runtime stopped, or was revoked, before the server applied
    /// it (#630). The server applies it then; it is validated and idempotent.
    fn lapsed_runtime_completion(
        &self,
        _environment: &str,
        _plan_id: &str,
        _now: i64,
    ) -> Result<Option<String>> {
        Ok(None)
    }
    /// Record a single-use runtime enrollment (#630).
    fn create_runtime_enrollment(&self, _enrollment: &RuntimeEnrollmentRecord) -> Result<()> {
        Err(StoreError::AdapterUnavailable(
            "runtime enrollment is not implemented by this store".into(),
        ))
    }
    /// Spend the enrollment `token_digest` of `environment` once, before it
    /// expires at `now`,
    /// and record `credential_digest` as its credential, in one transaction:
    /// of two concurrent redemptions, one wins. Unknown, spent and expired
    /// enrollments are all `InvalidData`.
    fn redeem_runtime_enrollment(
        &self,
        _environment: &str,
        _token_digest: &str,
        _credential_digest: &str,
        _now: i64,
    ) -> Result<RuntimeCredentialRecord> {
        Err(StoreError::AdapterUnavailable(
            "runtime enrollment is not implemented by this store".into(),
        ))
    }
    fn runtime_credential(
        &self,
        _credential_digest: &str,
    ) -> Result<Option<RuntimeCredentialRecord>> {
        Err(StoreError::AdapterUnavailable(
            "runtime credentials are not implemented by this store".into(),
        ))
    }
    /// Revoke a runtime credential from `now` on, recording `revocation`;
    /// revoking again keeps the first time and reason. Unknown credentials
    /// are `NotFound`.
    fn revoke_runtime_credential(
        &self,
        _credential_digest: &str,
        _now: i64,
        _revocation: &RuntimeRevocation,
    ) -> Result<()> {
        Err(StoreError::AdapterUnavailable(
            "runtime credentials are not implemented by this store".into(),
        ))
    }
    /// Every enrolled runtime credential, revoked or not (#673).
    fn runtime_runners(&self) -> Result<Vec<RuntimeRunnerRecord>> {
        Err(StoreError::AdapterUnavailable(
            "the runner registry is not implemented by this store".into(),
        ))
    }
    /// Merge one instance's activity: set timestamps advance, a missing
    /// version keeps the recorded one (#673).
    fn record_runtime_activity(&self, _activity: &RuntimeActivityRecord) -> Result<()> {
        Err(StoreError::AdapterUnavailable(
            "the runner registry is not implemented by this store".into(),
        ))
    }
    fn runtime_activity(&self) -> Result<Vec<RuntimeActivityRecord>> {
        Err(StoreError::AdapterUnavailable(
            "the runner registry is not implemented by this store".into(),
        ))
    }
    /// Owners holding an unexpired runtime plan claim at `now`.
    fn live_runtime_claim_owners(&self, _now: i64) -> Result<Vec<String>> {
        Err(StoreError::AdapterUnavailable(
            "the runner registry is not implemented by this store".into(),
        ))
    }
}

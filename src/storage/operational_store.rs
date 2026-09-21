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
}

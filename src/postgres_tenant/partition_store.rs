use crate::runtime_capabilities::ComponentCapabilities;
use crate::storage::{
    AuditRecord, ChannelRecord, EnvironmentRecord, LeaseRecord, OfflineImportRecord,
    OfflineStepImportRecord, OperationalStore, PlanRecord, PlanStatus, ProviderEventRecord,
    ReceiptRecord, ReleaseRecord, Result, RollbackRecord, RollbackStatus, RuntimeClaim,
};

use super::PostgresTenantPartition;
use super::tenant_postgres_store_capabilities;

#[cfg(feature = "postgres")]
impl OperationalStore for PostgresTenantPartition {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()> {
        self.inner.publish_release(&self.schema, release)
    }
    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>> {
        self.inner.get_release(&self.schema, id)
    }
    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        self.inner.promote_channel(&self.schema, channel)
    }
    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord> {
        self.inner.put_environment(&self.schema, environment)
    }
    fn create_plan(&self, plan: &PlanRecord) -> Result<()> {
        self.inner.create_plan(&self.schema, plan)
    }
    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>> {
        self.inner.get_plan(&self.schema, id)
    }
    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        self.inner
            .transition_plan(&self.schema, id, owner, generation, status, detail)
    }
    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        self.inner
            .acquire_lease(&self.schema, environment, owner, expires_at)
    }
    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>> {
        self.inner.current_lease(&self.schema, environment)
    }
    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        self.inner.record_receipt(&self.schema, owner, receipt)
    }
    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>> {
        self.inner.get_receipt(&self.schema, id)
    }
    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        self.inner
            .record_offline_import(&self.schema, receipt, steps)
    }
    fn get_offline_import(&self, bundle_digest: &str) -> Result<Option<OfflineImportRecord>> {
        self.inner.get_offline_import(&self.schema, bundle_digest)
    }
    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()> {
        self.inner.create_rollback(&self.schema, owner, rollback)
    }
    fn transition_rollback(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> Result<RollbackRecord> {
        self.inner.transition_rollback(
            &self.schema,
            id,
            owner,
            generation,
            status,
            checkpoint_json,
            detail,
        )
    }
    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>> {
        self.inner.pending_rollbacks(&self.schema)
    }
    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()> {
        self.inner.enqueue_provider_event(&self.schema, event)
    }
    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.inner
            .list_provider_events(&self.schema, provider_kind, environment_id, limit)
    }
    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.inner
            .claim_provider_events(&self.schema, now, limit, claim_token, claim_until)
    }
    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.inner.claim_provider_events_for_kind(
            &self.schema,
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
        self.inner
            .reserve_provider_event_sequence(&self.schema, provider_kind, id, claim_token)
    }
    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()> {
        self.inner.bind_provider_event_collection_time(
            &self.schema,
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
        self.inner.record_provider_failure(
            &self.schema,
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
        self.inner.mark_provider_event_delivered(
            &self.schema,
            provider_kind,
            id,
            claim_token,
            delivered_at,
        )
    }
    fn append_audit(&self, event: &AuditRecord) -> Result<()> {
        self.inner.append_audit(&self.schema, event)
    }
    fn audit_events(&self) -> Result<Vec<AuditRecord>> {
        self.inner.audit_events(&self.schema)
    }
    fn check_health(&self) -> Result<()> {
        self.inner.check_health()
    }
    fn import_development_fixture(
        &self,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        self.inner
            .import_development_fixture(&self.schema, fixture, actor, request_id)
    }
    fn reset_development_fixture(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        self.inner
            .reset_development_fixture(&self.schema, fixture_id, actor, request_id)
    }
    fn development_fixture_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        self.inner
            .development_fixture_environment(&self.schema, environment_id)
    }
    fn runtime_capabilities(&self) -> ComponentCapabilities {
        tenant_postgres_store_capabilities()
    }
    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.inner
            .claim_runtime_plan(&self.schema, environment, plan_id, owner, expires_at)
    }
    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.inner
            .renew_runtime_plan(&self.schema, plan_id, owner, generation, expires_at)
    }
    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        self.inner
            .complete_runtime_plan(&self.schema, plan_id, owner, generation, completion_json)
    }
}

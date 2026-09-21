use super::*;

impl OperationalStore for SqliteStore {
    fn publish_release(&self, release: &ReleaseRecord) -> Result<()> {
        self.publish_release_sqlite(release)
    }

    fn get_release(&self, id: &str) -> Result<Option<ReleaseRecord>> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT id,product,version,content_digest,descriptor_json FROM releases WHERE id=?1", [id],
            |row| Ok(ReleaseRecord { id: row.get(0)?, product: row.get(1)?, version: row.get(2)?, content_digest: row.get(3)?, descriptor_json: row.get(4)? }),
        ).optional()?)
    }

    fn import_development_fixture(
        &self,
        fixture: &crate::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureMap> {
        self.import_development_fixture_sqlite(fixture, actor, request_id)
    }

    fn reset_development_fixture(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<crate::development_fixtures::FixtureResetResult> {
        self.reset_development_fixture_sqlite(fixture_id, actor, request_id)
    }

    fn development_fixture_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<crate::development_fixtures::FixtureEnvironmentProjection>> {
        self.development_fixture_environment_sqlite(environment_id)
    }

    fn promote_channel(&self, channel: &ChannelRecord) -> Result<ChannelRecord> {
        self.promote_channel_sqlite(channel)
    }

    fn put_environment(&self, environment: &EnvironmentRecord) -> Result<EnvironmentRecord> {
        self.put_environment_sqlite(environment)
    }

    fn create_plan(&self, plan: &PlanRecord) -> Result<()> {
        self.create_plan_sqlite(plan)
    }

    fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>> {
        let connection = self.connection()?;
        connection.query_row(
            "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail FROM plans WHERE id=?1", [id],
            |row| {
                let status: String = row.get(5)?;
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, status, row.get(6)?))
            },
        ).optional()?.map(|(id, environment_id, format_version, content_digest, plan_json, status, status_detail)| {
            Ok::<PlanRecord, StoreError>(PlanRecord { id, environment_id, format_version, content_digest, plan_json, status: PlanStatus::parse(&status)?, status_detail })
        }).transpose()
    }

    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> Result<PlanRecord> {
        self.transition_plan_sqlite(id, owner, generation, status, detail)
    }

    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<LeaseRecord> {
        self.acquire_lease_sqlite(environment, owner, expires_at)
    }

    fn current_lease(&self, environment: &str) -> Result<Option<LeaseRecord>> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let lease = lease_in(&tx, environment)?;
        tx.commit()?;
        Ok(lease)
    }

    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> Result<()> {
        self.record_receipt_sqlite(owner, receipt)
    }

    fn get_receipt(&self, id: &str) -> Result<Option<ReceiptRecord>> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT id,environment_id,plan_id,step_id,lease_generation,payload_json FROM receipts WHERE id=?1", [id],
            |row| Ok(ReceiptRecord { id: row.get(0)?, environment_id: row.get(1)?, plan_id: row.get(2)?, step_id: row.get(3)?, lease_generation: row.get(4)?, payload_json: row.get(5)? }),
        ).optional()?)
    }

    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> Result<()> {
        self.record_offline_import_sqlite(receipt, steps)
    }

    fn get_offline_import(&self, bundle_digest: &str) -> Result<Option<OfflineImportRecord>> {
        self.get_offline_import_sqlite(bundle_digest)
    }

    fn create_rollback(&self, owner: &str, rollback: &RollbackRecord) -> Result<()> {
        self.create_rollback_sqlite(owner, rollback)
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
        self.transition_rollback_sqlite(id, owner, generation, status, checkpoint_json, detail)
    }

    fn pending_rollbacks(&self) -> Result<Vec<RollbackRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail FROM rollbacks WHERE status IN ('pending','running') ORDER BY id"
        )?;
        let rows = statement.query_map([], rollback_from_row)?;
        rows.map(|row| row.map_err(StoreError::from))
            .collect::<Result<Vec<_>>>()
    }

    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> Result<()> {
        let connection = self.connection()?;
        enqueue_provider_event_in(&connection, event)
    }

    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.list_provider_events_sqlite(provider_kind, environment_id, limit)
    }

    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.claim_provider_events_sqlite(now, limit, claim_token, claim_until)
    }

    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> Result<Vec<ProviderEventRecord>> {
        self.claim_provider_events_for_kind_sqlite(
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
        self.reserve_provider_event_sequence_sqlite(provider_kind, id, claim_token)
    }

    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> Result<()> {
        self.bind_provider_event_collection_time_sqlite(
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
        self.record_provider_failure_sqlite(provider_kind, id, claim_token, next_attempt_at, error)
    }

    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> Result<()> {
        self.mark_provider_event_delivered_sqlite(provider_kind, id, claim_token, delivered_at)
    }

    fn append_audit(&self, event: &AuditRecord) -> Result<()> {
        self.append_audit_sqlite(event)
    }

    fn audit_events(&self) -> Result<Vec<AuditRecord>> {
        self.audit_events_sqlite()
    }

    fn check_health(&self) -> Result<()> {
        let connection = self.connection()?;
        connection.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    fn runtime_capabilities(&self) -> crate::runtime_capabilities::ComponentCapabilities {
        crate::runtime_capabilities::sqlite_store_capabilities()
    }

    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.claim_runtime_plan_sqlite(environment, plan_id, owner, expires_at)
    }

    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> Result<Option<RuntimeClaim>> {
        self.renew_runtime_plan_sqlite(plan_id, owner, generation, expires_at)
    }

    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> Result<()> {
        self.complete_runtime_plan_sqlite(plan_id, owner, generation, completion_json)
    }
}

use super::*;

impl OperationalStore for SqliteStore {
    fn publish_release(&self, release: &ReleaseRecord) -> tenkai::storage::Result<()> {
        self.publish_release_sqlite(release).map_err(Into::into)
    }

    fn get_release(&self, id: &str) -> tenkai::storage::Result<Option<ReleaseRecord>> {
        release_record_in(&*self.connection()?, id).map_err(Into::into)
    }

    fn import_development_fixture(
        &self,
        fixture: &tenkai::development_fixtures::PreparedDevelopmentFixture,
        actor: &str,
        request_id: &str,
    ) -> tenkai::storage::Result<tenkai::development_fixtures::FixtureMap> {
        self.import_development_fixture_sqlite(fixture, actor, request_id)
            .map_err(Into::into)
    }

    fn reset_development_fixture(
        &self,
        fixture_id: &str,
        actor: &str,
        request_id: &str,
    ) -> tenkai::storage::Result<tenkai::development_fixtures::FixtureResetResult> {
        self.reset_development_fixture_sqlite(fixture_id, actor, request_id)
            .map_err(Into::into)
    }

    fn development_fixture_environment(
        &self,
        environment_id: &str,
    ) -> tenkai::storage::Result<Option<tenkai::development_fixtures::FixtureEnvironmentProjection>>
    {
        self.development_fixture_environment_sqlite(environment_id)
            .map_err(Into::into)
    }

    fn promote_channel(&self, channel: &ChannelRecord) -> tenkai::storage::Result<ChannelRecord> {
        self.promote_channel_sqlite(channel).map_err(Into::into)
    }

    fn put_environment(
        &self,
        environment: &EnvironmentRecord,
    ) -> tenkai::storage::Result<EnvironmentRecord> {
        self.put_environment_sqlite(environment).map_err(Into::into)
    }

    fn get_environment(&self, id: &str) -> tenkai::storage::Result<Option<EnvironmentRecord>> {
        SqliteStore::get_environment(self, id).map_err(Into::into)
    }

    fn list_environment_ids(&self) -> tenkai::storage::Result<Vec<String>> {
        SqliteStore::list_environment_ids(self).map_err(Into::into)
    }

    fn list_active_environment_ids(&self) -> tenkai::storage::Result<Vec<String>> {
        SqliteStore::list_active_environment_ids(self).map_err(Into::into)
    }

    fn create_plan(&self, plan: &PlanRecord) -> tenkai::storage::Result<()> {
        self.create_plan_sqlite(plan).map_err(Into::into)
    }

    fn get_plan(&self, id: &str) -> tenkai::storage::Result<Option<PlanRecord>> {
        plan_record_in(&*self.connection()?, id).map_err(Into::into)
    }

    fn transition_plan(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: PlanStatus,
        detail: &str,
    ) -> tenkai::storage::Result<PlanRecord> {
        self.transition_plan_sqlite(id, owner, generation, status, detail)
            .map_err(Into::into)
    }

    fn acquire_lease(
        &self,
        environment: &str,
        owner: &str,
        expires_at: i64,
    ) -> tenkai::storage::Result<LeaseRecord> {
        self.acquire_lease_sqlite(environment, owner, expires_at)
            .map_err(Into::into)
    }

    fn current_lease(&self, environment: &str) -> tenkai::storage::Result<Option<LeaseRecord>> {
        (|| -> crate::Result<Option<LeaseRecord>> {
            let mut connection = self.connection()?;
            let tx = connection.transaction()?;
            let lease = lease_in(&tx, environment)?;
            tx.commit()?;
            Ok(lease)
        })()
        .map_err(Into::into)
    }

    fn takeover_expired_lease(
        &self,
        environment: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
        evidence_json: &str,
    ) -> tenkai::storage::Result<LeaseRecord> {
        SqliteStore::takeover_expired_lease(
            self,
            environment,
            owner,
            generation,
            expires_at,
            evidence_json,
        )
        .map_err(Into::into)
    }

    fn require_claimed_undelivered_provider_event(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> tenkai::storage::Result<()> {
        SqliteStore::require_claimed_undelivered_provider_event(
            self,
            provider_kind,
            id,
            claim_token,
        )
        .map_err(Into::into)
    }

    fn record_receipt(&self, owner: &str, receipt: &ReceiptRecord) -> tenkai::storage::Result<()> {
        self.record_receipt_sqlite(owner, receipt)
            .map_err(Into::into)
    }

    fn get_receipt(&self, id: &str) -> tenkai::storage::Result<Option<ReceiptRecord>> {
        (|| -> crate::Result<Option<ReceiptRecord>> {
            let connection = self.connection()?;
            Ok(connection.query_row(
                "SELECT id,environment_id,plan_id,step_id,lease_generation,payload_json FROM receipts WHERE id=?1", [id],
                |row| Ok(ReceiptRecord { id: row.get(0)?, environment_id: row.get(1)?, plan_id: row.get(2)?, step_id: row.get(3)?, lease_generation: row.get(4)?, payload_json: row.get(5)? }),
            ).optional()?)

        })().map_err(Into::into)
    }

    fn record_offline_import(
        &self,
        receipt: &OfflineImportRecord,
        steps: &[OfflineStepImportRecord],
    ) -> tenkai::storage::Result<()> {
        self.record_offline_import_sqlite(receipt, steps)
            .map_err(Into::into)
    }

    fn get_offline_import(
        &self,
        bundle_digest: &str,
    ) -> tenkai::storage::Result<Option<OfflineImportRecord>> {
        self.get_offline_import_sqlite(bundle_digest)
            .map_err(Into::into)
    }

    fn create_rollback(
        &self,
        owner: &str,
        rollback: &RollbackRecord,
    ) -> tenkai::storage::Result<()> {
        self.create_rollback_sqlite(owner, rollback)
            .map_err(Into::into)
    }

    fn transition_rollback(
        &self,
        id: &str,
        owner: &str,
        generation: u64,
        status: RollbackStatus,
        checkpoint_json: &str,
        detail: &str,
    ) -> tenkai::storage::Result<RollbackRecord> {
        self.transition_rollback_sqlite(id, owner, generation, status, checkpoint_json, detail)
            .map_err(Into::into)
    }

    fn pending_rollbacks(&self) -> tenkai::storage::Result<Vec<RollbackRecord>> {
        (|| -> crate::Result<Vec<RollbackRecord>> {
            let connection = self.connection()?;
            let mut statement = connection.prepare(
                "SELECT id,environment_id,plan_id,lease_generation,checkpoint_json,status,status_detail FROM rollbacks WHERE status IN ('pending','running') ORDER BY id"
            )?;
            let rows = statement.query_map([], rollback_from_row)?;
            rows.map(|row| row.map_err(Error::from))
                .collect::<Result<Vec<_>>>()

        })().map_err(Into::into)
    }

    fn enqueue_provider_event(&self, event: &ProviderEventRecord) -> tenkai::storage::Result<()> {
        (|| -> crate::Result<()> {
            let connection = self.connection()?;
            enqueue_provider_event_in(&connection, event)
        })()
        .map_err(Into::into)
    }

    fn list_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> tenkai::storage::Result<Vec<ProviderEventRecord>> {
        self.list_provider_events_sqlite(provider_kind, environment_id, limit)
            .map_err(Into::into)
    }

    fn list_provider_events_after(
        &self,
        provider_kind: &str,
        environment_id: &str,
        after: Option<&ProviderEventPosition>,
        limit: usize,
    ) -> tenkai::storage::Result<Vec<(ProviderEventPosition, ProviderEventRecord)>> {
        self.list_provider_events_after_sqlite(provider_kind, environment_id, after, limit)
            .map_err(Into::into)
    }

    fn list_failing_provider_events(
        &self,
        provider_kind: &str,
        environment_id: &str,
        limit: usize,
    ) -> tenkai::storage::Result<Vec<ProviderEventRecord>> {
        self.list_failing_provider_events_sqlite(provider_kind, environment_id, limit)
            .map_err(Into::into)
    }

    fn claim_provider_events(
        &self,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> tenkai::storage::Result<Vec<ProviderEventRecord>> {
        self.claim_provider_events_sqlite(now, limit, claim_token, claim_until)
            .map_err(Into::into)
    }

    fn claim_provider_events_for_kind(
        &self,
        provider_kind: &str,
        now: i64,
        limit: usize,
        claim_token: &str,
        claim_until: i64,
    ) -> tenkai::storage::Result<Vec<ProviderEventRecord>> {
        self.claim_provider_events_for_kind_sqlite(
            provider_kind,
            now,
            limit,
            claim_token,
            claim_until,
        )
        .map_err(Into::into)
    }

    fn reserve_provider_event_sequence(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
    ) -> tenkai::storage::Result<i64> {
        self.reserve_provider_event_sequence_sqlite(provider_kind, id, claim_token)
            .map_err(Into::into)
    }

    fn bind_provider_event_collection_time(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        payload_json: &str,
    ) -> tenkai::storage::Result<()> {
        self.bind_provider_event_collection_time_sqlite(
            provider_kind,
            id,
            claim_token,
            payload_json,
        )
        .map_err(Into::into)
    }

    fn record_provider_failure(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        next_attempt_at: i64,
        error: &str,
    ) -> tenkai::storage::Result<()> {
        self.record_provider_failure_sqlite(provider_kind, id, claim_token, next_attempt_at, error)
            .map_err(Into::into)
    }

    fn mark_provider_event_delivered(
        &self,
        provider_kind: &str,
        id: &str,
        claim_token: &str,
        delivered_at: i64,
    ) -> tenkai::storage::Result<()> {
        self.mark_provider_event_delivered_sqlite(provider_kind, id, claim_token, delivered_at)
            .map_err(Into::into)
    }

    fn append_audit(&self, event: &AuditRecord) -> tenkai::storage::Result<()> {
        self.append_audit_sqlite(event).map_err(Into::into)
    }

    fn audit_events(&self) -> tenkai::storage::Result<Vec<AuditRecord>> {
        self.audit_events_sqlite().map_err(Into::into)
    }

    fn audit_events_after(
        &self,
        cursor: i64,
        limit: usize,
    ) -> tenkai::storage::Result<Vec<(i64, AuditRecord)>> {
        self.audit_events_after_sqlite(cursor, limit)
            .map_err(Into::into)
    }

    fn append_change_event(
        &self,
        occurred_at: i64,
        kind: &str,
        resource: &str,
        environment_id: &str,
    ) -> tenkai::storage::Result<tenkai::change_stream::ChangeEvent> {
        self.append_change_event_sqlite(occurred_at, kind, resource, environment_id)
            .map_err(Into::into)
    }

    fn append_change_event_once(
        &self,
        occurred_at: i64,
        kind: tenkai::change_stream::ChangeEventKind,
        resource: &str,
        since: i64,
        only_after_another: bool,
    ) -> tenkai::storage::Result<Option<tenkai::change_stream::ChangeEvent>> {
        self.append_change_event_once_sqlite(occurred_at, kind, resource, since, only_after_another)
            .map_err(Into::into)
    }

    fn list_change_events_after(
        &self,
        cursor: i64,
        limit: usize,
    ) -> tenkai::storage::Result<Vec<tenkai::change_stream::ChangeEvent>> {
        self.list_change_events_after_sqlite(cursor, limit)
            .map_err(Into::into)
    }

    fn check_health(&self) -> tenkai::storage::Result<()> {
        (|| -> crate::Result<()> {
            let connection = self.connection()?;
            connection.query_row("SELECT 1", [], |_| Ok(()))?;
            Ok(())
        })()
        .map_err(Into::into)
    }

    fn runtime_capabilities(&self) -> tenkai::runtime_capabilities::ComponentCapabilities {
        tenkai::runtime_capabilities::sqlite_store_capabilities()
    }

    fn claim_runtime_plan(
        &self,
        environment: &str,
        plan_id: &str,
        owner: &str,
        expires_at: i64,
    ) -> tenkai::storage::Result<Option<RuntimeClaim>> {
        self.claim_runtime_plan_sqlite(environment, plan_id, owner, expires_at)
            .map_err(Into::into)
    }

    fn durable_runtime_completion(
        &self,
        plan_id: &str,
        owner: &str,
    ) -> tenkai::storage::Result<Option<RuntimeClaim>> {
        (|| -> crate::Result<Option<RuntimeClaim>> {
            Ok(self
                .connection()?
                .query_row(
                    "SELECT environment_id,generation,expires_at,completion_json FROM runtime_claims
                     WHERE plan_id=?1 AND owner=?2 AND completion_json IS NOT NULL",
                    params![plan_id, owner],
                    |row| {
                        Ok(RuntimeClaim {
                            plan_id: plan_id.into(),
                            environment_id: row.get(0)?,
                            owner: owner.into(),
                            generation: row.get(1)?,
                            expires_at: row.get(2)?,
                            completion_json: row.get(3)?,
                            progress_json: None,
                        })
                    },
                )
                .optional()?)
        })()
        .map_err(Into::into)
    }

    fn renew_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        expires_at: i64,
    ) -> tenkai::storage::Result<Option<RuntimeClaim>> {
        self.renew_runtime_plan_sqlite(plan_id, owner, generation, expires_at)
            .map_err(Into::into)
    }

    fn complete_runtime_plan(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        completion_json: &str,
    ) -> tenkai::storage::Result<()> {
        self.complete_runtime_plan_sqlite(plan_id, owner, generation, completion_json)
            .map_err(Into::into)
    }

    fn lapsed_runtime_completion(
        &self,
        environment: &str,
        plan_id: &str,
        now: i64,
    ) -> tenkai::storage::Result<Option<String>> {
        self.lapsed_runtime_completion_sqlite(environment, plan_id, now)
            .map_err(Into::into)
    }

    fn record_runtime_progress(
        &self,
        plan_id: &str,
        owner: &str,
        generation: u64,
        progress_json: &str,
    ) -> tenkai::storage::Result<bool> {
        (|| -> crate::Result<bool> {
            Ok(self.connection()?.execute(
                "UPDATE runtime_claims SET progress_json=?4
                 WHERE plan_id=?1 AND owner=?2 AND generation=?3
                   AND expires_at>?5 AND completion_json IS NULL",
                params![
                    plan_id,
                    owner,
                    generation,
                    progress_json,
                    tenkai::now_millis()
                ],
            )? == 1)
        })()
        .map_err(Into::into)
    }

    fn runtime_progress(&self, plan_id: &str) -> tenkai::storage::Result<Option<String>> {
        (|| -> crate::Result<Option<String>> {
            Ok(self
                .connection()?
                .query_row(
                    "SELECT progress_json FROM runtime_claims WHERE plan_id=?1",
                    [plan_id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten())
        })()
        .map_err(Into::into)
    }

    fn create_runtime_enrollment(
        &self,
        enrollment: &RuntimeEnrollmentRecord,
    ) -> tenkai::storage::Result<()> {
        self.create_runtime_enrollment_sqlite(enrollment)
            .map_err(Into::into)
    }

    fn redeem_runtime_enrollment(
        &self,
        environment: &str,
        token_digest: &str,
        credential_digest: &str,
        now: i64,
        attestation: Option<&RuntimeAttestationRecord>,
        sealing: Option<&RuntimeSealingKeyRecord>,
    ) -> tenkai::storage::Result<RuntimeCredentialRecord> {
        self.redeem_runtime_enrollment_sqlite(
            environment,
            token_digest,
            credential_digest,
            now,
            attestation,
            sealing,
        )
        .map_err(Into::into)
    }

    fn runtime_enrollment_usable(
        &self,
        environment: &str,
        token_digest: &str,
        now: i64,
    ) -> tenkai::storage::Result<bool> {
        self.runtime_enrollment_usable_sqlite(environment, token_digest, now)
            .map_err(Into::into)
    }

    fn runtime_credential(
        &self,
        credential_digest: &str,
    ) -> tenkai::storage::Result<Option<RuntimeCredentialRecord>> {
        self.runtime_credential_sqlite(credential_digest)
            .map_err(Into::into)
    }

    fn revoke_runtime_credential(
        &self,
        credential_digest: &str,
        now: i64,
        revocation: &RuntimeRevocation,
    ) -> tenkai::storage::Result<()> {
        self.revoke_runtime_credential_sqlite(credential_digest, now, revocation)
            .map_err(Into::into)
    }

    fn runtime_runners(&self) -> tenkai::storage::Result<Vec<RuntimeRunnerRecord>> {
        self.runtime_runners_sqlite().map_err(Into::into)
    }

    fn record_runtime_activity(
        &self,
        activity: &RuntimeActivityRecord,
    ) -> tenkai::storage::Result<()> {
        self.record_runtime_activity_sqlite(activity)
            .map_err(Into::into)
    }

    fn runtime_activity(&self) -> tenkai::storage::Result<Vec<RuntimeActivityRecord>> {
        self.runtime_activity_sqlite().map_err(Into::into)
    }

    fn record_runtime_certificate(
        &self,
        runner_id: &str,
        environment_id: &str,
        issued_at: i64,
    ) -> tenkai::storage::Result<()> {
        self.record_runtime_certificate_sqlite(runner_id, environment_id, issued_at)
            .map_err(Into::into)
    }

    fn certified_runtime_runners(&self) -> tenkai::storage::Result<Vec<String>> {
        self.certified_runtime_runners_sqlite().map_err(Into::into)
    }

    fn live_runtime_claim_owners(&self, now: i64) -> tenkai::storage::Result<Vec<String>> {
        self.live_runtime_claim_owners_sqlite(now)
            .map_err(Into::into)
    }

    fn record_runtime_attestation(
        &self,
        record: &RuntimeAttestationRecord,
    ) -> tenkai::storage::Result<()> {
        self.record_runtime_attestation_sqlite(record)
            .map_err(Into::into)
    }

    fn runtime_attestations(&self) -> tenkai::storage::Result<Vec<RuntimeAttestationRecord>> {
        self.runtime_attestations_sqlite().map_err(Into::into)
    }

    fn record_runtime_sealing_key(
        &self,
        record: &RuntimeSealingKeyRecord,
    ) -> tenkai::storage::Result<()> {
        self.record_runtime_sealing_key_sqlite(record)
            .map_err(Into::into)
    }

    fn runtime_sealing_keys(
        &self,
        environment: &str,
    ) -> tenkai::storage::Result<Vec<RuntimeSealingKeyRecord>> {
        self.runtime_sealing_keys_sqlite(environment)
            .map_err(Into::into)
    }

    fn runtime_sealing_key(
        &self,
        runner_id: &str,
    ) -> tenkai::storage::Result<Option<RuntimeSealingKeyRecord>> {
        self.runtime_sealing_key_sqlite(runner_id)
            .map_err(Into::into)
    }
}

/// The release row `id`, read through `connection` (a transaction too).
pub(crate) fn release_record_in(
    connection: &rusqlite::Connection,
    id: &str,
) -> Result<Option<ReleaseRecord>> {
    Ok(connection
        .query_row(
            "SELECT id,product,version,content_digest,descriptor_json FROM releases WHERE id=?1",
            [id],
            |row| {
                Ok(ReleaseRecord {
                    id: row.get(0)?,
                    product: row.get(1)?,
                    version: row.get(2)?,
                    content_digest: row.get(3)?,
                    descriptor_json: row.get(4)?,
                })
            },
        )
        .optional()?)
}

/// The plan row `id`, read through `connection` (a transaction too).
pub(crate) fn plan_record_in(
    connection: &rusqlite::Connection,
    id: &str,
) -> Result<Option<PlanRecord>> {
    connection.query_row(
            "SELECT id,environment_id,format_version,content_digest,plan_json,status,status_detail FROM plans WHERE id=?1", [id],
            |row| {
                let status: String = row.get(5)?;
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, status, row.get(6)?))
            },
        ).optional()?.map(|(id, environment_id, format_version, content_digest, plan_json, status, status_detail)| {
            Ok::<PlanRecord, StoreError>(PlanRecord { id, environment_id, format_version, content_digest, plan_json, status: PlanStatus::parse(&status)?, status_detail })
        }).transpose().map_err(Into::into)
}

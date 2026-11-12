use super::remote_client::RemoteClient;
use super::runtime::encode_plan_path;

impl RemoteClient {
    pub async fn retire_environment(
        &self,
        environment: &str,
        reason: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/retire"),
            Some(&tenkai::management_lifecycle::RetireEnvironmentRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Retire
                    .as_str()
                    .into(),
                reason: reason.to_string(),
            }),
        )
        .await
    }

    pub async fn preview_package_migration(
        &self,
        name: &str,
        request: &tenkai::package_migration::PackageMigrationPreviewRequest,
    ) -> anyhow::Result<tenkai::package_migration::PackageMigrationResult> {
        self.package_migration_result(
            reqwest::Method::POST,
            &format!("/v1/migrations/{name}/preview"),
            Some(request),
        )
        .await
    }

    pub async fn apply_package_migration(
        &self,
        name: &str,
        request: &tenkai::package_migration::PackageMigrationApplyRequest,
    ) -> anyhow::Result<tenkai::package_migration::PackageMigrationResult> {
        self.package_migration_result(
            reqwest::Method::POST,
            &format!("/v1/migrations/{name}/apply"),
            Some(request),
        )
        .await
    }

    pub async fn package_migration_status(
        &self,
        name: &str,
    ) -> anyhow::Result<tenkai::package_migration::PackageMigrationResult> {
        self.package_migration_result(
            reqwest::Method::GET,
            &format!("/v1/migrations/{name}"),
            None::<&tenkai::package_migration::PackageMigrationPreviewRequest>,
        )
        .await
    }

    pub async fn resume_package_migration(
        &self,
        name: &str,
        request: &tenkai::package_migration::PackageMigrationMutateRequest,
    ) -> anyhow::Result<tenkai::package_migration::PackageMigrationResult> {
        self.package_migration_result(
            reqwest::Method::POST,
            &format!("/v1/migrations/{name}/resume"),
            Some(request),
        )
        .await
    }

    pub async fn publish_release(
        &self,
        request: &tenkai::management_lifecycle::PublishRequest,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(reqwest::Method::POST, "/v1/releases", Some(request))
            .await
    }

    pub async fn promote_release(
        &self,
        spec: &str,
        channel: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.promote_release_expecting(spec, channel, None).await
    }

    /// [`Self::promote_release`], refused unless the channel is empty, heads
    /// `spec`, or heads `expected_head`.
    pub async fn promote_release_expecting(
        &self,
        spec: &str,
        channel: &str,
        expected_head: Option<&str>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/channels/{channel}/promote"),
            Some(&tenkai::management_lifecycle::PromoteHttpRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Promote
                    .as_str()
                    .into(),
                spec: spec.to_string(),
                expected_head: expected_head.map(str::to_string),
            }),
        )
        .await
    }

    pub async fn recall_release(
        &self,
        spec: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        let encoded = spec.replace('@', "%40");
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/releases/{encoded}/recall"),
            Some(&tenkai::management_lifecycle::RecallRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Recall
                    .as_str()
                    .into(),
            }),
        )
        .await
    }

    pub async fn record_recall_range(
        &self,
        product: &str,
        from: &str,
        before: Option<&str>,
        reason: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/recall-range"),
            Some(&tenkai::management_lifecycle::RecallRangeRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Recall
                    .as_str()
                    .into(),
                product: product.to_string(),
                from: from.to_string(),
                before: before.map(str::to_string),
                reason: reason.to_string(),
            }),
        )
        .await
    }

    pub async fn close_recall_range(
        &self,
        product: &str,
        from: &str,
        before: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/recall-range/close"),
            Some(&tenkai::management_lifecycle::RecallRangeCloseRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Recall
                    .as_str()
                    .into(),
                product: product.to_string(),
                from: from.to_string(),
                before: before.to_string(),
            }),
        )
        .await
    }

    /// `POST /v1/environments`.
    pub async fn register_environment(
        &self,
        environment: &str,
        description: &str,
        connectivity_class: Option<tenkai::connectivity::ConnectivityClass>,
        reason: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            "/v1/environments",
            Some(&tenkai::environment_config::RegisterEnvironmentRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Register
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                description: description.to_string(),
                connectivity_class,
                reason: reason.to_string(),
            }),
        )
        .await
    }

    /// One generation-fenced configuration change; the change picks the
    /// route and whether it is a `PUT` or a `DELETE`.
    pub async fn configure_environment(
        &self,
        environment: &str,
        change: tenkai::environment_config::EnvironmentConfigChange,
        reason: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        let method = if change.clears() {
            reqwest::Method::DELETE
        } else {
            reqwest::Method::PUT
        };
        let path = change.path(environment);
        self.lifecycle_result(
            method,
            &path,
            Some(&tenkai::environment_config::EnvironmentConfigRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Configure
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                reason: reason.to_string(),
                change,
            }),
        )
        .await
    }

    pub async fn subscribe_environment(
        &self,
        environment: &str,
        spec: &str,
        expected_generation: u64,
        instance: Option<&str>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/subscriptions"),
            Some(&tenkai::management_lifecycle::SubscribeRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Subscribe
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                spec: spec.to_string(),
                instance: instance.map(str::to_string),
            }),
        )
        .await
    }

    pub async fn unsubscribe_environment(
        &self,
        environment: &str,
        product: &str,
        expected_generation: u64,
        instance: Option<&str>,
        expected_version: Option<&str>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::DELETE,
            &format!("/v1/environments/{environment}/subscriptions/{product}"),
            Some(&tenkai::management_lifecycle::UnsubscribeRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Unsubscribe
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                product: product.to_string(),
                instance: instance.map(str::to_string),
                expected_version: expected_version.map(str::to_string),
            }),
        )
        .await
    }

    pub async fn plan_environment(
        &self,
        environment: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/plans"),
            Some(&tenkai::management_lifecycle::PlanRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Plan
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
            }),
        )
        .await
    }

    pub async fn plan_approvals(
        &self,
        plan_id: &str,
    ) -> anyhow::Result<tenkai::plan_approval::PlanApprovalsView> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/plans/{}/approvals", encode_plan_path(plan_id)),
        )
        .await
    }

    pub async fn approve_plan(
        &self,
        plan_id: &str,
        request: &tenkai::management_lifecycle::ApproveRequest,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/plans/{}/approve", encode_plan_path(plan_id)),
            Some(request),
        )
        .await
    }

    pub async fn apply_plan(
        &self,
        plan_id: &str,
        request: &tenkai::management_lifecycle::ApplyRequest,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        // `steps=true` asks for one result per step (#1076). A server that
        // predates it ignores the query and returns the message alone; a
        // refused apply's 422 body then carries `steps` too.
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/plans/{}/apply?steps=true", encode_plan_path(plan_id)),
            Some(request),
        )
        .await
    }

    pub async fn environment_hold(
        &self,
        environment: &str,
    ) -> anyhow::Result<tenkai::delivery_hold::DeliveryHoldView> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}/hold"),
        )
        .await
    }

    pub async fn set_environment_hold(
        &self,
        environment: &str,
        reason: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/hold"),
            Some(&tenkai::management_lifecycle::DeliveryHoldRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Hold
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                reason: Some(reason.to_string()),
            }),
        )
        .await
    }

    pub async fn release_environment_hold(
        &self,
        environment: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/hold/release"),
            Some(&tenkai::management_lifecycle::DeliveryHoldRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Release
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                reason: None,
            }),
        )
        .await
    }

    pub async fn schedule_environment_freeze(
        &self,
        environment: &str,
        name: &str,
        from: Option<&str>,
        until: &str,
        reason: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/hold/schedule"),
            Some(&tenkai::management_lifecycle::DeliveryFreezeRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::HoldSchedule
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                name: name.to_string(),
                from: from.map(str::to_string),
                until: Some(until.to_string()),
                reason: Some(reason.to_string()),
            }),
        )
        .await
    }

    pub async fn cancel_environment_freeze(
        &self,
        environment: &str,
        name: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/hold/cancel"),
            Some(&tenkai::management_lifecycle::DeliveryFreezeRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::HoldCancel
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                name: name.to_string(),
                from: None,
                until: None,
                reason: None,
            }),
        )
        .await
    }

    pub async fn set_environment_failure_threshold(
        &self,
        environment: &str,
        count: u32,
        window: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/hold/threshold"),
            Some(
                &tenkai::management_lifecycle::DeliveryFailureThresholdRequest {
                    version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                    operation:
                        tenkai::management_lifecycle::ManagementLifecycleOperation::HoldThreshold
                            .as_str()
                            .into(),
                    environment: environment.to_string(),
                    expected_generation,
                    count: Some(count),
                    window: Some(window.to_string()),
                },
            ),
        )
        .await
    }

    pub async fn clear_environment_failure_threshold(
        &self,
        environment: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/hold/threshold/clear"),
            Some(
                &tenkai::management_lifecycle::DeliveryFailureThresholdRequest {
                    version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                    operation:
                        tenkai::management_lifecycle::ManagementLifecycleOperation::HoldThresholdClear
                            .as_str()
                            .into(),
                    environment: environment.to_string(),
                    expected_generation,
                    count: None,
                    window: None,
                },
            ),
        )
        .await
    }

    pub async fn retry_failed_target(
        &self,
        environment: &str,
        product: &str,
        reason: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/failed-targets/{product}/retry"),
            Some(&tenkai::management_lifecycle::RetryFailedTargetRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Retry
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                product: product.to_string(),
                reason: Some(reason.to_string()),
            }),
        )
        .await
    }

    pub async fn channel_hold(
        &self,
        product: &str,
        channel: &str,
    ) -> anyhow::Result<tenkai::delivery_hold::DeliveryHoldView> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/products/{product}/channels/{channel}/hold"),
        )
        .await
    }

    pub async fn set_channel_hold(
        &self,
        product: &str,
        channel: &str,
        reason: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/channels/{channel}/hold"),
            Some(&tenkai::management_lifecycle::ChannelHoldRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::ChannelHold
                    .as_str()
                    .into(),
                reason: Some(reason.to_string()),
            }),
        )
        .await
    }

    pub async fn release_channel_hold(
        &self,
        product: &str,
        channel: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/channels/{channel}/hold/release"),
            Some(&tenkai::management_lifecycle::ChannelHoldRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation:
                    tenkai::management_lifecycle::ManagementLifecycleOperation::ChannelRelease
                        .as_str()
                        .into(),
                reason: None,
            }),
        )
        .await
    }

    pub async fn configure_channel_pace(
        &self,
        product: &str,
        channel: &str,
        upgrade_pace: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/channels/{channel}/pace"),
            Some(&tenkai::management_lifecycle::ChannelConfigureRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation:
                    tenkai::management_lifecycle::ManagementLifecycleOperation::ChannelConfigure
                        .as_str()
                        .into(),
                upgrade_pace: upgrade_pace.to_string(),
            }),
        )
        .await
    }

    pub async fn admit_channel_instance(
        &self,
        product: &str,
        channel: &str,
        environment: &str,
        instance: &str,
        reason: &str,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/channels/{channel}/admit"),
            Some(&tenkai::management_lifecycle::ChannelAdmitRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::ChannelAdmit
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                instance: instance.to_string(),
                reason: reason.to_string(),
            }),
        )
        .await
    }

    /// Removes `product`'s head from `channel`; `expected_head`
    /// (`<product>@<version>`) refuses it when another release heads it.
    pub async fn remove_channel_head(
        &self,
        product: &str,
        channel: &str,
        expected_head: Option<&str>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/products/{product}/channels/{channel}/remove"),
            Some(&tenkai::management_lifecycle::ChannelRemoveRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation:
                    tenkai::management_lifecycle::ManagementLifecycleOperation::ChannelRemove
                        .as_str()
                        .into(),
                expected_head: expected_head.map(str::to_owned),
            }),
        )
        .await
    }

    pub async fn cancel_apply(
        &self,
        environment: &str,
        expected_generation: u64,
        reason: Option<String>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/apply/cancel"),
            Some(&tenkai::management_lifecycle::DeliveryHoldRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Cancel
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                reason,
            }),
        )
        .await
    }

    pub async fn rollback_environment(
        &self,
        environment: &str,
        product: &str,
        expected_generation: u64,
        recovery_reason: Option<String>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/rollback"),
            Some(&tenkai::management_lifecycle::RollbackRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Rollback
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                product: product.to_string(),
                recovery_reason,
            }),
        )
        .await
    }

    /// Issue a single-use runtime enrollment token for `environment` (#630).
    pub async fn create_runtime_enrollment(
        &self,
        environment: &str,
        request: &tenkai::management_operations::RuntimeEnrollmentRequest,
    ) -> anyhow::Result<tenkai::management_operations::RuntimeEnrollmentIssued> {
        self.request_json_body(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/runtime-enrollments"),
            Some(request),
        )
        .await
    }

    /// Revoke the runner `credential_id` for `reason` (#630, #673).
    pub async fn revoke_runtime_credential(
        &self,
        credential_id: &str,
        reason: &str,
    ) -> anyhow::Result<tenkai::management_operations::RuntimeCredentialRevoked> {
        self.request_json_body(
            reqwest::Method::POST,
            &format!("/v1/runners/{credential_id}/revoke"),
            Some(&tenkai::management_operations::RuntimeRevokeRequest {
                reason: reason.into(),
            }),
        )
        .await
    }

    /// The runner registry (#673).
    pub async fn list_runtime_runners(
        &self,
    ) -> anyhow::Result<tenkai::management_operations::RuntimeRunnerList> {
        self.request_json(reqwest::Method::GET, "/v1/runners").await
    }

    /// Unrevoked sealing public keys of `environment` (ADR 0045).
    pub async fn list_environment_recipients(
        &self,
        environment: &str,
    ) -> anyhow::Result<tenkai::management_operations::EnvironmentRecipients> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}/recipient-keys"),
        )
        .await
    }

    /// Ask for a plan that re-wraps `environment`'s sealed values for the
    /// recipient key `recipient` (ADR 0045 §5). `recovered` carries wraps
    /// for `recipient` the recovery key made, per instance (ADR 0045 §7).
    pub async fn rewrap_sealed_secrets(
        &self,
        environment: &str,
        recipient: &str,
        expected_generation: u64,
        recovered: std::collections::BTreeMap<String, Vec<tenkai::sealed_secret::RecipientWrap>>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/sealed-secrets/rewrap"),
            Some(&tenkai::management_lifecycle::SealedRewrapRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Plan
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                recipient: recipient.to_string(),
                recovered,
            }),
        )
        .await
    }

    /// Ask `environment`'s runtimes for an identity issuer candidate of the
    /// next generation (ADR 0046 §2).
    pub async fn prepare_identity_issuer(
        &self,
        environment: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.identity_issuer(environment, "prepare", expected_generation)
            .await
    }

    /// Ask for a plan that activates `environment`'s uploaded identity
    /// issuer candidate (ADR 0046 §2).
    pub async fn plan_identity_issuer(
        &self,
        environment: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.identity_issuer(environment, "plan", expected_generation)
            .await
    }

    /// Ask for a plan that wraps `environment`'s identity issuer key for the
    /// recipient key `recipient` (ADR 0046 §2).
    pub async fn rewrap_identity_issuer(
        &self,
        environment: &str,
        recipient: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/identity-issuer/rewrap"),
            Some(&tenkai::management_lifecycle::SealedRewrapRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Plan
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
                recipient: recipient.to_string(),
                recovered: Default::default(),
            }),
        )
        .await
    }

    async fn identity_issuer(
        &self,
        environment: &str,
        action: &str,
        expected_generation: u64,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/environments/{environment}/identity-issuer/{action}"),
            Some(&tenkai::management_lifecycle::PlanRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Plan
                    .as_str()
                    .into(),
                environment: environment.to_string(),
                expected_generation,
            }),
        )
        .await
    }

    /// Sealed keys of `environment`. `with_sealed` also returns each
    /// value's ciphertext and wraps, which `secret recover` opens offline.
    pub async fn list_sealed_secrets(
        &self,
        environment: &str,
        with_sealed: bool,
    ) -> anyhow::Result<tenkai::sealed_secret::SealedSecretList> {
        let query = if with_sealed { "?sealed=true" } else { "" };
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}/sealed-secrets{query}"),
        )
        .await
    }

    /// One runner of the registry (#673).
    pub async fn inspect_runtime_runner(
        &self,
        runner_id: &str,
    ) -> anyhow::Result<tenkai::management_operations::RuntimeRunner> {
        self.request_json(reqwest::Method::GET, &format!("/v1/runners/{runner_id}"))
            .await
    }

    async fn lifecycle_result<B: serde::Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> anyhow::Result<tenkai::management_lifecycle::ManagementLifecycleResult> {
        let result: tenkai::management_lifecycle::ManagementLifecycleResult =
            self.request_json_body(method, path, body).await?;
        tenkai::management_lifecycle::require_management_lifecycle_api_version(result.version)?;
        Ok(result)
    }

    pub async fn rollback_package_migration(
        &self,
        name: &str,
        request: &tenkai::package_migration::PackageMigrationMutateRequest,
    ) -> anyhow::Result<tenkai::package_migration::PackageMigrationResult> {
        self.package_migration_result(
            reqwest::Method::POST,
            &format!("/v1/migrations/{name}/rollback"),
            Some(request),
        )
        .await
    }

    async fn package_migration_result<B: serde::Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> anyhow::Result<tenkai::package_migration::PackageMigrationResult> {
        let result: tenkai::package_migration::PackageMigrationResult =
            self.request_json_body(method, path, body).await?;
        tenkai::package_migration::require_migration_api_version(result.version)?;
        Ok(result)
    }
}

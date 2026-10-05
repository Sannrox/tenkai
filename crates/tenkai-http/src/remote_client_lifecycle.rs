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
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/channels/{channel}/promote"),
            Some(&tenkai::management_lifecycle::PromoteRequest {
                version: tenkai::management_lifecycle::MANAGEMENT_LIFECYCLE_API_VERSION,
                operation: tenkai::management_lifecycle::ManagementLifecycleOperation::Promote
                    .as_str()
                    .into(),
                spec: spec.to_string(),
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

    pub async fn subscribe_environment(
        &self,
        environment: &str,
        spec: &str,
        expected_generation: u64,
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
        self.lifecycle_result(
            reqwest::Method::POST,
            &format!("/v1/plans/{}/apply", encode_plan_path(plan_id)),
            Some(request),
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

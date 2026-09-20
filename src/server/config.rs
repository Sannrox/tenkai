use std::collections::HashMap;
use std::sync::Arc;

use crate::auth_context::{
    AuthHostConfig, AuthStack, CommunityTokenAuthenticator, EnterpriseAuthExtension,
    PrincipalIdentity, PrincipalKind, build_auth_stack,
};
use crate::federated_identity::{FederatingAuthExtension, FederationConfig, IdentityDirectory};
use crate::runtime_capabilities::{
    ProvidedCapabilities, RuntimeRequirements, community_auth_capabilities,
    community_sqlite_profile, validate_runtime_capabilities,
};
use crate::tenant_store::TenantOperationalStore;

#[derive(Clone)]
pub struct ServerConfig {
    pub management_token: String,
    /// Maps a runtime bearer token to its one assigned environment.
    pub runtime_assignments: HashMap<String, String>,
    /// Maps an environment-scoped management bearer to its one granted environment.
    pub environment_management_assignments: HashMap<String, String>,
    /// Host capability requirements validated before the router accepts traffic.
    pub requirements: RuntimeRequirements,
    /// Composed capabilities advertised by storage and extensions.
    pub capabilities: ProvidedCapabilities,
    /// Auth host composition (community default; set required extension for enterprise).
    pub auth_host: AuthHostConfig,
    /// Optional enterprise auth extension. Required when `auth_host` demands one
    /// or when `requirements.require_enterprise_authentication` is set.
    pub enterprise_auth: Option<Arc<dyn EnterpriseAuthExtension>>,
    /// Federation accept rules (issuer/audience/replay). Community hosts leave
    /// the enterprise issuer unset so federation is not required.
    pub federation: FederationConfig,
    /// Local correlation + replay directory (never shared with an identity plane DB).
    pub identity_directory: Arc<IdentityDirectory>,
    /// Optional tenant-isolating operational store. Required when `tenant_mode` is on.
    /// In-memory for tests; Postgres hub adapter for durable multi-tenant recovery.
    pub tenant_store: Option<Arc<dyn TenantOperationalStore>>,
    /// When true, expose unauthenticated `GET /metrics` OpenMetrics (#137).
    /// Intended for loopback scrapes only (server already binds loopback).
    pub metrics_enabled: bool,
    /// Explicitly enabled, development-only authenticated fixture surface.
    pub development_fixtures: Option<DevelopmentFixtureConfig>,
    /// Host-owned package-migration approval trust roots (ADR 0026).
    /// Remote apply/resume/rollback require this file; request-supplied roots
    /// must match it and cannot introduce a caller-chosen signer set.
    pub package_migration_trust_roots: Option<std::path::PathBuf>,
}

#[derive(Clone, Debug)]
pub struct DevelopmentFixtureConfig {
    pub allowed_principals: std::collections::BTreeSet<String>,
}

impl ServerConfig {
    /// Community server defaults: SQLite store profile and community auth.
    pub fn community(
        management_token: impl Into<String>,
        runtime_assignments: HashMap<String, String>,
    ) -> Self {
        Self {
            management_token: management_token.into(),
            runtime_assignments,
            environment_management_assignments: HashMap::new(),
            requirements: RuntimeRequirements::community(),
            capabilities: community_sqlite_profile(community_auth_capabilities()),
            auth_host: AuthHostConfig::community(),
            enterprise_auth: None,
            federation: FederationConfig::community(),
            identity_directory: Arc::new(IdentityDirectory::new()),
            tenant_store: None,
            metrics_enabled: false,
            development_fixtures: None,
            package_migration_trust_roots: None,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.management_token.is_empty(),
            "management token must not be empty"
        );
        anyhow::ensure!(
            self.runtime_assignments
                .iter()
                .all(|(token, environment)| !token.is_empty() && !environment.is_empty()),
            "runtime tokens and environment assignments must not be empty"
        );
        anyhow::ensure!(
            !self
                .runtime_assignments
                .contains_key(&self.management_token),
            "management and runtime credentials must be distinct"
        );
        anyhow::ensure!(
            self.environment_management_assignments
                .iter()
                .all(|(token, environment)| !token.is_empty() && !environment.is_empty()),
            "environment-scoped management tokens and assignments must not be empty"
        );
        anyhow::ensure!(
            !self
                .environment_management_assignments
                .contains_key(&self.management_token)
                && self
                    .environment_management_assignments
                    .keys()
                    .all(|token| !self.runtime_assignments.contains_key(token)),
            "environment-scoped management credentials must be distinct from fleet management and runtime tokens"
        );
        validate_runtime_capabilities(&self.capabilities, &self.requirements)
            .map_err(|error| anyhow::anyhow!("runtime capability negotiation failed: {error}"))?;
        if self.requirements.tenant_mode && self.tenant_store.is_none() {
            anyhow::bail!(
                "tenant mode requires a tenant-isolating operational store adapter (tenant_store)"
            );
        }
        if let Some(fixtures) = &self.development_fixtures {
            anyhow::ensure!(
                self.requirements.tenant_mode
                    && self.requirements.require_enterprise_authentication
                    && self.enterprise_auth.is_some(),
                "development fixtures require tenant mode and enterprise authentication"
            );
            anyhow::ensure!(
                !fixtures.allowed_principals.is_empty()
                    && fixtures
                        .allowed_principals
                        .iter()
                        .all(|principal| !principal.trim().is_empty()),
                "development fixtures require at least one non-empty allowed principal"
            );
        }
        // Compose AuthStack at validation time so missing required enterprise
        // extensions fail before the router accepts traffic.
        let _ = self.build_auth_stack()?;
        Ok(())
    }

    fn resolved_auth_host(&self) -> AuthHostConfig {
        let mut host = self.auth_host.clone();
        if self.requirements.require_enterprise_authentication
            && host.required_extension_id.is_none()
        {
            host.required_extension_id = Some(
                self.enterprise_auth
                    .as_ref()
                    .map(|extension| extension.extension_id().to_string())
                    .unwrap_or_else(|| "auth.enterprise".into()),
            );
        }
        host
    }

    pub(super) fn build_auth_stack(&self) -> anyhow::Result<AuthStack> {
        let mut tokens = vec![(
            self.management_token.clone(),
            PrincipalIdentity {
                id: "management".into(),
                kind: PrincipalKind::Management,
            },
        )];
        tokens.extend(self.environment_management_assignments.iter().map(
            |(token, environment)| {
                (
                    token.clone(),
                    PrincipalIdentity {
                        id: format!("management:{environment}"),
                        kind: PrincipalKind::Management,
                    },
                )
            },
        ));
        tokens.extend(self.runtime_assignments.keys().map(|token| {
            (
                token.clone(),
                PrincipalIdentity {
                    id: format!(
                        "runtime:{}",
                        self.runtime_assignments
                            .get(token)
                            .expect("runtime assignment exists")
                    ),
                    kind: PrincipalKind::Runtime,
                },
            )
        }));
        let community = CommunityTokenAuthenticator::new("auth.community", tokens)
            .map_err(|error| anyhow::anyhow!("community management authenticator: {error}"))?;
        let enterprise = self.enterprise_auth.clone().map(|extension| {
            if self.federation.required_enterprise_issuer.is_some() {
                Arc::new(FederatingAuthExtension::new(
                    extension,
                    self.identity_directory.clone(),
                    self.federation.clone(),
                )) as Arc<dyn EnterpriseAuthExtension>
            } else {
                extension
            }
        });
        build_auth_stack(&self.resolved_auth_host(), enterprise, Arc::new(community))
            .map_err(|error| anyhow::anyhow!("auth stack composition failed: {error}"))
    }
}

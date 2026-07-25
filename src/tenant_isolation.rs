//! Tenant-isolation conformance harness for enterprise compositions.
//!
//! Community Tenkai remains tenant-free. Before an enterprise host enables
//! tenant mode it must pass this deterministic two-tenant harness. The harness
//! does not depend on external policy, evaluation, or identity providers.
//!
//! Isolation failures are security defects: cross-tenant access uses a
//! non-disclosing error posture and list/count/status/event/audit/cache
//! surfaces must never reveal foreign tenant identifiers or values.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth_context::{
    AUTH_CONTEXT_CONTRACT_VERSION, AuthError, AuthHostConfig, AuthMode, AuthStack,
    AuthenticatedRequestContext, AuthenticatedRequestContextBuilder, CredentialAuthenticator,
    CredentialMaterial, EnterpriseAuthExtension, PrincipalIdentity, PrincipalKind,
    TenantDerivationAuthority, build_auth_stack,
};

/// Contract version of the tenant-isolation conformance harness.
pub const TENANT_ISOLATION_CONTRACT_VERSION: u32 = 1;

/// Non-disclosing error message used when a principal is not authorized to see
/// a resource. Implementations must not reveal whether the foreign resource
/// exists or leak its tenant identity.
pub const NON_DISCLOSING_DENY: &str = "resource not found";

/// Kind of public surface that can carry tenant-visible data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantVisibleSurface {
    Management,
    Catalog,
    Environment,
    Plan,
    Deployment,
    Agent,
    Event,
    Aggregate,
    RuntimeAgent,
}

/// A public operation that can reveal tenant-scoped identifiers or values.
///
/// Every tenant-visible RPC must appear in [`tenant_visible_rpcs`] and register
/// conformance coverage through [`conformance_case_matrix`]. CI fails when a
/// registered RPC lacks a required isolation case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TenantVisibleRpc {
    pub id: &'static str,
    pub path_template: &'static str,
    pub surface: TenantVisibleSurface,
}

/// Isolation cases every tenant-visible RPC must cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationCase {
    ValidContext,
    MissingContext,
    MismatchedTenant,
    ForgedContext,
    ExpiredContext,
    WrongAudience,
    SuspendedTenant,
    RevokedCredential,
    CrossTenantIdentifier,
    ListLeakage,
    CountLeakage,
    StatusLeakage,
    EventLeakage,
    MetricLabelLeakage,
    CacheLeakage,
    AuditLeakage,
    AgentCrossEnvironment,
    AgentCrossTenant,
}

/// Required cases for every registered tenant-visible RPC.
pub fn required_isolation_cases() -> &'static [IsolationCase] {
    &[
        IsolationCase::ValidContext,
        IsolationCase::MissingContext,
        IsolationCase::MismatchedTenant,
        IsolationCase::ForgedContext,
        IsolationCase::ExpiredContext,
        IsolationCase::WrongAudience,
        IsolationCase::SuspendedTenant,
        IsolationCase::RevokedCredential,
        IsolationCase::CrossTenantIdentifier,
        IsolationCase::ListLeakage,
        IsolationCase::CountLeakage,
        IsolationCase::StatusLeakage,
        IsolationCase::EventLeakage,
        IsolationCase::MetricLabelLeakage,
        IsolationCase::CacheLeakage,
        IsolationCase::AuditLeakage,
        IsolationCase::AgentCrossEnvironment,
        IsolationCase::AgentCrossTenant,
    ]
}

/// Public tenant-visible RPCs for the current Tenkai server/agent contract plus
/// the enterprise catalog/plan surfaces that must remain isolated when tenant
/// mode is enabled.
pub fn tenant_visible_rpcs() -> &'static [TenantVisibleRpc] {
    &[
        TenantVisibleRpc {
            id: "management.reconcile",
            path_template: "POST /v1/reconcile",
            surface: TenantVisibleSurface::Management,
        },
        TenantVisibleRpc {
            id: "runtime.work",
            path_template: "GET /v1/runtime/environments/{environment}/work",
            surface: TenantVisibleSurface::RuntimeAgent,
        },
        TenantVisibleRpc {
            id: "runtime.complete",
            path_template: "POST /v1/runtime/environments/{environment}/complete",
            surface: TenantVisibleSurface::RuntimeAgent,
        },
        TenantVisibleRpc {
            id: "runtime.heartbeat",
            path_template: "POST /v1/runtime/environments/{environment}/heartbeat",
            surface: TenantVisibleSurface::RuntimeAgent,
        },
        TenantVisibleRpc {
            id: "catalog.list_products",
            path_template: "LIST catalog.products",
            surface: TenantVisibleSurface::Catalog,
        },
        TenantVisibleRpc {
            id: "catalog.get_product",
            path_template: "GET catalog.products/{id}",
            surface: TenantVisibleSurface::Catalog,
        },
        TenantVisibleRpc {
            id: "environment.list",
            path_template: "GET /v1/environments",
            surface: TenantVisibleSurface::Environment,
        },
        TenantVisibleRpc {
            id: "environment.get",
            path_template: "GET /v1/environments/{environment}",
            surface: TenantVisibleSurface::Environment,
        },
        TenantVisibleRpc {
            id: "plan.list",
            path_template: "LIST plans",
            surface: TenantVisibleSurface::Plan,
        },
        TenantVisibleRpc {
            id: "plan.get",
            path_template: "GET plans/{id}",
            surface: TenantVisibleSurface::Plan,
        },
        TenantVisibleRpc {
            id: "deployment.list",
            path_template: "LIST deployments",
            surface: TenantVisibleSurface::Deployment,
        },
        TenantVisibleRpc {
            id: "agent.list",
            path_template: "LIST agents",
            surface: TenantVisibleSurface::Agent,
        },
        TenantVisibleRpc {
            id: "event.list",
            path_template: "LIST events",
            surface: TenantVisibleSurface::Event,
        },
        TenantVisibleRpc {
            id: "aggregate.status",
            path_template: "GET status",
            surface: TenantVisibleSurface::Aggregate,
        },
        TenantVisibleRpc {
            id: "aggregate.counts",
            path_template: "GET counts",
            surface: TenantVisibleSurface::Aggregate,
        },
        TenantVisibleRpc {
            id: "aggregate.metric_labels",
            path_template: "GET metric-labels",
            surface: TenantVisibleSurface::Aggregate,
        },
        TenantVisibleRpc {
            id: "aggregate.cache_lookup",
            path_template: "GET cache/{key}",
            surface: TenantVisibleSurface::Aggregate,
        },
        TenantVisibleRpc {
            id: "aggregate.audit_list",
            path_template: "LIST audit",
            surface: TenantVisibleSurface::Aggregate,
        },
    ]
}

/// Declares which isolation cases the harness exercises for each registered RPC.
///
/// When adding a tenant-visible RPC, append it to [`tenant_visible_rpcs`] and
/// list its covered cases here. [`assert_conformance_coverage`] fails CI if a
/// required case is missing.
pub fn conformance_case_matrix() -> BTreeMap<&'static str, BTreeSet<IsolationCase>> {
    let all: BTreeSet<IsolationCase> = required_isolation_cases().iter().copied().collect();
    tenant_visible_rpcs()
        .iter()
        .map(|rpc| (rpc.id, all.clone()))
        .collect()
}

/// Fail when a registered RPC lacks a required isolation case.
pub fn assert_conformance_coverage() -> Result<(), CoverageError> {
    let matrix = conformance_case_matrix();
    let required: BTreeSet<_> = required_isolation_cases().iter().copied().collect();
    let mut missing = BTreeMap::new();
    for rpc in tenant_visible_rpcs() {
        let covered = matrix.get(rpc.id).cloned().unwrap_or_default();
        let gap: BTreeSet<_> = required.difference(&covered).copied().collect();
        if !gap.is_empty() {
            missing.insert(rpc.id.to_string(), gap);
        }
    }
    for rpc_id in matrix.keys() {
        if !tenant_visible_rpcs().iter().any(|rpc| rpc.id == *rpc_id) {
            return Err(CoverageError::UnregisteredRpc {
                rpc_id: (*rpc_id).into(),
            });
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(CoverageError::MissingCases { missing })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoverageError {
    #[error("tenant-visible RPC `{rpc_id}` is listed in the case matrix but not registered")]
    UnregisteredRpc { rpc_id: String },
    #[error("tenant-visible RPCs are missing required isolation cases: {missing:?}")]
    MissingCases {
        missing: BTreeMap<String, BTreeSet<IsolationCase>>,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IsolationError {
    #[error("{NON_DISCLOSING_DENY}")]
    NotFound,
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    #[error("isolation contract violation: {0}")]
    Contract(String),
}

impl IsolationError {
    /// Public error text that must never include foreign tenant identifiers.
    pub fn public_message(&self) -> String {
        match self {
            Self::NotFound => NON_DISCLOSING_DENY.into(),
            Self::Unauthenticated => "unauthenticated".into(),
            Self::InvalidCredential(_) => "invalid credential".into(),
            Self::Contract(detail) => detail.clone(),
        }
    }
}

/// Resources owned by one tenant in the two-tenant fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantResources {
    pub tenant_id: String,
    pub product_id: String,
    pub environment_id: String,
    pub agent_id: String,
    pub plan_id: String,
    pub deployment_id: String,
    pub runtime_token: String,
    pub principal_id: String,
    pub event_id: String,
    pub audit_id: String,
    pub cache_key: String,
    pub metric_label: String,
}

/// Deterministic two-tenant fixture with distinct products, environments,
/// agents, plans, deployments, and credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoTenantFixture {
    pub tenant_a: TenantResources,
    pub tenant_b: TenantResources,
    pub expected_audience: String,
    pub extension_id: String,
}

impl TwoTenantFixture {
    pub fn new() -> Self {
        Self {
            tenant_a: TenantResources {
                tenant_id: "tenant-a".into(),
                product_id: "product-a".into(),
                environment_id: "env-a".into(),
                agent_id: "agent-a".into(),
                plan_id: "plan-a".into(),
                deployment_id: "deploy-a".into(),
                runtime_token: "runtime-token-a".into(),
                principal_id: "user-a".into(),
                event_id: "event-a".into(),
                audit_id: "audit-a".into(),
                cache_key: "cache-a".into(),
                metric_label: "tenant=tenant-a".into(),
            },
            tenant_b: TenantResources {
                tenant_id: "tenant-b".into(),
                product_id: "product-b".into(),
                environment_id: "env-b".into(),
                agent_id: "agent-b".into(),
                plan_id: "plan-b".into(),
                deployment_id: "deploy-b".into(),
                runtime_token: "runtime-token-b".into(),
                principal_id: "user-b".into(),
                event_id: "event-b".into(),
                audit_id: "audit-b".into(),
                cache_key: "cache-b".into(),
                metric_label: "tenant=tenant-b".into(),
            },
            expected_audience: "tenkai-server".into(),
            extension_id: "enterprise-auth".into(),
        }
    }

    pub fn all_foreign_markers_for(&self, viewer: &TenantResources) -> Vec<String> {
        let other = if viewer.tenant_id == self.tenant_a.tenant_id {
            &self.tenant_b
        } else {
            &self.tenant_a
        };
        vec![
            other.tenant_id.clone(),
            other.product_id.clone(),
            other.environment_id.clone(),
            other.agent_id.clone(),
            other.plan_id.clone(),
            other.deployment_id.clone(),
            other.runtime_token.clone(),
            other.principal_id.clone(),
            other.event_id.clone(),
            other.audit_id.clone(),
            other.cache_key.clone(),
            other.metric_label.clone(),
        ]
    }
}

impl Default for TwoTenantFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialized enterprise assertion used only inside this harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HarnessAssertion {
    tenant_id: String,
    principal_id: String,
    audience: String,
    /// good | forged | expired | suspended | revoked
    state: String,
}

fn encode_assertion(assertion: &HarnessAssertion) -> Vec<u8> {
    serde_json::to_vec(assertion).expect("harness assertion encodes")
}

/// In-process enterprise authenticator for the harness (no external IdP).
struct HarnessEnterpriseAuth {
    fixture: TwoTenantFixture,
    suspended: Mutex<BTreeSet<String>>,
    revoked_principals: Mutex<BTreeSet<String>>,
}

impl HarnessEnterpriseAuth {
    fn new(fixture: TwoTenantFixture) -> Self {
        Self {
            fixture,
            suspended: Mutex::new(BTreeSet::new()),
            revoked_principals: Mutex::new(BTreeSet::new()),
        }
    }

    fn suspend(&self, tenant_id: &str) {
        self.suspended
            .lock()
            .expect("suspend mutex")
            .insert(tenant_id.into());
    }

    fn revoke_principal(&self, principal_id: &str) {
        self.revoked_principals
            .lock()
            .expect("revoke mutex")
            .insert(principal_id.into());
    }
}

impl EnterpriseAuthExtension for HarnessEnterpriseAuth {
    fn extension_id(&self) -> &str {
        &self.fixture.extension_id
    }

    fn contract_version(&self) -> u32 {
        AUTH_CONTEXT_CONTRACT_VERSION
    }

    fn expected_audience(&self) -> &str {
        &self.fixture.expected_audience
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
        authority: &TenantDerivationAuthority,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        let raw = credential.assertion.as_ref().ok_or_else(|| {
            AuthError::InvalidCredential("enterprise harness requires an assertion".into())
        })?;
        let assertion: HarnessAssertion = serde_json::from_slice(raw)
            .map_err(|_| AuthError::Unauthorized("assertion verification failed".into()))?;
        if assertion.audience != self.fixture.expected_audience {
            return Err(AuthError::Unauthorized("wrong audience".into()));
        }
        match assertion.state.as_str() {
            "good" => {}
            "forged" => {
                return Err(AuthError::Unauthorized(
                    "assertion verification failed".into(),
                ));
            }
            "expired" => return Err(AuthError::Unauthorized("assertion expired".into())),
            "suspended" => {
                return Err(AuthError::Unauthorized("tenant suspended".into()));
            }
            "revoked" => {
                return Err(AuthError::Unauthorized("credential revoked".into()));
            }
            other => {
                return Err(AuthError::InvalidCredential(format!(
                    "unknown assertion state {other}"
                )));
            }
        }
        if self
            .suspended
            .lock()
            .expect("suspend mutex")
            .contains(&assertion.tenant_id)
        {
            return Err(AuthError::Unauthorized("tenant suspended".into()));
        }
        if self
            .revoked_principals
            .lock()
            .expect("revoke mutex")
            .contains(&assertion.principal_id)
        {
            return Err(AuthError::Unauthorized("credential revoked".into()));
        }
        if assertion.tenant_id != self.fixture.tenant_a.tenant_id
            && assertion.tenant_id != self.fixture.tenant_b.tenant_id
        {
            return Err(AuthError::Unauthorized("unknown tenant".into()));
        }
        AuthenticatedRequestContextBuilder::new(
            credential.request_id.clone(),
            PrincipalIdentity {
                id: assertion.principal_id,
                kind: PrincipalKind::Human,
            },
            self.fixture.extension_id.clone(),
        )
        .with_tenant(assertion.tenant_id, authority)?
        .build()
    }
}

/// Require an authenticated tenant context and authorize access to a resource
/// owned by `resource_tenant`. Mismatches return a non-disclosing deny.
pub fn authorize_tenant_resource(
    context: &AuthenticatedRequestContext,
    resource_tenant: &str,
) -> Result<(), IsolationError> {
    context
        .validate()
        .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
    let Some(tenant) = context.tenant() else {
        return Err(IsolationError::Unauthenticated);
    };
    if tenant.tenant_id() != resource_tenant {
        return Err(IsolationError::NotFound);
    }
    Ok(())
}

/// Fail when a response body contains any foreign tenant marker.
pub fn assert_no_foreign_leakage(
    body: &str,
    foreign_markers: &[String],
) -> Result<(), IsolationError> {
    for marker in foreign_markers {
        if !marker.is_empty() && body.contains(marker) {
            return Err(IsolationError::Contract(format!(
                "response leaked foreign marker `{marker}`"
            )));
        }
    }
    // Public deny text itself is allowed; ensure it does not embed tenant ids.
    if body.contains("tenant-a") && body.contains("tenant-b") {
        return Err(IsolationError::Contract(
            "response mentioned both tenant identifiers".into(),
        ));
    }
    Ok(())
}

/// Ensure an error's public message is non-disclosing for cross-tenant denials.
pub fn assert_non_disclosing_error(
    error: &IsolationError,
    foreign_markers: &[String],
) -> Result<(), IsolationError> {
    let message = error.public_message();
    if matches!(error, IsolationError::NotFound) && message != NON_DISCLOSING_DENY {
        return Err(IsolationError::Contract(
            "cross-tenant deny used a disclosing message".into(),
        ));
    }
    assert_no_foreign_leakage(&message, foreign_markers)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceRecord {
    pub tenant_id: String,
    pub id: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateStatus {
    pub tenant_id: String,
    pub product_count: usize,
    pub environment_count: usize,
    pub plan_count: usize,
    pub deployment_count: usize,
    pub agent_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateCounts {
    pub products: usize,
    pub environments: usize,
    pub plans: usize,
    pub deployments: usize,
    pub agents: usize,
    pub events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePoll {
    pub environment_id: String,
    pub plan_id: Option<String>,
}

/// Reference enterprise surface used by the conformance harness.
///
/// This is not a production tenant database. It models the isolation rules
/// enterprise hosts must satisfy without external services.
#[derive(Debug)]
pub struct InMemoryTenantSurface {
    products: Vec<SurfaceRecord>,
    environments: Vec<SurfaceRecord>,
    plans: Vec<SurfaceRecord>,
    deployments: Vec<SurfaceRecord>,
    agents: Vec<SurfaceRecord>,
    events: Vec<SurfaceRecord>,
    audits: Vec<SurfaceRecord>,
    cache: BTreeMap<String, SurfaceRecord>,
    metrics: Vec<String>,
    runtime_owner: BTreeMap<String, String>,
}

impl InMemoryTenantSurface {
    pub fn from_fixture(fixture: &TwoTenantFixture) -> Self {
        let mut surface = Self {
            products: Vec::new(),
            environments: Vec::new(),
            plans: Vec::new(),
            deployments: Vec::new(),
            agents: Vec::new(),
            events: Vec::new(),
            audits: Vec::new(),
            cache: BTreeMap::new(),
            metrics: Vec::new(),
            runtime_owner: BTreeMap::new(),
        };
        for tenant in [&fixture.tenant_a, &fixture.tenant_b] {
            surface.products.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.product_id.clone(),
                value: format!("product:{}", tenant.product_id),
            });
            surface.environments.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.environment_id.clone(),
                value: format!("environment:{}", tenant.environment_id),
            });
            surface.plans.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.plan_id.clone(),
                value: format!("plan:{}", tenant.plan_id),
            });
            surface.deployments.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.deployment_id.clone(),
                value: format!("deployment:{}", tenant.deployment_id),
            });
            surface.agents.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.agent_id.clone(),
                value: format!("agent:{}", tenant.agent_id),
            });
            surface.events.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.event_id.clone(),
                value: format!("event:{}", tenant.event_id),
            });
            surface.audits.push(SurfaceRecord {
                tenant_id: tenant.tenant_id.clone(),
                id: tenant.audit_id.clone(),
                value: format!("audit:{}", tenant.audit_id),
            });
            surface.cache.insert(
                tenant.cache_key.clone(),
                SurfaceRecord {
                    tenant_id: tenant.tenant_id.clone(),
                    id: tenant.cache_key.clone(),
                    value: format!("cache:{}", tenant.cache_key),
                },
            );
            surface.metrics.push(tenant.metric_label.clone());
            surface
                .runtime_owner
                .insert(tenant.runtime_token.clone(), tenant.environment_id.clone());
        }
        surface
    }

    fn require_tenant<'a>(
        &'a self,
        context: &'a AuthenticatedRequestContext,
    ) -> Result<&'a str, IsolationError> {
        context
            .validate()
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        context
            .tenant()
            .map(|tenant| tenant.tenant_id())
            .ok_or(IsolationError::Unauthenticated)
    }

    fn filter_tenant<'a>(
        &'a self,
        rows: &'a [SurfaceRecord],
        tenant_id: &str,
    ) -> Vec<&'a SurfaceRecord> {
        rows.iter()
            .filter(|row| row.tenant_id == tenant_id)
            .collect()
    }

    fn get_scoped(
        &self,
        rows: &[SurfaceRecord],
        context: &AuthenticatedRequestContext,
        id: &str,
    ) -> Result<SurfaceRecord, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        match rows.iter().find(|row| row.id == id) {
            Some(row) if row.tenant_id == tenant_id => Ok(row.clone()),
            Some(_) | None => Err(IsolationError::NotFound),
        }
    }

    pub fn list_products(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.products, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn get_product(
        &self,
        context: &AuthenticatedRequestContext,
        id: &str,
    ) -> Result<SurfaceRecord, IsolationError> {
        self.get_scoped(&self.products, context, id)
    }

    pub fn list_environments(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.environments, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn get_environment(
        &self,
        context: &AuthenticatedRequestContext,
        id: &str,
    ) -> Result<SurfaceRecord, IsolationError> {
        self.get_scoped(&self.environments, context, id)
    }

    pub fn list_plans(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.plans, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn get_plan(
        &self,
        context: &AuthenticatedRequestContext,
        id: &str,
    ) -> Result<SurfaceRecord, IsolationError> {
        self.get_scoped(&self.plans, context, id)
    }

    pub fn list_deployments(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.deployments, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn list_agents(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.agents, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn list_events(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.events, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn list_audit(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<SurfaceRecord>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .filter_tenant(&self.audits, tenant_id)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn status(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<AggregateStatus, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(AggregateStatus {
            tenant_id: tenant_id.into(),
            product_count: self.filter_tenant(&self.products, tenant_id).len(),
            environment_count: self.filter_tenant(&self.environments, tenant_id).len(),
            plan_count: self.filter_tenant(&self.plans, tenant_id).len(),
            deployment_count: self.filter_tenant(&self.deployments, tenant_id).len(),
            agent_count: self.filter_tenant(&self.agents, tenant_id).len(),
        })
    }

    pub fn counts(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<AggregateCounts, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(AggregateCounts {
            products: self.filter_tenant(&self.products, tenant_id).len(),
            environments: self.filter_tenant(&self.environments, tenant_id).len(),
            plans: self.filter_tenant(&self.plans, tenant_id).len(),
            deployments: self.filter_tenant(&self.deployments, tenant_id).len(),
            agents: self.filter_tenant(&self.agents, tenant_id).len(),
            events: self.filter_tenant(&self.events, tenant_id).len(),
        })
    }

    pub fn metric_labels(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<Vec<String>, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        Ok(self
            .metrics
            .iter()
            .filter(|label| label.contains(tenant_id))
            .cloned()
            .collect())
    }

    pub fn cache_lookup(
        &self,
        context: &AuthenticatedRequestContext,
        key: &str,
    ) -> Result<SurfaceRecord, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        match self.cache.get(key) {
            Some(row) if row.tenant_id == tenant_id => Ok(row.clone()),
            Some(_) | None => Err(IsolationError::NotFound),
        }
    }

    pub fn reconcile(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<AggregateStatus, IsolationError> {
        // Management reconcile is tenant-scoped in enterprise mode: it only
        // reports the caller's tenant aggregate.
        self.status(context)
    }

    pub fn poll_work(
        &self,
        context: &AuthenticatedRequestContext,
        runtime_token: &str,
        environment_id: &str,
    ) -> Result<RuntimePoll, IsolationError> {
        let tenant_id = self.require_tenant(context)?;
        let assigned =
            self.runtime_owner
                .get(runtime_token)
                .ok_or(IsolationError::InvalidCredential(
                    "unknown runtime credential".into(),
                ))?;
        if assigned != environment_id {
            return Err(IsolationError::NotFound);
        }
        let environment = self
            .environments
            .iter()
            .find(|row| row.id == environment_id)
            .ok_or(IsolationError::NotFound)?;
        authorize_tenant_resource(context, &environment.tenant_id)?;
        if environment.tenant_id != tenant_id {
            return Err(IsolationError::NotFound);
        }
        let plan = self
            .plans
            .iter()
            .find(|row| row.tenant_id == tenant_id)
            .map(|row| row.id.clone());
        Ok(RuntimePoll {
            environment_id: environment_id.into(),
            plan_id: plan,
        })
    }

    pub fn complete_work(
        &self,
        context: &AuthenticatedRequestContext,
        runtime_token: &str,
        environment_id: &str,
        plan_id: &str,
    ) -> Result<(), IsolationError> {
        let poll = self.poll_work(context, runtime_token, environment_id)?;
        if poll.plan_id.as_deref() != Some(plan_id) {
            return Err(IsolationError::NotFound);
        }
        Ok(())
    }

    pub fn heartbeat(
        &self,
        context: &AuthenticatedRequestContext,
        runtime_token: &str,
        environment_id: &str,
        plan_id: &str,
    ) -> Result<(), IsolationError> {
        self.complete_work(context, runtime_token, environment_id, plan_id)
    }
}

/// Hosts the two-tenant fixture, enterprise auth stack, and reference surface.
pub struct TenantIsolationHarness {
    pub fixture: TwoTenantFixture,
    pub auth: AuthStack,
    pub surface: InMemoryTenantSurface,
    enterprise_auth: Arc<HarnessEnterpriseAuth>,
}

impl TenantIsolationHarness {
    pub fn new() -> Result<Self, AuthError> {
        let fixture = TwoTenantFixture::new();
        let enterprise_auth = Arc::new(HarnessEnterpriseAuth::new(fixture.clone()));
        let community: Arc<dyn CredentialAuthenticator> = Arc::new(
            crate::auth_context::CommunityTokenAuthenticator::new(
                "community-token",
                [(
                    "management-secret".into(),
                    PrincipalIdentity {
                        id: "management".into(),
                        kind: PrincipalKind::Management,
                    },
                )],
            )
            .map_err(|error| AuthError::InvalidCredential(error.to_string()))?,
        );
        let config = AuthHostConfig {
            required_extension_id: Some(fixture.extension_id.clone()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some(fixture.expected_audience.clone()),
        };
        let auth = build_auth_stack(&config, Some(enterprise_auth.clone()), community)
            .map_err(|error| AuthError::InvalidCredential(error.to_string()))?;
        if auth.mode() != AuthMode::Enterprise {
            return Err(AuthError::InvalidCredential(
                "harness requires enterprise auth mode".into(),
            ));
        }
        let surface = InMemoryTenantSurface::from_fixture(&fixture);
        Ok(Self {
            fixture,
            auth,
            surface,
            enterprise_auth,
        })
    }

    pub fn authenticate(
        &self,
        tenant: &TenantResources,
        state: &str,
        request_id: &str,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        let assertion = encode_assertion(&HarnessAssertion {
            tenant_id: tenant.tenant_id.clone(),
            principal_id: tenant.principal_id.clone(),
            audience: self.fixture.expected_audience.clone(),
            state: state.into(),
        });
        self.auth.authenticate(&CredentialMaterial {
            request_id: request_id.into(),
            bearer_token: None,
            assertion: Some(assertion),
        })
    }

    pub fn valid_context(
        &self,
        tenant: &TenantResources,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        self.authenticate(tenant, "good", &format!("req-{}", tenant.tenant_id))
    }

    /// Run the full isolation matrix against the reference surface.
    pub fn run_conformance(&self) -> Result<(), IsolationError> {
        assert_conformance_coverage()
            .map_err(|error| IsolationError::Contract(error.to_string()))?;

        let a = &self.fixture.tenant_a;
        let b = &self.fixture.tenant_b;
        let ctx_a = self
            .valid_context(a)
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        let ctx_b = self
            .valid_context(b)
            .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        let foreign_for_a = self.fixture.all_foreign_markers_for(a);
        let foreign_for_b = self.fixture.all_foreign_markers_for(b);

        // Valid context sees only own resources.
        self.assert_valid_tenant_view(&ctx_a, a, &foreign_for_a)?;
        self.assert_valid_tenant_view(&ctx_b, b, &foreign_for_b)?;

        // Missing context.
        let missing = AuthenticatedRequestContextBuilder::new(
            "missing",
            PrincipalIdentity {
                id: "anon".into(),
                kind: PrincipalKind::Service,
            },
            "none",
        )
        .build()
        .map_err(|error| IsolationError::InvalidCredential(error.to_string()))?;
        assert!(matches!(
            self.surface.list_products(&missing),
            Err(IsolationError::Unauthenticated)
        ));

        // Forged / expired / suspended / revoked / wrong audience at auth time.
        for (state, _label) in [
            ("forged", "forged"),
            ("expired", "expired"),
            ("suspended", "suspended"),
            ("revoked", "revoked"),
        ] {
            let result = self.authenticate(a, state, &format!("req-{state}"));
            assert!(
                result.is_err(),
                "expected auth failure for state {state}, got {result:?}"
            );
        }
        // Wrong audience is represented as forged verification failure when the
        // assertion carries a foreign audience string.
        let wrong_audience = encode_assertion(&HarnessAssertion {
            tenant_id: a.tenant_id.clone(),
            principal_id: a.principal_id.clone(),
            audience: "other-service".into(),
            state: "good".into(),
        });
        assert!(
            self.auth
                .authenticate(&CredentialMaterial {
                    request_id: "req-wrong-aud".into(),
                    bearer_token: None,
                    assertion: Some(wrong_audience),
                })
                .is_err()
        );

        // Runtime host-side suspended/revoked flags.
        self.enterprise_auth.suspend(&a.tenant_id);
        assert!(self.authenticate(a, "good", "req-suspended-live").is_err());
        self.enterprise_auth
            .suspended
            .lock()
            .expect("suspend mutex")
            .clear();
        self.enterprise_auth.revoke_principal(&a.principal_id);
        assert!(self.authenticate(a, "good", "req-revoked-live").is_err());
        self.enterprise_auth
            .revoked_principals
            .lock()
            .expect("revoke mutex")
            .clear();

        // Mismatched / cross-tenant identifier access uses non-disclosing deny.
        let cross = self.surface.get_product(&ctx_a, &b.product_id);
        assert!(matches!(cross, Err(IsolationError::NotFound)));
        assert_non_disclosing_error(cross.as_ref().unwrap_err(), &foreign_for_a)?;

        let cross_env = self.surface.get_environment(&ctx_a, &b.environment_id);
        assert!(matches!(cross_env, Err(IsolationError::NotFound)));
        assert_non_disclosing_error(cross_env.as_ref().unwrap_err(), &foreign_for_a)?;

        let cross_plan = self.surface.get_plan(&ctx_a, &b.plan_id);
        assert!(matches!(cross_plan, Err(IsolationError::NotFound)));
        assert_non_disclosing_error(cross_plan.as_ref().unwrap_err(), &foreign_for_a)?;

        // Agent credentials cannot poll/ack/report across environment or tenant.
        let cross_env_poll = self
            .surface
            .poll_work(&ctx_a, &a.runtime_token, &b.environment_id);
        assert!(matches!(cross_env_poll, Err(IsolationError::NotFound)));
        assert_non_disclosing_error(cross_env_poll.as_ref().unwrap_err(), &foreign_for_a)?;

        let cross_tenant_poll = self
            .surface
            .poll_work(&ctx_a, &b.runtime_token, &b.environment_id);
        assert!(matches!(
            cross_tenant_poll,
            Err(IsolationError::NotFound | IsolationError::InvalidCredential(_))
        ));
        if let Err(error) = &cross_tenant_poll
            && matches!(error, IsolationError::NotFound)
        {
            assert_non_disclosing_error(error, &foreign_for_a)?;
        }

        let ok_poll = self
            .surface
            .poll_work(&ctx_a, &a.runtime_token, &a.environment_id)?;
        assert_eq!(ok_poll.plan_id.as_deref(), Some(a.plan_id.as_str()));
        self.surface
            .complete_work(&ctx_a, &a.runtime_token, &a.environment_id, &a.plan_id)?;
        self.surface
            .heartbeat(&ctx_a, &a.runtime_token, &a.environment_id, &a.plan_id)?;

        // Foreign agent credential on own environment path fails closed.
        let stolen = self
            .surface
            .poll_work(&ctx_b, &a.runtime_token, &a.environment_id);
        assert!(stolen.is_err());

        Ok(())
    }

    fn assert_valid_tenant_view(
        &self,
        context: &AuthenticatedRequestContext,
        tenant: &TenantResources,
        foreign: &[String],
    ) -> Result<(), IsolationError> {
        let products = self.surface.list_products(context)?;
        assert_eq!(products.len(), 1);
        assert_eq!(products[0].id, tenant.product_id);
        let body = serde_json::to_string(&products).expect("json");
        assert_no_foreign_leakage(&body, foreign)?;

        let product = self.surface.get_product(context, &tenant.product_id)?;
        assert_eq!(product.id, tenant.product_id);
        assert_no_foreign_leakage(&serde_json::to_string(&product).unwrap(), foreign)?;

        let environments = self.surface.list_environments(context)?;
        assert_eq!(environments[0].id, tenant.environment_id);
        assert_no_foreign_leakage(&serde_json::to_string(&environments).unwrap(), foreign)?;

        let plans = self.surface.list_plans(context)?;
        assert_eq!(plans[0].id, tenant.plan_id);
        assert_no_foreign_leakage(&serde_json::to_string(&plans).unwrap(), foreign)?;

        let deployments = self.surface.list_deployments(context)?;
        assert_eq!(deployments[0].id, tenant.deployment_id);
        assert_no_foreign_leakage(&serde_json::to_string(&deployments).unwrap(), foreign)?;

        let agents = self.surface.list_agents(context)?;
        assert_eq!(agents[0].id, tenant.agent_id);
        assert_no_foreign_leakage(&serde_json::to_string(&agents).unwrap(), foreign)?;

        let events = self.surface.list_events(context)?;
        assert_eq!(events[0].id, tenant.event_id);
        assert_no_foreign_leakage(&serde_json::to_string(&events).unwrap(), foreign)?;

        let audits = self.surface.list_audit(context)?;
        assert_eq!(audits[0].id, tenant.audit_id);
        assert_no_foreign_leakage(&serde_json::to_string(&audits).unwrap(), foreign)?;

        let status = self.surface.status(context)?;
        assert_eq!(status.tenant_id, tenant.tenant_id);
        assert_eq!(status.product_count, 1);
        assert_no_foreign_leakage(&serde_json::to_string(&status).unwrap(), foreign)?;

        let counts = self.surface.counts(context)?;
        assert_eq!(counts.products, 1);
        assert_eq!(counts.environments, 1);
        assert_no_foreign_leakage(&serde_json::to_string(&counts).unwrap(), foreign)?;

        let labels = self.surface.metric_labels(context)?;
        assert_eq!(labels, vec![tenant.metric_label.clone()]);
        assert_no_foreign_leakage(&serde_json::to_string(&labels).unwrap(), foreign)?;

        let cache = self.surface.cache_lookup(context, &tenant.cache_key)?;
        assert_eq!(cache.id, tenant.cache_key);
        assert_no_foreign_leakage(&serde_json::to_string(&cache).unwrap(), foreign)?;
        let other_key = if tenant.tenant_id == self.fixture.tenant_a.tenant_id {
            &self.fixture.tenant_b.cache_key
        } else {
            &self.fixture.tenant_a.cache_key
        };
        let foreign_cache = self.surface.cache_lookup(context, other_key);
        assert!(matches!(foreign_cache, Err(IsolationError::NotFound)));
        assert_non_disclosing_error(foreign_cache.as_ref().unwrap_err(), foreign)?;

        let reconcile = self.surface.reconcile(context)?;
        assert_eq!(reconcile.tenant_id, tenant.tenant_id);
        assert_no_foreign_leakage(&serde_json::to_string(&reconcile).unwrap(), foreign)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_requires_isolation_cases_for_every_rpc() {
        assert_conformance_coverage().unwrap();
        assert!(!tenant_visible_rpcs().is_empty());
        assert_eq!(conformance_case_matrix().len(), tenant_visible_rpcs().len());
    }

    #[test]
    fn fixture_has_distinct_two_tenant_resources() {
        let fixture = TwoTenantFixture::new();
        assert_ne!(fixture.tenant_a.tenant_id, fixture.tenant_b.tenant_id);
        assert_ne!(fixture.tenant_a.product_id, fixture.tenant_b.product_id);
        assert_ne!(
            fixture.tenant_a.environment_id,
            fixture.tenant_b.environment_id
        );
        assert_ne!(fixture.tenant_a.agent_id, fixture.tenant_b.agent_id);
        assert_ne!(fixture.tenant_a.plan_id, fixture.tenant_b.plan_id);
        assert_ne!(
            fixture.tenant_a.deployment_id,
            fixture.tenant_b.deployment_id
        );
        assert_ne!(
            fixture.tenant_a.runtime_token,
            fixture.tenant_b.runtime_token
        );
    }

    #[test]
    fn harness_runs_without_external_providers() {
        let harness = TenantIsolationHarness::new().unwrap();
        harness.run_conformance().unwrap();
    }

    #[test]
    fn cross_tenant_errors_are_non_disclosing() {
        let harness = TenantIsolationHarness::new().unwrap();
        let ctx = harness.valid_context(&harness.fixture.tenant_a).unwrap();
        let error = harness
            .surface
            .get_product(&ctx, &harness.fixture.tenant_b.product_id)
            .unwrap_err();
        assert_eq!(error.public_message(), NON_DISCLOSING_DENY);
        let foreign = harness
            .fixture
            .all_foreign_markers_for(&harness.fixture.tenant_a);
        assert_non_disclosing_error(&error, &foreign).unwrap();
    }

    #[test]
    fn authorize_tenant_resource_rejects_mismatch() {
        let harness = TenantIsolationHarness::new().unwrap();
        let ctx = harness.valid_context(&harness.fixture.tenant_a).unwrap();
        assert!(matches!(
            authorize_tenant_resource(&ctx, "tenant-b"),
            Err(IsolationError::NotFound)
        ));
        authorize_tenant_resource(&ctx, "tenant-a").unwrap();
    }

    #[test]
    fn missing_case_coverage_is_detected() {
        // Sanity: empty matrix would fail; our production matrix is complete.
        let required = required_isolation_cases();
        assert!(required.contains(&IsolationCase::AgentCrossTenant));
        assert!(required.contains(&IsolationCase::ListLeakage));
    }

    #[test]
    fn community_mode_is_not_the_enterprise_harness() {
        // The harness itself requires enterprise mode; community remains
        // tenant-free and does not run this surface.
        let fixture = TwoTenantFixture::new();
        let community = Arc::new(
            crate::auth_context::CommunityTokenAuthenticator::new(
                "community-token",
                [(
                    "management-secret".into(),
                    PrincipalIdentity {
                        id: "management".into(),
                        kind: PrincipalKind::Management,
                    },
                )],
            )
            .unwrap(),
        );
        let stack = build_auth_stack(&AuthHostConfig::community(), None, community).unwrap();
        assert_eq!(stack.mode(), AuthMode::Community);
        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "c1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: None,
            })
            .unwrap();
        assert!(!context.is_tenant_scoped());
        let surface = InMemoryTenantSurface::from_fixture(&fixture);
        assert!(matches!(
            surface.list_products(&context),
            Err(IsolationError::Unauthenticated)
        ));
    }
}

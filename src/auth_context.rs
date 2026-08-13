//! Authenticated request context and enterprise auth-extension contracts.
//!
//! Tenkai remains authoritative for catalog, planning, reconciliation, and
//! execution state. Authentication adapters only derive principal identity and
//! optional tenant context from trusted credentials. Ordinary caller metadata
//! cannot select a tenant.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version of the authenticated-request-context contract.
pub const AUTH_CONTEXT_CONTRACT_VERSION: u32 = 1;

/// Transport credentials presented to an authenticator.
///
/// Deliberately omits any caller-selected tenant field. Tenant membership is
/// derived only after credential verification inside a trusted authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMaterial {
    pub request_id: String,
    pub bearer_token: Option<String>,
    /// Opaque enterprise assertion bytes (for example an audience-bound JWT).
    /// Interpreting this material is extension-owned, not Tenkai-core-owned.
    pub assertion: Option<Vec<u8>>,
}

impl CredentialMaterial {
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.request_id.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "request id must not be empty".into(),
            ));
        }
        if self
            .bearer_token
            .as_ref()
            .is_some_and(|t| t.trim().is_empty())
        {
            return Err(AuthError::InvalidCredential(
                "bearer token must not be empty when present".into(),
            ));
        }
        if self.assertion.as_ref().is_some_and(Vec::is_empty) {
            return Err(AuthError::InvalidCredential(
                "assertion must not be empty when present".into(),
            ));
        }
        if self.bearer_token.is_none() && self.assertion.is_none() {
            return Err(AuthError::InvalidCredential(
                "credential material must include a bearer token or assertion".into(),
            ));
        }
        Ok(())
    }
}

/// Capability that permits attaching tenant context to an authenticated request.
///
/// Only the auth host grants this when an enterprise extension is successfully
/// loaded at startup. Request handlers and ordinary application code never mint
/// it from caller metadata.
#[derive(Debug, Clone)]
pub struct TenantDerivationAuthority {
    extension_id: String,
}

impl TenantDerivationAuthority {
    pub fn new(extension_id: impl Into<String>) -> Self {
        Self {
            extension_id: extension_id.into(),
        }
    }

    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }
}

/// Optional tenant membership derived only by trusted authentication code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    tenant_id: String,
    extension_id: String,
}

impl TenantContext {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }
}

/// Authenticated principal identity, always present for an authorized call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalIdentity {
    pub id: String,
    pub kind: PrincipalKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Service,
    Runtime,
    Management,
}

/// Delivery-domain capability enforced after authentication.
///
/// Authentication proves identity; these capabilities authorize Tenkai
/// management use cases. Missing capabilities fail closed for gated routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryCapability {
    /// Read fleet/environment inspection surfaces.
    Read,
    /// Mutating management operations such as reconcile.
    Management,
}

/// Capabilities implied by a verified principal kind when no explicit delivery
/// capability claim is present.
///
/// Human and Runtime principals receive none unless an assertion carries an
/// explicit `tenkai_capabilities` claim (fail closed for management APIs).
pub fn default_delivery_capabilities(kind: PrincipalKind) -> BTreeSet<DeliveryCapability> {
    match kind {
        PrincipalKind::Management | PrincipalKind::Service => {
            BTreeSet::from([DeliveryCapability::Read, DeliveryCapability::Management])
        }
        PrincipalKind::Human | PrincipalKind::Runtime => BTreeSet::new(),
    }
}

/// Backend-neutral authenticated request context consumed by Tenkai use cases.
///
/// Principal identity is always set. Tenant context is optional and only present
/// when a trusted authenticator derived it under a startup-granted authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedRequestContext {
    pub contract_version: u32,
    pub request_id: String,
    pub principal: PrincipalIdentity,
    tenant: Option<TenantContext>,
    pub authenticator_id: String,
    /// Delivery-domain capabilities. Absent/empty means no management API use.
    #[serde(default)]
    delivery_capabilities: BTreeSet<DeliveryCapability>,
}

impl AuthenticatedRequestContext {
    pub fn tenant(&self) -> Option<&TenantContext> {
        self.tenant.as_ref()
    }

    pub fn is_tenant_scoped(&self) -> bool {
        self.tenant.is_some()
    }

    pub fn principal_id(&self) -> &str {
        &self.principal.id
    }

    pub fn delivery_capabilities(&self) -> &BTreeSet<DeliveryCapability> {
        &self.delivery_capabilities
    }

    pub fn has_delivery_capability(&self, required: DeliveryCapability) -> bool {
        match required {
            DeliveryCapability::Read => {
                self.delivery_capabilities
                    .contains(&DeliveryCapability::Read)
                    || self
                        .delivery_capabilities
                        .contains(&DeliveryCapability::Management)
            }
            DeliveryCapability::Management => self
                .delivery_capabilities
                .contains(&DeliveryCapability::Management),
        }
    }

    /// Fail closed when the authenticated principal lacks a delivery capability.
    pub fn require_delivery_capability(
        &self,
        required: DeliveryCapability,
    ) -> Result<(), AuthError> {
        self.validate()?;
        if self.has_delivery_capability(required) {
            Ok(())
        } else {
            Err(AuthError::Unauthorized(
                "insufficient delivery capability".into(),
            ))
        }
    }

    pub fn principal_kind_name(&self) -> &'static str {
        match self.principal.kind {
            PrincipalKind::Human => "human",
            PrincipalKind::Service => "service",
            PrincipalKind::Runtime => "runtime",
            PrincipalKind::Management => "management",
        }
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        if self.contract_version != AUTH_CONTEXT_CONTRACT_VERSION {
            return Err(AuthError::IncompatibleContract {
                found: self.contract_version,
                expected: AUTH_CONTEXT_CONTRACT_VERSION,
            });
        }
        if self.request_id.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "request id must not be empty".into(),
            ));
        }
        if self.principal.id.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "principal id must not be empty".into(),
            ));
        }
        if self.authenticator_id.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "authenticator id must not be empty".into(),
            ));
        }
        if let Some(tenant) = &self.tenant {
            if tenant.tenant_id.trim().is_empty() {
                return Err(AuthError::InvalidCredential(
                    "tenant id must not be empty when tenant context is present".into(),
                ));
            }
            if tenant.extension_id.trim().is_empty() {
                return Err(AuthError::InvalidCredential(
                    "tenant extension id must not be empty when tenant context is present".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Builder used only by trusted authenticators after credential verification.
#[derive(Debug)]
pub struct AuthenticatedRequestContextBuilder {
    request_id: String,
    principal: PrincipalIdentity,
    authenticator_id: String,
    tenant: Option<TenantContext>,
    delivery_capabilities: BTreeSet<DeliveryCapability>,
}

impl AuthenticatedRequestContextBuilder {
    pub fn new(
        request_id: impl Into<String>,
        principal: PrincipalIdentity,
        authenticator_id: impl Into<String>,
    ) -> Self {
        let delivery_capabilities = default_delivery_capabilities(principal.kind);
        Self {
            request_id: request_id.into(),
            principal,
            authenticator_id: authenticator_id.into(),
            tenant: None,
            delivery_capabilities,
        }
    }

    /// Attach tenant context. Requires a startup-granted authority; cannot be
    /// satisfied by ordinary caller-selected metadata.
    pub fn with_tenant(
        mut self,
        tenant_id: impl Into<String>,
        authority: &TenantDerivationAuthority,
    ) -> Result<Self, AuthError> {
        let tenant_id = tenant_id.into();
        if tenant_id.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "tenant id must not be empty".into(),
            ));
        }
        self.tenant = Some(TenantContext {
            tenant_id,
            extension_id: authority.extension_id.clone(),
        });
        Ok(self)
    }

    /// Replace delivery capabilities with an explicit verified set.
    ///
    /// Authenticators that see an explicit capability claim must call this so
    /// missing claims are not silently widened from principal kind defaults.
    pub fn with_delivery_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = DeliveryCapability>,
    ) -> Self {
        self.delivery_capabilities = capabilities.into_iter().collect();
        self
    }

    pub fn build(self) -> Result<AuthenticatedRequestContext, AuthError> {
        let context = AuthenticatedRequestContext {
            contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            request_id: self.request_id,
            principal: self.principal,
            tenant: self.tenant,
            authenticator_id: self.authenticator_id,
            delivery_capabilities: self.delivery_capabilities,
        };
        context.validate()?;
        Ok(context)
    }
}

/// Object-safe authenticator used by hosts to derive request context.
pub trait CredentialAuthenticator: Send + Sync {
    fn authenticator_id(&self) -> &str;

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, AuthError>;
}

/// Enterprise auth extension (assertion verification adapter).
///
/// Extensions verify short-lived, audience-bound credentials and may attach
/// tenant context using the host-granted authority. They never own catalog,
/// planning, reconciliation, or execution state.
pub trait EnterpriseAuthExtension: Send + Sync {
    fn extension_id(&self) -> &str;

    fn contract_version(&self) -> u32;

    /// Expected audience for assertions this extension accepts.
    fn expected_audience(&self) -> &str;

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
        authority: &TenantDerivationAuthority,
    ) -> Result<AuthenticatedRequestContext, AuthError>;
}

/// Host configuration for composing community or enterprise authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHostConfig {
    /// When set, startup fails unless an extension with this id loads.
    pub required_extension_id: Option<String>,
    pub expected_contract_version: u32,
    /// Audience the enterprise extension must accept (when required or present).
    pub expected_audience: Option<String>,
}

impl Default for AuthHostConfig {
    fn default() -> Self {
        Self {
            required_extension_id: None,
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: None,
        }
    }
}

impl AuthHostConfig {
    /// Community host: no enterprise extension required or expected.
    pub fn community() -> Self {
        Self::default()
    }
}

/// Resolved authentication stack for a host process.
#[derive(Clone)]
pub struct AuthStack {
    authenticator: Arc<dyn CredentialAuthenticator>,
    tenant_authority: Option<TenantDerivationAuthority>,
    mode: AuthMode,
}

impl std::fmt::Debug for AuthStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthStack")
            .field("authenticator_id", &self.authenticator.authenticator_id())
            .field("tenant_authority", &self.tenant_authority)
            .field("mode", &self.mode)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Community,
    Enterprise,
}

impl AuthStack {
    pub fn authenticator(&self) -> &dyn CredentialAuthenticator {
        self.authenticator.as_ref()
    }

    pub fn tenant_authority(&self) -> Option<&TenantDerivationAuthority> {
        self.tenant_authority.as_ref()
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    pub fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        self.authenticator.authenticate(credential)
    }
}

/// Compose the host authenticator at startup.
///
/// Missing or incompatible *required* extensions fail here rather than during
/// a later deployment operation.
pub fn build_auth_stack(
    config: &AuthHostConfig,
    extension: Option<Arc<dyn EnterpriseAuthExtension>>,
    community: Arc<dyn CredentialAuthenticator>,
) -> Result<AuthStack, AuthStartupError> {
    if config.expected_contract_version != AUTH_CONTEXT_CONTRACT_VERSION {
        return Err(AuthStartupError::IncompatibleHostContract {
            found: config.expected_contract_version,
            expected: AUTH_CONTEXT_CONTRACT_VERSION,
        });
    }

    match (&config.required_extension_id, extension) {
        (None, None) => Ok(AuthStack {
            authenticator: community,
            tenant_authority: None,
            mode: AuthMode::Community,
        }),
        (None, Some(extension)) => {
            validate_extension(config, extension.as_ref())?;
            let authority = TenantDerivationAuthority {
                extension_id: extension.extension_id().into(),
            };
            Ok(AuthStack {
                authenticator: Arc::new(DualStackAuthenticator {
                    community,
                    enterprise: EnterpriseAuthenticatorAdapter {
                        extension,
                        authority: authority.clone(),
                    },
                }),
                tenant_authority: Some(authority),
                mode: AuthMode::Enterprise,
            })
        }
        (Some(required_id), None) => Err(AuthStartupError::MissingRequiredExtension {
            extension_id: required_id.clone(),
        }),
        (Some(required_id), Some(extension)) => {
            if extension.extension_id() != required_id.as_str() {
                return Err(AuthStartupError::ExtensionIdMismatch {
                    required: required_id.clone(),
                    found: extension.extension_id().into(),
                });
            }
            validate_extension(config, extension.as_ref())?;
            let authority = TenantDerivationAuthority {
                extension_id: extension.extension_id().into(),
            };
            Ok(AuthStack {
                authenticator: Arc::new(DualStackAuthenticator {
                    community,
                    enterprise: EnterpriseAuthenticatorAdapter {
                        extension,
                        authority: authority.clone(),
                    },
                }),
                tenant_authority: Some(authority),
                mode: AuthMode::Enterprise,
            })
        }
    }
}

fn validate_extension(
    config: &AuthHostConfig,
    extension: &dyn EnterpriseAuthExtension,
) -> Result<(), AuthStartupError> {
    if extension.extension_id().trim().is_empty() {
        return Err(AuthStartupError::InvalidExtension(
            "extension id must not be empty".into(),
        ));
    }
    if extension.contract_version() != config.expected_contract_version {
        return Err(AuthStartupError::IncompatibleExtensionContract {
            extension_id: extension.extension_id().into(),
            found: extension.contract_version(),
            expected: config.expected_contract_version,
        });
    }
    if let Some(expected_audience) = &config.expected_audience
        && extension.expected_audience() != expected_audience.as_str()
    {
        return Err(AuthStartupError::AudienceMismatch {
            extension_id: extension.extension_id().into(),
            found: extension.expected_audience().into(),
            expected: expected_audience.clone(),
        });
    }
    Ok(())
}

struct EnterpriseAuthenticatorAdapter {
    extension: Arc<dyn EnterpriseAuthExtension>,
    authority: TenantDerivationAuthority,
}

impl CredentialAuthenticator for EnterpriseAuthenticatorAdapter {
    fn authenticator_id(&self) -> &str {
        self.extension.extension_id()
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        self.extension
            .authenticate(credential, &self.authority)
            .and_then(|context| {
                context.validate()?;
                if context.authenticator_id != self.extension.extension_id() {
                    return Err(AuthError::InvalidCredential(
                        "enterprise authenticator returned a foreign authenticator id".into(),
                    ));
                }
                match context.tenant() {
                    Some(tenant) if tenant.extension_id() == self.extension.extension_id() => {
                        Ok(context)
                    }
                    Some(_) => Err(AuthError::InvalidCredential(
                        "tenant context extension id does not match loaded extension".into(),
                    )),
                    // Tenant remains optional even under an enterprise extension.
                    None => Ok(context),
                }
            })
    }
}

/// Prefer the community management bearer when present and valid; otherwise use
/// the enterprise assertion path. Enabling enterprise auth therefore does not
/// silently disable the host management token break-glass path.
struct DualStackAuthenticator {
    community: Arc<dyn CredentialAuthenticator>,
    enterprise: EnterpriseAuthenticatorAdapter,
}

impl CredentialAuthenticator for DualStackAuthenticator {
    fn authenticator_id(&self) -> &str {
        self.enterprise.authenticator_id()
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        if credential.bearer_token.is_some() {
            match self.community.authenticate(credential) {
                Ok(context) => return Ok(context),
                Err(error) if credential.assertion.is_some() => {
                    // Invalid/unknown bearer with a simultaneous assertion falls
                    // through to enterprise verification instead of failing open.
                    let _ = error;
                }
                Err(error) => return Err(error),
            }
        }
        if credential.assertion.is_some() {
            return self.enterprise.authenticate(credential);
        }
        Err(AuthError::InvalidCredential(
            "enterprise dual-stack authenticator requires a community bearer or assertion".into(),
        ))
    }
}

/// Community token authenticator: maps configured bearer tokens to principals
/// and never attaches tenant context.
#[derive(Debug, Clone)]
pub struct CommunityTokenAuthenticator {
    pub authenticator_id: String,
    /// token -> principal
    pub tokens: std::collections::BTreeMap<String, PrincipalIdentity>,
}

impl CommunityTokenAuthenticator {
    pub fn new(
        authenticator_id: impl Into<String>,
        tokens: impl IntoIterator<Item = (String, PrincipalIdentity)>,
    ) -> Result<Self, AuthError> {
        let authenticator_id = authenticator_id.into();
        if authenticator_id.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "community authenticator id must not be empty".into(),
            ));
        }
        let tokens: std::collections::BTreeMap<_, _> = tokens.into_iter().collect();
        if tokens.is_empty() {
            return Err(AuthError::InvalidCredential(
                "community authenticator requires at least one token mapping".into(),
            ));
        }
        for (token, principal) in &tokens {
            if token.trim().is_empty() || principal.id.trim().is_empty() {
                return Err(AuthError::InvalidCredential(
                    "community token mappings must use non-empty token and principal ids".into(),
                ));
            }
        }
        Ok(Self {
            authenticator_id,
            tokens,
        })
    }
}

impl CredentialAuthenticator for CommunityTokenAuthenticator {
    fn authenticator_id(&self) -> &str {
        &self.authenticator_id
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        let token = credential.bearer_token.as_deref().ok_or_else(|| {
            AuthError::InvalidCredential("community authenticator requires a bearer token".into())
        })?;
        let principal = self
            .tokens
            .get(token)
            .cloned()
            .ok_or_else(|| AuthError::Unauthorized("unknown community bearer token".into()))?;
        AuthenticatedRequestContextBuilder::new(
            credential.request_id.clone(),
            principal,
            self.authenticator_id.clone(),
        )
        .build()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("incompatible auth contract version {found}, expected {expected}")]
    IncompatibleContract { found: u32, expected: u32 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthStartupError {
    #[error("required auth extension `{extension_id}` is not configured")]
    MissingRequiredExtension { extension_id: String },
    #[error(
        "auth extension `{extension_id}` contract version {found} is incompatible with expected {expected}"
    )]
    IncompatibleExtensionContract {
        extension_id: String,
        found: u32,
        expected: u32,
    },
    #[error("host expected auth contract version {found}, core supports {expected}")]
    IncompatibleHostContract { found: u32, expected: u32 },
    #[error("required auth extension `{required}`, found `{found}`")]
    ExtensionIdMismatch { required: String, found: String },
    #[error(
        "auth extension `{extension_id}` audience `{found}` does not match expected `{expected}`"
    )]
    AudienceMismatch {
        extension_id: String,
        found: String,
        expected: String,
    },
    #[error("invalid auth extension: {0}")]
    InvalidExtension(String),
}

#[cfg(test)]
pub(crate) fn test_management_context(
    request_id: impl Into<String>,
) -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        request_id,
        PrincipalIdentity {
            id: "management".into(),
            kind: PrincipalKind::Management,
        },
        "test-auth",
    )
    .build()
    .expect("test management context")
}

#[cfg(test)]
pub(crate) fn test_human_context(request_id: impl Into<String>) -> AuthenticatedRequestContext {
    AuthenticatedRequestContextBuilder::new(
        request_id,
        PrincipalIdentity {
            id: "user-42".into(),
            kind: PrincipalKind::Human,
        },
        "test-auth",
    )
    .build()
    .expect("test human context")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn management_principal() -> PrincipalIdentity {
        PrincipalIdentity {
            id: "management".into(),
            kind: PrincipalKind::Management,
        }
    }

    fn community_auth() -> Arc<dyn CredentialAuthenticator> {
        Arc::new(
            CommunityTokenAuthenticator::new(
                "community-token",
                [("management-secret".into(), management_principal())],
            )
            .unwrap(),
        )
    }

    struct StubEnterpriseAuth {
        id: String,
        version: u32,
        audience: String,
        tenant_id: String,
        principal_id: String,
    }

    impl EnterpriseAuthExtension for StubEnterpriseAuth {
        fn extension_id(&self) -> &str {
            &self.id
        }

        fn contract_version(&self) -> u32 {
            self.version
        }

        fn expected_audience(&self) -> &str {
            &self.audience
        }

        fn authenticate(
            &self,
            credential: &CredentialMaterial,
            authority: &TenantDerivationAuthority,
        ) -> Result<AuthenticatedRequestContext, AuthError> {
            credential.validate()?;
            let assertion = credential.assertion.as_ref().ok_or_else(|| {
                AuthError::InvalidCredential("enterprise extension requires an assertion".into())
            })?;
            // Stub verification: assertion must equal "good" and audience is host-checked.
            if assertion != b"good" {
                return Err(AuthError::Unauthorized(
                    "assertion verification failed".into(),
                ));
            }
            AuthenticatedRequestContextBuilder::new(
                credential.request_id.clone(),
                PrincipalIdentity {
                    id: self.principal_id.clone(),
                    kind: PrincipalKind::Human,
                },
                self.id.clone(),
            )
            .with_tenant(self.tenant_id.clone(), authority)?
            .build()
        }
    }

    #[test]
    fn community_context_has_principal_without_tenant() {
        let stack = build_auth_stack(&AuthHostConfig::community(), None, community_auth()).unwrap();
        assert_eq!(stack.mode(), AuthMode::Community);
        assert!(stack.tenant_authority().is_none());

        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "req-1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: None,
            })
            .unwrap();
        assert_eq!(context.principal_id(), "management");
        assert!(!context.is_tenant_scoped());
        assert!(context.tenant().is_none());
        assert_eq!(context.contract_version, AUTH_CONTEXT_CONTRACT_VERSION);
    }

    #[test]
    fn tenant_context_requires_derivation_authority() {
        // Ordinary code can construct a builder, but cannot attach a tenant
        // without a host-granted authority value. Authorities are only created
        // inside build_auth_stack when an extension loads.
        let builder = AuthenticatedRequestContextBuilder::new(
            "req-2",
            management_principal(),
            "community-token",
        );
        let context = builder.build().unwrap();
        assert!(context.tenant().is_none());
    }

    #[test]
    fn credential_material_rejects_caller_style_empty_fields() {
        let error = CredentialMaterial {
            request_id: "req".into(),
            bearer_token: Some("  ".into()),
            assertion: None,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(error, AuthError::InvalidCredential(_)));
    }

    #[test]
    fn enterprise_extension_derives_tenant_only_after_verification() {
        let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(StubEnterpriseAuth {
            id: "enterprise-auth".into(),
            version: AUTH_CONTEXT_CONTRACT_VERSION,
            audience: "tenkai-server".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "user:42".into(),
        });
        let config = AuthHostConfig {
            required_extension_id: Some("enterprise-auth".into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        let stack = build_auth_stack(&config, Some(extension), community_auth()).unwrap();
        assert_eq!(stack.mode(), AuthMode::Enterprise);
        assert_eq!(
            stack.tenant_authority().unwrap().extension_id(),
            "enterprise-auth"
        );

        let denied = stack.authenticate(&CredentialMaterial {
            request_id: "req-3".into(),
            bearer_token: None,
            assertion: Some(b"forged".to_vec()),
        });
        assert!(matches!(denied, Err(AuthError::Unauthorized(_))));

        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "req-4".into(),
                bearer_token: None,
                assertion: Some(b"good".to_vec()),
            })
            .unwrap();
        assert_eq!(context.principal_id(), "user:42");
        assert_eq!(context.tenant().unwrap().tenant_id(), "tenant-a");
        assert_eq!(context.tenant().unwrap().extension_id(), "enterprise-auth");
    }

    #[test]
    fn missing_required_extension_fails_at_startup() {
        let config = AuthHostConfig {
            required_extension_id: Some("enterprise-auth".into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        let error = build_auth_stack(&config, None, community_auth()).unwrap_err();
        assert_eq!(
            error,
            AuthStartupError::MissingRequiredExtension {
                extension_id: "enterprise-auth".into(),
            }
        );
    }

    #[test]
    fn incompatible_extension_contract_fails_at_startup() {
        let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(StubEnterpriseAuth {
            id: "enterprise-auth".into(),
            version: 99,
            audience: "tenkai-server".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "user:42".into(),
        });
        let config = AuthHostConfig {
            required_extension_id: Some("enterprise-auth".into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        let error = build_auth_stack(&config, Some(extension), community_auth()).unwrap_err();
        assert!(matches!(
            error,
            AuthStartupError::IncompatibleExtensionContract { found: 99, .. }
        ));
    }

    #[test]
    fn audience_mismatch_fails_at_startup() {
        let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(StubEnterpriseAuth {
            id: "enterprise-auth".into(),
            version: AUTH_CONTEXT_CONTRACT_VERSION,
            audience: "other-service".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "user:42".into(),
        });
        let config = AuthHostConfig {
            required_extension_id: Some("enterprise-auth".into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        let error = build_auth_stack(&config, Some(extension), community_auth()).unwrap_err();
        assert!(matches!(error, AuthStartupError::AudienceMismatch { .. }));
    }

    #[test]
    fn community_stack_works_when_enterprise_extension_absent() {
        // Embedded and community server hosts use this path.
        let stack = build_auth_stack(&AuthHostConfig::community(), None, community_auth()).unwrap();
        assert_eq!(stack.mode(), AuthMode::Community);
        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "embedded-1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: None,
            })
            .unwrap();
        assert!(!context.is_tenant_scoped());
    }

    #[test]
    fn dyn_credential_authenticator_is_object_safe() {
        let auth: Arc<dyn CredentialAuthenticator> = community_auth();
        let _ = auth.authenticator_id();
        let context = auth
            .authenticate(&CredentialMaterial {
                request_id: "dyn-1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: None,
            })
            .unwrap();
        assert_eq!(context.principal.kind, PrincipalKind::Management);
    }

    #[test]
    fn forged_tenant_cannot_be_injected_via_credential_material() {
        // CredentialMaterial has no tenant field; community mode ignores assertions
        // for tenant selection and never becomes tenant-scoped.
        let stack = build_auth_stack(&AuthHostConfig::community(), None, community_auth()).unwrap();
        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "forge-1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: Some(b"tenant=evil".to_vec()),
            })
            .unwrap();
        assert!(context.tenant().is_none());
    }

    #[test]
    fn missing_management_capability_fails_closed() {
        let human = test_human_context("cap-deny");
        let error = human
            .require_delivery_capability(DeliveryCapability::Management)
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::Unauthorized(ref message) if message.contains("insufficient delivery capability")
        ));
        test_management_context("cap-allow")
            .require_delivery_capability(DeliveryCapability::Management)
            .unwrap();
    }

    #[test]
    fn community_management_principal_receives_management_capability() {
        let stack = build_auth_stack(&AuthHostConfig::community(), None, community_auth()).unwrap();
        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "cap-1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: None,
            })
            .unwrap();
        assert!(context.has_delivery_capability(DeliveryCapability::Management));
        assert!(context.has_delivery_capability(DeliveryCapability::Read));
    }

    #[test]
    fn enterprise_human_defaults_to_no_delivery_capabilities() {
        let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(StubEnterpriseAuth {
            id: "enterprise-auth".into(),
            version: AUTH_CONTEXT_CONTRACT_VERSION,
            audience: "tenkai-server".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "user:42".into(),
        });
        let config = AuthHostConfig {
            required_extension_id: Some("enterprise-auth".into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        let stack = build_auth_stack(&config, Some(extension), community_auth()).unwrap();
        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "cap-2".into(),
                bearer_token: None,
                assertion: Some(b"good".to_vec()),
            })
            .unwrap();
        assert_eq!(context.principal.kind, PrincipalKind::Human);
        assert!(!context.has_delivery_capability(DeliveryCapability::Read));
        assert!(!context.has_delivery_capability(DeliveryCapability::Management));
    }

    #[test]
    fn enterprise_dual_stack_keeps_community_management_token() {
        let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(StubEnterpriseAuth {
            id: "enterprise-auth".into(),
            version: AUTH_CONTEXT_CONTRACT_VERSION,
            audience: "tenkai-server".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "user:42".into(),
        });
        let config = AuthHostConfig {
            required_extension_id: Some("enterprise-auth".into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some("tenkai-server".into()),
        };
        let stack = build_auth_stack(&config, Some(extension), community_auth()).unwrap();
        let context = stack
            .authenticate(&CredentialMaterial {
                request_id: "dual-1".into(),
                bearer_token: Some("management-secret".into()),
                assertion: None,
            })
            .unwrap();
        assert_eq!(context.principal_id(), "management");
        assert_eq!(context.principal.kind, PrincipalKind::Management);
        assert!(context.has_delivery_capability(DeliveryCapability::Management));
        assert!(context.tenant().is_none());
    }
}

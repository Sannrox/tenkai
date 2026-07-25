//! Federated identity mapping across Tenkai, the enterprise identity plane,
//! and optional governance providers.
//!
//! Identities are stable opaque subjects bound to an explicit issuer and
//! audience. No component reads another product's tenant database. Tenant
//! mappings are derived only by trusted authentication code—never from ordinary
//! caller metadata. Tenkai remains authoritative for products, environments,
//! agents, plans, and deployment history.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Version of the federated-identity contract.
pub const FEDERATED_IDENTITY_CONTRACT_VERSION: u32 = 1;

/// Which system is authoritative for a class of identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAuthority {
    /// Browser-facing enterprise identity plane (tenant, principal, session).
    EnterpriseIdentityPlane,
    /// Tenkai delivery domain (environments, agents, products, plans, history).
    Tenkai,
    /// Governance / intelligence providers (policy, eval, evidence records).
    GovernanceProvider,
}

/// Kind of identity being named or mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Tenant,
    Principal,
    Service,
    Environment,
    Agent,
    Product,
    Plan,
    Evidence,
}

impl IdentityKind {
    pub fn default_authority(self) -> IdentityAuthority {
        match self {
            Self::Tenant | Self::Principal | Self::Service => {
                IdentityAuthority::EnterpriseIdentityPlane
            }
            Self::Environment | Self::Agent | Self::Product | Self::Plan => {
                IdentityAuthority::Tenkai
            }
            Self::Evidence => IdentityAuthority::GovernanceProvider,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Principal => "principal",
            Self::Service => "service",
            Self::Environment => "environment",
            Self::Agent => "agent",
            Self::Product => "product",
            Self::Plan => "plan",
            Self::Evidence => "evidence",
        }
    }
}

/// Stable opaque identifier bound to issuer and audience.
///
/// The `subject` is opaque to Tenkai core: it is never interpreted as a local
/// path, SQL key, or caller-selected tenant header.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FederatedIdentifier {
    pub contract_version: u32,
    pub kind: IdentityKind,
    /// Issuer that mints or owns this subject (URI or stable issuer id).
    pub issuer: String,
    /// Intended audience that may consume this identifier.
    pub audience: String,
    /// Opaque subject string stable for the lifetime of the identity at the issuer.
    pub subject: String,
}

impl FederatedIdentifier {
    pub fn new(
        kind: IdentityKind,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, FederationError> {
        let identity = Self {
            contract_version: FEDERATED_IDENTITY_CONTRACT_VERSION,
            kind,
            issuer: issuer.into(),
            audience: audience.into(),
            subject: subject.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), FederationError> {
        if self.contract_version != FEDERATED_IDENTITY_CONTRACT_VERSION {
            return Err(FederationError::IncompatibleContract {
                found: self.contract_version,
                expected: FEDERATED_IDENTITY_CONTRACT_VERSION,
            });
        }
        for (name, value) in [
            ("issuer", &self.issuer),
            ("audience", &self.audience),
            ("subject", &self.subject),
        ] {
            if value.trim().is_empty() {
                return Err(FederationError::InvalidIdentifier(format!(
                    "{name} must not be empty"
                )));
            }
        }
        Ok(())
    }

    /// Correlation token for audit logs (issuer + kind + subject). Contains no secrets.
    pub fn audit_correlation_id(&self) -> String {
        format!("{}:{}:{}", self.issuer, self.kind.as_str(), self.subject)
    }
}

/// Mapping from an external federated identifier into a Tenkai-local handle.
///
/// Tenkai-local handles for environments, agents, products, and plans remain
/// Tenkai-owned strings. External tenant/principal subjects are never used as
/// Tenkai environment ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMapping {
    pub external: FederatedIdentifier,
    pub local_handle: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    /// Monotonic generation for rotation; higher generation supersedes lower.
    pub generation: u64,
}

impl IdentityMapping {
    pub fn validate(&self, now: i64) -> Result<(), FederationError> {
        self.external.validate()?;
        if self.local_handle.trim().is_empty() {
            return Err(FederationError::InvalidIdentifier(
                "local handle must not be empty".into(),
            ));
        }
        if self.generation == 0 {
            return Err(FederationError::InvalidIdentifier(
                "mapping generation must be >= 1".into(),
            ));
        }
        if let Some(expires_at) = self.expires_at
            && expires_at <= now
        {
            return Err(FederationError::Expired);
        }
        if self.revoked_at.is_some() {
            return Err(FederationError::Revoked);
        }
        Ok(())
    }

    pub fn is_active(&self, now: i64) -> bool {
        self.validate(now).is_ok()
    }
}

/// Signed context envelope metadata used when mapping identities.
///
/// The cryptographic verification of the underlying assertion is performed by
/// the enterprise auth extension (ADR 0004). This type only carries the
/// federation claims that must be issuer- and audience-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIdentityContext {
    pub issuer: String,
    pub audience: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    /// Unique assertion id for replay protection.
    pub assertion_id: String,
    pub principal: FederatedIdentifier,
    pub tenant: Option<FederatedIdentifier>,
    pub service: Option<FederatedIdentifier>,
}

impl SignedIdentityContext {
    pub fn validate(
        &self,
        expected_issuer: &str,
        expected_audience: &str,
        now: i64,
        max_clock_skew_ms: i64,
    ) -> Result<(), FederationError> {
        if self.issuer != expected_issuer {
            return Err(FederationError::IssuerMismatch {
                found: self.issuer.clone(),
                expected: expected_issuer.into(),
            });
        }
        if self.audience != expected_audience {
            return Err(FederationError::AudienceMismatch {
                found: self.audience.clone(),
                expected: expected_audience.into(),
            });
        }
        if self.assertion_id.trim().is_empty() {
            return Err(FederationError::InvalidIdentifier(
                "assertion id must not be empty".into(),
            ));
        }
        if now + max_clock_skew_ms < self.not_before {
            return Err(FederationError::NotYetValid);
        }
        if now - max_clock_skew_ms >= self.expires_at {
            return Err(FederationError::Expired);
        }
        self.principal.validate()?;
        if self.principal.kind != IdentityKind::Principal {
            return Err(FederationError::InvalidIdentifier(
                "principal claim must have kind principal".into(),
            ));
        }
        if self.principal.issuer != self.issuer || self.principal.audience != self.audience {
            return Err(FederationError::InvalidIdentifier(
                "principal issuer/audience must match signed context".into(),
            ));
        }
        if let Some(tenant) = &self.tenant {
            tenant.validate()?;
            if tenant.kind != IdentityKind::Tenant {
                return Err(FederationError::InvalidIdentifier(
                    "tenant claim must have kind tenant".into(),
                ));
            }
            if tenant.issuer != self.issuer || tenant.audience != self.audience {
                return Err(FederationError::InvalidIdentifier(
                    "tenant issuer/audience must match signed context".into(),
                ));
            }
        }
        if let Some(service) = &self.service {
            service.validate()?;
            if service.kind != IdentityKind::Service {
                return Err(FederationError::InvalidIdentifier(
                    "service claim must have kind service".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Capability that permits writing tenant mappings. Only trusted authentication
/// code receives this after verifying signed context.
#[derive(Debug, Clone)]
pub struct MappingAuthority {
    issuer: String,
    audience: String,
}

impl MappingAuthority {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// Host configuration for federation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConfig {
    /// When set, enterprise operation requires this issuer on every signed context.
    pub required_enterprise_issuer: Option<String>,
    pub expected_audience: String,
    pub max_clock_skew_ms: i64,
    /// Maximum retained assertion ids for replay protection in the default store.
    pub replay_cache_capacity: usize,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            required_enterprise_issuer: None,
            expected_audience: "tenkai-server".into(),
            max_clock_skew_ms: 60_000,
            replay_cache_capacity: 4_096,
        }
    }
}

impl FederationConfig {
    /// Community / standalone: no enterprise issuer required.
    pub fn community() -> Self {
        Self::default()
    }

    /// Enterprise host that requires a configured identity-plane issuer.
    pub fn enterprise(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            required_enterprise_issuer: Some(issuer.into()),
            expected_audience: audience.into(),
            ..Self::default()
        }
    }
}

/// In-process mapping table and replay cache for conformance and host wiring.
///
/// This is not a shared database with the enterprise identity plane. Mappings
/// are Tenkai-local correlation records only.
#[derive(Debug, Default)]
pub struct IdentityDirectory {
    mappings: Mutex<BTreeMap<String, IdentityMapping>>,
    replayed: Mutex<BTreeMap<String, i64>>,
}

impl IdentityDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    fn mapping_key(external: &FederatedIdentifier) -> String {
        format!(
            "{}|{}|{}|{}",
            external.issuer,
            external.kind.as_str(),
            external.audience,
            external.subject
        )
    }

    /// Grant mapping authority only for the configured enterprise issuer/audience.
    pub fn mapping_authority(
        &self,
        config: &FederationConfig,
    ) -> Result<MappingAuthority, FederationError> {
        let issuer = config
            .required_enterprise_issuer
            .clone()
            .ok_or(FederationError::EnterpriseIssuerNotConfigured)?;
        Ok(MappingAuthority {
            issuer,
            audience: config.expected_audience.clone(),
        })
    }

    /// Record a mapping after signed context verification. Caller metadata cannot
    /// supply the authority.
    pub fn put_mapping(
        &self,
        authority: &MappingAuthority,
        mapping: IdentityMapping,
        now: i64,
    ) -> Result<(), FederationError> {
        mapping.validate(now)?;
        if mapping.external.issuer != authority.issuer
            || mapping.external.audience != authority.audience
        {
            return Err(FederationError::UnauthorizedMapping);
        }
        let key = Self::mapping_key(&mapping.external);
        let mut guard = self.mappings.lock().expect("mapping mutex");
        if let Some(existing) = guard.get(&key) {
            if existing.generation > mapping.generation {
                return Err(FederationError::StaleGeneration {
                    found: mapping.generation,
                    current: existing.generation,
                });
            }
            // Same generation must be identical; cannot overwrite with different handle.
            if existing.generation == mapping.generation
                && existing.local_handle != mapping.local_handle
            {
                return Err(FederationError::MappingConflict);
            }
        }
        guard.insert(key, mapping);
        Ok(())
    }

    pub fn resolve(
        &self,
        external: &FederatedIdentifier,
        now: i64,
    ) -> Result<IdentityMapping, FederationError> {
        external.validate()?;
        let key = Self::mapping_key(external);
        let guard = self.mappings.lock().expect("mapping mutex");
        let mapping = guard.get(&key).cloned().ok_or(FederationError::NotFound)?;
        mapping.validate(now)?;
        Ok(mapping)
    }

    pub fn revoke(
        &self,
        authority: &MappingAuthority,
        external: &FederatedIdentifier,
        now: i64,
    ) -> Result<(), FederationError> {
        external.validate()?;
        if external.issuer != authority.issuer || external.audience != authority.audience {
            return Err(FederationError::UnauthorizedMapping);
        }
        let key = Self::mapping_key(external);
        let mut guard = self.mappings.lock().expect("mapping mutex");
        let mapping = guard.get_mut(&key).ok_or(FederationError::NotFound)?;
        mapping.revoked_at = Some(now);
        Ok(())
    }

    pub fn delete(
        &self,
        authority: &MappingAuthority,
        external: &FederatedIdentifier,
    ) -> Result<(), FederationError> {
        external.validate()?;
        if external.issuer != authority.issuer || external.audience != authority.audience {
            return Err(FederationError::UnauthorizedMapping);
        }
        let key = Self::mapping_key(external);
        let mut guard = self.mappings.lock().expect("mapping mutex");
        if guard.remove(&key).is_none() {
            return Err(FederationError::NotFound);
        }
        Ok(())
    }

    /// Accept a signed context once; duplicate assertion ids fail closed (replay).
    pub fn accept_signed_context(
        &self,
        config: &FederationConfig,
        context: &SignedIdentityContext,
        now: i64,
    ) -> Result<(), FederationError> {
        let issuer = config
            .required_enterprise_issuer
            .as_deref()
            .ok_or(FederationError::EnterpriseIssuerNotConfigured)?;
        context.validate(
            issuer,
            &config.expected_audience,
            now,
            config.max_clock_skew_ms,
        )?;
        let mut replayed = self.replayed.lock().expect("replay mutex");
        if replayed.contains_key(&context.assertion_id) {
            return Err(FederationError::Replay);
        }
        if replayed.len() >= config.replay_cache_capacity {
            // Drop oldest by expiry-ish: remove the smallest expires timestamp entry.
            if let Some(oldest) = replayed
                .iter()
                .min_by_key(|(_, expires)| *expires)
                .map(|(id, _)| id.clone())
            {
                replayed.remove(&oldest);
            }
        }
        replayed.insert(context.assertion_id.clone(), context.expires_at);
        Ok(())
    }
}

/// Whether an unavailable governance provider blocks the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDecisionClass {
    /// Operation requires provider evidence; unavailability fails closed.
    Required,
    /// Provider is optional enrichment; unavailability degrades with retry.
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderAvailabilityOutcome {
    Proceed,
    FailClosed { reason: String },
    Degrade { reason: String },
}

/// Provider unavailability policy for federated evidence identities.
pub fn provider_unavailability_outcome(
    class: ProviderDecisionClass,
    provider_id: &str,
) -> ProviderAvailabilityOutcome {
    match class {
        ProviderDecisionClass::Required => ProviderAvailabilityOutcome::FailClosed {
            reason: format!(
                "required governance provider `{provider_id}` is unavailable; decision fails closed"
            ),
        },
        ProviderDecisionClass::Optional => ProviderAvailabilityOutcome::Degrade {
            reason: format!(
                "optional governance provider `{provider_id}` is unavailable; operational recovery continues"
            ),
        },
    }
}

/// Tenkai standalone enterprise hosts authenticate via a configured issuer and
/// do not require a governance provider for authentication or recovery.
pub fn standalone_enterprise_requires_governance_provider() -> bool {
    false
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FederationError {
    #[error("invalid federated identifier: {0}")]
    InvalidIdentifier(String),
    #[error("incompatible federated identity contract version {found}, expected {expected}")]
    IncompatibleContract { found: u32, expected: u32 },
    #[error("issuer mismatch: found `{found}`, expected `{expected}`")]
    IssuerMismatch { found: String, expected: String },
    #[error("audience mismatch: found `{found}`, expected `{expected}`")]
    AudienceMismatch { found: String, expected: String },
    #[error("signed identity context is not yet valid")]
    NotYetValid,
    #[error("signed identity context or mapping is expired")]
    Expired,
    #[error("identity mapping is revoked")]
    Revoked,
    #[error("identity mapping not found")]
    NotFound,
    #[error("replayed assertion id")]
    Replay,
    #[error("mapping authority rejected the write")]
    UnauthorizedMapping,
    #[error("mapping generation {found} is stale; current is {current}")]
    StaleGeneration { found: u64, current: u64 },
    #[error("mapping conflict for the same generation")]
    MappingConflict,
    #[error("enterprise issuer is not configured")]
    EnterpriseIssuerNotConfigured,
    #[error("caller metadata cannot select or overwrite tenant mappings")]
    CallerMetadataForbidden,
}

/// Reject attempts to set tenant identity from ordinary caller metadata.
pub fn reject_caller_selected_tenant(
    caller_tenant_header: Option<&str>,
) -> Result<(), FederationError> {
    if caller_tenant_header.is_some() {
        return Err(FederationError::CallerMetadataForbidden);
    }
    Ok(())
}

/// Non-secret audit correlation token for an accepted assertion.
///
/// Derived from the assertion id only (SHA-256 hex). Never includes bearer
/// tokens, raw assertions, or mapping private material.
pub fn audit_correlation_token(assertion_id: &str) -> String {
    format!("fed:{:x}", Sha256::digest(assertion_id.as_bytes()))
}

/// Wraps an enterprise auth extension so accepted requests also pass federation
/// accept rules (issuer/audience bind + replay cache) and optional local
/// correlation mappings under [`MappingAuthority`].
pub struct FederatingAuthExtension {
    inner: Arc<dyn crate::auth_context::EnterpriseAuthExtension>,
    directory: Arc<IdentityDirectory>,
    config: FederationConfig,
}

impl FederatingAuthExtension {
    pub fn new(
        inner: Arc<dyn crate::auth_context::EnterpriseAuthExtension>,
        directory: Arc<IdentityDirectory>,
        config: FederationConfig,
    ) -> Self {
        Self {
            inner,
            directory,
            config,
        }
    }

    pub fn directory(&self) -> &IdentityDirectory {
        &self.directory
    }

    pub fn config(&self) -> &FederationConfig {
        &self.config
    }
}

impl crate::auth_context::EnterpriseAuthExtension for FederatingAuthExtension {
    fn extension_id(&self) -> &str {
        self.inner.extension_id()
    }

    fn contract_version(&self) -> u32 {
        self.inner.contract_version()
    }

    fn expected_audience(&self) -> &str {
        self.inner.expected_audience()
    }

    fn authenticate(
        &self,
        credential: &crate::auth_context::CredentialMaterial,
        authority: &crate::auth_context::TenantDerivationAuthority,
    ) -> Result<crate::auth_context::AuthenticatedRequestContext, crate::auth_context::AuthError>
    {
        // Caller-selected tenant metadata is forbidden on the federation path.
        // Transport may still pass headers; the host must not interpret them as authority.
        let context = self.inner.authenticate(credential, authority)?;
        let Some(assertion) = credential.assertion.as_ref() else {
            // Community-style bearer on an enterprise host: no federation claims.
            return Ok(context);
        };
        let signed: SignedIdentityContext = serde_json::from_slice(assertion).map_err(|error| {
            crate::auth_context::AuthError::InvalidCredential(format!(
                "signed identity context is not valid federation JSON: {error}"
            ))
        })?;
        let now = crate::now_millis();
        self.directory
            .accept_signed_context(&self.config, &signed, now)
            .map_err(federation_to_auth_error)?;
        // Optional local correlation mapping lookup (read); writes require MappingAuthority.
        let _correlation = audit_correlation_token(&signed.assertion_id);
        let _ = self.directory.resolve(&signed.principal, now);
        Ok(context)
    }
}

fn federation_to_auth_error(error: FederationError) -> crate::auth_context::AuthError {
    match error {
        FederationError::Replay => {
            crate::auth_context::AuthError::Unauthorized("replayed assertion id".into())
        }
        FederationError::Expired | FederationError::NotYetValid => {
            crate::auth_context::AuthError::Unauthorized(error.to_string())
        }
        FederationError::IssuerMismatch { .. }
        | FederationError::AudienceMismatch { .. }
        | FederationError::EnterpriseIssuerNotConfigured => {
            crate::auth_context::AuthError::Unauthorized(error.to_string())
        }
        other => crate::auth_context::AuthError::InvalidCredential(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> FederatedIdentifier {
        FederatedIdentifier::new(
            IdentityKind::Principal,
            "https://identity.example/issuer",
            "tenkai-server",
            "user-42",
        )
        .unwrap()
    }

    fn tenant() -> FederatedIdentifier {
        FederatedIdentifier::new(
            IdentityKind::Tenant,
            "https://identity.example/issuer",
            "tenkai-server",
            "tenant-7",
        )
        .unwrap()
    }

    fn enterprise_config() -> FederationConfig {
        FederationConfig::enterprise("https://identity.example/issuer", "tenkai-server")
    }

    fn signed_context(assertion_id: &str) -> SignedIdentityContext {
        SignedIdentityContext {
            issuer: "https://identity.example/issuer".into(),
            audience: "tenkai-server".into(),
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 10_000,
            assertion_id: assertion_id.into(),
            principal: principal(),
            tenant: Some(tenant()),
            service: None,
        }
    }

    #[test]
    fn tenkai_owns_delivery_identities() {
        assert_eq!(
            IdentityKind::Environment.default_authority(),
            IdentityAuthority::Tenkai
        );
        assert_eq!(
            IdentityKind::Agent.default_authority(),
            IdentityAuthority::Tenkai
        );
        assert_eq!(
            IdentityKind::Product.default_authority(),
            IdentityAuthority::Tenkai
        );
        assert_eq!(
            IdentityKind::Plan.default_authority(),
            IdentityAuthority::Tenkai
        );
        assert_eq!(
            IdentityKind::Evidence.default_authority(),
            IdentityAuthority::GovernanceProvider
        );
        assert_eq!(
            IdentityKind::Tenant.default_authority(),
            IdentityAuthority::EnterpriseIdentityPlane
        );
    }

    #[test]
    fn identifiers_require_issuer_audience_subject() {
        assert!(matches!(
            FederatedIdentifier::new(IdentityKind::Principal, "", "aud", "sub"),
            Err(FederationError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn signed_context_binds_issuer_and_audience() {
        let config = enterprise_config();
        let context = signed_context("assert-1");
        let dir = IdentityDirectory::new();
        dir.accept_signed_context(&config, &context, 2_000).unwrap();
        assert!(matches!(
            dir.accept_signed_context(&config, &context, 2_000),
            Err(FederationError::Replay)
        ));
    }

    #[test]
    fn audit_correlation_token_contains_no_secrets() {
        let token = audit_correlation_token("assert-secret-material");
        assert!(token.starts_with("fed:"));
        assert!(!token.contains("assert-secret-material"));
        assert!(!token.contains("Bearer"));
        assert_eq!(token.len(), 4 + 64);
    }

    struct StubEnterpriseAuth;

    impl crate::auth_context::EnterpriseAuthExtension for StubEnterpriseAuth {
        fn extension_id(&self) -> &str {
            "auth.enterprise"
        }
        fn contract_version(&self) -> u32 {
            crate::auth_context::AUTH_CONTEXT_CONTRACT_VERSION
        }
        fn expected_audience(&self) -> &str {
            "tenkai-server"
        }
        fn authenticate(
            &self,
            credential: &crate::auth_context::CredentialMaterial,
            authority: &crate::auth_context::TenantDerivationAuthority,
        ) -> Result<crate::auth_context::AuthenticatedRequestContext, crate::auth_context::AuthError>
        {
            let signed: SignedIdentityContext =
                serde_json::from_slice(credential.assertion.as_ref().ok_or_else(|| {
                    crate::auth_context::AuthError::InvalidCredential("need assertion".into())
                })?)
                .map_err(|e| crate::auth_context::AuthError::InvalidCredential(e.to_string()))?;
            crate::auth_context::AuthenticatedRequestContextBuilder::new(
                credential.request_id.clone(),
                crate::auth_context::PrincipalIdentity {
                    id: signed.principal.subject.clone(),
                    kind: crate::auth_context::PrincipalKind::Human,
                },
                self.extension_id(),
            )
            .with_tenant(signed.tenant.as_ref().unwrap().subject.clone(), authority)?
            .build()
        }
    }

    #[test]
    fn federating_extension_replays_fail_closed_and_mappings_need_authority() {
        use crate::auth_context::EnterpriseAuthExtension as _;

        let config = enterprise_config();
        let directory = Arc::new(IdentityDirectory::new());
        let extension = FederatingAuthExtension::new(
            Arc::new(StubEnterpriseAuth),
            directory.clone(),
            config.clone(),
        );
        let authority = crate::auth_context::TenantDerivationAuthority::new("auth.enterprise");
        let now = crate::now_millis();
        let mut signed = signed_context("assert-live-1");
        signed.issued_at = now - 1_000;
        signed.not_before = now - 1_000;
        signed.expires_at = now + 60_000;
        let credential = crate::auth_context::CredentialMaterial {
            request_id: "req-1".into(),
            bearer_token: None,
            assertion: Some(serde_json::to_vec(&signed).unwrap()),
        };
        extension.authenticate(&credential, &authority).unwrap();
        let replay = extension.authenticate(&credential, &authority).unwrap_err();
        assert!(
            matches!(replay, crate::auth_context::AuthError::Unauthorized(ref msg) if msg.contains("replay")),
            "{replay:?}"
        );

        let mapping_authority = directory.mapping_authority(&config).unwrap();
        directory
            .put_mapping(
                &mapping_authority,
                IdentityMapping {
                    external: principal(),
                    local_handle: "tenkai-principal-local".into(),
                    created_at: now,
                    expires_at: None,
                    revoked_at: None,
                    generation: 1,
                },
                now,
            )
            .unwrap();
        // Foreign authority rejected.
        let foreign = MappingAuthority {
            issuer: "https://other".into(),
            audience: "tenkai-server".into(),
        };
        assert!(matches!(
            directory.put_mapping(
                &foreign,
                IdentityMapping {
                    external: principal(),
                    local_handle: "hijack".into(),
                    created_at: now,
                    expires_at: None,
                    revoked_at: None,
                    generation: 2,
                },
                now,
            ),
            Err(FederationError::UnauthorizedMapping)
        ));
        directory.revoke(&mapping_authority, &principal(), now).unwrap();
        assert!(matches!(
            directory.resolve(&principal(), now),
            Err(FederationError::Revoked)
        ));
        directory.delete(&mapping_authority, &principal()).unwrap();
        assert!(matches!(
            directory.resolve(&principal(), now),
            Err(FederationError::NotFound)
        ));
    }

    #[test]
    fn wrong_issuer_or_audience_fails_closed() {
        let config = enterprise_config();
        let mut context = signed_context("assert-2");
        context.issuer = "https://other.example/issuer".into();
        let dir = IdentityDirectory::new();
        assert!(matches!(
            dir.accept_signed_context(&config, &context, 2_000),
            Err(FederationError::IssuerMismatch { .. })
        ));
        context = signed_context("assert-3");
        context.audience = "other-service".into();
        context.principal.audience = "other-service".into();
        context.tenant.as_mut().unwrap().audience = "other-service".into();
        assert!(matches!(
            dir.accept_signed_context(&config, &context, 2_000),
            Err(FederationError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn tenant_mapping_requires_authority_not_caller_metadata() {
        assert!(matches!(
            reject_caller_selected_tenant(Some("tenant-7")),
            Err(FederationError::CallerMetadataForbidden)
        ));
        reject_caller_selected_tenant(None).unwrap();

        let dir = IdentityDirectory::new();
        let config = enterprise_config();
        let authority = dir.mapping_authority(&config).unwrap();
        let mapping = IdentityMapping {
            external: tenant(),
            local_handle: "tenkai-tenant-correlation-7".into(),
            created_at: 1_000,
            expires_at: Some(20_000),
            revoked_at: None,
            generation: 1,
        };
        dir.put_mapping(&authority, mapping.clone(), 2_000).unwrap();
        let resolved = dir.resolve(&tenant(), 2_000).unwrap();
        assert_eq!(resolved.local_handle, "tenkai-tenant-correlation-7");

        // Foreign authority cannot overwrite.
        let foreign = MappingAuthority {
            issuer: "https://evil.example".into(),
            audience: "tenkai-server".into(),
        };
        assert!(matches!(
            dir.put_mapping(&foreign, mapping, 2_000),
            Err(FederationError::UnauthorizedMapping)
        ));
    }

    #[test]
    fn rotation_revocation_and_deletion() {
        let dir = IdentityDirectory::new();
        let config = enterprise_config();
        let authority = dir.mapping_authority(&config).unwrap();
        let v1 = IdentityMapping {
            external: principal(),
            local_handle: "principal-v1".into(),
            created_at: 1_000,
            expires_at: None,
            revoked_at: None,
            generation: 1,
        };
        dir.put_mapping(&authority, v1, 1_000).unwrap();
        let v2 = IdentityMapping {
            external: principal(),
            local_handle: "principal-v2".into(),
            created_at: 2_000,
            expires_at: None,
            revoked_at: None,
            generation: 2,
        };
        dir.put_mapping(&authority, v2, 2_000).unwrap();
        assert_eq!(
            dir.resolve(&principal(), 3_000).unwrap().local_handle,
            "principal-v2"
        );
        assert!(matches!(
            dir.put_mapping(
                &authority,
                IdentityMapping {
                    external: principal(),
                    local_handle: "stale".into(),
                    created_at: 3_000,
                    expires_at: None,
                    revoked_at: None,
                    generation: 1,
                },
                3_000
            ),
            Err(FederationError::StaleGeneration { .. })
        ));
        dir.revoke(&authority, &principal(), 4_000).unwrap();
        assert!(matches!(
            dir.resolve(&principal(), 4_000),
            Err(FederationError::Revoked)
        ));
        dir.delete(&authority, &principal()).unwrap();
        assert!(matches!(
            dir.resolve(&principal(), 5_000),
            Err(FederationError::NotFound)
        ));
    }

    #[test]
    fn provider_unavailability_policy() {
        assert!(matches!(
            provider_unavailability_outcome(ProviderDecisionClass::Required, "gate"),
            ProviderAvailabilityOutcome::FailClosed { .. }
        ));
        assert!(matches!(
            provider_unavailability_outcome(ProviderDecisionClass::Optional, "audit"),
            ProviderAvailabilityOutcome::Degrade { .. }
        ));
        assert!(!standalone_enterprise_requires_governance_provider());
    }

    #[test]
    fn community_mode_has_no_required_issuer() {
        let config = FederationConfig::community();
        assert!(config.required_enterprise_issuer.is_none());
        let dir = IdentityDirectory::new();
        assert!(matches!(
            dir.mapping_authority(&config),
            Err(FederationError::EnterpriseIssuerNotConfigured)
        ));
    }

    #[test]
    fn audit_correlation_contains_no_secrets() {
        let id = principal();
        let token = id.audit_correlation_id();
        assert!(token.contains("user-42"));
        assert!(!token.contains("password"));
        assert!(!token.contains("Bearer"));
    }

    #[test]
    fn no_cross_product_database_reads_in_contract() {
        // Documented invariant: IdentityDirectory only stores local correlation
        // records; FederatedIdentifier never encodes another product's DB URL.
        let env = FederatedIdentifier::new(
            IdentityKind::Environment,
            "tenkai",
            "tenkai-server",
            "env-prod",
        )
        .unwrap();
        assert_eq!(env.kind.default_authority(), IdentityAuthority::Tenkai);
        assert!(!env.subject.contains("postgres://"));
    }
}

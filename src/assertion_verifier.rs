//! Production-shaped enterprise assertion verification ports.
//!
//! Community hosts never require this module. Enterprise compositions load a
//! verifier at startup, wrap it in [`JwtEnterpriseAuthExtension`], and pass the
//! extension to [`crate::auth_context::build_auth_stack`]. Live network JWKS /
//! IdP calls are optional and not the default CI path.
//!
//! Reference algorithm: compact **JWT with EdDSA (Ed25519)** and static trust
//! roots (file or in-memory). Other opaque assertion types implement
//! [`AssertionVerifier`].

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::auth_context::{
    AUTH_CONTEXT_CONTRACT_VERSION, AuthError, AuthenticatedRequestContext,
    AuthenticatedRequestContextBuilder, CredentialMaterial, DeliveryCapability,
    EnterpriseAuthExtension, PrincipalIdentity, PrincipalKind, TenantDerivationAuthority,
};

/// Object-safe verifier for opaque enterprise assertions.
pub trait AssertionVerifier: Send + Sync {
    fn verifier_id(&self) -> &str;

    /// Verify assertion bytes and return validated claims (no secrets).
    fn verify(
        &self,
        assertion: &[u8],
        now_unix_secs: i64,
    ) -> Result<VerifiedAssertionClaims, AuthError>;
}

/// Claims extracted after cryptographic verification and time checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedAssertionClaims {
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub expires_at: i64,
    pub not_before: Option<i64>,
    pub principal_kind: PrincipalKind,
    /// Optional tenant id derived only from verified claims (never caller headers).
    pub tenant_id: Option<String>,
    /// Explicit delivery capabilities from `tenkai_capabilities`.
    ///
    /// `None` means the claim was absent and defaults from `principal_kind`
    /// apply. `Some(empty)` means the claim was present but granted nothing.
    pub delivery_capabilities: Option<std::collections::BTreeSet<DeliveryCapability>>,
}

/// Clock skew allowed when comparing `exp` / `nbf` (seconds).
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 60;

/// One trusted Ed25519 public key for JWT verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtTrustedKey {
    /// Optional key id matching JWT `kid` (when present).
    pub key_id: Option<String>,
    /// Base64-encoded 32-byte Ed25519 public key.
    pub public_key: String,
}

/// Static JWT verifier configuration (no network IdP in the default path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtVerifierConfig {
    pub issuer: String,
    pub audience: String,
    pub keys: Vec<JwtTrustedKey>,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: i64,
}

fn default_clock_skew() -> i64 {
    DEFAULT_CLOCK_SKEW_SECS
}

impl JwtVerifierConfig {
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let raw = std::fs::read_to_string(path).map_err(|error| {
            AuthError::InvalidCredential(format!(
                "failed to read JWT trust config {}: {error}",
                path.display()
            ))
        })?;
        let config: Self = toml::from_str(&raw).map_err(|error| {
            let location = error
                .span()
                .map(|span| format!(" near byte {}", span.start))
                .unwrap_or_default();
            AuthError::InvalidCredential(format!(
                "failed to parse JWT trust config {}{location}",
                path.display()
            ))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        if self.issuer.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "JWT verifier issuer must not be empty".into(),
            ));
        }
        if self.audience.trim().is_empty() {
            return Err(AuthError::InvalidCredential(
                "JWT verifier audience must not be empty".into(),
            ));
        }
        if self.keys.is_empty() {
            return Err(AuthError::InvalidCredential(
                "JWT verifier requires at least one trusted public key".into(),
            ));
        }
        if self.clock_skew_secs < 0 || self.clock_skew_secs > 600 {
            return Err(AuthError::InvalidCredential(
                "JWT clock skew must be between 0 and 600 seconds".into(),
            ));
        }
        for key in &self.keys {
            decode_public_key(&key.public_key)?;
        }
        Ok(())
    }
}

/// Reference JWT (EdDSA) assertion verifier with static trust roots.
#[derive(Debug, Clone)]
pub struct JwtAssertionVerifier {
    config: JwtVerifierConfig,
    keys: Vec<(Option<String>, VerifyingKey)>,
}

impl JwtAssertionVerifier {
    pub fn new(config: JwtVerifierConfig) -> Result<Self, AuthError> {
        config.validate()?;
        let mut keys = Vec::with_capacity(config.keys.len());
        for key in &config.keys {
            let verifying = decode_public_key(&key.public_key)?;
            keys.push((key.key_id.clone(), verifying));
        }
        Ok(Self { config, keys })
    }

    pub fn from_path(path: &Path) -> Result<Self, AuthError> {
        Self::new(JwtVerifierConfig::load(path)?)
    }

    pub fn config(&self) -> &JwtVerifierConfig {
        &self.config
    }
}

impl AssertionVerifier for JwtAssertionVerifier {
    fn verifier_id(&self) -> &str {
        "jwt-eddsa-static"
    }

    fn verify(
        &self,
        assertion: &[u8],
        now_unix_secs: i64,
    ) -> Result<VerifiedAssertionClaims, AuthError> {
        let token = std::str::from_utf8(assertion)
            .map_err(|_| AuthError::Unauthorized("assertion is not valid UTF-8 JWT text".into()))?;
        let parts: Vec<&str> = token.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::Unauthorized(
                "assertion is not a compact JWT (header.payload.signature)".into(),
            ));
        }
        let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);
        let header_raw = b64url_decode(header_b64)?;
        let payload_raw = b64url_decode(payload_b64)?;
        let signature_raw = b64url_decode(signature_b64)?;
        if signature_raw.len() != 64 {
            return Err(AuthError::Unauthorized(
                "JWT EdDSA signature must be 64 bytes".into(),
            ));
        }

        let header: JwtHeader = serde_json::from_slice(&header_raw)
            .map_err(|_| AuthError::Unauthorized("JWT header is not valid JSON".into()))?;
        if header.alg != "EdDSA" {
            return Err(AuthError::Unauthorized(format!(
                "unsupported JWT alg {:?}; expected EdDSA",
                header.alg
            )));
        }
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature: [u8; 64] = signature_raw
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Unauthorized("invalid JWT signature length".into()))?;

        let key = select_key(&self.keys, header.kid.as_deref())?;
        crate::signature_verification::verify_strict_bytes(
            key,
            "JWT signature",
            &signature,
            signing_input.as_bytes(),
        )
        .map_err(|error| AuthError::Unauthorized(error.to_string()))?;

        let claims: JwtClaims = serde_json::from_slice(&payload_raw)
            .map_err(|_| AuthError::Unauthorized("JWT payload is not valid JSON claims".into()))?;
        validate_claims(&claims, &self.config, now_unix_secs)
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    principal_kind: Option<String>,
    /// Tenant claim accepted only after signature verification.
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    tenkai_tenant: Option<String>,
    /// Explicit delivery RBAC claim: `["read"]`, `["management"]`, or both.
    #[serde(default)]
    tenkai_capabilities: Option<Vec<String>>,
}

fn validate_claims(
    claims: &JwtClaims,
    config: &JwtVerifierConfig,
    now_unix_secs: i64,
) -> Result<VerifiedAssertionClaims, AuthError> {
    if claims.iss != config.issuer {
        return Err(AuthError::Unauthorized(format!(
            "JWT issuer {:?} does not match trusted issuer",
            claims.iss
        )));
    }
    if claims.aud != config.audience {
        return Err(AuthError::Unauthorized(
            "JWT audience does not match expected audience".into(),
        ));
    }
    if claims.sub.trim().is_empty() {
        return Err(AuthError::Unauthorized(
            "JWT subject must not be empty".into(),
        ));
    }
    let skew = config.clock_skew_secs;
    if claims.exp + skew < now_unix_secs {
        return Err(AuthError::Unauthorized("JWT is expired".into()));
    }
    if let Some(nbf) = claims.nbf
        && nbf - skew > now_unix_secs
    {
        return Err(AuthError::Unauthorized("JWT is not valid yet (nbf)".into()));
    }
    let principal_kind = match claims.principal_kind.as_deref() {
        None | Some("human") => PrincipalKind::Human,
        Some("service") => PrincipalKind::Service,
        Some("runtime") => PrincipalKind::Runtime,
        Some("management") => PrincipalKind::Management,
        Some(other) => {
            return Err(AuthError::Unauthorized(format!(
                "unsupported principal_kind {other:?}"
            )));
        }
    };
    if let (Some(tenant_id), Some(tenkai_tenant)) = (&claims.tenant_id, &claims.tenkai_tenant)
        && tenant_id != tenkai_tenant
    {
        return Err(AuthError::Unauthorized(
            "JWT contains conflicting tenant claims".into(),
        ));
    }
    let tenant_id = claims
        .tenant_id
        .clone()
        .or_else(|| claims.tenkai_tenant.clone())
        .filter(|value| !value.trim().is_empty());
    let delivery_capabilities = match &claims.tenkai_capabilities {
        None => None,
        Some(values) => Some(parse_delivery_capabilities(values)?),
    };
    Ok(VerifiedAssertionClaims {
        issuer: claims.iss.clone(),
        audience: claims.aud.clone(),
        subject: claims.sub.clone(),
        expires_at: claims.exp,
        not_before: claims.nbf,
        principal_kind,
        tenant_id,
        delivery_capabilities,
    })
}

fn parse_delivery_capabilities(
    values: &[String],
) -> Result<std::collections::BTreeSet<DeliveryCapability>, AuthError> {
    let mut capabilities = std::collections::BTreeSet::new();
    for value in values {
        match value.as_str() {
            "read" => {
                capabilities.insert(DeliveryCapability::Read);
            }
            "management" => {
                capabilities.insert(DeliveryCapability::Management);
            }
            other => {
                return Err(AuthError::Unauthorized(format!(
                    "unsupported tenkai_capabilities value {other:?}"
                )));
            }
        }
    }
    Ok(capabilities)
}

fn select_key<'a>(
    keys: &'a [(Option<String>, VerifyingKey)],
    kid: Option<&str>,
) -> Result<&'a VerifyingKey, AuthError> {
    if let Some(kid) = kid {
        if let Some((_, key)) = keys.iter().find(|(id, _)| id.as_deref() == Some(kid)) {
            return Ok(key);
        }
        return Err(AuthError::Unauthorized(format!(
            "JWT kid {kid:?} is not trusted"
        )));
    }
    if keys.len() == 1 {
        return Ok(&keys[0].1);
    }
    Err(AuthError::Unauthorized(
        "JWT missing kid and multiple trust keys are configured".into(),
    ))
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey, AuthError> {
    // Shared trust seam: length, base64, weak-key rejection, and key parsing.
    crate::signature_verification::verifying_key("JWT public key", encoded.trim())
        .map_err(|error| AuthError::InvalidCredential(error.to_string()))
}

fn b64url_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .map_err(|_| AuthError::Unauthorized("JWT segment is not valid base64url".into()))
}

/// Enterprise auth extension that verifies JWTs via an [`AssertionVerifier`].
pub struct JwtEnterpriseAuthExtension {
    extension_id: String,
    expected_audience: String,
    verifier: Arc<dyn AssertionVerifier>,
    /// When true, missing tenant claim fails closed (tenant mode hosts).
    require_tenant: bool,
}

impl JwtEnterpriseAuthExtension {
    pub fn new(
        extension_id: impl Into<String>,
        expected_audience: impl Into<String>,
        verifier: Arc<dyn AssertionVerifier>,
        require_tenant: bool,
    ) -> Self {
        Self {
            extension_id: extension_id.into(),
            expected_audience: expected_audience.into(),
            verifier,
            require_tenant,
        }
    }

    pub fn from_jwt_verifier(
        extension_id: impl Into<String>,
        verifier: JwtAssertionVerifier,
        require_tenant: bool,
    ) -> Self {
        let audience = verifier.config().audience.clone();
        Self::new(extension_id, audience, Arc::new(verifier), require_tenant)
    }
}

impl EnterpriseAuthExtension for JwtEnterpriseAuthExtension {
    fn extension_id(&self) -> &str {
        &self.extension_id
    }

    fn contract_version(&self) -> u32 {
        AUTH_CONTEXT_CONTRACT_VERSION
    }

    fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
        authority: &TenantDerivationAuthority,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        let assertion = credential.assertion.as_ref().ok_or_else(|| {
            AuthError::InvalidCredential("enterprise JWT extension requires an assertion".into())
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let claims = self.verifier.verify(assertion, now)?;
        if claims.audience != self.expected_audience {
            return Err(AuthError::Unauthorized(
                "verified JWT audience does not match extension audience".into(),
            ));
        }
        // authenticator_id must equal extension_id (AuthStack adapter invariant).
        let mut builder = AuthenticatedRequestContextBuilder::new(
            credential.request_id.clone(),
            PrincipalIdentity {
                id: claims.subject,
                kind: claims.principal_kind,
            },
            self.extension_id.clone(),
        );
        // Explicit claim wins (including empty → deny). Absent claim keeps the
        // principal-kind defaults from the builder (Human/Runtime → none).
        if let Some(capabilities) = claims.delivery_capabilities {
            builder = builder.with_delivery_capabilities(capabilities);
        }
        match (&claims.tenant_id, self.require_tenant) {
            (Some(tenant_id), _) => {
                builder = builder.with_tenant(tenant_id, authority)?;
            }
            (None, true) => {
                return Err(AuthError::Unauthorized(
                    "JWT is missing required tenant_id claim".into(),
                ));
            }
            (None, false) => {}
        }
        builder.build()
    }
}

/// Current unix seconds for hosts that do not inject a clock.
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Diagnostic key fingerprint (sha256 of raw public key bytes). Never logs secrets.
pub fn public_key_fingerprint(public_key_b64: &str) -> Result<String, AuthError> {
    let key = decode_public_key(public_key_b64)?;
    Ok(crate::signature_verification::key_id(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::{AuthHostConfig, CommunityTokenAuthenticator, build_auth_stack};
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::BTreeMap;

    fn b64url_encode(input: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
    }

    fn mint_jwt(
        signing_key: &SigningKey,
        claims: &BTreeMap<String, serde_json::Value>,
        kid: Option<&str>,
    ) -> String {
        let mut header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
        if let Some(kid) = kid {
            header["kid"] = serde_json::Value::String(kid.into());
        }
        let header_b64 = b64url_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let payload_b64 = b64url_encode(serde_json::to_vec(claims).unwrap().as_slice());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = b64url_encode(&signature.to_bytes());
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    fn keypair() -> (SigningKey, String) {
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let public_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes());
        (signing, public_b64)
    }

    fn verifier(public_b64: &str) -> JwtAssertionVerifier {
        JwtAssertionVerifier::new(JwtVerifierConfig {
            issuer: "https://idp.example.test/".into(),
            audience: "tenkai-control-plane".into(),
            keys: vec![JwtTrustedKey {
                key_id: Some("k1".into()),
                public_key: public_b64.into(),
            }],
            clock_skew_secs: 60,
        })
        .unwrap()
    }

    fn base_claims(now: i64) -> BTreeMap<String, serde_json::Value> {
        BTreeMap::from([
            (
                "iss".into(),
                serde_json::Value::String("https://idp.example.test/".into()),
            ),
            (
                "aud".into(),
                serde_json::Value::String("tenkai-control-plane".into()),
            ),
            ("sub".into(), serde_json::Value::String("user-42".into())),
            ("exp".into(), serde_json::json!(now + 3600)),
            ("nbf".into(), serde_json::json!(now - 10)),
            (
                "principal_kind".into(),
                serde_json::Value::String("human".into()),
            ),
            (
                "tenant_id".into(),
                serde_json::Value::String("tenant-a".into()),
            ),
        ])
    }

    #[test]
    fn valid_jwt_yields_principal_and_tenant() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let token = mint_jwt(&signing, &base_claims(now), Some("k1"));
        let claims = v.verify(token.as_bytes(), now).unwrap();
        assert_eq!(claims.subject, "user-42");
        assert_eq!(claims.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(claims.audience, "tenkai-control-plane");
    }

    #[test]
    fn bad_signature_fails_closed() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let mut token = mint_jwt(&signing, &base_claims(now), Some("k1"));
        // Flip last character of signature segment.
        token.pop();
        token.push(if token.ends_with('A') { 'B' } else { 'A' });
        let err = v.verify(token.as_bytes(), now).unwrap_err().to_string();
        assert!(
            err.contains("signature") || err.contains("Unauthorized") || err.contains("base64"),
            "{err}"
        );
    }

    #[test]
    fn wrong_audience_fails_closed() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let mut claims = base_claims(now);
        claims.insert(
            "aud".into(),
            serde_json::Value::String("other-audience".into()),
        );
        let token = mint_jwt(&signing, &claims, Some("k1"));
        let err = v.verify(token.as_bytes(), now).unwrap_err().to_string();
        assert!(err.contains("audience"), "{err}");
    }

    #[test]
    fn wrong_issuer_fails_closed() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let mut claims = base_claims(now);
        claims.insert(
            "iss".into(),
            serde_json::Value::String("https://forged-issuer.example.test/".into()),
        );
        let token = mint_jwt(&signing, &claims, Some("k1"));
        let err = v.verify(token.as_bytes(), now).unwrap_err().to_string();
        assert!(err.contains("issuer"), "{err}");
    }

    #[test]
    fn malformed_jwt_fails_closed() {
        let (_, public_b64) = keypair();
        let v = verifier(&public_b64);
        let err = v
            .verify(b"not-a-compact-jwt", 1_700_000_000_i64)
            .unwrap_err()
            .to_string();
        assert!(err.contains("compact JWT"), "{err}");
    }

    #[test]
    fn expired_jwt_fails_closed() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let mut claims = base_claims(now);
        claims.insert("exp".into(), serde_json::json!(now - 120));
        let token = mint_jwt(&signing, &claims, Some("k1"));
        let err = v.verify(token.as_bytes(), now).unwrap_err().to_string();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn conflicting_tenant_claims_fail_closed() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let mut claims = base_claims(now);
        claims.insert(
            "tenkai_tenant".into(),
            serde_json::Value::String("tenant-b".into()),
        );
        let token = mint_jwt(&signing, &claims, Some("k1"));
        let err = v.verify(token.as_bytes(), now).unwrap_err().to_string();
        assert!(err.contains("conflicting tenant"), "{err}");
    }

    #[test]
    fn human_jwt_without_capabilities_has_empty_delivery_set() {
        let (signing, public_b64) = keypair();
        let jwt = verifier(&public_b64);
        let extension = Arc::new(JwtEnterpriseAuthExtension::from_jwt_verifier(
            "jwt-ref", jwt, true,
        ));
        let now = now_unix_secs();
        let token = mint_jwt(&signing, &base_claims(now), Some("k1"));
        let ctx = extension
            .authenticate(
                &CredentialMaterial {
                    request_id: "cap-1".into(),
                    bearer_token: None,
                    assertion: Some(token.into_bytes()),
                },
                &TenantDerivationAuthority::new("jwt-ref"),
            )
            .unwrap();
        assert_eq!(ctx.principal.kind, PrincipalKind::Human);
        assert!(!ctx.has_delivery_capability(DeliveryCapability::Read));
        assert!(!ctx.has_delivery_capability(DeliveryCapability::Management));
    }

    #[test]
    fn tenkai_capabilities_claim_is_honored_and_unknown_values_fail_closed() {
        let (signing, public_b64) = keypair();
        let v = verifier(&public_b64);
        let now = 1_700_000_000_i64;
        let mut claims = base_claims(now);
        claims.insert(
            "tenkai_capabilities".into(),
            serde_json::json!(["read", "management"]),
        );
        let token = mint_jwt(&signing, &claims, Some("k1"));
        let verified = v.verify(token.as_bytes(), now).unwrap();
        assert_eq!(
            verified.delivery_capabilities,
            Some(std::collections::BTreeSet::from([
                DeliveryCapability::Read,
                DeliveryCapability::Management,
            ]))
        );

        claims.insert("tenkai_capabilities".into(), serde_json::json!(["admin"]));
        let bad = mint_jwt(&signing, &claims, Some("k1"));
        let err = v.verify(bad.as_bytes(), now).unwrap_err().to_string();
        assert!(err.contains("tenkai_capabilities"), "{err}");
    }

    #[test]
    fn extension_builds_auth_context_without_leaking_keys() {
        let (signing, public_b64) = keypair();
        let jwt = verifier(&public_b64);
        let extension = Arc::new(JwtEnterpriseAuthExtension::from_jwt_verifier(
            "jwt-ref", jwt, true,
        )) as Arc<dyn EnterpriseAuthExtension>;
        let community = Arc::new(
            CommunityTokenAuthenticator::new(
                "community",
                BTreeMap::from([(
                    "mgmt".into(),
                    PrincipalIdentity {
                        id: "community-admin".into(),
                        kind: PrincipalKind::Management,
                    },
                )]),
            )
            .unwrap(),
        );
        let stack = build_auth_stack(
            &AuthHostConfig {
                required_extension_id: Some("jwt-ref".into()),
                expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
                expected_audience: Some("tenkai-control-plane".into()),
            },
            Some(extension),
            community,
        )
        .unwrap();
        let now = now_unix_secs();
        let token = mint_jwt(&signing, &base_claims(now), Some("k1"));
        let ctx = stack
            .authenticate(&CredentialMaterial {
                request_id: "req-1".into(),
                bearer_token: None,
                assertion: Some(token.into_bytes()),
            })
            .unwrap();
        assert_eq!(ctx.principal_id(), "user-42");
        assert_eq!(ctx.tenant().unwrap().tenant_id(), "tenant-a");
        let debug = format!("{ctx:?}");
        assert!(!debug.contains(&public_b64));
        assert!(!debug.contains("-----BEGIN"));
    }

    #[test]
    fn community_stack_unchanged_without_verifier() {
        let community = Arc::new(
            CommunityTokenAuthenticator::new(
                "community",
                BTreeMap::from([(
                    "mgmt".into(),
                    PrincipalIdentity {
                        id: "admin".into(),
                        kind: PrincipalKind::Management,
                    },
                )]),
            )
            .unwrap(),
        );
        let stack = build_auth_stack(&AuthHostConfig::community(), None, community).unwrap();
        let ctx = stack
            .authenticate(&CredentialMaterial {
                request_id: "r".into(),
                bearer_token: Some("mgmt".into()),
                assertion: None,
            })
            .unwrap();
        assert_eq!(ctx.principal_id(), "admin");
        assert!(ctx.tenant().is_none());
    }

    #[test]
    fn trust_config_round_trip_from_file() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-jwt-trust-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jwt-trust.toml");
        let (_, public_b64) = keypair();
        std::fs::write(
            &path,
            format!(
                r#"
issuer = "https://idp.example.test/"
audience = "tenkai-control-plane"
clock_skew_secs = 30

[[keys]]
key_id = "k1"
public_key = "{public_b64}"
"#
            ),
        )
        .unwrap();
        let loaded = JwtVerifierConfig::load(&path).unwrap();
        assert_eq!(loaded.clock_skew_secs, 30);
        assert_eq!(loaded.keys.len(), 1);
        let fp = public_key_fingerprint(&public_b64).unwrap();
        assert!(fp.starts_with("sha256:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn weak_public_keys_are_rejected_at_trust_load() {
        let weak = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let err = JwtAssertionVerifier::new(JwtVerifierConfig {
            issuer: "https://idp.example.test/".into(),
            audience: "tenkai-control-plane".into(),
            keys: vec![JwtTrustedKey {
                key_id: Some("weak".into()),
                public_key: weak,
            }],
            clock_skew_secs: 60,
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("weak") || err.contains("JWT public key"),
            "{err}"
        );
    }
}

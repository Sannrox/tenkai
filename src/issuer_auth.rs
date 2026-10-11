//! Multi-issuer enterprise authentication (#589).
//!
//! A host may load more than one verifier in one process. Tokens are selected
//! by unverified JWT `iss`, then the matching verifier still checks signature,
//! audience, lifetime, and claims. Unknown issuers fail closed.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::assertion_verifier::unverified_jwt_issuer;
use crate::auth_context::{
    AUTH_CONTEXT_CONTRACT_VERSION, AuthError, AuthenticatedRequestContext, CredentialMaterial,
    EnterpriseAuthExtension, TenantDerivationAuthority,
};

/// Extension id when more than one issuer verifier is loaded.
pub const ISSUER_AUTH_EXTENSION_ID: &str = "auth.issuers";

/// Dispatches compact JWTs to the verifier configured for their `iss`.
pub struct IssuerAuthExtension {
    verifiers: BTreeMap<String, Arc<dyn EnterpriseAuthExtension>>,
}

impl IssuerAuthExtension {
    /// `verifiers` is `(issuer, extension)`. Issuers must be unique and there
    /// must be at least two, so JWT-only and OIDC-only hosts keep their own
    /// extension ids.
    pub fn new(
        verifiers: impl IntoIterator<Item = (String, Arc<dyn EnterpriseAuthExtension>)>,
    ) -> Result<Self, AuthError> {
        let mut map = BTreeMap::new();
        for (issuer, extension) in verifiers {
            let issuer = issuer.trim();
            if issuer.is_empty() {
                return Err(AuthError::InvalidCredential(
                    "issuer auth verifier issuer must not be empty".into(),
                ));
            }
            if map.insert(issuer.to_string(), extension).is_some() {
                return Err(AuthError::InvalidCredential(format!(
                    "issuer {issuer:?} is configured on more than one verifier"
                )));
            }
        }
        if map.len() < 2 {
            return Err(AuthError::InvalidCredential(
                "issuer auth requires at least two verifiers".into(),
            ));
        }
        Ok(Self { verifiers: map })
    }

    pub fn issuers(&self) -> impl Iterator<Item = &str> {
        self.verifiers.keys().map(String::as_str)
    }
}

impl EnterpriseAuthExtension for IssuerAuthExtension {
    fn extension_id(&self) -> &str {
        ISSUER_AUTH_EXTENSION_ID
    }

    fn contract_version(&self) -> u32 {
        AUTH_CONTEXT_CONTRACT_VERSION
    }

    fn expected_audience(&self) -> &str {
        // Each inner verifier checks its own audience.
        ""
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
        authority: &TenantDerivationAuthority,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        let token = credential.assertion.as_deref().ok_or_else(|| {
            AuthError::InvalidCredential("issuer auth requires a compact JWT assertion".into())
        })?;
        let issuer = unverified_jwt_issuer(token)?;
        let Some(extension) = self.verifiers.get(&issuer) else {
            return Err(AuthError::Unauthorized(
                "token issuer is not trusted".into(),
            ));
        };
        let mut context = extension.authenticate(credential, authority)?;
        // AuthStack requires authenticator_id to match the loaded extension.
        context.authenticator_id = ISSUER_AUTH_EXTENSION_ID.to_string();
        context.validate()?;
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion_verifier::{
        JwtAssertionVerifier, JwtEnterpriseAuthExtension, JwtTrustedKey, JwtVerifierConfig,
        TENKAI_TENANT_CLAIM_DEPRECATION, take_tenkai_tenant_deprecation,
    };
    use crate::auth_context::{
        AuthHostConfig, CommunityTokenAuthenticator, DeliveryCapability, PrincipalIdentity,
        PrincipalKind, build_auth_stack,
    };
    use crate::oidc_verifier::test_support::{Signer, jwks};
    use crate::oidc_verifier::{JwksCache, KeySource, OidcAuthExtension};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const JWT_ISS: &str = "https://aldunis.example.test/";
    const JWT_AUD: &str = "tenkai-control-plane";
    const OIDC_ISS: &str = "https://idp.example.test/realms/ops";
    const OIDC_AUD: &str = "tenkai";
    const JWT_EXT: &str = "auth.jwt.aldunis";

    fn b64url_encode(input: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
    }

    fn mint_platform_jwt(
        signing_key: &SigningKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
        let header_b64 = b64url_encode(header.to_string().as_bytes());
        let payload_b64 = b64url_encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        format!(
            "{header_b64}.{payload_b64}.{}",
            b64url_encode(&signature.to_bytes())
        )
    }

    fn platform_claims(now: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": JWT_ISS,
            "aud": JWT_AUD,
            "sub": "platform-user",
            "exp": now + 3600,
            "nbf": now - 10,
            "principal_kind": "human",
            "tenant_id": "tenant-a",
            "tenkai_capabilities": ["read", "management"],
        })
    }

    fn jwt_extension(public_b64: &str, require_tenant: bool) -> Arc<dyn EnterpriseAuthExtension> {
        let verifier = JwtAssertionVerifier::new(JwtVerifierConfig {
            issuer: JWT_ISS.into(),
            audience: JWT_AUD.into(),
            keys: vec![JwtTrustedKey {
                key_id: Some("k1".into()),
                public_key: public_b64.into(),
            }],
            clock_skew_secs: 60,
        })
        .unwrap();
        Arc::new(JwtEnterpriseAuthExtension::from_jwt_verifier(
            JWT_EXT,
            verifier,
            require_tenant,
        ))
    }

    fn oidc_config() -> crate::oidc_verifier::OidcConfig {
        toml::from_str(&format!(
            r#"
issuer = "{OIDC_ISS}"
audience = "{OIDC_AUD}"
[grants]
claim = "groups"
tenant_claim = "tenant_id"
[[grants.rules]]
value = "tenkai-admins"
capabilities = ["read", "management"]
"#
        ))
        .unwrap()
    }

    fn oidc_extension(signer: &Signer, require_tenant: bool) -> Arc<dyn EnterpriseAuthExtension> {
        let source: Arc<dyn KeySource> = Arc::new({
            let raw = jwks(&[signer]);
            move || Ok(raw.clone())
        });
        let cache = JwksCache::load(source).unwrap();
        Arc::new(
            OidcAuthExtension::new(oidc_config(), Arc::new(cache), None, require_tenant).unwrap(),
        )
    }

    fn keypair() -> (SigningKey, String) {
        let signing = SigningKey::from_bytes(&[11_u8; 32]);
        let public_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes());
        (signing, public_b64)
    }

    fn dual_stack(
        jwt: Arc<dyn EnterpriseAuthExtension>,
        oidc: Arc<dyn EnterpriseAuthExtension>,
    ) -> crate::auth_context::AuthStack {
        let routed = IssuerAuthExtension::new(vec![
            (JWT_ISS.to_string(), jwt),
            (OIDC_ISS.to_string(), oidc),
        ])
        .unwrap();
        assert_eq!(
            routed.issuers().collect::<Vec<_>>(),
            vec![JWT_ISS, OIDC_ISS]
        );
        let extension = Arc::new(routed);
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
        build_auth_stack(
            &AuthHostConfig {
                required_extension_id: Some(ISSUER_AUTH_EXTENSION_ID.into()),
                expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
                expected_audience: None,
            },
            Some(extension),
            community,
        )
        .unwrap()
    }

    fn assertion(request_id: &str, token: impl Into<Vec<u8>>) -> CredentialMaterial {
        let token = token.into();
        let bearer = String::from_utf8(token.clone()).ok();
        CredentialMaterial {
            request_id: request_id.into(),
            bearer_token: bearer,
            assertion: Some(token),
        }
    }

    #[test]
    fn same_process_accepts_platform_jwt_and_oidc_token() {
        let (signing, public_b64) = keypair();
        let signer = Signer::new("k1");
        let stack = dual_stack(
            jwt_extension(&public_b64, true),
            oidc_extension(&signer, true),
        );
        let now = crate::assertion_verifier::now_unix_secs();

        let platform = stack
            .authenticate(&assertion(
                "req-jwt",
                mint_platform_jwt(&signing, &platform_claims(now), "k1").into_bytes(),
            ))
            .unwrap();
        assert_eq!(platform.principal_id(), "platform-user");
        assert_eq!(
            platform.tenant().map(|tenant| tenant.tenant_id()),
            Some("tenant-a")
        );
        assert!(platform.has_delivery_capability(DeliveryCapability::Management));
        assert_eq!(platform.authenticator_id, ISSUER_AUTH_EXTENSION_ID);

        let oidc_claims = serde_json::json!({
            "iss": OIDC_ISS,
            "sub": "oidc-user",
            "aud": [OIDC_AUD, "account"],
            "exp": now + 300,
            "nbf": now - 10,
            "groups": ["tenkai-admins"],
            "tenant_id": "tenant-b",
        });
        let oidc = stack
            .authenticate(&assertion("req-oidc", signer.sign(&oidc_claims)))
            .unwrap();
        assert_eq!(oidc.principal_id(), format!("oidc-user@{OIDC_ISS}"));
        assert_eq!(
            oidc.tenant().map(|tenant| tenant.tenant_id()),
            Some("tenant-b")
        );
        assert!(oidc.has_delivery_capability(DeliveryCapability::Management));
        assert_eq!(oidc.authenticator_id, ISSUER_AUTH_EXTENSION_ID);

        let community = stack
            .authenticate(&CredentialMaterial {
                request_id: "req-mgmt".into(),
                bearer_token: Some("mgmt".into()),
                assertion: None,
            })
            .unwrap();
        assert_eq!(community.principal_id(), "community-admin");
        assert!(community.tenant().is_none());
    }

    #[test]
    fn unknown_issuer_is_rejected() {
        let (signing, public_b64) = keypair();
        let signer = Signer::new("k1");
        let stack = dual_stack(
            jwt_extension(&public_b64, true),
            oidc_extension(&signer, true),
        );
        let now = crate::assertion_verifier::now_unix_secs();
        let mut claims = platform_claims(now);
        claims["iss"] = serde_json::json!("https://unknown.example.test/");
        let err = stack
            .authenticate(&assertion(
                "req-unknown",
                mint_platform_jwt(&signing, &claims, "k1").into_bytes(),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("issuer is not trusted"), "{err}");
    }

    #[test]
    fn oidc_token_without_mapped_tenant_is_rejected_on_tenant_hosts() {
        let (_, public_b64) = keypair();
        let signer = Signer::new("k1");
        let stack = dual_stack(
            jwt_extension(&public_b64, true),
            oidc_extension(&signer, true),
        );
        let now = crate::assertion_verifier::now_unix_secs();
        let claims = serde_json::json!({
            "iss": OIDC_ISS,
            "sub": "oidc-user",
            "aud": [OIDC_AUD],
            "exp": now + 300,
            "nbf": now - 10,
            "groups": ["tenkai-admins"],
        });
        let err = stack
            .authenticate(&assertion("req-no-tenant", signer.sign(&claims)))
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)), "{err:?}");
        assert!(err.to_string().contains("tenant"), "{err}");
    }

    #[test]
    fn duplicate_issuers_fail_closed() {
        let (_, public_b64) = keypair();
        let signer = Signer::new("k1");
        let err = IssuerAuthExtension::new(vec![
            (JWT_ISS.to_string(), jwt_extension(&public_b64, false)),
            (JWT_ISS.to_string(), oidc_extension(&signer, false)),
        ])
        .err()
        .expect("duplicate issuers must fail")
        .to_string();
        assert!(err.contains("more than one verifier"), "{err}");
    }

    #[test]
    fn tenkai_tenant_alone_still_authenticates_with_deprecation() {
        let _ = take_tenkai_tenant_deprecation();
        let (signing, public_b64) = keypair();
        let signer = Signer::new("k1");
        let stack = dual_stack(
            jwt_extension(&public_b64, true),
            oidc_extension(&signer, true),
        );
        let now = crate::assertion_verifier::now_unix_secs();
        let mut claims = platform_claims(now);
        claims.as_object_mut().unwrap().remove("tenant_id");
        claims["tenkai_tenant"] = serde_json::json!("tenant-a");
        let context = stack
            .authenticate(&assertion(
                "req-deprecated",
                mint_platform_jwt(&signing, &claims, "k1").into_bytes(),
            ))
            .unwrap();
        assert_eq!(
            context.tenant().map(|tenant| tenant.tenant_id()),
            Some("tenant-a")
        );
        assert_eq!(
            take_tenkai_tenant_deprecation(),
            Some(TENKAI_TENANT_CLAIM_DEPRECATION)
        );
    }
}

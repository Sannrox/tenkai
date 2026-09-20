use super::*;

/// Enterprise extension that maps a JSON assertion `{"tenant":"...","principal":"..."}`
/// into authenticated tenant context for router isolation tests.
pub(super) struct TenantAssertionExtension;

impl EnterpriseAuthExtension for TenantAssertionExtension {
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
        credential: &CredentialMaterial,
        authority: &crate::auth_context::TenantDerivationAuthority,
    ) -> Result<AuthenticatedRequestContext, crate::auth_context::AuthError> {
        let raw = credential.assertion.as_ref().ok_or_else(|| {
            crate::auth_context::AuthError::InvalidCredential("assertion required".into())
        })?;
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|error| {
            crate::auth_context::AuthError::InvalidCredential(error.to_string())
        })?;
        let tenant = value
            .get("tenant")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                crate::auth_context::AuthError::InvalidCredential("tenant claim required".into())
            })?;
        let principal = value
            .get("principal")
            .and_then(|v| v.as_str())
            .unwrap_or("enterprise-user");
        let kind = match value.get("kind").and_then(|value| value.as_str()) {
            Some("service") => PrincipalKind::Service,
            Some("management") => PrincipalKind::Management,
            _ => PrincipalKind::Human,
        };
        let mut builder = crate::auth_context::AuthenticatedRequestContextBuilder::new(
            credential.request_id.clone(),
            PrincipalIdentity {
                id: principal.into(),
                kind,
            },
            self.extension_id(),
        );
        if let Some(capabilities) = value.get("capabilities").and_then(|value| value.as_array()) {
            let mut parsed = std::collections::BTreeSet::new();
            for capability in capabilities {
                match capability.as_str() {
                    Some("read") => {
                        parsed.insert(crate::auth_context::DeliveryCapability::Read);
                    }
                    Some("management") => {
                        parsed.insert(crate::auth_context::DeliveryCapability::Management);
                    }
                    _ => {
                        return Err(crate::auth_context::AuthError::Unauthorized(
                            "unsupported capability claim".into(),
                        ));
                    }
                }
            }
            builder = builder.with_delivery_capabilities(parsed);
        }
        builder.with_tenant(tenant, authority)?.build()
    }
}

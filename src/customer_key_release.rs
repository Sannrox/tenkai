//! Distribute, rotate, and revoke customer data keys as ordinary releases.
//!
//! The document type lives in `tenkai-keys` so Tenkai and the products that
//! consume a release share one type and one adapter set. Tenkai keeps the
//! preflight: every component can unwrap before the release ships. Rotation and
//! revocation are the same document with a new wrapping KEK or a revoked KEK id.

use anyhow::{Result, bail};
use sekai_keys::{KeyProvider, ProviderKind, TenantId, UnwrapGrant};
use tenkai_keys::pkcs11::Pkcs11KeyProvider;
pub use tenkai_keys::release::{
    CustomerKeyRelease, DOCUMENT_SCHEMA, DistributedDataKey, KeyReleaseIntent, ProviderEndpoint,
};

/// Preflight: every wrapped key in the release unwraps at this provider.
pub fn preflight_unwrap(provider: &Pkcs11KeyProvider, document: &CustomerKeyRelease) -> Result<()> {
    document.refuse_plaintext()?;
    if document.intent == KeyReleaseIntent::Revoke {
        bail!("revoked customer-key release fails closed");
    }
    if document.provider.kind != "pkcs11" || document.provider.token_label.is_empty() {
        bail!("customer-key preflight requires a PKCS#11 provider endpoint");
    }
    if let Some(module) = &document.provider.module
        && !module.exists()
    {
        bail!("customer-key provider module is missing");
    }
    let described = provider.describe();
    if described.kind != ProviderKind::Pkcs11 {
        bail!("customer-key preflight requires a PKCS#11 provider");
    }
    for key in &document.data_keys {
        let wrapped = key.wrapped_dek()?;
        let grant = UnwrapGrant {
            tenant_id: TenantId::new(&key.tenant)?,
            purpose: wrapped.purpose,
            expires_unix_secs: i64::MAX,
        };
        provider
            .unwrap(&wrapped, &grant, "tenkai", 1)
            .map_err(|error| anyhow::anyhow!("component cannot unwrap {}: {error}", key.key_id))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_keys::{Dek, KeyPurpose, RuntimeProfile};
    use std::path::PathBuf;
    use tenkai_keys::pkcs11::{TEST_USER_PIN, next_software_token};

    fn provider() -> Option<(Pkcs11KeyProvider, String, PathBuf)> {
        let (module, label) = next_software_token()?;
        let provider =
            Pkcs11KeyProvider::open(&module, &label, TEST_USER_PIN, RuntimeProfile::Production)
                .expect("open pkcs11");
        Some((provider, label, module))
    }

    #[test]
    fn ceremony_deploy_rotate_revoke_with_pkcs11_software_token() {
        let Some((provider, label, module)) = provider() else {
            return;
        };
        let tenant = TenantId::new("acme").expect("tenant");
        let dek = Dek::generate();
        let wrapped = provider
            .wrap(&tenant, KeyPurpose::Store, &dek)
            .expect("wrap");
        let endpoint = ProviderEndpoint {
            kind: "pkcs11".into(),
            token_label: label,
            module: Some(module),
        };
        let deploy = CustomerKeyRelease::deploy(endpoint.clone(), &wrapped).expect("deploy");
        let json = deploy.to_json().expect("json");
        let hint: String = dek
            .as_bytes()
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!json.contains(&hint), "release json leaked DEK bytes");
        assert!(!json.contains("root.kek"));
        preflight_unwrap(&provider, &deploy).expect("deploy unwrap");

        provider.rotate_kek().expect("rotate");
        let rotated = provider.rewrap(&wrapped, &dek).expect("rewrap");
        let rotate = CustomerKeyRelease::rotate(endpoint.clone(), &rotated).expect("rotate");
        preflight_unwrap(&provider, &rotate).expect("rotate still unwraps");

        let kek_id = wrapped.kek_id.as_str().to_string();
        provider.revoke_kek().expect("revoke");
        let revoke = CustomerKeyRelease::revoke(endpoint, &wrapped, &kek_id).expect("revoke doc");
        let error = preflight_unwrap(&provider, &revoke)
            .expect_err("revoked release must fail closed")
            .to_string();
        assert!(
            error.contains("fails closed") || error.contains("cannot unwrap"),
            "{error}"
        );
    }
}

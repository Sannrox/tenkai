//! Distribute, rotate, and revoke customer data keys as ordinary releases.
//!
//! Release configuration carries wrapped DEKs and a provider endpoint. Plaintext
//! keys never appear in the document. Preflight checks that every component can
//! unwrap. Rotation and revocation are the same document with a new wrapping
//! KEK or a revoked KEK id.

use std::path::PathBuf;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sekai_keys::{KeyId, KeyProvider, KeyPurpose, ProviderKind, TenantId, UnwrapGrant, WrappedDek};
use serde::{Deserialize, Serialize};

use crate::pkcs11_provider::Pkcs11KeyProvider;

pub const DOCUMENT_SCHEMA: &str = "tenkai.customer-key-release.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyReleaseIntent {
    Deploy,
    Rotate,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEndpoint {
    pub kind: String,
    pub token_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributedDataKey {
    pub tenant: String,
    pub key_id: String,
    pub kek_id: String,
    pub purpose: String,
    pub wrapped: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerKeyRelease {
    pub schema: String,
    pub intent: KeyReleaseIntent,
    pub provider: ProviderEndpoint,
    pub data_keys: Vec<DistributedDataKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_kek_id: Option<String>,
}

impl CustomerKeyRelease {
    pub fn deploy(provider: ProviderEndpoint, wrapped: &WrappedDek) -> Result<Self> {
        Ok(Self {
            schema: DOCUMENT_SCHEMA.into(),
            intent: KeyReleaseIntent::Deploy,
            provider,
            data_keys: vec![distributed(wrapped)?],
            revoked_kek_id: None,
        })
    }

    pub fn rotate(provider: ProviderEndpoint, wrapped: &WrappedDek) -> Result<Self> {
        let mut document = Self::deploy(provider, wrapped)?;
        document.intent = KeyReleaseIntent::Rotate;
        Ok(document)
    }

    pub fn revoke(provider: ProviderEndpoint, wrapped: &WrappedDek, kek_id: &str) -> Result<Self> {
        let mut document = Self::deploy(provider, wrapped)?;
        document.intent = KeyReleaseIntent::Revoke;
        document.revoked_kek_id = Some(kek_id.to_string());
        Ok(document)
    }

    pub fn to_json(&self) -> Result<String> {
        refuse_plaintext(self)?;
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let document: Self = serde_json::from_str(raw)?;
        if document.schema != DOCUMENT_SCHEMA {
            bail!(
                "unsupported customer-key release schema {}",
                document.schema
            );
        }
        refuse_plaintext(&document)?;
        Ok(document)
    }
}

fn distributed(wrapped: &WrappedDek) -> Result<DistributedDataKey> {
    Ok(DistributedDataKey {
        tenant: wrapped.tenant_id.as_str().to_string(),
        key_id: wrapped.dek_id.as_str().to_string(),
        kek_id: wrapped.kek_id.as_str().to_string(),
        purpose: purpose_name(wrapped.purpose).into(),
        wrapped: STANDARD.encode(wrapped.ciphertext()),
    })
}

fn parse_purpose(name: &str) -> Result<KeyPurpose> {
    match name {
        "store" => Ok(KeyPurpose::Store),
        "spill" => Ok(KeyPurpose::Spill),
        "cache" => Ok(KeyPurpose::Cache),
        "backup" => Ok(KeyPurpose::Backup),
        "export" => Ok(KeyPurpose::Export),
        _ => bail!("unknown data-key purpose {name}"),
    }
}

fn purpose_name(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Store => "store",
        KeyPurpose::Spill => "spill",
        KeyPurpose::Cache => "cache",
        KeyPurpose::Backup => "backup",
        KeyPurpose::Export => "export",
    }
}

fn refuse_plaintext(document: &CustomerKeyRelease) -> Result<()> {
    let encoded = serde_json::to_string(document)?;
    if encoded.contains("Dek(") || encoded.contains("root.kek") {
        bail!("customer-key release must not contain plaintext key material");
    }
    for key in &document.data_keys {
        if STANDARD
            .decode(&key.wrapped)
            .map(|bytes| bytes.len())
            .unwrap_or(0)
            < 13
        {
            bail!("wrapped data key {} is truncated", key.key_id);
        }
    }
    if document.provider.kind == "software"
        || document.provider.kind == "file"
        || document.provider.kind == "memory"
    {
        bail!(
            "customer-key release refuses lab-only provider {}",
            document.provider.kind
        );
    }
    Ok(())
}

/// Preflight: every wrapped key in the release unwraps at this provider.
pub fn preflight_unwrap(provider: &Pkcs11KeyProvider, document: &CustomerKeyRelease) -> Result<()> {
    refuse_plaintext(document)?;
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
        let ciphertext = STANDARD.decode(&key.wrapped)?;
        let purpose = parse_purpose(&key.purpose)?;
        let wrapped = WrappedDek::new(
            KeyId::new(&key.kek_id)?,
            KeyId::new(&key.key_id)?,
            TenantId::new(&key.tenant)?,
            purpose,
            ciphertext,
        )?;
        let grant = UnwrapGrant {
            tenant_id: TenantId::new(&key.tenant)?,
            purpose,
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
    use crate::pkcs11_provider::{TEST_USER_PIN, next_software_token};
    use sekai_keys::{Dek, RuntimeProfile};

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

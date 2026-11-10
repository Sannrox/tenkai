//! `tenkai.customer-key-release.v1`: distribute, rotate, and revoke customer
//! data keys as ordinary releases.
//!
//! Release configuration carries wrapped DEKs and a provider endpoint. Plaintext
//! keys never appear in the document. Rotation and revocation are the same
//! document with a new wrapping KEK or a revoked KEK id. Tenkai writes this
//! document; a delivered product parses it with the same type and unwraps each
//! listed key through the provider it names ([`crate::open_provider`]).

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sekai_keys::{KeyError, KeyId, KeyPurpose, TenantId, WrappedDek};
use serde::{Deserialize, Serialize};

pub const DOCUMENT_SCHEMA: &str = "tenkai.customer-key-release.v1";

/// Why a release document was refused.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("unsupported customer-key release schema {0}")]
    UnsupportedSchema(String),
    #[error("customer-key release must not contain plaintext key material")]
    PlaintextKeyMaterial,
    #[error("wrapped data key {0} is truncated")]
    TruncatedKey(String),
    #[error("customer-key release refuses lab-only provider {0}")]
    LabOnlyProvider(String),
    #[error("unknown data-key purpose {0}")]
    UnknownPurpose(String),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Key(#[from] KeyError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyReleaseIntent {
    Deploy,
    Rotate,
    Revoke,
}

/// The provider every listed data key unwraps through. `kind` is the
/// deploy-profile provider name (`pkcs11`, `kmip`, ...).
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

impl DistributedDataKey {
    /// Decode this entry into the envelope a [`sekai_keys::KeyProvider`] unwraps.
    pub fn wrapped_dek(&self) -> Result<WrappedDek, ReleaseError> {
        let ciphertext = STANDARD.decode(&self.wrapped)?;
        let purpose = parse_purpose(&self.purpose)?;
        Ok(WrappedDek::new(
            KeyId::new(&self.kek_id)?,
            KeyId::new(&self.key_id)?,
            TenantId::new(&self.tenant)?,
            purpose,
            ciphertext,
        )?)
    }
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
    pub fn deploy(provider: ProviderEndpoint, wrapped: &WrappedDek) -> Result<Self, ReleaseError> {
        Ok(Self {
            schema: DOCUMENT_SCHEMA.into(),
            intent: KeyReleaseIntent::Deploy,
            provider,
            data_keys: vec![distributed(wrapped)],
            revoked_kek_id: None,
        })
    }

    pub fn rotate(provider: ProviderEndpoint, wrapped: &WrappedDek) -> Result<Self, ReleaseError> {
        let mut document = Self::deploy(provider, wrapped)?;
        document.intent = KeyReleaseIntent::Rotate;
        Ok(document)
    }

    pub fn revoke(
        provider: ProviderEndpoint,
        wrapped: &WrappedDek,
        kek_id: &str,
    ) -> Result<Self, ReleaseError> {
        let mut document = Self::deploy(provider, wrapped)?;
        document.intent = KeyReleaseIntent::Revoke;
        document.revoked_kek_id = Some(kek_id.to_string());
        Ok(document)
    }

    pub fn to_json(&self) -> Result<String, ReleaseError> {
        self.refuse_plaintext()?;
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(raw: &str) -> Result<Self, ReleaseError> {
        let document: Self = serde_json::from_str(raw)?;
        if document.schema != DOCUMENT_SCHEMA {
            return Err(ReleaseError::UnsupportedSchema(document.schema));
        }
        document.refuse_plaintext()?;
        Ok(document)
    }

    /// Refuse plaintext key material, truncated envelopes, and lab-only
    /// providers. Every parse and every write runs this check.
    pub fn refuse_plaintext(&self) -> Result<(), ReleaseError> {
        let encoded = serde_json::to_string(self)?;
        if encoded.contains("Dek(") || encoded.contains("root.kek") {
            return Err(ReleaseError::PlaintextKeyMaterial);
        }
        for key in &self.data_keys {
            if STANDARD
                .decode(&key.wrapped)
                .map(|bytes| bytes.len())
                .unwrap_or(0)
                < 13
            {
                return Err(ReleaseError::TruncatedKey(key.key_id.clone()));
            }
        }
        if matches!(self.provider.kind.as_str(), "software" | "file" | "memory") {
            return Err(ReleaseError::LabOnlyProvider(self.provider.kind.clone()));
        }
        Ok(())
    }
}

fn distributed(wrapped: &WrappedDek) -> DistributedDataKey {
    DistributedDataKey {
        tenant: wrapped.tenant_id.as_str().to_string(),
        key_id: wrapped.dek_id.as_str().to_string(),
        kek_id: wrapped.kek_id.as_str().to_string(),
        purpose: purpose_name(wrapped.purpose).into(),
        wrapped: STANDARD.encode(wrapped.ciphertext()),
    }
}

fn parse_purpose(name: &str) -> Result<KeyPurpose, ReleaseError> {
    match name {
        "store" => Ok(KeyPurpose::Store),
        "spill" => Ok(KeyPurpose::Spill),
        "cache" => Ok(KeyPurpose::Cache),
        "backup" => Ok(KeyPurpose::Backup),
        "export" => Ok(KeyPurpose::Export),
        _ => Err(ReleaseError::UnknownPurpose(name.to_string())),
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

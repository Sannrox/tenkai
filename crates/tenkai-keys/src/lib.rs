//! Customer-key release document and key-provider adapters.
//!
//! Tenkai writes `tenkai.customer-key-release.v1` ([`release`]). A delivered
//! product depends on this crate to parse that document with the same type and
//! open the provider it names as a [`sekai_keys::KeyProvider`], then unwraps its
//! tenant data keys directly against that provider:
//!
//! ```ignore
//! let release = CustomerKeyRelease::from_json(&raw)?;
//! let provider = open_provider(&release, ProviderAccess::Pkcs11 { pin })?;
//! for key in &release.data_keys {
//!     let wrapped = key.wrapped_dek()?;
//!     // provider.unwrap(&wrapped, &grant, engine, now)
//! }
//! ```
//!
//! Adapters sit behind features so a consumer builds only what it uses:
//! `pkcs11` (PKCS#11 HSM) and `kmip` (KMIP 1.4). `test-support` adds the
//! software-token pool for tests.

use serde::{Deserialize, Serialize};

pub mod release;

#[cfg(feature = "kmip")]
pub mod kmip;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(any(feature = "kmip", feature = "pkcs11"))]
mod open;
#[cfg(any(feature = "kmip", feature = "pkcs11"))]
pub use open::{OpenError, ProviderAccess, ReleaseProvider, open_provider};
pub use release::{
    CustomerKeyRelease, DOCUMENT_SCHEMA, DistributedDataKey, KeyReleaseIntent, ProviderEndpoint,
    ReleaseError,
};

/// Key-provider kinds named in a deploy profile or a customer-key release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    Software,
    File,
    Memory,
    Pkcs11,
    Kmip,
    CloudKms,
}

impl KeyProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::File => "file",
            Self::Memory => "memory",
            Self::Pkcs11 => "pkcs11",
            Self::Kmip => "kmip",
            Self::CloudKms => "cloud_kms",
        }
    }

    /// Parse the name a release or profile uses (`pkcs11`, `cloud_kms`, ...).
    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::Software,
            Self::File,
            Self::Memory,
            Self::Pkcs11,
            Self::Kmip,
            Self::CloudKms,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == name)
    }

    pub fn is_lab_only(self) -> bool {
        matches!(self, Self::Software | Self::File | Self::Memory)
    }
}

impl std::fmt::Display for KeyProviderKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

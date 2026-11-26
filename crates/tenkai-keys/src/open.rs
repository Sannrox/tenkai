//! Open the key provider a customer-key release names.

use std::net::SocketAddr;
use std::path::Path;

#[cfg(feature = "kmip")]
use crate::kmip;
#[cfg(feature = "pkcs11")]
use crate::pkcs11;
use crate::{CustomerKeyRelease, KeyProviderKind, KeyReleaseIntent, ReleaseError};

/// What the consumer supplies to reach the provider a release names. The
/// release carries no secrets and, in v1, no KMIP address.
#[derive(Clone, Copy)]
pub enum ProviderAccess<'a> {
    /// PKCS#11 module from the consumer's own configuration and the user PIN
    /// for the token named by `provider.token_label`. A module the release
    /// names is never loaded: the release producer must not choose the library
    /// that receives the consumer's PIN (#1316).
    Pkcs11 { module: &'a Path, pin: &'a str },
    /// KMIP endpoint from the consumer's own configuration.
    Kmip { endpoint: SocketAddr },
}

impl std::fmt::Debug for ProviderAccess<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs11 { module, .. } => formatter
                .debug_struct("Pkcs11")
                .field("module", module)
                .field("pin", &"<redacted>")
                .finish(),
            Self::Kmip { endpoint } => formatter
                .debug_struct("Kmip")
                .field("endpoint", endpoint)
                .finish(),
        }
    }
}

impl ProviderAccess<'_> {
    fn kind(&self) -> KeyProviderKind {
        match self {
            Self::Pkcs11 { .. } => KeyProviderKind::Pkcs11,
            Self::Kmip { .. } => KeyProviderKind::Kmip,
        }
    }
}

/// Why [`open_provider`] refused to open the provider a release names.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error(transparent)]
    Release(#[from] ReleaseError),
    #[error("revoked customer-key release fails closed")]
    Revoked,
    #[error("customer-key release names unknown key provider {0}")]
    UnknownKind(String),
    #[error("key provider {0} has no adapter in tenkai-keys")]
    NoAdapter(KeyProviderKind),
    #[error("key provider {0} needs the `{0}` feature of tenkai-keys")]
    FeatureDisabled(KeyProviderKind),
    #[error("customer-key release names key provider {named}, but the access given is for {given}")]
    AccessMismatch {
        named: KeyProviderKind,
        given: KeyProviderKind,
    },
    #[error("key provider {kind} refused to open: {source}")]
    Provider {
        kind: KeyProviderKind,
        source: envelope_keys::KeyError,
    },
}

/// A provider opened from a release. It implements
/// [`envelope_keys::KeyProvider`], so `KeyProvider`-generic code takes it as is.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReleaseProvider {
    #[cfg(feature = "pkcs11")]
    Pkcs11(pkcs11::Pkcs11KeyProvider),
    #[cfg(feature = "kmip")]
    Kmip(kmip::KmipKeyProvider),
}

/// Open the provider `release` names, admitted under the production profile.
///
/// Fails closed on a revoked release, on a lab-only provider (`software`,
/// `file`, `memory`; every release refuses those, which is stricter than a lab
/// deploy profile), on an unknown kind, on access for a different kind, and on
/// a kind whose adapter feature is off.
pub fn open_provider(
    release: &CustomerKeyRelease,
    access: ProviderAccess<'_>,
) -> Result<ReleaseProvider, OpenError> {
    release.refuse_plaintext()?;
    if release.intent == KeyReleaseIntent::Revoke {
        return Err(OpenError::Revoked);
    }
    let named = KeyProviderKind::parse(&release.provider.kind)
        .ok_or_else(|| OpenError::UnknownKind(release.provider.kind.clone()))?;
    if !matches!(named, KeyProviderKind::Pkcs11 | KeyProviderKind::Kmip) {
        return Err(OpenError::NoAdapter(named));
    }
    if named != access.kind() {
        return Err(OpenError::AccessMismatch {
            named,
            given: access.kind(),
        });
    }
    let profile = envelope_keys::RuntimeProfile::Production;
    let provider_error = |source| OpenError::Provider {
        kind: named,
        source,
    };
    match access {
        #[cfg(feature = "pkcs11")]
        ProviderAccess::Pkcs11 { module, pin } => {
            pkcs11::Pkcs11KeyProvider::open(module, &release.provider.token_label, pin, profile)
                .map(ReleaseProvider::Pkcs11)
                .map_err(provider_error)
        }
        #[cfg(feature = "kmip")]
        ProviderAccess::Kmip { endpoint } => kmip::KmipKeyProvider::open(endpoint, profile)
            .map(ReleaseProvider::Kmip)
            .map_err(provider_error),
        #[cfg(not(feature = "pkcs11"))]
        ProviderAccess::Pkcs11 { .. } => Err(OpenError::FeatureDisabled(named)),
        #[cfg(not(feature = "kmip"))]
        ProviderAccess::Kmip { .. } => Err(OpenError::FeatureDisabled(named)),
    }
}

/// Forward one `KeyProvider` call to the opened adapter.
macro_rules! forward {
    ($self:ident, $provider:ident => $call:expr) => {
        match *$self {
            #[cfg(feature = "pkcs11")]
            Self::Pkcs11(ref $provider) => $call,
            #[cfg(feature = "kmip")]
            Self::Kmip(ref $provider) => $call,
        }
    };
}

impl envelope_keys::KeyProvider for ReleaseProvider {
    fn describe(&self) -> envelope_keys::ProviderDescription {
        forward!(self, provider => provider.describe())
    }

    fn wrap(
        &self,
        tenant_id: &envelope_keys::TenantId,
        purpose: envelope_keys::KeyPurpose,
        dek: &envelope_keys::Dek,
    ) -> Result<envelope_keys::WrappedDek, envelope_keys::KeyError> {
        forward!(self, provider => provider.wrap(tenant_id, purpose, dek))
    }

    fn rewrap(
        &self,
        wrapped: &envelope_keys::WrappedDek,
        dek: &envelope_keys::Dek,
    ) -> Result<envelope_keys::WrappedDek, envelope_keys::KeyError> {
        forward!(self, provider => provider.rewrap(wrapped, dek))
    }

    fn unwrap(
        &self,
        wrapped: &envelope_keys::WrappedDek,
        grant: &envelope_keys::UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<envelope_keys::UnwrapOutcome, envelope_keys::KeyError> {
        forward!(self, provider => provider.unwrap(wrapped, grant, engine, now_unix_secs))
    }

    fn rotate_kek(&self) -> Result<envelope_keys::KeyId, envelope_keys::KeyError> {
        forward!(self, provider => provider.rotate_kek())
    }

    fn complete_kek_rotation(&self) -> Result<(), envelope_keys::KeyError> {
        forward!(self, provider => provider.complete_kek_rotation())
    }

    fn revoke_kek(&self) -> Result<(), envelope_keys::KeyError> {
        forward!(self, provider => provider.revoke_kek())
    }

    fn revoke_dek(&self, dek_id: &envelope_keys::KeyId) -> Result<(), envelope_keys::KeyError> {
        forward!(self, provider => provider.revoke_dek(dek_id))
    }
}

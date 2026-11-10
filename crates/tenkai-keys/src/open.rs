//! Open the key provider a customer-key release names.

use std::net::SocketAddr;

#[cfg(feature = "kmip")]
use crate::kmip;
#[cfg(feature = "pkcs11")]
use crate::pkcs11;
use crate::{CustomerKeyRelease, KeyProviderKind, KeyReleaseIntent, ReleaseError};

/// What the consumer supplies to reach the provider a release names. The
/// release carries no secrets and, in v1, no KMIP address.
#[derive(Clone, Copy)]
pub enum ProviderAccess<'a> {
    /// User PIN for the token named by `provider.token_label` in
    /// `provider.module`.
    Pkcs11 { pin: &'a str },
    /// KMIP endpoint from the consumer's own configuration.
    Kmip { endpoint: SocketAddr },
}

impl std::fmt::Debug for ProviderAccess<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs11 { .. } => formatter
                .debug_struct("Pkcs11")
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
    #[error("customer-key release names no PKCS#11 module")]
    MissingModule,
    #[error("key provider {kind} refused to open: {source}")]
    Provider {
        kind: KeyProviderKind,
        source: sekai_keys::KeyError,
    },
}

/// A provider opened from a release. It implements
/// [`sekai_keys::KeyProvider`], so `KeyProvider`-generic code takes it as is.
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
    let profile = sekai_keys::RuntimeProfile::Production;
    let provider_error = |source| OpenError::Provider {
        kind: named,
        source,
    };
    match access {
        #[cfg(feature = "pkcs11")]
        ProviderAccess::Pkcs11 { pin } => {
            let module = release
                .provider
                .module
                .as_deref()
                .ok_or(OpenError::MissingModule)?;
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

impl sekai_keys::KeyProvider for ReleaseProvider {
    fn describe(&self) -> sekai_keys::ProviderDescription {
        forward!(self, provider => provider.describe())
    }

    fn wrap(
        &self,
        tenant_id: &sekai_keys::TenantId,
        purpose: sekai_keys::KeyPurpose,
        dek: &sekai_keys::Dek,
    ) -> Result<sekai_keys::WrappedDek, sekai_keys::KeyError> {
        forward!(self, provider => provider.wrap(tenant_id, purpose, dek))
    }

    fn rewrap(
        &self,
        wrapped: &sekai_keys::WrappedDek,
        dek: &sekai_keys::Dek,
    ) -> Result<sekai_keys::WrappedDek, sekai_keys::KeyError> {
        forward!(self, provider => provider.rewrap(wrapped, dek))
    }

    fn unwrap(
        &self,
        wrapped: &sekai_keys::WrappedDek,
        grant: &sekai_keys::UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<sekai_keys::UnwrapOutcome, sekai_keys::KeyError> {
        forward!(self, provider => provider.unwrap(wrapped, grant, engine, now_unix_secs))
    }

    fn rotate_kek(&self) -> Result<sekai_keys::KeyId, sekai_keys::KeyError> {
        forward!(self, provider => provider.rotate_kek())
    }

    fn complete_kek_rotation(&self) -> Result<(), sekai_keys::KeyError> {
        forward!(self, provider => provider.complete_kek_rotation())
    }

    fn revoke_kek(&self) -> Result<(), sekai_keys::KeyError> {
        forward!(self, provider => provider.revoke_kek())
    }

    fn revoke_dek(&self, dek_id: &sekai_keys::KeyId) -> Result<(), sekai_keys::KeyError> {
        forward!(self, provider => provider.revoke_dek(dek_id))
    }
}

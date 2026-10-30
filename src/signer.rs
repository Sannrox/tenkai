//! External signer for releases, offline bundles, and plan approvals (#642).
//!
//! Lab and PKCS#11 backends share one interface. A production profile refuses
//! file-based signing keys, so private key material never sits on disk there.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use ed25519_dalek::{SigningKey, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::key_provider::{DeployProfile, ProfileClass};
use crate::offline_bundle::{BundleEnvelope, BundleStatement};
use crate::plan_approval::{APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement};
use crate::release_signing::SignatureEnvelope;
use crate::secret_source;

/// PKCS#11 object label for the Ed25519 signing key pair.
pub const DEFAULT_KEY_LABEL: &str = "tenkai-signer";

/// PKCS#11 module path used when the profile names a PKCS#11 signer.
pub const MODULE_ENV: &str = "TENKAI_SIGNER_MODULE";
/// Token label used when the profile names a PKCS#11 signer.
pub const TOKEN_ENV: &str = "TENKAI_SIGNER_TOKEN";
/// Token PIN; read as a secret setting (`TENKAI_SIGNER_PIN`).
pub const PIN_ENV: &str = "TENKAI_SIGNER_PIN";
/// Optional object label; defaults to [`DEFAULT_KEY_LABEL`].
pub const KEY_LABEL_ENV: &str = "TENKAI_SIGNER_KEY_LABEL";
/// Path of a 32-byte Ed25519 seed. Lab profiles only.
pub const FILE_KEY_ENV: &str = "TENKAI_SIGNER_KEY";

const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// Backing store for a content signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    Lab,
    File,
    Pkcs11,
}

impl SignerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lab => "lab",
            Self::File => "file",
            Self::Pkcs11 => "pkcs11",
        }
    }

    /// Lab and file backends keep a seed in process or on disk.
    pub fn is_lab_only(self) -> bool {
        matches!(self, Self::Lab | Self::File)
    }
}

impl fmt::Display for SignerKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How to construct a [`ContentSigner`].
#[derive(Clone, PartialEq, Eq)]
pub enum SignerBackend {
    /// In-memory Ed25519 key. Never writes a seed.
    Lab { seed: Option<[u8; 32]> },
    /// 32-byte seed file. Refused by a production profile.
    File { path: PathBuf },
    /// Token-resident Ed25519 key. Private material never leaves the token.
    Pkcs11 {
        module: PathBuf,
        token_label: String,
        pin: String,
        key_label: String,
    },
}

impl fmt::Debug for SignerBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lab { seed } => formatter
                .debug_struct("Lab")
                .field("seed", &seed.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::File { path } => formatter.debug_struct("File").field("path", path).finish(),
            Self::Pkcs11 {
                module,
                token_label,
                key_label,
                pin: _,
            } => formatter
                .debug_struct("Pkcs11")
                .field("module", module)
                .field("token_label", token_label)
                .field("key_label", key_label)
                .field("pin", &"<redacted>")
                .finish(),
        }
    }
}

impl SignerBackend {
    pub fn kind(&self) -> SignerKind {
        match self {
            Self::Lab { .. } => SignerKind::Lab,
            Self::File { .. } => SignerKind::File,
            Self::Pkcs11 { .. } => SignerKind::Pkcs11,
        }
    }
}

/// Signs canonical bytes for a release, bundle, or approval envelope.
pub trait ContentSigner: Send + Sync + fmt::Debug {
    fn kind(&self) -> SignerKind;
    fn key_id(&self) -> &str;
    fn public_key(&self) -> &[u8; 32];
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]>;
}

/// In-memory Ed25519 signer for labs and tests.
pub struct LabSigner {
    key: SigningKey,
    public: [u8; 32],
    key_id: String,
}

impl LabSigner {
    /// Fresh key held only in this process.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(random_seed()?))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        let key_id = crate::signature_verification::key_id(&public);
        Self {
            key,
            public,
            key_id,
        }
    }
}

impl ContentSigner for LabSigner {
    fn kind(&self) -> SignerKind {
        SignerKind::Lab
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(payload).to_bytes())
    }
}

impl fmt::Debug for LabSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LabSigner")
            .field("kind", &SignerKind::Lab)
            .field("key_id", &self.key_id)
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// Seed-file signer. Production profiles refuse it.
pub struct FileSigner {
    inner: LabSigner,
    path: PathBuf,
}

impl FileSigner {
    pub fn open(path: &Path) -> Result<Self> {
        let seed = crate::approval_policy::load_signer_seed(path)?;
        Ok(Self {
            inner: LabSigner::from_seed(seed),
            path: path.to_path_buf(),
        })
    }
}

impl ContentSigner for FileSigner {
    fn kind(&self) -> SignerKind {
        SignerKind::File
    }

    fn key_id(&self) -> &str {
        self.inner.key_id()
    }

    fn public_key(&self) -> &[u8; 32] {
        self.inner.public_key()
    }

    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> {
        self.inner.sign(payload)
    }
}

impl fmt::Debug for FileSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSigner")
            .field("kind", &SignerKind::File)
            .field("key_id", &self.inner.key_id)
            .field("path", &self.path)
            .field("seed", &"<redacted>")
            .finish()
    }
}

struct Pkcs11Inner {
    session: Session,
    private: ObjectHandle,
}

/// PKCS#11-backed Ed25519 signer. The private key stays on the token.
pub struct Pkcs11Signer {
    inner: Mutex<Pkcs11Inner>,
    public: [u8; 32],
    key_id: String,
    token_label: String,
    key_label: String,
    _claim: crate::pkcs11_provider::TokenClaim,
}

impl Pkcs11Signer {
    fn from_session(
        session: Session,
        claim: crate::pkcs11_provider::TokenClaim,
        token_label: &str,
        key_label: &str,
        private: ObjectHandle,
        public: [u8; 32],
    ) -> Self {
        Self {
            inner: Mutex::new(Pkcs11Inner { session, private }),
            key_id: crate::signature_verification::key_id(&public),
            public,
            token_label: token_label.to_string(),
            key_label: key_label.to_string(),
            _claim: claim,
        }
    }

    /// Restore a previously provisioned key. Fails if missing or ambiguous.
    pub fn open(module: &Path, token_label: &str, pin: &str, key_label: &str) -> Result<Self> {
        validate_token_field("key label", key_label)?;
        let (session, claim) = connect(module, token_label, pin)?;
        let (private, public) = restore(&session, key_label)?;
        Ok(Self::from_session(
            session,
            claim,
            token_label,
            key_label,
            private,
            public,
        ))
    }

    /// Mint the labeled key if absent, then restore it.
    pub fn provision(module: &Path, token_label: &str, pin: &str, key_label: &str) -> Result<Self> {
        validate_token_field("key label", key_label)?;
        let (session, claim) = connect(module, token_label, pin)?;
        ensure_provisioned(&session, key_label)?;
        let (private, public) = restore(&session, key_label)?;
        Ok(Self::from_session(
            session,
            claim,
            token_label,
            key_label,
            private,
            public,
        ))
    }
}

impl ContentSigner for Pkcs11Signer {
    fn kind(&self) -> SignerKind {
        SignerKind::Pkcs11
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("PKCS#11 signer lock was poisoned"))?;
        let params = EddsaParams::new(EddsaSignatureScheme::Pure);
        let signature = inner
            .session
            .sign(&Mechanism::Eddsa(params), inner.private, payload)
            .map_err(|error| anyhow::anyhow!("PKCS#11 Ed25519 sign failed: {error}"))?;
        signature.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("PKCS#11 signature must be 64 bytes, got {}", bytes.len())
        })
    }
}

impl fmt::Debug for Pkcs11Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Pkcs11Signer")
            .field("kind", &SignerKind::Pkcs11)
            .field("key_id", &self.key_id)
            .field("token_label", &self.token_label)
            .field("key_label", &self.key_label)
            .field("pin", &"<redacted>")
            .finish()
    }
}

/// Refuse lab-only backends on a production profile.
pub fn admit(profile: &DeployProfile, kind: SignerKind) -> Result<()> {
    profile.validate()?;
    if profile.class == ProfileClass::Production && kind.is_lab_only() {
        bail!("production profile refuses file-based signing keys ({kind})");
    }
    Ok(())
}

/// Open the named backend after admitting it against `profile`.
pub fn open(profile: &DeployProfile, backend: SignerBackend) -> Result<Box<dyn ContentSigner>> {
    admit(profile, backend.kind())?;
    match backend {
        SignerBackend::Lab { seed } => {
            let signer = match seed {
                Some(seed) => LabSigner::from_seed(seed),
                None => LabSigner::generate()?,
            };
            Ok(Box::new(signer))
        }
        SignerBackend::File { path } => Ok(Box::new(FileSigner::open(&path)?)),
        SignerBackend::Pkcs11 {
            module,
            token_label,
            pin,
            key_label,
        } => Ok(Box::new(Pkcs11Signer::open(
            &module,
            &token_label,
            &pin,
            &key_label,
        )?)),
    }
}

/// Mint a PKCS#11 signing key if absent, then open it. Lab and file backends
/// behave like [`open`].
pub fn provision(
    profile: &DeployProfile,
    backend: SignerBackend,
) -> Result<Box<dyn ContentSigner>> {
    if let SignerBackend::Pkcs11 {
        module,
        token_label,
        pin,
        key_label,
    } = &backend
    {
        admit(profile, SignerKind::Pkcs11)?;
        return Ok(Box::new(Pkcs11Signer::provision(
            module,
            token_label,
            pin,
            key_label,
        )?));
    }
    open(profile, backend)
}

/// Open the signer named by the deploy profile and process environment.
pub fn open_from_profile(profile: &DeployProfile) -> Result<Box<dyn ContentSigner>> {
    let kind = profile
        .signer
        .as_ref()
        .map(|section| section.kind)
        .context("deploy profile does not name a signer")?;
    let backend = match kind {
        SignerKind::Lab => SignerBackend::Lab { seed: None },
        SignerKind::File => SignerBackend::File {
            path: PathBuf::from(secret_source::require(FILE_KEY_ENV)?),
        },
        SignerKind::Pkcs11 => SignerBackend::Pkcs11 {
            module: PathBuf::from(secret_source::require(MODULE_ENV)?),
            token_label: secret_source::require(TOKEN_ENV)?,
            pin: secret_source::require(PIN_ENV)?,
            key_label: secret_source::read(KEY_LABEL_ENV)?
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_KEY_LABEL.to_string()),
        },
    };
    open(profile, backend)
}

/// Fill `envelope.key_id` and `envelope.signature` from `signer`.
pub fn sign_release(signer: &dyn ContentSigner, envelope: &mut SignatureEnvelope) -> Result<()> {
    envelope.key_id = signer.key_id().to_string();
    let signed_bytes = envelope.signed_bytes()?;
    envelope.signature = STANDARD.encode(signer.sign(&signed_bytes)?);
    envelope.validate()?;
    Ok(())
}

/// Sign a plan-approval statement.
pub fn sign_approval(
    signer: &dyn ContentSigner,
    statement: ApprovalStatement,
) -> Result<ApprovalEnvelope> {
    let bytes = crate::plan_approval::canonical_bytes(&statement)?;
    Ok(ApprovalEnvelope {
        schema: APPROVAL_SCHEMA.into(),
        key_id: signer.key_id().to_string(),
        statement,
        signature: STANDARD.encode(signer.sign(&bytes)?),
    })
}

/// Sign an offline bundle through the same interface.
pub fn sign_bundle(
    signer: &dyn ContentSigner,
    statement: BundleStatement,
    payloads: std::collections::BTreeMap<String, (String, Vec<u8>)>,
) -> Result<BundleEnvelope> {
    BundleEnvelope::create_with(statement, payloads, signer)
}

pub fn verifying_key(signer: &dyn ContentSigner) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(signer.public_key())
        .context("signer public key is not a valid Ed25519 key")
}

fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| anyhow::anyhow!("generating lab signer seed"))?;
    Ok(seed)
}

fn validate_token_field(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 32 || value.contains('\0') || value != value.trim() {
        bail!("{label} must be 1 to 32 non-empty characters");
    }
    Ok(())
}

fn connect(
    module: &Path,
    token_label: &str,
    pin: &str,
) -> Result<(Session, crate::pkcs11_provider::TokenClaim)> {
    validate_token_field("token label", token_label)?;
    let claim = crate::pkcs11_provider::claim_token_for(module, token_label, "signer")
        .map_err(|_| anyhow::anyhow!("PKCS#11 token {token_label} is already in use"))?;
    let pkcs11 = crate::pkcs11_provider::load_pkcs11(module)
        .map_err(|_| anyhow::anyhow!("loading PKCS#11 module {}", module.display()))?;
    let slot = crate::pkcs11_provider::slot_with_label(&pkcs11, token_label)
        .map_err(|_| anyhow::anyhow!("PKCS#11 token {token_label} was not found"))?;
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|error| anyhow::anyhow!("opening PKCS#11 session: {error}"))?;
    match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {
        }
        Err(error) => bail!("PKCS#11 login failed: {error}"),
    }
    Ok((session, claim))
}

fn restore(session: &Session, key_label: &str) -> Result<(ObjectHandle, [u8; 32])> {
    match find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
        [] => bail!("PKCS#11 signing key {key_label} is not provisioned"),
        [private] => {
            require_private_protection(session, *private, key_label)?;
            let id = object_id(session, *private)?;
            let public = unique_object(
                find_by_id(session, ObjectClass::PUBLIC_KEY, &id)?,
                &format!("PKCS#11 signing key {key_label} public object"),
            )?;
            let bytes = public_key_bytes(session, public)?;
            Ok((*private, bytes))
        }
        found => bail!(
            "PKCS#11 signing key {key_label} is ambiguous ({} private objects)",
            found.len()
        ),
    }
}

fn ensure_provisioned(session: &Session, key_label: &str) -> Result<()> {
    // Ceremony mints when the label is empty. Two processes can both mint;
    // restore then fails closed on an ambiguous label. Cross-process HSM
    // locking is out of scope, same as the wrap provider.
    match find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
        [] => {
            mint_ed25519(session, key_label)?;
            Ok(())
        }
        [_] => Ok(()),
        found => bail!(
            "PKCS#11 signing key {key_label} is ambiguous ({} private objects)",
            found.len()
        ),
    }
}

fn require_private_protection(
    session: &Session,
    handle: ObjectHandle,
    key_label: &str,
) -> Result<()> {
    let attributes = session
        .get_attributes(
            handle,
            &[
                AttributeType::Extractable,
                AttributeType::Sensitive,
                AttributeType::Sign,
                AttributeType::Token,
                AttributeType::Private,
            ],
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "reading PKCS#11 signing key {key_label} protection attributes: {error}"
            )
        })?;
    let mut extractable = None;
    let mut sensitive = None;
    let mut sign = None;
    let mut token = None;
    let mut private = None;
    for attribute in attributes {
        match attribute {
            Attribute::Extractable(value) => extractable = Some(value),
            Attribute::Sensitive(value) => sensitive = Some(value),
            Attribute::Sign(value) => sign = Some(value),
            Attribute::Token(value) => token = Some(value),
            Attribute::Private(value) => private = Some(value),
            _ => {}
        }
    }
    let extractable = extractable.ok_or_else(|| {
        anyhow::anyhow!("PKCS#11 signing key {key_label} is missing CKA_EXTRACTABLE")
    })?;
    let sensitive = sensitive.ok_or_else(|| {
        anyhow::anyhow!("PKCS#11 signing key {key_label} is missing CKA_SENSITIVE")
    })?;
    let sign =
        sign.ok_or_else(|| anyhow::anyhow!("PKCS#11 signing key {key_label} is missing CKA_SIGN"))?;
    let token = token
        .ok_or_else(|| anyhow::anyhow!("PKCS#11 signing key {key_label} is missing CKA_TOKEN"))?;
    let private = private
        .ok_or_else(|| anyhow::anyhow!("PKCS#11 signing key {key_label} is missing CKA_PRIVATE"))?;
    if extractable || !sensitive || !sign || !token || !private {
        bail!(
            "PKCS#11 signing key {key_label} is not a token-resident non-extractable signing key"
        );
    }
    Ok(())
}

fn find_labeled(
    session: &Session,
    class: ObjectClass,
    key_label: &str,
) -> Result<Vec<ObjectHandle>> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .map_err(|error| anyhow::anyhow!("searching PKCS#11 signing key {key_label}: {error}"))
}

fn find_by_id(session: &Session, class: ObjectClass, id: &[u8]) -> Result<Vec<ObjectHandle>> {
    session
        .find_objects(&[Attribute::Class(class), Attribute::Id(id.to_vec())])
        .map_err(|error| anyhow::anyhow!("searching PKCS#11 object by CKA_ID: {error}"))
}

fn unique_object(found: Vec<ObjectHandle>, what: &str) -> Result<ObjectHandle> {
    match found.as_slice() {
        [handle] => Ok(*handle),
        [] => bail!("{what} was not found"),
        objects => bail!("{what} is ambiguous ({} objects)", objects.len()),
    }
}

fn object_id(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::Id])
        .map_err(|error| anyhow::anyhow!("reading PKCS#11 CKA_ID: {error}"))?;
    let Some(Attribute::Id(id)) = attributes.into_iter().next() else {
        bail!("PKCS#11 signing key is missing CKA_ID");
    };
    if id.is_empty() {
        bail!("PKCS#11 signing key CKA_ID is empty");
    }
    Ok(id)
}

fn mint_ed25519(session: &Session, key_label: &str) -> Result<(ObjectHandle, [u8; 32])> {
    let label = key_label.as_bytes().to_vec();
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| anyhow::anyhow!("generating PKCS#11 signing key id"))?;
    let id = id.to_vec();
    let (public, private) = session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Label(label.clone()),
                Attribute::Id(id.clone()),
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::EcParams(ED25519_OID.to_vec()),
            ],
            &[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Label(label),
                Attribute::Id(id),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
            ],
        )
        .map_err(|error| anyhow::anyhow!("generating PKCS#11 Ed25519 signing key: {error}"))?;
    let privates = find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?;
    if privates.len() != 1 {
        bail!(
            "PKCS#11 signing key {key_label} became ambiguous during mint ({} private objects)",
            privates.len()
        );
    }
    let bytes = public_key_bytes(session, public)?;
    Ok((private, bytes))
}

fn public_key_bytes(session: &Session, handle: ObjectHandle) -> Result<[u8; 32]> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|error| anyhow::anyhow!("reading PKCS#11 Ed25519 public key: {error}"))?;
    let Some(Attribute::EcPoint(point)) = attributes.into_iter().next() else {
        bail!("PKCS#11 Ed25519 public key is missing CKA_EC_POINT");
    };
    parse_ed25519_point(&point)
}

fn parse_ed25519_point(point: &[u8]) -> Result<[u8; 32]> {
    match point {
        raw if raw.len() == 32 => raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("PKCS#11 Ed25519 public key is not 32 bytes")),
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest
            .try_into()
            .map_err(|_| anyhow::anyhow!("PKCS#11 Ed25519 OCTET STRING is not 32 bytes")),
        [0x03, 0x21, 0x00, rest @ ..] if rest.len() == 32 => rest
            .try_into()
            .map_err(|_| anyhow::anyhow!("PKCS#11 Ed25519 BIT STRING is not 32 bytes")),
        other => bail!(
            "PKCS#11 Ed25519 public key has unexpected CKA_EC_POINT length {}",
            other.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::{KeyProviderKind, KeyProviderSection, SignerSection};
    use crate::pkcs11_provider::{Pkcs11KeyProvider, TEST_USER_PIN, next_software_token};
    use crate::release_signing::{
        Provenance, ReleaseStatement, TRUST_ROOT_VERSION, TrustRoots, TrustedSigner, verify_release,
    };
    use sekai_keys::RuntimeProfile;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::OpenOptionsExt as _;

    fn production(kind: SignerKind) -> DeployProfile {
        DeployProfile {
            version: 1,
            class: ProfileClass::Production,
            key_provider: KeyProviderSection {
                kind: KeyProviderKind::Pkcs11,
            },
            signer: Some(SignerSection { kind }),
        }
    }

    fn lab(kind: SignerKind) -> DeployProfile {
        DeployProfile {
            version: 1,
            class: ProfileClass::Lab,
            key_provider: KeyProviderSection {
                kind: KeyProviderKind::Software,
            },
            signer: Some(SignerSection { kind }),
        }
    }

    fn hex_digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn prefixed(value: &str) -> String {
        format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
    }

    fn release_envelope() -> SignatureEnvelope {
        SignatureEnvelope {
            schema: crate::release_signing::ENVELOPE_SCHEMA.into(),
            key_id: String::new(),
            statement: ReleaseStatement {
                manifest_digest: hex_digest("manifest"),
                artifact_digest: hex_digest("artifact"),
                provenance: Provenance {
                    source_uri: "https://github.com/Sannrox/tenkai".into(),
                    revision: "test".into(),
                    builder: "tenkai-signer-test".into(),
                    built_at_unix_ms: 1_700_000_000_000,
                    materials: Default::default(),
                },
            },
            signature: String::new(),
        }
    }

    fn approval_statement() -> ApprovalStatement {
        ApprovalStatement {
            plan_digest: prefixed("plan"),
            environment: "lab".into(),
            purpose: "execute_plan".into(),
            skip_gates: false,
            issued_at: 1_000,
            expires_at: 2_000,
            policy_provider: "builtin".into(),
            policy_evidence_id: "test".into(),
            policy_digest: prefixed("policy"),
        }
    }

    fn bundle_payloads() -> (BundleStatement, BTreeMap<String, (String, Vec<u8>)>) {
        let plan = br#"{"plan":"plan-1"}"#.to_vec();
        let approval = br#"{"approval":"plan-1"}"#.to_vec();
        let mut payloads = BTreeMap::new();
        payloads.insert(
            "approvals/plan-1.json".into(),
            ("application/json".into(), approval.clone()),
        );
        payloads.insert(
            "plans/plan-1.json".into(),
            ("application/json".into(), plan.clone()),
        );
        payloads.insert(
            "releases/app@1.0.0/payload.bin".into(),
            (
                "application/octet-stream".into(),
                b"immutable payload".to_vec(),
            ),
        );
        let statement = BundleStatement {
            tenant_id: "tenant-1".into(),
            environment_id: "airgap-1".into(),
            plan_id: "plan-1".into(),
            plan_digest: format!("sha256:{:x}", Sha256::digest(&plan)),
            approval_digest: format!("sha256:{:x}", Sha256::digest(&approval)),
            release_ids: vec!["app@1.0.0".into()],
            exporter_identity: "exporter".into(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            entries: Vec::new(),
        };
        (statement, payloads)
    }

    fn roots_for(signer: &dyn ContentSigner, identity: &str) -> TrustRoots {
        TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers: vec![TrustedSigner {
                key_id: signer.key_id().to_string(),
                identity: identity.into(),
                public_key: STANDARD.encode(signer.public_key()),
                not_before: None,
                not_after: None,
            }],
        }
    }

    fn sign_all(signer: &dyn ContentSigner) {
        let mut envelope = release_envelope();
        sign_release(signer, &mut envelope).unwrap();
        let evidence = verify_release(
            &envelope,
            &roots_for(signer, "release@localhost"),
            &envelope.statement.manifest_digest,
            &envelope.statement.artifact_digest,
        )
        .unwrap();
        assert_eq!(evidence.signer_key_id, signer.key_id());

        let approval = sign_approval(signer, approval_statement()).unwrap();
        crate::signature_verification::verify_strict(
            &verifying_key(signer).unwrap(),
            "approval",
            &approval.signature,
            &crate::plan_approval::canonical_bytes(&approval.statement).unwrap(),
        )
        .unwrap();
        assert_eq!(approval.key_id, signer.key_id());

        let (statement, payloads) = bundle_payloads();
        let mut statement = statement;
        statement.exporter_identity = "exporter".into();
        let bundle = sign_bundle(signer, statement, payloads).unwrap();
        bundle
            .verify(
                &roots_for(signer, "exporter"),
                "tenant-1",
                "airgap-1",
                1_500,
            )
            .unwrap();
        assert_eq!(bundle.key_id, signer.key_id());
    }

    #[test]
    fn lab_signer_signs_release_bundle_and_approval_without_writing_a_seed() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-signer-lab-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        let profile = lab(SignerKind::Lab);
        let signer = open(&profile, SignerBackend::Lab { seed: None }).unwrap();
        assert_eq!(signer.kind(), SignerKind::Lab);
        sign_all(signer.as_ref());
        let debug = format!("{signer:?}");
        assert!(debug.contains("redacted"), "{debug}");
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert!(leftover.is_empty(), "{leftover:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signer_backend_debug_redacts_pin_and_seed() {
        let pin = "super-secret-pin";
        let backend = SignerBackend::Pkcs11 {
            module: PathBuf::from("/nonexistent/libsofthsm2.so"),
            token_label: "lab".into(),
            pin: pin.into(),
            key_label: DEFAULT_KEY_LABEL.into(),
        };
        let debug = format!("{backend:?}");
        assert!(!debug.contains(pin), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");

        let seed = [7_u8; 32];
        let backend = SignerBackend::Lab { seed: Some(seed) };
        let debug = format!("{backend:?}");
        assert!(!debug.contains("7, 7"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    #[test]
    fn production_profile_refuses_file_and_lab_signers() {
        for kind in [SignerKind::File, SignerKind::Lab] {
            let error = production(kind).validate().unwrap_err().to_string();
            assert!(
                error.contains("production profile refuses file-based signing keys"),
                "{kind}: {error}"
            );
        }
        production(SignerKind::Pkcs11).validate().unwrap();
    }

    #[test]
    fn production_open_refuses_a_file_backend_without_reading_the_seed() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-signer-missing-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let error = open(
            &DeployProfile {
                version: 1,
                class: ProfileClass::Production,
                key_provider: KeyProviderSection {
                    kind: KeyProviderKind::Pkcs11,
                },
                signer: Some(SignerSection {
                    kind: SignerKind::Pkcs11,
                }),
            },
            SignerBackend::File { path: path.clone() },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("production profile refuses file-based signing keys"),
            "{error}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn lab_file_signer_loads_an_owner_only_seed() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-signer-file-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("signer.ed25519");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        use std::io::Write as _;
        file.write_all(&[9_u8; 32]).unwrap();
        drop(file);
        let signer = open(&lab(SignerKind::File), SignerBackend::File { path }).unwrap();
        assert_eq!(signer.kind(), SignerKind::File);
        sign_all(signer.as_ref());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn pkcs11_backend(module: PathBuf, label: String) -> SignerBackend {
        SignerBackend::Pkcs11 {
            module,
            token_label: label,
            pin: TEST_USER_PIN.into(),
            key_label: DEFAULT_KEY_LABEL.into(),
        }
    }

    #[test]
    fn pkcs11_software_token_signs_release_bundle_and_approval() {
        let Some((module, label)) = next_software_token() else {
            return;
        };
        let profile = production(SignerKind::Pkcs11);
        let backend = pkcs11_backend(module, label);
        let error = open(&profile, backend.clone()).unwrap_err().to_string();
        assert!(error.contains("is not provisioned"), "{error}");
        let signer = provision(&profile, backend.clone()).expect("provision pkcs11 signer");
        assert_eq!(signer.kind(), SignerKind::Pkcs11);
        let key_id = signer.key_id().to_string();
        let debug = format!("{signer:?}");
        assert!(debug.contains("redacted"), "{debug}");
        assert!(!debug.contains(TEST_USER_PIN), "{debug}");
        sign_all(signer.as_ref());
        drop(signer);
        let restored = open(&profile, backend.clone()).expect("restore pkcs11 signer");
        assert_eq!(restored.key_id(), key_id);
        drop(restored);
        let again = provision(&profile, backend).expect("idempotent provision");
        assert_eq!(again.key_id(), key_id);
    }

    #[test]
    fn pkcs11_signer_and_key_provider_share_a_token() {
        let Some((module, label)) = next_software_token() else {
            return;
        };
        let provider =
            Pkcs11KeyProvider::open(&module, &label, TEST_USER_PIN, RuntimeProfile::Production)
                .expect("open wrap provider");
        let profile = production(SignerKind::Pkcs11);
        let signer = provision(&profile, pkcs11_backend(module, label))
            .expect("provision signer on the wrap token");
        sign_all(signer.as_ref());
        drop(signer);
        drop(provider);
    }
}

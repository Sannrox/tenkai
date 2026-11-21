//! PKCS#11 session, find, sign, and derive helpers.
//!
//! Callers keep admit, locators, and `ContentSigner` / runner-key types. This
//! module owns cryptoki types so those callers do not compile the PKCS#11 crate.

use std::path::Path;

use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};

use super::{load_pkcs11, slot_with_label};

const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER OID of `prime256v1` (secp256r1) for `CKA_EC_PARAMS`.
const PRIME256V1_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// PKCS#11 session operation that failed with an operator-visible reason.
#[derive(Debug)]
pub struct SessionError {
    message: String,
}

impl SessionError {
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SessionError {}

/// Opaque handle of a token object found in a [`TokenSession`].
#[derive(Clone, Copy, Debug)]
pub struct TokenObject {
    handle: ObjectHandle,
}

/// Role of a P-256 key on the token: ECDSA sign or ECDH derive.
#[derive(Clone, Copy, Debug)]
pub enum P256Role {
    Sign,
    Derive,
}

/// Logged-in read-write session on one token. Send, not Sync: PKCS#11 sessions
/// are not used from two threads at once. `Mutex` around this type is Sync.
pub struct TokenSession {
    session: Session,
}

impl TokenSession {
    /// Load the module, find `token_label`, open a read-write session, and log in.
    /// A token that is already logged in is accepted.
    pub fn open(module: &Path, token_label: &str, pin: &str) -> Result<Self, SessionError> {
        let pkcs11 = load_pkcs11(module).map_err(|_| {
            SessionError::msg(format!("loading PKCS#11 module {}", module.display()))
        })?;
        let slot = slot_with_label(&pkcs11, token_label)
            .map_err(|_| SessionError::msg(format!("PKCS#11 token {token_label} was not found")))?;
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|error| SessionError::msg(format!("opening PKCS#11 session: {error}")))?;
        match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
            Ok(())
            | Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::UserAlreadyLoggedIn,
                _,
            )) => {}
            Err(error) => return Err(SessionError::msg(format!("PKCS#11 login failed: {error}"))),
        }
        Ok(Self { session })
    }

    /// Restore a previously provisioned Ed25519 signing key. Fails if missing or
    /// ambiguous, or if the private object is extractable.
    pub fn restore_ed25519(
        &self,
        key_label: &str,
    ) -> Result<(TokenObject, [u8; 32]), SessionError> {
        match find_labeled_ed25519(&self.session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
            [] => Err(SessionError::msg(format!(
                "PKCS#11 signing key {key_label} is not provisioned"
            ))),
            [private] => {
                require_ed25519_protection(&self.session, *private, key_label)?;
                let id = signing_key_id(&self.session, *private)?;
                let public = unique_object(
                    find_by_id(&self.session, ObjectClass::PUBLIC_KEY, &id)?,
                    &format!("PKCS#11 signing key {key_label} public object"),
                )?;
                let bytes = ed25519_public_bytes(&self.session, public)?;
                Ok((TokenObject { handle: *private }, bytes))
            }
            found => Err(SessionError::msg(format!(
                "PKCS#11 signing key {key_label} is ambiguous ({} private objects)",
                found.len()
            ))),
        }
    }

    /// Mint the labeled Ed25519 key if absent. Two processes can both mint;
    /// restore then fails closed on an ambiguous label.
    pub fn ensure_ed25519(&self, key_label: &str) -> Result<(), SessionError> {
        match find_labeled_ed25519(&self.session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
            [] => {
                mint_ed25519(&self.session, key_label)?;
                Ok(())
            }
            [_] => Ok(()),
            found => Err(SessionError::msg(format!(
                "PKCS#11 signing key {key_label} is ambiguous ({} private objects)",
                found.len()
            ))),
        }
    }

    /// Ed25519 (pure) signature over `payload`. The private key stays on the token.
    pub fn sign_ed25519(
        &self,
        private: TokenObject,
        payload: &[u8],
    ) -> Result<[u8; 64], SessionError> {
        let params = EddsaParams::new(EddsaSignatureScheme::Pure);
        let signature = self
            .session
            .sign(&Mechanism::Eddsa(params), private.handle, payload)
            .map_err(|error| SessionError::msg(format!("PKCS#11 Ed25519 sign failed: {error}")))?;
        signature.try_into().map_err(|bytes: Vec<u8>| {
            SessionError::msg(format!(
                "PKCS#11 signature must be 64 bytes, got {}",
                bytes.len()
            ))
        })
    }

    /// Restore a previously provisioned P-256 key for `role`.
    pub fn restore_p256(
        &self,
        key_label: &str,
        role: P256Role,
    ) -> Result<(TokenObject, Vec<u8>), SessionError> {
        match find_labeled(&self.session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
            [] => Err(SessionError::msg(format!(
                "hardware runner key {key_label} is not provisioned"
            ))),
            [private] => {
                require_not_extractable(&self.session, *private, key_label, role)?;
                let id = runner_key_id(&self.session, *private)?;
                let public = unique_runner_public(
                    self.session
                        .find_objects(&[
                            Attribute::Class(ObjectClass::PUBLIC_KEY),
                            Attribute::Id(id),
                        ])
                        .map_err(|error| {
                            SessionError::msg(format!(
                                "listing PKCS#11 runner public keys: {error}"
                            ))
                        })?,
                    key_label,
                )?;
                Ok((
                    TokenObject { handle: *private },
                    ec_point(&self.session, public)?,
                ))
            }
            found => Err(SessionError::msg(format!(
                "hardware runner key {key_label} is ambiguous ({} private objects)",
                found.len()
            ))),
        }
    }

    /// Mint the labeled P-256 key if absent.
    pub fn ensure_p256(&self, key_label: &str, role: P256Role) -> Result<(), SessionError> {
        match find_labeled(&self.session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
            [] => {
                mint_p256(&self.session, key_label, role)?;
                Ok(())
            }
            [_] => Ok(()),
            found => Err(SessionError::msg(format!(
                "hardware runner key {key_label} is ambiguous ({} private objects)",
                found.len()
            ))),
        }
    }

    /// ECDSA P-256 signature of SHA-256(`message`), returned as ASN.1 DER.
    pub fn sign_ecdsa_p256(
        &self,
        private: TokenObject,
        message: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let hash = digest(&SHA256, message);
        let raw = self
            .session
            .sign(&Mechanism::Ecdsa, private.handle, hash.as_ref())
            .map_err(|error| {
                SessionError::msg(format!("signing with the hardware runner key: {error}"))
            })?;
        ecdsa_der(&raw)
    }

    /// ECDH (`CKM_ECDH1_DERIVE`, no KDF) of the private key with `peer`.
    /// The shared secret leaves the token; the private key does not. Errors
    /// never carry the secret.
    pub fn derive_ecdh(&self, private: TokenObject, peer: &[u8]) -> Result<Vec<u8>, SessionError> {
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32.into()),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        let derived = self
            .session
            .derive_key(&mechanism, private.handle, &template)
            .map_err(|error| {
                SessionError::msg(format!("deriving with the hardware sealing key: {error}"))
            })?;
        let value = self
            .session
            .get_attributes(derived, &[AttributeType::Value]);
        let _ = self.session.destroy_object(derived);
        let value = value.map_err(|_| SessionError::msg("reading the derived shared secret"))?;
        value
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(bytes) if bytes.len() == 32 => Some(bytes),
                _ => None,
            })
            .ok_or_else(|| SessionError::msg("the token derived no 32-byte shared secret"))
    }

    /// Read CKA_VALUE of a private object. A protected key fails; success means
    /// the store leaked private material.
    pub fn export_private_value(&self, private: TokenObject) -> Result<Vec<u8>, SessionError> {
        match self
            .session
            .get_attributes(private.handle, &[AttributeType::Value])
        {
            Ok(attributes)
                if attributes.iter().any(
                    |attribute| matches!(attribute, Attribute::Value(bytes) if !bytes.is_empty()),
                ) =>
            {
                Ok(b"exported".to_vec())
            }
            Ok(_) => Err(SessionError::msg("hardware runner key cannot be exported")),
            Err(_) => Err(SessionError::msg("hardware runner key cannot be exported")),
        }
    }
}

fn find_labeled_ed25519(
    session: &Session,
    class: ObjectClass,
    key_label: &str,
) -> Result<Vec<ObjectHandle>, SessionError> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .map_err(|error| {
            SessionError::msg(format!(
                "searching PKCS#11 signing key {key_label}: {error}"
            ))
        })
}

fn find_labeled(
    session: &Session,
    class: ObjectClass,
    key_label: &str,
) -> Result<Vec<ObjectHandle>, SessionError> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .map_err(|error| SessionError::msg(format!("listing PKCS#11 runner keys: {error}")))
}

fn find_by_id(
    session: &Session,
    class: ObjectClass,
    id: &[u8],
) -> Result<Vec<ObjectHandle>, SessionError> {
    session
        .find_objects(&[Attribute::Class(class), Attribute::Id(id.to_vec())])
        .map_err(|error| SessionError::msg(format!("searching PKCS#11 object by CKA_ID: {error}")))
}

fn unique_object(found: Vec<ObjectHandle>, what: &str) -> Result<ObjectHandle, SessionError> {
    match found.as_slice() {
        [handle] => Ok(*handle),
        [] => Err(SessionError::msg(format!("{what} was not found"))),
        objects => Err(SessionError::msg(format!(
            "{what} is ambiguous ({} objects)",
            objects.len()
        ))),
    }
}

fn unique_runner_public(
    found: Vec<ObjectHandle>,
    key_label: &str,
) -> Result<ObjectHandle, SessionError> {
    match found.as_slice() {
        [handle] => Ok(*handle),
        found => Err(SessionError::msg(format!(
            "hardware runner key {key_label} public object is ambiguous ({} objects)",
            found.len()
        ))),
    }
}

fn signing_key_id(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>, SessionError> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::Id])
        .map_err(|error| SessionError::msg(format!("reading PKCS#11 CKA_ID: {error}")))?;
    let Some(Attribute::Id(id)) = attributes.into_iter().next() else {
        return Err(SessionError::msg("PKCS#11 signing key is missing CKA_ID"));
    };
    if id.is_empty() {
        return Err(SessionError::msg("PKCS#11 signing key CKA_ID is empty"));
    }
    Ok(id)
}

fn runner_key_id(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>, SessionError> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::Id])
        .map_err(|error| SessionError::msg(format!("reading PKCS#11 runner key id: {error}")))?;
    match attributes.into_iter().next() {
        Some(Attribute::Id(id)) if !id.is_empty() => Ok(id),
        _ => Err(SessionError::msg("PKCS#11 runner key is missing CKA_ID")),
    }
}

fn require_ed25519_protection(
    session: &Session,
    handle: ObjectHandle,
    key_label: &str,
) -> Result<(), SessionError> {
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
            SessionError::msg(format!(
                "reading PKCS#11 signing key {key_label} protection attributes: {error}"
            ))
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
        SessionError::msg(format!(
            "PKCS#11 signing key {key_label} is missing CKA_EXTRACTABLE"
        ))
    })?;
    let sensitive = sensitive.ok_or_else(|| {
        SessionError::msg(format!(
            "PKCS#11 signing key {key_label} is missing CKA_SENSITIVE"
        ))
    })?;
    let sign = sign.ok_or_else(|| {
        SessionError::msg(format!(
            "PKCS#11 signing key {key_label} is missing CKA_SIGN"
        ))
    })?;
    let token = token.ok_or_else(|| {
        SessionError::msg(format!(
            "PKCS#11 signing key {key_label} is missing CKA_TOKEN"
        ))
    })?;
    let private = private.ok_or_else(|| {
        SessionError::msg(format!(
            "PKCS#11 signing key {key_label} is missing CKA_PRIVATE"
        ))
    })?;
    if extractable || !sensitive || !sign || !token || !private {
        return Err(SessionError::msg(format!(
            "PKCS#11 signing key {key_label} is not a token-resident non-extractable signing key"
        )));
    }
    Ok(())
}

fn require_not_extractable(
    session: &Session,
    handle: ObjectHandle,
    key_label: &str,
    role: P256Role,
) -> Result<(), SessionError> {
    let usage = match role {
        P256Role::Sign => AttributeType::Sign,
        P256Role::Derive => AttributeType::Derive,
    };
    let attributes = session
        .get_attributes(
            handle,
            &[AttributeType::Extractable, AttributeType::Sensitive, usage],
        )
        .map_err(|error| {
            SessionError::msg(format!(
                "reading PKCS#11 runner key {key_label} protection attributes: {error}"
            ))
        })?;
    let mut extractable = None;
    let mut sensitive = None;
    let mut usable = None;
    for attribute in attributes {
        match attribute {
            Attribute::Extractable(value) => extractable = Some(value),
            Attribute::Sensitive(value) => sensitive = Some(value),
            Attribute::Sign(value) if matches!(role, P256Role::Sign) => usable = Some(value),
            Attribute::Derive(value) if matches!(role, P256Role::Derive) => usable = Some(value),
            _ => {}
        }
    }
    if extractable != Some(false) {
        return Err(SessionError::msg(format!(
            "hardware runner key {key_label} is extractable"
        )));
    }
    if sensitive != Some(true) {
        return Err(SessionError::msg(format!(
            "hardware runner key {key_label} is not sensitive"
        )));
    }
    match role {
        P256Role::Sign if usable != Some(true) => Err(SessionError::msg(format!(
            "hardware runner key {key_label} cannot sign"
        ))),
        P256Role::Derive if usable != Some(true) => Err(SessionError::msg(format!(
            "hardware sealing key {key_label} cannot derive"
        ))),
        _ => Ok(()),
    }
}

fn mint_ed25519(session: &Session, key_label: &str) -> Result<(), SessionError> {
    let label = key_label.as_bytes().to_vec();
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| SessionError::msg("generating PKCS#11 signing key id"))?;
    let id = id.to_vec();
    session
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
        .map_err(|error| {
            SessionError::msg(format!("generating PKCS#11 Ed25519 signing key: {error}"))
        })?;
    let privates = find_labeled_ed25519(session, ObjectClass::PRIVATE_KEY, key_label)?;
    if privates.len() != 1 {
        return Err(SessionError::msg(format!(
            "PKCS#11 signing key {key_label} became ambiguous during mint ({} private objects)",
            privates.len()
        )));
    }
    Ok(())
}

fn mint_p256(session: &Session, key_label: &str, role: P256Role) -> Result<(), SessionError> {
    let label = key_label.as_bytes().to_vec();
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| SessionError::msg("generating PKCS#11 runner key id"))?;
    let id = id.to_vec();
    let public_usage = match role {
        P256Role::Sign => Attribute::Verify(true),
        P256Role::Derive => Attribute::Derive(true),
    };
    let private_usage = match role {
        P256Role::Sign => Attribute::Sign(true),
        P256Role::Derive => Attribute::Derive(true),
    };
    session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Label(label.clone()),
                Attribute::Id(id.clone()),
                Attribute::Token(true),
                public_usage,
                Attribute::EcParams(PRIME256V1_OID.to_vec()),
            ],
            &[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Label(label),
                Attribute::Id(id),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                private_usage,
            ],
        )
        .map_err(|error| SessionError::msg(format!("generating a hardware runner key: {error}")))?;
    let privates = find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?;
    if privates.len() != 1 {
        return Err(SessionError::msg(format!(
            "hardware runner key {key_label} became ambiguous during mint ({} private objects)",
            privates.len()
        )));
    }
    Ok(())
}

fn ed25519_public_bytes(session: &Session, handle: ObjectHandle) -> Result<[u8; 32], SessionError> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|error| {
            SessionError::msg(format!("reading PKCS#11 Ed25519 public key: {error}"))
        })?;
    let Some(Attribute::EcPoint(point)) = attributes.into_iter().next() else {
        return Err(SessionError::msg(
            "PKCS#11 Ed25519 public key is missing CKA_EC_POINT",
        ));
    };
    parse_ed25519_point(&point)
}

fn parse_ed25519_point(point: &[u8]) -> Result<[u8; 32], SessionError> {
    match point {
        raw if raw.len() == 32 => raw
            .try_into()
            .map_err(|_| SessionError::msg("PKCS#11 Ed25519 public key is not 32 bytes")),
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest
            .try_into()
            .map_err(|_| SessionError::msg("PKCS#11 Ed25519 OCTET STRING is not 32 bytes")),
        [0x03, 0x21, 0x00, rest @ ..] if rest.len() == 32 => rest
            .try_into()
            .map_err(|_| SessionError::msg("PKCS#11 Ed25519 BIT STRING is not 32 bytes")),
        other => Err(SessionError::msg(format!(
            "PKCS#11 Ed25519 public key has unexpected CKA_EC_POINT length {}",
            other.len()
        ))),
    }
}

fn ec_point(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>, SessionError> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|error| {
            SessionError::msg(format!("reading PKCS#11 runner public key: {error}"))
        })?;
    let Some(Attribute::EcPoint(point)) = attributes.into_iter().next() else {
        return Err(SessionError::msg(
            "PKCS#11 runner public key is missing CKA_EC_POINT",
        ));
    };
    parse_p256_point(&point)
}

fn parse_p256_point(point: &[u8]) -> Result<Vec<u8>, SessionError> {
    let raw = match point {
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
        raw if raw.len() == 65 => raw,
        other => {
            return Err(SessionError::msg(format!(
                "PKCS#11 runner public key has unexpected CKA_EC_POINT length {}",
                other.len()
            )));
        }
    };
    if raw[0] != 0x04 {
        return Err(SessionError::msg(
            "PKCS#11 runner public key is not an uncompressed P-256 point",
        ));
    }
    Ok(raw.to_vec())
}

/// ASN.1 DER ECDSA signature from PKCS#11 `CKM_ECDSA` `r||s`.
fn ecdsa_der(raw: &[u8]) -> Result<Vec<u8>, SessionError> {
    if raw.len() != 64 {
        return Err(SessionError::msg("ECDSA P-256 signature must be 64 bytes"));
    }
    let integer = |half: &[u8]| {
        let mut start = 0;
        while start + 1 < half.len() && half[start] == 0 && half[start + 1] < 0x80 {
            start += 1;
        }
        let body = &half[start..];
        let mut out = vec![0x02];
        if body[0] >= 0x80 {
            out.push((body.len() + 1) as u8);
            out.push(0);
        } else {
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    };
    let r = integer(&raw[..32]);
    let s = integer(&raw[32..]);
    let mut seq = vec![0x30, (r.len() + s.len()) as u8];
    seq.extend(r);
    seq.extend(s);
    Ok(seq)
}

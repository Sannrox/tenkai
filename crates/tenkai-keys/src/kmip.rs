//! KMIP 1.4 adapter for the customer-managed key contract (ADR 0113).
//!
//! Wrap, unwrap, KEK rotate, describe, and revoke run through a KMIP endpoint
//! using TTLV Create, Activate, Locate, Get Attributes, Encrypt, Decrypt,
//! Revoke, and Destroy. Describe reports kind, key ids, and algorithm names. It
//! never returns key material. Tests speak TTLV to a loopback lab endpoint.
//!
//! The KEK state lives on the endpoint, so every process sees the same keys
//! (#1299). Each KEK carries the name [`KEK_NAME`]; its KMIP state is its role:
//! the Active one is current, Deactivated ones are previous KEKs of a rotation
//! still in overlap, and a Compromised or Destroyed Compromised one marks the
//! KEK as revoked, which every later open refuses.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use envelope_keys::{
    Dek, KeyError, KeyId, KeyProvider, KeyPurpose, ProviderDescription, ProviderKind,
    RuntimeProfile, TenantId, UnwrapAudit, UnwrapGrant, UnwrapOutcome, admit_provider,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

const ALGORITHM: &str = "AES-256-GCM";
const TAG_LEN: usize = 16;
const TYPE_STRUCTURE: u8 = 0x01;
const TYPE_INTEGER: u8 = 0x02;
const TYPE_ENUMERATION: u8 = 0x05;
const TYPE_TEXT: u8 = 0x07;
const TYPE_BYTES: u8 = 0x08;
const TYPE_DATE_TIME: u8 = 0x09;
const MAX_TTLV: usize = 1_048_576;
const MAX_DEPTH: usize = 16;

const TAG_ATTRIBUTE: u32 = 0x420008;
const TAG_ATTRIBUTE_NAME: u32 = 0x42000A;
const TAG_ATTRIBUTE_VALUE: u32 = 0x42000B;
const TAG_BATCH_COUNT: u32 = 0x42000D;
const TAG_BATCH_ITEM: u32 = 0x42000F;
const TAG_BLOCK_CIPHER_MODE: u32 = 0x420011;
const TAG_CRYPTOGRAPHIC_PARAMETERS: u32 = 0x42002B;
const TAG_COMPROMISE_OCCURRENCE_DATE: u32 = 0x420021;
const TAG_IV_COUNTER_NONCE: u32 = 0x42003D;
const TAG_NAME_TYPE: u32 = 0x420054;
const TAG_NAME_VALUE: u32 = 0x420055;
const TAG_OBJECT_TYPE: u32 = 0x420057;
const TAG_OPERATION: u32 = 0x42005C;
const TAG_PROTOCOL_VERSION: u32 = 0x420069;
const TAG_PROTOCOL_VERSION_MAJOR: u32 = 0x42006A;
const TAG_PROTOCOL_VERSION_MINOR: u32 = 0x42006B;
const TAG_REQUEST_HEADER: u32 = 0x420077;
const TAG_REQUEST_MESSAGE: u32 = 0x420078;
const TAG_REQUEST_PAYLOAD: u32 = 0x420079;
const TAG_RESPONSE_HEADER: u32 = 0x42007A;
const TAG_RESPONSE_MESSAGE: u32 = 0x42007B;
const TAG_RESPONSE_PAYLOAD: u32 = 0x42007C;
const TAG_RESULT_STATUS: u32 = 0x42007F;
const TAG_REVOCATION_REASON: u32 = 0x420081;
const TAG_REVOCATION_REASON_CODE: u32 = 0x420082;
const TAG_TEMPLATE_ATTRIBUTE: u32 = 0x420091;
const TAG_TIME_STAMP: u32 = 0x420092;
const TAG_UNIQUE_IDENTIFIER: u32 = 0x420094;
const TAG_DATA: u32 = 0x4200C2;
const TAG_AEAD: u32 = 0x4200FE;
const TAG_AE_TAG: u32 = 0x4200FF;

const OP_CREATE: u32 = 0x01;
const OP_LOCATE: u32 = 0x08;
const OP_GET_ATTRIBUTES: u32 = 0x0B;
const OP_ACTIVATE: u32 = 0x12;
const OP_REVOKE: u32 = 0x13;
const OP_DESTROY: u32 = 0x14;
const OP_ENCRYPT: u32 = 0x1F;
const OP_DECRYPT: u32 = 0x20;
const STATUS_SUCCESS: u32 = 0;
const OBJECT_SYMMETRIC_KEY: u32 = 0x02;
const ALG_AES: u32 = 0x03;
const MODE_GCM: u32 = 0x09;
const USAGE_ENCRYPT_DECRYPT: u32 = 0x04 | 0x08;
const NAME_TYPE_TEXT: u32 = 0x01;
const REASON_KEY_COMPROMISE: u32 = 0x02;
const REASON_SUPERSEDED: u32 = 0x05;
const STATE_PRE_ACTIVE: u32 = 0x01;
const STATE_ACTIVE: u32 = 0x02;
const STATE_DEACTIVATED: u32 = 0x03;
const STATE_COMPROMISED: u32 = 0x04;
const STATE_DESTROYED: u32 = 0x05;
const STATE_DESTROYED_COMPROMISED: u32 = 0x06;

/// KMIP Name every Tenkai KEK on an endpoint carries.
const KEK_NAME: &str = "tenkai-kek";

type Wrapped = envelope_keys::WrappedDek;

#[derive(Debug, Clone)]
struct Item {
    tag: u32,
    value: Value,
}

#[derive(Debug, Clone)]
enum Value {
    Structure(Vec<Item>),
    Integer(i32),
    Enumeration(u32),
    Text(String),
    Bytes(Vec<u8>),
    DateTime(i64),
}

struct KekRef {
    id: KeyId,
}

struct ProviderInner {
    endpoint: SocketAddr,
    current: KekRef,
    /// Deactivated KEKs of a rotation not yet completed.
    previous: Vec<KekRef>,
    kek_revoked: bool,
    dek_revoked: HashSet<String>,
}

struct EndpointClaim {
    key: SocketAddr,
}

impl Drop for EndpointClaim {
    fn drop(&mut self) {
        if let Ok(mut held) = held_endpoints().lock() {
            held.remove(&self.key);
        }
    }
}

fn held_endpoints() -> &'static Mutex<HashSet<SocketAddr>> {
    static HELD: OnceLock<Mutex<HashSet<SocketAddr>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashSet::new()))
}

fn revoked_deks() -> &'static Mutex<HashMap<SocketAddr, HashSet<String>>> {
    static REVOKED: OnceLock<Mutex<HashMap<SocketAddr, HashSet<String>>>> = OnceLock::new();
    REVOKED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_revoked_dek(endpoint: SocketAddr, dek_id: &str) -> Result<(), KeyError> {
    revoked_deks()
        .lock()
        .map_err(|_| KeyError::WrapFailed)?
        .entry(endpoint)
        .or_default()
        .insert(dek_id.to_string());
    Ok(())
}

fn is_revoked_dek(endpoint: SocketAddr, dek_id: &str) -> Result<bool, KeyError> {
    Ok(revoked_deks()
        .lock()
        .map_err(|_| KeyError::WrapFailed)?
        .get(&endpoint)
        .is_some_and(|set| set.contains(dek_id)))
}

/// KMIP key provider. Keys never leave the endpoint.
pub struct KmipKeyProvider {
    inner: Mutex<ProviderInner>,
    _claim: EndpointClaim,
}

impl fmt::Debug for KmipKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.lock() {
            Ok(inner) => formatter
                .debug_struct("KmipKeyProvider")
                .field("kind", &ProviderKind::Kmip)
                .field("kek_id", &inner.current.id)
                .field(
                    "previous",
                    &inner.previous.iter().map(|kek| &kek.id).collect::<Vec<_>>(),
                )
                .field("kek", &"<redacted>")
                .field("kek_revoked", &inner.kek_revoked)
                .finish(),
            Err(_) => formatter
                .debug_struct("KmipKeyProvider")
                .field("kek", &"<redacted>")
                .finish(),
        }
    }
}

impl KmipKeyProvider {
    /// Open a KMIP endpoint and restore its KEKs, minting a current one only
    /// when the endpoint has none. A revoked KEK refuses the open. The DEK
    /// denylist is still process-local.
    pub fn open(endpoint: SocketAddr, profile: RuntimeProfile) -> Result<Self, KeyError> {
        admit_provider(profile, ProviderKind::Kmip)?;
        if !endpoint.ip().is_loopback() {
            // Remote KMIP is TLS-only; plaintext is lab loopback evidence.
            return Err(KeyError::WrapFailed);
        }
        let mut held = held_endpoints().lock().map_err(|_| KeyError::WrapFailed)?;
        if !held.insert(endpoint) {
            return Err(KeyError::WrapFailed);
        }
        drop(held);
        let claim = EndpointClaim { key: endpoint };
        let (current, previous) = restore_or_mint(endpoint)?;
        Ok(Self {
            inner: Mutex::new(ProviderInner {
                endpoint,
                current,
                previous,
                kek_revoked: false,
                dek_revoked: HashSet::new(),
            }),
            _claim: claim,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ProviderInner>, KeyError> {
        self.inner.lock().map_err(|_| KeyError::WrapFailed)
    }
}

impl KeyProvider for KmipKeyProvider {
    fn describe(&self) -> ProviderDescription {
        let kek_id = self
            .lock()
            .ok()
            .map(|inner| inner.current.id.clone())
            .unwrap_or_else(|| KeyId::new("unknown").expect("id"));
        ProviderDescription {
            kind: ProviderKind::Kmip,
            kek_id,
            algorithm: ALGORITHM,
        }
    }

    fn wrap(
        &self,
        tenant_id: &TenantId,
        purpose: KeyPurpose,
        dek: &Dek,
    ) -> Result<Wrapped, KeyError> {
        let inner = self.lock()?;
        wrap_with(&inner, tenant_id, purpose, dek, random_key_id("dek")?)
    }

    fn rewrap(&self, wrapped: &Wrapped, dek: &Dek) -> Result<Wrapped, KeyError> {
        let inner = self.lock()?;
        let recovered = unwrap_with(&inner, wrapped, &grant_from(wrapped), "rewrap", 0, true)?;
        if recovered.dek.as_bytes() != dek.as_bytes() {
            return Err(KeyError::WrapFailed);
        }
        wrap_with(
            &inner,
            &wrapped.tenant_id,
            wrapped.purpose,
            dek,
            wrapped.dek_id.clone(),
        )
    }

    fn unwrap(
        &self,
        wrapped: &Wrapped,
        grant: &UnwrapGrant,
        engine: &str,
        now_unix_secs: i64,
    ) -> Result<UnwrapOutcome, KeyError> {
        let inner = self.lock()?;
        unwrap_with(&inner, wrapped, grant, engine, now_unix_secs, false)
    }

    fn rotate_kek(&self) -> Result<KeyId, KeyError> {
        let mut inner = self.lock()?;
        if inner.kek_revoked {
            return Err(KeyError::Revoked);
        }
        if !inner.previous.is_empty() {
            return Err(KeyError::RotationOverlapActive);
        }
        // Deactivate first: a crash before the new KEK is Active leaves no
        // Active KEK, and the next open activates or mints one beside the
        // previous.
        revoke_key(inner.endpoint, &inner.current.id, REASON_SUPERSEDED)?;
        let next = create_and_activate(inner.endpoint)?;
        let previous = std::mem::replace(&mut inner.current, next);
        inner.previous.push(previous);
        Ok(inner.current.id.clone())
    }

    fn complete_kek_rotation(&self) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        if inner.kek_revoked {
            return Err(KeyError::Revoked);
        }
        while let Some(previous) = inner.previous.last() {
            destroy_key(inner.endpoint, &previous.id)?;
            inner.previous.pop();
        }
        Ok(())
    }

    fn revoke_kek(&self) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        inner.kek_revoked = true;
        // Compromised is recorded on the endpoint before any key is gone, so
        // a revocation interrupted here is still refused by the next open.
        revoke_key(inner.endpoint, &inner.current.id, REASON_KEY_COMPROMISE)?;
        for previous in &inner.previous {
            revoke_key(inner.endpoint, &previous.id, REASON_KEY_COMPROMISE)?;
        }
        destroy_key(inner.endpoint, &inner.current.id)?;
        while let Some(previous) = inner.previous.last() {
            destroy_key(inner.endpoint, &previous.id)?;
            inner.previous.pop();
        }
        Ok(())
    }

    fn revoke_dek(&self, dek_id: &KeyId) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        remember_revoked_dek(inner.endpoint, dek_id.as_str())?;
        let _ = inner.dek_revoked.insert(dek_id.as_str().to_string());
        Ok(())
    }
}

fn wrap_with(
    inner: &ProviderInner,
    tenant_id: &TenantId,
    purpose: KeyPurpose,
    dek: &Dek,
    dek_id: KeyId,
) -> Result<Wrapped, KeyError> {
    if inner.kek_revoked {
        return Err(KeyError::Revoked);
    }
    let nonce = random_bytes::<NONCE_LEN>()?;
    let (ciphertext, tag) = encrypt(
        inner.endpoint,
        inner.current.id.as_str(),
        &nonce,
        &aad(tenant_id, purpose, &dek_id),
        dek.as_bytes(),
    )?;
    let mut wrapped = nonce.to_vec();
    wrapped.extend_from_slice(&ciphertext);
    wrapped.extend_from_slice(&tag);
    Wrapped::new(
        inner.current.id.clone(),
        dek_id,
        tenant_id.clone(),
        purpose,
        wrapped,
    )
}

fn unwrap_with(
    inner: &ProviderInner,
    wrapped: &Wrapped,
    grant: &UnwrapGrant,
    engine: &str,
    now_unix_secs: i64,
    skip_grant: bool,
) -> Result<UnwrapOutcome, KeyError> {
    if inner.kek_revoked
        || inner.dek_revoked.contains(wrapped.dek_id.as_str())
        || is_revoked_dek(inner.endpoint, wrapped.dek_id.as_str())?
    {
        return Err(KeyError::Revoked);
    }
    if !skip_grant {
        if now_unix_secs >= grant.expires_unix_secs {
            return Err(KeyError::GrantDenied);
        }
        if wrapped.tenant_id != grant.tenant_id {
            return Err(KeyError::WrongTenant);
        }
        if wrapped.purpose != grant.purpose {
            return Err(KeyError::WrongPurpose);
        }
    }
    let key_id = wrapped.kek_id.as_str();
    let blob = wrapped.ciphertext();
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(KeyError::WrapFailed);
    }
    let nonce = &blob[..NONCE_LEN];
    let tag = &blob[blob.len() - TAG_LEN..];
    let ciphertext = &blob[NONCE_LEN..blob.len() - TAG_LEN];
    let mut plaintext = decrypt(
        inner.endpoint,
        key_id,
        nonce,
        &aad(&wrapped.tenant_id, wrapped.purpose, &wrapped.dek_id),
        ciphertext,
        tag,
    )?;
    let bytes = match <[u8; 32]>::try_from(plaintext.as_slice()) {
        Ok(bytes) => bytes,
        Err(_) => {
            plaintext.fill(0);
            return Err(KeyError::WrapFailed);
        }
    };
    plaintext.fill(0);
    Ok(UnwrapOutcome {
        dek: Dek::from_bytes(bytes),
        audit: UnwrapAudit {
            tenant_id: wrapped.tenant_id.clone(),
            engine: engine.to_string(),
            purpose: wrapped.purpose,
            key_id: wrapped.dek_id.clone(),
        },
    })
}

fn grant_from(wrapped: &Wrapped) -> UnwrapGrant {
    UnwrapGrant {
        tenant_id: wrapped.tenant_id.clone(),
        purpose: wrapped.purpose,
        expires_unix_secs: i64::MAX,
    }
}

fn purpose_tag(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Store => "store",
        KeyPurpose::Spill => "spill",
        KeyPurpose::Cache => "cache",
        KeyPurpose::Backup => "backup",
        KeyPurpose::Export => "export",
    }
}

fn aad(tenant_id: &TenantId, purpose: KeyPurpose, dek_id: &KeyId) -> Vec<u8> {
    let mut out = Vec::new();
    write_len_bytes(&mut out, tenant_id.as_str().as_bytes());
    write_len_bytes(&mut out, purpose_tag(purpose).as_bytes());
    write_len_bytes(&mut out, dek_id.as_str().as_bytes());
    out
}

fn write_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The endpoint's current KEK and the previous ones still in rotation
/// overlap, minting a current KEK when none is Active. A revoked KEK refuses.
///
/// Interrupted or concurrent opens are repaired rather than refused: a KEK
/// left Pre-Active between Create and Activate becomes current when no KEK
/// is Active, and is destroyed otherwise (it protects nothing). Two
/// processes minting on an empty endpoint leave several Active KEKs; the
/// lowest id stays current and the rest are deactivated, so their envelopes
/// still unwrap. Every opener picks the same one.
fn restore_or_mint(endpoint: SocketAddr) -> Result<(KekRef, Vec<KekRef>), KeyError> {
    let mut active = Vec::new();
    let mut pre_active = Vec::new();
    let mut previous = Vec::new();
    for id in locate_keks(endpoint)? {
        let state = key_state(endpoint, &id)?;
        let kek = KekRef {
            id: KeyId::new(id)?,
        };
        match state {
            STATE_ACTIVE => active.push(kek),
            STATE_PRE_ACTIVE => pre_active.push(kek),
            STATE_DEACTIVATED => previous.push(kek),
            STATE_COMPROMISED | STATE_DESTROYED_COMPROMISED => return Err(KeyError::Revoked),
            STATE_DESTROYED => {}
            _ => return Err(KeyError::WrapFailed),
        }
    }
    active.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    pre_active.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    if active.is_empty() && !pre_active.is_empty() {
        let kek = pre_active.remove(0);
        activate_key(endpoint, &kek.id)?;
        active.push(kek);
    }
    for orphan in &pre_active {
        destroy_key(endpoint, &orphan.id)?;
    }
    let mut active = active.into_iter();
    let current = match active.next() {
        Some(current) => current,
        None => create_and_activate(endpoint)?,
    };
    for extra in active {
        revoke_key(endpoint, &extra.id, REASON_SUPERSEDED)?;
        previous.push(extra);
    }
    Ok((current, previous))
}

fn locate_keks(endpoint: SocketAddr) -> Result<Vec<String>, KeyError> {
    let response = transact(endpoint, OP_LOCATE, vec![kek_name_attribute()])?;
    Ok(response
        .iter()
        .filter_map(|item| match (item.tag, &item.value) {
            (TAG_UNIQUE_IDENTIFIER, Value::Text(id)) => Some(id.clone()),
            _ => None,
        })
        .collect())
}

fn key_state(endpoint: SocketAddr, id: &str) -> Result<u32, KeyError> {
    let response = transact(
        endpoint,
        OP_GET_ATTRIBUTES,
        vec![
            text(TAG_UNIQUE_IDENTIFIER, id),
            text(TAG_ATTRIBUTE_NAME, "State"),
        ],
    )?;
    response
        .iter()
        .filter(|item| item.tag == TAG_ATTRIBUTE)
        .find(|attribute| {
            matches!(
                child(attribute, TAG_ATTRIBUTE_NAME).map(|name| &name.value),
                Some(Value::Text(name)) if name == "State"
            )
        })
        .and_then(|attribute| find_enum(attribute, TAG_ATTRIBUTE_VALUE))
        .ok_or(KeyError::WrapFailed)
}

fn kek_name_attribute() -> Item {
    structure(
        TAG_ATTRIBUTE,
        vec![
            text(TAG_ATTRIBUTE_NAME, "Name"),
            structure(
                TAG_ATTRIBUTE_VALUE,
                vec![
                    text(TAG_NAME_VALUE, KEK_NAME),
                    enumeration(TAG_NAME_TYPE, NAME_TYPE_TEXT),
                ],
            ),
        ],
    )
}

fn create_and_activate(endpoint: SocketAddr) -> Result<KekRef, KeyError> {
    let response = transact(endpoint, OP_CREATE, create_payload())?;
    let id = KeyId::new(unique_id(&response)?)?;
    activate_key(endpoint, &id)?;
    Ok(KekRef { id })
}

fn activate_key(endpoint: SocketAddr, id: &KeyId) -> Result<(), KeyError> {
    let activate = vec![text(TAG_UNIQUE_IDENTIFIER, id.as_str())];
    transact(endpoint, OP_ACTIVATE, activate).map(|_| ())
}

/// Revoke `id`: Superseded deactivates it (it still decrypts), Key
/// Compromise marks it revoked.
fn revoke_key(endpoint: SocketAddr, id: &KeyId, reason: u32) -> Result<(), KeyError> {
    let mut revoke = vec![
        text(TAG_UNIQUE_IDENTIFIER, id.as_str()),
        structure(
            TAG_REVOCATION_REASON,
            vec![enumeration(TAG_REVOCATION_REASON_CODE, reason)],
        ),
    ];
    // KMIP requires the occurrence date with a Key Compromise reason.
    if reason == REASON_KEY_COMPROMISE {
        revoke.push(Item {
            tag: TAG_COMPROMISE_OCCURRENCE_DATE,
            value: Value::DateTime(unix_now()),
        });
    }
    transact(endpoint, OP_REVOKE, revoke).map(|_| ())
}

fn destroy_key(endpoint: SocketAddr, id: &KeyId) -> Result<(), KeyError> {
    let payload = vec![text(TAG_UNIQUE_IDENTIFIER, id.as_str())];
    transact(endpoint, OP_DESTROY, payload).map(|_| ())
}

fn encrypt(
    endpoint: SocketAddr,
    key_id: &str,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KeyError> {
    let payload = vec![
        text(TAG_UNIQUE_IDENTIFIER, key_id),
        gcm_parameters(),
        bytes(TAG_DATA, plaintext),
        bytes(TAG_IV_COUNTER_NONCE, nonce),
        bytes(TAG_AEAD, aad),
    ];
    let response = transact(endpoint, OP_ENCRYPT, payload)?;
    let ciphertext = find_bytes(&response, TAG_DATA).ok_or(KeyError::WrapFailed)?;
    let tag = find_bytes(&response, TAG_AE_TAG).ok_or(KeyError::WrapFailed)?;
    Ok((ciphertext, tag))
}

fn decrypt(
    endpoint: SocketAddr,
    key_id: &str,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let payload = vec![
        text(TAG_UNIQUE_IDENTIFIER, key_id),
        gcm_parameters(),
        bytes(TAG_DATA, ciphertext),
        bytes(TAG_IV_COUNTER_NONCE, nonce),
        bytes(TAG_AEAD, aad),
        bytes(TAG_AE_TAG, tag),
    ];
    let response = transact(endpoint, OP_DECRYPT, payload)?;
    find_bytes(&response, TAG_DATA).ok_or(KeyError::WrapFailed)
}

fn create_payload() -> Vec<Item> {
    vec![
        enumeration(TAG_OBJECT_TYPE, OBJECT_SYMMETRIC_KEY),
        structure(
            TAG_TEMPLATE_ATTRIBUTE,
            vec![
                named_enum("Cryptographic Algorithm", ALG_AES),
                named_int("Cryptographic Length", 256),
                named_int("Cryptographic Usage Mask", USAGE_ENCRYPT_DECRYPT as i32),
                kek_name_attribute(),
            ],
        ),
    ]
}

fn gcm_parameters() -> Item {
    structure(
        TAG_CRYPTOGRAPHIC_PARAMETERS,
        vec![enumeration(TAG_BLOCK_CIPHER_MODE, MODE_GCM)],
    )
}

fn named_enum(name: &str, value: u32) -> Item {
    structure(
        TAG_ATTRIBUTE,
        vec![
            text(TAG_ATTRIBUTE_NAME, name),
            enumeration(TAG_ATTRIBUTE_VALUE, value),
        ],
    )
}

fn named_int(name: &str, value: i32) -> Item {
    structure(
        TAG_ATTRIBUTE,
        vec![
            text(TAG_ATTRIBUTE_NAME, name),
            integer(TAG_ATTRIBUTE_VALUE, value),
        ],
    )
}

fn structure(tag: u32, children: Vec<Item>) -> Item {
    Item {
        tag,
        value: Value::Structure(children),
    }
}

fn enumeration(tag: u32, value: u32) -> Item {
    Item {
        tag,
        value: Value::Enumeration(value),
    }
}

fn integer(tag: u32, value: i32) -> Item {
    Item {
        tag,
        value: Value::Integer(value),
    }
}

fn text(tag: u32, value: &str) -> Item {
    Item {
        tag,
        value: Value::Text(value.to_string()),
    }
}

fn bytes(tag: u32, value: &[u8]) -> Item {
    Item {
        tag,
        value: Value::Bytes(value.to_vec()),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn protocol_header(tag: u32) -> Item {
    structure(
        tag,
        vec![
            structure(
                TAG_PROTOCOL_VERSION,
                vec![
                    integer(TAG_PROTOCOL_VERSION_MAJOR, 1),
                    integer(TAG_PROTOCOL_VERSION_MINOR, 4),
                ],
            ),
            integer(TAG_BATCH_COUNT, 1),
            Item {
                tag: TAG_TIME_STAMP,
                value: Value::DateTime(unix_now()),
            },
        ],
    )
}

fn request_message(operation: u32, payload: Vec<Item>) -> Item {
    structure(
        TAG_REQUEST_MESSAGE,
        vec![
            protocol_header(TAG_REQUEST_HEADER),
            structure(
                TAG_BATCH_ITEM,
                vec![
                    enumeration(TAG_OPERATION, operation),
                    structure(TAG_REQUEST_PAYLOAD, payload),
                ],
            ),
        ],
    )
}

fn read_ttlv(stream: &mut TcpStream) -> Result<Item, KeyError> {
    let mut header = [0_u8; 8];
    stream
        .read_exact(&mut header)
        .map_err(|_| KeyError::WrapFailed)?;
    let len =
        u32::from_be_bytes(header[4..8].try_into().map_err(|_| KeyError::WrapFailed)?) as usize;
    if len == 0 || len > MAX_TTLV {
        return Err(KeyError::WrapFailed);
    }
    let mut rest = vec![0_u8; len + pad_len(len)];
    stream
        .read_exact(&mut rest)
        .map_err(|_| KeyError::WrapFailed)?;
    let mut buf = header.to_vec();
    buf.extend_from_slice(&rest);
    decode(&buf, 0)
        .and_then(|(item, leftover)| leftover.is_empty().then_some(item))
        .ok_or(KeyError::WrapFailed)
}

fn transact(
    endpoint: SocketAddr,
    operation: u32,
    payload: Vec<Item>,
) -> Result<Vec<Item>, KeyError> {
    let encoded = encode(&request_message(operation, payload));
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))
        .map_err(|_| KeyError::WrapFailed)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| KeyError::WrapFailed)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| KeyError::WrapFailed)?;
    stream
        .write_all(&encoded)
        .map_err(|_| KeyError::WrapFailed)?;
    let message = read_ttlv(&mut stream)?;
    if message.tag != TAG_RESPONSE_MESSAGE {
        return Err(KeyError::WrapFailed);
    }
    let batch = child(&message, TAG_BATCH_ITEM).ok_or(KeyError::WrapFailed)?;
    match find_enum(batch, TAG_RESULT_STATUS) {
        Some(STATUS_SUCCESS) => {}
        _ => return Err(KeyError::WrapFailed),
    }
    child(batch, TAG_RESPONSE_PAYLOAD)
        .map(|item| match &item.value {
            Value::Structure(items) => items.clone(),
            _ => Vec::new(),
        })
        .ok_or(KeyError::WrapFailed)
}

fn unique_id(payload: &[Item]) -> Result<String, KeyError> {
    payload
        .iter()
        .find_map(|item| match (&item.tag, &item.value) {
            (&TAG_UNIQUE_IDENTIFIER, Value::Text(id)) => Some(id.clone()),
            _ => None,
        })
        .ok_or(KeyError::WrapFailed)
}

fn find_bytes(payload: &[Item], tag: u32) -> Option<Vec<u8>> {
    payload
        .iter()
        .find_map(|item| match (item.tag, &item.value) {
            (item_tag, Value::Bytes(bytes)) if item_tag == tag => Some(bytes.clone()),
            _ => None,
        })
}

fn child(item: &Item, tag: u32) -> Option<&Item> {
    match &item.value {
        Value::Structure(items) => items.iter().find(|item| item.tag == tag),
        _ => None,
    }
}

fn find_enum(item: &Item, tag: u32) -> Option<u32> {
    match &item.value {
        Value::Structure(items) => items.iter().find_map(|item| match (item.tag, &item.value) {
            (item_tag, Value::Enumeration(value)) if item_tag == tag => Some(*value),
            _ => None,
        }),
        _ => None,
    }
}

fn pad_len(len: usize) -> usize {
    (8 - (len % 8)) % 8
}

fn encode(item: &Item) -> Vec<u8> {
    let (ty, raw) = match &item.value {
        Value::Structure(children) => {
            let mut raw = Vec::new();
            for child in children {
                raw.extend_from_slice(&encode(child));
            }
            (TYPE_STRUCTURE, raw)
        }
        Value::Integer(value) => (TYPE_INTEGER, value.to_be_bytes().to_vec()),
        Value::Enumeration(value) => (TYPE_ENUMERATION, value.to_be_bytes().to_vec()),
        Value::Text(value) => (TYPE_TEXT, value.as_bytes().to_vec()),
        Value::Bytes(value) => (TYPE_BYTES, value.clone()),
        Value::DateTime(value) => (TYPE_DATE_TIME, value.to_be_bytes().to_vec()),
    };
    let mut out = Vec::new();
    out.extend_from_slice(&item.tag.to_be_bytes()[1..]);
    out.push(ty);
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(&raw);
    out.extend(std::iter::repeat_n(0, pad_len(raw.len())));
    out
}

fn decode(input: &[u8], depth: usize) -> Option<(Item, &[u8])> {
    if input.len() < 8 || depth > MAX_DEPTH {
        return None;
    }
    let tag = u32::from_be_bytes([0, input[0], input[1], input[2]]);
    let ty = input[3];
    let len = u32::from_be_bytes(input[4..8].try_into().ok()?) as usize;
    if len > MAX_TTLV {
        return None;
    }
    let padded = len + pad_len(len);
    if input.len() < 8 + padded {
        return None;
    }
    let raw = &input[8..8 + len];
    let rest = &input[8 + padded..];
    let value = match ty {
        TYPE_STRUCTURE => {
            let mut children = Vec::new();
            let mut cursor = raw;
            while !cursor.is_empty() {
                let (child, next) = decode(cursor, depth + 1)?;
                children.push(child);
                cursor = next;
            }
            Value::Structure(children)
        }
        TYPE_INTEGER if raw.len() == 4 => Value::Integer(i32::from_be_bytes(raw.try_into().ok()?)),
        TYPE_ENUMERATION if raw.len() == 4 => {
            Value::Enumeration(u32::from_be_bytes(raw.try_into().ok()?))
        }
        TYPE_TEXT => Value::Text(std::str::from_utf8(raw).ok()?.to_string()),
        TYPE_BYTES => Value::Bytes(raw.to_vec()),
        TYPE_DATE_TIME if raw.len() == 8 => {
            Value::DateTime(i64::from_be_bytes(raw.try_into().ok()?))
        }
        _ => return None,
    };
    Some((Item { tag, value }, rest))
}

fn random_key_id(prefix: &str) -> Result<KeyId, KeyError> {
    let bytes = random_bytes::<16>()?;
    let mut id = String::from(prefix);
    id.push('-');
    for byte in bytes {
        id.push_str(&format!("{byte:02x}"));
    }
    KeyId::new(id)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], KeyError> {
    let mut bytes = [0_u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| KeyError::WrapFailed)?;
    Ok(bytes)
}

/// One key on the lab endpoint. Destroy wipes the material and keeps the
/// record, as a KMIP server keeps a destroyed object's state.
struct LabKey {
    secret: Option<[u8; 32]>,
    name: Option<String>,
    state: u32,
}

type LabKeys = Mutex<HashMap<String, LabKey>>;

/// Loopback KMIP 1.4 TTLV lab endpoint for tests.
pub fn serve_lab_endpoint(listener: TcpListener) -> SocketAddr {
    let addr = listener.local_addr().expect("lab kmip addr");
    thread::spawn(move || {
        let keys = LabKeys::default();
        for stream in listener.incoming().flatten() {
            let _ = handle_lab_client(stream, &keys);
        }
    });
    addr
}

fn handle_lab_client(mut stream: TcpStream, keys: &LabKeys) -> Result<(), KeyError> {
    let message = read_ttlv(&mut stream)?;
    let batch = child(&message, TAG_BATCH_ITEM).ok_or(KeyError::WrapFailed)?;
    let operation = find_enum(batch, TAG_OPERATION).ok_or(KeyError::WrapFailed)?;
    let payload = child(batch, TAG_REQUEST_PAYLOAD).ok_or(KeyError::WrapFailed)?;
    let items = match &payload.value {
        Value::Structure(items) => items,
        _ => return Err(KeyError::WrapFailed),
    };
    let response_payload = lab_operation(operation, items, keys).ok();
    write_ttlv(&mut stream, operation, response_payload)
}

fn lab_operation(operation: u32, items: &[Item], keys: &LabKeys) -> Result<Vec<Item>, KeyError> {
    let mut keys = keys.lock().map_err(|_| KeyError::WrapFailed)?;
    match operation {
        OP_CREATE => {
            let id = random_key_id("kek")?;
            let mut secret = [0_u8; 32];
            SystemRandom::new()
                .fill(&mut secret)
                .map_err(|_| KeyError::WrapFailed)?;
            let name = items
                .iter()
                .find(|item| item.tag == TAG_TEMPLATE_ATTRIBUTE)
                .and_then(|template| match &template.value {
                    Value::Structure(attributes) => attributes.iter().find_map(name_of),
                    _ => None,
                });
            keys.insert(
                id.as_str().to_string(),
                LabKey {
                    secret: Some(secret),
                    name,
                    state: STATE_PRE_ACTIVE,
                },
            );
            Ok(vec![
                enumeration(TAG_OBJECT_TYPE, OBJECT_SYMMETRIC_KEY),
                text(TAG_UNIQUE_IDENTIFIER, id.as_str()),
            ])
        }
        OP_ACTIVATE => {
            let id = unique_id(items)?;
            let key = keys.get_mut(&id).ok_or(KeyError::UnknownKey)?;
            if key.state != STATE_PRE_ACTIVE {
                return Err(KeyError::WrapFailed);
            }
            key.state = STATE_ACTIVE;
            Ok(vec![text(TAG_UNIQUE_IDENTIFIER, &id)])
        }
        OP_REVOKE => {
            let id = unique_id(items)?;
            let reason = items
                .iter()
                .find(|item| item.tag == TAG_REVOCATION_REASON)
                .and_then(|reason| find_enum(reason, TAG_REVOCATION_REASON_CODE))
                .ok_or(KeyError::WrapFailed)?;
            let dated = items
                .iter()
                .any(|item| item.tag == TAG_COMPROMISE_OCCURRENCE_DATE);
            if reason == REASON_KEY_COMPROMISE && !dated {
                return Err(KeyError::WrapFailed);
            }
            let key = keys.get_mut(&id).ok_or(KeyError::UnknownKey)?;
            key.state = match (reason, key.state) {
                (REASON_KEY_COMPROMISE, STATE_DESTROYED | STATE_DESTROYED_COMPROMISED) => {
                    STATE_DESTROYED_COMPROMISED
                }
                (REASON_KEY_COMPROMISE, _) => STATE_COMPROMISED,
                (_, STATE_ACTIVE) => STATE_DEACTIVATED,
                (_, state) => state,
            };
            Ok(vec![text(TAG_UNIQUE_IDENTIFIER, &id)])
        }
        OP_DESTROY => {
            let id = unique_id(items)?;
            let key = keys.get_mut(&id).ok_or(KeyError::UnknownKey)?;
            if key.state == STATE_ACTIVE {
                return Err(KeyError::WrapFailed);
            }
            if let Some(mut secret) = key.secret.take() {
                secret.fill(0);
            }
            key.state = if matches!(key.state, STATE_COMPROMISED | STATE_DESTROYED_COMPROMISED) {
                STATE_DESTROYED_COMPROMISED
            } else {
                STATE_DESTROYED
            };
            Ok(vec![text(TAG_UNIQUE_IDENTIFIER, &id)])
        }
        OP_LOCATE => {
            let wanted = items.iter().find_map(name_of).ok_or(KeyError::WrapFailed)?;
            let mut ids = keys
                .iter()
                .filter(|(_, key)| key.name.as_deref() == Some(wanted.as_str()))
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            ids.sort();
            Ok(ids
                .iter()
                .map(|id| text(TAG_UNIQUE_IDENTIFIER, id))
                .collect())
        }
        OP_GET_ATTRIBUTES => {
            let id = unique_id(items)?;
            let key = keys.get(&id).ok_or(KeyError::UnknownKey)?;
            Ok(vec![
                text(TAG_UNIQUE_IDENTIFIER, &id),
                structure(
                    TAG_ATTRIBUTE,
                    vec![
                        text(TAG_ATTRIBUTE_NAME, "State"),
                        enumeration(TAG_ATTRIBUTE_VALUE, key.state),
                    ],
                ),
            ])
        }
        OP_ENCRYPT | OP_DECRYPT => {
            let id = unique_id(items)?;
            let key = keys.get(&id).ok_or(KeyError::UnknownKey)?;
            // Only an Active key protects; a Deactivated one still processes.
            let usable = match operation {
                OP_ENCRYPT => key.state == STATE_ACTIVE,
                _ => matches!(key.state, STATE_ACTIVE | STATE_DEACTIVATED),
            };
            let secret = key
                .secret
                .as_ref()
                .filter(|_| usable)
                .ok_or(KeyError::Revoked)?;
            crypto_op(&id, items, secret, operation == OP_ENCRYPT)
        }
        _ => Err(KeyError::WrapFailed),
    }
}

/// The text value of a KMIP `Name` attribute.
fn name_of(attribute: &Item) -> Option<String> {
    if attribute.tag != TAG_ATTRIBUTE {
        return None;
    }
    match child(attribute, TAG_ATTRIBUTE_NAME).map(|name| &name.value) {
        Some(Value::Text(name)) if name == "Name" => {}
        _ => return None,
    }
    match child(child(attribute, TAG_ATTRIBUTE_VALUE)?, TAG_NAME_VALUE)?.value {
        Value::Text(ref value) => Some(value.clone()),
        _ => None,
    }
}

fn crypto_op(
    id: &str,
    items: &[Item],
    secret: &[u8; 32],
    encrypting: bool,
) -> Result<Vec<Item>, KeyError> {
    let data = find_bytes(items, TAG_DATA).ok_or(KeyError::WrapFailed)?;
    let nonce = find_bytes(items, TAG_IV_COUNTER_NONCE).ok_or(KeyError::WrapFailed)?;
    let aad = find_bytes(items, TAG_AEAD).unwrap_or_default();
    if encrypting {
        let (ciphertext, tag) = seal(secret, &nonce, &aad, &data)?;
        Ok(vec![
            text(TAG_UNIQUE_IDENTIFIER, id),
            bytes(TAG_DATA, &ciphertext),
            bytes(TAG_IV_COUNTER_NONCE, &nonce),
            bytes(TAG_AE_TAG, &tag),
        ])
    } else {
        let tag = find_bytes(items, TAG_AE_TAG).ok_or(KeyError::WrapFailed)?;
        let plaintext = open(secret, &nonce, &aad, &data, &tag)?;
        Ok(vec![
            text(TAG_UNIQUE_IDENTIFIER, id),
            bytes(TAG_DATA, &plaintext),
        ])
    }
}

fn write_ttlv(
    stream: &mut TcpStream,
    operation: u32,
    payload: Option<Vec<Item>>,
) -> Result<(), KeyError> {
    let status = if payload.is_some() { STATUS_SUCCESS } else { 1 };
    let mut batch = vec![
        enumeration(TAG_OPERATION, operation),
        enumeration(TAG_RESULT_STATUS, status),
    ];
    if let Some(payload) = payload {
        batch.push(structure(TAG_RESPONSE_PAYLOAD, payload));
    }
    let message = structure(
        TAG_RESPONSE_MESSAGE,
        vec![
            protocol_header(TAG_RESPONSE_HEADER),
            structure(TAG_BATCH_ITEM, batch),
        ],
    );
    stream
        .write_all(&encode(&message))
        .map_err(|_| KeyError::WrapFailed)
}

fn aes_key(secret: &[u8; 32]) -> Result<LessSafeKey, KeyError> {
    let unbound = UnboundKey::new(&AES_256_GCM, secret).map_err(|_| KeyError::WrapFailed)?;
    Ok(LessSafeKey::new(unbound))
}

fn nonce_from(bytes: &[u8]) -> Result<Nonce, KeyError> {
    if bytes.len() != NONCE_LEN {
        return Err(KeyError::WrapFailed);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(bytes);
    Ok(Nonce::assume_unique_for_key(nonce))
}

fn seal(
    secret: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KeyError> {
    let mut body = plaintext.to_vec();
    aes_key(secret)?
        .seal_in_place_append_tag(nonce_from(nonce)?, Aad::from(aad), &mut body)
        .map_err(|_| KeyError::WrapFailed)?;
    if body.len() < TAG_LEN {
        return Err(KeyError::WrapFailed);
    }
    let tag = body.split_off(body.len() - TAG_LEN);
    Ok((body, tag))
}

fn open(
    secret: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let mut body = ciphertext.to_vec();
    body.extend_from_slice(tag);
    let plaintext = aes_key(secret)?
        .open_in_place(nonce_from(nonce)?, Aad::from(aad), &mut body)
        .map_err(|_| KeyError::WrapFailed)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kmip_ttlv_round_trips_a_create_request() {
        let encoded = encode(&request_message(OP_CREATE, create_payload()));
        let (decoded, rest) = decode(&encoded, 0).expect("ttlv");
        assert!(rest.is_empty());
        assert_eq!(decoded.tag, TAG_REQUEST_MESSAGE);
        let batch = child(&decoded, TAG_BATCH_ITEM).expect("batch");
        assert_eq!(find_enum(batch, TAG_OPERATION), Some(OP_CREATE));
    }

    #[test]
    fn kmip_lab_endpoint_covers_wrap_unwrap_rotate_describe_and_revoke() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("lab kmip bind");
        let endpoint = serve_lab_endpoint(listener);
        let provider =
            KmipKeyProvider::open(endpoint, RuntimeProfile::Production).expect("open kmip");
        let described = provider.describe();
        assert_eq!(described.kind, ProviderKind::Kmip);
        assert_eq!(described.algorithm, ALGORITHM);
        let dek = Dek::generate();
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let wrapped = provider
            .wrap(&tenant, KeyPurpose::Store, &dek)
            .expect("wrap");
        let debug = format!("{provider:?}");
        let hint: String = dek
            .as_bytes()
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&hint));
        drop(wrapped);
        envelope_keys::conformance::assert_provider_contract(&provider);
    }

    fn lab() -> SocketAddr {
        serve_lab_endpoint(TcpListener::bind("127.0.0.1:0").expect("lab kmip bind"))
    }

    fn open_lab(endpoint: SocketAddr) -> Result<KmipKeyProvider, KeyError> {
        KmipKeyProvider::open(endpoint, RuntimeProfile::Production)
    }

    fn grant(tenant: &TenantId) -> UnwrapGrant {
        UnwrapGrant {
            tenant_id: tenant.clone(),
            purpose: KeyPurpose::Store,
            expires_unix_secs: i64::MAX,
        }
    }

    // #1299: each provider below stands in for a separate process.
    #[test]
    fn a_revoke_from_a_later_open_destroys_the_kek_earlier_envelopes_use() {
        let endpoint = lab();
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let first = open_lab(endpoint).expect("open first");
        let wrapped = first
            .wrap(&tenant, KeyPurpose::Store, &Dek::generate())
            .expect("wrap");
        drop(first);

        let second = open_lab(endpoint).expect("open second");
        assert_eq!(second.describe().kek_id, wrapped.kek_id);
        second.revoke_kek().expect("revoke");
        drop(second);

        assert!(matches!(open_lab(endpoint), Err(KeyError::Revoked)));
        // The endpoint itself no longer decrypts under the revoked KEK.
        let blob = wrapped.ciphertext();
        let decrypted = decrypt(
            endpoint,
            wrapped.kek_id.as_str(),
            &blob[..NONCE_LEN],
            &aad(&wrapped.tenant_id, wrapped.purpose, &wrapped.dek_id),
            &blob[NONCE_LEN..blob.len() - TAG_LEN],
            &blob[blob.len() - TAG_LEN..],
        );
        assert!(decrypted.is_err());
    }

    #[test]
    fn repeated_opens_create_no_new_kek() {
        let endpoint = lab();
        let first = open_lab(endpoint).expect("open").describe().kek_id;
        for _ in 0..3 {
            assert_eq!(open_lab(endpoint).expect("reopen").describe().kek_id, first);
        }
        assert_eq!(locate_keks(endpoint).expect("locate").len(), 1);
    }

    // An interrupted Create-then-Activate and two concurrent first opens
    // are repaired on the next open, not refused forever.
    #[test]
    fn a_pre_active_or_duplicate_active_kek_is_repaired_on_open() {
        let endpoint = lab();
        let stranded = unique_id(&transact(endpoint, OP_CREATE, create_payload()).expect("create"))
            .expect("id");
        let current = open_lab(endpoint).expect("open").describe().kek_id;
        assert_eq!(current.as_str(), stranded);

        let other = lab();
        let first = create_and_activate(other).expect("first").id;
        let second = create_and_activate(other).expect("second").id;
        let orphan =
            unique_id(&transact(other, OP_CREATE, create_payload()).expect("create")).expect("id");
        let lowest = first.as_str().min(second.as_str()).to_string();
        let provider = open_lab(other).expect("open");
        assert_eq!(provider.describe().kek_id.as_str(), lowest);
        assert!(matches!(
            provider.rotate_kek(),
            Err(KeyError::RotationOverlapActive)
        ));
        assert_eq!(key_state(other, &orphan).expect("state"), STATE_DESTROYED);
    }

    #[test]
    fn a_rotation_in_overlap_survives_a_reopen() {
        let endpoint = lab();
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let dek = Dek::generate();
        let first = open_lab(endpoint).expect("open first");
        let wrapped = first.wrap(&tenant, KeyPurpose::Store, &dek).expect("wrap");
        let rotated = first.rotate_kek().expect("rotate");
        drop(first);

        let second = open_lab(endpoint).expect("open second");
        assert_eq!(second.describe().kek_id, rotated);
        assert!(matches!(
            second.rotate_kek(),
            Err(KeyError::RotationOverlapActive)
        ));
        let recovered = second
            .unwrap(&wrapped, &grant(&tenant), "test", 0)
            .expect("unwrap under the previous KEK");
        assert_eq!(recovered.dek.as_bytes(), dek.as_bytes());
        second.complete_kek_rotation().expect("complete");
        assert!(second.unwrap(&wrapped, &grant(&tenant), "test", 0).is_err());
        drop(second);

        let third = open_lab(endpoint).expect("open third");
        assert_eq!(third.describe().kek_id, rotated);
        third.rotate_kek().expect("no overlap left");
    }
}

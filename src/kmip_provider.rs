//! KMIP 1.4 adapter for the customer-managed key contract (ADR 0113).
//!
//! Wrap, unwrap, KEK rotate, describe, and revoke run through a KMIP endpoint
//! using TTLV Create, Activate, Encrypt, Decrypt, and Destroy. Describe reports
//! kind, key ids, and algorithm names. It never returns key material. Tests speak
//! TTLV to a loopback lab endpoint.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sekai_keys::{
    Dek, KeyError, KeyId, KeyProvider, KeyPurpose, ProviderDescription, ProviderKind,
    RuntimeProfile, TenantId, UnwrapAudit, UnwrapGrant, UnwrapOutcome, admit_provider,
};

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
const TAG_IV_COUNTER_NONCE: u32 = 0x42003D;
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

type Wrapped = sekai_keys::WrappedDek;

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
    previous: Option<KekRef>,
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

fn revoked_keks() -> &'static Mutex<HashMap<SocketAddr, HashSet<String>>> {
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

fn remember_revoked_kek(endpoint: SocketAddr, kek_id: &str) -> Result<(), KeyError> {
    revoked_keks()
        .lock()
        .map_err(|_| KeyError::WrapFailed)?
        .entry(endpoint)
        .or_default()
        .insert(kek_id.to_string());
    Ok(())
}

fn is_revoked_dek(endpoint: SocketAddr, dek_id: &str) -> Result<bool, KeyError> {
    Ok(revoked_deks()
        .lock()
        .map_err(|_| KeyError::WrapFailed)?
        .get(&endpoint)
        .is_some_and(|set| set.contains(dek_id)))
}

fn is_revoked_kek(endpoint: SocketAddr, kek_id: &str) -> Result<bool, KeyError> {
    Ok(revoked_keks()
        .lock()
        .map_err(|_| KeyError::WrapFailed)?
        .get(&endpoint)
        .is_some_and(|set| set.contains(kek_id)))
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
                .field("previous", &inner.previous.as_ref().map(|kek| &kek.id))
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
    /// Open a KMIP endpoint and mint a current wrapping KEK.
    /// Existing envelopes still decrypt against their own KEK ids until Destroy.
    /// Session rotation/DEK denylists are not a durable client store.
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
        let current = create_and_activate(endpoint)?;
        Ok(Self {
            inner: Mutex::new(ProviderInner {
                endpoint,
                current,
                previous: None,
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
        if inner.previous.is_some() {
            return Err(KeyError::RotationOverlapActive);
        }
        let next = create_and_activate(inner.endpoint)?;
        inner.previous = Some(std::mem::replace(&mut inner.current, next));
        Ok(inner.current.id.clone())
    }

    fn complete_kek_rotation(&self) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        if inner.kek_revoked {
            return Err(KeyError::Revoked);
        }
        let Some(previous) = inner.previous.as_ref() else {
            return Ok(());
        };
        destroy_key(inner.endpoint, &previous.id)?;
        inner.previous = None;
        Ok(())
    }

    fn revoke_kek(&self) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        inner.kek_revoked = true;
        remember_revoked_kek(inner.endpoint, inner.current.id.as_str())?;
        destroy_key(inner.endpoint, &inner.current.id)?;
        if let Some(previous) = inner.previous.as_ref() {
            remember_revoked_kek(inner.endpoint, previous.id.as_str())?;
            destroy_key(inner.endpoint, &previous.id)?;
            inner.previous = None;
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
        || is_revoked_kek(inner.endpoint, wrapped.kek_id.as_str())?
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

fn create_and_activate(endpoint: SocketAddr) -> Result<KekRef, KeyError> {
    let response = transact(endpoint, OP_CREATE, create_payload())?;
    let id = unique_id(&response)?;
    let activate = vec![text(TAG_UNIQUE_IDENTIFIER, &id)];
    let _ = transact(endpoint, OP_ACTIVATE, activate)?;
    Ok(KekRef {
        id: KeyId::new(id)?,
    })
}

fn destroy_key(endpoint: SocketAddr, id: &KeyId) -> Result<(), KeyError> {
    let revoke = vec![
        text(TAG_UNIQUE_IDENTIFIER, id.as_str()),
        structure(
            TAG_REVOCATION_REASON,
            vec![enumeration(TAG_REVOCATION_REASON_CODE, 1)],
        ),
    ];
    let _ = transact(endpoint, OP_REVOKE, revoke);
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

/// Loopback KMIP 1.4 TTLV lab endpoint for tests.
pub fn serve_lab_endpoint(listener: TcpListener) -> SocketAddr {
    let addr = listener.local_addr().expect("lab kmip addr");
    thread::spawn(move || {
        let keys = Mutex::new(HashMap::<String, [u8; 32]>::new());
        for stream in listener.incoming().flatten() {
            let _ = handle_lab_client(stream, &keys);
        }
    });
    addr
}

fn handle_lab_client(
    mut stream: TcpStream,
    keys: &Mutex<HashMap<String, [u8; 32]>>,
) -> Result<(), KeyError> {
    let message = read_ttlv(&mut stream)?;
    let batch = child(&message, TAG_BATCH_ITEM).ok_or(KeyError::WrapFailed)?;
    let operation = find_enum(batch, TAG_OPERATION).ok_or(KeyError::WrapFailed)?;
    let payload = child(batch, TAG_REQUEST_PAYLOAD).ok_or(KeyError::WrapFailed)?;
    let items = match &payload.value {
        Value::Structure(items) => items,
        _ => return Err(KeyError::WrapFailed),
    };
    let response_payload = match operation {
        OP_CREATE => {
            let id = random_key_id("kek")?;
            let mut secret = [0_u8; 32];
            SystemRandom::new()
                .fill(&mut secret)
                .map_err(|_| KeyError::WrapFailed)?;
            keys.lock()
                .map_err(|_| KeyError::WrapFailed)?
                .insert(id.as_str().to_string(), secret);
            vec![
                enumeration(TAG_OBJECT_TYPE, OBJECT_SYMMETRIC_KEY),
                text(TAG_UNIQUE_IDENTIFIER, id.as_str()),
            ]
        }
        OP_ACTIVATE => {
            let id = unique_id(items)?;
            if !keys
                .lock()
                .map_err(|_| KeyError::WrapFailed)?
                .contains_key(&id)
            {
                return write_ttlv(&mut stream, OP_ACTIVATE, None);
            }
            vec![text(TAG_UNIQUE_IDENTIFIER, &id)]
        }
        OP_DESTROY => {
            let id = unique_id(items)?;
            if let Some(mut secret) = keys.lock().map_err(|_| KeyError::WrapFailed)?.remove(&id) {
                secret.fill(0);
            }
            vec![text(TAG_UNIQUE_IDENTIFIER, &id)]
        }
        OP_REVOKE => {
            let id = unique_id(items)?;
            vec![text(TAG_UNIQUE_IDENTIFIER, &id)]
        }
        OP_ENCRYPT => crypto_op(items, keys, true)?,
        OP_DECRYPT => crypto_op(items, keys, false)?,
        _ => return write_ttlv(&mut stream, operation, None),
    };
    write_ttlv(&mut stream, operation, Some(response_payload))
}

fn crypto_op(
    items: &[Item],
    keys: &Mutex<HashMap<String, [u8; 32]>>,
    encrypting: bool,
) -> Result<Vec<Item>, KeyError> {
    let id = unique_id(items)?;
    let data = find_bytes(items, TAG_DATA).ok_or(KeyError::WrapFailed)?;
    let nonce = find_bytes(items, TAG_IV_COUNTER_NONCE).ok_or(KeyError::WrapFailed)?;
    let aad = find_bytes(items, TAG_AEAD).unwrap_or_default();
    let keys = keys.lock().map_err(|_| KeyError::WrapFailed)?;
    let secret = keys.get(&id).ok_or(KeyError::UnknownKey)?;
    if encrypting {
        let (ciphertext, tag) = seal(secret, &nonce, &aad, &data)?;
        Ok(vec![
            text(TAG_UNIQUE_IDENTIFIER, &id),
            bytes(TAG_DATA, &ciphertext),
            bytes(TAG_IV_COUNTER_NONCE, &nonce),
            bytes(TAG_AE_TAG, &tag),
        ])
    } else {
        let tag = find_bytes(items, TAG_AE_TAG).ok_or(KeyError::WrapFailed)?;
        let plaintext = open(secret, &nonce, &aad, &data, &tag)?;
        Ok(vec![
            text(TAG_UNIQUE_IDENTIFIER, &id),
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
        sekai_keys::conformance::assert_provider_contract(&provider);
    }
}

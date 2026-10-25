//! PKCS#11 adapter for the customer-managed key contract (ADR 0113).
//!
//! Wrap, unwrap, KEK rotate, describe, and revoke run inside a PKCS#11 token.
//! Describe reports kind, key ids, and algorithm names. It never returns key
//! material. A software token (SoftHSM) is the CI stand-in for a customer HSM.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use ring::rand::{SecureRandom, SystemRandom};
use sekai_keys::{
    Dek, KeyError, KeyId, KeyProvider, KeyPurpose, ProviderDescription, ProviderKind,
    RuntimeProfile, TenantId, UnwrapAudit, UnwrapGrant, UnwrapOutcome, admit_provider,
};
use serde::{Deserialize, Serialize};

const ALGORITHM: &str = "AES-256-GCM";
const TAG_BITS: u64 = 128;
const NONCE_LEN: usize = 12;
const AES_KEY_LEN: u64 = 32;
const META_LABEL: &[u8] = b"tenkai.pkcs11.meta.v1";

type Wrapped = sekai_keys::WrappedDek;

struct KekRef {
    id: KeyId,
    handle: ObjectHandle,
}

struct ProviderInner {
    session: Session,
    current: KekRef,
    previous: Option<KekRef>,
    kek_revoked: bool,
    dek_revoked: HashSet<String>,
}

pub(crate) struct TokenClaim {
    key: String,
}

impl Drop for TokenClaim {
    fn drop(&mut self) {
        if let Ok(mut held) = held_tokens().lock() {
            held.remove(&self.key);
        }
    }
}

fn held_tokens() -> &'static Mutex<HashSet<String>> {
    static HELD: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(crate) fn claim_token(module: &Path, token_label: &str) -> Result<TokenClaim, KeyError> {
    claim_token_for(module, token_label, "key-provider")
}

pub(crate) fn claim_token_for(
    module: &Path,
    token_label: &str,
    purpose: &str,
) -> Result<TokenClaim, KeyError> {
    // Exclusive per (module, token, purpose) in this process so wrap and sign
    // can share a token. Cross-process HSM locking is out of scope.
    let module = std::fs::canonicalize(module).unwrap_or_else(|_| module.to_path_buf());
    let key = format!("{}:{token_label}:{purpose}", module.display());
    let mut held = held_tokens().lock().map_err(|_| KeyError::WrapFailed)?;
    if !held.insert(key.clone()) {
        return Err(KeyError::WrapFailed);
    }
    Ok(TokenClaim { key })
}

/// PKCS#11 HSM (or software-token) key provider.
pub struct Pkcs11KeyProvider {
    inner: Mutex<ProviderInner>,
    _claim: TokenClaim,
}

impl fmt::Debug for Pkcs11KeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.lock() {
            Ok(inner) => formatter
                .debug_struct("Pkcs11KeyProvider")
                .field("kind", &ProviderKind::Pkcs11)
                .field("kek_id", &inner.current.id)
                .field("previous", &inner.previous.as_ref().map(|kek| &kek.id))
                .field("kek", &"<redacted>")
                .field("kek_revoked", &inner.kek_revoked)
                .finish(),
            Err(_) => formatter
                .debug_struct("Pkcs11KeyProvider")
                .field("kek", &"<redacted>")
                .finish(),
        }
    }
}

impl Pkcs11KeyProvider {
    /// Open a token by label and mint a KEK if the token has none yet.
    pub fn open(
        module: &Path,
        token_label: &str,
        pin: &str,
        profile: RuntimeProfile,
    ) -> Result<Self, KeyError> {
        admit_provider(profile, ProviderKind::Pkcs11)?;
        let claim = claim_token(module, token_label)?;
        let pkcs11 = load_pkcs11(module)?;
        let slot = slot_with_label(&pkcs11, token_label)?;
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|_| KeyError::WrapFailed)?;
        match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
            Ok(())
            | Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::UserAlreadyLoggedIn,
                _,
            )) => {}
            Err(_) => return Err(KeyError::WrapFailed),
        }
        let restored = restore_or_mint(&session)?;
        Ok(Self {
            inner: Mutex::new(ProviderInner {
                session,
                current: restored.current,
                previous: restored.previous,
                kek_revoked: restored.revoked,
                dek_revoked: restored.dek_revoked,
            }),
            _claim: claim,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ProviderInner>, KeyError> {
        self.inner.lock().map_err(|_| KeyError::WrapFailed)
    }
}

impl KeyProvider for Pkcs11KeyProvider {
    fn describe(&self) -> ProviderDescription {
        let kek_id = self
            .lock()
            .ok()
            .map(|inner| inner.current.id.clone())
            .unwrap_or_else(|| KeyId::new("unknown").expect("id"));
        ProviderDescription {
            kind: ProviderKind::Pkcs11,
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
        wrap_with(&inner, tenant_id, purpose, dek, random_dek_id()?)
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
        let next = generate_kek(&inner.session)?;
        inner.previous = Some(std::mem::replace(&mut inner.current, next));
        if let Err(error) = persist_inner(&inner) {
            let Some(previous) = inner.previous.take() else {
                return Err(error);
            };
            let unpublished = std::mem::replace(&mut inner.current, previous);
            let _ = destroy_kek(&inner.session, unpublished.handle);
            return Err(error);
        }
        Ok(inner.current.id.clone())
    }

    fn complete_kek_rotation(&self) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        if inner.kek_revoked {
            return Err(KeyError::Revoked);
        }
        let Some(previous) = inner.previous.take() else {
            return persist_inner(&inner);
        };
        if let Err(error) = persist_inner(&inner) {
            inner.previous = Some(previous);
            return Err(error);
        }
        destroy_kek(&inner.session, previous.handle)?;
        Ok(())
    }

    fn revoke_kek(&self) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        inner.kek_revoked = true;
        persist_inner(&inner)?;
        destroy_kek(&inner.session, inner.current.handle)?;
        if let Some(previous) = inner.previous.take() {
            destroy_kek(&inner.session, previous.handle)?;
        }
        Ok(())
    }

    fn revoke_dek(&self, dek_id: &KeyId) -> Result<(), KeyError> {
        let mut inner = self.lock()?;
        let _ = inner.dek_revoked.insert(dek_id.as_str().to_string());
        persist_inner(&inner)?;
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
    let ciphertext = encrypt(
        &inner.session,
        inner.current.handle,
        &aad(tenant_id, purpose, &dek_id),
        dek.as_bytes(),
    )?;
    Wrapped::new(
        inner.current.id.clone(),
        dek_id,
        tenant_id.clone(),
        purpose,
        ciphertext,
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
    if inner.kek_revoked || inner.dek_revoked.contains(wrapped.dek_id.as_str()) {
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
    let handle = kek_handle(inner, &wrapped.kek_id)?;
    let dek = decrypt(
        &inner.session,
        handle,
        &aad(&wrapped.tenant_id, wrapped.purpose, &wrapped.dek_id),
        wrapped.ciphertext(),
    )?;
    Ok(UnwrapOutcome {
        dek,
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

fn kek_handle(inner: &ProviderInner, kek_id: &KeyId) -> Result<ObjectHandle, KeyError> {
    if inner.current.id == *kek_id {
        return Ok(inner.current.handle);
    }
    match &inner.previous {
        Some(previous) if previous.id == *kek_id => Ok(previous.handle),
        _ => Err(KeyError::UnknownKey),
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

fn encrypt(
    session: &Session,
    key: ObjectHandle,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let mut nonce = random_nonce()?;
    let prefix = nonce;
    let params =
        GcmParams::new(&mut nonce, aad, TAG_BITS.into()).map_err(|_| KeyError::WrapFailed)?;
    let ciphertext = session
        .encrypt(&Mechanism::AesGcm(params), key, plaintext)
        .map_err(|_| KeyError::WrapFailed)?;
    let mut out = prefix.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(
    session: &Session,
    key: ObjectHandle,
    aad: &[u8],
    wrapped: &[u8],
) -> Result<Dek, KeyError> {
    if wrapped.len() < NONCE_LEN {
        return Err(KeyError::WrapFailed);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&wrapped[..NONCE_LEN]);
    let params =
        GcmParams::new(&mut nonce, aad, TAG_BITS.into()).map_err(|_| KeyError::WrapFailed)?;
    let mut plaintext = session
        .decrypt(&Mechanism::AesGcm(params), key, &wrapped[NONCE_LEN..])
        .map_err(|_| KeyError::WrapFailed)?;
    let bytes = match <[u8; 32]>::try_from(plaintext.as_slice()) {
        Ok(bytes) => bytes,
        Err(_) => {
            plaintext.fill(0);
            return Err(KeyError::WrapFailed);
        }
    };
    plaintext.fill(0);
    Ok(Dek::from_bytes(bytes))
}

#[derive(Serialize, Deserialize)]
struct TokenMeta {
    generation: u64,
    current: String,
    previous: Option<String>,
    revoked: bool,
    #[serde(default)]
    dek_revoked: Vec<String>,
}

struct Restored {
    current: KekRef,
    previous: Option<KekRef>,
    revoked: bool,
    dek_revoked: HashSet<String>,
}

fn destroy_kek(session: &Session, handle: ObjectHandle) -> Result<(), KeyError> {
    session
        .destroy_object(handle)
        .map_err(|_| KeyError::WrapFailed)
}

fn find_kek(session: &Session, id: &KeyId) -> Result<KekRef, KeyError> {
    let found = session
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Private(true),
            Attribute::Label(id.as_str().as_bytes().to_vec()),
        ])
        .map_err(|_| KeyError::WrapFailed)?;
    let handle = found.into_iter().next().ok_or(KeyError::UnknownKey)?;
    Ok(KekRef {
        id: id.clone(),
        handle,
    })
}

fn find_meta_objects(session: &Session) -> Result<Vec<ObjectHandle>, KeyError> {
    session
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Private(true),
            Attribute::Label(META_LABEL.to_vec()),
        ])
        .map_err(|_| KeyError::WrapFailed)
}

fn read_meta(session: &Session, handle: ObjectHandle) -> Result<TokenMeta, KeyError> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|_| KeyError::WrapFailed)?;
    let Some(Attribute::Value(bytes)) = attributes.into_iter().next() else {
        return Err(KeyError::WrapFailed);
    };
    serde_json::from_slice(&bytes).map_err(|_| KeyError::WrapFailed)
}

fn load_meta(session: &Session) -> Result<Option<TokenMeta>, KeyError> {
    let mut best: Option<TokenMeta> = None;
    for handle in find_meta_objects(session)? {
        let meta = read_meta(session, handle)?;
        if best
            .as_ref()
            .is_none_or(|current| meta.generation > current.generation)
        {
            best = Some(meta);
        }
    }
    Ok(best)
}

fn persist_inner(inner: &ProviderInner) -> Result<(), KeyError> {
    persist_meta(
        &inner.session,
        &inner.current.id,
        inner.previous.as_ref().map(|kek| &kek.id),
        inner.kek_revoked,
        &inner.dek_revoked,
    )
}

fn persist_meta(
    session: &Session,
    current: &KeyId,
    previous: Option<&KeyId>,
    revoked: bool,
    dek_revoked: &HashSet<String>,
) -> Result<(), KeyError> {
    let generation = load_meta(session)?
        .map(|meta| meta.generation.saturating_add(1))
        .unwrap_or(1);
    let existing = find_meta_objects(session)?;
    let meta = TokenMeta {
        generation,
        current: current.as_str().to_string(),
        previous: previous.map(|id| id.as_str().to_string()),
        revoked,
        dek_revoked: dek_revoked.iter().cloned().collect(),
    };
    let value = serde_json::to_vec(&meta).map_err(|_| KeyError::WrapFailed)?;
    let created = session
        .create_object(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(META_LABEL.to_vec()),
            Attribute::Value(value),
        ])
        .map_err(|_| KeyError::WrapFailed)?;
    for handle in existing {
        if handle != created {
            let _ = session.destroy_object(handle);
        }
    }
    Ok(())
}

fn restore_or_mint(session: &Session) -> Result<Restored, KeyError> {
    match load_meta(session)? {
        Some(meta) if meta.revoked => Err(KeyError::Revoked),
        Some(meta) => {
            let current = find_kek(session, &KeyId::new(meta.current)?)?;
            let previous = match meta.previous {
                Some(id) => Some(find_kek(session, &KeyId::new(id)?)?),
                None => None,
            };
            Ok(Restored {
                current,
                previous,
                revoked: false,
                dek_revoked: meta.dek_revoked.into_iter().collect(),
            })
        }
        None => {
            let current = generate_kek(session)?;
            persist_meta(session, &current.id, None, false, &HashSet::new())?;
            Ok(Restored {
                current,
                previous: None,
                revoked: false,
                dek_revoked: HashSet::new(),
            })
        }
    }
}

fn generate_kek(session: &Session) -> Result<KekRef, KeyError> {
    let id = random_key_id("kek")?;
    let handle = session
        .generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::ValueLen(AES_KEY_LEN.into()),
                Attribute::Label(id.as_str().as_bytes().to_vec()),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
            ],
        )
        .map_err(|_| KeyError::WrapFailed)?;
    Ok(KekRef { id, handle })
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

fn random_dek_id() -> Result<KeyId, KeyError> {
    random_key_id("dek")
}

fn random_nonce() -> Result<[u8; NONCE_LEN], KeyError> {
    random_bytes::<NONCE_LEN>()
}

fn random_bytes<const N: usize>() -> Result<[u8; N], KeyError> {
    let mut bytes = [0_u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| KeyError::WrapFailed)?;
    Ok(bytes)
}

pub(crate) fn load_pkcs11(module: &Path) -> Result<Pkcs11, KeyError> {
    static LIBRARY: OnceLock<Mutex<HashMap<PathBuf, Pkcs11>>> = OnceLock::new();
    let key = std::fs::canonicalize(module).unwrap_or_else(|_| module.to_path_buf());
    let mut guard = LIBRARY
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| KeyError::WrapFailed)?;
    if let Some(existing) = guard.get(&key) {
        return Ok(existing.clone());
    }
    let pkcs11 = Pkcs11::new(&key).map_err(|_| KeyError::WrapFailed)?;
    match pkcs11.initialize(CInitializeArgs::OsThreads) {
        Ok(()) | Err(cryptoki::error::Error::AlreadyInitialized) => {}
        Err(_) => return Err(KeyError::WrapFailed),
    }
    guard.insert(key, pkcs11.clone());
    Ok(pkcs11)
}

pub(crate) fn slot_with_label(pkcs11: &Pkcs11, token_label: &str) -> Result<Slot, KeyError> {
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|_| KeyError::WrapFailed)?;
    for slot in slots {
        let info = pkcs11
            .get_token_info(slot)
            .map_err(|_| KeyError::WrapFailed)?;
        if info.label() == token_label {
            return Ok(slot);
        }
    }
    Err(KeyError::UnknownKey)
}

/// Locate a PKCS#11 software-token module for tests and CI.
pub fn software_token_module() -> Option<PathBuf> {
    const CANDIDATES: &[&str] = &[
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    ];
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

#[cfg(test)]
pub(crate) const TEST_USER_PIN: &str = "1234";
#[cfg(test)]
const TEST_SO_PIN: &str = "1234";

#[cfg(test)]
fn softhsm_conf() -> &'static PathBuf {
    static CONF: OnceLock<PathBuf> = OnceLock::new();
    CONF.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("tenkai-softhsm-{}", std::process::id()));
        let tokens = root.join("tokens");
        std::fs::create_dir_all(&tokens).expect("token dir");
        let conf = root.join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )
        .expect("conf");
        // SoftHSM reads this at C_Initialize. Set it before any PKCS#11 load.
        // SAFETY: tests own this process environment and set the path once.
        unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
        conf
    })
}

#[cfg(test)]
struct SoftwareTokenPool {
    module: PathBuf,
    labels: Vec<String>,
    next: usize,
}

#[cfg(test)]
pub(crate) fn next_software_token() -> Option<(PathBuf, String)> {
    use std::process::Command;
    static POOL: OnceLock<Mutex<SoftwareTokenPool>> = OnceLock::new();
    let mut pool = POOL
        .get_or_init(|| {
            let module = software_token_module().unwrap_or_else(|| {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "PKCS#11 software token required in CI"
                );
                PathBuf::new()
            });
            let mut labels = Vec::new();
            if !module.as_os_str().is_empty() {
                let _ = softhsm_conf();
                for _ in 0..4 {
                    let label = uuid::Uuid::new_v4().simple().to_string();
                    let status = Command::new("softhsm2-util")
                        .args([
                            "--init-token",
                            "--free",
                            "--label",
                            &label,
                            "--pin",
                            TEST_USER_PIN,
                            "--so-pin",
                            TEST_SO_PIN,
                        ])
                        .status()
                        .expect("softhsm2-util");
                    assert!(status.success(), "softhsm2-util failed: {status}");
                    labels.push(label);
                }
            }
            Mutex::new(SoftwareTokenPool {
                module,
                labels,
                next: 0,
            })
        })
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if pool.module.as_os_str().is_empty() {
        return None;
    }
    let label = pool.labels.get(pool.next)?.clone();
    pool.next += 1;
    Some((pool.module.clone(), label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Option<Pkcs11KeyProvider> {
        let (module, label) = next_software_token()?;
        Some(
            Pkcs11KeyProvider::open(&module, &label, TEST_USER_PIN, RuntimeProfile::Production)
                .expect("open pkcs11 provider"),
        )
    }

    #[test]
    fn pkcs11_software_token_covers_wrap_unwrap_rotate_describe_and_revoke() {
        let Some(provider) = provider() else {
            return;
        };
        let described = provider.describe();
        assert_eq!(described.kind, ProviderKind::Pkcs11);
        assert_eq!(described.algorithm, ALGORITHM);
        assert!(!described.kek_id.as_str().is_empty());

        let dek = Dek::generate();
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let wrapped = provider
            .wrap(&tenant, KeyPurpose::Store, &dek)
            .expect("wrap");
        let described = format!("{:?}", provider.describe());
        let debug = format!("{provider:?}");
        let hint: String = dek
            .as_bytes()
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!described.contains(&hint), "describe leaked DEK bytes");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&hint), "debug leaked DEK bytes");
        drop(wrapped);

        sekai_keys::conformance::assert_provider_contract(&provider);
    }
}

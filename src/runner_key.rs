//! Non-exportable runner keys (#785).
//!
//! The runtime agent generates its ECDSA P-256 runner key either as a file in
//! the certificate directory or in a hardware key store. Hardware keys are
//! PKCS#11 objects with `CKA_EXTRACTABLE=false`: on Linux that is TPM 2.0
//! through a PKCS#11 module (`tpm2-pkcs11`); CI uses a software PKCS#11
//! token as the software TPM. The agent never writes a hardware private key
//! to disk, and [`RunnerKey::export_private`] cannot read it out of the
//! store.
//!
//! `TENKAI_RUNTIME_KEY_STORE=file` (default) keeps the #674 file key, so
//! hosts without a hardware store keep working when the hardware-key policy
//! is off.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use rcgen::PublicKeyData as _;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::secret_source;

/// File name of a file runner key in the certificate directory.
pub const RUNNER_KEY: &str = "key.pem";
/// Locator for a hardware runner key; never contains key material or the PIN.
pub const RUNNER_KEY_STORE: &str = "key.store";
pub const STORE_SCHEMA: &str = "tenkai.runner-key.v1";
pub const KEY_STORE_ENV: &str = "TENKAI_RUNTIME_KEY_STORE";
pub const MODULE_ENV: &str = "TENKAI_RUNTIME_PKCS11_MODULE";
pub const TOKEN_ENV: &str = "TENKAI_RUNTIME_PKCS11_TOKEN";
pub const PIN_ENV: &str = "TENKAI_RUNTIME_PKCS11_PIN";
pub const KEY_LABEL_ENV: &str = "TENKAI_RUNTIME_PKCS11_KEY_LABEL";
pub const DEFAULT_KEY_LABEL: &str = "tenkai-runner";

/// DER OID of `prime256v1` (secp256r1) for `CKA_EC_PARAMS`.
const PRIME256V1_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// How the agent generates a missing runner key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreKind {
    File,
    Hardware,
}

/// PKCS#11 token that holds a non-exportable runner key.
#[derive(Clone)]
pub struct HardwareStore {
    pub module: PathBuf,
    pub token_label: String,
    pub pin: String,
    pub key_label: String,
}

impl fmt::Debug for HardwareStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardwareStore")
            .field("module", &self.module)
            .field("token_label", &self.token_label)
            .field("key_label", &self.key_label)
            .field("pin", &"<redacted>")
            .finish()
    }
}

impl HardwareStore {
    /// The hardware store named by the process environment, when
    /// `TENKAI_RUNTIME_KEY_STORE=hardware`.
    pub fn from_env() -> Result<Option<Self>> {
        match kind_from_env()? {
            KeyStoreKind::File => Ok(None),
            KeyStoreKind::Hardware => Ok(Some(Self {
                module: module_from_env()?,
                token_label: secret_source::require(TOKEN_ENV)?,
                pin: secret_source::require(PIN_ENV)?,
                key_label: secret_source::read(KEY_LABEL_ENV)?
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| DEFAULT_KEY_LABEL.into()),
            })),
        }
    }

    fn from_locator(locator: &StoreFile) -> Result<Self> {
        Ok(Self {
            module: PathBuf::from(&locator.module),
            token_label: locator.token_label.clone(),
            pin: secret_source::require(PIN_ENV)?,
            key_label: locator.key_label.clone(),
        })
    }
}

fn kind_from_env() -> Result<KeyStoreKind> {
    match std::env::var(KEY_STORE_ENV) {
        Err(_) => Ok(KeyStoreKind::File),
        Ok(value) => match value.as_str() {
            "file" => Ok(KeyStoreKind::File),
            "hardware" => Ok(KeyStoreKind::Hardware),
            other => bail!("{KEY_STORE_ENV} must be file or hardware, not {other:?}"),
        },
    }
}

fn module_from_env() -> Result<PathBuf> {
    if let Some(path) = secret_source::read(MODULE_ENV)? {
        return Ok(PathBuf::from(path));
    }
    const CANDIDATES: &[&str] = &[
        "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
        "/usr/lib/aarch64-linux-gnu/libtpm2_pkcs11.so.1",
        "/usr/lib/libtpm2_pkcs11.so.1",
        "/usr/lib/libtpm2_pkcs11.so",
    ];
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .with_context(|| {
            format!(
                "{MODULE_ENV} is required for a hardware runner key \
                 (TPM 2.0 PKCS#11 module, for example tpm2-pkcs11)"
            )
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    schema: String,
    kind: String,
    module: String,
    token_label: String,
    key_label: String,
}

/// Client authentication for a runner certificate.
pub enum ClientAuth {
    /// File key: PEM leaf, CA and PKCS#8.
    Pem(reqwest::Identity),
    /// Hardware key: rustls signs with the token; the private key never
    /// leaves it.
    Rustls(std::sync::Arc<dyn rustls::client::ResolvesClientCert>),
}

/// The agent's runner key: a file or a hardware-backed PKCS#11 object.
#[derive(Clone)]
pub enum RunnerKey {
    File { pem: String },
    Hardware(Arc<HardwareRunnerKey>),
}

impl RunnerKey {
    /// The key already in `dir`, if any. A hardware locator needs
    /// [`PIN_ENV`].
    pub fn open(dir: &Path) -> Result<Option<Self>> {
        let store = dir.join(RUNNER_KEY_STORE);
        let file = dir.join(RUNNER_KEY);
        match (store.exists(), file.exists()) {
            (true, true) => bail!(
                "{} has both a file runner key and a hardware locator",
                dir.display()
            ),
            (true, false) => {
                let locator: StoreFile = serde_json::from_str(
                    &std::fs::read_to_string(&store)
                        .with_context(|| format!("reading {}", store.display()))?,
                )
                .with_context(|| format!("parsing {}", store.display()))?;
                if locator.schema != STORE_SCHEMA || locator.kind != "pkcs11" {
                    bail!("unsupported runner key store {}", locator.schema);
                }
                Ok(Some(Self::Hardware(Arc::new(HardwareRunnerKey::open(
                    &HardwareStore::from_locator(&locator)?,
                )?))))
            }
            (false, true) => {
                let pem = std::fs::read_to_string(&file)
                    .with_context(|| format!("reading {}", file.display()))?;
                rcgen::KeyPair::from_pem(&pem).context("reading the runner key")?;
                Ok(Some(Self::File { pem }))
            }
            (false, false) => Ok(None),
        }
    }

    /// The key in `dir`, generating one according to `hardware` when missing.
    pub fn open_or_generate_with(dir: &Path, hardware: Option<&HardwareStore>) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        if let Some(existing) = Self::open(dir)? {
            match (&existing, hardware) {
                (Self::File { .. }, Some(_)) => {
                    bail!(
                        "{} already has a file runner key; a hardware key store cannot replace it",
                        dir.display()
                    )
                }
                (Self::Hardware(_), None) => {}
                _ => {}
            }
            return Ok(existing);
        }
        match hardware {
            None => {
                let key = rcgen::KeyPair::generate()?;
                let pem = key.serialize_pem();
                write_owner_only(&dir.join(RUNNER_KEY), &pem)?;
                Ok(Self::File { pem })
            }
            Some(store) => {
                let hardware = HardwareRunnerKey::provision(store)?;
                let locator = StoreFile {
                    schema: STORE_SCHEMA.into(),
                    kind: "pkcs11".into(),
                    module: store.module.display().to_string(),
                    token_label: store.token_label.clone(),
                    key_label: store.key_label.clone(),
                };
                write_owner_only(
                    &dir.join(RUNNER_KEY_STORE),
                    &serde_json::to_string_pretty(&locator)?,
                )?;
                Ok(Self::Hardware(Arc::new(hardware)))
            }
        }
    }

    /// [`Self::open_or_generate_with`] using [`HardwareStore::from_env`].
    pub fn open_or_generate(dir: &Path) -> Result<Self> {
        let hardware = HardwareStore::from_env()?;
        Self::open_or_generate_with(dir, hardware.as_ref())
    }

    pub fn hardware_backed(&self) -> bool {
        matches!(self, Self::Hardware(_))
    }

    /// A CSR over this key. The private key never appears in the request.
    pub fn csr(&self) -> Result<String> {
        let params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        match self {
            Self::File { pem } => {
                let key = rcgen::KeyPair::from_pem(pem).context("reading the runner key")?;
                Ok(params.serialize_request(&key)?.pem()?)
            }
            Self::Hardware(key) => Ok(params.serialize_request(key.as_ref())?.pem()?),
        }
    }

    /// Host evidence signed with this key for `csr`.
    pub fn sign_attestation(
        &self,
        environment: &str,
        checks: Vec<crate::host_preflight::CheckResult>,
        facts: std::collections::BTreeMap<String, String>,
        csr: &str,
        now_ms: i64,
    ) -> Result<crate::runner_attestation::RunnerAttestation> {
        match self {
            Self::File { pem } => crate::runner_attestation::sign_with(
                environment,
                checks,
                facts,
                csr,
                now_ms,
                false,
                |message| sign_pem(pem, message),
            ),
            Self::Hardware(key) => crate::runner_attestation::sign_with(
                environment,
                checks,
                facts,
                csr,
                now_ms,
                true,
                |message| key.sign_ecdsa(message),
            ),
        }
    }

    /// Client identity for `dir`'s certificate, when one has been issued.
    pub fn tls_identity(&self, dir: &Path) -> Result<Option<(ClientAuth, i64)>> {
        let cert_path = dir.join("cert.pem");
        let certificate = match std::fs::read(&cert_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", cert_path.display()));
            }
        };
        let (_, pem) = x509_parser::pem::parse_x509_pem(&certificate)
            .map_err(|error| anyhow::anyhow!("reading the runner certificate: {error}"))?;
        let not_after = pem
            .parse_x509()
            .map_err(|error| anyhow::anyhow!("reading the runner certificate: {error}"))?
            .validity()
            .not_after
            .timestamp();
        let mut chain = certificate;
        if let Ok(ca) = std::fs::read(dir.join("ca.pem")) {
            chain.extend_from_slice(b"\n");
            chain.extend_from_slice(&ca);
        }
        match self {
            Self::File { pem } => {
                chain.extend_from_slice(b"\n");
                chain.extend_from_slice(pem.as_bytes());
                let identity = reqwest::Identity::from_pem(&chain)
                    .context("loading the runner certificate")?;
                Ok(Some((ClientAuth::Pem(identity), not_after)))
            }
            Self::Hardware(key) => {
                use rustls::pki_types::CertificateDer;
                use rustls::pki_types::pem::PemObject as _;
                let certs = CertificateDer::pem_slice_iter(&chain)
                    .collect::<Result<Vec<_>, _>>()
                    .context("reading the runner certificate")?;
                anyhow::ensure!(!certs.is_empty(), "the runner certificate is empty");
                let certified = rustls::sign::CertifiedKey::new(
                    certs,
                    Arc::new(RustlsKey(key.clone())) as Arc<dyn rustls::sign::SigningKey>,
                );
                let resolver = Arc::new(rustls::sign::SingleCertAndKey::from(certified));
                Ok(Some((ClientAuth::Rustls(resolver), not_after)))
            }
        }
    }

    /// The PKCS#8 PEM of a file key. A hardware key cannot be read out.
    pub fn export_private(&self) -> Result<String> {
        match self {
            Self::File { pem } => Ok(pem.clone()),
            Self::Hardware(key) => key.refuse_export(),
        }
    }
}

fn sign_pem(pem: &str, message: &[u8]) -> Result<Vec<u8>> {
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
    let key = rcgen::KeyPair::from_pem(pem).context("reading the runner key")?;
    let rng = SystemRandom::new();
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng)
            .map_err(|error| anyhow::anyhow!("the runner key is not ECDSA P-256: {error}"))?;
    let signature = signer
        .sign(&rng, message)
        .map_err(|_| anyhow::anyhow!("signing with the runner key failed"))?;
    Ok(signature.as_ref().to_vec())
}

enum Command {
    Sign {
        message: Vec<u8>,
        reply: std::sync::mpsc::Sender<Result<Vec<u8>, String>>,
    },
    Export {
        reply: std::sync::mpsc::Sender<Result<Vec<u8>, String>>,
    },
}

/// PKCS#11-backed ECDSA P-256 runner key. The private object is not extractable.
/// A dedicated thread owns the PKCS#11 session (`Session` is neither Send nor
/// Sync); this type is Send+Sync so rustls can sign from its I/O threads.
pub struct HardwareRunnerKey {
    commands: Mutex<std::sync::mpsc::Sender<Command>>,
    point: Vec<u8>,
    token_label: String,
    key_label: String,
}

impl fmt::Debug for HardwareRunnerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardwareRunnerKey")
            .field("token_label", &self.token_label)
            .field("key_label", &self.key_label)
            .field("extractable", &false)
            .finish()
    }
}

impl HardwareRunnerKey {
    fn open(store: &HardwareStore) -> Result<Self> {
        spawn_store(store, false)
    }

    fn provision(store: &HardwareStore) -> Result<Self> {
        spawn_store(store, true)
    }

    fn sign_ecdsa(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.call(|reply| Command::Sign {
            message: message.to_vec(),
            reply,
        })
    }

    /// The store refuses to return the private value; the agent never has it.
    fn refuse_export(&self) -> Result<String> {
        match self.call(|reply| Command::Export { reply }) {
            Ok(_) => bail!("hardware runner key was readable from the key store"),
            Err(error) => Err(error),
        }
    }

    fn call(
        &self,
        command: impl FnOnce(std::sync::mpsc::Sender<Result<Vec<u8>, String>>) -> Command,
    ) -> Result<Vec<u8>> {
        let (reply, wait) = std::sync::mpsc::channel();
        self.commands
            .lock()
            .map_err(|_| anyhow::anyhow!("hardware runner key lock was poisoned"))?
            .send(command(reply))
            .map_err(|_| anyhow::anyhow!("hardware runner key thread stopped"))?;
        wait.recv()
            .map_err(|_| anyhow::anyhow!("hardware runner key thread stopped"))?
            .map_err(|error| anyhow::anyhow!("{error}"))
    }
}

fn spawn_store(store: &HardwareStore, mint: bool) -> Result<HardwareRunnerKey> {
    let (commands, inbox) = std::sync::mpsc::channel();
    let worker_store = store.clone();
    let token_label = store.token_label.clone();
    let key_label = store.key_label.clone();
    let (ready, wait) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("tenkai-runner-key".into())
        .spawn(move || match connect(&worker_store, mint) {
            Ok((session, private, point)) => {
                let _ = ready.send(Ok(point));
                while let Ok(command) = inbox.recv() {
                    match command {
                        Command::Sign { message, reply } => {
                            let _ = reply.send(sign_on_token(&session, private, &message));
                        }
                        Command::Export { reply } => {
                            let _ = reply.send(export_on_token(&session, private));
                        }
                    }
                }
            }
            Err(error) => {
                let _ = ready.send(Err(error));
            }
        })
        .context("starting the hardware runner key thread")?;
    let point = wait
        .recv()
        .map_err(|_| anyhow::anyhow!("hardware runner key thread stopped"))??;
    Ok(HardwareRunnerKey {
        commands: Mutex::new(commands),
        point,
        token_label,
        key_label,
    })
}

fn sign_on_token(
    session: &Session,
    private: ObjectHandle,
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let hash = Sha256::digest(message);
    let raw = session
        .sign(&Mechanism::Ecdsa, private, &hash)
        .map_err(|error| format!("signing with the hardware runner key: {error}"))?;
    ecdsa_der(&raw).map_err(|error| error.to_string())
}

fn export_on_token(session: &Session, private: ObjectHandle) -> Result<Vec<u8>, String> {
    match session.get_attributes(private, &[AttributeType::Value]) {
        Ok(attributes)
            if attributes.iter().any(
                |attribute| matches!(attribute, Attribute::Value(bytes) if !bytes.is_empty()),
            ) =>
        {
            Ok(b"exported".to_vec())
        }
        Ok(_) => Err("hardware runner key cannot be exported".into()),
        Err(_) => Err("hardware runner key cannot be exported".into()),
    }
}

impl rcgen::PublicKeyData for HardwareRunnerKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for HardwareRunnerKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.sign_ecdsa(msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[derive(Debug, Clone)]
struct RustlsKey(Arc<HardwareRunnerKey>);

impl rustls::sign::SigningKey for RustlsKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn rustls::sign::Signer>)
    }

    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'static>> {
        Some(self.0.as_ref().subject_public_key_info().into())
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

impl rustls::sign::Signer for RustlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0
            .sign_ecdsa(message)
            .map_err(|error| rustls::Error::General(error.to_string()))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn connect(store: &HardwareStore, mint: bool) -> Result<(Session, ObjectHandle, Vec<u8>)> {
    let pkcs11 = crate::pkcs11_provider::load_pkcs11(&store.module)
        .map_err(|_| anyhow::anyhow!("loading PKCS#11 module {}", store.module.display()))?;
    let slot = crate::pkcs11_provider::slot_with_label(&pkcs11, &store.token_label)
        .map_err(|_| anyhow::anyhow!("PKCS#11 token {} was not found", store.token_label))?;
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|error| anyhow::anyhow!("opening PKCS#11 session: {error}"))?;
    match session.login(UserType::User, Some(&AuthPin::new(store.pin.clone()))) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {
        }
        Err(error) => bail!("PKCS#11 login failed: {error}"),
    }
    if mint {
        ensure_provisioned(&session, &store.key_label)?;
    }
    let (private, point) = restore(&session, &store.key_label)?;
    Ok((session, private, point))
}

fn find_labeled(
    session: &Session,
    class: ObjectClass,
    key_label: &str,
) -> Result<Vec<ObjectHandle>> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .map_err(|error| anyhow::anyhow!("listing PKCS#11 runner keys: {error}"))
}

fn restore(session: &Session, key_label: &str) -> Result<(ObjectHandle, Vec<u8>)> {
    match find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
        [] => bail!("hardware runner key {key_label} is not provisioned"),
        [private] => {
            require_not_extractable(session, *private, key_label)?;
            let id = object_id(session, *private)?;
            let public = unique_object(
                session
                    .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Id(id)])
                    .map_err(|error| {
                        anyhow::anyhow!("listing PKCS#11 runner public keys: {error}")
                    })?,
                key_label,
            )?;
            Ok((*private, ec_point(session, public)?))
        }
        found => bail!(
            "hardware runner key {key_label} is ambiguous ({} private objects)",
            found.len()
        ),
    }
}

fn object_id(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::Id])
        .map_err(|error| anyhow::anyhow!("reading PKCS#11 runner key id: {error}"))?;
    match attributes.into_iter().next() {
        Some(Attribute::Id(id)) if !id.is_empty() => Ok(id),
        _ => bail!("PKCS#11 runner key is missing CKA_ID"),
    }
}

fn unique_object(found: Vec<ObjectHandle>, key_label: &str) -> Result<ObjectHandle> {
    match found.as_slice() {
        [handle] => Ok(*handle),
        found => bail!(
            "hardware runner key {key_label} public object is ambiguous ({} objects)",
            found.len()
        ),
    }
}

fn ec_point(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|error| anyhow::anyhow!("reading PKCS#11 runner public key: {error}"))?;
    let Some(Attribute::EcPoint(point)) = attributes.into_iter().next() else {
        bail!("PKCS#11 runner public key is missing CKA_EC_POINT");
    };
    parse_p256_point(&point)
}

fn parse_p256_point(point: &[u8]) -> Result<Vec<u8>> {
    let raw = match point {
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
        raw if raw.len() == 65 => raw,
        other => bail!(
            "PKCS#11 runner public key has unexpected CKA_EC_POINT length {}",
            other.len()
        ),
    };
    anyhow::ensure!(
        raw[0] == 0x04,
        "PKCS#11 runner public key is not an uncompressed P-256 point"
    );
    Ok(raw.to_vec())
}

fn require_not_extractable(session: &Session, handle: ObjectHandle, key_label: &str) -> Result<()> {
    let attributes = session
        .get_attributes(
            handle,
            &[
                AttributeType::Extractable,
                AttributeType::Sensitive,
                AttributeType::Sign,
            ],
        )
        .map_err(|error| {
            anyhow::anyhow!("reading PKCS#11 runner key {key_label} protection attributes: {error}")
        })?;
    let mut extractable = None;
    let mut sensitive = None;
    let mut sign = None;
    for attribute in attributes {
        match attribute {
            Attribute::Extractable(value) => extractable = Some(value),
            Attribute::Sensitive(value) => sensitive = Some(value),
            Attribute::Sign(value) => sign = Some(value),
            _ => {}
        }
    }
    if extractable != Some(false) {
        bail!("hardware runner key {key_label} is extractable");
    }
    if sensitive != Some(true) {
        bail!("hardware runner key {key_label} is not sensitive");
    }
    if sign != Some(true) {
        bail!("hardware runner key {key_label} cannot sign");
    }
    Ok(())
}

fn ensure_provisioned(session: &Session, key_label: &str) -> Result<()> {
    match find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?.as_slice() {
        [] => {
            mint_p256(session, key_label)?;
            Ok(())
        }
        [_] => Ok(()),
        found => bail!(
            "hardware runner key {key_label} is ambiguous ({} private objects)",
            found.len()
        ),
    }
}

fn mint_p256(session: &Session, key_label: &str) -> Result<()> {
    let label = key_label.as_bytes().to_vec();
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| anyhow::anyhow!("generating PKCS#11 runner key id"))?;
    let id = id.to_vec();
    session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Label(label.clone()),
                Attribute::Id(id.clone()),
                Attribute::Token(true),
                Attribute::Verify(true),
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
                Attribute::Sign(true),
            ],
        )
        .map_err(|error| anyhow::anyhow!("generating a hardware runner key: {error}"))?;
    let privates = find_labeled(session, ObjectClass::PRIVATE_KEY, key_label)?;
    if privates.len() != 1 {
        bail!(
            "hardware runner key {key_label} became ambiguous during mint ({} private objects)",
            privates.len()
        );
    }
    Ok(())
}

/// ASN.1 DER ECDSA signature from PKCS#11 `CKM_ECDSA` `r||s`.
fn ecdsa_der(raw: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(raw.len() == 64, "ECDSA P-256 signature must be 64 bytes");
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

fn write_owner_only(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&temporary, path));
    let _ = std::fs::remove_file(&temporary);
    written.with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-runner-key-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_file_key_stays_on_the_host_and_exports() {
        let dir = temp_dir();
        let key = RunnerKey::open_or_generate_with(&dir, None).unwrap();
        assert!(!key.hardware_backed());
        let csr = key.csr().unwrap();
        assert!(csr.contains("CERTIFICATE REQUEST") && !csr.contains("PRIVATE KEY"));
        assert!(key.export_private().unwrap().contains("PRIVATE KEY"));
        let again = RunnerKey::open_or_generate_with(&dir, None).unwrap();
        assert_eq!(
            again.export_private().unwrap(),
            key.export_private().unwrap()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_hardware_key_cannot_be_read_out_of_the_store() {
        let Some((module, token_label)) = crate::pkcs11_provider::next_software_token() else {
            return;
        };
        let dir = temp_dir();
        let store = HardwareStore {
            module,
            token_label,
            pin: crate::pkcs11_provider::TEST_USER_PIN.into(),
            key_label: format!("runner-{}", uuid::Uuid::new_v4().simple()),
        };
        let key = RunnerKey::open_or_generate_with(&dir, Some(&store)).unwrap();
        assert!(key.hardware_backed());
        assert!(!dir.join(RUNNER_KEY).exists());
        assert!(dir.join(RUNNER_KEY_STORE).exists());
        let error = key.export_private().unwrap_err().to_string();
        assert!(error.contains("cannot be exported"), "{error}");
        let csr = key.csr().unwrap();
        assert!(csr.contains("CERTIFICATE REQUEST") && !csr.contains("PRIVATE KEY"));
        let attestation = key
            .sign_attestation(
                "prod",
                Vec::new(),
                Default::default(),
                &csr,
                1_800_000_000_000,
            )
            .unwrap();
        assert!(attestation.statement.hardware_backed);
        crate::runner_attestation::verify(
            Some(&attestation),
            &csr,
            "prod",
            &Default::default(),
            &crate::runner_attestation::RunnerAttestationPolicy {
                require_runner_attestation: true,
                require_hardware_backed_key: true,
                max_age_ms: 600_000,
            },
            1_800_000_000_000,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}

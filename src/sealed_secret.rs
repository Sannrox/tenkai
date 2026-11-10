//! Sealed secret values set from the client and planned like overlays
//! (ADR 0045 §1–§3).
//!
//! The client seals a value under a random AES-256-GCM data key and wraps
//! that key with HPKE (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM)
//! for each pinned runtime recipient. The server stores only the ciphertext
//! and the wraps, on the environment object under `sealed.<instance>`, and
//! never a value or data key. Associated data binds every value to its
//! environment, instance, secret, key and format version.
//!
//! The ciphertext digest joins the instance's configuration digest
//! ([`config_digest`]), so a rotation plans the same-version Restart an
//! overlay change does, and every step for the instance names its sealed
//! values ([`step_bindings`]). Wraps are outside both, so re-wrapping
//! changes nothing. Servers that predate this module ignore the property
//! and never plan it.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::validate_identifier;
use crate::pb::sekai::Object;
use crate::plan::SealedStep;
use crate::sealing_key::SealingPublicKey;

/// Version of the sealed format and of its associated data.
pub const SEALED_FORMAT_VERSION: u32 = 1;
/// HPKE `info` of every wrap.
const WRAP_INFO: &[u8] = b"tenkai.sealed-secret.v1";
/// Largest value accepted. A Kubernetes Secret holds at most 1 MiB in all.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Most wraps one value may carry; a value with more opens for no one.
pub(crate) const MAX_WRAPS: usize = 64;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const PROPERTY_PREFIX: &str = "sealed.";
/// Environment property with the offline recovery public key (ADR 0045 §7).
/// It does not start with [`PROPERTY_PREFIX`], so instance scans skip it.
const RECOVERY_KEY_PROPERTY: &str = "sealed_recovery_key";

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm256;

/// `<secret>/<key>`: one key of a secret the release reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretRef {
    pub secret: String,
    pub key: String,
}

impl SecretRef {
    pub fn new(secret: &str, key: &str) -> Result<Self> {
        validate_identifier("secret name", secret)?;
        if key.is_empty()
            || key.len() > 253
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            bail!("secret key must be 1..=253 letters, digits, '.', '_' or '-'");
        }
        Ok(Self {
            secret: secret.into(),
            key: key.into(),
        })
    }

    /// Parse `<secret>/<key>`.
    pub fn parse(value: &str) -> Result<Self> {
        let (secret, key) = value
            .split_once('/')
            .with_context(|| format!("expected <secret>/<key>, got {value:?}"))?;
        Self::new(secret, key)
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.secret, self.key)
    }
}

/// Where a sealed value may be written. Its associated data binds the
/// ciphertext and every wrap to exactly this target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTarget {
    pub environment: String,
    pub instance: String,
    pub secret: SecretRef,
}

impl SealedTarget {
    pub fn new(environment: &str, instance: &str, secret: SecretRef) -> Result<Self> {
        validate_identifier("environment", environment)?;
        validate_identifier("instance", instance)?;
        Ok(Self {
            environment: environment.into(),
            instance: instance.into(),
            secret,
        })
    }

    /// The environment's identity issuer key of `generation` (ADR 0046 §2).
    /// Its instance is empty, which no instance name is, so the issuer key
    /// can never pass for an instance's sealed value or the reverse.
    pub fn identity_issuer(environment: &str, generation: u64) -> Result<Self> {
        validate_identifier("environment", environment)?;
        Ok(Self {
            environment: environment.into(),
            instance: String::new(),
            secret: SecretRef {
                secret: crate::identity_issuer::WRAP_SECRET.into(),
                key: format!("generation-{generation}"),
            },
        })
    }

    /// Associated data: format version, environment, instance, secret, key.
    pub fn associated_data(&self) -> Vec<u8> {
        let mut data = format!("tenkai.sealed-secret.v{SEALED_FORMAT_VERSION}").into_bytes();
        for field in [
            &self.environment,
            &self.instance,
            &self.secret.secret,
            &self.secret.key,
        ] {
            data.push(0);
            data.extend_from_slice(field.as_bytes());
        }
        data
    }
}

/// A sealed value as the client submits it and the server stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedValue {
    pub format_version: u32,
    /// Standard base64 of the 12-byte nonce followed by the AES-256-GCM
    /// ciphertext and tag of the value under the data key.
    pub ciphertext: String,
    /// One HPKE wrap of the data key per recipient.
    pub wraps: Vec<SealedWrap>,
}

/// The data key wrapped for one recipient key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedWrap {
    /// `sha256:<hex>` fingerprint of the recipient's sealing key.
    pub fingerprint: String,
    /// Standard base64 HPKE encapsulated key.
    pub encapsulated_key: String,
    /// Standard base64 HPKE ciphertext of the data key.
    pub wrapped_key: String,
}

/// Seal `value` for `target` to every key in `recipients`. The caller has
/// already checked the recipients against its pins.
pub fn seal(
    target: &SealedTarget,
    value: &[u8],
    recipients: &[SealingPublicKey],
) -> Result<SealedValue> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use ring::rand::SecureRandom as _;

    if value.is_empty() || value.len() > MAX_VALUE_BYTES {
        bail!("a sealed value must be 1..={MAX_VALUE_BYTES} bytes");
    }
    if recipients.is_empty() {
        bail!("{} has no recipient keys to seal to", target.environment);
    }
    let random = ring::rand::SystemRandom::new();
    let mut data_key = zeroize::Zeroizing::new([0_u8; 32]);
    let mut nonce = [0_u8; NONCE_BYTES];
    random
        .fill(data_key.as_mut())
        .and_then(|()| random.fill(&mut nonce))
        .map_err(|_| anyhow::anyhow!("the system random source failed"))?;
    let aad = target.associated_data();
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, data_key.as_ref())
            .map_err(|_| anyhow::anyhow!("creating the data key"))?,
    );
    let mut sealed = value.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut sealed,
    )
    .map_err(|_| anyhow::anyhow!("sealing the value"))?;
    let mut ciphertext = nonce.to_vec();
    ciphertext.extend_from_slice(&sealed);

    let wraps = recipients
        .iter()
        .map(|recipient| wrap_data_key(data_key.as_ref(), &aad, recipient))
        .collect::<Result<Vec<_>>>()?;
    Ok(SealedValue {
        format_version: SEALED_FORMAT_VERSION,
        ciphertext: STANDARD.encode(ciphertext),
        wraps,
    })
}

/// Wrap `data_key` for `recipient` under the value's associated data.
fn wrap_data_key(data_key: &[u8], aad: &[u8], recipient: &SealingPublicKey) -> Result<SealedWrap> {
    use hpke::{Deserializable as _, Serializable as _};
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
    let public = <Kem as hpke::Kem>::PublicKey::from_bytes(&recipient.point)
        .map_err(|_| anyhow::anyhow!("recipient {} is not a P-256 key", recipient.fingerprint()))?;
    let (encapsulated, wrapped) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &hpke::OpModeS::Base,
        &public,
        WRAP_INFO,
        data_key,
        aad,
        &mut rng,
    )
    .map_err(|error| anyhow::anyhow!("wrapping the data key: {error}"))?;
    Ok(SealedWrap {
        fingerprint: recipient.fingerprint(),
        encapsulated_key: STANDARD.encode(encapsulated.to_bytes()),
        wrapped_key: STANDARD.encode(wrapped),
    })
}

/// The private half of this runtime's file sealing key. It opens values
/// wrapped for its fingerprint (ADR 0045 §4). Errors never carry a value.
pub struct SealedOpener {
    private: OpenerKey,
    fingerprint: String,
}

/// Where the sealing key's private half is.
enum OpenerKey {
    File(<Kem as hpke::Kem>::PrivateKey),
    /// In a PKCS#11 token: only the ECDH runs there ([`hpke_receiver`]).
    Token {
        key: crate::runner_key::HardwareRunnerKey,
        point: Vec<u8>,
    },
}

impl SealedOpener {
    /// Load the sealing key [`crate::sealing_key::SealingKey::open_or_generate`]
    /// keeps for `dir`: the file key there, or the hardware key in the token
    /// its runner key store names. A token key that cannot derive is
    /// refused with a named reason.
    pub fn load(dir: &std::path::Path) -> Result<Self> {
        let path = dir.join(crate::sealing_key::SEALING_KEY);
        if !path.is_file() {
            let Some(store) = crate::runner_key::HardwareStore::from_dir(dir)? else {
                bail!(
                    "no sealing key at {} and no hardware key store; sealed steps are refused",
                    path.display()
                );
            };
            let key = store
                .open_sealing_key()
                .context("opening the hardware sealing key; sealed steps are refused")?;
            return Self::from_hardware(key);
        }
        Self::from_pem_file(&path)
    }

    /// An opener over a P-256 PKCS#8 PEM private key file, such as the
    /// offline recovery key `secret recover` reads (ADR 0045 §7).
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey as _;
        let pem = zeroize::Zeroizing::new(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        );
        let secret = p256::SecretKey::from_pkcs8_pem(&pem)
            .map_err(|_| anyhow::anyhow!("{} is not a P-256 PKCS#8 private key", path.display()))?;
        Self::from_private(secret.to_bytes().as_slice())
    }

    /// An opener over a sealing key in a PKCS#11 token
    /// ([`crate::runner_key::HardwareStore::open_sealing_key`]).
    pub fn from_hardware(key: crate::runner_key::HardwareRunnerKey) -> Result<Self> {
        let point = key.point().to_vec();
        let fingerprint = SealingPublicKey::from_point(point.clone())?.fingerprint();
        Ok(Self {
            private: OpenerKey::Token { key, point },
            fingerprint,
        })
    }

    fn from_private(scalar: &[u8]) -> Result<Self> {
        use hpke::{Deserializable as _, Kem as _, Serializable as _};
        let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(scalar)
            .map_err(|_| anyhow::anyhow!("the sealing key is not a P-256 scalar"))?;
        let public = Kem::sk_to_pk(&private);
        let fingerprint = SealingPublicKey::from_point(public.to_bytes().to_vec())?.fingerprint();
        Ok(Self {
            private: OpenerKey::File(private),
            fingerprint,
        })
    }

    /// `sha256:<hex>` of the public half: the wrap this opener reads.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Unwrap the data key from this opener's wrap and decrypt `sealed`
    /// under `target`'s associated data. A value sealed for another target,
    /// or without a wrap for this key, is refused.
    pub fn open(
        &self,
        target: &SealedTarget,
        sealed: &SealedValue,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        Ok(self.unwrap(target, sealed)?.1)
    }

    /// Wrap `sealed`'s data key for `recipient` too (ADR 0045 §5): only once
    /// this opener's wrap opened it and it decrypted the ciphertext, so a
    /// wrap that does not open the value is never passed on. The
    /// ciphertext, and with it the value's digest, is unchanged.
    pub fn rewrap(
        &self,
        target: &SealedTarget,
        sealed: &SealedValue,
        recipient: &SealingPublicKey,
    ) -> Result<SealedWrap> {
        let (data_key, _value) = self.unwrap(target, sealed)?;
        wrap_data_key(&data_key, &target.associated_data(), recipient)
    }

    /// The data key and the value it decrypts.
    #[allow(clippy::type_complexity)]
    fn unwrap(
        &self,
        target: &SealedTarget,
        sealed: &SealedValue,
    ) -> Result<(zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>)> {
        use hpke::{Deserializable as _, Serializable as _};
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        check_form(sealed)?;
        let wrap = sealed
            .wraps
            .iter()
            .find(|wrap| wrap.fingerprint == self.fingerprint)
            .with_context(|| {
                format!(
                    "{} has no wrap for this runtime's sealing key {}",
                    target.secret, self.fingerprint
                )
            })?;
        let aad = target.associated_data();
        let refused = || anyhow::anyhow!("{} does not open for this target", target.secret);
        let encapsulated = <Kem as hpke::Kem>::EncappedKey::from_bytes(
            &STANDARD
                .decode(&wrap.encapsulated_key)
                .map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
        let wrapped = STANDARD.decode(&wrap.wrapped_key).map_err(|_| refused())?;
        let data_key = match &self.private {
            OpenerKey::File(private) => zeroize::Zeroizing::new(
                hpke::single_shot_open::<Aead, Kdf, Kem>(
                    &hpke::OpModeR::Base,
                    private,
                    &encapsulated,
                    WRAP_INFO,
                    &wrapped,
                    &aad,
                )
                .map_err(|_| refused())?,
            ),
            OpenerKey::Token { key, point } => hpke_receiver::open(
                point,
                &encapsulated.to_bytes(),
                WRAP_INFO,
                &aad,
                &wrapped,
                |peer| key.derive(peer),
            )
            .map_err(|_| refused())?,
        };
        let mut body =
            zeroize::Zeroizing::new(STANDARD.decode(&sealed.ciphertext).map_err(|_| refused())?);
        if body.len() < NONCE_BYTES + TAG_BYTES {
            return Err(refused());
        }
        let nonce =
            Nonce::try_assume_unique_for_key(&body[..NONCE_BYTES]).map_err(|_| refused())?;
        let key =
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &data_key).map_err(|_| refused())?);
        let plain = key
            .open_within(nonce, Aad::from(&aad), &mut body[..], NONCE_BYTES..)
            .map_err(|_| refused())?;
        Ok((data_key, zeroize::Zeroizing::new(plain.to_vec())))
    }
}

/// `sha256:<hex>` over the associated data and the ciphertext, not the
/// wraps: what the configuration digest and a plan step name.
pub fn digest(target: &SealedTarget, sealed: &SealedValue) -> Result<String> {
    let ciphertext = STANDARD
        .decode(&sealed.ciphertext)
        .context("the sealed ciphertext is not standard base64")?;
    let aad = target.associated_data();
    let mut hasher = Sha256::new();
    hasher.update((aad.len() as u64).to_be_bytes());
    hasher.update(&aad);
    hasher.update(&ciphertext);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Check the form of a submitted value: format version, lengths, and
/// distinct wrap fingerprints. Opening is the runtime's job; the server
/// cannot.
pub fn check_form(sealed: &SealedValue) -> Result<()> {
    if sealed.format_version != SEALED_FORMAT_VERSION {
        bail!(
            "sealed format version {} is not supported; this server reads {SEALED_FORMAT_VERSION}",
            sealed.format_version
        );
    }
    let ciphertext = STANDARD
        .decode(&sealed.ciphertext)
        .context("the sealed ciphertext is not standard base64")?;
    if ciphertext.len() <= NONCE_BYTES + TAG_BYTES
        || ciphertext.len() > NONCE_BYTES + TAG_BYTES + MAX_VALUE_BYTES
    {
        bail!("the sealed ciphertext has an invalid length");
    }
    if sealed.wraps.is_empty() || sealed.wraps.len() > MAX_WRAPS {
        bail!("a sealed value needs 1..={MAX_WRAPS} wraps");
    }
    let mut seen = BTreeSet::new();
    for wrap in &sealed.wraps {
        check_wrap(wrap)?;
        if !seen.insert(wrap.fingerprint.clone()) {
            bail!("wrap fingerprints must be distinct and in sha256:<hex> form");
        }
    }
    Ok(())
}

/// Check one wrap's form: a `sha256:<hex>` fingerprint and base64 fields of
/// a sane length. A value with one malformed wrap opens for no one, so a
/// wrap is checked before it is stored.
pub fn check_wrap(wrap: &SealedWrap) -> Result<()> {
    let fingerprint = crate::sealing_key::normalize_fingerprint(&wrap.fingerprint)?;
    if fingerprint != wrap.fingerprint {
        bail!("wrap fingerprints must be distinct and in sha256:<hex> form");
    }
    for (field, value) in [
        ("encapsulated key", &wrap.encapsulated_key),
        ("wrapped key", &wrap.wrapped_key),
    ] {
        let bytes = STANDARD
            .decode(value)
            .with_context(|| format!("the {field} of wrap {fingerprint} is not base64"))?;
        if bytes.is_empty() || bytes.len() > 256 {
            bail!("the {field} of wrap {fingerprint} has an invalid length");
        }
    }
    Ok(())
}

/// Refuse a wrap for a key that is not one of the environment's current
/// `recipients` (fingerprints).
pub fn require_recipients(
    environment: &str,
    sealed: &SealedValue,
    recipients: &BTreeSet<String>,
) -> Result<()> {
    for wrap in &sealed.wraps {
        if !recipients.contains(&wrap.fingerprint) {
            bail!(
                "wrap {} is not a recipient key of {environment}",
                wrap.fingerprint
            );
        }
    }
    Ok(())
}

/// One stored sealed key of an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRecord {
    pub sealed: SealedValue,
    pub digest: String,
    pub set_by: String,
    pub set_at: i64,
}

/// `<secret>/<key>` → record, for one instance.
type InstanceRecords = BTreeMap<String, SealedRecord>;

fn instance_records(env_obj: &Object, instance: &str) -> Result<InstanceRecords> {
    match env_obj
        .properties
        .get(&format!("{PROPERTY_PREFIX}{instance}"))
    {
        None => Ok(BTreeMap::new()),
        Some(raw) => serde_json::from_str(raw)
            .with_context(|| format!("stored sealed secrets of {instance} are not valid")),
    }
}

fn persist_instance_records(env_obj: &mut Object, instance: &str, records: &InstanceRecords) {
    let property = format!("{PROPERTY_PREFIX}{instance}");
    if records.is_empty() {
        env_obj.properties.remove(&property);
    } else {
        env_obj.properties.insert(
            property,
            serde_json::to_string(records).expect("sealed records are JSON-serializable"),
        );
    }
}

/// What a plan step names for each sealed key of `instance`, in key order.
/// A record that does not parse refuses the plan rather than dropping it.
pub fn step_bindings(env_obj: &Object, instance: &str) -> Result<Vec<SealedStep>> {
    instance_records(env_obj, instance)?
        .into_iter()
        .map(|(name, record)| {
            let secret = SecretRef::parse(&name)?;
            Ok(SealedStep {
                secret: secret.secret,
                key: secret.key,
                digest: record.digest,
            })
        })
        .collect()
}

/// The stored values `step` names, in its order, for a runtime to open. A
/// value set, changed or deleted since the plan refuses it: the runtime must
/// write exactly what was approved.
pub fn step_values(
    env_obj: &Object,
    instance: &str,
    step: &[SealedStep],
) -> Result<Vec<(SealedStep, SealedValue)>> {
    let mut records = instance_records(env_obj, instance)?;
    step.iter()
        .map(|binding| {
            let name = format!("{}/{}", binding.secret, binding.key);
            match records.remove(&name) {
                Some(record) if record.digest == binding.digest => {
                    Ok((binding.clone(), record.sealed))
                }
                _ => bail!("sealed {instance} {name} changed since the plan was made"),
            }
        })
        .collect()
}

/// The instance's configuration digest: the overlay digest alone when it
/// has no sealed values, so environments without them keep today's digest;
/// otherwise a digest over the overlay digest and each sealed digest.
pub fn config_digest(overlay_digest: &str, sealed: &[SealedStep]) -> String {
    if sealed.is_empty() {
        return overlay_digest.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"tenkai.config-digest.v2\0");
    hasher.update(overlay_digest.as_bytes());
    for step in sealed {
        for field in [&step.secret, &step.key, &step.digest] {
            hasher.update([0]);
            hasher.update(field.as_bytes());
        }
    }
    format!("{:x}", hasher.finalize())
}

/// [`config_digest`] of `instance` from the environment object. An
/// unreadable sealed record yields a digest no applied state matches, so
/// the instance shows stale instead of current.
pub fn instance_config_digest(env_obj: &Object, overlay_digest: &str, instance: &str) -> String {
    match step_bindings(env_obj, instance) {
        Ok(sealed) => config_digest(overlay_digest, &sealed),
        Err(_) => "unreadable-sealed-secrets".into(),
    }
}

/// One sealed key as `secret list` shows it. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedSecretEntry {
    pub instance: String,
    pub secret: String,
    pub key: String,
    /// `sha256:` digest of the sealed ciphertext.
    pub digest: String,
    pub set_by: String,
    pub set_at: i64,
    /// Recipient fingerprints that can open the value.
    pub recipients: Vec<String>,
    /// The stored ciphertext and wraps, only when the caller asked for them
    /// (`secret recover` opens its wraps offline). Never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub sealed: Option<SealedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedSecretList {
    pub environment: String,
    pub secrets: Vec<SealedSecretEntry>,
    /// Fingerprint of the environment's offline recovery key (ADR 0045 §7).
    /// Absent: losing every runtime loses the environment's sealed values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub recovery_key: Option<String>,
}

/// Every sealed key of `environment`, by instance and key. `with_sealed`
/// includes each value's stored ciphertext and wraps.
pub async fn list(ctx: &mut Ctx, environment: &str, with_sealed: bool) -> Result<SealedSecretList> {
    validate_identifier("environment", environment)?;
    let env_obj = crate::environment::environment(ctx, environment).await?;
    list_from_object(&env_obj, with_sealed)
}

/// [`list`] over an environment object already read.
pub fn list_from_object(env_obj: &Object, with_sealed: bool) -> Result<SealedSecretList> {
    let mut instances: Vec<&str> = env_obj
        .properties
        .keys()
        .filter_map(|key| key.strip_prefix(PROPERTY_PREFIX))
        .collect();
    instances.sort_unstable();
    let mut secrets = Vec::new();
    for instance in instances {
        for (name, record) in instance_records(env_obj, instance)? {
            let secret = SecretRef::parse(&name)?;
            secrets.push(SealedSecretEntry {
                instance: instance.into(),
                secret: secret.secret,
                key: secret.key,
                digest: record.digest,
                set_by: record.set_by,
                set_at: record.set_at,
                recipients: record
                    .sealed
                    .wraps
                    .iter()
                    .map(|wrap| wrap.fingerprint.clone())
                    .collect(),
                sealed: with_sealed.then_some(record.sealed),
            });
        }
    }
    Ok(SealedSecretList {
        environment: env_obj.name.clone(),
        secrets,
        recovery_key: recovery_key(env_obj)?.map(|key| key.fingerprint()),
    })
}

impl SealedSecretList {
    /// Values without a wrap for the recovery key, as `instance secret/key`.
    /// Every value when no recovery key is set.
    pub fn without_recovery(&self) -> Vec<String> {
        self.secrets
            .iter()
            .filter(|entry| {
                self.recovery_key
                    .as_ref()
                    .is_none_or(|fingerprint| !entry.recipients.contains(fingerprint))
            })
            .map(|entry| format!("{} {}/{}", entry.instance, entry.secret, entry.key))
            .collect()
    }

    /// Why losing every runtime would lose sealed values (ADR 0045 §7), or
    /// `None` when every value can be recovered.
    pub fn recovery_warning(&self) -> Option<String> {
        let lost = self.without_recovery().len();
        if lost == 0 {
            return None;
        }
        Some(match &self.recovery_key {
            None => format!(
                "{} has {lost} sealed value(s) and no recovery key: losing every runtime loses them; set one with tenkaictl secret recovery-key set",
                self.environment
            ),
            Some(fingerprint) => format!(
                "{lost} sealed value(s) of {} have no wrap for the recovery key; add one with tenkaictl secret rewrap --recipient {fingerprint}",
                self.environment
            ),
        })
    }
}

/// [`recovery_key`] of `environment` by name; none when the environment
/// has no object yet.
pub async fn stored_recovery_key(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<SealingPublicKey>> {
    validate_identifier("environment", environment)?;
    match ctx.get(&crate::ontology::env_id(environment)).await? {
        Some(env_obj) => recovery_key(&env_obj),
        None => Ok(None),
    }
}

/// The environment's offline recovery public key (ADR 0045 §7), if set.
pub fn recovery_key(env_obj: &Object) -> Result<Option<SealingPublicKey>> {
    env_obj
        .properties
        .get(RECOVERY_KEY_PROPERTY)
        .map(|raw| SealingPublicKey::from_wire(raw))
        .transpose()
        .context("the stored recovery key is not a valid sealing key")
}

/// Record `key` as `environment`'s recovery key under the configuration
/// `lease` (ADR 0045 §7). A replaced key opens nothing any more: its wraps
/// are dropped from every value, as a revoked runtime's are. Values sealed
/// before the key was set carry no wrap for it until a re-wrap step for it
/// runs. Setting the same key again changes nothing.
pub(crate) async fn set_recovery_key_locked(
    ctx: &mut Ctx,
    environment: &str,
    key: &SealingPublicKey,
    lease: &crate::apply::EnvironmentLease,
) -> Result<String> {
    let mut env_obj = crate::environment::environment(ctx, environment).await?;
    let fingerprint = key.fingerprint();
    let previous = recovery_key(&env_obj)?.map(|key| key.fingerprint());
    if previous.as_deref() == Some(fingerprint.as_str()) {
        return Ok(format!(
            "{environment} recovery key is already {fingerprint}"
        ));
    }
    let mut lost = Vec::new();
    if let Some(previous) = &previous {
        lost = drop_wraps(&mut env_obj, previous)?.1;
    }
    env_obj
        .properties
        .insert(RECOVERY_KEY_PROPERTY.into(), key.to_wire());
    env_obj.updated = crate::now_millis();
    put_fenced(ctx, env_obj, lease).await?;
    let mut message = format!(
        "set {environment} recovery key {fingerprint}; values sealed before it carry no recovery wrap until `secret rewrap --recipient {fingerprint}` runs"
    );
    if let Some(previous) = previous {
        message.push_str(&format!("; dropped the wraps of {previous}"));
    }
    if !lost.is_empty() {
        message.push_str(&format!("; no recipient left for: {}", lost.join(", ")));
    }
    Ok(message)
}

/// Secret names the release subscribed for `instance` declares (#1019),
/// with that release, or `None` when the instance is not subscribed.
async fn declared_secrets(
    ctx: &mut Ctx,
    env_obj: &Object,
    instance: &str,
) -> Result<Option<(String, Vec<String>)>> {
    let Some(sub) = crate::environment::list_subscriptions(ctx, env_obj)
        .await?
        .into_iter()
        .find(|sub| {
            let name = if sub.instance.is_empty() {
                &sub.product
            } else {
                &sub.instance
            };
            name == instance
        })
    else {
        return Ok(None);
    };
    let Some(release) = sub.channel.properties.get("current_release").cloned() else {
        return Ok(Some((format!("channel of {instance}"), Vec::new())));
    };
    let declared = crate::environment::release_config_schema(ctx, &release)
        .await?
        .map(|schema| schema.secrets)
        .unwrap_or_default();
    Ok(Some((release, declared)))
}

/// Store a sealed value for `target` under the environment configuration
/// lease. The secret name must be one the instance's release declares. The
/// server checks wraps against current recipients before this
/// ([`require_recipients`]).
pub(crate) async fn set_locked(
    ctx: &mut Ctx,
    target: &SealedTarget,
    sealed: &SealedValue,
    actor: &str,
) -> Result<String> {
    check_form(sealed)?;
    let digest = digest(target, sealed)?;
    let mut env_obj = crate::environment::environment(ctx, &target.environment).await?;
    let instance = &target.instance;
    let Some((release, declared)) = declared_secrets(ctx, &env_obj, instance).await? else {
        bail!(
            "{instance} is not subscribed in {}; a sealed secret belongs to an instance",
            target.environment
        );
    };
    if !declared.contains(&target.secret.secret) {
        bail!(
            "release {release} does not declare secret {}; declare it under [config] secrets",
            target.secret.secret
        );
    }
    let mut records = instance_records(&env_obj, instance)?;
    let now = crate::now_millis();
    records.insert(
        target.secret.to_string(),
        SealedRecord {
            sealed: sealed.clone(),
            digest: digest.clone(),
            set_by: actor.into(),
            set_at: now,
        },
    );
    persist_instance_records(&mut env_obj, instance, &records);
    env_obj.updated = now;
    ctx.put(env_obj).await?;
    Ok(format!(
        "set {} sealed {instance} {} {digest}",
        target.environment, target.secret
    ))
}

/// Remove one sealed key under the environment configuration lease. A key
/// of a secret the instance's release declares is refused, naming the
/// release, unless the operator states it is present in the target by
/// other means.
pub(crate) async fn delete_locked(
    ctx: &mut Ctx,
    environment: &str,
    instance: &str,
    secret: &SecretRef,
    present_in_target: bool,
) -> Result<String> {
    let mut env_obj = crate::environment::environment(ctx, environment).await?;
    let mut records = instance_records(&env_obj, instance)?;
    if !records.contains_key(&secret.to_string()) {
        bail!("{instance} has no sealed {secret} in {environment}");
    }
    if !present_in_target
        && let Some((release, declared)) = declared_secrets(ctx, &env_obj, instance).await?
        && declared.contains(&secret.secret)
    {
        bail!(
            "release {release} reads secret {}; deleting {secret} is refused unless the key is \
             present in the target by other means (--present-in-target)",
            secret.secret
        );
    }
    records.remove(&secret.to_string());
    persist_instance_records(&mut env_obj, instance, &records);
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!("deleted {environment} sealed {instance} {secret}"))
}

/// A wrap a runtime made for an approved recipient (ADR 0045 §5), for one
/// stored value of an instance, named by its slot and sealed digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipientWrap {
    pub secret: String,
    pub key: String,
    /// The value's sealed digest when it was re-wrapped.
    pub digest: String,
    pub wrap: SealedWrap,
}

/// Add `wraps` to `instance`'s stored values. A wrap replaces one for the
/// same key. A value changed or deleted since it was re-wrapped is skipped:
/// a new value is sealed to the recipients of its time. The ciphertext and
/// digest of a value never change. Returns the slots that got a wrap.
pub(crate) fn add_wraps(
    env_obj: &mut Object,
    instance: &str,
    wraps: &[RecipientWrap],
) -> Result<Vec<String>> {
    let mut records = instance_records(env_obj, instance)?;
    let mut added = Vec::new();
    for wrap in wraps {
        let name = SecretRef::new(&wrap.secret, &wrap.key)?.to_string();
        let Some(record) = records.get_mut(&name) else {
            continue;
        };
        if record.digest != wrap.digest {
            continue;
        }
        // A value at the wrap limit would no longer open for anyone.
        let known = record
            .sealed
            .wraps
            .iter()
            .any(|existing| existing.fingerprint == wrap.wrap.fingerprint);
        if !known && record.sealed.wraps.len() >= MAX_WRAPS {
            continue;
        }
        let mut updated = record.sealed.clone();
        updated
            .wraps
            .retain(|existing| existing.fingerprint != wrap.wrap.fingerprint);
        updated.wraps.push(wrap.wrap.clone());
        check_form(&updated).with_context(|| format!("refusing a wrap for {name}"))?;
        record.sealed = updated;
        added.push(name);
    }
    persist_instance_records(env_obj, instance, &records);
    Ok(added)
}

/// Store the wraps a re-wrap plan's runtime returned, per instance, under
/// the environment lease (ADR 0045 §5). `current` yields the environment's
/// unrevoked recipients and is read inside the lease, and revocation drops
/// a key's wraps under the same lease, so a recipient revoked before this
/// commits gets no wrap, and one revoked after it has its wrap dropped.
/// Storing the same wraps again changes nothing, so a replayed completion
/// is safe. A busy lease fails, and the completion is retried.
pub async fn store_completion_wraps(
    ctx: &mut Ctx,
    environment: &str,
    wraps: &[(String, Vec<RecipientWrap>)],
    current: impl FnOnce() -> Result<BTreeSet<String>>,
) -> Result<()> {
    if wraps.iter().all(|(_, wraps)| wraps.is_empty()) {
        return Ok(());
    }
    let purpose = format!("sealed-rewrap-store:{}", crate::now_millis());
    let lease = crate::apply::claim_environment_for_completion(ctx, environment, &purpose).await?;
    let stored = async {
        let mut current = current()?;
        let mut env_obj = crate::environment::environment(ctx, environment).await?;
        // The recovery key is a recipient too (ADR 0045 §7), and it is read
        // here, inside the lease, like the runtime keys.
        current.extend(recovery_key(&env_obj)?.map(|key| key.fingerprint()));
        for (instance, wraps) in wraps {
            let kept: Vec<RecipientWrap> = wraps
                .iter()
                .filter(|wrap| current.contains(&wrap.wrap.fingerprint))
                .cloned()
                .collect();
            // The identity issuer is environment-level: its re-wrap step
            // names no instance (ADR 0046 §2).
            if instance.is_empty() {
                crate::identity_issuer::add_wraps(&mut env_obj, environment, &kept)?;
            } else {
                add_wraps(&mut env_obj, instance, &kept)?;
            }
        }
        env_obj.updated = crate::now_millis();
        put_fenced(ctx, env_obj, &lease).await?;
        anyhow::Ok(())
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (stored, unlock) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.context("releasing the environment lease")),
    }
}

/// The values of `instance` that no wrap is left on: no recipient can open
/// them, and they must be set again (ADR 0045 §5).
pub fn unopenable(env_obj: &Object, instance: &str) -> Result<Vec<String>> {
    Ok(instance_records(env_obj, instance)?
        .into_iter()
        .filter(|(_, record)| record.sealed.wraps.is_empty())
        .map(|(name, _)| name)
        .collect())
}

/// Write `env_obj` only while `lease` is still the environment's current
/// holder: a holder that stalled past its lease never overwrites a newer
/// one, so a revocation cannot be undone by a delayed write.
pub(crate) async fn put_fenced(
    ctx: &mut Ctx,
    env_obj: Object,
    lease: &crate::apply::EnvironmentLease,
) -> Result<()> {
    ctx.guarded_update(
        env_obj,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        &lease.environment,
        &lease.fencing_token,
    )
    .await?;
    Ok(())
}

/// Drop every wrap for `fingerprint` from `environment`'s stored values,
/// under the environment lease: a retired or revoked runtime's key opens
/// nothing any more (ADR 0045 §5). Returns `<instance> <secret>/<key>` of
/// the values no wrap is left on. Dropping wraps that are gone already
/// changes nothing, so this is safe to retry.
pub async fn drop_recipient(
    ctx: &mut Ctx,
    environment: &str,
    fingerprint: &str,
) -> Result<Vec<String>> {
    validate_identifier("environment", environment)?;
    // An environment the store does not register holds no sealed values.
    if ctx
        .get(&crate::ontology::env_id(environment))
        .await?
        .is_none()
    {
        return Ok(Vec::new());
    }
    let owner = format!("sealed-recipient-drop:{}", crate::now_millis());
    let lease = crate::apply::claim_environment(ctx, environment, &owner).await?;
    let dropped = async {
        let mut env_obj = crate::environment::environment(ctx, environment).await?;
        let (changed, lost) = drop_wraps(&mut env_obj, fingerprint)?;
        if changed {
            env_obj.updated = crate::now_millis();
            put_fenced(ctx, env_obj, &lease).await?;
        }
        anyhow::Ok(lost)
    }
    .await;
    let unlock = crate::apply::release_environment(ctx, &lease).await;
    match (dropped, unlock) {
        (Ok(lost), Ok(())) => Ok(lost),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing the environment lease")),
    }
}

/// Drop every wrap for `fingerprint` from `env_obj`'s stored values.
/// Returns whether any was dropped, and `<instance> <secret>/<key>` of the
/// values no wrap is left on.
fn drop_wraps(env_obj: &mut Object, fingerprint: &str) -> Result<(bool, Vec<String>)> {
    let instances: Vec<String> = env_obj
        .properties
        .keys()
        .filter_map(|key| key.strip_prefix(PROPERTY_PREFIX).map(str::to_owned))
        .collect();
    let mut changed = false;
    let mut lost = Vec::new();
    for instance in instances {
        let mut records = instance_records(env_obj, &instance)?;
        for (name, record) in &mut records {
            let before = record.sealed.wraps.len();
            record
                .sealed
                .wraps
                .retain(|wrap| wrap.fingerprint != fingerprint);
            changed |= record.sealed.wraps.len() != before;
            if record.sealed.wraps.is_empty() {
                lost.push(format!("{instance} {name}"));
            }
        }
        persist_instance_records(env_obj, &instance, &records);
    }
    let (issuer_changed, issuer_lost) = crate::identity_issuer::drop_wraps(env_obj, fingerprint)?;
    changed |= issuer_changed;
    lost.extend(issuer_lost);
    Ok((changed, lost))
}

mod hpke_receiver;

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SealedTarget {
        SealedTarget::new("prod", "api", SecretRef::parse("db/password").unwrap()).unwrap()
    }

    fn recipient() -> (<Kem as hpke::Kem>::PrivateKey, SealingPublicKey) {
        use hpke::Serializable as _;
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let (private, public) = <Kem as hpke::Kem>::gen_keypair(&mut rng);
        let public = SealingPublicKey::from_point(public.to_bytes().to_vec()).unwrap();
        (private, public)
    }

    /// A value sealed to a key in a PKCS#11 token opens with the token
    /// computing only the ECDH; one sealed for another target is refused,
    /// and neither the value nor the shared secret reaches an error. Runs
    /// against SoftHSM in CI.
    #[test]
    fn a_value_sealed_to_a_token_key_opens_through_the_token() {
        let Some((module, token_label)) = crate::pkcs11_provider::next_software_token() else {
            return;
        };
        let store = crate::runner_key::HardwareStore {
            module,
            token_label,
            pin: crate::pkcs11_provider::TEST_USER_PIN.into(),
            key_label: "runner".into(),
        };
        let point = store.open_or_generate_sealing_point().unwrap();
        let public = SealingPublicKey::from_point(point).unwrap();
        let value = b"token-held-plain-value";
        let sealed = seal(&target(), value, std::slice::from_ref(&public)).unwrap();

        let opener = SealedOpener::from_hardware(store.open_sealing_key().unwrap()).unwrap();
        assert_eq!(opener.fingerprint(), public.fingerprint());
        assert_eq!(opener.open(&target(), &sealed).unwrap().as_slice(), value);

        let other =
            SealedTarget::new("prod", "worker", SecretRef::parse("db/password").unwrap()).unwrap();
        let error = format!("{:#}", opener.open(&other, &sealed).unwrap_err());
        assert!(!error.contains("token-held-plain-value"), "{error}");
        assert!(error.contains("does not open"), "{error}");
    }

    /// Wraps reach a stored value only for its current digest, a revoked
    /// key's wraps are dropped from every value, and a value left with none
    /// is named (ADR 0045 §5).
    #[tokio::test]
    async fn recipients_are_added_and_dropped_without_touching_values() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-sealed-recipients-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "sealed")
            .await
            .unwrap();
        let (private_a, public_a) = recipient();
        let (_, public_b) = recipient();
        let target = target();
        let sealed = seal(&target, b"hunter2", std::slice::from_ref(&public_a)).unwrap();
        let digest = digest(&target, &sealed).unwrap();
        let mut env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        persist_instance_records(
            &mut env_obj,
            "api",
            &BTreeMap::from([(
                "db/password".to_string(),
                SealedRecord {
                    sealed: sealed.clone(),
                    digest: digest.clone(),
                    set_by: "operator".into(),
                    set_at: 1,
                },
            )]),
        );

        // A runtime re-wraps for B; a wrap for a changed value is skipped.
        use hpke::Serializable as _;
        let opener_a = SealedOpener::from_private(&private_a.to_bytes()).unwrap();
        let wrap_b = opener_a.rewrap(&target, &sealed, &public_b).unwrap();
        let wraps = [
            RecipientWrap {
                secret: "db".into(),
                key: "password".into(),
                digest: digest.clone(),
                wrap: wrap_b.clone(),
            },
            RecipientWrap {
                secret: "db".into(),
                key: "password".into(),
                digest: "sha256:changed".into(),
                wrap: wrap_b.clone(),
            },
        ];
        assert_eq!(
            add_wraps(&mut env_obj, "api", &wraps).unwrap(),
            ["db/password"]
        );
        ctx.put(env_obj).await.unwrap();
        let stored = |list: &SealedSecretList| {
            let [entry] = list.secrets.as_slice() else {
                panic!("one sealed key");
            };
            (entry.digest.clone(), entry.recipients.clone())
        };
        let listed = list(&mut ctx, "prod", false).await.unwrap();
        assert_eq!(
            stored(&listed),
            (
                digest.clone(),
                vec![public_a.fingerprint(), public_b.fingerprint()]
            )
        );

        // Revoking A drops its wraps; B still opens the value.
        let lost = drop_recipient(&mut ctx, "prod", &public_a.fingerprint())
            .await
            .unwrap();
        assert!(lost.is_empty(), "{lost:?}");
        assert_eq!(
            stored(&list(&mut ctx, "prod", false).await.unwrap()),
            (digest.clone(), vec![public_b.fingerprint()])
        );
        // Revoking B too leaves a value nobody can open, and names it.
        let lost = drop_recipient(&mut ctx, "prod", &public_b.fingerprint())
            .await
            .unwrap();
        assert_eq!(lost, ["api db/password"]);
        let env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        assert_eq!(unopenable(&env_obj, "api").unwrap(), ["db/password"]);
        // Dropping again changes nothing.
        assert_eq!(
            drop_recipient(&mut ctx, "prod", &public_b.fingerprint())
                .await
                .unwrap(),
            ["api db/password"]
        );
        let _ = std::fs::remove_file(database);
    }

    /// Replacing the recovery key drops the old key's wraps (ADR 0045 §7):
    /// the retired private key opens nothing the server still stores, and
    /// a value only it could open is named.
    #[tokio::test]
    async fn replacing_the_recovery_key_drops_its_wraps() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-sealed-recovery-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "sealed")
            .await
            .unwrap();
        let (_, runtime) = recipient();
        let (_, first) = recipient();
        let (_, second) = recipient();
        let target = target();
        let lease = crate::apply::claim_environment(&mut ctx, "prod", "test")
            .await
            .unwrap();
        set_recovery_key_locked(&mut ctx, "prod", &first, &lease)
            .await
            .unwrap();
        let mut env_obj = crate::environment::environment(&mut ctx, "prod")
            .await
            .unwrap();
        let record = |sealed: SealedValue| SealedRecord {
            digest: digest(&target, &sealed).unwrap(),
            sealed,
            set_by: "operator".into(),
            set_at: 1,
        };
        persist_instance_records(
            &mut env_obj,
            "api",
            &BTreeMap::from([
                (
                    "db/password".to_string(),
                    record(seal(&target, b"a", &[runtime.clone(), first.clone()]).unwrap()),
                ),
                (
                    "db/token".to_string(),
                    record(seal(&target, b"b", std::slice::from_ref(&first)).unwrap()),
                ),
            ]),
        );
        ctx.put(env_obj).await.unwrap();
        assert_eq!(
            list(&mut ctx, "prod", false)
                .await
                .unwrap()
                .recovery_warning(),
            None
        );

        let message = set_recovery_key_locked(&mut ctx, "prod", &second, &lease)
            .await
            .unwrap();
        assert!(message.contains("api db/token"), "{message}");
        let listed = list(&mut ctx, "prod", false).await.unwrap();
        assert_eq!(listed.recovery_key, Some(second.fingerprint()));
        assert!(
            listed
                .secrets
                .iter()
                .all(|entry| !entry.recipients.contains(&first.fingerprint())),
            "{listed:?}"
        );
        assert_eq!(
            listed.without_recovery(),
            ["api db/password", "api db/token"]
        );
        let _ = std::fs::remove_file(database);
    }

    /// A value at the wrap limit gets no more: one more would make it open
    /// for no one.
    #[test]
    fn a_value_at_the_wrap_limit_gets_no_more_wraps() {
        let wrap = |n: usize| SealedWrap {
            fingerprint: format!("sha256:{n:064x}"),
            encapsulated_key: "AA==".into(),
            wrapped_key: "AA==".into(),
        };
        let mut env_obj = Object {
            id: "tenkai:environment:prod".into(),
            kind: crate::ontology::KIND_ENVIRONMENT.into(),
            name: "prod".into(),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        };
        persist_instance_records(
            &mut env_obj,
            "api",
            &BTreeMap::from([(
                "db/password".to_string(),
                SealedRecord {
                    sealed: SealedValue {
                        format_version: 1,
                        ciphertext: STANDARD.encode([0_u8; 40]),
                        wraps: (0..MAX_WRAPS).map(wrap).collect(),
                    },
                    digest: "sha256:value".into(),
                    set_by: "operator".into(),
                    set_at: 1,
                },
            )]),
        );
        let one_more = |n: usize| RecipientWrap {
            secret: "db".into(),
            key: "password".into(),
            digest: "sha256:value".into(),
            wrap: wrap(n),
        };
        assert!(
            add_wraps(&mut env_obj, "api", &[one_more(MAX_WRAPS)])
                .unwrap()
                .is_empty()
        );
        // Replacing an existing recipient's wrap is still fine.
        assert_eq!(
            add_wraps(&mut env_obj, "api", &[one_more(0)]).unwrap(),
            ["db/password"]
        );
        let records = instance_records(&env_obj, "api").unwrap();
        assert_eq!(records["db/password"].sealed.wraps.len(), MAX_WRAPS);

        // A malformed wrap would make the value open for no one: refused,
        // and the stored value is unchanged.
        let mut malformed = one_more(0);
        malformed.wrap.wrapped_key = "not base64!".into();
        assert!(add_wraps(&mut env_obj, "api", &[malformed]).is_err());
        assert_eq!(instance_records(&env_obj, "api").unwrap(), records);
    }

    fn open(
        target: &SealedTarget,
        sealed: &SealedValue,
        private: &<Kem as hpke::Kem>::PrivateKey,
        _fingerprint: &str,
    ) -> Result<Vec<u8>> {
        use hpke::Serializable as _;
        let opener = SealedOpener::from_private(&private.to_bytes())?;
        Ok(opener.open(target, sealed)?.to_vec())
    }

    #[test]
    fn the_runtime_file_key_opens_what_was_sealed_to_it() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-opener-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let key = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        let opener = SealedOpener::load(&dir).unwrap();
        assert_eq!(opener.fingerprint(), key.fingerprint());
        let sealed = seal(&target(), b"s3cret", &[key.public().clone()]).unwrap();
        assert_eq!(
            opener.open(&target(), &sealed).unwrap().as_slice(),
            b"s3cret"
        );
        let other =
            SealedTarget::new("prod", "worker", SecretRef::parse("db/password").unwrap()).unwrap();
        let refused = opener.open(&other, &sealed).unwrap_err().to_string();
        assert!(!refused.contains("s3cret"), "{refused}");
        let (_, stranger) = recipient();
        let unwrapped = seal(&target(), b"s3cret", &[stranger]).unwrap();
        assert!(
            opener
                .open(&target(), &unwrapped)
                .unwrap_err()
                .to_string()
                .contains("no wrap for this runtime's sealing key")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_runtime_receives_only_the_values_the_plan_named() {
        let (_, public) = recipient();
        let sealed = seal(&target(), b"s3cret", &[public]).unwrap();
        let digest = digest(&target(), &sealed).unwrap();
        let mut env_obj = Object::default();
        let records = BTreeMap::from([(
            "db/password".to_string(),
            SealedRecord {
                sealed: sealed.clone(),
                digest: digest.clone(),
                set_by: "ops".into(),
                set_at: 0,
            },
        )]);
        persist_instance_records(&mut env_obj, "api", &records);
        let planned = step_bindings(&env_obj, "api").unwrap();
        let values = step_values(&env_obj, "api", &planned).unwrap();
        assert_eq!(values, vec![(planned[0].clone(), sealed)]);

        // A rotation after the plan was made is not what was approved.
        let mut stale = planned.clone();
        stale[0].digest = "sha256:00".into();
        let refused = step_values(&env_obj, "api", &stale)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("changed since the plan"), "{refused}");
    }

    #[test]
    fn every_recipient_opens_and_another_target_is_refused() {
        let (first_private, first) = recipient();
        let (second_private, second) = recipient();
        let target = target();
        let sealed = seal(&target, b"s3cret", &[first.clone(), second.clone()]).unwrap();
        assert_eq!(sealed.wraps.len(), 2);
        assert_eq!(
            open(&target, &sealed, &first_private, &first.fingerprint()).unwrap(),
            b"s3cret"
        );
        assert_eq!(
            open(&target, &sealed, &second_private, &second.fingerprint()).unwrap(),
            b"s3cret"
        );
        let moved =
            SealedTarget::new("prod", "billing", SecretRef::parse("db/password").unwrap()).unwrap();
        assert!(open(&moved, &sealed, &first_private, &first.fingerprint()).is_err());
    }

    #[test]
    fn digest_covers_ciphertext_and_target_but_not_wraps() {
        let (_, first) = recipient();
        let (_, second) = recipient();
        let target = target();
        let sealed = seal(&target, b"s3cret", std::slice::from_ref(&first)).unwrap();
        let expected = digest(&target, &sealed).unwrap();

        let mut rewrapped = sealed.clone();
        rewrapped
            .wraps
            .extend(seal(&target, b"x", &[second]).unwrap().wraps);
        check_form(&rewrapped).unwrap();
        assert_eq!(digest(&target, &rewrapped).unwrap(), expected);

        let rotated = seal(&target, b"s3cret", &[first]).unwrap();
        assert_ne!(digest(&target, &rotated).unwrap(), expected);
        let other_key =
            SealedTarget::new("prod", "api", SecretRef::parse("db/user").unwrap()).unwrap();
        assert_ne!(digest(&other_key, &sealed).unwrap(), expected);
    }

    #[test]
    fn unknown_recipients_and_malformed_values_are_refused() {
        let (_, first) = recipient();
        let (_, stranger) = recipient();
        let target = target();
        let known = BTreeSet::from([first.fingerprint()]);
        let sealed = seal(&target, b"s3cret", &[stranger]).unwrap();
        check_form(&sealed).unwrap();
        let error = require_recipients("prod", &sealed, &known)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a recipient key"), "{error}");

        let valid = seal(&target, b"s3cret", std::slice::from_ref(&first)).unwrap();
        require_recipients("prod", &valid, &known).unwrap();
        let mut sealed = valid.clone();
        sealed.format_version = 2;
        assert!(check_form(&sealed).is_err());
        let mut sealed = valid.clone();
        sealed.wraps.clear();
        assert!(check_form(&sealed).is_err());
        let mut sealed = valid.clone();
        sealed.wraps.push(sealed.wraps[0].clone());
        assert!(check_form(&sealed).is_err());
        let mut sealed = valid;
        sealed.ciphertext = STANDARD.encode([0_u8; 8]);
        assert!(check_form(&sealed).is_err());
        assert!(seal(&target, b"", &[first]).is_err());
    }

    async fn publish(ctx: &mut Ctx, root: &std::path::Path, product: &str, config: &str) {
        let dir = root.join(product);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                "[product]\nname = \"{product}\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\n{config}"
            ),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("sealed-secrets");
        crate::catalog::promote(ctx, &actor, &format!("{product}@1.0.0"), "stable")
            .await
            .unwrap();
        crate::plan::subscribe(ctx, "local", product, "stable")
            .await
            .unwrap();
        let mut env = crate::environment::environment(ctx, "local").await.unwrap();
        env.properties
            .insert(format!("deployed.{product}"), "1.0.0".into());
        env.properties.insert(
            format!("deployed_release.{product}"),
            format!("tenkai:release:{product}@1.0.0"),
        );
        ctx.put(env).await.unwrap();
    }

    async fn change(
        ctx: &mut Ctx,
        change: crate::environment_config::EnvironmentConfigChange,
    ) -> Result<String> {
        crate::environment_config::apply(ctx, "local", &change, "rotate db", "alice", |_| Ok(()))
            .await
    }

    fn set(sealed: &SealedValue) -> crate::environment_config::EnvironmentConfigChange {
        crate::environment_config::EnvironmentConfigChange::SetSealedSecret {
            instance: "api".into(),
            secret: "db".into(),
            key: "password".into(),
            sealed: sealed.clone(),
        }
    }

    /// Record the current configuration as applied, as a healthy apply does.
    async fn mark_applied(ctx: &mut Ctx) {
        let mut env = crate::environment::environment(ctx, "local").await.unwrap();
        for instance in ["api", "web"] {
            let digest = instance_config_digest(&env, "", instance);
            env.properties
                .insert(format!("applied_config.{instance}"), digest);
        }
        ctx.put(env).await.unwrap();
    }

    #[tokio::test]
    async fn rotation_restarts_only_the_reading_instance_and_a_rewrap_does_not() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-sealed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        publish(&mut ctx, &root, "api", "\n[config]\nsecrets = [\"db\"]\n").await;
        publish(&mut ctx, &root, "web", "").await;
        let (_, first) = recipient();
        let (_, second) = recipient();
        let target =
            SealedTarget::new("local", "api", SecretRef::parse("db/password").unwrap()).unwrap();

        let undeclared = change(
            &mut ctx,
            crate::environment_config::EnvironmentConfigChange::SetSealedSecret {
                instance: "api".into(),
                secret: "cache".into(),
                key: "password".into(),
                sealed: seal(&target, b"s3cret", std::slice::from_ref(&first)).unwrap(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            undeclared.contains("does not declare secret cache")
                && undeclared.contains("api@1.0.0"),
            "{undeclared}"
        );

        let sealed = seal(&target, b"s3cret", std::slice::from_ref(&first)).unwrap();
        change(&mut ctx, set(&sealed)).await.unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1, "{:?}", plan.steps);
        let step = &plan.steps[0];
        assert_eq!(
            (step.product.as_str(), step.action),
            ("api", crate::plan::Action::Restart)
        );
        assert_eq!(
            step.sealed,
            vec![SealedStep {
                secret: "db".into(),
                key: "password".into(),
                digest: digest(&target, &sealed).unwrap(),
            }]
        );
        mark_applied(&mut ctx).await;
        assert!(
            crate::plan::create(&mut ctx, "local")
                .await
                .unwrap()
                .steps
                .is_empty()
        );

        let mut rewrapped = sealed.clone();
        rewrapped.wraps.extend(
            seal(&target, b"other", std::slice::from_ref(&second))
                .unwrap()
                .wraps,
        );
        change(&mut ctx, set(&rewrapped)).await.unwrap();
        assert!(
            crate::plan::create(&mut ctx, "local")
                .await
                .unwrap()
                .steps
                .is_empty()
        );

        let rotated = seal(&target, b"n3w", &[first.clone(), second.clone()]).unwrap();
        change(&mut ctx, set(&rotated)).await.unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 1, "{:?}", plan.steps);
        assert_eq!(plan.steps[0].product, "api");
        assert_eq!(
            plan.steps[0].sealed[0].digest,
            digest(&target, &rotated).unwrap()
        );
        // A plan approved for one value does not apply another.
        assert_eq!(
            crate::apply::classify_candidate(&mut ctx, &plan)
                .await
                .unwrap(),
            crate::apply::CandidateAdmission::Admissible
        );
        change(
            &mut ctx,
            set(&seal(&target, b"l4ter", &[first, second]).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(
            crate::apply::classify_candidate(&mut ctx, &plan)
                .await
                .unwrap(),
            crate::apply::CandidateAdmission::Superseded
        );
        change(&mut ctx, set(&rotated)).await.unwrap();

        let listed = list(&mut ctx, "local", false).await.unwrap();
        assert_eq!(listed.secrets.len(), 1);
        assert_eq!(listed.secrets[0].set_by, "alice");
        assert_eq!(listed.secrets[0].recipients.len(), 2);
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let stored = serde_json::to_string(&env.properties).unwrap()
            + &serde_json::to_string(&listed).unwrap()
            + &serde_json::to_string(&plan).unwrap();
        for plain in ["s3cret", "n3w", &STANDARD.encode("n3w")] {
            assert!(!stored.contains(plain), "{plain} leaked");
        }

        let delete = |present_in_target| {
            crate::environment_config::EnvironmentConfigChange::DeleteSealedSecret {
                instance: "api".into(),
                secret: "db".into(),
                key: "password".into(),
                present_in_target,
            }
        };
        let refused = change(&mut ctx, delete(false))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("api@1.0.0") && refused.contains("--present-in-target"),
            "{refused}"
        );
        change(&mut ctx, delete(true)).await.unwrap();
        assert!(
            list(&mut ctx, "local", false)
                .await
                .unwrap()
                .secrets
                .is_empty()
        );
        let audit = crate::environment_config::audit(&mut ctx, "local")
            .await
            .unwrap();
        assert!(
            audit
                .iter()
                .any(|event| event.action == "delete_sealed_secret"
                    && event.outcome == "completed"
                    && event.actor == "alice")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn config_digest_is_unchanged_without_sealed_values() {
        assert_eq!(config_digest("abc", &[]), "abc");
        assert_eq!(config_digest("", &[]), "");
        let step = |digest: &str| SealedStep {
            secret: "db".into(),
            key: "password".into(),
            digest: digest.into(),
        };
        let one = config_digest("", &[step("sha256:1")]);
        assert!(!one.is_empty());
        assert_ne!(one, config_digest("", &[step("sha256:2")]));
        assert_ne!(one, config_digest("abc", &[step("sha256:1")]));
    }

    #[test]
    fn secret_refs_are_validated() {
        assert_eq!(
            SecretRef::parse("db/password").unwrap().to_string(),
            "db/password"
        );
        assert!(SecretRef::parse("db").is_err());
        assert!(SecretRef::parse("db/").is_err());
        assert!(SecretRef::parse("/password").is_err());
        assert!(SecretRef::parse("db/pass/word").is_err());
    }
}

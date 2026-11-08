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
const MAX_WRAPS: usize = 64;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const PROPERTY_PREFIX: &str = "sealed.";

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

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
    let mut wraps = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        use hpke::{Deserializable as _, Serializable as _};
        let public = <Kem as hpke::Kem>::PublicKey::from_bytes(&recipient.point).map_err(|_| {
            anyhow::anyhow!("recipient {} is not a P-256 key", recipient.fingerprint())
        })?;
        let (encapsulated, wrapped) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
            &hpke::OpModeS::Base,
            &public,
            WRAP_INFO,
            data_key.as_ref(),
            &aad,
            &mut rng,
        )
        .map_err(|error| anyhow::anyhow!("wrapping the data key: {error}"))?;
        wraps.push(SealedWrap {
            fingerprint: recipient.fingerprint(),
            encapsulated_key: STANDARD.encode(encapsulated.to_bytes()),
            wrapped_key: STANDARD.encode(wrapped),
        });
    }
    Ok(SealedValue {
        format_version: SEALED_FORMAT_VERSION,
        ciphertext: STANDARD.encode(ciphertext),
        wraps,
    })
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
        let fingerprint = crate::sealing_key::normalize_fingerprint(&wrap.fingerprint)?;
        if fingerprint != wrap.fingerprint || !seen.insert(fingerprint.clone()) {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedSecretList {
    pub environment: String,
    pub secrets: Vec<SealedSecretEntry>,
}

/// Every sealed key of `environment`, by instance and key.
pub async fn list(ctx: &mut Ctx, environment: &str) -> Result<SealedSecretList> {
    validate_identifier("environment", environment)?;
    let env_obj = crate::environment::environment(ctx, environment).await?;
    let mut instances: Vec<&str> = env_obj
        .properties
        .keys()
        .filter_map(|key| key.strip_prefix(PROPERTY_PREFIX))
        .collect();
    instances.sort_unstable();
    let mut secrets = Vec::new();
    for instance in instances {
        for (name, record) in instance_records(&env_obj, instance)? {
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
                    .into_iter()
                    .map(|wrap| wrap.fingerprint)
                    .collect(),
            });
        }
    }
    Ok(SealedSecretList {
        environment: environment.into(),
        secrets,
    })
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

    /// What the runtime will do (#1050): unwrap and open with `private`.
    fn open(
        target: &SealedTarget,
        sealed: &SealedValue,
        private: &<Kem as hpke::Kem>::PrivateKey,
        fingerprint: &str,
    ) -> Result<Vec<u8>> {
        use hpke::Deserializable as _;
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let wrap = sealed
            .wraps
            .iter()
            .find(|wrap| wrap.fingerprint == fingerprint)
            .context("no wrap")?;
        let aad = target.associated_data();
        let encapsulated =
            <Kem as hpke::Kem>::EncappedKey::from_bytes(&STANDARD.decode(&wrap.encapsulated_key)?)
                .map_err(|_| anyhow::anyhow!("encapsulated key"))?;
        let data_key = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &hpke::OpModeR::Base,
            private,
            &encapsulated,
            WRAP_INFO,
            &STANDARD.decode(&wrap.wrapped_key)?,
            &aad,
        )
        .map_err(|_| anyhow::anyhow!("unwrap refused"))?;
        let mut ciphertext = STANDARD.decode(&sealed.ciphertext)?;
        let body = ciphertext.split_off(NONCE_BYTES);
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &data_key).unwrap());
        let mut body = body;
        let nonce = Nonce::try_assume_unique_for_key(&ciphertext).unwrap();
        let plain = key
            .open_in_place(nonce, Aad::from(&aad), &mut body)
            .map_err(|_| anyhow::anyhow!("open refused"))?;
        Ok(plain.to_vec())
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

        let listed = list(&mut ctx, "local").await.unwrap();
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
        assert!(list(&mut ctx, "local").await.unwrap().secrets.is_empty());
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

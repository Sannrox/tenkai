//! Detached Ed25519 signatures for release manifests and deployment artifacts.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

pub const ENVELOPE_SCHEMA: &str = "tenkai.release-signature.v1";
pub const TRUST_ROOT_VERSION: u32 = 1;
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub schema: String,
    pub key_id: String,
    pub statement: ReleaseStatement,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseStatement {
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_uri: String,
    pub revision: String,
    pub builder: String,
    pub built_at_unix_ms: i64,
    #[serde(default, deserialize_with = "deserialize_unique_materials")]
    pub materials: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoots {
    pub version: u32,
    pub signers: Vec<TrustedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSigner {
    pub key_id: String,
    pub identity: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedSigner {
    pub identity: String,
    pub key_id: String,
    pub verifying_key: VerifyingKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEvidence {
    pub signer_identity: String,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub statement_digest: String,
    pub provenance: Provenance,
}

impl SignatureEnvelope {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading release signature {}", path.display()))?;
        let envelope: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing release signature {}", path.display()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != ENVELOPE_SCHEMA {
            bail!(
                "unsupported release signature schema {:?}; expected {ENVELOPE_SCHEMA:?}",
                self.schema
            );
        }
        validate_key_id(&self.key_id)?;
        validate_digest("manifest_digest", &self.statement.manifest_digest)?;
        validate_digest("artifact_digest", &self.statement.artifact_digest)?;
        self.statement.provenance.validate()?;
        decode_exact::<64>("signature", &self.signature)?;
        Ok(())
    }

    /// Canonical signed bytes use a versioned, length-prefixed binary encoding
    /// independent of the JSON serializer used for the detached envelope.
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
            output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            output.extend_from_slice(bytes);
        }

        let statement = &self.statement;
        let mut output = b"TENKAI-RELEASE-SIGNATURE-V1\0".to_vec();
        push_bytes(&mut output, statement.manifest_digest.as_bytes());
        push_bytes(&mut output, statement.artifact_digest.as_bytes());
        push_bytes(&mut output, statement.provenance.source_uri.as_bytes());
        push_bytes(&mut output, statement.provenance.revision.as_bytes());
        push_bytes(&mut output, statement.provenance.builder.as_bytes());
        output.extend_from_slice(&statement.provenance.built_at_unix_ms.to_be_bytes());
        output.extend_from_slice(&(statement.provenance.materials.len() as u64).to_be_bytes());
        for (uri, digest) in &statement.provenance.materials {
            push_bytes(&mut output, uri.as_bytes());
            push_bytes(&mut output, digest.as_bytes());
        }
        Ok(output)
    }

    pub fn statement_digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(self.signed_bytes()?)))
    }

    /// Resolve the envelope's signer through trusted local configuration and
    /// strictly authenticate the statement before returning its identity.
    pub fn authenticate(&self, roots: &TrustRoots) -> Result<ResolvedSigner> {
        self.validate()?;
        roots.validate()?;
        let signer = roots.resolve(&self.key_id)?;
        let signature_bytes = decode_exact::<64>("signature", &self.signature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        signer
            .verifying_key
            .verify_strict(&self.signed_bytes()?, &signature)
            .context("release signature verification failed")?;
        Ok(signer)
    }
}

pub fn verify_release(
    envelope: &SignatureEnvelope,
    roots: &TrustRoots,
    manifest_digest: &str,
    artifact_digest: &str,
) -> Result<VerificationEvidence> {
    let signer = envelope.authenticate(roots)?;
    if envelope.statement.manifest_digest != manifest_digest {
        bail!(
            "release signature manifest digest does not match the published manifest: signed {}, actual {manifest_digest}",
            envelope.statement.manifest_digest
        );
    }
    if envelope.statement.artifact_digest != artifact_digest {
        bail!(
            "release signature artifact digest does not match the declared deploy inputs: signed {}, actual {artifact_digest}",
            envelope.statement.artifact_digest
        );
    }
    Ok(VerificationEvidence {
        signer_identity: signer.identity,
        signer_key_id: signer.key_id,
        signer_public_key: base64::engine::general_purpose::STANDARD
            .encode(signer.verifying_key.to_bytes()),
        manifest_digest: manifest_digest.into(),
        artifact_digest: artifact_digest.into(),
        statement_digest: envelope.statement_digest()?,
        provenance: envelope.statement.provenance.clone(),
    })
}

impl Provenance {
    pub fn validate(&self) -> Result<()> {
        validate_canonical_url("provenance source_uri", &self.source_uri)?;
        validate_text("provenance revision", &self.revision, 256)?;
        validate_text("provenance builder", &self.builder, 256)?;
        if self.built_at_unix_ms <= 0 {
            bail!("provenance built_at_unix_ms must be positive");
        }
        for (uri, digest) in &self.materials {
            validate_canonical_url("provenance material URL", uri)?;
            validate_digest("provenance material digest", digest)?;
        }
        Ok(())
    }
}

impl TrustRoots {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading release trust roots {}", path.display()))?;
        let roots: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing release trust roots {}", path.display()))?;
        roots.validate()?;
        Ok(roots)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != TRUST_ROOT_VERSION {
            bail!(
                "unsupported release trust-root version {}; expected {TRUST_ROOT_VERSION}",
                self.version
            );
        }
        if self.signers.is_empty() {
            bail!("release trust roots contain no signers");
        }
        let mut key_ids = std::collections::BTreeSet::new();
        let mut identities = std::collections::BTreeSet::new();
        for signer in &self.signers {
            validate_key_id(&signer.key_id)?;
            validate_text("trusted signer identity", &signer.identity, 256)?;
            if !key_ids.insert(&signer.key_id) {
                bail!(
                    "release trust roots contain duplicate key id {}",
                    signer.key_id
                );
            }
            if !identities.insert(&signer.identity) {
                bail!(
                    "release trust roots contain duplicate signer identity {}",
                    signer.identity
                );
            }
            let public_key = decode_exact::<32>("trusted signer public_key", &signer.public_key)?;
            let derived_key_id = key_id(&public_key);
            if signer.key_id != derived_key_id {
                bail!(
                    "trusted signer key id {} does not match its public key ({derived_key_id})",
                    signer.key_id
                );
            }
            parse_verifying_key(&public_key)?;
        }
        Ok(())
    }

    pub fn resolve(&self, key_id: &str) -> Result<ResolvedSigner> {
        let signers: HashMap<_, _> = self
            .signers
            .iter()
            .map(|signer| (signer.key_id.as_str(), signer))
            .collect();
        let signer = signers
            .get(key_id)
            .with_context(|| format!("release signer {key_id} is not trusted"))?;
        let public_key = decode_exact::<32>("trusted signer public_key", &signer.public_key)?;
        Ok(ResolvedSigner {
            identity: signer.identity.clone(),
            key_id: signer.key_id.clone(),
            verifying_key: parse_verifying_key(&public_key)?,
        })
    }
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    format!("sha256:{:x}", Sha256::digest(public_key))
}

fn validate_key_id(value: &str) -> Result<()> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        bail!("release signer key id must use the sha256:<hex> format");
    };
    validate_digest("release signer key id", digest)
}

fn validate_digest(label: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be a 64-character hexadecimal sha256 digest");
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("{label} must use lowercase hexadecimal");
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max_len: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        bail!("{label} must contain 1 to {max_len} non-control UTF-8 bytes");
    }
    Ok(())
}

fn validate_canonical_url(label: &str, value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("{label} must not contain control characters");
    }
    let parsed = url::Url::parse(value)
        .with_context(|| format!("{label} {value:?} is not an absolute URL"))?;
    if parsed.cannot_be_a_base() || !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("{label} must be hierarchical and must not contain credentials");
    }
    if parsed.as_str() != value {
        bail!(
            "{label} must use its canonical URL representation {:?}",
            parsed.as_str()
        );
    }
    Ok(())
}

fn deserialize_unique_materials<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueMaterialsVisitor;

    impl<'de> Visitor<'de> for UniqueMaterialsVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with unique material URLs")
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut materials = BTreeMap::new();
            while let Some((uri, digest)) = map.next_entry::<String, String>()? {
                if materials.insert(uri.clone(), digest).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate provenance material URL {uri:?}"
                    )));
                }
            }
            Ok(materials)
        }
    }

    deserializer.deserialize_map(UniqueMaterialsVisitor)
}

fn decode_exact<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("{label} is not valid base64"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("{label} must decode to {N} bytes, got {}", bytes.len())
    })
}

fn parse_verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes).context("invalid Ed25519 public key")?;
    if key.is_weak() {
        bail!("Ed25519 public key is weak and cannot be trusted");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::Signer as _;

    fn provenance() -> Provenance {
        Provenance {
            source_uri: "https://github.com/example/service".into(),
            revision: "0123456789abcdef".into(),
            builder: "github-actions://example/service/release".into(),
            built_at_unix_ms: 1_700_000_000_000,
            materials: BTreeMap::from([("https://github.com/example/base".into(), "a".repeat(64))]),
        }
    }

    #[test]
    fn canonical_statement_is_stable() {
        let envelope = SignatureEnvelope {
            schema: ENVELOPE_SCHEMA.into(),
            key_id: format!("sha256:{}", "1".repeat(64)),
            statement: ReleaseStatement {
                manifest_digest: "2".repeat(64),
                artifact_digest: "3".repeat(64),
                provenance: provenance(),
            },
            signature: STANDARD.encode([0_u8; 64]),
        };
        envelope.validate().unwrap();
        assert_eq!(
            envelope.statement_digest().unwrap(),
            "309cf929604744888b117e8de40da0ef61f5993b3bc88312867102c61021c9c9"
        );
    }

    #[test]
    fn trust_root_identity_is_bound_to_public_key() {
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
            .verifying_key()
            .to_bytes();
        let roots = TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&public_key),
                identity: "release@example.com".into(),
                public_key: STANDARD.encode(public_key),
            }],
        };
        roots.validate().unwrap();
        let signer = roots.resolve(&key_id(&public_key)).unwrap();
        assert_eq!(signer.identity, "release@example.com");
    }

    #[test]
    fn malformed_provenance_is_rejected() {
        let mut invalid_source = provenance();
        invalid_source.source_uri = "relative/path".into();
        assert!(invalid_source.validate().is_err());

        let mut credentialed_material = provenance();
        credentialed_material.materials.insert(
            "https://user:secret@example.com/input".into(),
            "a".repeat(64),
        );
        assert!(credentialed_material.validate().is_err());

        let mut noncanonical_source = provenance();
        noncanonical_source.source_uri = "https://github.com/example/../service".into();
        assert!(noncanonical_source.validate().is_err());
    }

    #[test]
    fn duplicate_material_urls_are_rejected_during_deserialization() {
        let raw = format!(
            r#"{{
                "source_uri":"https://github.com/example/service",
                "revision":"abc",
                "builder":"builder",
                "built_at_unix_ms":1,
                "materials":{{"https://example.com/input":"{digest}","https://example.com/input":"{digest}"}}
            }}"#,
            digest = "a".repeat(64)
        );
        assert!(serde_json::from_str::<Provenance>(&raw).is_err());
    }

    #[test]
    fn authenticates_only_an_untampered_statement_from_a_trusted_key() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let roots = TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&public_key),
                identity: "release@example.com".into(),
                public_key: STANDARD.encode(public_key),
            }],
        };
        let mut envelope = SignatureEnvelope {
            schema: ENVELOPE_SCHEMA.into(),
            key_id: key_id(&public_key),
            statement: ReleaseStatement {
                manifest_digest: "2".repeat(64),
                artifact_digest: "3".repeat(64),
                provenance: provenance(),
            },
            signature: String::new(),
        };
        envelope.signature = STANDARD.encode(
            signing_key
                .sign(&envelope.signed_bytes().unwrap())
                .to_bytes(),
        );

        let signer = envelope.authenticate(&roots).unwrap();
        assert_eq!(signer.identity, "release@example.com");

        envelope.statement.manifest_digest = "4".repeat(64);
        assert!(envelope.authenticate(&roots).is_err());
    }

    #[test]
    fn weak_public_keys_are_rejected() {
        let mut identity_point = [0_u8; 32];
        identity_point[0] = 1;
        let roots = TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&identity_point),
                identity: "release@example.com".into(),
                public_key: STANDARD.encode(identity_point),
            }],
        };
        assert!(roots.validate().is_err());
    }

    #[test]
    fn verification_binds_manifest_and_artifact_digests() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let roots = TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&public_key),
                identity: "release@example.com".into(),
                public_key: STANDARD.encode(public_key),
            }],
        };
        let mut envelope = SignatureEnvelope {
            schema: ENVELOPE_SCHEMA.into(),
            key_id: key_id(&public_key),
            statement: ReleaseStatement {
                manifest_digest: "2".repeat(64),
                artifact_digest: "3".repeat(64),
                provenance: provenance(),
            },
            signature: String::new(),
        };
        envelope.signature = STANDARD.encode(
            signing_key
                .sign(&envelope.signed_bytes().unwrap())
                .to_bytes(),
        );

        let evidence = verify_release(&envelope, &roots, &"2".repeat(64), &"3".repeat(64)).unwrap();
        assert_eq!(evidence.signer_identity, "release@example.com");
        assert!(verify_release(&envelope, &roots, &"4".repeat(64), &"3".repeat(64)).is_err());
        assert!(verify_release(&envelope, &roots, &"2".repeat(64), &"4".repeat(64)).is_err());
    }

    #[test]
    fn verification_rejects_an_untrusted_signer() {
        let trusted_key = ed25519_dalek::SigningKey::from_bytes(&[12_u8; 32]);
        let untrusted_key = ed25519_dalek::SigningKey::from_bytes(&[13_u8; 32]);
        let trusted_public_key = trusted_key.verifying_key().to_bytes();
        let untrusted_public_key = untrusted_key.verifying_key().to_bytes();
        let roots = TrustRoots {
            version: TRUST_ROOT_VERSION,
            signers: vec![TrustedSigner {
                key_id: key_id(&trusted_public_key),
                identity: "trusted@example.com".into(),
                public_key: STANDARD.encode(trusted_public_key),
            }],
        };
        let mut envelope = SignatureEnvelope {
            schema: ENVELOPE_SCHEMA.into(),
            key_id: key_id(&untrusted_public_key),
            statement: ReleaseStatement {
                manifest_digest: "2".repeat(64),
                artifact_digest: "3".repeat(64),
                provenance: provenance(),
            },
            signature: String::new(),
        };
        envelope.signature = STANDARD.encode(
            untrusted_key
                .sign(&envelope.signed_bytes().unwrap())
                .to_bytes(),
        );
        assert!(verify_release(&envelope, &roots, &"2".repeat(64), &"3".repeat(64)).is_err());
    }
}

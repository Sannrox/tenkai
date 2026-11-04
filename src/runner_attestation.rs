//! Runner attestation (#675): bind a runner certificate to host evidence the
//! runner signs with its own key.
//!
//! On enrollment and on every certificate renewal under an environment's
//! opt-in `require_runner_attestation` policy, the runtime agent runs the
//! host preflight checks on its own host, adds its probed host facts, and
//! signs a `tenkai.runner-attestation.v2` statement with its runner key,
//! the ECDSA P-256 key of its CSR, over the exact bytes it sends (#849).
//! The server verifies the signature over the received bytes against the
//! CSR's public key, then parses them, checks freshness and results,
//! compares the host facts with the environment's operator-declared facts,
//! and then issues a certificate that carries the evidence digest and the
//! key fingerprint in a private extension. A runner key never becomes a plan
//! approval or `preflight` trust root, and `tenkai.preflight.v1` is
//! unchanged.
//!
//! The policy is advertised by refusal: a server that requires attestation
//! answers a request without it with `attestation_missing` (HTTP 428) and
//! the statement schemas it accepts, and only then does the agent send
//! evidence, in the best schema both sides know. With the policy off,
//! nothing changes, so old agents and old servers keep working. The wire
//! format is published in `docs/runtime-protocol-v1.md`.
//!
//! Limit: a file key copied together with its certificate directory carries
//! the same fingerprint. This catches fact drift and bounds a copied
//! credential to one certificate lifetime unless the copy also passes
//! attested renewal. Proving the same host needs a non-exportable hardware
//! key (#785): the policy may require one, a file key is then refused as
//! `hardware_key_required`, and the certificate records whether the key is
//! hardware-backed.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::host_preflight::CheckResult;

/// The statement agents of this release sign: over the bytes sent (#849).
pub const ATTESTATION_SCHEMA: &str = "tenkai.runner-attestation.v2";
/// Deprecated (#675): signed over a re-encoding, accepted from agents of
/// earlier releases until a later release removes it.
pub const LEGACY_ATTESTATION_SCHEMA: &str = "tenkai.runner-attestation.v1";
/// The schemas this server verifies, preferred first.
pub const ACCEPTED_SCHEMAS: &[&str] = &[ATTESTATION_SCHEMA, LEGACY_ATTESTATION_SCHEMA];
/// The only algorithm: runner keys are ECDSA P-256 (#674).
pub const ATTESTATION_ALGORITHM: &str = "ecdsa-p256-sha256";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-RUNNER-ATTESTATION-V2\0";
const LEGACY_SIGNING_DOMAIN: &[u8] = b"TENKAI-RUNNER-ATTESTATION-V1\0";
/// Environment property holding the policy as JSON.
pub const POLICY_PROPERTY: &str = "runner_attestation_policy";
/// Longest accepted `max_age_ms`: seven days.
pub const MAX_POLICY_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
/// Evidence may be dated this far ahead of the server's clock.
const FUTURE_SKEW_MS: i64 = 60_000;
/// Private, non-critical extension in a runner certificate: a DER sequence
/// of two 32-byte octet strings, the evidence digest and the key
/// fingerprint. Under the UUID arc 2.25, so it needs no registration.
pub const BINDING_OID: &[u64] = &[2, 25, 15_797_326_480_183_637_975];

/// Environment property naming who set fact `<key>`: [`OPERATOR_FACT_SOURCE`]
/// for `env facts set` and the facts route, [`RUNTIME_FACT_SOURCE`] for a
/// runtime inventory report. Facts set before #675 have none.
pub const FACT_SOURCE_PREFIX: &str = "fact_source.";
pub const OPERATOR_FACT_SOURCE: &str = "operator";
pub const RUNTIME_FACT_SOURCE: &str = "runtime";

/// The opt-in policy of one environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerAttestationPolicy {
    pub require_runner_attestation: bool,
    /// When true, a file runner key is refused (`hardware_key_required`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_hardware_backed_key: bool,
    /// The oldest evidence accepted, in milliseconds.
    pub max_age_ms: u64,
}

impl RunnerAttestationPolicy {
    pub fn required(max_age_ms: u64) -> Result<Self> {
        Self::required_with(max_age_ms, false)
    }

    pub fn required_with(max_age_ms: u64, require_hardware_backed_key: bool) -> Result<Self> {
        if max_age_ms == 0 || max_age_ms > MAX_POLICY_AGE_MS {
            bail!("runner attestation max_age_ms must be 1..={MAX_POLICY_AGE_MS}");
        }
        Ok(Self {
            require_runner_attestation: true,
            require_hardware_backed_key,
            max_age_ms,
        })
    }
}

/// Which statement an agent signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationSchema {
    /// [`ATTESTATION_SCHEMA`], signed over the bytes sent.
    V2,
    /// [`LEGACY_ATTESTATION_SCHEMA`], for a server that names no schemas.
    V1,
}

impl AttestationSchema {
    pub fn id(self) -> &'static str {
        match self {
            Self::V2 => ATTESTATION_SCHEMA,
            Self::V1 => LEGACY_ATTESTATION_SCHEMA,
        }
    }

    /// The schema to attest with after a 428 whose body is `body`: v2 when
    /// the server accepts it, v1 from a server that names no schemas (an
    /// earlier release), and an error naming what the server accepts when
    /// this agent signs none of them.
    pub fn for_challenge(body: &str) -> Result<Self> {
        let accepted = serde_json::from_str::<AttestationChallenge>(body)
            .map(|challenge| challenge.accepted_schemas)
            .unwrap_or_default();
        if accepted.is_empty() {
            return Ok(Self::V1);
        }
        [Self::V2, Self::V1]
            .into_iter()
            .find(|schema| accepted.iter().any(|id| id == schema.id()))
            .with_context(|| {
                format!(
                    "the server accepts runner attestation schemas {accepted:?}, none of which this agent signs"
                )
            })
    }
}

/// The body of a `428` `attestation_missing` and a `403`
/// `attestation_schema_unsupported`: the refusal and the statement schemas
/// the server verifies, preferred first. Servers before #849 send no list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationChallenge {
    pub error: String,
    #[serde(default)]
    pub accepted_schemas: Vec<String>,
}

impl AttestationChallenge {
    /// The challenge this server sends with `refusal`.
    pub fn new(refusal: &AttestationRefusal) -> Self {
        Self {
            error: refusal.to_string(),
            accepted_schemas: ACCEPTED_SCHEMAS.iter().map(|id| (*id).into()).collect(),
        }
    }
}

/// What the runner signs ([`ATTESTATION_SCHEMA`]). A verifier ignores
/// fields it does not know; the signature still covers them, since it is
/// over the bytes sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerAttestationStatement {
    pub environment: String,
    pub checked_at: i64,
    /// True only when every check passed.
    pub passed: bool,
    pub checks: Vec<AttestedCheck>,
    /// Host facts the runner probed ([`crate::environment::ENVIRONMENT_FACT_KEYS`]).
    /// A key may appear once.
    #[serde(deserialize_with = "unique_facts")]
    pub facts: BTreeMap<String, String>,
    /// `sha256:<hex>` of the signing key's SubjectPublicKeyInfo.
    pub key_fingerprint: String,
    /// True when this runtime generated the key in a hardware store (#785).
    /// Signed with the CSR key, same trust as probed host facts.
    pub hardware_backed: bool,
}

/// One host check as attested. Its own type, not [`CheckResult`], so
/// operator preflight evidence can change without changing this statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedCheck {
    pub check: String,
    pub passed: bool,
    pub reason: String,
}

impl From<CheckResult> for AttestedCheck {
    fn from(result: CheckResult) -> Self {
        Self {
            check: result.check,
            passed: result.passed,
            reason: result.reason,
        }
    }
}

/// A facts map that refuses a repeated key, so two readers of the signed
/// bytes cannot disagree on which value counts.
fn unique_facts<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of host facts")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut facts = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if facts.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!("duplicate fact `{key}`")));
                }
                facts.insert(key, value);
            }
            Ok(facts)
        }
    }
    deserializer.deserialize_map(Unique)
}

/// A [`ATTESTATION_SCHEMA`] attestation as sent. `statement` is the base64
/// (standard, padded) statement JSON bytes; `signature` the base64 ASN.1
/// DER ECDSA P-256 SHA-256 signature over
/// `TENKAI-RUNNER-ATTESTATION-V2\0 || bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub schema: String,
    pub algorithm: String,
    pub statement: String,
    pub signature: String,
}

/// The deprecated [`LEGACY_ATTESTATION_SCHEMA`] statement (#675), kept so
/// agents of earlier releases attest during an upgrade. Its signature
/// covers this struct's serde_json encoding, so the shape is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyStatement {
    pub environment: String,
    pub checked_at: i64,
    pub passed: bool,
    pub checks: Vec<LegacyCheck>,
    pub facts: BTreeMap<String, String>,
    pub key_fingerprint: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hardware_backed: bool,
}

/// One check of a [`LegacyStatement`], frozen with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyCheck {
    pub check: String,
    pub passed: bool,
    pub reason: String,
}

impl From<LegacyStatement> for RunnerAttestationStatement {
    fn from(legacy: LegacyStatement) -> Self {
        Self {
            environment: legacy.environment,
            checked_at: legacy.checked_at,
            passed: legacy.passed,
            checks: legacy
                .checks
                .into_iter()
                .map(|check| AttestedCheck {
                    check: check.check,
                    passed: check.passed,
                    reason: check.reason,
                })
                .collect(),
            facts: legacy.facts,
            key_fingerprint: legacy.key_fingerprint,
            hardware_backed: legacy.hardware_backed,
        }
    }
}

/// A [`LEGACY_ATTESTATION_SCHEMA`] attestation as sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyAttestation {
    pub schema: String,
    pub algorithm: String,
    pub statement: LegacyStatement,
    /// Base64 ASN.1 DER ECDSA signature over the domain-separated statement.
    pub signature: String,
}

/// Signed runner attestation, as sent with an enrollment or a renewal.
/// Any JSON value parses, so an unknown schema is refused by name
/// (`attestation_schema_unsupported`) rather than by the JSON extractor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunnerAttestation {
    Signed(SignedAttestation),
    Legacy(LegacyAttestation),
    Unrecognized(serde_json::Value),
}

/// Host evidence an agent signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEvidence {
    pub environment: String,
    pub checks: Vec<CheckResult>,
    pub facts: BTreeMap<String, String>,
    pub checked_at: i64,
}

/// Why attested enrollment or renewal, or a runtime inventory report under
/// the policy, was refused. [`Self::code`] is the stable name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationRefusal {
    #[error("runner attestation required: attestation_missing")]
    Missing,
    #[error("runner attestation refused: certificate_required (attestation binds a CSR key)")]
    CertificateRequired,
    #[error(
        "runner attestation refused: attestation_schema_unsupported (send one of the accepted_schemas)"
    )]
    SchemaUnsupported,
    #[error("runner attestation refused: attestation_malformed ({0})")]
    Malformed(String),
    #[error("runner attestation refused: environment_mismatch")]
    EnvironmentMismatch,
    #[error("runner attestation refused: signature_invalid (not signed by the CSR key)")]
    SignatureInvalid,
    #[error("runner attestation refused: fingerprint_mismatch")]
    FingerprintMismatch,
    #[error("runner attestation refused: key_changed (the CSR key is not the runner's key)")]
    KeyChanged,
    #[error("runner attestation refused: no_bound_key (renew with the current certificate)")]
    NoBoundKey,
    #[error("runner attestation refused: evidence_stale")]
    Stale,
    #[error("runner attestation refused: evidence_failed ({0})")]
    Failed(String),
    #[error("runner attestation refused: fact_mismatch ({key})")]
    FactMismatch { key: String },
    #[error("runtime inventory refused: inventory_contradicts_declared_fact ({key})")]
    InventoryContradictsDeclaredFact { key: String },
    #[error(
        "runtime request refused: attestation_requires_client_certificate (present the runner certificate; a bearer only renews it)"
    )]
    ClientCertificateRequired,
    #[error(
        "runner attestation refused: hardware_key_required (file runner keys are not admitted)"
    )]
    HardwareKeyRequired,
}

impl AttestationRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "attestation_missing",
            Self::CertificateRequired => "certificate_required",
            Self::SchemaUnsupported => "attestation_schema_unsupported",
            Self::Malformed(_) => "attestation_malformed",
            Self::EnvironmentMismatch => "environment_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::KeyChanged => "key_changed",
            Self::NoBoundKey => "no_bound_key",
            Self::Stale => "evidence_stale",
            Self::Failed(_) => "evidence_failed",
            Self::FactMismatch { .. } => "fact_mismatch",
            Self::InventoryContradictsDeclaredFact { .. } => "inventory_contradicts_declared_fact",
            Self::ClientCertificateRequired => "attestation_requires_client_certificate",
            Self::HardwareKeyRequired => "hardware_key_required",
        }
    }

    /// Whether the response carries an [`AttestationChallenge`].
    pub fn names_schemas(&self) -> bool {
        matches!(self, Self::Missing | Self::SchemaUnsupported)
    }
}

/// What a verified attestation binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// `sha256:<hex>` of the statement bytes as sent (v2), or of the
    /// re-encoded attestation (v1).
    pub evidence_digest: String,
    /// `sha256:<hex>` of the runner key's SubjectPublicKeyInfo.
    pub key_fingerprint: String,
    pub checked_at: i64,
    pub hardware_backed: bool,
}

fn legacy_message(statement: &LegacyStatement) -> Result<Vec<u8>> {
    let mut bytes = LEGACY_SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// The SubjectPublicKeyInfo (DER) and raw public key of a PEM CSR.
fn csr_key(csr_pem: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use x509_parser::prelude::FromDer as _;
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())
        .map_err(|error| anyhow::anyhow!("reading the CSR: {error}"))?;
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .map_err(|error| anyhow::anyhow!("parsing the CSR: {error}"))?;
    let spki = &request.certification_request_info.subject_pki;
    Ok((spki.raw.to_vec(), spki.subject_public_key.data.to_vec()))
}

/// `sha256:<hex>` of a CSR's SubjectPublicKeyInfo.
pub fn csr_fingerprint(csr_pem: &str) -> Result<String> {
    Ok(sha256_label(&csr_key(csr_pem)?.0))
}

/// `sha256:<hex>` of a certificate's (DER) SubjectPublicKeyInfo.
pub fn certificate_fingerprint(certificate_der: &[u8]) -> Result<String> {
    use x509_parser::prelude::FromDer as _;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
        .map_err(|error| anyhow::anyhow!("parsing the certificate: {error}"))?;
    Ok(sha256_label(certificate.public_key().raw))
}

/// Sign `evidence` as `schema` with the runner key `key_pem` (PKCS#8
/// P-256, as the agent stores a file key), for the key of `csr_pem`. File
/// keys are not hardware-backed.
pub fn sign(
    schema: AttestationSchema,
    evidence: HostEvidence,
    key_pem: &str,
    csr_pem: &str,
) -> Result<RunnerAttestation> {
    sign_with(schema, evidence, csr_pem, false, |message| {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let key = rcgen::KeyPair::from_pem(key_pem).context("reading the runner key")?;
        let rng = ring::rand::SystemRandom::new();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng)
                .map_err(|error| anyhow::anyhow!("the runner key is not ECDSA P-256: {error}"))?;
        let signature = signer
            .sign(&rng, message)
            .map_err(|_| anyhow::anyhow!("signing the runner attestation failed"))?;
        Ok(signature.as_ref().to_vec())
    })
}

/// [`sign`] with a caller-supplied signature (ASN.1 DER over the message
/// it is given) and hardware-backed flag (#785).
pub fn sign_with(
    schema: AttestationSchema,
    evidence: HostEvidence,
    csr_pem: &str,
    hardware_backed: bool,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<RunnerAttestation> {
    let HostEvidence {
        environment,
        checks,
        facts,
        checked_at,
    } = evidence;
    crate::ontology::validate_identifier("environment", &environment)?;
    let passed = checks.iter().all(|check| check.passed);
    let key_fingerprint = csr_fingerprint(csr_pem)?;
    Ok(match schema {
        AttestationSchema::V2 => {
            let statement = RunnerAttestationStatement {
                environment,
                checked_at,
                passed,
                checks: checks.into_iter().map(Into::into).collect(),
                facts,
                key_fingerprint,
                hardware_backed,
            };
            let signed = crate::signed_bytes::sign(SIGNING_DOMAIN, &statement, sign)?;
            RunnerAttestation::Signed(SignedAttestation {
                schema: ATTESTATION_SCHEMA.into(),
                algorithm: ATTESTATION_ALGORITHM.into(),
                statement: signed.statement,
                signature: STANDARD.encode(signed.signature),
            })
        }
        AttestationSchema::V1 => {
            let statement = LegacyStatement {
                environment,
                checked_at,
                passed,
                checks: checks
                    .into_iter()
                    .map(|check| LegacyCheck {
                        check: check.check,
                        passed: check.passed,
                        reason: check.reason,
                    })
                    .collect(),
                facts,
                key_fingerprint,
                hardware_backed,
            };
            let signature = sign(&legacy_message(&statement)?)?;
            RunnerAttestation::Legacy(LegacyAttestation {
                schema: LEGACY_ATTESTATION_SCHEMA.into(),
                algorithm: ATTESTATION_ALGORITHM.into(),
                statement,
                signature: STANDARD.encode(signature),
            })
        }
    })
}

/// The statement of `evidence` once its signature verified with the key
/// `public_key`, and its evidence digest.
fn verified_statement(
    evidence: &RunnerAttestation,
    public_key: &[u8],
) -> Result<(RunnerAttestationStatement, String), AttestationRefusal> {
    let signed_by = |message: &[u8], signature: &str| {
        STANDARD.decode(signature).is_ok_and(|signature| {
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                public_key,
            )
            .verify(message, &signature)
            .is_ok()
        })
    };
    let algorithm = |algorithm: &str, schema: &str| {
        if algorithm == ATTESTATION_ALGORITHM {
            Ok(())
        } else {
            Err(AttestationRefusal::Malformed(format!(
                "{schema} is signed with {ATTESTATION_ALGORITHM}"
            )))
        }
    };
    match evidence {
        RunnerAttestation::Signed(signed) if signed.schema == ATTESTATION_SCHEMA => {
            algorithm(&signed.algorithm, ATTESTATION_SCHEMA)?;
            let verified =
                crate::signed_bytes::verify(SIGNING_DOMAIN, &signed.statement, |message| {
                    signed_by(message, &signed.signature)
                })
                .map_err(|refusal| match refusal {
                    crate::signed_bytes::Refusal::Signature => AttestationRefusal::SignatureInvalid,
                    other => AttestationRefusal::Malformed(other.to_string()),
                })?;
            Ok((verified.statement, verified.digest))
        }
        RunnerAttestation::Legacy(legacy) if legacy.schema == LEGACY_ATTESTATION_SCHEMA => {
            algorithm(&legacy.algorithm, LEGACY_ATTESTATION_SCHEMA)?;
            let message = legacy_message(&legacy.statement)
                .map_err(|error| AttestationRefusal::Malformed(error.to_string()))?;
            if !signed_by(&message, &legacy.signature) {
                return Err(AttestationRefusal::SignatureInvalid);
            }
            let encoded = serde_json::to_vec(legacy)
                .map_err(|error| AttestationRefusal::Malformed(error.to_string()))?;
            Ok((legacy.statement.clone().into(), sha256_label(&encoded)))
        }
        other => {
            let schema = match other {
                RunnerAttestation::Signed(signed) => Some(signed.schema.as_str()),
                RunnerAttestation::Legacy(legacy) => Some(legacy.schema.as_str()),
                RunnerAttestation::Unrecognized(value) => {
                    value.get("schema").and_then(serde_json::Value::as_str)
                }
            };
            Err(match schema {
                Some(schema) if ACCEPTED_SCHEMAS.contains(&schema) => {
                    AttestationRefusal::Malformed(format!("not a {schema} attestation"))
                }
                _ => AttestationRefusal::SchemaUnsupported,
            })
        }
    }
}

/// Verify `evidence` for `environment` under `policy`: signed by the key of
/// `csr_pem`, naming that key, fresh at `now_ms`, passed, and not
/// contradicting any operator-declared fact in `declared`.
pub fn verify(
    evidence: Option<&RunnerAttestation>,
    csr_pem: &str,
    environment: &str,
    declared: &BTreeMap<String, String>,
    policy: &RunnerAttestationPolicy,
    now_ms: i64,
) -> Result<Binding, AttestationRefusal> {
    let evidence = evidence.ok_or(AttestationRefusal::Missing)?;
    let (spki, public_key) =
        csr_key(csr_pem).map_err(|error| AttestationRefusal::Malformed(format!("{error:#}")))?;
    let (statement, evidence_digest) = verified_statement(evidence, &public_key)?;
    let key_fingerprint = sha256_label(&spki);
    if statement.key_fingerprint != key_fingerprint {
        return Err(AttestationRefusal::FingerprintMismatch);
    }
    if statement.environment != environment {
        return Err(AttestationRefusal::EnvironmentMismatch);
    }
    let max_age = i64::try_from(policy.max_age_ms).unwrap_or(i64::MAX);
    if statement.checked_at > now_ms.saturating_add(FUTURE_SKEW_MS)
        || now_ms.saturating_sub(statement.checked_at) > max_age
    {
        return Err(AttestationRefusal::Stale);
    }
    let failed: Vec<&str> = statement
        .checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| check.check.as_str())
        .collect();
    if !statement.passed || !failed.is_empty() {
        return Err(AttestationRefusal::Failed(failed.join(", ")));
    }
    for (key, value) in declared {
        if statement
            .facts
            .get(key)
            .is_some_and(|probed| probed != value)
        {
            return Err(AttestationRefusal::FactMismatch { key: key.clone() });
        }
    }
    // Agent-reported, signed by the CSR key (same trust as facts).
    if policy.require_hardware_backed_key && !statement.hardware_backed {
        return Err(AttestationRefusal::HardwareKeyRequired);
    }
    Ok(Binding {
        evidence_digest,
        key_fingerprint,
        checked_at: statement.checked_at,
        hardware_backed: statement.hardware_backed,
    })
}

/// The certificate extension content for `binding`.
pub(crate) fn binding_extension(binding: &Binding) -> Result<Vec<u8>> {
    let raw = |label: &str| -> Result<Vec<u8>> {
        let hex = label
            .strip_prefix("sha256:")
            .filter(|hex| hex.len() == 64)
            .context("a binding digest must be sha256")?;
        (0..32)
            .map(|at| {
                u8::from_str_radix(&hex[2 * at..2 * at + 2], 16)
                    .context("a binding digest must be hex")
            })
            .collect()
    };
    // SEQUENCE { OCTET STRING (32), OCTET STRING (32) } and, when the key is
    // hardware-backed, BOOLEAN TRUE. File-key certificates keep the #675
    // two-field encoding so older parsers still read them.
    let mut content = vec![0x30, 68, 0x04, 32];
    content.extend(raw(&binding.evidence_digest)?);
    content.extend([0x04, 32]);
    content.extend(raw(&binding.key_fingerprint)?);
    if binding.hardware_backed {
        content[1] = 71;
        content.extend([0x01, 0x01, 0xff]);
    }
    Ok(content)
}

/// The DER content bytes of [`BINDING_OID`].
fn binding_oid_der() -> Vec<u8> {
    let mut bytes = vec![(BINDING_OID[0] * 40 + BINDING_OID[1]) as u8];
    for arc in &BINDING_OID[2..] {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        bytes.extend(groups.into_iter().rev());
    }
    bytes
}

/// The evidence digest and key fingerprint a certificate (DER) binds, when
/// it carries the attestation extension.
pub fn certificate_binding(certificate_der: &[u8]) -> Result<Option<(String, String)>> {
    use x509_parser::prelude::FromDer as _;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
        .map_err(|error| anyhow::anyhow!("parsing the certificate: {error}"))?;
    // x509-parser prints large arcs as hex, so compare encodings.
    let oid = binding_oid_der();
    let Some(extension) = certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.as_bytes() == oid.as_slice())
    else {
        return Ok(None);
    };
    let value = extension.value;
    let two_field =
        value.len() == 70 && value[..4] == [0x30, 68, 0x04, 32] && value[36..38] == [0x04, 32];
    let three_field = value.len() == 73
        && value[..4] == [0x30, 71, 0x04, 32]
        && value[36..38] == [0x04, 32]
        && value[70..72] == [0x01, 0x01]
        && (value[72] == 0x00 || value[72] == 0xff);
    if !two_field && !three_field {
        bail!("the runner attestation extension is malformed");
    }
    let hex = |bytes: &[u8]| {
        format!(
            "sha256:{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    Ok(Some((hex(&value[4..36]), hex(&value[38..70]))))
}

/// Whether a runner certificate's attestation extension records a
/// hardware-backed key. Certificates without the third field are file keys.
pub fn certificate_hardware_backed(certificate_der: &[u8]) -> Result<bool> {
    use x509_parser::prelude::FromDer as _;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
        .map_err(|error| anyhow::anyhow!("parsing the certificate: {error}"))?;
    let oid = binding_oid_der();
    let Some(extension) = certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.as_bytes() == oid.as_slice())
    else {
        return Ok(false);
    };
    let value = extension.value;
    Ok(value.len() == 73 && value.get(72) == Some(&0xff))
}

/// The policy stored on an environment object, if any.
pub fn policy_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Result<Option<RunnerAttestationPolicy>> {
    properties
        .get(POLICY_PROPERTY)
        .map(|raw| {
            serde_json::from_str::<RunnerAttestationPolicy>(raw)
                .context("parsing the stored runner attestation policy")
        })
        .transpose()
        .map(|policy| policy.filter(|policy| policy.require_runner_attestation))
}

/// The policy and operator-declared facts of `environment`. An environment
/// that does not exist has no policy; a store error is an error, so the
/// caller fails closed.
pub async fn environment_policy(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<Option<(RunnerAttestationPolicy, BTreeMap<String, String>)>> {
    crate::ontology::validate_identifier("environment", environment)?;
    let Some(object) = ctx.get(&crate::ontology::env_id(environment)).await? else {
        return Ok(None);
    };
    let Some(policy) = policy_from_properties(&object.properties)? else {
        return Ok(None);
    };
    Ok(Some((policy, declared_facts(&object.properties))))
}

/// Facts an operator set, by key. Facts reported by a runtime, or set
/// before provenance was recorded, are not declarations.
pub fn declared_facts(
    properties: &std::collections::HashMap<String, String>,
) -> BTreeMap<String, String> {
    properties
        .iter()
        .filter_map(|(property, source)| {
            let key = property.strip_prefix(FACT_SOURCE_PREFIX)?;
            (source == OPERATOR_FACT_SOURCE)
                .then(|| {
                    Some((
                        key.to_string(),
                        properties.get(&format!("fact.{key}"))?.clone(),
                    ))
                })
                .flatten()
        })
        .collect()
}

/// Require runner attestation for `environment`'s enrollments and renewals.
pub async fn set_policy(
    ctx: &mut Ctx,
    environment: &str,
    max_age_ms: u64,
    require_hardware_backed_key: bool,
) -> Result<String> {
    let policy = RunnerAttestationPolicy::required_with(max_age_ms, require_hardware_backed_key)?;
    let mut object = crate::environment::environment(ctx, environment).await?;
    object
        .properties
        .insert(POLICY_PROPERTY.into(), serde_json::to_string(&policy)?);
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(if require_hardware_backed_key {
        format!(
            "{environment} requires a hardware-backed runner key and runner attestation, evidence at most {max_age_ms} ms old"
        )
    } else {
        format!("{environment} requires runner attestation, evidence at most {max_age_ms} ms old")
    })
}

/// Stop requiring runner attestation for `environment`.
pub async fn clear_policy(ctx: &mut Ctx, environment: &str) -> Result<String> {
    let mut object = crate::environment::environment(ctx, environment).await?;
    if object.properties.remove(POLICY_PROPERTY).is_none() {
        return Ok(format!("{environment} does not require runner attestation"));
    }
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!(
        "{environment} no longer requires runner attestation"
    ))
}

/// The stored policy of `environment`, for `env runner-attestation show`.
pub async fn policy(ctx: &mut Ctx, environment: &str) -> Result<Option<RunnerAttestationPolicy>> {
    let object = crate::environment::environment(ctx, environment).await?;
    policy_from_properties(&object.properties)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A runner key and a CSR over it, as the agent makes them.
    pub(crate) fn runner_key() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        (key.serialize_pem(), csr)
    }

    pub(crate) fn attest(
        environment: &str,
        facts: &[(&str, &str)],
        key: &(String, String),
        now_ms: i64,
    ) -> RunnerAttestation {
        attest_as(AttestationSchema::V2, environment, facts, key, now_ms)
    }

    pub(crate) fn attest_as(
        schema: AttestationSchema,
        environment: &str,
        facts: &[(&str, &str)],
        key: &(String, String),
        now_ms: i64,
    ) -> RunnerAttestation {
        sign(
            schema,
            HostEvidence {
                environment: environment.into(),
                checks: vec![CheckResult {
                    check: "port 8443".into(),
                    passed: true,
                    reason: "free".into(),
                }],
                facts: facts
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
                checked_at: now_ms,
            },
            &key.0,
            &key.1,
        )
        .unwrap()
    }

    /// A v2 attestation over `bytes`, signed as another implementation
    /// would: its own JSON formatting and field order.
    fn signed_bytes_attestation(key: &(String, String), bytes: &[u8]) -> RunnerAttestation {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let pkcs8 = rcgen::KeyPair::from_pem(&key.0).unwrap().serialize_der();
        let rng = ring::rand::SystemRandom::new();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
        let signature = signer
            .sign(&rng, &[SIGNING_DOMAIN, bytes].concat())
            .unwrap();
        RunnerAttestation::Signed(SignedAttestation {
            schema: ATTESTATION_SCHEMA.into(),
            algorithm: ATTESTATION_ALGORITHM.into(),
            statement: STANDARD.encode(bytes),
            signature: STANDARD.encode(signature.as_ref()),
        })
    }

    const NOW: i64 = 1_800_000_000_000;
    const POLICY: RunnerAttestationPolicy = RunnerAttestationPolicy {
        require_runner_attestation: true,
        require_hardware_backed_key: false,
        max_age_ms: 600_000,
    };

    fn declared(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn a_fresh_passing_attestation_binds_its_key_and_digest() {
        let key = runner_key();
        let evidence = attest("prod", &[("architecture", "arm64")], &key, NOW);
        let binding = verify(
            Some(&evidence),
            &key.1,
            "prod",
            &declared(&[("architecture", "arm64")]),
            &POLICY,
            NOW + 1_000,
        )
        .unwrap();
        assert_eq!(binding.key_fingerprint, csr_fingerprint(&key.1).unwrap());
        assert!(binding.evidence_digest.starts_with("sha256:"));
        let extension = binding_extension(&binding).unwrap();
        assert_eq!(extension.len(), 70);
        let mut hardware = binding;
        hardware.hardware_backed = true;
        let extension = binding_extension(&hardware).unwrap();
        assert_eq!(extension.len(), 73);
        assert_eq!(&extension[70..], [0x01, 0x01, 0xff]);
    }

    /// Each refusal is named: another signer, another environment, stale,
    /// failed, a fact that contradicts the operator, and no evidence.
    #[test]
    fn refusals_are_named() {
        let key = runner_key();
        let other = runner_key();
        let check = |evidence: Option<&RunnerAttestation>, csr: &str, facts, now| {
            verify(evidence, csr, "prod", &declared(facts), &POLICY, now)
                .unwrap_err()
                .code()
        };
        let good = attest("prod", &[("architecture", "arm64")], &key, NOW);
        assert_eq!(check(None, &key.1, &[], NOW), "attestation_missing");
        // Signed by a key other than the CSR's.
        assert_eq!(check(Some(&good), &other.1, &[], NOW), "signature_invalid");
        let RunnerAttestation::Signed(mut tampered) = good.clone() else {
            panic!("v2 is sent as bytes");
        };
        let bytes = STANDARD.decode(&tampered.statement).unwrap();
        tampered.statement =
            STANDARD.encode(String::from_utf8(bytes).unwrap().replace("arm64", "x86_64"));
        let tampered = RunnerAttestation::Signed(tampered);
        assert_eq!(
            check(Some(&tampered), &key.1, &[], NOW),
            "signature_invalid"
        );
        let stage = attest("stage", &[], &key, NOW);
        assert_eq!(
            check(Some(&stage), &key.1, &[], NOW),
            "environment_mismatch"
        );
        assert_eq!(
            check(Some(&good), &key.1, &[], NOW + 600_001),
            "evidence_stale"
        );
        assert_eq!(
            check(Some(&good), &key.1, &[], NOW - 120_000),
            "evidence_stale"
        );
        let failed = sign(
            AttestationSchema::V2,
            HostEvidence {
                environment: "prod".into(),
                checks: vec![CheckResult {
                    check: "disk /var".into(),
                    passed: false,
                    reason: "1 byte free".into(),
                }],
                facts: BTreeMap::new(),
                checked_at: NOW,
            },
            &key.0,
            &key.1,
        )
        .unwrap();
        assert_eq!(check(Some(&failed), &key.1, &[], NOW), "evidence_failed");
        let refusal = verify(
            Some(&good),
            &key.1,
            "prod",
            &declared(&[("architecture", "x86_64")]),
            &POLICY,
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            refusal,
            AttestationRefusal::FactMismatch {
                key: "architecture".into()
            }
        );
        // A declared fact the runner did not report is no contradiction.
        assert!(
            verify(
                Some(&good),
                &key.1,
                "prod",
                &declared(&[("zone", "a")]),
                &POLICY,
                NOW
            )
            .is_ok()
        );
        let mut hardware_policy = POLICY;
        hardware_policy.require_hardware_backed_key = true;
        assert_eq!(
            verify(
                Some(&good),
                &key.1,
                "prod",
                &BTreeMap::new(),
                &hardware_policy,
                NOW
            )
            .unwrap_err()
            .code(),
            "hardware_key_required"
        );
    }

    /// v2 is verified over the bytes sent (#849): another implementation's
    /// formatting, field order and an added field verify, the added field
    /// stays signed, and the digest is of those bytes. A repeated fact is
    /// refused rather than read one way by one verifier and another way by
    /// the next.
    #[test]
    fn v2_signs_the_bytes_sent_and_tolerates_added_fields() {
        let key = runner_key();
        let fingerprint = csr_fingerprint(&key.1).unwrap();
        let bytes = format!(
            r#"{{ "key_fingerprint": "{fingerprint}", "facts": {{"architecture": "arm64"}},
                "environment": "prod", "checked_at": {NOW}, "passed": true, "checks": [
                {{"check": "port 8443", "passed": true, "reason": "free", "took_ms": 3}}],
                "hardware_backed": false, "uptime_s": 9 }}"#
        );
        let evidence = signed_bytes_attestation(&key, bytes.as_bytes());
        let binding = verify(
            Some(&evidence),
            &key.1,
            "prod",
            &declared(&[("architecture", "arm64")]),
            &POLICY,
            NOW,
        )
        .unwrap();
        assert_eq!(binding.evidence_digest, sha256_label(bytes.as_bytes()));
        // The added field is signed: dropping it breaks the signature.
        let RunnerAttestation::Signed(mut stripped) = evidence else {
            unreachable!()
        };
        stripped.statement = STANDARD.encode(bytes.replace(r#", "uptime_s": 9"#, ""));
        assert_eq!(
            verify(
                Some(&RunnerAttestation::Signed(stripped)),
                &key.1,
                "prod",
                &BTreeMap::new(),
                &POLICY,
                NOW
            )
            .unwrap_err()
            .code(),
            "signature_invalid"
        );
        let repeated = format!(
            r#"{{"environment":"prod","checked_at":{NOW},"passed":true,"checks":[],"facts":{{"architecture":"arm64","architecture":"x86_64"}},"key_fingerprint":"{fingerprint}","hardware_backed":false}}"#
        );
        let refusal = verify(
            Some(&signed_bytes_attestation(&key, repeated.as_bytes())),
            &key.1,
            "prod",
            &BTreeMap::new(),
            &POLICY,
            NOW,
        )
        .unwrap_err();
        assert_eq!(refusal.code(), "attestation_malformed", "{refusal}");
        let twice = format!(
            r#"{{"environment":"stage","environment":"prod","checked_at":{NOW},"passed":true,"checks":[],"facts":{{}},"key_fingerprint":"{fingerprint}","hardware_backed":false}}"#
        );
        let refusal = verify(
            Some(&signed_bytes_attestation(&key, twice.as_bytes())),
            &key.1,
            "prod",
            &BTreeMap::new(),
            &POLICY,
            NOW,
        )
        .unwrap_err();
        assert_eq!(refusal.code(), "attestation_malformed", "{refusal}");
    }

    /// v1 statements of earlier agents still verify, over the encoding
    /// those agents signed; an unknown schema, in any shape, is refused by
    /// name, and a known schema in the wrong shape is malformed.
    #[test]
    fn v1_still_verifies_and_unknown_schemas_are_named() {
        let key = runner_key();
        let legacy = attest_as(
            AttestationSchema::V1,
            "prod",
            &[("architecture", "arm64")],
            &key,
            NOW,
        );
        let RunnerAttestation::Legacy(sent) = &legacy else {
            panic!("v1 is sent as an object");
        };
        // The bytes an agent before #849 signed for this statement.
        let expected = format!(
            r#"{{"environment":"prod","checked_at":{NOW},"passed":true,"checks":[{{"check":"port 8443","passed":true,"reason":"free"}}],"facts":{{"architecture":"arm64"}},"key_fingerprint":"{}"}}"#,
            csr_fingerprint(&key.1).unwrap()
        );
        assert_eq!(
            legacy_message(&sent.statement).unwrap(),
            [LEGACY_SIGNING_DOMAIN, expected.as_bytes()].concat()
        );
        let wire = serde_json::to_value(&legacy).unwrap();
        let received: RunnerAttestation = serde_json::from_value(wire).unwrap();
        assert!(matches!(received, RunnerAttestation::Legacy(_)));
        verify(
            Some(&received),
            &key.1,
            "prod",
            &BTreeMap::new(),
            &POLICY,
            NOW,
        )
        .unwrap();

        let refuse = |wire: serde_json::Value| {
            let received: RunnerAttestation = serde_json::from_value(wire).unwrap();
            verify(
                Some(&received),
                &key.1,
                "prod",
                &BTreeMap::new(),
                &POLICY,
                NOW,
            )
            .unwrap_err()
            .code()
        };
        let mut future = serde_json::to_value(attest("prod", &[], &key, NOW)).unwrap();
        future["schema"] = "tenkai.runner-attestation.v9".into();
        assert_eq!(refuse(future), "attestation_schema_unsupported");
        assert_eq!(
            refuse(serde_json::json!({"schema": "tenkai.runner-attestation.v9", "proof": [1]})),
            "attestation_schema_unsupported"
        );
        assert_eq!(
            refuse(serde_json::json!("v1")),
            "attestation_schema_unsupported"
        );
        assert_eq!(
            refuse(serde_json::json!({"schema": ATTESTATION_SCHEMA, "statement": {}})),
            "attestation_malformed"
        );
    }

    /// After a 428 an agent signs v2 when the server names it, v1 when the
    /// server names nothing (an earlier release), and stops when it signs
    /// none of the named schemas.
    #[test]
    fn the_agent_picks_a_schema_from_the_challenge() {
        let challenge =
            serde_json::to_string(&AttestationChallenge::new(&AttestationRefusal::Missing))
                .unwrap();
        assert_eq!(
            AttestationSchema::for_challenge(&challenge).unwrap(),
            AttestationSchema::V2
        );
        let earlier = r#"{"error":"runner attestation required: attestation_missing"}"#;
        assert_eq!(
            AttestationSchema::for_challenge(earlier).unwrap(),
            AttestationSchema::V1
        );
        assert_eq!(
            AttestationSchema::for_challenge("").unwrap(),
            AttestationSchema::V1
        );
        let later = r#"{"error":"x","accepted_schemas":["tenkai.runner-attestation.v9"]}"#;
        let error = AttestationSchema::for_challenge(later).unwrap_err();
        assert!(format!("{error}").contains("v9"), "{error}");
    }

    #[test]
    fn only_operator_set_facts_are_declarations() {
        let properties = std::collections::HashMap::from([
            ("fact.architecture".to_string(), "arm64".to_string()),
            (
                "fact_source.architecture".to_string(),
                "operator".to_string(),
            ),
            ("fact.memory_gib".to_string(), "16".to_string()),
            ("fact_source.memory_gib".to_string(), "runtime".to_string()),
            ("fact.zone".to_string(), "a".to_string()),
        ]);
        assert_eq!(
            declared_facts(&properties),
            declared(&[("architecture", "arm64")])
        );
        assert!(RunnerAttestationPolicy::required(0).is_err());
        assert!(RunnerAttestationPolicy::required(MAX_POLICY_AGE_MS + 1).is_err());
    }
}

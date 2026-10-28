//! Runner attestation (#675): bind a runner certificate to host evidence the
//! runner signs with its own key.
//!
//! On enrollment and on every certificate renewal under an environment's
//! opt-in `require_runner_attestation` policy, the runtime agent runs the
//! host preflight checks on its own host, adds its probed host facts, and
//! signs a `tenkai.runner-attestation.v1` statement with its runner key,
//! the ECDSA P-256 key of its CSR. The server verifies the signature
//! against the CSR's public key, checks freshness and results, compares the
//! host facts with the environment's operator-declared facts, and then
//! issues a certificate that carries the evidence digest and the key
//! fingerprint in a private extension. A runner key never becomes a plan
//! approval or `preflight` trust root, and `tenkai.preflight.v1` is
//! unchanged.
//!
//! The policy is advertised by refusal: a server that requires attestation
//! answers a request without it with `attestation_missing` (HTTP 428), and
//! only then does the agent send evidence. With the policy off, nothing
//! changes, so old agents and old servers keep working.
//!
//! Limit: a file key copied together with its certificate directory carries
//! the same fingerprint. This catches fact drift and bounds a copied
//! credential to one certificate lifetime unless the copy also passes
//! attested renewal; proving the same host needs non-exportable keys.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::host_preflight::CheckResult;

pub const ATTESTATION_SCHEMA: &str = "tenkai.runner-attestation.v1";
/// The only algorithm: runner keys are ECDSA P-256 (#674).
pub const ATTESTATION_ALGORITHM: &str = "ecdsa-p256-sha256";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-RUNNER-ATTESTATION-V1\0";
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
    /// The oldest evidence accepted, in milliseconds.
    pub max_age_ms: u64,
}

impl RunnerAttestationPolicy {
    pub fn required(max_age_ms: u64) -> Result<Self> {
        if max_age_ms == 0 || max_age_ms > MAX_POLICY_AGE_MS {
            bail!("runner attestation max_age_ms must be 1..={MAX_POLICY_AGE_MS}");
        }
        Ok(Self {
            require_runner_attestation: true,
            max_age_ms,
        })
    }
}

/// What the runner signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerAttestationStatement {
    pub environment: String,
    pub checked_at: i64,
    /// True only when every check passed.
    pub passed: bool,
    pub checks: Vec<CheckResult>,
    /// Host facts the runner probed ([`crate::environment::ENVIRONMENT_FACT_KEYS`]).
    pub facts: BTreeMap<String, String>,
    /// `sha256:<hex>` of the signing key's SubjectPublicKeyInfo.
    pub key_fingerprint: String,
}

/// Signed runner attestation, as sent with an enrollment or a renewal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerAttestation {
    pub schema: String,
    pub algorithm: String,
    pub statement: RunnerAttestationStatement,
    /// Base64 ASN.1 DER ECDSA signature over the domain-separated statement.
    pub signature: String,
}

/// Why attested enrollment or renewal, or a runtime inventory report under
/// the policy, was refused. [`Self::code`] is the stable name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationRefusal {
    #[error("runner attestation required: attestation_missing")]
    Missing,
    #[error("runner attestation refused: certificate_required (attestation binds a CSR key)")]
    CertificateRequired,
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
}

impl AttestationRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "attestation_missing",
            Self::CertificateRequired => "certificate_required",
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
        }
    }
}

/// What a verified attestation binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// `sha256:<hex>` of the attestation as sent.
    pub evidence_digest: String,
    /// `sha256:<hex>` of the runner key's SubjectPublicKeyInfo.
    pub key_fingerprint: String,
    pub checked_at: i64,
}

fn canonical_bytes(statement: &RunnerAttestationStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
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

/// Sign `checks` and `facts` for `environment` with the runner key
/// `key_pem` (PKCS#8 P-256, as the agent stores it), for the key of `csr_pem`.
pub fn sign(
    environment: &str,
    checks: Vec<CheckResult>,
    facts: BTreeMap<String, String>,
    key_pem: &str,
    csr_pem: &str,
    now_ms: i64,
) -> Result<RunnerAttestation> {
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
    crate::ontology::validate_identifier("environment", environment)?;
    let key = rcgen::KeyPair::from_pem(key_pem).context("reading the runner key")?;
    let rng = ring::rand::SystemRandom::new();
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng)
            .map_err(|error| anyhow::anyhow!("the runner key is not ECDSA P-256: {error}"))?;
    let statement = RunnerAttestationStatement {
        environment: environment.into(),
        checked_at: now_ms,
        passed: checks.iter().all(|check| check.passed),
        checks,
        facts,
        key_fingerprint: csr_fingerprint(csr_pem)?,
    };
    let signature = signer
        .sign(&rng, &canonical_bytes(&statement)?)
        .map_err(|_| anyhow::anyhow!("signing the runner attestation failed"))?;
    Ok(RunnerAttestation {
        schema: ATTESTATION_SCHEMA.into(),
        algorithm: ATTESTATION_ALGORITHM.into(),
        statement,
        signature: STANDARD.encode(signature.as_ref()),
    })
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
    if evidence.schema != ATTESTATION_SCHEMA || evidence.algorithm != ATTESTATION_ALGORITHM {
        return Err(AttestationRefusal::Malformed(format!(
            "expected {ATTESTATION_SCHEMA} with {ATTESTATION_ALGORITHM}"
        )));
    }
    let (spki, public_key) =
        csr_key(csr_pem).map_err(|error| AttestationRefusal::Malformed(format!("{error:#}")))?;
    let signature = STANDARD
        .decode(&evidence.signature)
        .map_err(|_| AttestationRefusal::SignatureInvalid)?;
    let message = canonical_bytes(&evidence.statement)
        .map_err(|error| AttestationRefusal::Malformed(error.to_string()))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&message, &signature)
        .map_err(|_| AttestationRefusal::SignatureInvalid)?;
    let statement = &evidence.statement;
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
    let encoded = serde_json::to_vec(evidence)
        .map_err(|error| AttestationRefusal::Malformed(error.to_string()))?;
    Ok(Binding {
        evidence_digest: sha256_label(&encoded),
        key_fingerprint,
        checked_at: statement.checked_at,
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
    // SEQUENCE { OCTET STRING (32), OCTET STRING (32) }
    let mut content = vec![0x30, 68, 0x04, 32];
    content.extend(raw(&binding.evidence_digest)?);
    content.extend([0x04, 32]);
    content.extend(raw(&binding.key_fingerprint)?);
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
    if value.len() != 70 || value[..4] != [0x30, 68, 0x04, 32] || value[36..38] != [0x04, 32] {
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
pub async fn set_policy(ctx: &mut Ctx, environment: &str, max_age_ms: u64) -> Result<String> {
    let policy = RunnerAttestationPolicy::required(max_age_ms)?;
    let mut object = crate::environment::environment(ctx, environment).await?;
    object
        .properties
        .insert(POLICY_PROPERTY.into(), serde_json::to_string(&policy)?);
    object.updated = crate::now_millis();
    ctx.put(object).await?;
    Ok(format!(
        "{environment} requires runner attestation, evidence at most {max_age_ms} ms old"
    ))
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
        sign(
            environment,
            vec![CheckResult {
                check: "port 8443".into(),
                passed: true,
                reason: "free".into(),
            }],
            facts
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            &key.0,
            &key.1,
            now_ms,
        )
        .unwrap()
    }

    const NOW: i64 = 1_800_000_000_000;
    const POLICY: RunnerAttestationPolicy = RunnerAttestationPolicy {
        require_runner_attestation: true,
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
        let mut tampered = good.clone();
        tampered
            .statement
            .facts
            .insert("architecture".into(), "x86_64".into());
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
            "prod",
            vec![CheckResult {
                check: "disk /var".into(),
                passed: false,
                reason: "1 byte free".into(),
            }],
            BTreeMap::new(),
            &key.0,
            &key.1,
            NOW,
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

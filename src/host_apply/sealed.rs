//! Sealed values a runtime hands the host applier (ADR 0048 §4, Host).
//!
//! The runtime opens a host step's sealed values in memory and writes them,
//! with their ciphertexts, to [`SEALED_FILE`] next to the request, in a spool
//! on memory-backed storage. The applier cannot open a value itself, so it
//! binds what it reads to the approved step instead: the same slots in the
//! same order, and each ciphertext's digest equal to the one the approved
//! step names. A forged value can therefore land only in a slot an approved
//! step names. Errors name the slot, never a value.
//!
//! The same document carries the workload certificate a step issues
//! (ADR 0046 §4), whose private key the runtime generated: the applier
//! accepts it only when it is signed by the approved issuer for exactly the
//! approved grant. During an issuer rotation (ADR 0046 §7) the document also
//! carries the approved rotation plans the runtime verified: the applier
//! checks them against its own approval policy, and admits a further issuer
//! in the trust bundle, or a renewal from the next issuer, only as one of
//! them proves.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::host_apply::HostApprovalPolicy;
use crate::identity_issuer::{IssuerProof, Proven};
use crate::plan::SealedStep;
use crate::sealed_secret::{SealedTarget, SealedValue, SecretRef};
use crate::workload_identity::{IdentityGrant, IssuedIdentity};

pub const SEALED_SCHEMA: &str = "tenkai.host-sealed-values.v1";
/// The sealed values inside a spooled instance directory.
pub const SEALED_FILE: &str = "sealed.json";
/// Largest [`SEALED_FILE`] the applier reads.
pub const MAX_SEALED_BYTES: u64 = 4 * 1024 * 1024;

/// One opened value and the ciphertext it was opened from.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSealedValue {
    pub secret: String,
    pub key: String,
    /// The sealed ciphertext (standard base64), so the applier can recompute
    /// the digest the approved step names.
    pub ciphertext: String,
    /// Standard base64 of the opened value.
    #[serde(with = "zeroizing_string")]
    pub value: Zeroizing<String>,
}

/// Serde for a value that is wiped when dropped.
mod zeroizing_string {
    use serde::{Deserialize as _, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(
        value: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

impl std::fmt::Debug for HostSealedValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostSealedValue")
            .field("secret", &self.secret)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// [`SEALED_FILE`]: every value one host step writes, in the step's order,
/// and the workload certificate it installs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSealedValues {
    pub schema: String,
    pub values: Vec<HostSealedValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<HostIdentity>,
    /// Approved rotation plans that prove the further issuers of the
    /// certificate's trust bundle, or a renewal from the next issuer. Sent
    /// only with such a certificate, which an older applier refuses anyway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_proofs: Vec<IssuerProof>,
}

/// What the applier checks [`HostSealedValues::issuer_proofs`] against: its
/// approval policy, loaded only when a proof is spooled, for one environment
/// at one time.
pub struct IssuerTrust<'a> {
    pub policy: &'a dyn Fn() -> Result<HostApprovalPolicy>,
    pub environment: &'a str,
    pub now_ms: i64,
}

/// A workload certificate the runtime issued, as PEM.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    pub certificate: String,
    #[serde(with = "zeroizing_string")]
    pub key: Zeroizing<String>,
    pub ca: String,
}

impl std::fmt::Debug for HostIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostIdentity")
            .finish_non_exhaustive()
    }
}

impl From<&IssuedIdentity> for HostIdentity {
    fn from(issued: &IssuedIdentity) -> Self {
        Self {
            certificate: issued.certificate.clone(),
            key: issued.key.clone(),
            ca: issued.ca.clone(),
        }
    }
}

/// A value bound to an approved slot, ready to write.
pub struct BoundSecret {
    pub secret: String,
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for BoundSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundSecret")
            .field("secret", &self.secret)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl HostSealedValues {
    /// The document for `values`, already checked by the runtime against the
    /// plan step it writes.
    pub fn new(
        values: Vec<HostSealedValue>,
        identity: Option<HostIdentity>,
        issuer_proofs: Vec<IssuerProof>,
    ) -> Self {
        Self {
            schema: SEALED_SCHEMA.into(),
            values,
            identity,
            issuer_proofs,
        }
    }

    /// Parse the document, refusing other schemas and unknown fields. A
    /// parse error never quotes the input.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("{SEALED_FILE} is not a valid sealed-values document"))?;
        if parsed.schema != SEALED_SCHEMA {
            bail!("{SEALED_FILE} is not a {SEALED_SCHEMA} document");
        }
        Ok(parsed)
    }

    /// Bind the values to `approved`, the sealed slots of the verified step
    /// of `instance` in `environment`: the same slots in the same order, and
    /// each ciphertext's digest the approved one.
    pub fn bind(
        &self,
        environment: &str,
        instance: &str,
        approved: &[SealedStep],
    ) -> Result<Vec<BoundSecret>> {
        let slots = self.values.iter().map(|value| (&value.secret, &value.key));
        if !slots.eq(approved.iter().map(|step| (&step.secret, &step.key))) {
            bail!("the sealed values do not name the slots the approved step writes");
        }
        approved
            .iter()
            .zip(&self.values)
            .map(|(step, value)| {
                let slot = SecretRef::new(&step.secret, &step.key)?;
                // Path segments on the host: a leading letter or digit, so
                // never `.` or `..`.
                crate::ontology::validate_identifier("secret key", &step.key)?;
                let target = SealedTarget::new(environment, instance, slot)?;
                let sealed = SealedValue {
                    format_version: 1,
                    ciphertext: value.ciphertext.clone(),
                    wraps: Vec::new(),
                };
                if crate::sealed_secret::digest(&target, &sealed)? != step.digest {
                    bail!(
                        "sealed {}/{} does not match the approved step's digest",
                        step.secret,
                        step.key
                    );
                }
                let plain = STANDARD.decode(value.value.as_bytes()).map_err(|_| {
                    anyhow::anyhow!("sealed {}/{} is not standard base64", step.secret, step.key)
                })?;
                Ok(BoundSecret {
                    secret: step.secret.clone(),
                    key: step.key.clone(),
                    value: Zeroizing::new(plain),
                })
            })
            .collect()
    }

    /// Bind the workload certificate to `approved`, the grant of the
    /// verified step: one is spooled exactly when the step grants one, and
    /// it is signed by the approved issuer for exactly the approved names,
    /// with only proven further issuers in its bundle.
    pub fn bind_identity(
        &self,
        approved: Option<&IdentityGrant>,
        trust: &IssuerTrust<'_>,
    ) -> Result<Option<IssuedIdentity>> {
        match (&self.identity, approved) {
            (None, None) => Ok(None),
            (Some(identity), Some(grant)) => {
                let proven = self.proven(trust)?;
                check_bundle(identity.issued(grant), &proven, trust.now_ms).map(Some)
            }
            (None, Some(_)) => {
                bail!("the approved step grants a workload certificate, and none was spooled")
            }
            (Some(_), None) => {
                bail!("a workload certificate was spooled for a step that grants none")
            }
        }
    }

    /// Bind a renewed certificate to `recorded`, the grant the applier
    /// installed. It is that grant from the same issuer, or, once an
    /// approved issue plan replaced that issuer, the same grant from the
    /// issuer that replaced it.
    pub fn bind_renewal(
        &self,
        recorded: &IdentityGrant,
        trust: &IssuerTrust<'_>,
    ) -> Result<IssuedIdentity> {
        let identity = self
            .identity
            .as_ref()
            .context("the renewal carries no certificate")?;
        let proven = self.proven(trust)?;
        let first = crate::workload_identity::bundle_fingerprints(&identity.ca)?
            .into_iter()
            .next();
        let grant = if first.as_ref() == Some(&recorded.issuer_fingerprint) {
            recorded.clone()
        } else {
            proven
                .iter()
                .filter_map(|proven| match proven {
                    Proven::Issued { replaced, issuing }
                        if replaced.generation == recorded.issuer_generation
                            && replaced.fingerprint == recorded.issuer_fingerprint =>
                    {
                        Some(issuing)
                    }
                    _ => None,
                })
                .find(|issuing| first.as_ref() == Some(&issuing.fingerprint))
                .map(|issuing| IdentityGrant {
                    issuer_generation: issuing.generation,
                    issuer_fingerprint: issuing.fingerprint.clone(),
                    ..recorded.clone()
                })
                .with_context(|| {
                    format!(
                        "the renewed certificate is not from the recorded issuer {}, and no approved issue plan replaced it with its issuer",
                        recorded.issuer_fingerprint
                    )
                })?
        };
        check_bundle(identity.issued(&grant), &proven, trust.now_ms)
    }

    /// The spooled proofs that verify under the applier's policy. One that
    /// does not is left out, so the issuer it would prove is refused by
    /// name; with none spooled the policy is never read.
    fn proven(&self, trust: &IssuerTrust<'_>) -> Result<Vec<Proven>> {
        if self.issuer_proofs.is_empty() {
            return Ok(Vec::new());
        }
        let policy = (trust.policy)()?;
        Ok(self
            .issuer_proofs
            .iter()
            .filter_map(|proof| {
                crate::identity_issuer::verify_proof(
                    Some(&policy),
                    trust.environment,
                    proof,
                    trust.now_ms,
                )
                .inspect_err(|error| eprintln!("an issuer proof was refused: {error:#}"))
                .ok()
            })
            .collect())
    }
}

impl HostIdentity {
    fn issued(&self, grant: &IdentityGrant) -> IssuedIdentity {
        IssuedIdentity {
            grant: grant.clone(),
            certificate: self.certificate.clone(),
            key: self.key.clone(),
            ca: self.ca.clone(),
        }
    }
}

/// Check `issued` where the applier writes it, and that every issuer of its
/// bundle after the granted one is one generation from it and trusted by
/// an approved rotation plan in `proven`.
fn check_bundle(issued: IssuedIdentity, proven: &[Proven], now_ms: i64) -> Result<IssuedIdentity> {
    let trust = crate::workload_identity::check_issued_trust(&issued, now_ms / 1000)?;
    for fingerprint in trust.iter().skip(1) {
        let approved = proven.iter().filter_map(Proven::trusted).any(|trusted| {
            trusted.fingerprint == *fingerprint
                && trusted.generation.abs_diff(issued.grant.issuer_generation) == 1
        });
        if !approved {
            bail!(
                "ca.pem holds issuer {fingerprint}, which no approved rotation plan proves next to the granted issuer"
            );
        }
    }
    Ok(issued)
}

/// Filesystem types whose pages stay in memory (reaching disk only through
/// swap): tmpfs and ramfs.
const MEMORY_BACKED: [i64; 2] = [0x0102_1994, 0x8584_58f6];

/// Whether the filesystem `f_type` reports is memory-backed.
pub fn is_memory_backed(f_type: i64) -> bool {
    MEMORY_BACKED.contains(&f_type)
}

/// Refuse `path` unless it is on memory-backed storage.
pub fn require_memory_backed(path: &std::path::Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `c_path` is a valid NUL-terminated path and `stat` is a
    // zeroed, writable statfs that outlives the call.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error()).map_err(|error| {
            anyhow::anyhow!("reading the filesystem of {}: {error}", path.display())
        });
    }
    #[allow(clippy::unnecessary_cast)]
    let f_type = stat.f_type as i64;
    if !is_memory_backed(f_type) {
        bail!(
            "{} is on persistent storage; sealed host values are written only to a memory-backed directory (tmpfs)",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "a-distinct-plain-value";

    fn approved(digest: &str) -> Vec<SealedStep> {
        vec![SealedStep {
            secret: "db".into(),
            key: "password".into(),
            digest: digest.into(),
        }]
    }

    fn values(ciphertext: &str) -> HostSealedValues {
        HostSealedValues::new(
            vec![HostSealedValue {
                secret: "db".into(),
                key: "password".into(),
                ciphertext: ciphertext.into(),
                value: Zeroizing::new(STANDARD.encode(VALUE)),
            }],
            None,
            Vec::new(),
        )
    }

    fn digest_of(ciphertext: &str) -> String {
        let target =
            SealedTarget::new("edge", "api", SecretRef::new("db", "password").unwrap()).unwrap();
        crate::sealed_secret::digest(
            &target,
            &SealedValue {
                format_version: 1,
                ciphertext: ciphertext.into(),
                wraps: Vec::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn only_the_approved_slot_and_ciphertext_bind() {
        let ciphertext = STANDARD.encode(b"sealed-bytes");
        let bound = values(&ciphertext)
            .bind("edge", "api", &approved(&digest_of(&ciphertext)))
            .unwrap();
        assert_eq!(bound[0].value.as_slice(), VALUE.as_bytes());

        let other = STANDARD.encode(b"other-bytes");
        let refusals = [
            // Another ciphertext than the approved one.
            values(&other).bind("edge", "api", &approved(&digest_of(&ciphertext))),
            // The approved ciphertext for another instance.
            values(&ciphertext).bind("edge", "web", &approved(&digest_of(&ciphertext))),
            // A slot the step does not write.
            values(&ciphertext).bind("edge", "api", &[]),
        ];
        for refused in refusals {
            let error = format!("{:#}", refused.expect_err("refused"));
            assert!(!error.contains(VALUE), "{error}");
        }
        // Debug output and parse errors never carry the value.
        assert!(!format!("{:?}", values(&ciphertext)).contains(&STANDARD.encode(VALUE)));
        let error = HostSealedValues::parse(format!("{{\"x\":\"{VALUE}\"}}").as_bytes())
            .unwrap_err()
            .to_string();
        assert!(!error.contains(VALUE), "{error}");
    }

    #[test]
    fn a_key_that_could_name_a_parent_directory_never_binds() {
        let ciphertext = STANDARD.encode(b"sealed-bytes");
        let mut document = values(&ciphertext);
        document.values[0].key = "..".into();
        let mut steps = approved(&digest_of(&ciphertext));
        steps[0].key = "..".into();
        assert!(document.bind("edge", "api", &steps).is_err());
    }

    #[test]
    fn only_tmpfs_and_ramfs_count_as_memory_backed() {
        assert!(is_memory_backed(0x0102_1994));
        assert!(is_memory_backed(0x8584_58f6));
        // ext4 and xfs.
        assert!(!is_memory_backed(0xef53));
        assert!(!is_memory_backed(0x5846_5342));
    }
}

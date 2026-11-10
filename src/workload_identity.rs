//! Workload certificates (ADR 0046 §1, §3, §4).
//!
//! A release declares `[deploy.identity]` ([`IdentitySection`]). The planner
//! turns it into an [`IdentityGrant`] per instance with [`grant`], and the
//! approved step carries the grant. The runtime computes the same grant from
//! the verified manifest and refuses a step whose grant differs, opens the
//! environment issuer only when its fingerprint is the granted one, and
//! issues a fresh key and certificate with [`issue`]. The target receives
//! [`IssuedIdentity::files`]; the server never sees the key.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::identity_issuer::IssuerKey;
use crate::software_executor::INSTANCE_PLACEHOLDER;

/// Lifetime of a workload certificate. Renewal (ADR 0046 §3) starts at two
/// thirds of it.
pub const WORKLOAD_CERTIFICATE_TTL_SECS: i64 = 24 * 60 * 60;

/// Files of an issued identity, as written to the target.
pub const CERTIFICATE_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";
pub const CA_FILE: &str = "ca.pem";
/// The grant the certificate was issued for, recorded beside it so renewal
/// re-issues exactly that grant without the server.
pub const GRANT_FILE: &str = "grant.json";

/// `[deploy.identity]`: the certificate a release asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    pub certificate: CertificateRole,
    /// How the product picks up a renewed certificate. Files mounted with
    /// `subPath` and values passed as environment variables are read only
    /// at start, so such a product declares `"restart"`.
    pub reload: Reload,
    /// DNS names a server certificate carries. `${TENKAI_INSTANCE}` expands
    /// to the instance name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateRole {
    Server,
    Client,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reload {
    Runtime,
    Restart,
}

/// What an approved step grants one instance. Covered by the plan digest;
/// the runtime issues exactly this or nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityGrant {
    /// `tenkai://<environment>/<instance>`.
    pub uri: String,
    /// Expanded DNS names; only on a server certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
    pub certificate: CertificateRole,
    pub reload: Reload,
    /// The issuer generation and key fingerprint that sign it.
    pub issuer_generation: u64,
    pub issuer_fingerprint: String,
    /// The peers the dependency bindings allow (ADR 0046 §5). Omitted when
    /// there are none, so a grant without peers keeps its digest.
    #[serde(default, skip_serializing_if = "Peers::is_empty")]
    pub peers: Peers,
}

/// Which identities one instance may accept, per contract, as the plan's
/// bindings give them (ADR 0046 §5). It names identities only: no keys,
/// secrets or endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peers {
    /// Contract the instance requires → the provider it accepts as server.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servers: BTreeMap<String, String>,
    /// Contract the instance provides → the dependents it accepts as clients.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub clients: BTreeMap<String, BTreeSet<String>>,
}

impl Peers {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.clients.is_empty()
    }
}

/// The identity of `instance` in `environment`: the URI its certificate
/// carries.
pub fn uri(environment: &str, instance: &str) -> String {
    format!("tenkai://{environment}/{instance}")
}

/// Check `[deploy.identity]` at publish and at the runtime. A release that
/// allows several instances must name each DNS name per instance.
pub fn validate(section: &IdentitySection, allows_several: bool) -> Result<()> {
    if section.certificate == CertificateRole::Client && !section.dns_names.is_empty() {
        bail!(
            "[deploy.identity] dns_names apply to server certificates; a client certificate names none"
        );
    }
    for name in &section.dns_names {
        if allows_several && !name.contains(INSTANCE_PLACEHOLDER) {
            bail!(
                "[deploy.identity] dns name {name:?} must contain {INSTANCE_PLACEHOLDER}: two instances of this release would share it"
            );
        }
        check_dns_name(&crate::software_executor::substitute_instance_placeholder(
            name, "instance",
        ))
        .with_context(|| format!("[deploy.identity] dns name {name:?}"))?;
    }
    Ok(())
}

/// The grant `section` gives `instance` of `environment`, signed by `issuer`.
/// The planner and the runtime both call it; they must agree.
pub fn grant(
    section: &IdentitySection,
    environment: &str,
    instance: &str,
    issuer: &IssuerKey,
) -> Result<IdentityGrant> {
    let mut dns_names = section
        .dns_names
        .iter()
        .map(|name| crate::software_executor::substitute_instance_placeholder(name, instance))
        .collect::<Vec<_>>();
    for name in &dns_names {
        check_dns_name(name).with_context(|| format!("dns name {name:?} of {instance}"))?;
    }
    dns_names.sort();
    dns_names.dedup();
    Ok(IdentityGrant {
        uri: uri(environment, instance),
        dns_names,
        certificate: section.certificate,
        reload: section.reload,
        issuer_generation: issuer.generation,
        issuer_fingerprint: issuer.fingerprint.clone(),
        peers: Peers::default(),
    })
}

fn check_dns_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 253,
        "a DNS name has 1 to 253 characters"
    );
    for label in name.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-'),
            "{label:?} is not a lowercase DNS label"
        );
    }
    Ok(())
}

/// A key and certificate issued for a grant. The key never leaves the
/// runtime and the target; it is not serialized.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedIdentity {
    pub grant: IdentityGrant,
    pub certificate: String,
    pub key: zeroize::Zeroizing<String>,
    /// The issuer certificate: the trust bundle.
    pub ca: String,
}

impl std::fmt::Debug for IssuedIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedIdentity")
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

/// The files a target holds for one certificate, by name, in write order.
pub type IdentityFiles = [(&'static str, zeroize::Zeroizing<Vec<u8>>); 4];

impl IssuedIdentity {
    /// The files the target holds, by name.
    pub fn files(&self) -> Result<IdentityFiles> {
        Ok([
            (
                CERTIFICATE_FILE,
                self.certificate.as_bytes().to_vec().into(),
            ),
            (KEY_FILE, self.key.as_bytes().to_vec().into()),
            (CA_FILE, self.ca.as_bytes().to_vec().into()),
            (GRANT_FILE, serde_json::to_vec_pretty(&self.grant)?.into()),
        ])
    }
}

/// Issue a fresh key and certificate for `grant` from `issuer`, whose key
/// `issuer_key` opened. Refuses an issuer other than the granted one.
pub fn issue(
    grant: &IdentityGrant,
    issuer: &IssuerKey,
    issuer_key: rcgen::KeyPair,
    now_secs: i64,
) -> Result<IssuedIdentity> {
    ensure!(
        issuer.generation == grant.issuer_generation
            && issuer.fingerprint == grant.issuer_fingerprint,
        "the identity issuer is generation {} ({}), not the granted generation {} ({})",
        issuer.generation,
        issuer.fingerprint,
        grant.issuer_generation,
        grant.issuer_fingerprint
    );
    let signer = rcgen::Issuer::from_ca_cert_pem(&issuer.certificate, issuer_key)
        .context("loading the identity issuer")?;
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = std::iter::once(rcgen::SanType::URI(grant.uri.as_str().try_into()?))
        .chain(
            grant
                .dns_names
                .iter()
                .map(|name| Ok(rcgen::SanType::DnsName(name.as_str().try_into()?)))
                .collect::<Result<Vec<_>>>()?,
        )
        .collect();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, grant.uri.as_str());
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = match grant.certificate {
        CertificateRole::Server => vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
        CertificateRole::Client => vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
        CertificateRole::Both => vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ],
    };
    params.not_before = time::OffsetDateTime::from_unix_timestamp(now_secs - 60)?;
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(now_secs + WORKLOAD_CERTIFICATE_TTL_SECS)?;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(
        &uuid::Uuid::new_v4().into_bytes(),
    ));
    let certificate = params.signed_by(&key, &signer)?.pem();
    let issued = IssuedIdentity {
        grant: grant.clone(),
        certificate,
        key: key.serialize_pem().into(),
        ca: issuer.certificate.clone(),
    };
    // The issuer certificate came from the server: every target gets only
    // what passes the check the host applier runs, so an appended
    // certificate never reaches a trust bundle.
    check_issued(&issued, now_secs)?;
    Ok(issued)
}

/// Check, where the files are written, that the certificate is signed by
/// `ca`, that `ca` is the granted issuer, that its names and key usage are
/// exactly the grant's, that it is valid at `now_secs`, and that `key` is
/// its key. The host applier calls it before it writes anything. Errors
/// never quote the key.
pub fn check_issued(issued: &IssuedIdentity, now_secs: i64) -> Result<()> {
    let leaf = check_certificate(&issued.grant, &issued.certificate, &issued.ca)?;
    ensure!(
        leaf.not_before <= now_secs && now_secs <= leaf.not_after,
        "cert.pem is not valid now"
    );
    // The error never quotes the key.
    let pair = rcgen::KeyPair::from_pem(&issued.key)
        .map_err(|_| anyhow::anyhow!("key.pem is not a valid private key"))?;
    ensure!(
        rcgen::PublicKeyData::subject_public_key_info(&pair) == leaf.public_key,
        "key.pem is not the key of cert.pem"
    );
    Ok(())
}

/// What [`check_certificate`] read from a certificate it accepted.
struct CheckedLeaf {
    not_before: i64,
    not_after: i64,
    /// DER SubjectPublicKeyInfo.
    public_key: Vec<u8>,
}

/// Check that `certificate` is signed by `ca`, that `ca` is the issuer
/// `grant` names, and that its names and key usage are exactly the grant's.
/// Says nothing about time or the key.
fn check_certificate(grant: &IdentityGrant, certificate: &str, ca: &str) -> Result<CheckedLeaf> {
    use x509_parser::prelude::*;
    // Exactly one certificate per file: a workload loads ca.pem as its trust
    // bundle, so an appended block would make it trust another issuer.
    let (rest, ca_pem) = parse_x509_pem(ca.as_bytes())
        .map_err(|error| anyhow::anyhow!("reading ca.pem: {error}"))?;
    ensure!(
        rest.iter().all(u8::is_ascii_whitespace),
        "ca.pem holds more than the issuer certificate"
    );
    let ca_cert = ca_pem
        .parse_x509()
        .map_err(|error| anyhow::anyhow!("parsing ca.pem: {error}"))?;
    ensure!(
        crate::sealing_key::fingerprint(ca_cert.public_key().raw) == grant.issuer_fingerprint,
        "ca.pem is not the granted issuer {}",
        grant.issuer_fingerprint
    );
    let (rest, leaf_pem) = parse_x509_pem(certificate.as_bytes())
        .map_err(|error| anyhow::anyhow!("reading cert.pem: {error}"))?;
    ensure!(
        rest.iter().all(u8::is_ascii_whitespace),
        "cert.pem holds more than one certificate"
    );
    let leaf = leaf_pem
        .parse_x509()
        .map_err(|error| anyhow::anyhow!("parsing cert.pem: {error}"))?;
    leaf.verify_signature(Some(ca_cert.public_key()))
        .map_err(|error| anyhow::anyhow!("cert.pem is not signed by ca.pem: {error}"))?;
    let mut uris = Vec::new();
    let mut dns_names = Vec::new();
    if let Some(names) = leaf
        .subject_alternative_name()
        .map_err(|error| anyhow::anyhow!("reading cert.pem names: {error}"))?
    {
        for name in &names.value.general_names {
            match name {
                GeneralName::URI(uri) => uris.push(uri.to_string()),
                GeneralName::DNSName(dns) => dns_names.push(dns.to_string()),
                other => bail!("cert.pem names {other:?}, which no grant gives"),
            }
        }
    }
    dns_names.sort();
    ensure!(
        uris == [grant.uri.clone()] && dns_names == grant.dns_names,
        "cert.pem names are not the granted ones"
    );
    let usage = leaf
        .extended_key_usage()
        .map_err(|error| anyhow::anyhow!("reading cert.pem key usage: {error}"))?
        .context("cert.pem names no extended key usage")?
        .value;
    let (server, client) = match grant.certificate {
        CertificateRole::Server => (true, false),
        CertificateRole::Client => (false, true),
        CertificateRole::Both => (true, true),
    };
    ensure!(
        usage.server_auth == server
            && usage.client_auth == client
            && !usage.any
            && !usage.code_signing
            && !usage.email_protection
            && !usage.time_stamping
            && !usage.ocsp_signing
            && usage.other.is_empty(),
        "cert.pem key usage is not the granted {:?} role",
        grant.certificate
    );
    Ok(CheckedLeaf {
        not_before: leaf.validity().not_before.timestamp(),
        not_after: leaf.validity().not_after.timestamp(),
        public_key: leaf.public_key().raw.to_vec(),
    })
}

/// A workload certificate a target holds (ADR 0046 §3): the grant recorded
/// beside it, proven by the certificate the issuer signed for exactly that
/// grant. Renewal re-issues this grant and nothing wider: an edited
/// `grant.json` no longer matches the signed certificate and is refused.
/// `reload` is not in the certificate; it only says how the workload picks
/// up a certificate, never what one names, and whoever can edit it can
/// already remove the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledIdentity {
    pub instance: String,
    pub grant: IdentityGrant,
    /// The certificate the target holds, PEM. Renewal replaces only this
    /// one: a target changed since it was read is left to the next pass.
    pub certificate: String,
    /// Its validity, in Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
}

impl InstalledIdentity {
    /// Read what the target holds for `instance` of `environment`: the
    /// certificate, the issuer certificate and the recorded grant. Refuses a
    /// grant for another instance, or one the certificate does not prove.
    /// An expired certificate still proves its grant.
    pub fn read(
        environment: &str,
        instance: &str,
        certificate: &str,
        ca: &str,
        grant_json: &[u8],
    ) -> Result<Self> {
        let grant: IdentityGrant =
            serde_json::from_slice(grant_json).context("reading grant.json")?;
        let uri = format!("tenkai://{environment}/{instance}");
        ensure!(
            grant.uri == uri,
            "grant.json of {instance} grants {}, not {uri}",
            grant.uri
        );
        let leaf = check_certificate(&grant, certificate, ca)
            .with_context(|| format!("the certificate of {instance} does not prove its grant"))?;
        Ok(Self {
            instance: instance.to_owned(),
            grant,
            certificate: certificate.to_owned(),
            not_before: leaf.not_before,
            not_after: leaf.not_after,
        })
    }

    /// Whether renewal is due: two thirds of the lifetime have passed.
    pub fn renewal_due(&self, now_secs: i64) -> bool {
        let lifetime = self.not_after.saturating_sub(self.not_before);
        now_secs >= self.not_before.saturating_add(lifetime / 3 * 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(certificate: CertificateRole, dns_names: &[&str]) -> IdentitySection {
        IdentitySection {
            certificate,
            reload: Reload::Runtime,
            dns_names: dns_names.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    /// A literal DNS name would be shared by two instances of a release
    /// that allows several, so it fails validation; with the placeholder,
    /// or for a single-instance release, it passes.
    #[test]
    fn a_literal_dns_name_in_a_multi_instance_release_fails_validation() {
        let literal = section(CertificateRole::Server, &["api.example.internal"]);
        let error = format!("{:#}", validate(&literal, true).unwrap_err());
        assert!(error.contains(INSTANCE_PLACEHOLDER), "{error}");
        validate(&literal, false).unwrap();
        validate(
            &section(
                CertificateRole::Server,
                &["${TENKAI_INSTANCE}.example.internal"],
            ),
            true,
        )
        .unwrap();
        assert!(validate(&section(CertificateRole::Client, &["a.internal"]), false).is_err());
        assert!(validate(&section(CertificateRole::Server, &["Not_A_Name"]), false).is_err());
    }

    /// An issuer whose key is held in the clear, as a runtime holds it
    /// once opened.
    fn issuer() -> (IssuerKey, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let certificate = params.self_signed(&key).unwrap();
        let issuer = IssuerKey {
            generation: 1,
            fingerprint: crate::sealing_key::fingerprint(
                &rcgen::PublicKeyData::subject_public_key_info(&key),
            ),
            certificate: certificate.pem(),
            sealed_key: crate::sealed_secret::SealedValue {
                format_version: 1,
                ciphertext: String::new(),
                wraps: Vec::new(),
            },
        };
        (issuer, key)
    }

    #[test]
    fn the_host_accepts_only_a_whole_current_certificate_for_the_grant() {
        let (issuer_key, key) = issuer();
        let grant = grant(
            &section(CertificateRole::Server, &["api.internal"]),
            "prod",
            "api",
            &issuer_key,
        )
        .unwrap();
        let now = crate::now_millis() / 1000;
        let issued = issue(&grant, &issuer_key, key, now).unwrap();
        check_issued(&issued, now).unwrap();

        let refused = |issued: &IssuedIdentity, now: i64| {
            let error = format!("{:#}", check_issued(issued, now).unwrap_err());
            assert!(!error.contains(issued.key.as_str()), "{error}");
            error
        };
        // Another key than the certificate's.
        let mut other_key = issued.clone();
        other_key.key = rcgen::KeyPair::generate().unwrap().serialize_pem().into();
        assert!(refused(&other_key, now).contains("not the key"));
        // Replayed after it expired.
        let later = now + 2 * WORKLOAD_CERTIFICATE_TTL_SECS;
        assert!(refused(&issued, later).contains("not valid now"));
        // A grant for another role than the certificate carries.
        let mut client = issued.clone();
        client.grant.certificate = CertificateRole::Both;
        assert!(refused(&client, now).contains("key usage"));
        // Another issuer appended to the trust bundle.
        let (other, _) = issuer();
        let mut bundle = issued.clone();
        bundle.ca = format!("{}{}", issued.ca, other.certificate);
        assert!(refused(&bundle, now).contains("more than the issuer"));
        // The runtime refuses to issue from such a bundle at all.
        let (mut appended, key) = issuer();
        appended.certificate = format!("{}{}", appended.certificate, other.certificate);
        let grant = super::grant(
            &section(CertificateRole::Server, &["api.internal"]),
            "prod",
            "api",
            &appended,
        )
        .unwrap();
        assert!(issue(&grant, &appended, key, now).is_err());
    }

    /// Renewal re-issues only what the signed certificate proves: a
    /// `grant.json` edited in the target, or moved to another instance, is
    /// refused, and renewal falls due at two thirds of the lifetime.
    #[test]
    fn a_recorded_grant_counts_only_as_far_as_the_certificate_proves_it() {
        let (issuer_key, key) = issuer();
        let grant = grant(
            &section(CertificateRole::Server, &["api.internal"]),
            "prod",
            "api",
            &issuer_key,
        )
        .unwrap();
        let now = crate::now_millis() / 1000;
        let issued = issue(&grant, &issuer_key, key, now).unwrap();
        let read = |environment: &str, instance: &str, grant: &IdentityGrant| {
            InstalledIdentity::read(
                environment,
                instance,
                &issued.certificate,
                &issued.ca,
                &serde_json::to_vec(grant).unwrap(),
            )
        };
        let installed = read("prod", "api", &grant).unwrap();
        assert_eq!(installed.grant, grant);

        let mut wider = grant.clone();
        wider.dns_names.push("bank.example".into());
        assert!(read("prod", "api", &wider).is_err());
        let mut both = grant.clone();
        both.certificate = CertificateRole::Both;
        assert!(read("prod", "api", &both).is_err());
        // Another instance's Secret copied under this instance's name.
        assert!(read("prod", "web", &grant).is_err());

        // Still proves its grant once expired, so a long outage renews.
        assert!(!installed.renewal_due(now));
        let lifetime = installed.not_after - installed.not_before;
        let due_at = installed.not_before + lifetime / 3 * 2;
        assert!(!installed.renewal_due(due_at - 1));
        assert!(installed.renewal_due(due_at));
        assert!(installed.renewal_due(now + 2 * WORKLOAD_CERTIFICATE_TTL_SECS));
    }
}

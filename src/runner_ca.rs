//! The runner certificate authority (#674).
//!
//! An intermediate CA, separate from release and approval signing keys,
//! issues each enrolled runtime agent a short-lived client certificate. The
//! certificate's only identity is a URI subject alternative name,
//! `urn:tenkai:runner:<environment>:<credential hex>`: exactly one
//! environment and the runner's registry id (#673), the digest of the
//! credential its enrollment produced, so registry revocation applies to
//! certificates as it does to bearer credentials. The agent generates its
//! key and sends only a CSR; no private key leaves its host.

use std::path::Path;

use anyhow::{Context as _, Result, bail};

/// How long an issued runner certificate is valid.
pub const RUNNER_CERTIFICATE_TTL_SECS: i64 = 24 * 60 * 60;

const IDENTITY_PREFIX: &str = "urn:tenkai:runner:";

/// The runner a verified certificate names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerIdentity {
    pub environment: String,
    /// `sha256:<hex>`: the registry id of the runner's credential.
    pub runner_id: String,
}

impl RunnerIdentity {
    fn uri(&self) -> Result<String> {
        crate::ontology::validate_identifier("environment", &self.environment)?;
        let hex = self
            .runner_id
            .strip_prefix("sha256:")
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .context("runner id must be a sha256 digest")?;
        Ok(format!("{IDENTITY_PREFIX}{}:{hex}", self.environment))
    }

    fn from_uri(uri: &str) -> Option<Self> {
        let (environment, hex) = uri.strip_prefix(IDENTITY_PREFIX)?.rsplit_once(':')?;
        crate::ontology::validate_identifier("environment", environment).ok()?;
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Self {
            environment: environment.into(),
            runner_id: format!("sha256:{hex}"),
        })
    }
}

/// The CA certificate and key that issue runner certificates.
pub struct RunnerCa {
    cert_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl RunnerCa {
    /// A new self-signed runner CA, as `(certificate PEM, key PEM)`, for
    /// `tenkaictl runner-ca init`. Operators may bring their own instead.
    pub fn generate(common_name: &str) -> Result<(String, String)> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// The CA from its certificate and key PEM files.
    pub fn load(cert: &Path, key: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert)
            .with_context(|| format!("reading runner CA certificate {}", cert.display()))?;
        let key_pem = std::fs::read_to_string(key)
            .with_context(|| format!("reading runner CA key {}", key.display()))?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = rcgen::KeyPair::from_pem(key_pem).context("parsing the runner CA key")?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(cert_pem, key)
            .context("parsing the runner CA certificate")?;
        let ca = Self {
            cert_pem: cert_pem.into(),
            issuer,
        };
        ca.self_check()?;
        Ok(ca)
    }

    /// Refuse a certificate and key that do not belong together, before any
    /// enrollment spends a token on a certificate nothing would accept: a
    /// probe certificate it issues must verify against its own certificate.
    fn self_check(&self) -> Result<()> {
        let key = rcgen::KeyPair::generate()?;
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())?
            .serialize_request(&key)?
            .pem()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let probe = RunnerIdentity {
            environment: "self-check".into(),
            runner_id: format!("sha256:{}", "0".repeat(64)),
        };
        let issued = self.issue(&csr, &probe, now)?;
        let der = x509_parser::pem::parse_x509_pem(issued.as_bytes())
            .map_err(|error| anyhow::anyhow!("reading the probe certificate: {error}"))?
            .1
            .contents;
        self.verify(&der, now)
            .context("the runner CA key does not match its certificate")?;
        Ok(())
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A client certificate for `identity` over the key of `csr_pem`, valid
    /// from `now_secs` for [`RUNNER_CERTIFICATE_TTL_SECS`]. Whatever names
    /// or extensions the CSR asks for are ignored: the identity is ours.
    pub fn issue(&self, csr_pem: &str, identity: &RunnerIdentity, now_secs: i64) -> Result<String> {
        let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .context("the CSR is not a valid, self-signed certificate request")?;
        let uri = identity.uri()?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params.subject_alt_names = vec![rcgen::SanType::URI(uri.as_str().try_into()?)];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, identity.runner_id.as_str());
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = time::OffsetDateTime::from_unix_timestamp(now_secs - 60)?;
        params.not_after =
            time::OffsetDateTime::from_unix_timestamp(now_secs + RUNNER_CERTIFICATE_TTL_SECS)?;
        params.serial_number = Some(rcgen::SerialNumber::from_slice(
            &uuid::Uuid::new_v4().into_bytes(),
        ));
        Ok(params.signed_by(&csr.public_key, &self.issuer)?.pem())
    }

    /// The runner a presented leaf certificate (DER) names, once it is
    /// signed by this CA, valid at `now_secs`, and carries exactly one
    /// runner identity. The TLS handshake already checked the chain against
    /// the configured client CA; this binds it to the runner CA itself, so a
    /// certificate from any other trusted CA cannot claim a runner.
    pub fn verify(&self, leaf_der: &[u8], now_secs: i64) -> Result<RunnerIdentity> {
        use x509_parser::prelude::*;
        let (_, ca) = parse_x509_pem(self.cert_pem.as_bytes())
            .map_err(|error| anyhow::anyhow!("parsing the runner CA certificate: {error}"))?;
        let ca = ca
            .parse_x509()
            .map_err(|error| anyhow::anyhow!("parsing the runner CA certificate: {error}"))?;
        let (_, leaf) = X509Certificate::from_der(leaf_der)
            .map_err(|error| anyhow::anyhow!("parsing the client certificate: {error}"))?;
        leaf.verify_signature(Some(ca.public_key())).map_err(|_| {
            anyhow::anyhow!("the client certificate was not issued by the runner CA")
        })?;
        let validity = leaf.validity();
        if now_secs < validity.not_before.timestamp() || now_secs > validity.not_after.timestamp() {
            bail!("the client certificate is not valid now");
        }
        let names = leaf
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|extension| extension.value.general_names.clone())
            .unwrap_or_default();
        let mut identities = names.iter().filter_map(|name| match name {
            GeneralName::URI(uri) => RunnerIdentity::from_uri(uri),
            _ => None,
        });
        match (identities.next(), identities.next()) {
            (Some(identity), None) => Ok(identity),
            _ => bail!("the client certificate names no single runner"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(environment: &str) -> RunnerIdentity {
        RunnerIdentity {
            environment: environment.into(),
            runner_id: format!("sha256:{}", "ab".repeat(32)),
        }
    }

    fn leaf_der(pem: &str) -> Vec<u8> {
        x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .unwrap()
            .1
            .contents
    }

    fn csr() -> (rcgen::KeyPair, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["evil.example".into()]).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            "urn:tenkai:runner:other:00".try_into().unwrap(),
        ));
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        (key, csr)
    }

    #[test]
    fn issues_one_environment_bound_identity_and_verifies_it() {
        let (cert, key) = RunnerCa::generate("site runner CA").unwrap();
        let ca = RunnerCa::from_pem(&cert, &key).unwrap();
        let (_, request) = csr();
        let now = 1_800_000_000;
        let issued = ca.issue(&request, &identity("prod"), now).unwrap();
        // The CSR's own names are ignored; only the issued identity counts.
        assert_eq!(
            ca.verify(&leaf_der(&issued), now).unwrap(),
            identity("prod")
        );
        let expired = now + RUNNER_CERTIFICATE_TTL_SECS + 1;
        assert!(ca.verify(&leaf_der(&issued), expired).is_err());
    }

    #[test]
    fn a_certificate_from_another_ca_claims_no_runner() {
        let (cert, key) = RunnerCa::generate("site runner CA").unwrap();
        let ca = RunnerCa::from_pem(&cert, &key).unwrap();
        let (other_cert, other_key) = RunnerCa::generate("someone else").unwrap();
        let other = RunnerCa::from_pem(&other_cert, &other_key).unwrap();
        let (_, request) = csr();
        let forged = other
            .issue(&request, &identity("prod"), 1_800_000_000)
            .unwrap();
        let refused = ca.verify(&leaf_der(&forged), 1_800_000_000).unwrap_err();
        assert!(
            refused.to_string().contains("not issued by the runner CA"),
            "{refused}"
        );
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let (cert, _) = RunnerCa::generate("site runner CA").unwrap();
        let (_, other_key) = RunnerCa::generate("someone else").unwrap();
        let refused = RunnerCa::from_pem(&cert, &other_key).err().unwrap();
        assert!(
            format!("{refused:#}").contains("does not match"),
            "{refused:#}"
        );
    }

    #[test]
    fn identities_are_strict() {
        assert!(RunnerIdentity::from_uri("urn:tenkai:runner:prod:00").is_none());
        assert!(
            RunnerIdentity::from_uri(&format!("urn:tenkai:runner:a:b:{}", "ab".repeat(32)))
                .is_none()
        );
        assert!(identity("bad env").uri().is_err());
        assert!(
            RunnerIdentity {
                runner_id: "tkr_x".into(),
                ..identity("prod")
            }
            .uri()
            .is_err()
        );
    }
}

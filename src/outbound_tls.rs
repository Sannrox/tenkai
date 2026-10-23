//! One trust setting for every outbound TLS client (#633).
//!
//! `TENKAI_CA_BUNDLE` names a PEM file of CA certificates that every Tenkai
//! TLS client trusts in addition to the built-in roots: the registry and
//! hub-model HTTP clients, OIDC discovery, webhooks, telemetry, remote gates,
//! the runtime agent, the remote CLI and its login, the gRPC outcome
//! provider, the remote backend and the PostgreSQL store.
//! `TENKAI_TLS_SYSTEM_ROOTS=false` drops the built-in roots, so only the
//! bundle is trusted; that needs a bundle, and the remote backend, whose
//! client cannot drop its roots yet, is refused over HTTPS. A bundle that
//! cannot be read or holds a certificate that is not a usable trust anchor
//! fails closed, never falls back to the built-in roots alone.
//!
//! Kubernetes clients trust the CA in their kubeconfig, which is per cluster.

use anyhow::{Context as _, Result, bail};

pub const CA_BUNDLE_ENV: &str = "TENKAI_CA_BUNDLE";
pub const SYSTEM_ROOTS_ENV: &str = "TENKAI_TLS_SYSTEM_ROOTS";

/// The outbound trust of this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTrust {
    /// PEM certificates from `TENKAI_CA_BUNDLE`, if set.
    pub bundle_pem: Option<Vec<u8>>,
    /// False when `TENKAI_TLS_SYSTEM_ROOTS=false`.
    pub system_roots: bool,
}

impl OutboundTrust {
    pub fn from_env() -> Result<Self> {
        let bundle_pem =
            match std::env::var_os(CA_BUNDLE_ENV).filter(|path| !path.is_empty()) {
                Some(path) => Some(std::fs::read(&path).with_context(|| {
                    format!("reading {CA_BUNDLE_ENV} {}", path.to_string_lossy())
                })?),
                None => None,
            };
        let system_roots = match std::env::var(SYSTEM_ROOTS_ENV) {
            Ok(value) => match value.as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => bail!("{SYSTEM_ROOTS_ENV} must be true or false, not {other:?}"),
            },
            Err(_) => true,
        };
        Self::new(bundle_pem, system_roots)
    }

    pub fn new(bundle_pem: Option<Vec<u8>>, system_roots: bool) -> Result<Self> {
        let trust = Self {
            bundle_pem,
            system_roots,
        };
        if !system_roots && trust.bundle_pem.is_none() {
            bail!("{SYSTEM_ROOTS_ENV}=false needs {CA_BUNDLE_ENV}: nothing would be trusted");
        }
        trust.certificates()?;
        Ok(trust)
    }

    fn certificates(&self) -> Result<Vec<reqwest::Certificate>> {
        let Some(pem) = &self.bundle_pem else {
            return Ok(Vec::new());
        };
        // Every certificate must be a usable trust anchor: a client that
        // skips an unparsable one would quietly fall back to the built-in roots.
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject as _;
        let mut anchors = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let certificate = certificate.with_context(|| format!("parsing {CA_BUNDLE_ENV}"))?;
            anchors
                .add(certificate)
                .with_context(|| format!("{CA_BUNDLE_ENV} holds an unusable certificate"))?;
        }
        if anchors.is_empty() {
            bail!("{CA_BUNDLE_ENV} holds no certificate");
        }
        reqwest::Certificate::from_pem_bundle(pem)
            .with_context(|| format!("parsing {CA_BUNDLE_ENV}"))
    }

    pub fn apply(&self, mut builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        for certificate in self.certificates()? {
            builder = builder.add_root_certificate(certificate);
        }
        Ok(builder.tls_built_in_root_certs(self.system_roots))
    }

    pub fn apply_blocking(
        &self,
        mut builder: reqwest::blocking::ClientBuilder,
    ) -> Result<reqwest::blocking::ClientBuilder> {
        for certificate in self.certificates()? {
            builder = builder.add_root_certificate(certificate);
        }
        Ok(builder.tls_built_in_root_certs(self.system_roots))
    }

    /// gRPC client TLS with the same trust.
    pub fn tonic(&self) -> tonic::transport::ClientTlsConfig {
        let mut config = tonic::transport::ClientTlsConfig::new();
        if self.system_roots {
            config = config.with_webpki_roots();
        }
        if let Some(pem) = &self.bundle_pem {
            config = config.ca_certificate(tonic::transport::Certificate::from_pem(pem));
        }
        config
    }
}

/// True when `url` uses TLS. Schemes are case-insensitive, as the transports
/// that parse them treat them.
pub fn is_tls_url(url: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
}

/// An async HTTP client builder with this process's outbound trust.
pub fn client() -> Result<reqwest::ClientBuilder> {
    OutboundTrust::from_env()?.apply(reqwest::Client::builder())
}

/// A blocking HTTP client builder with this process's outbound trust.
pub fn blocking_client() -> Result<reqwest::blocking::ClientBuilder> {
    OutboundTrust::from_env()?.apply_blocking(reqwest::blocking::Client::builder())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCa {
        pem: String,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn ca(name: &str) -> TestCa {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            pem: cert.pem(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// An HTTPS server on 127.0.0.1 whose certificate `ca` signed; answers
    /// one request per connection with `ok`.
    async fn server(ca: &TestCa) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca.issuer).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "https://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buffer = [0_u8; 1024];
                    let _ = tls.read(&mut buffer).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        url
    }

    async fn get(trust: &OutboundTrust, url: &str) -> Result<String> {
        let client = trust.apply(reqwest::Client::builder())?.build()?;
        Ok(client.get(url).send().await?.text().await?)
    }

    #[tokio::test]
    async fn the_bundle_is_trusted_and_built_in_roots_can_be_dropped() {
        let site = ca("site ca");
        let other = ca("other ca");
        let url = server(&site).await;

        // The built-in roots alone do not trust a private CA.
        let default = OutboundTrust::new(None, true).unwrap();
        assert!(get(&default, &url).await.is_err());
        // The bundle is trusted, with or without the built-in roots.
        for system_roots in [true, false] {
            let trust =
                OutboundTrust::new(Some(site.pem.clone().into_bytes()), system_roots).unwrap();
            assert_eq!(get(&trust, &url).await.unwrap(), "ok");
        }
        // Only the bundle: a certificate from any other CA is refused.
        let only_other = OutboundTrust::new(Some(other.pem.clone().into_bytes()), false).unwrap();
        assert!(get(&only_other, &url).await.is_err());
        // The blocking client takes the same trust.
        let trust = OutboundTrust::new(Some(site.pem.clone().into_bytes()), false).unwrap();
        let blocking_url = url.clone();
        let body = tokio::task::spawn_blocking(move || {
            trust
                .apply_blocking(reqwest::blocking::Client::builder())?
                .build()?
                .get(blocking_url)
                .send()?
                .text()
                .map_err(anyhow::Error::from)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(body, "ok");
    }

    #[test]
    fn tls_schemes_are_case_insensitive() {
        assert!(is_tls_url("HTTPS://backend.example"));
        assert!(is_tls_url("https://backend.example"));
        assert!(!is_tls_url("http://127.0.0.1:50051"));
        assert!(!is_tls_url("backend.example"));
    }

    #[test]
    fn misconfiguration_fails_closed() {
        assert!(OutboundTrust::new(None, false).is_err());
        assert!(OutboundTrust::new(Some(b"not a certificate".to_vec()), true).is_err());
        assert!(OutboundTrust::new(Some(Vec::new()), true).is_err());
        // PEM framing around bytes that are not a certificate.
        let garbage = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".to_vec();
        assert!(OutboundTrust::new(Some(garbage), true).is_err());
    }
}

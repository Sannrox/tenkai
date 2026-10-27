//! Native TLS for `tenkai-server` (#671) and the seed registry (#627).
//!
//! [`TlsListener`] completes each TLS handshake on its own task, with a
//! timeout, and hands finished connections to `axum::serve`. The handshake
//! takes its configuration from a [`ReloadingTls`] at accept time, so a
//! renewed certificate applies to new connections while every open one, and
//! the runner leases in the store, carry on untouched.
//!
//! With a client CA, a client certificate is verified when presented and
//! optional otherwise. Which routes require one is HTTP policy, applied per
//! request from [`PeerCertificate`]; an untrusted certificate fails the
//! handshake.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context as _, Result};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// A client that has not finished its TLS handshake by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The lowest protocol version a listener accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMinVersion {
    Tls12,
    #[default]
    Tls13,
}

impl std::str::FromStr for TlsMinVersion {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            other => Err(format!("TLS minimum version {other:?} is not 1.2 or 1.3")),
        }
    }
}

/// Where a listener's private key comes from.
#[derive(Debug, Clone)]
pub enum TlsKey {
    /// A secret setting (inline, `_FILE` or the secret directory), which is
    /// how `tenkai-server` takes it: never an argument.
    Secret(&'static str),
    /// A PEM file read directly.
    File(PathBuf),
}

/// Where a listener's certificate, key and client CA come from.
#[derive(Debug, Clone)]
pub struct TlsSource {
    pub cert_chain: PathBuf,
    pub key: TlsKey,
    pub client_ca: Option<PathBuf>,
    pub min_version: TlsMinVersion,
}

impl TlsSource {
    /// The current material, read again on every call.
    fn material(&self) -> Result<Material> {
        Ok(Material {
            cert_chain: std::fs::read(&self.cert_chain).with_context(|| {
                format!("reading certificate chain {}", self.cert_chain.display())
            })?,
            key: match &self.key {
                TlsKey::Secret(setting) => tenkai::secret_source::require(setting)?.into_bytes(),
                TlsKey::File(path) => std::fs::read(path)
                    .with_context(|| format!("reading private key {}", path.display()))?,
            },
            client_ca: self
                .client_ca
                .as_ref()
                .map(|path| {
                    std::fs::read(path)
                        .with_context(|| format!("reading client CA {}", path.display()))
                })
                .transpose()?,
        })
    }

    fn config(&self, material: &Material) -> Result<rustls::ServerConfig> {
        let chain = CertificateDer::pem_slice_iter(&material.cert_chain)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parsing certificate chain {}", self.cert_chain.display()))?;
        anyhow::ensure!(
            !chain.is_empty(),
            "certificate chain {} is empty",
            self.cert_chain.display()
        );
        let key =
            PrivateKeyDer::from_pem_slice(&material.key).context("parsing the private key")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = match self.min_version {
            TlsMinVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
            TlsMinVersion::Tls13 => &[&rustls::version::TLS13],
        };
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)?;
        let builder = match &material.client_ca {
            None => builder.with_no_client_auth(),
            Some(pem) => {
                let mut roots = rustls::RootCertStore::empty();
                for certificate in CertificateDer::pem_slice_iter(pem) {
                    roots.add(certificate.context("parsing the client CA")?)?;
                }
                anyhow::ensure!(!roots.is_empty(), "the client CA holds no certificate");
                builder.with_client_cert_verifier(
                    rustls::server::WebPkiClientVerifier::builder_with_provider(
                        Arc::new(roots),
                        provider,
                    )
                    .allow_unauthenticated()
                    .build()?,
                )
            }
        };
        let mut config = builder.with_single_cert(chain, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

#[derive(PartialEq, Eq)]
struct Material {
    cert_chain: Vec<u8>,
    key: Vec<u8>,
    client_ca: Option<Vec<u8>>,
}

/// The listener's current TLS configuration, replaced when its material
/// changes. A reload that fails keeps the configuration in use.
pub struct ReloadingTls {
    source: TlsSource,
    current: RwLock<(Material, Arc<rustls::ServerConfig>)>,
}

impl ReloadingTls {
    /// Fails when the material cannot be read or does not form a valid
    /// configuration, so a misconfigured server never starts.
    pub fn new(source: TlsSource) -> Result<Arc<Self>> {
        let material = source.material()?;
        let config = Arc::new(source.config(&material)?);
        Ok(Arc::new(Self {
            source,
            current: RwLock::new((material, config)),
        }))
    }

    /// The certificate chain (PEM) in use: the last that loaded, which a
    /// renewal that failed to load has not replaced (#676).
    pub fn active_cert_chain(&self) -> Vec<u8> {
        self.current
            .read()
            .map(|current| current.0.cert_chain.clone())
            .unwrap_or_default()
    }

    /// The client CA (PEM) in use, when one is configured.
    pub fn active_client_ca(&self) -> Option<Vec<u8>> {
        self.current
            .read()
            .ok()
            .and_then(|current| current.0.client_ca.clone())
    }

    /// Read the material again and swap the configuration in when it
    /// changed. `Ok(true)` when it was replaced.
    pub fn reload(&self) -> Result<bool> {
        let material = self.source.material()?;
        if self.current.read().map_err(poisoned)?.0 == material {
            return Ok(false);
        }
        let config = Arc::new(self.source.config(&material)?);
        *self.current.write().map_err(poisoned)? = (material, config);
        Ok(true)
    }

    /// Reload every `every` and on `SIGHUP`, logging each outcome.
    pub fn spawn_reloader(self: &Arc<Self>, every: Duration) -> std::io::Result<()> {
        let tls = self.clone();
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(every);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let trigger = tokio::select! {
                    _ = ticks.tick() => "poll",
                    _ = hangup.recv() => "sighup",
                };
                let tls = tls.clone();
                match tokio::task::spawn_blocking(move || tls.reload()).await {
                    Ok(Ok(true)) => {
                        eprintln!("tenkai.tls_reload outcome=reloaded trigger={trigger}")
                    }
                    Ok(Ok(false)) => {}
                    Ok(Err(error)) => {
                        eprintln!(
                            "tenkai.tls_reload outcome=failed trigger={trigger} detail={error:#}"
                        )
                    }
                    Err(error) => {
                        eprintln!(
                            "tenkai.tls_reload outcome=failed trigger={trigger} detail={error}"
                        )
                    }
                }
            }
        });
        Ok(())
    }

    fn acceptor(&self) -> TlsAcceptor {
        let config = self
            .current
            .read()
            .map(|current| current.1.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().1.clone());
        TlsAcceptor::from(config)
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("TLS configuration lock poisoned")
}

/// Accepts TCP connections and completes their TLS handshakes, each on its
/// own task, so a slow client never blocks the next one.
pub struct TlsListener {
    incoming: tokio::sync::mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    /// Owns the TCP socket; aborted on drop so the port is released.
    accepting: tokio::task::JoinHandle<()>,
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl TlsListener {
    /// Handshakes with whatever configuration `acceptor` returns at accept.
    pub fn spawn(
        listener: TcpListener,
        acceptor: impl Fn() -> TlsAcceptor + Send + 'static,
    ) -> Result<Self> {
        let local = listener.local_addr()?;
        let (sender, incoming) = tokio::sync::mpsc::channel(64);
        let accepting = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    // Out of descriptors and the like: back off and go on.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor();
                let sender = sender.clone();
                tokio::spawn(async move {
                    if let Ok(Ok(tls)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        let _ = sender.send((tls, peer)).await;
                    }
                });
            }
        });
        Ok(Self {
            incoming,
            local,
            accepting,
        })
    }

    /// Handshakes with `tls`'s configuration at the time of each accept.
    pub fn reloading(listener: TcpListener, tls: Arc<ReloadingTls>) -> Result<Self> {
        Self::spawn(listener, move || tls.acceptor())
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.incoming.recv().await {
            Some(connection) => connection,
            // The accept task never ends while the listener lives.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// The leaf certificate (DER) a connection's client presented, if any. The
/// handshake verified it against the client CA, so presence is trust; the
/// runner CA then binds it to one runner (#674).
pub trait PeerCertificate {
    fn client_certificate(&self) -> Option<Arc<[u8]>>;
}

impl PeerCertificate for TcpStream {
    fn client_certificate(&self) -> Option<Arc<[u8]>> {
        None
    }
}

impl PeerCertificate for TlsStream<TcpStream> {
    fn client_certificate(&self) -> Option<Arc<[u8]>> {
        self.get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| Arc::from(leaf.as_ref()))
    }
}

/// Request extension: the verified client certificate of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate(pub Option<Arc<[u8]>>);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    /// A CA and a certificate for `name` it issued, as PEM.
    struct Authority {
        ca_pem: String,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    impl Authority {
        fn new() -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = rcgen::KeyPair::generate().unwrap();
            let ca_pem = params.self_signed(&key).unwrap().pem();
            Self {
                ca_pem,
                issuer: rcgen::Issuer::new(params, key),
            }
        }

        fn issue(&self, name: &str) -> (String, String) {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec![name.into()])
                .unwrap()
                .signed_by(&key, &self.issuer)
                .unwrap();
            (cert.pem(), key.serialize_pem())
        }
    }

    /// A private directory, removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tenkai-tls-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Site {
        dir: TempDir,
        port: u16,
        tls: Arc<ReloadingTls>,
    }

    impl Site {
        fn write(&self, (cert, key): &(String, String)) {
            std::fs::write(self.dir.path().join("cert.pem"), cert).unwrap();
            std::fs::write(self.dir.path().join("key.pem"), key).unwrap();
        }

        fn client(
            &self,
            server_ca: &Authority,
            identity: Option<&(String, String)>,
        ) -> reqwest::Client {
            let mut builder = reqwest::Client::builder()
                .tls_built_in_root_certs(false)
                .use_rustls_tls()
                .add_root_certificate(
                    reqwest::Certificate::from_pem(server_ca.ca_pem.as_bytes()).unwrap(),
                )
                .resolve("localhost", ([127, 0, 0, 1], self.port).into());
            if let Some((cert, key)) = identity {
                builder = builder.identity(
                    reqwest::Identity::from_pem(format!("{cert}{key}").as_bytes()).unwrap(),
                );
            }
            builder.build().unwrap()
        }

        async fn status(&self, client: &reqwest::Client, path: &str) -> Option<u16> {
            client
                .get(format!("https://localhost:{}{path}", self.port))
                .send()
                .await
                .ok()
                .map(|response| response.status().as_u16())
        }
    }

    /// A TLS server for `/healthz` and `/v1/runtime/work`, with client
    /// certificates from `client_ca` required on runtime routes.
    async fn site(server_ca: &Authority, client_ca: &Authority) -> Site {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("client-ca.pem"), &client_ca.ca_pem).unwrap();
        let source = TlsSource {
            cert_chain: dir.path().join("cert.pem"),
            key: TlsKey::File(dir.path().join("key.pem")),
            client_ca: Some(dir.path().join("client-ca.pem")),
            min_version: TlsMinVersion::Tls13,
        };
        let pair = server_ca.issue("localhost");
        std::fs::write(&source.cert_chain, &pair.0).unwrap();
        std::fs::write(dir.path().join("key.pem"), &pair.1).unwrap();
        let tls = ReloadingTls::new(source).unwrap();
        let router = axum::Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/v1/runtime/work", get(|| async { "work" }));
        let serving = crate::HotSwap::new(router).requiring_runtime_client_certificates();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = TlsListener::reloading(listener, tls.clone()).unwrap();
        tokio::spawn(async move { axum::serve(listener, serving).await });
        Site { dir, port, tls }
    }

    #[tokio::test]
    async fn runtime_routes_need_a_trusted_client_certificate_and_health_never_does() {
        let (server_ca, client_ca, stranger) =
            (Authority::new(), Authority::new(), Authority::new());
        let site = site(&server_ca, &client_ca).await;
        let runner = client_ca.issue("runner-1");

        let anonymous = site.client(&server_ca, None);
        assert_eq!(site.status(&anonymous, "/healthz").await, Some(200));
        assert_eq!(site.status(&anonymous, "/v1/runtime/work").await, Some(403));
        let trusted = site.client(&server_ca, Some(&runner));
        assert_eq!(site.status(&trusted, "/v1/runtime/work").await, Some(200));
        // A certificate the client CA did not issue fails the handshake.
        let untrusted = site.client(&server_ca, Some(&stranger.issue("runner-1")));
        assert_eq!(site.status(&untrusted, "/v1/runtime/work").await, None);
    }

    #[tokio::test]
    async fn a_renewed_certificate_serves_new_connections_and_open_ones_carry_on() {
        let (old_ca, new_ca, client_ca) = (Authority::new(), Authority::new(), Authority::new());
        let site = site(&old_ca, &client_ca).await;
        let runner = client_ca.issue("runner-1");
        // A runner holding a connection open across the renewal.
        let holding = site.client(&old_ca, Some(&runner));
        assert_eq!(site.status(&holding, "/v1/runtime/work").await, Some(200));

        site.write(&new_ca.issue("localhost"));
        assert!(
            site.tls.reload().unwrap(),
            "the renewed certificate is loaded"
        );
        assert!(
            !site.tls.reload().unwrap(),
            "unchanged material is not reloaded"
        );

        assert_eq!(site.status(&holding, "/v1/runtime/work").await, Some(200));
        assert_eq!(
            site.status(&site.client(&new_ca, Some(&runner)), "/v1/runtime/work")
                .await,
            Some(200)
        );
        assert_eq!(
            site.status(&site.client(&old_ca, Some(&runner)), "/healthz")
                .await,
            None,
            "new connections get the renewed certificate"
        );
    }

    #[tokio::test]
    async fn dropping_the_listener_releases_its_port() {
        let (server_ca, client_ca) = (Authority::new(), Authority::new());
        let site = site(&server_ca, &client_ca).await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        drop(TlsListener::reloading(tcp, site.tls.clone()).unwrap());
        tokio::task::yield_now().await;
        let mut rebound = None;
        for _ in 0..50 {
            if let Ok(listener) = TcpListener::bind(address).await {
                rebound = Some(listener);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(rebound.is_some(), "the port is free again");
    }

    #[tokio::test]
    async fn a_broken_renewal_keeps_the_certificate_in_use() {
        let (server_ca, client_ca) = (Authority::new(), Authority::new());
        let site = site(&server_ca, &client_ca).await;
        std::fs::write(site.dir.path().join("key.pem"), "not a key").unwrap();
        assert!(site.tls.reload().is_err());
        assert_eq!(
            site.status(&site.client(&server_ca, None), "/healthz")
                .await,
            Some(200)
        );
    }
}

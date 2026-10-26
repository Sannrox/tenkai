//! Seed registry (#627): a read-only OCI distribution endpoint over
//! `TENKAI_OCI_STORE`, so a dark site with no registry can pull the images a
//! verified bundle imported.
//!
//! It serves `<store>/<name>/<repository>/sha256-<hex>`, where `name` is the
//! `host[:port]` the environment mirrors to. Only `GET`/`HEAD` by digest are
//! answered: tags, pushes and deletes are refused, so what it serves is
//! exactly what signed bundles stored, and the client checks every digest.
//! It holds no state; any number of instances may serve one store.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tenkai::oci_artifact::{FilesystemArtifactRegistry, manifest_content_type};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// Largest manifest served; image manifests and indexes are a few KiB.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// A client that has not finished its TLS handshake by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct Registry {
    store: FilesystemArtifactRegistry,
    root: std::path::PathBuf,
    /// The `host[:port]` this registry answers as: its directory in the store.
    name: String,
}

/// The registry routes over the store at `root`, answering as `name`.
pub fn router(root: &Path, name: &str) -> Result<Router> {
    tenkai::oci_artifact::validate_pull_registry("seed registry name", name)?;
    let registry = Arc::new(Registry {
        store: FilesystemArtifactRegistry::new(root.to_path_buf()),
        root: root.to_path_buf(),
        name: name.to_string(),
    });
    Ok(Router::new()
        .route("/v2/", any(base))
        .route("/v2/{*path}", any(content))
        .with_state(registry))
}

/// Serve `router` over TLS on `listener` until the process stops.
pub async fn serve_tls(
    listener: TcpListener,
    tls: rustls::ServerConfig,
    router: Router,
) -> Result<()> {
    let listener = TlsListener::spawn(listener, TlsAcceptor::from(Arc::new(tls)))?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// A TLS server configuration from PEM files: the certificate chain the
/// customer CA issued for the registry name, and its private key.
pub fn tls_config(cert_chain_pem: &Path, key_pem: &Path) -> Result<rustls::ServerConfig> {
    let chain = CertificateDer::pem_file_iter(cert_chain_pem)
        .with_context(|| format!("reading certificate chain {}", cert_chain_pem.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificate chain {}", cert_chain_pem.display()))?;
    if chain.is_empty() {
        anyhow::bail!("certificate chain {} is empty", cert_chain_pem.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_pem)
        .with_context(|| format!("reading private key {}", key_pem.display()))?;
    Ok(rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?)
}

/// `/v2/`: the API version check clients make first. It also answers
/// whether this instance can serve: 503 when the store is unreadable.
async fn base(method: Method, State(registry): State<Arc<Registry>>) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "read-only registry",
        );
    }
    // Listing proves read and search access, which serving needs.
    let readable = match tokio::fs::read_dir(registry.root.join(&registry.name)).await {
        Ok(mut entries) => entries.next_entry().await.is_ok(),
        Err(_) => false,
    };
    if !readable {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UNAVAILABLE",
            "the artifact store holds nothing for this registry",
        );
    }
    with_api_version(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            "{}",
        )
            .into_response(),
    )
}

/// `/v2/<repository>/manifests/<digest>` and `/v2/<repository>/blobs/<digest>`.
async fn content(
    method: Method,
    State(registry): State<Arc<Registry>>,
    UrlPath(path): UrlPath<String>,
) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "read-only registry",
        );
    }
    let mut parts = path.rsplitn(3, '/');
    let (Some(reference), Some(kind), Some(repository)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "unknown path");
    };
    let manifest = match kind {
        "manifests" => true,
        "blobs" => false,
        _ => return error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "unknown path"),
    };
    if !reference.starts_with("sha256:") {
        return if manifest {
            error(
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
                "this registry serves by digest only",
            )
        } else {
            error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "blobs are addressed by digest",
            )
        };
    }
    let file = match registry
        .store
        .served_blob_path(&registry.name, repository, reference)
    {
        Ok(file) => file,
        Err(reason) => return error(StatusCode::BAD_REQUEST, "NAME_INVALID", &reason.to_string()),
    };
    let unknown = if manifest {
        "MANIFEST_UNKNOWN"
    } else {
        "BLOB_UNKNOWN"
    };
    let Ok(metadata) = tokio::fs::metadata(&file).await else {
        return error(StatusCode::NOT_FOUND, unknown, "not in the artifact store");
    };
    let digest = HeaderValue::from_str(reference).expect("validated digest is a header value");
    let length = metadata.len();
    if manifest {
        if length > MAX_MANIFEST_BYTES {
            return error(StatusCode::NOT_FOUND, unknown, "not an image manifest");
        }
        let Ok(bytes) = tokio::fs::read(&file).await else {
            return error(StatusCode::NOT_FOUND, unknown, "not in the artifact store");
        };
        let Some(content_type) = manifest_content_type(&bytes) else {
            return error(StatusCode::NOT_FOUND, unknown, "not an image manifest");
        };
        return with_api_version(
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(&content_type).expect("media type"),
                    ),
                    (header::CONTENT_LENGTH, HeaderValue::from(length)),
                    (
                        header::HeaderName::from_static("docker-content-digest"),
                        digest,
                    ),
                ],
                bytes,
            )
                .into_response(),
        );
    }
    let Ok(opened) = tokio::fs::File::open(&file).await else {
        return error(StatusCode::NOT_FOUND, unknown, "not in the artifact store");
    };
    with_api_version(
        (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                ),
                (header::CONTENT_LENGTH, HeaderValue::from(length)),
                (
                    header::HeaderName::from_static("docker-content-digest"),
                    digest,
                ),
            ],
            Body::from_stream(tokio_util::io::ReaderStream::new(opened)),
        )
            .into_response(),
    )
}

fn with_api_version(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::HeaderName::from_static("docker-distribution-api-version"),
        HeaderValue::from_static("registry/2.0"),
    );
    response
}

/// An OCI distribution error body.
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({"errors": [{"code": code, "message": message}]});
    with_api_version((status, axum::Json(body)).into_response())
}

/// TLS connections for `axum::serve`. Handshakes run in their own tasks, so
/// a slow client never holds up the accept loop.
struct TlsListener {
    incoming: tokio::sync::mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    fn spawn(listener: TcpListener, acceptor: TlsAcceptor) -> Result<Self> {
        let local = listener.local_addr()?;
        let (sender, incoming) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    // Out of descriptors and the like: back off and go on.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
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
        Ok(Self { incoming, local })
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::to_bytes;
    use axum::http::Request;
    use sha2::{Digest as _, Sha256};
    use tower::ServiceExt as _;

    use super::*;

    const NAME: &str = "seed.site:5443";

    struct Store(std::path::PathBuf);

    impl Drop for Store {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    /// A store holding one image: a manifest and its layer, under `NAME`.
    fn store() -> (Store, String, String) {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "tenkai-seed-registry-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let repository = root.join(NAME).join("edge/app");
        std::fs::create_dir_all(&repository).unwrap();
        let layer = b"layer bytes".to_vec();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": digest(b"{}")},
            "layers": [{"digest": digest(&layer)}],
        })
        .to_string();
        for bytes in [manifest.as_bytes(), &layer] {
            std::fs::write(repository.join(digest(bytes).replace(':', "-")), bytes).unwrap();
        }
        (Store(root), digest(manifest.as_bytes()), digest(&layer))
    }

    async fn call(router: &Router, method: Method, path: &str) -> Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn code(response: Response) -> String {
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["errors"][0]["code"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn serves_images_by_digest_and_refuses_tags_writes_and_bad_names() {
        let (store, manifest, layer) = store();
        let router = router(&store.0, NAME).unwrap();

        let base = call(&router, Method::GET, "/v2/").await;
        assert_eq!(base.status(), StatusCode::OK);
        assert_eq!(
            base.headers()["docker-distribution-api-version"],
            "registry/2.0"
        );

        let found = call(
            &router,
            Method::GET,
            &format!("/v2/edge/app/manifests/{manifest}"),
        )
        .await;
        assert_eq!(found.status(), StatusCode::OK);
        assert_eq!(
            found.headers()[header::CONTENT_TYPE],
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(found.headers()["docker-content-digest"], manifest.as_str());

        let head = call(
            &router,
            Method::HEAD,
            &format!("/v2/edge/app/blobs/{layer}"),
        )
        .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()[header::CONTENT_LENGTH], "11");
        let blob = call(&router, Method::GET, &format!("/v2/edge/app/blobs/{layer}")).await;
        let bytes = to_bytes(blob.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&bytes[..], b"layer bytes");

        for (method, path, status, expected) in [
            (
                Method::GET,
                "/v2/edge/app/manifests/latest".to_string(),
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
            ),
            (
                Method::GET,
                format!("/v2/edge/app/manifests/{layer}"),
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
            ),
            (
                Method::GET,
                format!("/v2/edge/app/blobs/{}", digest(b"absent")),
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
            ),
            (
                Method::GET,
                format!("/v2/edge/other/blobs/{layer}"),
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
            ),
            (
                Method::GET,
                format!("/v2/Edge/app/blobs/{layer}"),
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
            ),
            (
                Method::GET,
                format!("/v2/edge/%2E%2E/blobs/{layer}"),
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
            ),
            (
                Method::PUT,
                format!("/v2/edge/app/manifests/{manifest}"),
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
            ),
            (
                Method::POST,
                "/v2/edge/app/blobs/uploads/".to_string(),
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
            ),
            (
                Method::DELETE,
                format!("/v2/edge/app/blobs/{layer}"),
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
            ),
        ] {
            let response = call(&router, method.clone(), &path).await;
            assert_eq!(response.status(), status, "{method} {path}");
            assert_eq!(code(response).await, expected, "{method} {path}");
        }

        // An instance whose name the store holds nothing for cannot serve.
        let empty = super::router(&store.0, "other.site").unwrap();
        assert_eq!(
            call(&empty, Method::GET, "/v2/").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn serves_over_tls_from_the_site_ca() {
        let (store, _, layer) = store();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        std::fs::write(store.0.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(store.0.join("key.pem"), key.serialize_pem()).unwrap();
        let tls = tls_config(&store.0.join("cert.pem"), &store.0.join("key.pem")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve_tls(listener, tls, router(&store.0, NAME).unwrap()));

        let client = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
            .resolve("localhost", ([127, 0, 0, 1], port).into())
            .build()
            .unwrap();
        let response = client
            .get(format!(
                "https://localhost:{port}/v2/edge/app/blobs/{layer}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(&response.bytes().await.unwrap()[..], b"layer bytes");
    }
}

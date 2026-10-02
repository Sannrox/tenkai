//! Serve the web console at `/ui/` (ADR 0031).
//!
//! The console is a static single-page app built with relative URLs, so the
//! same files work at `/ui/` and behind a proxy at `/<prefix>/ui/`. Builds with
//! feature `ui` embed the pinned, checksum-verified release; `--ui-dir` serves a
//! local build instead for console development.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

#[cfg(feature = "ui")]
mod bundle {
    include!(concat!(env!("OUT_DIR"), "/console_bundle.rs"));
}

/// Where console files come from.
#[derive(Clone, Debug)]
pub enum UiSource {
    /// The pinned bundle compiled into this binary.
    Embedded(&'static [(&'static str, &'static [u8])]),
    /// A local console build, for development only.
    Directory(PathBuf),
}

impl UiSource {
    /// The bundle embedded by feature `ui`, if this binary was built with it.
    pub fn embedded() -> Option<Self> {
        #[cfg(feature = "ui")]
        {
            Some(Self::Embedded(bundle::FILES))
        }
        #[cfg(not(feature = "ui"))]
        {
            None
        }
    }

    /// Release tag of the embedded bundle, if any.
    pub fn embedded_tag() -> Option<&'static str> {
        #[cfg(feature = "ui")]
        {
            Some(bundle::TAG)
        }
        #[cfg(not(feature = "ui"))]
        {
            None
        }
    }

    fn read(&self, name: &str) -> Option<Vec<u8>> {
        match self {
            Self::Embedded(files) => files
                .iter()
                .find(|(file, _)| *file == name)
                .map(|(_, bytes)| bytes.to_vec()),
            Self::Directory(root) => {
                if !is_plain_relative(name) {
                    return None;
                }
                let path = root.join(name);
                path.is_file().then(|| std::fs::read(path).ok()).flatten()
            }
        }
    }
}

struct UiState {
    source: UiSource,
    csp: HeaderValue,
}

/// Add `GET /` (relative redirect to `ui/`), `GET /ui`, and `GET /ui/*` to
/// `router`. `connect_origins` are extra origins the console may call from the
/// browser, such as the OIDC issuer.
pub fn mount(
    router: Router,
    source: UiSource,
    connect_origins: &[String],
) -> anyhow::Result<Router> {
    let state = Arc::new(UiState {
        source,
        csp: HeaderValue::from_str(&content_security_policy(connect_origins))?,
    });
    let ui = Router::new()
        .route("/", get(redirect_to_ui))
        .route("/ui", get(redirect_to_ui))
        .route("/ui/", get(serve))
        .route("/ui/{*path}", get(serve))
        .with_state(state);
    Ok(router.merge(ui))
}

fn content_security_policy(connect_origins: &[String]) -> String {
    let mut connect = String::from("'self'");
    for origin in connect_origins {
        connect.push(' ');
        connect.push_str(origin);
    }
    format!(
        "default-src 'self'; connect-src {connect}; object-src 'none'; base-uri 'self'; \
         form-action 'self'; frame-ancestors 'none'"
    )
}

/// Relative, so it also works when a proxy mounts Tenkai under a sub-path:
/// from `/` and from `/ui` alike, `ui/` resolves to the console root.
async fn redirect_to_ui() -> Redirect {
    Redirect::temporary("ui/")
}

async fn serve(State(state): State<Arc<UiState>>, uri: Uri) -> Response {
    let requested = uri.path().strip_prefix("/ui/").unwrap_or_default();
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_SECURITY_POLICY, state.csp.clone());
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // Existing files are served. A missing asset is a real 404; any other
    // path is a client-side route (names may contain dots, e.g. `v1.2.3`) and
    // gets the app shell.
    if !requested.is_empty() && !is_plain_relative(requested) {
        return (StatusCode::NOT_FOUND, headers).into_response();
    }
    let (name, body) = match state.source.read(requested) {
        Some(body) => (requested, body),
        None if is_asset_path(requested) => {
            return (StatusCode::NOT_FOUND, headers).into_response();
        }
        None => match state.source.read("index.html") {
            Some(body) => ("index.html", body),
            None => return (StatusCode::NOT_FOUND, headers).into_response(),
        },
    };
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(name)),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if name.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    let body = if name == "index.html" {
        with_relative_base(body, requested)
    } else {
        body
    };
    (StatusCode::OK, headers, body).into_response()
}

/// The bundle uses relative URLs (`./assets/…`) so it works under any proxy
/// sub-path. A nested route such as `auth/callback` would resolve them against
/// `/ui/auth/`, so the app shell gets a `<base href>` that climbs back to the
/// console root by request depth. It never names the external prefix, and only
/// `index.html` is changed; a bundle that declares its own `<base>` is left alone.
fn with_relative_base(html: Vec<u8>, requested: &str) -> Vec<u8> {
    let depth = requested.matches('/').count();
    if depth == 0 {
        return html;
    }
    let Ok(text) = std::str::from_utf8(&html) else {
        return html;
    };
    let lower = text.to_ascii_lowercase();
    if lower.contains("<base") {
        return html;
    }
    let Some(head) = lower.find("<head>") else {
        return html;
    };
    let insert_at = head + "<head>".len();
    let base = format!("<base href=\"{}\">", "../".repeat(depth));
    let mut out = String::with_capacity(text.len() + base.len());
    out.push_str(&text[..insert_at]);
    out.push_str(&base);
    out.push_str(&text[insert_at..]);
    out.into_bytes()
}

/// Only plain relative names (no `..`, root, or prefix) may reach a source.
fn is_plain_relative(name: &str) -> bool {
    !name.contains('\\')
        && Path::new(name)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

/// Build output lives under `assets/`; other static files have a known type.
fn is_asset_path(name: &str) -> bool {
    name.starts_with("assets/") || content_type(name) != "application/octet-stream"
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    fn console_dir() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "tenkai-ui-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(
            root.join("index.html"),
            "<!doctype html><html><head><title>Tenkai</title><script type=\"module\" src=\"./assets/index-abc.js\"></script></head></html>",
        )
        .unwrap();
        std::fs::write(root.join("assets/index-abc.js"), "export {}").unwrap();
        root
    }

    fn app(root: &Path) -> Router {
        let api = Router::new().route("/healthz", get(|| async { "ok" }));
        mount(
            api,
            UiSource::Directory(root.to_path_buf()),
            &[
                "https://idp.example.com".into(),
                "https://token.example.net".into(),
            ],
        )
        .unwrap()
    }

    async fn call(app: &Router, method: Method, path: &str) -> Response {
        app.clone()
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

    #[tokio::test]
    async fn root_redirects_relatively_and_only_for_get() {
        let root = console_dir();
        let app = app(&root);
        for path in ["/", "/ui"] {
            let response = call(&app, Method::GET, path).await;
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
            assert_eq!(response.headers()[header::LOCATION], "ui/", "{path}");
        }
        let post = call(&app, Method::POST, "/").await;
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(post.headers().get(header::LOCATION).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn index_deep_links_and_assets_are_served_with_csp() {
        let root = console_dir();
        let app = app(&root);
        for path in [
            "/ui/",
            "/ui/environments",
            "/ui/environments/prod/plan",
            "/ui/environments/prod.eu",
            "/ui/releases/v1.2.3",
        ] {
            let response = call(&app, Method::GET, path).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8",
                "{path}"
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
            let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap();
            assert!(csp.starts_with("default-src 'self'"), "{csp}");
            assert!(
                csp.contains(
                    "connect-src 'self' https://idp.example.com https://token.example.net"
                ),
                "{csp}"
            );
            assert!(!csp.contains("unsafe"), "{csp}");
        }
        let asset = call(&app, Method::GET, "/ui/assets/index-abc.js").await;
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert!(
            asset.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn unknown_assets_and_paths_stay_404_and_api_is_untouched() {
        let root = console_dir();
        let app = app(&root);
        for path in [
            "/ui/assets/missing.js",
            "/ui/assets/missing",
            "/ui/missing.css",
            "/ui/../Cargo.toml",
            "/ui/%2e%2e/secret.txt",
            "/ui/a\\..\\b",
            "/elsewhere",
        ] {
            let response = call(&app, Method::GET, path).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let health = call(&app, Method::GET, "/healthz").await;
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            health
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    async fn body(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn nested_routes_get_a_depth_relative_base_so_assets_resolve() {
        let root = console_dir();
        let app = app(&root);
        for (path, base) in [
            ("/ui/", None),
            ("/ui/releases", None),
            ("/ui/auth/callback", Some("../")),
            ("/ui/environments/prod/plan", Some("../../")),
            ("/ui/environments/prod/", Some("../../")),
        ] {
            let html = body(call(&app, Method::GET, path).await).await;
            match base {
                None => assert!(!html.contains("<base"), "{path}: {html}"),
                Some(base) => {
                    assert!(
                        html.starts_with(&format!(
                            "<!doctype html><html><head><base href=\"{base}\"><title>"
                        )),
                        "{path}: {html}"
                    );
                    // Resolve the script like a browser: page URL, then base, then src.
                    let page = url::Url::parse("https://tenkai.example/proxy")
                        .unwrap()
                        .join(&format!("proxy{path}"))
                        .unwrap();
                    let script = page
                        .join(base)
                        .unwrap()
                        .join("./assets/index-abc.js")
                        .unwrap();
                    assert_eq!(script.path(), "/proxy/ui/assets/index-abc.js", "{path}");
                }
            }
        }
        let asset = body(call(&app, Method::GET, "/ui/assets/index-abc.js").await).await;
        assert_eq!(asset, "export {}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn existing_base_or_missing_head_is_left_alone() {
        let declared = b"<html><head><base href=\"/x/\"></head></html>".to_vec();
        assert_eq!(with_relative_base(declared.clone(), "a/b"), declared);
        let headless = b"<html><body></body></html>".to_vec();
        assert_eq!(with_relative_base(headless.clone(), "a/b"), headless);
    }

    #[cfg(feature = "ui")]
    #[test]
    fn embedded_bundle_has_an_index() {
        let source = UiSource::embedded().expect("feature ui embeds the console");
        assert!(source.read("index.html").is_some());
        assert!(UiSource::embedded_tag().unwrap().starts_with('v'));
    }
}

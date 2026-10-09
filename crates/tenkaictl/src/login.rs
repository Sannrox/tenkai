use std::io;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use crate::args::{Cli, Command};
use crate::token_cache::{SavedLogin, TokenCache, config_dir_from_env, now_unix};

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_METADATA_BYTES: u64 = 1 << 20;

type OpenBrowser = Arc<dyn Fn(&str) -> io::Result<()> + Send + Sync>;

/// Runtime hooks for login and token refresh. Tests replace the browser and
/// config directory.
#[derive(Clone)]
pub(crate) struct LoginRuntime {
    pub http: Client,
    pub open_browser: OpenBrowser,
    pub config_dir: PathBuf,
    pub env_token: Option<String>,
}

fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

impl LoginRuntime {
    pub(crate) fn from_env() -> Result<Self> {
        Ok(Self {
            http: http_client()?,
            open_browser: Arc::new(open_system_browser),
            config_dir: config_dir_from_env()?,
            env_token: std::env::var("TENKAI_MANAGEMENT_TOKEN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        })
    }
}

#[derive(Debug, Deserialize)]
struct OidcClientDiscovery {
    issuer: String,
    audience: String,
    client_id: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

pub(crate) async fn run(cli: Cli) -> Result<()> {
    let runtime = LoginRuntime::from_env()?;
    match cli.command {
        Command::Login {
            client_id,
            callback_port,
            no_browser,
            timeout,
        } => {
            login(
                &runtime,
                require_server_url(cli.server_url.as_deref())?,
                client_id,
                callback_port,
                no_browser,
                Duration::from_secs(timeout),
            )
            .await
        }
        Command::Logout => logout(&runtime, require_server_url(cli.server_url.as_deref())?).await,
        _ => unreachable!("login dispatcher handles only login and logout"),
    }
}

/// Resolve the bearer for a remote command: `TENKAI_MANAGEMENT_TOKEN` wins,
/// otherwise the saved login for this server, refreshed against the pinned
/// token endpoint when it has expired.
pub(crate) async fn bearer_token(runtime: &LoginRuntime, server_url: &str) -> Result<String> {
    if let Some(token) = runtime.env_token.as_deref() {
        return Ok(token.to_string());
    }
    saved_access_token(runtime, &normalize_server_url(server_url)?, false).await
}

pub(crate) fn require_server_url(server_url: Option<&str>) -> Result<String> {
    let url = server_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("--server-url is required (or set TENKAI_SERVER_URL)"))?;
    normalize_server_url(url)
}

fn normalize_server_url(url: &str) -> Result<String> {
    require_https(url)?;
    Ok(url.trim().trim_end_matches('/').to_string())
}

async fn login(
    runtime: &LoginRuntime,
    server_url: String,
    client_id_override: Option<String>,
    callback_port: u16,
    no_browser: bool,
    timeout: Duration,
) -> Result<()> {
    let discovery = discover_client(runtime, &server_url).await?;
    let client_id = client_id_override
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or(discovery.client_id.clone());
    if client_id.is_empty() {
        bail!("no OIDC client ID; pass --client-id or set TENKAI_CLIENT_ID");
    }
    let auth_server = discover_auth_server(runtime, &discovery.issuer).await?;

    let listener = TcpListener::bind(("127.0.0.1", callback_port))
        .await
        .with_context(|| {
            format!("starting the login callback listener on 127.0.0.1:{callback_port}")
        })?;
    let redirect_uri = format!("http://{}/callback", listener.local_addr()?);

    let verifier = random_urlsafe(32);
    let challenge = pkce_challenge(&verifier);
    let state = random_urlsafe(16);
    let auth_url = authorization_url(
        &auth_server.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &discovery.scopes,
        &state,
        &challenge,
    )?;

    if no_browser || (runtime.open_browser)(&auth_url).is_err() {
        eprintln!("Open this URL to log in:\n\n  {auth_url}\n");
    } else {
        eprintln!("Opened the browser to log in; waiting...");
    }

    let code = tokio::time::timeout(timeout, wait_for_callback(listener, &state))
        .await
        .map_err(|_| anyhow!("login timed out; run tenkaictl login again, or raise --timeout"))??;

    let token = exchange_code(
        runtime,
        &auth_server.token_endpoint,
        &client_id,
        &redirect_uri,
        &code,
        &verifier,
    )
    .await?;
    persist_login(
        runtime,
        &server_url,
        SavedLogin {
            issuer: auth_server.issuer,
            token_url: auth_server.token_endpoint,
            client_id,
            audience: discovery.audience,
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at_unix: token.expires_in.map(|secs| now_unix().saturating_add(secs)),
        },
    )?;
    eprintln!("Logged in to {server_url}");
    Ok(())
}

async fn logout(runtime: &LoginRuntime, server_url: String) -> Result<()> {
    TokenCache::new(&runtime.config_dir).put(&server_url, None)?;
    eprintln!("Logged out of {server_url}");
    Ok(())
}

async fn saved_access_token(
    runtime: &LoginRuntime,
    server_url: &str,
    force_refresh: bool,
) -> Result<String> {
    let cache = TokenCache::new(&runtime.config_dir);
    let mut login = cache.get(server_url)?.ok_or_else(|| {
        anyhow!(
            "not logged in to {server_url}; run tenkaictl login, or set TENKAI_MANAGEMENT_TOKEN"
        )
    })?;
    if login.access_token_usable() && !force_refresh {
        return Ok(login.access_token);
    }
    let cache_for_lock = cache.clone();
    let lock = tokio::task::spawn_blocking(move || cache_for_lock.lock_exclusive())
        .await
        .context("locking the token cache")??;
    login = cache.get(server_url)?.ok_or_else(|| {
        anyhow!(
            "not logged in to {server_url}; run tenkaictl login, or set TENKAI_MANAGEMENT_TOKEN"
        )
    })?;
    if login.access_token_usable() && !force_refresh {
        return Ok(login.access_token);
    }
    let refresh_token = login
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow!("the saved login has expired; run tenkaictl login"))?;
    let token = refresh(runtime, &login.token_url, &login.client_id, &refresh_token)
        .await
        .context("refreshing the saved login failed; run tenkaictl login")?;
    login.access_token = token.access_token.clone();
    if let Some(next) = token.refresh_token {
        login.refresh_token = Some(next);
    }
    login.expires_at_unix = token.expires_in.map(|secs| now_unix().saturating_add(secs));
    cache.put_locked(&lock, server_url, Some(&login))?;
    Ok(token.access_token)
}

fn persist_login(runtime: &LoginRuntime, server_url: &str, login: SavedLogin) -> Result<()> {
    TokenCache::new(&runtime.config_dir).put(server_url, Some(&login))
}

async fn discover_client(runtime: &LoginRuntime, server_url: &str) -> Result<OidcClientDiscovery> {
    let url = format!("{server_url}/v1/auth/oidc");
    let response = runtime
        .http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("reaching {url}"))?;
    let status = response.status();
    if status.as_u16() == 404 {
        bail!(
            "this server has no OIDC public client; configure [client] in TENKAI_OIDC_CONFIG, or set TENKAI_MANAGEMENT_TOKEN"
        );
    }
    if !status.is_success() {
        bail!("GET {url} answered {status}");
    }
    let discovery: OidcClientDiscovery = read_json(response).await?;
    if discovery.issuer.trim().is_empty() || discovery.audience.trim().is_empty() {
        bail!("OIDC client discovery omitted issuer or audience");
    }
    require_https(&discovery.issuer)?;
    Ok(discovery)
}

async fn discover_auth_server(runtime: &LoginRuntime, issuer: &str) -> Result<AuthServerMetadata> {
    let issuer = issuer.trim().trim_end_matches('/').to_string();
    require_https(&issuer)?;
    let mut last_error = None;
    for meta_url in auth_server_metadata_urls(&issuer) {
        match fetch_auth_server(runtime, &meta_url).await {
            Ok(metadata) => {
                if metadata.issuer.trim().trim_end_matches('/') != issuer {
                    bail!(
                        "authorization server metadata issuer {:?} does not match {issuer:?}",
                        metadata.issuer
                    );
                }
                require_https(&metadata.authorization_endpoint)?;
                require_https(&metadata.token_endpoint)?;
                if !metadata
                    .code_challenge_methods_supported
                    .iter()
                    .any(|method| method == "S256")
                {
                    bail!("authorization server {issuer} does not support PKCE S256");
                }
                return Ok(metadata);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow!("no authorization server metadata found for {issuer}")))
}

fn auth_server_metadata_urls(issuer: &str) -> Vec<String> {
    let Ok(parsed) = Url::parse(issuer) else {
        return Vec::new();
    };
    let path = parsed.path().trim_end_matches('/').to_string();
    let origin = match parsed.origin() {
        url::Origin::Opaque(_) => return Vec::new(),
        origin => origin.ascii_serialization(),
    };
    vec![
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}/.well-known/openid-configuration{path}"),
        format!("{origin}{path}/.well-known/openid-configuration"),
    ]
}

async fn fetch_auth_server(runtime: &LoginRuntime, url: &str) -> Result<AuthServerMetadata> {
    let response = runtime.http.get(url).send().await?;
    if !response.status().is_success() {
        bail!("GET {url} answered {}", response.status());
    }
    read_json(response).await
}

fn authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    challenge: &str,
) -> Result<String> {
    let mut url = Url::parse(endpoint)
        .with_context(|| format!("invalid authorization endpoint {endpoint}"))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", redirect_uri);
        if !scopes.is_empty() {
            query.append_pair("scope", &scopes.join(" "));
        }
        query.append_pair("state", state);
        query.append_pair("code_challenge", challenge);
        query.append_pair("code_challenge_method", "S256");
    }
    Ok(url.into())
}

async fn exchange_code(
    runtime: &LoginRuntime,
    token_url: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse> {
    post_token(
        runtime,
        token_url,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ],
    )
    .await
    .context("token exchange failed")
}

async fn refresh(
    runtime: &LoginRuntime,
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    post_token(
        runtime,
        token_url,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ],
    )
    .await
}

async fn post_token(
    runtime: &LoginRuntime,
    token_url: &str,
    form: &[(&str, &str)],
) -> Result<TokenResponse> {
    let response = runtime.http.post(token_url).form(form).send().await?;
    if !response.status().is_success() {
        bail!("POST {token_url} answered {}", response.status());
    }
    let token: TokenResponse = read_json(response).await?;
    if token.access_token.is_empty() {
        bail!("token response omitted access_token");
    }
    Ok(token)
}

async fn read_json<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let bytes = response.bytes().await?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        bail!("response exceeded {MAX_METADATA_BYTES} bytes");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        match read_callback(&mut stream, expected_state).await {
            Ok(code) => return Ok(code),
            Err(CallbackRead::Ignore) => continue,
            Err(CallbackRead::Failed(error)) => return Err(error),
        }
    }
}

enum CallbackRead {
    Ignore,
    Failed(anyhow::Error),
}

async fn read_callback(
    stream: &mut tokio::net::TcpStream,
    expected_state: &str,
) -> std::result::Result<String, CallbackRead> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| CallbackRead::Failed(error.into()))?;
        if n == 0 {
            let _ = write_http(stream, 400, "bad request").await;
            return Err(CallbackRead::Ignore);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            let _ = write_http(stream, 400, "bad request").await;
            return Err(CallbackRead::Ignore);
        }
    }
    let Ok(head) = std::str::from_utf8(&buf) else {
        let _ = write_http(stream, 400, "bad request").await;
        return Err(CallbackRead::Ignore);
    };
    let request_line = head.lines().next().unwrap_or_default();
    let Some(path) = request_line.split_whitespace().nth(1) else {
        let _ = write_http(stream, 400, "bad request").await;
        return Err(CallbackRead::Ignore);
    };
    let Ok(target) = Url::parse(&format!("http://127.0.0.1{path}")) else {
        let _ = write_http(stream, 400, "bad request").await;
        return Err(CallbackRead::Ignore);
    };
    if target.path() != "/callback" {
        let _ = write_http(stream, 404, "not found").await;
        return Err(CallbackRead::Ignore);
    }
    let query: std::collections::HashMap<_, _> = target.query_pairs().into_owned().collect();
    if let Some(error) = query.get("error").filter(|value| !value.is_empty()) {
        let _ = write_http(stream, 400, "login failed").await;
        return Err(CallbackRead::Failed(anyhow!("login failed: {error}")));
    }
    match query.get("state") {
        Some(state) if state == expected_state => {}
        _ => {
            let _ = write_http(stream, 400, "state mismatch").await;
            return Err(CallbackRead::Failed(anyhow!(
                "login callback state mismatch"
            )));
        }
    }
    let Some(code) = query.get("code").filter(|value| !value.is_empty()).cloned() else {
        let _ = write_http(stream, 400, "missing code").await;
        return Err(CallbackRead::Failed(anyhow!("login callback omitted code")));
    };
    let _ = write_http(
        stream,
        200,
        "Logged in. You can close this window and return to the terminal.",
    )
    .await;
    Ok(code)
}

async fn write_http(stream: &mut tokio::net::TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await.ok();
    Ok(())
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_urlsafe(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    getrandom::getrandom(&mut bytes).expect("entropy");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn open_system_browser(url: &str) -> io::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = ProcessCommand::new("open");
        command.arg(url);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = ProcessCommand::new("rundll32");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    } else {
        let mut command = ProcessCommand::new("xdg-open");
        command.arg(url);
        command
    };
    command.spawn()?;
    Ok(())
}

/// Reject non-HTTPS URLs except to loopback, so codes and tokens stay off the
/// clear-text network.
fn require_https(raw: &str) -> Result<()> {
    let url = Url::parse(raw).map_err(|_| anyhow!("invalid URL {raw:?}"))?;
    if url.host_str().is_none() {
        bail!("invalid URL {raw:?}");
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    let host = url.host_str().unwrap_or_default();
    if url.scheme() == "http" && matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Ok(());
    }
    bail!("refusing non-HTTPS URL {raw:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_cache::EXPIRY_SKEW_SECS;
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct FakeAuth {
        url: String,
        issuer: String,
        as_issuer: Mutex<String>,
        challenge: Arc<Mutex<String>>,
        grants: Mutex<Vec<String>>,
        live_refresh: Mutex<std::collections::HashSet<String>>,
        refresh_serial: Mutex<u64>,
        shutdown: tokio::sync::watch::Sender<bool>,
    }

    async fn spawn_fake_auth() -> Arc<FakeAuth> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let issuer = format!("{url}/realms/r");
        let (shutdown, mut rx) = tokio::sync::watch::channel(false);
        let fake = Arc::new(FakeAuth {
            url: url.clone(),
            issuer: issuer.clone(),
            as_issuer: Mutex::new(issuer),
            challenge: Arc::new(Mutex::new(String::new())),
            grants: Mutex::new(Vec::new()),
            live_refresh: Mutex::new(std::collections::HashSet::new()),
            refresh_serial: Mutex::new(1),
            shutdown,
        });
        let serving = fake.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = rx.changed() => {
                        if changed.is_err() || *rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let serving = serving.clone();
                        tokio::spawn(async move {
                            handle_fake(stream, serving).await;
                        });
                    }
                }
            }
        });
        fake
    }

    async fn handle_fake(mut stream: tokio::net::TcpStream, fake: Arc<FakeAuth>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let Ok(n) = stream.read(&mut chunk).await else {
                return;
            };
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let split = match buf.windows(4).position(|window| window == b"\r\n\r\n") {
            Some(index) => index,
            None => return,
        };
        let head = String::from_utf8_lossy(&buf[..split]).into_owned();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while buf.len() < split + 4 + content_length {
            let Ok(n) = stream.read(&mut chunk).await else {
                return;
            };
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let request_line = head.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();
        let body = buf.get(split + 4..).unwrap_or(&[]).to_vec();
        let (status, content_type, body) = route_fake(&fake, method, path, &body);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }

    fn route_fake(
        fake: &FakeAuth,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, &'static str, String) {
        match (method, path) {
            ("GET", "/v1/auth/oidc") => (
                200,
                "application/json",
                serde_json::json!({
                    "issuer": fake.issuer,
                    "audience": "tenkai",
                    "client_id": "tenkai-cli",
                    "scopes": ["openid", "groups"],
                })
                .to_string(),
            ),
            ("GET", "/.well-known/openid-configuration/realms/r")
            | ("GET", "/realms/r/.well-known/openid-configuration")
            | ("GET", "/.well-known/oauth-authorization-server/realms/r") => {
                let issuer = fake.as_issuer.lock().unwrap().clone();
                (
                    200,
                    "application/json",
                    serde_json::json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{}/authorize", fake.url),
                        "token_endpoint": format!("{}/token", fake.url),
                        "code_challenge_methods_supported": ["S256"],
                    })
                    .to_string(),
                )
            }
            ("POST", "/token") => {
                let form: HashMap<String, String> =
                    url::form_urlencoded::parse(body).into_owned().collect();
                fake.grants
                    .lock()
                    .unwrap()
                    .push(form.get("grant_type").cloned().unwrap_or_default());
                match form.get("grant_type").map(String::as_str) {
                    Some("authorization_code") => {
                        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                        let expected = fake.challenge.lock().unwrap().clone();
                        if form.get("code").map(String::as_str) != Some("the-code")
                            || pkce_challenge(&verifier) != expected
                        {
                            return (
                                400,
                                "application/json",
                                r#"{"error":"invalid_grant"}"#.into(),
                            );
                        }
                        fake.live_refresh
                            .lock()
                            .unwrap()
                            .insert("refresh-1".to_string());
                        (
                            200,
                            "application/json",
                            serde_json::json!({
                                "access_token": "access-1",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "refresh_token": "refresh-1",
                            })
                            .to_string(),
                        )
                    }
                    Some("refresh_token") => {
                        let presented = form.get("refresh_token").cloned().unwrap_or_default();
                        if !fake.live_refresh.lock().unwrap().remove(&presented) {
                            return (
                                400,
                                "application/json",
                                r#"{"error":"invalid_grant"}"#.into(),
                            );
                        }
                        let n = {
                            let mut serial = fake.refresh_serial.lock().unwrap();
                            *serial += 1;
                            *serial
                        };
                        let next_refresh = format!("refresh-{n}");
                        fake.live_refresh
                            .lock()
                            .unwrap()
                            .insert(next_refresh.clone());
                        (
                            200,
                            "application/json",
                            serde_json::json!({
                                "access_token": format!("access-{n}"),
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "refresh_token": next_refresh,
                            })
                            .to_string(),
                        )
                    }
                    _ => (
                        400,
                        "application/json",
                        r#"{"error":"invalid_grant"}"#.into(),
                    ),
                }
            }
            _ => (404, "text/plain", "not found".into()),
        }
    }

    fn runtime_for(
        fake: &FakeAuth,
        config_dir: PathBuf,
        env_token: Option<String>,
    ) -> LoginRuntime {
        let challenge = fake.challenge.clone();
        LoginRuntime {
            http: http_client().unwrap(),
            open_browser: Arc::new(move |auth_url: &str| {
                let parsed = Url::parse(auth_url).unwrap();
                let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
                assert_eq!(
                    query.get("code_challenge_method").map(String::as_str),
                    Some("S256")
                );
                assert_eq!(
                    query.get("client_id").map(String::as_str),
                    Some("tenkai-cli")
                );
                *challenge.lock().unwrap() =
                    query.get("code_challenge").cloned().unwrap_or_default();
                let redirect = query.get("redirect_uri").cloned().unwrap();
                let state = query.get("state").cloned().unwrap();
                assert!(redirect.starts_with("http://127.0.0.1:"), "{redirect}");
                std::thread::spawn(move || {
                    let parsed = Url::parse(&redirect).unwrap();
                    let host = parsed.host_str().unwrap();
                    let port = parsed.port().unwrap();
                    let mut probe = std::net::TcpStream::connect((host, port)).unwrap();
                    let _ = write!(
                        probe,
                        "GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
                    );
                    let mut ignore = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut probe, &mut ignore);
                    let target = format!("{redirect}?code=the-code&state={state}");
                    let parsed = Url::parse(&target).unwrap();
                    let path = parsed[url::Position::BeforePath..].to_string();
                    let mut stream = std::net::TcpStream::connect((host, port)).unwrap();
                    let _ = write!(
                        stream,
                        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
                    );
                    ignore.clear();
                    let _ = std::io::Read::read_to_end(&mut stream, &mut ignore);
                });
                Ok(())
            }),
            config_dir,
            env_token,
        }
    }

    fn temp_config() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tenkai-login-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn auth_server_metadata_urls_bracket_ipv6_origins() {
        let urls = auth_server_metadata_urls("http://[::1]:8081/realms/ops");
        assert_eq!(
            urls,
            [
                "http://[::1]:8081/.well-known/oauth-authorization-server/realms/ops",
                "http://[::1]:8081/.well-known/openid-configuration/realms/ops",
                "http://[::1]:8081/realms/ops/.well-known/openid-configuration",
            ]
        );
    }

    #[tokio::test]
    async fn login_refresh_logout() {
        let fake = spawn_fake_auth().await;
        let config_dir = temp_config();
        let runtime = runtime_for(&fake, config_dir.clone(), None);

        login(
            &runtime,
            fake.url.clone(),
            None,
            0,
            false,
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        let cache_path = config_dir.join("tokens.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "token cache mode {mode:#o}");
        }
        let token = bearer_token(&runtime, &fake.url).await.unwrap();
        assert_eq!(token, "access-1");

        let cache = TokenCache::new(&config_dir);
        let mut saved = cache.get(&fake.url).unwrap().unwrap();
        saved.expires_at_unix = Some(now_unix() - EXPIRY_SKEW_SECS - 1);
        cache.put(&fake.url, Some(&saved)).unwrap();
        let token = bearer_token(&runtime, &fake.url).await.unwrap();
        assert_eq!(token, "access-2");
        assert_eq!(
            fake.grants.lock().unwrap().as_slice(),
            ["authorization_code", "refresh_token"]
        );
        let saved = std::fs::read_to_string(&cache_path).unwrap();
        assert!(saved.contains(&fake.issuer), "{saved}");

        logout(&runtime, fake.url.clone()).await.unwrap();
        let error = bearer_token(&runtime, &fake.url).await.unwrap_err();
        assert!(error.to_string().contains("tenkaictl login"), "{error:#}");
        let _ = fake.shutdown.send(true);
    }

    #[tokio::test]
    async fn login_rejects_issuer_mix_up() {
        let fake = spawn_fake_auth().await;
        *fake.as_issuer.lock().unwrap() = "https://evil.example/realms/r".into();
        let runtime = runtime_for(&fake, temp_config(), None);
        let error = login(
            &runtime,
            fake.url.clone(),
            None,
            0,
            false,
            Duration::from_secs(300),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error:#}");
        let _ = fake.shutdown.send(true);
    }

    #[tokio::test]
    async fn env_token_wins_over_saved_login() {
        let fake = spawn_fake_auth().await;
        let runtime = runtime_for(&fake, temp_config(), Some("env-token".into()));
        let token = bearer_token(&runtime, &fake.url).await.unwrap();
        assert_eq!(token, "env-token");
        let _ = fake.shutdown.send(true);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_refresh_reuses_rotated_token() {
        let fake = spawn_fake_auth().await;
        let config_dir = temp_config();
        let runtime = runtime_for(&fake, config_dir.clone(), None);

        login(
            &runtime,
            fake.url.clone(),
            None,
            0,
            false,
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        let cache = TokenCache::new(&config_dir);
        let mut saved = cache.get(&fake.url).unwrap().unwrap();
        saved.expires_at_unix = Some(now_unix() - EXPIRY_SKEW_SECS - 1);
        cache.put(&fake.url, Some(&saved)).unwrap();

        let held = cache.lock_exclusive().unwrap();
        let first = runtime.clone();
        let second = runtime.clone();
        let url = fake.url.clone();
        let t1 = tokio::spawn(async move { bearer_token(&first, &url).await });
        let url = fake.url.clone();
        let t2 = tokio::spawn(async move { bearer_token(&second, &url).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !t1.is_finished() && !t2.is_finished(),
            "both refreshers should wait on the cache lock"
        );
        drop(held);

        let first_token = t1.await.unwrap().unwrap();
        let second_token = t2.await.unwrap().unwrap();
        assert_eq!(first_token, "access-2");
        assert_eq!(second_token, "access-2");
        let refresh_grants = fake
            .grants
            .lock()
            .unwrap()
            .iter()
            .filter(|grant| *grant == "refresh_token")
            .count();
        assert_eq!(refresh_grants, 1, "the waiter must skip after re-read");
        let saved = cache.get(&fake.url).unwrap().unwrap();
        assert_eq!(saved.access_token, "access-2");
        assert_eq!(saved.refresh_token.as_deref(), Some("refresh-2"));
        let raw = std::fs::read(config_dir.join("tokens.json")).unwrap();
        serde_json::from_slice::<serde_json::Value>(&raw).unwrap();
        let _ = fake.shutdown.send(true);
        let _ = std::fs::remove_dir_all(&config_dir);
    }
}

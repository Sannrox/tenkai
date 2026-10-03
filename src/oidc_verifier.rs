//! OIDC access-token verification for enterprise hosts (#468, ADR 0031).
//!
//! Tenkai is a resource server: it never runs a login flow or holds client
//! secrets. Browsers and other clients obtain access tokens from the
//! deployment's OIDC provider and present them as `Authorization: Bearer`.
//! [`OidcAuthExtension`] verifies RS256/ES256 signatures against the
//! provider's JWKS, checks issuer, audience, and lifetime, and maps a
//! configured group or role claim to Tenkai delivery grants. No matching rule
//! grants nothing.
//!
//! Keys come from OIDC discovery, an explicit `jwks_uri`, or a static JWKS
//! file for air-gapped sites. [`JwksCache`] keeps the last good key set; a
//! background thread refreshes it on an interval and when a token names an
//! unknown `kid`, so request authentication never performs network I/O.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::assertion_verifier::{
    DEFAULT_CLOCK_SKEW_SECS, b64url_decode, now_unix_secs, parse_delivery_capabilities,
};
use crate::auth_context::{
    AUTH_CONTEXT_CONTRACT_VERSION, AuthError, AuthenticatedRequestContext,
    AuthenticatedRequestContextBuilder, CredentialMaterial, DeliveryCapability,
    EnterpriseAuthExtension, PrincipalIdentity, PrincipalKind, TenantDerivationAuthority,
};

/// Extension id used by `tenkai-server` when `TENKAI_OIDC_CONFIG` is set.
pub const OIDC_AUTH_EXTENSION_ID: &str = "oidc";

/// Tokens larger than this are refused before any parsing.
const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Minimum spacing between JWKS fetches, including unknown-`kid` refetches.
const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// OIDC trust configuration (TOML). Public data only: no client secrets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Exact `iss` value; also the discovery base when no key source is set.
    pub issuer: String,
    /// Value that must appear in the token's `aud`.
    pub audience: String,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    /// Explicit JWKS URL; skips discovery.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Static JWKS file for sites without network access to the provider.
    #[serde(default)]
    pub jwks_file: Option<PathBuf>,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: i64,
    #[serde(default = "default_refresh_secs")]
    pub jwks_refresh_secs: u64,
    /// Public client settings served to browsers by `GET /v1/auth/oidc`.
    #[serde(default)]
    pub client: Option<OidcPublicClient>,
    pub grants: OidcGrantMapping,
}

/// Public OIDC client a browser uses for Authorization Code + PKCE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcPublicClient {
    pub client_id: String,
    /// Organisation name a sign-in page shows; clients fall back to the
    /// issuer host when unset.
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Origins besides the issuer that the browser calls during sign-in, for
    /// example a token endpoint on another host. Added to the console's
    /// Content-Security-Policy `connect-src`; never served to clients.
    #[serde(default)]
    pub connect_origins: Vec<String>,
}

/// Unauthenticated `GET /v1/auth/oidc` body: what a browser needs to start
/// Authorization Code + PKCE. Public values only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct OidcClientDiscovery {
    pub issuer: String,
    pub audience: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::server::contract::omitted_when_none)]
    pub display_name: Option<String>,
    /// Host-side only: browser `connect-src` origins (issuer first).
    #[serde(skip)]
    pub connect_origins: Vec<String>,
}

impl OidcClientDiscovery {
    /// `None` when the config names no public client.
    pub fn from_config(config: &OidcConfig) -> Option<Self> {
        config.client.as_ref().map(|client| Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            client_id: client.client_id.clone(),
            scopes: client.scopes.clone(),
            display_name: client.display_name.clone(),
            connect_origins: std::iter::once(config.issuer.as_str())
                .chain(client.connect_origins.iter().map(String::as_str))
                .filter_map(|url| url::Url::parse(url).ok())
                .map(|url| url.origin().ascii_serialization())
                .collect(),
        })
    }
}

/// How token claims become Tenkai grants.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcGrantMapping {
    /// Claim holding group or role values (string or array of strings).
    pub claim: String,
    /// Claim holding the tenant id on tenant-mode hubs.
    #[serde(default)]
    pub tenant_claim: Option<String>,
    pub rules: Vec<OidcGrantRule>,
}

/// One claim value and the grants it confers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcGrantRule {
    pub value: String,
    /// `read` and/or `management`.
    pub capabilities: Vec<String>,
    /// When set, management from this rule is confined to one environment.
    #[serde(default)]
    pub environment: Option<String>,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into(), "ES256".into()]
}

fn default_clock_skew() -> i64 {
    DEFAULT_CLOCK_SKEW_SECS
}

fn default_refresh_secs() -> u64 {
    600
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into()]
}

/// Where the configured provider keys come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksLocation {
    Discovery,
    Uri(String),
    File(PathBuf),
}

impl OidcConfig {
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let raw = std::fs::read_to_string(path).map_err(|error| {
            AuthError::InvalidCredential(format!(
                "failed to read OIDC config {}: {error}",
                path.display()
            ))
        })?;
        let config: Self = toml::from_str(&raw).map_err(|error| {
            AuthError::InvalidCredential(format!(
                "failed to parse OIDC config {}: {}",
                path.display(),
                error.message()
            ))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        let invalid = |detail: &str| Err(AuthError::InvalidCredential(detail.into()));
        require_secure_url(&self.issuer, "OIDC issuer")?;
        if self.audience.trim().is_empty() {
            return invalid("OIDC audience must not be empty");
        }
        if self.algorithms.is_empty() {
            return invalid("OIDC algorithms must not be empty");
        }
        for algorithm in &self.algorithms {
            Algorithm::parse(algorithm)?;
        }
        if self.jwks_uri.is_some() && self.jwks_file.is_some() {
            return invalid("set at most one of jwks_uri and jwks_file");
        }
        if let Some(uri) = &self.jwks_uri {
            require_secure_url(uri, "OIDC jwks_uri")?;
        }
        if !(0..=600).contains(&self.clock_skew_secs) {
            return invalid("OIDC clock skew must be between 0 and 600 seconds");
        }
        if !(60..=86_400).contains(&self.jwks_refresh_secs) {
            return invalid("OIDC jwks_refresh_secs must be between 60 and 86400");
        }
        if let Some(client) = &self.client {
            if client.client_id.trim().is_empty() {
                return invalid("OIDC client_id must not be empty");
            }
            if client
                .display_name
                .as_ref()
                .is_some_and(|name| name.trim().is_empty())
            {
                return invalid("OIDC client display_name must not be empty when set");
            }
            for origin in &client.connect_origins {
                let url = require_secure_url(origin, "OIDC client connect_origins entry")?;
                if url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                {
                    return invalid(
                        "OIDC client connect_origins entries must be origins like https://login.example.com",
                    );
                }
            }
        }
        if self.grants.claim.trim().is_empty() {
            return invalid("OIDC grants.claim must not be empty");
        }
        if self.grants.rules.is_empty() {
            return invalid("OIDC grants.rules must name at least one claim value");
        }
        for rule in &self.grants.rules {
            if rule.value.trim().is_empty() {
                return invalid("OIDC grant rule value must not be empty");
            }
            if parse_delivery_capabilities(&rule.capabilities)?.is_empty() {
                return invalid("OIDC grant rule must grant at least one capability");
            }
            if rule
                .environment
                .as_ref()
                .is_some_and(|environment| environment.trim().is_empty())
            {
                return invalid("OIDC grant rule environment must not be empty when set");
            }
        }
        Ok(())
    }

    pub fn jwks_location(&self) -> JwksLocation {
        match (&self.jwks_uri, &self.jwks_file) {
            (Some(uri), _) => JwksLocation::Uri(uri.clone()),
            (None, Some(path)) => JwksLocation::File(path.clone()),
            (None, None) => JwksLocation::Discovery,
        }
    }
}

/// HTTPS is required except for loopback development providers.
fn require_secure_url(raw: &str, what: &str) -> Result<url::Url, AuthError> {
    let url = url::Url::parse(raw)
        .map_err(|_| AuthError::InvalidCredential(format!("{what} is not a valid URL")))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(AuthError::InvalidCredential(format!(
            "{what} must use https (http is allowed only for loopback)"
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Rs256,
    Es256,
}

impl Algorithm {
    fn parse(raw: &str) -> Result<Self, AuthError> {
        match raw {
            "RS256" => Ok(Self::Rs256),
            "ES256" => Ok(Self::Es256),
            other => Err(AuthError::InvalidCredential(format!(
                "unsupported OIDC algorithm {other:?}; expected RS256 or ES256"
            ))),
        }
    }
}

/// One verified-usable public key from a JWKS.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicKey {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed SEC1 point (`0x04 || x || y`).
    P256(Vec<u8>),
}

impl PublicKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa { .. } => Algorithm::Rs256,
            Self::P256(_) => Algorithm::Es256,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), AuthError> {
        use ring::signature;
        let verified = match self {
            Self::Rsa { n, e } => signature::RsaPublicKeyComponents { n, e }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                signature,
            ),
            Self::P256(point) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
            }
        };
        verified.map_err(|_| AuthError::Unauthorized("OIDC token signature is invalid".into()))
    }
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

impl Jwk {
    /// Signature keys with a `kid` and a supported shape; anything else is skipped.
    fn into_entry(self) -> Option<(String, PublicKey)> {
        if self.usage.as_deref().is_some_and(|usage| usage != "sig") {
            return None;
        }
        let kid = self.kid?;
        let key = match (self.kty.as_str(), self.crv.as_deref()) {
            ("RSA", _) => PublicKey::Rsa {
                n: b64url_decode(self.n.as_deref()?).ok()?,
                e: b64url_decode(self.e.as_deref()?).ok()?,
            },
            ("EC", Some("P-256")) => {
                let x = b64url_decode(self.x.as_deref()?).ok()?;
                let y = b64url_decode(self.y.as_deref()?).ok()?;
                if x.len() != 32 || y.len() != 32 {
                    return None;
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                PublicKey::P256(point)
            }
            _ => return None,
        };
        if let Some(alg) = self.alg.as_deref()
            && Algorithm::parse(alg).ok() != Some(key.algorithm())
        {
            return None;
        }
        Some((kid, key))
    }
}

/// Signature keys by `kid`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet(HashMap<String, PublicKey>);

impl KeySet {
    pub fn from_jwks_json(raw: &str) -> Result<Self, AuthError> {
        let jwks: Jwks = serde_json::from_str(raw)
            .map_err(|_| AuthError::InvalidCredential("JWKS document is not valid JSON".into()))?;
        let keys: HashMap<_, _> = jwks.keys.into_iter().filter_map(Jwk::into_entry).collect();
        if keys.is_empty() {
            return Err(AuthError::InvalidCredential(
                "JWKS contains no usable RS256 or ES256 signature key with a kid".into(),
            ));
        }
        Ok(Self(keys))
    }

    fn get(&self, kid: &str) -> Option<&PublicKey> {
        self.0.get(kid)
    }
}

/// Fetches a raw JWKS document. Called only off the request path.
pub trait KeySource: Send + Sync {
    fn fetch(&self) -> Result<String, AuthError>;
}

impl<F> KeySource for F
where
    F: Fn() -> Result<String, AuthError> + Send + Sync,
{
    fn fetch(&self) -> Result<String, AuthError> {
        self()
    }
}

struct FileKeySource(PathBuf);

impl KeySource for FileKeySource {
    fn fetch(&self) -> Result<String, AuthError> {
        std::fs::read_to_string(&self.0).map_err(|error| {
            AuthError::InvalidCredential(format!(
                "failed to read JWKS file {}: {error}",
                self.0.display()
            ))
        })
    }
}

struct HttpKeySource {
    client: reqwest::blocking::Client,
    uri: String,
}

impl KeySource for HttpKeySource {
    fn fetch(&self) -> Result<String, AuthError> {
        http_get(&self.client, &self.uri)
    }
}

fn http_client() -> Result<reqwest::blocking::Client, AuthError> {
    reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| AuthError::InvalidCredential(format!("OIDC HTTP client: {error}")))
}

fn http_get(client: &reqwest::blocking::Client, uri: &str) -> Result<String, AuthError> {
    client
        .get(uri)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::text)
        .map_err(|error| AuthError::InvalidCredential(format!("fetching {uri} failed: {error}")))
}

/// Resolve the key source for a config. Discovery happens here, once.
///
/// Performs blocking I/O: call it outside an async runtime context.
pub fn key_source(config: &OidcConfig) -> Result<Arc<dyn KeySource>, AuthError> {
    match config.jwks_location() {
        JwksLocation::File(path) => Ok(Arc::new(FileKeySource(path))),
        JwksLocation::Uri(uri) => Ok(Arc::new(HttpKeySource {
            client: http_client()?,
            uri,
        })),
        JwksLocation::Discovery => {
            #[derive(Deserialize)]
            struct Discovery {
                issuer: String,
                jwks_uri: String,
            }
            let client = http_client()?;
            let url = format!(
                "{}/.well-known/openid-configuration",
                config.issuer.trim_end_matches('/')
            );
            let discovery: Discovery =
                serde_json::from_str(&http_get(&client, &url)?).map_err(|_| {
                    AuthError::InvalidCredential("OIDC discovery document is not valid".into())
                })?;
            if discovery.issuer != config.issuer {
                return Err(AuthError::InvalidCredential(
                    "OIDC discovery issuer does not match the configured issuer".into(),
                ));
            }
            require_secure_url(&discovery.jwks_uri, "discovered jwks_uri")?;
            Ok(Arc::new(HttpKeySource {
                client,
                uri: discovery.jwks_uri,
            }))
        }
    }
}

/// Last good key set plus rate-limited refresh.
pub struct JwksCache {
    source: Arc<dyn KeySource>,
    keys: RwLock<KeySet>,
    last_fetch: Mutex<Option<Instant>>,
    min_interval: Duration,
}

impl JwksCache {
    /// Fetch once; startup fails closed when no usable key is available.
    pub fn load(source: Arc<dyn KeySource>) -> Result<Self, AuthError> {
        Self::with_min_interval(source, MIN_REFETCH_INTERVAL)
    }

    fn with_min_interval(
        source: Arc<dyn KeySource>,
        min_interval: Duration,
    ) -> Result<Self, AuthError> {
        let keys = KeySet::from_jwks_json(&source.fetch()?)?;
        Ok(Self {
            source,
            keys: RwLock::new(keys),
            last_fetch: Mutex::new(Some(Instant::now())),
            min_interval,
        })
    }

    /// Replace the key set with a fresh fetch. Skipped when the previous fetch
    /// was within the minimum interval; a failed fetch keeps the old keys.
    pub fn refresh(&self) -> Result<(), AuthError> {
        {
            let mut last = self.last_fetch.lock().expect("jwks fetch lock");
            if last.is_some_and(|at| at.elapsed() < self.min_interval) {
                return Ok(());
            }
            *last = Some(Instant::now());
        }
        let keys = KeySet::from_jwks_json(&self.source.fetch()?)?;
        *self.keys.write().expect("jwks lock") = keys;
        Ok(())
    }

    fn key(&self, kid: &str) -> Option<PublicKey> {
        self.keys.read().expect("jwks lock").get(kid).cloned()
    }
}

/// Refresh `cache` every `interval` and whenever the returned sender fires.
/// The thread ends when every sender is dropped.
pub fn spawn_refresher(cache: Arc<JwksCache>, interval: Duration) -> SyncSender<()> {
    let (sender, receiver) = mpsc::sync_channel::<()>(1);
    std::thread::Builder::new()
        .name("tenkai-oidc-jwks".into())
        .spawn(move || {
            while !matches!(
                receiver.recv_timeout(interval),
                Err(RecvTimeoutError::Disconnected)
            ) {
                if let Err(error) = cache.refresh() {
                    eprintln!("OIDC JWKS refresh failed; keeping previous keys: {error}");
                }
            }
        })
        .expect("spawn OIDC JWKS refresher");
    sender
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    nbf: Option<i64>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(value) => value == audience,
            Self::Many(values) => values.iter().any(|value| value == audience),
        }
    }
}

/// Verified identity and grants derived from one access token.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grants {
    subject: String,
    tenant: Option<String>,
    capabilities: BTreeSet<DeliveryCapability>,
    environment: Option<String>,
}

/// Enterprise auth extension for OIDC access tokens.
pub struct OidcAuthExtension {
    config: OidcConfig,
    algorithms: Vec<Algorithm>,
    keys: Arc<JwksCache>,
    refresh: Option<SyncSender<()>>,
    require_tenant: bool,
}

impl OidcAuthExtension {
    /// `refresh` is signalled when a token names an unknown `kid`.
    pub fn new(
        config: OidcConfig,
        keys: Arc<JwksCache>,
        refresh: Option<SyncSender<()>>,
        require_tenant: bool,
    ) -> Result<Self, AuthError> {
        config.validate()?;
        let algorithms = config
            .algorithms
            .iter()
            .map(|raw| Algorithm::parse(raw))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            config,
            algorithms,
            keys,
            refresh,
            require_tenant,
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    fn verify(&self, token: &[u8], now: i64) -> Result<Grants, AuthError> {
        let unauthorized = |detail: &str| AuthError::Unauthorized(detail.into());
        if token.len() > MAX_TOKEN_BYTES {
            return Err(unauthorized("OIDC token is too large"));
        }
        let token =
            std::str::from_utf8(token).map_err(|_| unauthorized("OIDC token is not text"))?;
        let mut parts = token.trim().split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unauthorized("OIDC token is not a compact JWS"));
        };
        let header: Header = serde_json::from_slice(&b64url_decode(header_b64)?)
            .map_err(|_| unauthorized("OIDC token header is not valid JSON"))?;
        let algorithm = Algorithm::parse(&header.alg)
            .ok()
            .filter(|algorithm| self.algorithms.contains(algorithm))
            .ok_or_else(|| unauthorized("OIDC token algorithm is not accepted"))?;
        let kid = header
            .kid
            .ok_or_else(|| unauthorized("OIDC token has no kid"))?;
        let Some(key) = self.keys.key(&kid) else {
            if let Some(refresh) = &self.refresh {
                // Coalesced: a full channel already has a refresh pending.
                let _ = refresh.try_send(());
            }
            return Err(unauthorized("OIDC token signing key is unknown"));
        };
        if key.algorithm() != algorithm {
            return Err(unauthorized("OIDC token algorithm does not match its key"));
        }
        key.verify(
            format!("{header_b64}.{payload_b64}").as_bytes(),
            &b64url_decode(signature_b64)?,
        )?;
        let claims: Claims = serde_json::from_slice(&b64url_decode(payload_b64)?)
            .map_err(|_| unauthorized("OIDC token claims are not valid"))?;
        self.grants(claims, now)
    }

    fn grants(&self, claims: Claims, now: i64) -> Result<Grants, AuthError> {
        let unauthorized = |detail: &str| Err(AuthError::Unauthorized(detail.into()));
        let skew = self.config.clock_skew_secs;
        if claims.iss != self.config.issuer {
            return unauthorized("OIDC token issuer is not trusted");
        }
        if !claims.aud.contains(&self.config.audience) {
            return unauthorized("OIDC token audience does not include this server");
        }
        if claims.sub.trim().is_empty() {
            return unauthorized("OIDC token subject is empty");
        }
        if claims.exp + skew < now {
            return unauthorized("OIDC token has expired");
        }
        if claims.nbf.is_some_and(|nbf| nbf - skew > now) {
            return unauthorized("OIDC token is not valid yet");
        }

        let values = claim_values(claims.rest.get(&self.config.grants.claim));
        let mut fleet = BTreeSet::new();
        let mut scoped: BTreeMap<&str, BTreeSet<DeliveryCapability>> = BTreeMap::new();
        for rule in &self.config.grants.rules {
            if !values.contains(rule.value.as_str()) {
                continue;
            }
            let capabilities = parse_delivery_capabilities(&rule.capabilities)?;
            match &rule.environment {
                None => fleet.extend(capabilities),
                Some(environment) => scoped.entry(environment).or_default().extend(capabilities),
            }
        }
        // Fleet management already covers every environment.
        let fleet_management = fleet.contains(&DeliveryCapability::Management);
        let (capabilities, environment) = match scoped.len() {
            0 => (fleet, None),
            _ if fleet_management => (fleet, None),
            1 => {
                let (environment, capabilities) = scoped.pop_first().expect("one entry");
                fleet.extend(capabilities);
                (fleet, Some(environment.to_string()))
            }
            _ => {
                return Err(AuthError::Forbidden(
                    "OIDC grants confine management to more than one environment; grant fleet management or one environment".into(),
                ));
            }
        };

        let tenant = match &self.config.grants.tenant_claim {
            Some(claim) => match claims.rest.get(claim) {
                Some(serde_json::Value::String(tenant)) if !tenant.trim().is_empty() => {
                    Some(tenant.clone())
                }
                None => None,
                Some(_) => return unauthorized("OIDC tenant claim must be a non-empty string"),
            },
            None => None,
        };
        Ok(Grants {
            subject: format!("{}@{}", claims.sub, claims.iss),
            tenant,
            capabilities,
            environment,
        })
    }
}

/// A group/role claim as a set of strings; anything else grants nothing.
fn claim_values(value: Option<&serde_json::Value>) -> BTreeSet<&str> {
    match value {
        Some(serde_json::Value::String(value)) => BTreeSet::from([value.as_str()]),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect(),
        _ => BTreeSet::new(),
    }
}

impl EnterpriseAuthExtension for OidcAuthExtension {
    fn extension_id(&self) -> &str {
        OIDC_AUTH_EXTENSION_ID
    }

    fn contract_version(&self) -> u32 {
        AUTH_CONTEXT_CONTRACT_VERSION
    }

    fn expected_audience(&self) -> &str {
        &self.config.audience
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
        authority: &TenantDerivationAuthority,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        let token = credential.assertion.as_deref().ok_or_else(|| {
            AuthError::InvalidCredential("OIDC extension requires a bearer JWT".into())
        })?;
        let grants = self.verify(token, now_unix_secs())?;
        let mut builder = AuthenticatedRequestContextBuilder::new(
            credential.request_id.clone(),
            PrincipalIdentity {
                id: grants.subject,
                kind: PrincipalKind::Human,
            },
            OIDC_AUTH_EXTENSION_ID,
        )
        .with_delivery_capabilities(grants.capabilities);
        if let Some(environment) = grants.environment {
            builder = builder.with_environment_binding(environment);
        }
        match (grants.tenant, self.require_tenant) {
            (Some(tenant), _) => builder = builder.with_tenant(&tenant, authority)?,
            (None, true) => {
                return Err(AuthError::Forbidden(
                    "OIDC token is missing the required tenant claim".into(),
                ));
            }
            (None, false) => {}
        }
        builder.build()
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

//! Host identity: kernel peer credentials mapped through OS groups (ADR 0047).
//!
//! A Unix-socket request is identified by `SO_PEERCRED` (uid) and that user's
//! groups from NSS on every request. Groups map to the same grant-rule shape
//! as OIDC. A user in no mapped group, a uid with no passwd entry, or an NSS
//! failure is refused. TCP still uses bearer tokens and assertions.

use std::collections::{BTreeSet, HashMap};
use std::ffi::CStr;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::assertion_verifier::parse_delivery_capabilities;
use crate::auth_context::{
    AuthError, AuthenticatedRequestContext, AuthenticatedRequestContextBuilder,
    CredentialAuthenticator, CredentialMaterial, DeliveryCapability, PrincipalIdentity,
    PrincipalKind,
};
use crate::oidc_verifier::OidcGrantRule;

/// Authenticator id recorded on host-identity request context.
pub const HOST_IDENTITY_AUTHENTICATOR_ID: &str = "auth.host";

/// Default Linux listen path. Absent on a host that has not installed the socket.
pub const DEFAULT_UNIX_SOCKET: &str = "/run/tenkai/tenkai.sock";

/// Default root-owned mapping file written by a server install.
pub const DEFAULT_HOST_GRANTS: &str = "/etc/tenkai/host-grants.toml";

/// Socket-access group. Install puts every mapped user in it.
pub const VIEWER_GROUP: &str = "tenkai-viewer";
/// Operator role group: `management` (implies read and publish).
pub const OPERATOR_GROUP: &str = "tenkai-operator";
/// Admin role group: same capabilities as operator until a later split.
pub const ADMIN_GROUP: &str = "tenkai-admin";

/// Default mapping file body. Same `[[grants.rules]]` shape as OIDC.
pub const DEFAULT_HOST_GRANTS_TOML: &str = r#"# Host identity grants (ADR 0047). Root-owned; not writable by group or others.
# OS group names map to the same capabilities as OIDC grant rules.

[[grants.rules]]
value = "tenkai-viewer"
capabilities = ["read"]

[[grants.rules]]
value = "tenkai-operator"
capabilities = ["management"]

[[grants.rules]]
value = "tenkai-admin"
capabilities = ["management"]
"#;

pub use crate::auth_context::{HostIdentityFacts, PeerCredentials};

/// Passwd + groups resolved from NSS for one uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAccount {
    pub uid: u32,
    pub name: String,
    pub groups: Vec<String>,
}

/// NSS (or a test double) for uid → account. Lookups are never cached.
pub trait HostAccountLookup: Send + Sync {
    fn lookup(&self, uid: u32) -> Result<HostAccount, AuthError>;
}

/// Live NSS lookup via `getpwuid_r` and `getgrouplist`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NssAccountLookup;

impl HostAccountLookup for NssAccountLookup {
    fn lookup(&self, uid: u32) -> Result<HostAccount, AuthError> {
        nss_account(uid)
    }
}

/// Authenticated session as returned by `GET /v1/auth/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuthSession {
    pub principal: String,
    pub kind: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub source: Option<String>,
}

impl AuthSession {
    pub fn from_context(context: &AuthenticatedRequestContext) -> Self {
        let mut capabilities = Vec::new();
        if context.has_delivery_capability(DeliveryCapability::Read) {
            capabilities.push("read".into());
        }
        if context.has_delivery_capability(DeliveryCapability::Publish) {
            capabilities.push("publish".into());
        }
        if context.has_delivery_capability(DeliveryCapability::Management) {
            capabilities.push("management".into());
        }
        let (user, groups, source) = match context.host_identity() {
            Some(host) => (
                Some(host.user_name.clone()),
                host.groups.clone(),
                Some("host".into()),
            ),
            None => (None, Vec::new(), None),
        };
        Self {
            principal: context.principal_id().to_string(),
            kind: context.principal_kind_name().to_string(),
            capabilities,
            user,
            groups,
            source,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostGrantsFile {
    #[serde(default)]
    grants: HostGrantsSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostGrantsSection {
    #[serde(default)]
    rules: Vec<OidcGrantRule>,
}

/// Root-owned OS-group → capability mapping.
#[derive(Debug, Clone)]
pub struct HostGrantMapping {
    rules: Vec<OidcGrantRule>,
}

impl HostGrantMapping {
    pub fn from_rules(rules: Vec<OidcGrantRule>) -> Result<Self, AuthError> {
        for rule in &rules {
            rule.validate()?;
        }
        Ok(Self { rules })
    }

    /// Load a mapping file. Missing files disable host identity (`None`).
    /// An unreadable or invalid present file fails closed.
    pub fn load(path: &Path) -> Result<Option<Self>, AuthError> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AuthError::InvalidCredential(format!(
                    "reading {}: {error}",
                    path.display()
                )));
            }
        };
        let meta = file.metadata().map_err(|error| {
            AuthError::InvalidCredential(format!("inspecting {}: {error}", path.display()))
        })?;
        if !meta.is_file() {
            return Err(AuthError::InvalidCredential(format!(
                "{} must be a regular file",
                path.display()
            )));
        }
        require_root_owned(path, &meta)?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|error| {
            AuthError::InvalidCredential(format!("reading {}: {error}", path.display()))
        })?;
        let parsed: HostGrantsFile = toml::from_str(&text).map_err(|error| {
            AuthError::InvalidCredential(format!("parsing {}: {error}", path.display()))
        })?;
        Ok(Some(Self::from_rules(parsed.grants.rules)?))
    }

    pub fn default_groups() -> Result<Self, AuthError> {
        Self::from_rules(vec![
            grant(VIEWER_GROUP, "read"),
            grant(OPERATOR_GROUP, "management"),
            grant(ADMIN_GROUP, "management"),
        ])
    }
}

fn grant(value: &str, capability: &str) -> OidcGrantRule {
    OidcGrantRule {
        value: value.into(),
        capabilities: vec![capability.into()],
        environment: None,
        channels: Vec::new(),
        products: Vec::new(),
        kind: None,
    }
}

fn require_root_owned(path: &Path, meta: &fs::Metadata) -> Result<(), AuthError> {
    if meta.uid() != 0 {
        return Err(AuthError::InvalidCredential(format!(
            "{} must be owned by root",
            path.display()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(AuthError::InvalidCredential(format!(
            "{} must not be writable by group or others",
            path.display()
        )));
    }
    Ok(())
}

/// Maps peer-credential uids through NSS and grant rules.
pub struct HostIdentityAuthenticator {
    lookup: Arc<dyn HostAccountLookup>,
    grants: HostGrantMapping,
}

impl HostIdentityAuthenticator {
    pub fn new(lookup: Arc<dyn HostAccountLookup>, grants: HostGrantMapping) -> Self {
        Self { lookup, grants }
    }

    pub fn nss(grants: HostGrantMapping) -> Self {
        Self::new(Arc::new(NssAccountLookup), grants)
    }
}

impl CredentialAuthenticator for HostIdentityAuthenticator {
    fn authenticator_id(&self) -> &str {
        HOST_IDENTITY_AUTHENTICATOR_ID
    }

    fn authenticate(
        &self,
        credential: &CredentialMaterial,
    ) -> Result<AuthenticatedRequestContext, AuthError> {
        credential.validate()?;
        let peer = credential.peer_credentials.ok_or_else(|| {
            AuthError::InvalidCredential("host identity requires peer credentials".into())
        })?;
        let account = self.lookup.lookup(peer.uid)?;
        if account.name.trim().is_empty() {
            return Err(AuthError::Unauthorized(
                "peer uid has no passwd entry".into(),
            ));
        }
        let matched = match_host_grants(&self.grants.rules, &account.groups)?;
        let authorized_groups: Vec<String> = self
            .grants
            .rules
            .iter()
            .map(|rule| rule.value.as_str())
            .filter(|value| account.groups.iter().any(|group| group == value))
            .map(str::to_string)
            .collect();
        AuthenticatedRequestContextBuilder::new(
            credential.request_id.clone(),
            PrincipalIdentity {
                id: format!("host:uid:{}", account.uid),
                kind: PrincipalKind::Human,
            },
            HOST_IDENTITY_AUTHENTICATOR_ID,
        )
        .with_delivery_capabilities(matched.capabilities)
        .with_environment_binding_opt(matched.environment)
        .with_channel_bindings(matched.channel_bindings)
        .with_product_bindings(matched.product_bindings)
        .with_host_identity(HostIdentityFacts {
            uid: account.uid,
            user_name: account.name,
            groups: authorized_groups,
        })
        .build()
    }
}

struct MatchedGrants {
    capabilities: BTreeSet<DeliveryCapability>,
    environment: Option<String>,
    channel_bindings: BTreeSet<String>,
    product_bindings: BTreeSet<String>,
}

fn match_host_grants(
    rules: &[OidcGrantRule],
    groups: &[String],
) -> Result<MatchedGrants, AuthError> {
    let group_set: BTreeSet<&str> = groups.iter().map(String::as_str).collect();
    let mut fleet = BTreeSet::new();
    let mut scoped: HashMap<&str, BTreeSet<DeliveryCapability>> = HashMap::new();
    let mut channel_bindings = BTreeSet::new();
    let mut product_bindings = BTreeSet::new();
    let mut unrestricted_publication = false;
    let mut matched = false;
    for rule in rules {
        if !group_set.contains(rule.value.as_str()) {
            continue;
        }
        matched = true;
        let capabilities = parse_delivery_capabilities(&rule.capabilities)?;
        if capabilities.contains(&DeliveryCapability::Publish)
            || capabilities.contains(&DeliveryCapability::Management)
        {
            unrestricted_publication |= rule.products.is_empty();
            product_bindings.extend(rule.products.iter().cloned());
        }
        match &rule.environment {
            None => fleet.extend(capabilities),
            Some(environment) => scoped
                .entry(environment.as_str())
                .or_default()
                .extend(capabilities),
        }
        for channel in &rule.channels {
            let channel = channel.trim();
            if !channel.is_empty() {
                channel_bindings.insert(channel.to_string());
            }
        }
    }
    if !matched {
        return Err(AuthError::Unauthorized(
            "host identity is in no mapped group".into(),
        ));
    }
    let mut capabilities = fleet;
    let fleet_management = capabilities.contains(&DeliveryCapability::Management);
    let environment = match scoped.len() {
        0 => None,
        _ if fleet_management => None,
        1 => {
            let (environment, extra) = scoped.into_iter().next().expect("one scoped grant");
            capabilities.extend(extra);
            Some(environment.to_string())
        }
        _ => {
            return Err(AuthError::Forbidden(
                "host identity grants confine management to more than one environment".into(),
            ));
        }
    };
    if fleet_management {
        channel_bindings.clear();
    }
    if fleet_management || unrestricted_publication {
        product_bindings.clear();
    }
    Ok(MatchedGrants {
        capabilities,
        environment,
        channel_bindings,
        product_bindings,
    })
}

fn nss_account(uid: u32) -> Result<HostAccount, AuthError> {
    let passwd = nss_passwd(uid)?;
    let groups = nss_groups(&passwd.name, passwd.gid)?;
    Ok(HostAccount {
        uid,
        name: passwd.name,
        groups,
    })
}

struct Passwd {
    name: String,
    gid: u32,
}

const NSS_BUF_START: usize = 4096;
const NSS_BUF_MAX: usize = 1 << 20;

fn grow_nss_buffer(buf: &mut Vec<u8>) -> bool {
    if buf.len() >= NSS_BUF_MAX {
        return false;
    }
    buf.resize(
        buf.len()
            .saturating_mul(2)
            .clamp(NSS_BUF_START, NSS_BUF_MAX),
        0,
    );
    true
}

fn nss_passwd(uid: u32) -> Result<Passwd, AuthError> {
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; NSS_BUF_START];
    let rc = loop {
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && grow_nss_buffer(&mut buf) {
            continue;
        }
        break rc;
    };
    if rc != 0 {
        return Err(AuthError::Unauthorized(format!(
            "NSS passwd lookup failed for uid {uid}"
        )));
    }
    if result.is_null() {
        return Err(AuthError::Unauthorized(
            "peer uid has no passwd entry".into(),
        ));
    }
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .map_err(|_| AuthError::Unauthorized("passwd user name is not UTF-8".into()))?
        .to_string();
    if name.trim().is_empty() {
        return Err(AuthError::Unauthorized(
            "peer uid has no passwd entry".into(),
        ));
    }
    Ok(Passwd {
        name,
        gid: pwd.pw_gid,
    })
}

fn nss_groups(user: &str, gid: u32) -> Result<Vec<String>, AuthError> {
    let user_c = std::ffi::CString::new(user)
        .map_err(|_| AuthError::Unauthorized("passwd user name is not a C string".into()))?;
    let mut ngroups: libc::c_int = 32;
    // macOS takes c_int for the base gid and the group buffer; Linux takes gid_t.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let mut gids = vec![0 as libc::c_int; ngroups as usize];
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let mut gids = vec![0 as libc::gid_t; ngroups as usize];
    loop {
        let rc = unsafe {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                libc::getgrouplist(
                    user_c.as_ptr(),
                    gid as libc::c_int,
                    gids.as_mut_ptr(),
                    &mut ngroups,
                )
            }
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            {
                libc::getgrouplist(user_c.as_ptr(), gid, gids.as_mut_ptr(), &mut ngroups)
            }
        };
        if rc >= 0 {
            gids.truncate(ngroups as usize);
            break;
        }
        if ngroups as usize <= gids.len() {
            return Err(AuthError::Unauthorized(format!(
                "NSS group lookup failed for {user}"
            )));
        }
        gids.resize(ngroups as usize, 0);
    }
    let mut names = Vec::new();
    for gid in gids {
        if let Some(name) = nss_group_name(gid as libc::gid_t)? {
            names.push(name);
        }
    }
    Ok(names)
}

fn nss_group_name(gid: libc::gid_t) -> Result<Option<String>, AuthError> {
    let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; NSS_BUF_START];
    let rc = loop {
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && grow_nss_buffer(&mut buf) {
            continue;
        }
        break rc;
    };
    if rc != 0 {
        return Err(AuthError::Unauthorized(format!(
            "NSS group lookup failed for gid {gid}"
        )));
    }
    if result.is_null() {
        return Ok(None);
    }
    let name = unsafe { CStr::from_ptr(grp.gr_name) }
        .to_str()
        .map_err(|_| AuthError::Unauthorized("group name is not UTF-8".into()))?
        .to_string();
    Ok(Some(name))
}

/// Host header is a loopback authority (`127.0.0.1`, `localhost`, `[::1]`).
pub fn is_loopback_host(host: &str) -> bool {
    matches!(
        split_host_port(host),
        Some(("127.0.0.1", _)) | Some(("localhost", _)) | Some(("::1", _))
    )
}

/// Origin (or Referer) is a loopback console origin when present.
pub fn is_loopback_console_origin(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin.trim()) else {
        return false;
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.octets() == [127, 0, 0, 1],
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    }
}

/// Split `Host` into name and optional port without resolving DNS.
fn split_host_port(host: &str) -> Option<(&str, Option<&str>)> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if let Some(rest) = host.strip_prefix('[') {
        let (name, after) = rest.split_once(']')?;
        if after.is_empty() {
            return Some((name, None));
        }
        let port = after.strip_prefix(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        return Some((name, Some(port)));
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && !name.is_empty()
        && !name.contains(':')
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.is_empty()
    {
        return Some((name, Some(port)));
    }
    Some((host, None))
}

/// Path the CLI uses when no `--server-url` is set.
pub fn default_unix_socket_path() -> PathBuf {
    std::env::var("TENKAI_UNIX_SOCKET")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_UNIX_SOCKET))
}

/// Unlink a leftover Unix socket so bind can reuse the path.
///
/// A live listener, a regular file, or a connect error other than
/// `ConnectionRefused` is left in place and returned as an error.
pub fn remove_stale_unix_socket(path: &Path) -> std::io::Result<()> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("unix socket {} is already in use", path.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(error),
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    use std::os::unix::fs::FileTypeExt as _;
    if !meta.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a Unix socket", path.display()),
        ));
    }
    fs::remove_file(path)
}

/// chmod 0660 and, when `tenkai-viewer` exists, assign that group.
///
/// The service user must be in `tenkai-viewer` so an unprivileged bind can
/// chgrp. Missing group skips the chown (development sockets).
pub fn apply_host_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{PermissionsExt as _, chown};
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = viewer_group_gid()? {
        chown(path, None, Some(gid))?;
    }
    Ok(())
}

fn viewer_group_gid() -> std::io::Result<Option<u32>> {
    let name = std::ffi::CString::new(VIEWER_GROUP).expect("viewer group name is a C string");
    let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; NSS_BUF_START];
    let rc = loop {
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && grow_nss_buffer(&mut buf) {
            continue;
        }
        break rc;
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Ok(None);
    }
    Ok(Some(grp.gr_gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    enum LookupResult {
        Account(HostAccount),
        Fail(&'static str),
    }

    struct ScriptedLookup {
        accounts: BTreeMap<u32, LookupResult>,
    }

    impl HostAccountLookup for ScriptedLookup {
        fn lookup(&self, uid: u32) -> Result<HostAccount, AuthError> {
            match self.accounts.get(&uid) {
                Some(LookupResult::Account(account)) => Ok(account.clone()),
                Some(LookupResult::Fail(detail)) => Err(AuthError::Unauthorized((*detail).into())),
                None => Err(AuthError::Unauthorized(
                    "peer uid has no passwd entry".into(),
                )),
            }
        }
    }

    fn account(uid: u32, name: &str, groups: &[&str]) -> HostAccount {
        HostAccount {
            uid,
            name: name.into(),
            groups: groups.iter().map(|group| (*group).to_string()).collect(),
        }
    }

    fn authenticator(lookup: ScriptedLookup) -> HostIdentityAuthenticator {
        HostIdentityAuthenticator::new(
            Arc::new(lookup),
            HostGrantMapping::default_groups().unwrap(),
        )
    }

    fn peer_credential(uid: u32) -> CredentialMaterial {
        CredentialMaterial {
            request_id: "req-host".into(),
            bearer_token: None,
            assertion: None,
            peer_credentials: Some(PeerCredentials { uid }),
        }
    }

    #[test]
    fn operator_group_grants_management() {
        let auth = authenticator(ScriptedLookup {
            accounts: BTreeMap::from([(
                1000,
                LookupResult::Account(account(1000, "raphael", &[VIEWER_GROUP, OPERATOR_GROUP])),
            )]),
        });
        let context = auth.authenticate(&peer_credential(1000)).unwrap();
        assert_eq!(context.principal_id(), "host:uid:1000");
        assert_eq!(context.principal.kind, PrincipalKind::Human);
        assert_eq!(context.authenticator_id, HOST_IDENTITY_AUTHENTICATOR_ID);
        assert!(context.has_delivery_capability(DeliveryCapability::Read));
        assert!(context.has_delivery_capability(DeliveryCapability::Publish));
        assert!(context.has_delivery_capability(DeliveryCapability::Management));
        let host = context.host_identity().unwrap();
        assert_eq!(host.user_name, "raphael");
        assert_eq!(host.uid, 1000);
        assert!(host.groups.contains(&OPERATOR_GROUP.to_string()));
        assert!(context.audit_principal().contains("source=host"));
        let session = AuthSession::from_context(&context);
        assert_eq!(session.source.as_deref(), Some("host"));
        assert_eq!(session.user.as_deref(), Some("raphael"));
    }

    #[test]
    fn viewer_only_is_read() {
        let auth = authenticator(ScriptedLookup {
            accounts: BTreeMap::from([(
                1001,
                LookupResult::Account(account(1001, "view", &[VIEWER_GROUP])),
            )]),
        });
        let context = auth.authenticate(&peer_credential(1001)).unwrap();
        assert!(context.has_delivery_capability(DeliveryCapability::Read));
        assert!(!context.has_delivery_capability(DeliveryCapability::Management));
        assert!(!context.has_delivery_capability(DeliveryCapability::Publish));
    }

    #[test]
    fn unmapped_group_is_refused() {
        let auth = authenticator(ScriptedLookup {
            accounts: BTreeMap::from([(
                1002,
                LookupResult::Account(account(1002, "nobody", &["wheel"])),
            )]),
        });
        let error = auth.authenticate(&peer_credential(1002)).unwrap_err();
        assert!(
            matches!(error, AuthError::Unauthorized(message) if message.contains("no mapped group"))
        );
    }

    #[test]
    fn missing_passwd_is_refused() {
        let auth = authenticator(ScriptedLookup {
            accounts: BTreeMap::new(),
        });
        let error = auth.authenticate(&peer_credential(65534)).unwrap_err();
        assert!(matches!(error, AuthError::Unauthorized(message) if message.contains("passwd")));
    }

    #[test]
    fn nss_failure_is_refused() {
        let auth = authenticator(ScriptedLookup {
            accounts: BTreeMap::from([(9, LookupResult::Fail("NSS group lookup failed"))]),
        });
        let error = auth.authenticate(&peer_credential(9)).unwrap_err();
        assert!(matches!(error, AuthError::Unauthorized(message) if message.contains("NSS")));
    }

    #[test]
    fn current_process_peer_uid_resolves_through_nss() {
        let uid = unsafe { libc::geteuid() };
        let account = NssAccountLookup.lookup(uid).unwrap();
        assert_eq!(account.uid, uid);
        assert!(!account.name.is_empty());
        let grants = HostGrantMapping::from_rules(vec![OidcGrantRule {
            value: account.groups.first().cloned().unwrap_or_else(|| {
                // A user with no groups still needs a matching rule for this
                // NSS-path test; map the account name as a synthetic group.
                account.name.clone()
            }),
            capabilities: vec!["read".into()],
            environment: None,
            channels: Vec::new(),
            products: Vec::new(),
            kind: None,
        }])
        .unwrap();
        let mut groups = account.groups.clone();
        if groups.is_empty() {
            groups.push(account.name.clone());
        }
        let lookup = ScriptedLookup {
            accounts: BTreeMap::from([(
                uid,
                LookupResult::Account(HostAccount { groups, ..account }),
            )]),
        };
        let context = HostIdentityAuthenticator::new(Arc::new(lookup), grants)
            .authenticate(&peer_credential(uid))
            .unwrap();
        assert_eq!(context.principal_id(), format!("host:uid:{uid}"));
        assert!(context.has_delivery_capability(DeliveryCapability::Read));
    }

    #[test]
    fn loopback_host_accepts_only_literal_loopback() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.1:8080"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("localhost:8080"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("[::1]:8080"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("example.com:8080"));
        assert!(!is_loopback_host("127.0.0.1.example.com"));
        assert!(!is_loopback_host("localhost.example.com"));
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host(""));
    }

    #[test]
    fn loopback_origin_accepts_http_loopback() {
        assert!(is_loopback_console_origin("http://127.0.0.1"));
        assert!(is_loopback_console_origin("http://127.0.0.1:8080"));
        assert!(is_loopback_console_origin("http://localhost:8080/ui/"));
        assert!(is_loopback_console_origin("http://[::1]:8080"));
        assert!(!is_loopback_console_origin("http://example.com"));
        assert!(!is_loopback_console_origin("https://evil.example"));
        assert!(!is_loopback_console_origin("not a url"));
    }

    #[test]
    fn default_grants_file_parses() {
        let parsed: HostGrantsFile = toml::from_str(DEFAULT_HOST_GRANTS_TOML).unwrap();
        let mapping = HostGrantMapping::from_rules(parsed.grants.rules).unwrap();
        assert_eq!(mapping.rules.len(), 3);
    }

    #[test]
    fn mapping_file_missing_is_none() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-host-grants-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(HostGrantMapping::load(&path).unwrap().is_none());
    }

    #[test]
    fn mapping_file_refuses_group_writable() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-host-grants-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("host-grants.toml");
        fs::write(&path, DEFAULT_HOST_GRANTS_TOML).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt as _;
        perms.set_mode(0o664);
        fs::set_permissions(&path, perms).unwrap();
        let error = HostGrantMapping::load(&path).unwrap_err();
        let _ = fs::remove_dir_all(&dir);
        if unsafe { libc::geteuid() } == 0 {
            assert!(
                matches!(error, AuthError::InvalidCredential(ref message) if message.contains("writable")),
                "{error:?}"
            );
        } else {
            assert!(
                matches!(error, AuthError::InvalidCredential(ref message) if message.contains("owned by root") || message.contains("writable")),
                "{error:?}"
            );
        }
    }

    #[test]
    fn scripted_lookup_is_not_shared_across_threads_by_cache() {
        // The lookup trait is invoked per request; a Mutex counter proves
        // there is no authenticator-side cache.
        struct Counting(Mutex<u32>, HostAccount);
        impl HostAccountLookup for Counting {
            fn lookup(&self, uid: u32) -> Result<HostAccount, AuthError> {
                *self.0.lock().unwrap() += 1;
                assert_eq!(uid, self.1.uid);
                Ok(self.1.clone())
            }
        }
        let lookup = Arc::new(Counting(
            Mutex::new(0),
            account(7, "count", &[VIEWER_GROUP]),
        ));
        let auth = HostIdentityAuthenticator::new(
            lookup.clone(),
            HostGrantMapping::default_groups().unwrap(),
        );
        auth.authenticate(&peer_credential(7)).unwrap();
        auth.authenticate(&peer_credential(7)).unwrap();
        assert_eq!(*lookup.0.lock().unwrap(), 2);
    }

    fn unique_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-host-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn stale_socket_helper_leaves_regular_files() {
        let dir = unique_dir("regular");
        let path = dir.join("not-a-socket");
        fs::write(&path, "keep").unwrap();
        let error = remove_stale_unix_socket(&path).unwrap_err();
        assert_eq!(fs::read_to_string(&path).unwrap(), "keep");
        assert!(
            error.kind() == std::io::ErrorKind::AlreadyExists
                || error.kind() == std::io::ErrorKind::ConnectionRefused
                || error.raw_os_error() == Some(libc::ENOTSOCK),
            "{error:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_socket_helper_unlinks_leftover_socket() {
        let dir = unique_dir("stale");
        let path = dir.join("tenkai.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(path.exists());
        remove_stale_unix_socket(&path).unwrap();
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_socket_helper_refuses_a_live_listener() {
        let dir = unique_dir("live");
        let path = dir.join("tenkai.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let error = remove_stale_unix_socket(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(path.exists());
        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_socket_permissions_are_owner_and_group_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = unique_dir("perms");
        let path = dir.join("tenkai.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        apply_host_socket_permissions(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }
}

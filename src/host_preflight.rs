//! Host preflight ([ADR 0035](../docs/decisions/0035-host-preflight-evidence.md)).
//!
//! Before the first install, an operator runs `tenkaictl preflight` on the
//! environment's host. It checks disk, memory, ports, clock skew, certificate
//! validity, and registry and identity-provider reachability, signs the
//! results with an Ed25519 seed, and records them on the environment. An
//! approval policy with `require_preflight` refuses to execute a plan unless
//! the latest preflight passed, is fresh, and was signed by a trust root
//! scoped to the `preflight` provider for that environment. Every check uses
//! local resources or addresses inside the site, so it runs offline.

use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::plan_approval::TrustRoots;

pub const PREFLIGHT_SCHEMA: &str = "tenkai.preflight.v1";
/// Trust-root provider scope that may sign preflight evidence. Such a signer
/// cannot sign plan approvals.
pub const PREFLIGHT_PROVIDER: &str = "preflight";
/// Environment property holding the latest signed evidence as JSON.
pub const EVIDENCE_PROPERTY: &str = "preflight_evidence";
const CONFIG_VERSION: u32 = 1;
const SIGNING_DOMAIN: &[u8] = b"TENKAI-PREFLIGHT-V1\0";
/// Seconds between the NTP era (1900) and the Unix epoch.
const NTP_UNIX_OFFSET_SECS: i64 = 2_208_988_800;

/// What to check, read from a version 1 TOML file. Omitted sections are not
/// checked; an empty file checks nothing and passes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightConfig {
    pub version: u32,
    /// Network check timeout. Default 2000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub disks: Vec<DiskRule>,
    #[serde(default)]
    pub memory: Option<MemoryRule>,
    /// TCP ports that must be free to bind.
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub clock: Option<ClockRule>,
    #[serde(default)]
    pub certificates: Vec<CertificateRule>,
    /// `host:port` addresses that must accept TCP connections.
    #[serde(default)]
    pub registries: Vec<String>,
    #[serde(default)]
    pub identity_providers: Vec<String>,
}

fn default_timeout_ms() -> u64 {
    2_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskRule {
    pub path: PathBuf,
    pub min_free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRule {
    pub min_available_bytes: u64,
}

/// Skew against an SNTP server inside the site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRule {
    /// `host:port` of the time server, usually port 123.
    pub server: String,
    pub max_skew_ms: i64,
}

/// A PEM certificate whose first certificate must stay valid this long.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRule {
    pub path: PathBuf,
    pub min_remaining_ms: i64,
}

impl PreflightConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading preflight config {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing preflight config {}", path.display()))?;
        if config.version != CONFIG_VERSION {
            bail!("preflight config version must be {CONFIG_VERSION}");
        }
        if config.timeout_ms == 0 {
            bail!("preflight timeout_ms must be positive");
        }
        if config
            .clock
            .as_ref()
            .is_some_and(|clock| clock.max_skew_ms < 0)
            || config
                .certificates
                .iter()
                .any(|certificate| certificate.min_remaining_ms < 0)
        {
            bail!("preflight max_skew_ms and min_remaining_ms must not be negative");
        }
        Ok(config)
    }
}

/// One check's outcome. `reason` says why it passed or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub check: String,
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightStatement {
    pub environment: String,
    pub checked_at: i64,
    /// True only when every check passed.
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

/// Signed preflight result as stored on the environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightEvidence {
    pub schema: String,
    pub key_id: String,
    pub statement: PreflightStatement,
    pub signature: String,
}

fn canonical_bytes(statement: &PreflightStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

/// Run every configured check. Never fails as a whole: a check that cannot
/// run is a failed check with its reason.
pub fn run_checks(config: &PreflightConfig, now_ms: i64) -> Vec<CheckResult> {
    let timeout = Duration::from_millis(config.timeout_ms);
    let mut results = Vec::new();
    for rule in &config.disks {
        results.push(outcome(
            format!("disk {}", rule.path.display()),
            check_disk(rule),
        ));
    }
    if let Some(rule) = &config.memory {
        results.push(outcome("memory".into(), check_memory(rule)));
    }
    for port in &config.ports {
        results.push(outcome(format!("port {port}"), check_port(*port)));
    }
    if let Some(rule) = &config.clock {
        results.push(outcome(
            format!("clock {}", rule.server),
            check_clock(rule, timeout),
        ));
    }
    for rule in &config.certificates {
        results.push(outcome(
            format!("certificate {}", rule.path.display()),
            check_certificate(rule, now_ms),
        ));
    }
    for (kind, addresses) in [
        ("registry", &config.registries),
        ("identity provider", &config.identity_providers),
    ] {
        for address in addresses {
            results.push(outcome(
                format!("{kind} {address}"),
                check_reachable(address, timeout),
            ));
        }
    }
    results
}

/// `Ok(reason)` passes, `Err(reason)` fails.
fn outcome(check: String, result: Result<String, String>) -> CheckResult {
    let (passed, reason) = match result {
        Ok(reason) => (true, reason),
        Err(reason) => (false, reason),
    };
    CheckResult {
        check,
        passed,
        reason,
    }
}

#[cfg(unix)]
fn free_bytes(path: &Path) -> Result<u64, String> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains a NUL byte".to_string())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is NUL-terminated and `stat` is valid for writes.
    if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(format!("statvfs: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: statvfs returned 0, so it initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast)] // field widths differ by platform
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_bytes(_path: &Path) -> Result<u64, String> {
    Err("disk check is supported on Unix hosts only".into())
}

fn check_disk(rule: &DiskRule) -> Result<String, String> {
    let free = free_bytes(&rule.path)?;
    let detail = format!("{free} bytes free, {} required", rule.min_free_bytes);
    if free >= rule.min_free_bytes {
        Ok(detail)
    } else {
        Err(detail)
    }
}

fn check_memory(rule: &MemoryRule) -> Result<String, String> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")
        .map_err(|_| "memory check is supported on Linux hosts only".to_string())?;
    let available = parse_mem_available(&meminfo)
        .ok_or_else(|| "MemAvailable is missing from /proc/meminfo".to_string())?;
    let detail = format!(
        "{available} bytes available, {} required",
        rule.min_available_bytes
    );
    if available >= rule.min_available_bytes {
        Ok(detail)
    } else {
        Err(detail)
    }
}

fn parse_mem_available(meminfo: &str) -> Option<u64> {
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

/// Free on IPv4 and, when the host has IPv6, on IPv6 too. Each bind is
/// dropped before the next, so a dual-stack bind does not see the first.
fn check_port(port: u16) -> Result<String, String> {
    TcpListener::bind(("0.0.0.0", port)).map_err(|error| format!("cannot bind: {error}"))?;
    match TcpListener::bind(("::", port)) {
        Ok(_) => Ok("free".into()),
        // No IPv6 on this host: IPv4 alone decides.
        Err(error)
            if error.kind() == std::io::ErrorKind::AddrNotAvailable
                || error.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
        {
            Ok("free (no IPv6)".into())
        }
        Err(error) => Err(format!("cannot bind on IPv6: {error}")),
    }
}

fn check_reachable(address: &str, timeout: Duration) -> Result<String, String> {
    let addresses: Vec<SocketAddr> = address
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve: {error}"))?
        .collect();
    let mut last = "no address".to_string();
    for socket in addresses {
        match TcpStream::connect_timeout(&socket, timeout) {
            Ok(_) => return Ok(format!("connected to {socket}")),
            Err(error) => last = format!("{socket}: {error}"),
        }
    }
    Err(format!("unreachable ({last})"))
}

fn check_clock(rule: &ClockRule, timeout: Duration) -> Result<String, String> {
    let skew = sntp_skew_ms(&rule.server, timeout).map_err(|error| format!("{error:#}"))?;
    let detail = format!("skew {skew} ms, at most {} ms allowed", rule.max_skew_ms);
    if skew.abs() <= rule.max_skew_ms {
        Ok(detail)
    } else {
        Err(detail)
    }
}

/// Server time minus local time from the first resolved address that
/// answers an SNTP v4 request.
fn sntp_skew_ms(server: &str, timeout: Duration) -> Result<i64> {
    let mut last = None;
    for target in server
        .to_socket_addrs()
        .with_context(|| format!("resolving {server}"))?
    {
        match sntp_exchange(target, timeout) {
            Ok(skew) => return Ok(skew),
            Err(error) => last = Some(error.context(target.to_string())),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("{server} has no address")))
}

/// One SNTP v4 request to `target`.
fn sntp_exchange(target: SocketAddr, timeout: Duration) -> Result<i64> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).context("binding a UDP socket")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.connect(target)?;
    let mut request = [0_u8; 48];
    request[0] = 0x23; // leap 0, version 4, mode 3 (client)
    let sent = crate::now_millis();
    socket.send(&request).context("sending the time request")?;
    let mut reply = [0_u8; 48];
    let read = socket.recv(&mut reply).context("no time reply")?;
    let received = crate::now_millis();
    if read < 48 || reply[0] & 0x07 != 4 {
        bail!("reply is not an NTP server response");
    }
    // Leap indicator 3 means unsynchronized; stratum must be 1..=15.
    if reply[0] >> 6 == 3 || !(1..=15).contains(&reply[1]) {
        bail!("time server is not synchronized");
    }
    // Standard offset: ((t2 - t1) + (t3 - t4)) / 2, with t2 the server's
    // receive time and t3 its transmit time, so server delay cancels out.
    let server_received = ntp_timestamp_ms(&reply[32..40]);
    let server_sent = ntp_timestamp_ms(&reply[40..48]);
    Ok(((server_received - sent) + (server_sent - received)) / 2)
}

/// A 64-bit NTP timestamp (seconds since 1900, 32-bit fraction) in Unix ms.
fn ntp_timestamp_ms(bytes: &[u8]) -> i64 {
    let seconds = i64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    let fraction = i64::from(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    (seconds - NTP_UNIX_OFFSET_SECS) * 1_000 + ((fraction * 1_000) >> 32)
}

fn check_certificate(rule: &CertificateRule, now_ms: i64) -> Result<String, String> {
    let pem =
        std::fs::read_to_string(&rule.path).map_err(|error| format!("unreadable: {error}"))?;
    let (not_before, not_after) = certificate_validity_ms(&pem)?;
    let rfc3339 = |at: i64| {
        chrono::DateTime::from_timestamp_millis(at)
            .map_or_else(|| at.to_string(), |t| t.to_rfc3339())
    };
    if now_ms < not_before {
        return Err(format!("not valid until {}", rfc3339(not_before)));
    }
    let expires = rfc3339(not_after);
    let remaining = not_after.saturating_sub(now_ms);
    if remaining <= 0 {
        return Err(format!("expired {expires}"));
    }
    let detail = format!("expires {expires}, {} ms required", rule.min_remaining_ms);
    if remaining >= rule.min_remaining_ms {
        Ok(detail)
    } else {
        Err(detail)
    }
}

/// Validity window of the first PEM certificate, in Unix milliseconds.
fn certificate_validity_ms(pem: &str) -> Result<(i64, i64), String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN).ok_or("no PEM certificate")? + BEGIN.len();
    let end = pem[start..]
        .find(END)
        .ok_or("unterminated PEM certificate")?
        + start;
    let body: String = pem[start..end].split_whitespace().collect();
    let der = STANDARD
        .decode(body)
        .map_err(|_| "certificate is not valid base64".to_string())?;
    der_validity_ms(&der).ok_or_else(|| "certificate DER is malformed".into())
}

/// One DER element: (tag, contents, rest). Definite lengths only.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, tail) = rest.split_at(count);
        rest = tail;
        bytes
            .iter()
            .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte))
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// Certificate -> tbsCertificate -> validity -> (notBefore, notAfter), in
/// Unix milliseconds.
fn der_validity_ms(der: &[u8]) -> Option<(i64, i64)> {
    const SEQUENCE: u8 = 0x30;
    let (SEQUENCE, certificate, _) = der_element(der)? else {
        return None;
    };
    let (SEQUENCE, tbs, _) = der_element(certificate)? else {
        return None;
    };
    let mut fields = tbs;
    let (tag, _, rest) = der_element(fields)?;
    if tag == 0xa0 {
        fields = rest; // explicit version
    }
    // serialNumber, signature, issuer, then validity.
    for _ in 0..3 {
        fields = der_element(fields)?.2;
    }
    let (SEQUENCE, validity, _) = der_element(fields)? else {
        return None;
    };
    let (before_tag, before, rest) = der_element(validity)?;
    let (after_tag, after, _) = der_element(rest)?;
    Some((
        der_time_ms(before_tag, before)?,
        der_time_ms(after_tag, after)?,
    ))
}

fn der_time_ms(tag: u8, time: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(time).ok()?;
    let text = match tag {
        // UTCTime: X.509 reads YY below 50 as 20YY and the rest as 19YY.
        0x17 => {
            let century = if text.get(..2)?.parse::<u8>().ok()? < 50 {
                "20"
            } else {
                "19"
            };
            format!("{century}{text}")
        }
        0x18 => text.to_string(), // GeneralizedTime
        _ => return None,
    };
    let at = chrono::NaiveDateTime::parse_from_str(&text, "%Y%m%d%H%M%SZ").ok()?;
    Some(at.and_utc().timestamp_millis())
}

/// Sign the results with the Ed25519 seed at `seed_path` (32 bytes, mode 0600).
pub fn sign(
    environment: &str,
    checks: Vec<CheckResult>,
    now_ms: i64,
    seed_path: &Path,
) -> Result<PreflightEvidence> {
    crate::ontology::validate_identifier("environment", environment)?;
    let signing_key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let statement = PreflightStatement {
        environment: environment.into(),
        checked_at: now_ms,
        passed: checks.iter().all(|check| check.passed),
        checks,
    };
    let signature = signing_key.sign(&canonical_bytes(&statement)?);
    Ok(PreflightEvidence {
        schema: PREFLIGHT_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&signing_key.verifying_key().to_bytes()),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

/// Attach evidence to its environment, replacing any earlier preflight.
pub async fn record(ctx: &mut Ctx, evidence: &PreflightEvidence) -> Result<()> {
    let mut environment =
        crate::environment::environment(ctx, &evidence.statement.environment).await?;
    environment
        .properties
        .insert(EVIDENCE_PROPERTY.into(), serde_json::to_string(evidence)?);
    ctx.put(environment).await.map(|_| ())
}

/// Refuse unless the stored preflight for `environment` is signed by a
/// `preflight`-scoped trust root for it, passed, and is at most `max_age_ms` old.
pub fn require_passing(
    properties: &std::collections::HashMap<String, String>,
    environment: &str,
    roots: &TrustRoots,
    now_ms: i64,
    max_age_ms: i64,
) -> Result<()> {
    let raw = properties
        .get(EVIDENCE_PROPERTY)
        .with_context(|| format!("environment {environment} has no host preflight"))?;
    let evidence: PreflightEvidence =
        serde_json::from_str(raw).context("parsing stored host preflight")?;
    if evidence.schema != PREFLIGHT_SCHEMA || evidence.statement.environment != environment {
        bail!("stored host preflight is not a {PREFLIGHT_SCHEMA} result for {environment}");
    }
    let signer = roots.signer(&evidence.key_id)?;
    if signer.providers != [PREFLIGHT_PROVIDER]
        || !signer.environments.iter().any(|scope| scope == environment)
    {
        bail!("host preflight signer is not scoped to the preflight provider for {environment}");
    }
    let public_key = crate::signature_verification::trusted_key(
        "preflight signer public key",
        &signer.public_key,
        &signer.key_id,
    )?;
    crate::signature_verification::verify_strict(
        &public_key,
        "host preflight signature",
        &evidence.signature,
        &canonical_bytes(&evidence.statement)?,
    )?;
    let statement = &evidence.statement;
    if statement.checked_at > now_ms || now_ms - statement.checked_at > max_age_ms {
        bail!(
            "host preflight from {} is older than {max_age_ms} ms",
            statement.checked_at
        );
    }
    if !statement.passed || statement.checks.iter().any(|check| !check.passed) {
        let failed: Vec<String> = statement
            .checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| format!("{}: {}", check.check, check.reason))
            .collect();
        bail!("host preflight failed: {}", failed.join("; "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed P-256 test certificate, `notAfter` 2126 (GeneralizedTime).
    const VALID_UNTIL_2126: &str = "-----BEGIN CERTIFICATE-----
MIIBijCCAS+gAwIBAgIUc6OEGvINi0ymnyVdRDfuiNfPwjkwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOcHJlZmxpZ2h0LXRlc3QwIBcNMjYxMDE4MTI0MDU5WhgPMjEy
NjA5MjQxMjQwNTlaMBkxFzAVBgNVBAMMDnByZWZsaWdodC10ZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAE17ebi88A620pXrpz2zOjldG/eWCdWLX/8Smgxe05
dhpVgiuwdW3S4MX9sIPA2m1mL2/X6YxWQUPYrHxLXopX06NTMFEwHQYDVR0OBBYE
FKbLPvqEZkIxZ0Ko7mPd0Fb4qKwgMB8GA1UdIwQYMBaAFKbLPvqEZkIxZ0Ko7mPd
0Fb4qKwgMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKaghZxw
eDutcG1KripVHD2JJDmeqA1ZoMxhYyrMX8HHAiEAyLe4GDz76t76FZvyqAlNGau7
KHPpnoNaHx4oeQ0+h00=
-----END CERTIFICATE-----\n";
    /// Self-signed P-256 test certificate, `notAfter` 2020-01-02 (UTCTime).
    const EXPIRED_2020: &str = "-----BEGIN CERTIFICATE-----
MIIBjDCCATOgAwIBAgIUO95ihUOyGSs1F3kGD+w1V8TbeJ0wCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRcHJlZmxpZ2h0LWV4cGlyZWQwHhcNMjAwMTAxMDAwMDAwWhcN
MjAwMTAyMDAwMDAwWjAcMRowGAYDVQQDDBFwcmVmbGlnaHQtZXhwaXJlZDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABMrHAvGnldGuiMaUuXSiavbQs29B4b1bjTlv
1k+DxfIJzXtT9uEOyS/p2uDIuyz40PVUGE8UfwNPkl2JxCASZIijUzBRMB0GA1Ud
DgQWBBRZO1aLJEf7Wqx8iimaLa0KXRZ/mjAfBgNVHSMEGDAWgBRZO1aLJEf7Wqx8
iimaLa0KXRZ/mjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBBy
1On8KMGQryVgbA5uERJ/InHY0ORomz7NWWVkFc1uAiA5Sbi4UAQFRtykxt+9rI9w
R8E4AqWXYHDgxQg+tAyEng==
-----END CERTIFICATE-----\n";

    fn config() -> PreflightConfig {
        PreflightConfig {
            version: 1,
            timeout_ms: 500,
            ..PreflightConfig::default()
        }
    }

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-preflight-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// One-shot SNTP server on loopback that answers `skew_ms` ahead of now.
    fn fake_time_server(skew_ms: i64) -> String {
        time_server(skew_ms, 0x24, 2)
    }

    /// `first` is the leap/version/mode byte; `stratum` the second byte.
    fn time_server(skew_ms: i64, first: u8, stratum: u8) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let mut request = [0_u8; 48];
            let (_, peer) = socket.recv_from(&mut request).unwrap();
            let at = crate::now_millis() + skew_ms;
            let seconds = (at.div_euclid(1_000) + NTP_UNIX_OFFSET_SECS) as u32;
            let fraction = ((at.rem_euclid(1_000) << 32) / 1_000) as u32;
            let mut reply = [0_u8; 48];
            reply[0] = first;
            reply[1] = stratum;
            for at in [32, 40] {
                reply[at..at + 4].copy_from_slice(&seconds.to_be_bytes());
                reply[at + 4..at + 8].copy_from_slice(&fraction.to_be_bytes());
            }
            socket.send_to(&reply, peer).unwrap();
        });
        address
    }

    #[test]
    fn every_check_reports_pass_or_fail_with_a_reason() {
        let busy = TcpListener::bind("0.0.0.0:0").unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let listening = TcpListener::bind("127.0.0.1:0").unwrap();
        let registry = listening.local_addr().unwrap().to_string();
        let dir = unique_dir("checks");
        let valid = dir.join("valid.pem");
        let expired = dir.join("expired.pem");
        std::fs::write(&valid, VALID_UNTIL_2126).unwrap();
        std::fs::write(&expired, EXPIRED_2020).unwrap();
        let checks = run_checks(
            &PreflightConfig {
                disks: vec![
                    DiskRule {
                        path: dir.clone(),
                        min_free_bytes: 1,
                    },
                    DiskRule {
                        path: dir.clone(),
                        min_free_bytes: u64::MAX,
                    },
                ],
                ports: vec![busy_port],
                clock: Some(ClockRule {
                    server: fake_time_server(10_000),
                    max_skew_ms: 1_000,
                }),
                certificates: vec![
                    CertificateRule {
                        path: valid,
                        min_remaining_ms: 86_400_000,
                    },
                    CertificateRule {
                        path: expired,
                        min_remaining_ms: 86_400_000,
                    },
                ],
                registries: vec![registry],
                identity_providers: vec!["127.0.0.1:1".into()],
                ..config()
            },
            crate::now_millis(),
        );
        let verdicts: Vec<(bool, &str)> = checks
            .iter()
            .map(|check| (check.passed, check.reason.as_str()))
            .collect();
        assert!(verdicts[0].0, "{checks:?}");
        assert!(
            !verdicts[1].0 && verdicts[1].1.contains("required"),
            "{checks:?}"
        );
        assert!(
            !verdicts[2].0 && verdicts[2].1.contains("cannot bind"),
            "{checks:?}"
        );
        assert!(
            !verdicts[3].0 && verdicts[3].1.contains("skew"),
            "{checks:?}"
        );
        assert!(
            verdicts[4].0 && verdicts[4].1.contains("2126"),
            "{checks:?}"
        );
        assert!(
            !verdicts[5].0 && verdicts[5].1.contains("expired 2020"),
            "{checks:?}"
        );
        assert!(verdicts[6].0, "{checks:?}");
        assert!(
            !verdicts[7].0 && verdicts[7].1.contains("unreachable"),
            "{checks:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clock_within_tolerance_passes() {
        let checks = run_checks(
            &PreflightConfig {
                clock: Some(ClockRule {
                    server: fake_time_server(0),
                    max_skew_ms: 1_000,
                }),
                ..config()
            },
            crate::now_millis(),
        );
        assert!(checks[0].passed, "{checks:?}");
    }

    #[test]
    fn unsynchronized_time_server_fails() {
        for server in [time_server(0, 0xe4, 2), time_server(0, 0x24, 0)] {
            let checks = run_checks(
                &PreflightConfig {
                    clock: Some(ClockRule {
                        server,
                        max_skew_ms: 1_000,
                    }),
                    ..config()
                },
                crate::now_millis(),
            );
            assert!(
                !checks[0].passed && checks[0].reason.contains("not synchronized"),
                "{checks:?}"
            );
        }
    }

    #[test]
    fn utc_time_uses_the_x509_century_rule() {
        // UTCTime "690101000000Z" is 1969, not 2069.
        let validity = [&[0x17, 13][..], b"690101000000Z"].concat();
        let der = der_sequence(&[der_sequence(&[
            vec![0x02, 0x01, 0x01],
            der_sequence(&[]),
            der_sequence(&[]),
            der_sequence(&[validity.clone(), validity]),
        ])]);
        let (_, at) = der_validity_ms(&der).unwrap();
        assert_eq!(
            chrono::DateTime::from_timestamp_millis(at)
                .unwrap()
                .to_rfc3339(),
            "1969-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn certificate_before_its_validity_fails() {
        let not_before = [&[0x18, 15][..], b"21000101000000Z"].concat();
        let not_after = [&[0x18, 15][..], b"21100101000000Z"].concat();
        let der = der_sequence(&[der_sequence(&[
            vec![0x02, 0x01, 0x01],
            der_sequence(&[]),
            der_sequence(&[]),
            der_sequence(&[not_before, not_after]),
        ])]);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        );
        let dir = unique_dir("not-before");
        let path = dir.join("future.pem");
        std::fs::write(&path, pem).unwrap();
        let rule = CertificateRule {
            path,
            min_remaining_ms: 0,
        };
        let error = check_certificate(&rule, crate::now_millis()).unwrap_err();
        assert!(error.contains("not valid until 2100"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
        let body = items.concat();
        [vec![0x30, u8::try_from(body.len()).unwrap()], body].concat()
    }

    #[test]
    fn mem_available_parses_kib() {
        let meminfo = "MemTotal: 2048 kB\nMemAvailable:    1024 kB\n";
        assert_eq!(parse_mem_available(meminfo), Some(1024 * 1024));
        assert_eq!(parse_mem_available("MemTotal: 2048 kB\n"), None);
    }

    #[test]
    fn malformed_certificates_fail_closed() {
        assert!(certificate_validity_ms("not a certificate").is_err());
        let truncated = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        assert!(certificate_validity_ms(truncated).is_err());
    }
}

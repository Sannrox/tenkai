//! What this host trusts and how long its certificates last (#676).
//!
//! One read model over the host's trust configuration: the signing trust
//! roots it verifies releases, approvals and bundles against, the installed
//! key revocation list, and the TLS certificates it serves and trusts, each
//! with its expiry and a status against warning and critical thresholds.
//! Files are read on each request, so a renewed certificate shows at once.
//! Only certificates and public trust roots are read; key files never are,
//! and paths are reported by file name only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Status ordering: `ok` < `warning` < `critical` < `expired`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Ok,
    Warning,
    Critical,
    Expired,
}

/// Where a certificate comes from: a file read on each request, or the
/// material the server actually loaded (the TLS listener and client CA,
/// the runner CA), so a renewal that failed to load cannot clear a warning.
#[derive(Clone)]
pub enum CertificateSource {
    File(PathBuf),
    Loaded {
        /// Shown in place of a file name.
        name: String,
        pem: std::sync::Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    },
}

impl std::fmt::Debug for CertificateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Loaded { name, .. } => f.debug_struct("Loaded").field("name", name).finish(),
        }
    }
}

/// Where this host's trust lives, gathered from its configuration.
#[derive(Debug, Clone, Default)]
pub struct TrustSources {
    /// `(purpose, trust-root file)`, for example `("release", …)`.
    pub signing: Vec<(String, PathBuf)>,
    /// The installed key revocation list and the authorities that sign it,
    /// when configured.
    pub revocations: Option<(PathBuf, PathBuf)>,
    /// `(purpose, source)`: listener, client CA, runner CA, outbound CA
    /// bundle. A source may hold several certificates.
    pub certificates: Vec<(String, CertificateSource)>,
    pub warning_days: u32,
    pub critical_days: u32,
    /// `TENKAI_TLS_REQUIRE_RUNTIME_CLIENT_CERT`, as the listener enforces it.
    pub runtime_client_cert_required: bool,
}

impl TrustSources {
    pub fn is_empty(&self) -> bool {
        self.signing.is_empty() && self.revocations.is_none() && self.certificates.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustPosture {
    /// The worst certificate status; `ok` when nothing is about to lapse.
    pub status: TrustStatus,
    pub warning_days: u32,
    pub critical_days: u32,
    /// Runtime routes refuse a connection without a verified client
    /// certificate, enrollment and renewal aside (#809).
    pub runtime_client_cert_required: bool,
    pub signing: Vec<SigningRoot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub revocation_list: Option<InstalledRevocations>,
    pub tls: Vec<CertificateEntry>,
}

/// The worst certificate status and when it began, kept for health probes
/// and change-event announcements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustSnapshot {
    pub status: TrustStatus,
    /// Unix milliseconds at which the earliest certificate at `status`
    /// crossed into it, from its expiry and the threshold; `0` when unknown,
    /// as for an unreadable certificate.
    pub since_ms: i64,
}

impl TrustPosture {
    pub fn snapshot(&self) -> TrustSnapshot {
        let days = |status| match status {
            TrustStatus::Warning => i64::from(self.warning_days),
            TrustStatus::Critical => i64::from(self.critical_days),
            TrustStatus::Ok | TrustStatus::Expired => 0,
        };
        // Grading turns `warning` once `not_after - now` falls below the
        // threshold, so that instant is exact, not rounded to a day.
        let since_ms = self
            .tls
            .iter()
            .filter(|entry| entry.status == self.status)
            .map(|entry| {
                entry.not_after.map_or(0, |not_after| {
                    (not_after - days(entry.status) * 86_400).saturating_mul(1_000)
                })
            })
            .min()
            .unwrap_or(0);
        TrustSnapshot {
            status: self.status,
            since_ms,
        }
    }
}

/// Append one `trust_threshold_crossed` change event, resource
/// `trust/<status>`, when the worst certificate status is `warning`,
/// `critical` or `expired` and this crossing has not been announced, and
/// `trust/ok` when it returns to `ok` after one (#784).
///
/// Nothing is remembered in memory: the store skips the append while its
/// latest trust event names the same status, so a restart or a writer
/// takeover does not repeat it. The `trust/ok` marker is what lets the next
/// crossing into the same status count, even for an unreadable certificate,
/// whose crossing time is unknown. A crossing the latest event predates (a
/// renewed certificate that lapsed again while no writer ran) counts too.
pub fn announce_crossing(
    store: &dyn crate::storage::OperationalStore,
    snapshot: TrustSnapshot,
    now_ms: i64,
) -> crate::storage::Result<Option<crate::change_stream::ChangeEvent>> {
    let (status, since, only_after_another) = match snapshot.status {
        // Recovery is recorded only after an announcement, at most once.
        TrustStatus::Ok => ("ok", i64::MIN, true),
        TrustStatus::Warning => ("warning", snapshot.since_ms, false),
        TrustStatus::Critical => ("critical", snapshot.since_ms, false),
        TrustStatus::Expired => ("expired", snapshot.since_ms, false),
    };
    store.append_change_event_once(
        now_ms,
        crate::change_stream::ChangeEventKind::TrustThresholdCrossed,
        &format!("trust/{status}"),
        since,
        only_after_another,
    )
}

/// Whether an entry shows material the server loaded and uses, or a file as
/// it is on disk now, which a client that read it at startup adopts only
/// once restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    Loaded,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SigningRoot {
    pub purpose: String,
    pub file: String,
    /// Trust-root files are read as they are on disk.
    pub source: TrustSource,
    pub signers: Vec<TrustedSignerView>,
    /// Why the file could not be read, when it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedSignerView {
    pub key_id: String,
    pub identity: String,
    /// Revoked by the key revocations this process enforces.
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InstalledRevocations {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub signer_key_id: Option<String>,
    pub revoked_keys: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CertificateEntry {
    pub purpose: String,
    pub file: String,
    pub source: TrustSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub subject: Option<String>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub not_after: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub days_left: Option<i64>,
    /// SHA-256 of the certificate's DER, as `openssl x509 -fingerprint
    /// -sha256` prints it: uppercase hex pairs joined by colons (#809).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub sha256_fingerprint: Option<String>,
    /// An unreadable certificate file is `critical`.
    pub status: TrustStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub error: Option<String>,
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `error` with `path` reduced to its file name: host paths stay private.
fn redacted(error: &anyhow::Error, path: &Path) -> String {
    format!("{error:#}").replace(&*path.to_string_lossy(), &file_name(path))
}

/// A certificate that lapses before an environment's next maintenance window
/// opens, so a plan waiting for that window would fail at apply time (#778).
/// Advisory: it never blocks the plan or changes its steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRunway {
    /// The certificate's purpose, with its subject when readable.
    pub credential: String,
    pub expires_at_ms: i64,
    pub window_opens_at_ms: i64,
}

impl CredentialRunway {
    /// One line for plan output, with UTC timestamps.
    pub fn summary(&self) -> String {
        let at = |ms: i64| {
            chrono::DateTime::from_timestamp_millis(ms)
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_else(|| ms.to_string())
        };
        format!(
            "{} expires {}, before the maintenance window opens {}",
            self.credential,
            at(self.expires_at_ms),
            at(self.window_opens_at_ms)
        )
    }
}

/// The first certificate in `sources` that lapses at or before
/// `window_opens_at_ms`, if any. A certificate without a readable expiry is
/// left to the posture's own `critical` grade.
pub fn runway(
    sources: &TrustSources,
    now_ms: i64,
    window_opens_at_ms: i64,
) -> Option<CredentialRunway> {
    let shown = posture(sources, now_ms.div_euclid(1_000));
    shown
        .tls
        .into_iter()
        .filter_map(|entry| Some((entry.not_after?.saturating_mul(1_000), entry)))
        .filter(|(expires_at_ms, _)| *expires_at_ms <= window_opens_at_ms)
        .min_by_key(|(expires_at_ms, _)| *expires_at_ms)
        .map(|(expires_at_ms, entry)| CredentialRunway {
            credential: match entry.subject {
                Some(subject) => format!("{} ({subject})", entry.purpose),
                None => entry.purpose,
            },
            expires_at_ms,
            window_opens_at_ms,
        })
}

/// The posture of `sources` at `now_secs`.
pub fn posture(sources: &TrustSources, now_secs: i64) -> TrustPosture {
    let revoked = installed_revocations(sources);
    let signing = sources
        .signing
        .iter()
        .map(
            |(purpose, path)| match crate::release_signing::TrustRoots::load(path) {
                Ok(roots) => SigningRoot {
                    purpose: purpose.clone(),
                    file: file_name(path),
                    source: TrustSource::File,
                    signers: roots
                        .signers
                        .into_iter()
                        .map(|signer| TrustedSignerView {
                            revoked: crate::key_revocation::is_revoked(&signer.key_id),
                            key_id: signer.key_id,
                            identity: signer.identity,
                        })
                        .collect(),
                    error: None,
                },
                Err(error) => SigningRoot {
                    purpose: purpose.clone(),
                    file: file_name(path),
                    source: TrustSource::File,
                    signers: Vec::new(),
                    error: Some(redacted(&error, path)),
                },
            },
        )
        .collect();
    let tls: Vec<CertificateEntry> = sources
        .certificates
        .iter()
        .flat_map(|(purpose, source)| certificates(purpose, source, sources, now_secs))
        .collect();
    TrustPosture {
        status: tls
            .iter()
            .map(|entry| entry.status)
            .max()
            .unwrap_or(TrustStatus::Ok),
        warning_days: sources.warning_days,
        critical_days: sources.critical_days,
        runtime_client_cert_required: sources.runtime_client_cert_required,
        signing,
        revocation_list: revoked.map(|(file, list)| match list {
            Ok(list) => InstalledRevocations {
                file,
                sequence: Some(list.statement.sequence),
                signer_key_id: Some(list.key_id.clone()),
                revoked_keys: list.statement.revoked.len(),
                error: None,
            },
            Err(error) => InstalledRevocations {
                file,
                sequence: None,
                signer_key_id: None,
                revoked_keys: 0,
                error: Some(error),
            },
        }),
        tls,
    }
}

type Revocations = (
    String,
    Result<crate::key_revocation::RevocationList, String>,
);

/// The installed list, shown only once it verifies against its authorities:
/// an edited file is reported as an error, not as revocations.
fn installed_revocations(sources: &TrustSources) -> Option<Revocations> {
    let (path, authorities) = sources.revocations.as_ref()?;
    // A configured list that is not there yet installs nothing.
    if !path.exists() {
        return None;
    }
    let verified = crate::release_signing::TrustRoots::load(authorities)
        .map_err(|error| redacted(&error, authorities))
        .and_then(|authorities| {
            let list = crate::key_revocation::RevocationList::load(path)
                .map_err(|error| redacted(&error, path))?;
            list.verify(&authorities)
                .map_err(|error| format!("{} does not verify: {error:#}", file_name(path)))?;
            Ok(list)
        });
    Some((file_name(path), verified))
}

/// One entry per certificate in `source`.
/// `AB:CD:…`, the SHA-256 of `der` as `openssl x509 -fingerprint -sha256`.
fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn certificates(
    purpose: &str,
    source: &CertificateSource,
    sources: &TrustSources,
    now_secs: i64,
) -> Vec<CertificateEntry> {
    let (label, kind) = match source {
        CertificateSource::File(path) => (file_name(path), TrustSource::File),
        CertificateSource::Loaded { name, .. } => (name.clone(), TrustSource::Loaded),
    };
    let unreadable = |error: String| CertificateEntry {
        purpose: purpose.into(),
        file: label.clone(),
        source: kind,
        subject: None,
        not_after: None,
        days_left: None,
        sha256_fingerprint: None,
        status: TrustStatus::Critical,
        error: Some(error),
    };
    let bytes = match source {
        CertificateSource::File(path) => match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => return vec![unreadable(format!("reading {label}: {error}"))],
        },
        CertificateSource::Loaded { pem, .. } => pem(),
    };
    let mut entries = Vec::new();
    for pem in x509_parser::pem::Pem::iter_from_buffer(&bytes) {
        let parsed = pem.map_err(|error| error.to_string()).and_then(|pem| {
            if pem.label != "CERTIFICATE" {
                return Ok(None);
            }
            let certificate = pem.parse_x509().map_err(|error| error.to_string())?;
            Ok(Some((
                certificate.subject().to_string(),
                certificate.validity().not_after.timestamp(),
                fingerprint(&pem.contents),
            )))
        });
        match parsed {
            Ok(Some((subject, not_after, sha256_fingerprint))) => {
                let days_left = (not_after - now_secs).div_euclid(86_400);
                let status = if not_after <= now_secs {
                    TrustStatus::Expired
                } else if days_left < i64::from(sources.critical_days) {
                    TrustStatus::Critical
                } else if days_left < i64::from(sources.warning_days) {
                    TrustStatus::Warning
                } else {
                    TrustStatus::Ok
                };
                entries.push(CertificateEntry {
                    purpose: purpose.into(),
                    file: label.clone(),
                    source: kind,
                    subject: Some(subject),
                    not_after: Some(not_after),
                    days_left: Some(days_left),
                    sha256_fingerprint: Some(sha256_fingerprint),
                    status,
                    error: None,
                });
            }
            Ok(None) => {}
            Err(error) => entries.push(unreadable(error)),
        }
    }
    if entries.is_empty() {
        entries.push(unreadable(format!("{label} holds no certificate")));
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(dir: &Path, name: &str, days: i64) -> PathBuf {
        let mut params = rcgen::CertificateParams::new(vec!["hub.example.test".into()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(days);
        let key = rcgen::KeyPair::generate().unwrap();
        let path = dir.join(name);
        std::fs::write(&path, params.self_signed(&key).unwrap().pem()).unwrap();
        path
    }

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// #784: each crossing into warning, critical and expired appends one
    /// change event; a restart (a freshly opened store) does not repeat it,
    /// and a renewed certificate that lapses again is a new crossing.
    #[test]
    fn each_crossing_appends_one_change_event_across_restarts() {
        use crate::storage::OperationalStore as _;
        let dir = scratch("trust-crossing");
        let database = dir.join("tenkai.db");
        let sources = TrustSources {
            certificates: vec![(
                "listener".into(),
                CertificateSource::File(certificate(&dir, "listener.pem", 20)),
            )],
            warning_days: 30,
            critical_days: 7,
            ..TrustSources::default()
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let day = 86_400;
        let tick = |at: i64| {
            let store = crate::storage::SqliteStore::open(&database).unwrap();
            announce_crossing(&store, posture(&sources, at).snapshot(), at * 1_000)
                .unwrap()
                .map(|event| event.resource)
        };
        assert_eq!(tick(now).as_deref(), Some("trust/warning"));
        assert_eq!(tick(now + 60), None);
        assert_eq!(tick(now + 14 * day).as_deref(), Some("trust/critical"));
        assert_eq!(tick(now + 15 * day), None);
        assert_eq!(tick(now + 21 * day).as_deref(), Some("trust/expired"));
        assert_eq!(tick(now + 22 * day), None);
        // Renewed: healthy, recorded once, then inside the warning threshold again.
        certificate(&dir, "listener.pem", 200);
        assert_eq!(tick(now + 23 * day).as_deref(), Some("trust/ok"));
        assert_eq!(tick(now + 24 * day), None);
        assert_eq!(tick(now + 180 * day).as_deref(), Some("trust/warning"));
        assert_eq!(tick(now + 181 * day), None);

        let store = crate::storage::SqliteStore::open(&database).unwrap();
        let events = store.list_change_events_after(0, 100).unwrap();
        assert!(events.iter().all(|event| event.kind
            == crate::change_stream::ChangeEventKind::TrustThresholdCrossed
            && event.environment.is_none()));
        let resources: Vec<_> = events.into_iter().map(|event| event.resource).collect();
        assert_eq!(
            resources,
            [
                "trust/warning",
                "trust/critical",
                "trust/expired",
                "trust/ok",
                "trust/warning"
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An unreadable certificate has no crossing time; the `trust/ok` marker
    /// written when it recovers is what makes its next turn count. A healthy
    /// host with nothing announced records nothing.
    #[test]
    fn an_unreadable_certificate_announces_each_turn_across_restarts() {
        let dir = scratch("trust-unreadable");
        let database = dir.join("tenkai.db");
        let file = dir.join("outbound.pem");
        let sources = TrustSources {
            certificates: vec![("outbound_ca".into(), CertificateSource::File(file.clone()))],
            warning_days: 30,
            critical_days: 7,
            ..TrustSources::default()
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Each tick opens the store afresh, as a restarted server would.
        let tick = |at: i64| {
            let store = crate::storage::SqliteStore::open(&database).unwrap();
            announce_crossing(&store, posture(&sources, at).snapshot(), at * 1_000)
                .unwrap()
                .map(|event| event.resource)
        };
        certificate(&dir, "outbound.pem", 200);
        assert_eq!(tick(now), None);
        std::fs::remove_file(&file).unwrap();
        assert_eq!(tick(now + 60).as_deref(), Some("trust/critical"));
        assert_eq!(tick(now + 120), None);
        certificate(&dir, "outbound.pem", 200);
        assert_eq!(tick(now + 180).as_deref(), Some("trust/ok"));
        assert_eq!(tick(now + 240), None);
        std::fs::remove_file(&file).unwrap();
        assert_eq!(tick(now + 300).as_deref(), Some("trust/critical"));
        assert_eq!(tick(now + 360), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Writers racing on one store, as an old and a new writer across a
    /// takeover can, append a crossing once.
    #[test]
    fn racing_writers_append_a_crossing_once() {
        use crate::storage::OperationalStore as _;
        let dir = scratch("trust-race");
        let database = dir.join("tenkai.db");
        drop(crate::storage::SqliteStore::open(&database).unwrap());
        let snapshot = TrustSnapshot {
            status: TrustStatus::Critical,
            since_ms: 1_000,
        };
        let start = std::sync::Arc::new(std::sync::Barrier::new(4));
        let appended: usize = (0..4)
            .map(|writer| {
                let database = database.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    let store = crate::storage::SqliteStore::open(&database).unwrap();
                    start.wait();
                    announce_crossing(&store, snapshot, 2_000 + writer)
                        .unwrap()
                        .is_some()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|writer| usize::from(writer.join().unwrap()))
            .sum();
        assert_eq!(appended, 1);
        let store = crate::storage::SqliteStore::open(&database).unwrap();
        assert_eq!(store.list_change_events_after(0, 10).unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A fixed CA and the fingerprint `openssl x509 -fingerprint -sha256`
    /// printed for it.
    const FIXTURE_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBbjCCARSgAwIBAgIUSL3R77cFh5zussulS58Eu9/GUMEwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRZml4dHVyZSBydW5uZXIgQ0EwIBcNMjYxMDI4MTk1NjM1WhgP
MjEyNjEwMDQxOTU2MzVaMBwxGjAYBgNVBAMMEWZpeHR1cmUgcnVubmVyIENBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEymXf4tcRPPXy+MDoVDr9l6S6eG2xJpNA
qSQIlFuXsypjV6r9Miw/a62izR116OyE6WMCprjvHcdDj1LMZHrojaMyMDAwHQYD
VR0OBBYEFBFAo5iZFA+K3SLLnyP5+umyOViJMA8GA1UdEwEB/wQFMAMBAf8wCgYI
KoZIzj0EAwIDSAAwRQIga23B1ZgmpD7dXwJ/GxcxpghJ6tw7jrMiz2CyaOz3cp4C
IQDZq+YO1/tDxcu5xN5Lo9z7V6C39Ey9tLwLOK4Lqlybog==
-----END CERTIFICATE-----
";

    /// #809: the runner CA's fingerprint is the one openssl prints, and the
    /// client-certificate requirement is reported as configured.
    #[test]
    fn reports_the_runner_ca_fingerprint_and_the_client_certificate_requirement() {
        for required in [true, false] {
            let shown = posture(
                &TrustSources {
                    certificates: vec![(
                        "runner_ca".into(),
                        CertificateSource::Loaded {
                            name: "runner CA in use".into(),
                            pem: std::sync::Arc::new(|| FIXTURE_CA.as_bytes().to_vec()),
                        },
                    )],
                    warning_days: 30,
                    critical_days: 7,
                    runtime_client_cert_required: required,
                    ..TrustSources::default()
                },
                time::OffsetDateTime::now_utc().unix_timestamp(),
            );
            assert_eq!(shown.runtime_client_cert_required, required);
            assert_eq!(
                shown.tls[0].sha256_fingerprint.as_deref(),
                Some(
                    "C6:32:71:27:76:BC:88:A0:E8:D2:EC:76:3A:DF:E0:49:68:D4:E0:A0:B7:A5:C8:45:7C:F2:0D:0D:34:47:86:06"
                )
            );
        }
    }

    /// A window opening after a certificate lapses is flagged with the first
    /// certificate to lapse; one opening before every expiry is not (#778).
    #[test]
    fn runway_names_the_first_certificate_to_lapse_before_the_window() {
        let dir = std::env::temp_dir().join(format!("tenkai-runway-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let sources = TrustSources {
            certificates: vec![
                (
                    "listener".into(),
                    CertificateSource::File(certificate(&dir, "listener.pem", 200)),
                ),
                (
                    "runner_ca".into(),
                    CertificateSource::File(certificate(&dir, "runner-ca.pem", 5)),
                ),
                (
                    "client_ca".into(),
                    CertificateSource::File(certificate(&dir, "client-ca.pem", 10)),
                ),
            ],
            warning_days: 30,
            critical_days: 7,
            ..TrustSources::default()
        };
        let now_ms = crate::now_millis();
        let day_ms = 86_400_000;

        let flagged = runway(&sources, now_ms, now_ms + 30 * day_ms).unwrap();
        assert_eq!(flagged.credential, "runner_ca (CN=rcgen self signed cert)");
        assert_eq!(flagged.window_opens_at_ms, now_ms + 30 * day_ms);
        assert!((flagged.expires_at_ms - (now_ms + 5 * day_ms)).abs() < day_ms);
        assert_eq!(runway(&sources, now_ms, now_ms + 2 * day_ms), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Certificates are graded against the thresholds, the worst wins, and
    /// signing roots list their signers; no key material is read or shown.
    #[test]
    fn grades_certificates_and_lists_signers_without_key_material() {
        let dir = std::env::temp_dir().join(format!("tenkai-trust-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let healthy = certificate(&dir, "listener.pem", 200);
        let soon = certificate(&dir, "client-ca.pem", 20);
        let urgent = certificate(&dir, "runner-ca.pem", 3);
        let roots = dir.join("release-trust.toml");
        let public = ed25519_dalek::SigningKey::from_bytes(&[3; 32])
            .verifying_key()
            .to_bytes();
        let trust = crate::release_signing::TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: crate::release_signing::key_id(&public),
                identity: "release-bot".into(),
                public_key: {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(public)
                },
            }],
        };
        std::fs::write(&roots, toml::to_string(&trust).unwrap()).unwrap();
        let sources = TrustSources {
            signing: vec![
                ("release".into(), roots),
                ("approval".into(), dir.join("missing.toml")),
            ],
            revocations: None,
            certificates: vec![
                ("listener".into(), CertificateSource::File(healthy)),
                ("client_ca".into(), CertificateSource::File(soon)),
                (
                    "runner_ca".into(),
                    CertificateSource::Loaded {
                        name: "runner CA in use".into(),
                        pem: std::sync::Arc::new(move || std::fs::read(&urgent).unwrap()),
                    },
                ),
                (
                    "outbound_ca".into(),
                    CertificateSource::File(dir.join("absent.pem")),
                ),
            ],
            warning_days: 30,
            critical_days: 7,
            runtime_client_cert_required: false,
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let shown = posture(&sources, now);
        let statuses: Vec<TrustStatus> = shown.tls.iter().map(|entry| entry.status).collect();
        assert_eq!(
            statuses,
            [
                TrustStatus::Ok,
                TrustStatus::Warning,
                TrustStatus::Critical,
                TrustStatus::Critical
            ]
        );
        assert_eq!(shown.status, TrustStatus::Critical);
        assert_eq!(shown.tls[2].file, "runner CA in use");
        assert_eq!(shown.tls[2].source, TrustSource::Loaded);
        assert_eq!(shown.tls[0].source, TrustSource::File);
        assert_eq!(shown.signing[0].signers[0].identity, "release-bot");
        assert!(shown.signing[1].error.is_some());
        let body = serde_json::to_string(&shown).unwrap();
        assert!(!body.contains("PRIVATE KEY") && !body.contains(dir.to_str().unwrap()));
        let expired = posture(
            &TrustSources {
                certificates: vec![(
                    "listener".into(),
                    CertificateSource::File(dir.join("listener.pem")),
                )],
                warning_days: 30,
                critical_days: 7,
                ..TrustSources::default()
            },
            now + 400 * 86_400,
        );
        assert_eq!(expired.status, TrustStatus::Expired);
        // An edited revocation list is an error, not revocations.
        let list = dir.join("revocations.json");
        std::fs::write(&list, "{\"not\": \"a list\"}").unwrap();
        let edited = posture(
            &TrustSources {
                revocations: Some((list, dir.join("release-trust.toml"))),
                ..TrustSources::default()
            },
            now,
        );
        assert!(edited.revocation_list.unwrap().error.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }
}

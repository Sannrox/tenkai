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
    pub signing: Vec<SigningRoot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub revocation_list: Option<InstalledRevocations>,
    pub tls: Vec<CertificateEntry>,
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
            )))
        });
        match parsed {
            Ok(Some((subject, not_after))) => {
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

//! Redacted, signed support bundle for Tenkai alone (#638).
//!
//! `tenkaictl support-bundle export` collects what support needs to
//! diagnose a site that can only carry files out:
//!
//! - the Tenkai version and platform;
//! - configuration by allowlist: numeric and boolean settings with their
//!   values, every other setting as `set` or `unset` only;
//! - store health and object counts;
//! - whether the executor guard is installed;
//! - the recovery diagnostic (ADR 0027) of each environment's latest plan;
//! - optionally, recent `tenkai.*` log events from a log file, keeping only
//!   allowlisted fields;
//! - live workload replica, pod, and event facts for in-cluster releases
//!   (#1017), without log text or event messages.
//!
//! Nothing outside an allowlist leaves: no setting value that could hold a
//! secret, path or host, and no free-text log detail. The bundle is signed
//! with an Ed25519 seed and verifies offline. It is self-contained JSON, so a
//! larger whole-stack bundle can embed it unchanged as one entry.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::release_signing::TrustRoots;

pub const SUPPORT_BUNDLE_SCHEMA: &str = "tenkai.support-bundle.v1";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-SUPPORT-BUNDLE-V1\0";
/// At most this many log events are kept, the most recent ones.
const MAX_LOG_EVENTS: usize = 500;
/// At most this many pods per in-cluster workload in a support bundle.
pub const MAX_SUPPORT_PODS: usize = 20;
/// At most this many event-reason groups per in-cluster workload.
pub const MAX_SUPPORT_EVENTS: usize = 20;

/// Settings whose values are safe to carry: numbers, booleans and fixed
/// words. Any other `TENKAI_*` or `SEKAI_*` setting is reported by name only.
const VALUE_SETTINGS: &[&str] = &[
    "TENKAI_AUDIT_EXPORT_INTERVAL_SECS",
    "TENKAI_BACKUP_INTERVAL_SECS",
    "TENKAI_BACKUP_MAX_AGE_SECS",
    "TENKAI_BACKUP_RETAIN",
    "TENKAI_CLOCK_CHECK_SECS",
    "TENKAI_CLOCK_REFUSE_MS",
    "TENKAI_CLOCK_WARN_MS",
    "TENKAI_IMPORT_SCANNER_TIMEOUT_SECS",
    "TENKAI_TLS_SYSTEM_ROOTS",
];

/// Log fields kept from `tenkai.<event>` lines. Free text such as `detail`
/// can name hosts or paths and is dropped.
const LOG_FIELDS: &[&str] = &[
    "outcome",
    "state",
    "sequence",
    "entries",
    "delivered",
    "deferred",
    "skew_ms",
    "warn_ms",
    "refuse_ms",
    "first_administrator",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSetting {
    pub name: String,
    /// `set` or `unset`.
    pub state: String,
    /// The value, only for allowlisted numeric and boolean settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreStatus {
    /// `PRAGMA user_version` of the database itself, read before anything
    /// opens it; absent when it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    /// The schema version this Tenkai reads and writes.
    pub supported_schema_version: u32,
    /// `ok`, or why the store could not be read.
    pub health: String,
    pub environments: u64,
    pub releases: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportStatement {
    pub created_at_ms: i64,
    pub tenkai_version: String,
    pub os: String,
    pub arch: String,
    pub config: Vec<ConfigSetting>,
    pub store: StoreStatus,
    /// `found`, or why the executor guard could not be found.
    pub executor_guard: String,
    pub recovery: Vec<crate::recovery_bundle::RecoveryBundle>,
    /// What could not be collected, without detail, e.g.
    /// `environment prod: latest plan unreadable`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_errors: Vec<String>,
    pub log_events: Vec<String>,
    /// Live in-cluster workload facts for each environment's latest plan.
    /// Empty and omitted when the site has none, or the cluster cannot be
    /// read (that is a collection error instead).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<SupportWorkload>,
}

/// One in-cluster workload, allowlisted for a support bundle (#1017).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportWorkload {
    pub environment: String,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pods: Vec<SupportPod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<SupportEventCount>,
    /// Report-only live-spec comparison (#1028). Omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_drift: Option<crate::spec_drift::SpecDriftView>,
}

/// One pod of a support-bundle workload: counts and enumerated reasons only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportPod {
    pub phase: String,
    pub ready: bool,
    pub restarts: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exit_code: Option<i32>,
}

/// One Kubernetes event reason and how often it fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportEventCount {
    pub reason: String,
    pub count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportBundle {
    pub schema: String,
    pub key_id: String,
    pub statement: SupportStatement,
    pub signature: String,
}

impl SupportBundle {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading support bundle {}", path.display()))?;
        serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))
    }
}

fn canonical_bytes(statement: &SupportStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

/// Settings from `vars`, redacted by allowlist and sorted by name.
pub fn redacted_config(vars: impl IntoIterator<Item = (String, String)>) -> Vec<ConfigSetting> {
    let mut config: Vec<ConfigSetting> = vars
        .into_iter()
        .filter(|(name, _)| name.starts_with("TENKAI_") || name.starts_with("SEKAI_"))
        .map(|(name, value)| ConfigSetting {
            state: if value.is_empty() { "unset" } else { "set" }.into(),
            value: VALUE_SETTINGS
                .contains(&name.as_str())
                .then(|| typed_value(&name, &value))
                .flatten(),
            name,
        })
        .collect();
    config.sort_by(|left, right| left.name.cmp(&right.name));
    config
}

/// The value of an allowlisted setting, only when it parses as its type:
/// `TENKAI_TLS_SYSTEM_ROOTS` as a boolean, every other one as a whole
/// number. A misused setting holding anything else is reported as `set`.
fn typed_value(name: &str, value: &str) -> Option<String> {
    if name == "TENKAI_TLS_SYSTEM_ROOTS" {
        matches!(value, "true" | "false" | "1" | "0").then(|| value.into())
    } else {
        value.parse::<u64>().ok().map(|number| number.to_string())
    }
}

/// `tenkai.<event>` lines read from `log`, most recent last, with only the
/// leading allowlisted fields of each line kept. The log is streamed: only
/// the last [`MAX_LOG_EVENTS`] events are ever held.
pub fn redacted_log_events(log: impl std::io::BufRead) -> Vec<String> {
    let mut events = std::collections::VecDeque::with_capacity(MAX_LOG_EVENTS);
    for line in log.lines().map_while(Result::ok) {
        let mut tokens = line.split_whitespace();
        let Some(event) = tokens.next() else {
            continue;
        };
        let Some(name) = event.strip_prefix("tenkai.") else {
            continue;
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        // Stop at the first field off the allowlist: what follows may be
        // free text (`detail=...`) whose words only look like fields.
        let fields: Vec<&str> = tokens
            .take_while(|token| {
                token
                    .split_once('=')
                    .is_some_and(|(key, value)| LOG_FIELDS.contains(&key) && is_plain_field(value))
            })
            .collect();
        if events.len() == MAX_LOG_EVENTS {
            events.pop_front();
        }
        events.push_back(
            std::iter::once(event)
                .chain(fields)
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    events.into()
}

fn is_plain_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ',' | '(' | ')'))
}

/// Keep a Kubernetes reason, phase, or revision only when it is a short
/// enumerated token. Free-text messages never pass.
pub fn allowlisted_reason(value: &str) -> Option<String> {
    is_plain_field(value).then(|| value.to_string())
}

/// Serving revision: a DNS-1123 label up to 63 bytes (StatefulSet
/// ControllerRevision names). Free text never passes.
pub fn allowlisted_revision(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return None;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return None;
    }
    bytes
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.'))
        .then(|| value.to_string())
}

/// Collect and sign a support bundle from the embedded store behind `ctx`;
/// `None` when the store could not be opened, which is reported as such.
/// `schema_version` is the database's own version, read before opening.
pub async fn export(
    ctx: Option<&mut Ctx>,
    schema_version: Option<u32>,
    log: Option<&mut (dyn std::io::BufRead + Send)>,
    seed_path: &Path,
    now_ms: i64,
) -> Result<SupportBundle> {
    // Read before any await, so the reader is never held across one.
    let log_events = log.map(redacted_log_events).unwrap_or_default();
    let mut recovery = Vec::new();
    let mut collection_errors = Vec::new();
    let mut workloads = Vec::new();
    let store = match ctx {
        Some(ctx) => StoreStatus {
            schema_version,
            ..collect_store(ctx, &mut recovery, &mut collection_errors, &mut workloads).await
        },
        None => {
            collection_errors.push("store: could not be opened".into());
            StoreStatus {
                schema_version,
                supported_schema_version: crate::storage::SCHEMA_VERSION,
                health: "unreadable".into(),
                environments: 0,
                releases: 0,
            }
        }
    };
    let statement = SupportStatement {
        created_at_ms: now_ms,
        tenkai_version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        config: redacted_config(std::env::vars()),
        store,
        executor_guard: match crate::fenced_mutation::executor_guard_executable() {
            Ok(_) => "found".into(),
            Err(_) => "missing".into(),
        },
        recovery,
        collection_errors,
        log_events,
        workloads,
    };
    let signer = crate::signer::open_key("the support bundle key", seed_path)?;
    let signature = crate::signer::ContentSigner::sign(&signer, &canonical_bytes(&statement)?)?;
    Ok(SupportBundle {
        schema: SUPPORT_BUNDLE_SCHEMA.into(),
        key_id: crate::signer::ContentSigner::key_id(&signer).to_string(),
        statement,
        signature: STANDARD.encode(signature),
    })
}

/// Collect from the embedded database at `database` without changing it:
/// the store is copied through SQLite's read-only backup path, which also
/// checks its integrity, into a private temporary directory, and only the
/// copy is opened (and migrated, if this version is newer). A missing,
/// corrupt or unopenable database is reported, never created or repaired.
pub async fn export_from_database(
    database: &Path,
    log: Option<&mut (dyn std::io::BufRead + Send)>,
    seed_path: &Path,
    now_ms: i64,
) -> Result<SupportBundle> {
    let private = std::env::temp_dir().join(format!("tenkai-support-{}", uuid::Uuid::new_v4()));
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .context("creating the support snapshot directory")?;
    }
    let copy = private.join("tenkai.db");
    let copied =
        database.is_file() && crate::storage::SqliteStore::restore(database, &copy).is_ok();
    // The database's own version, before opening the copy migrates it.
    let schema_version = copied
        .then(|| {
            rusqlite::Connection::open_with_flags(&copy, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .and_then(|connection| {
                    connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                })
                .ok()
        })
        .flatten();
    // The control-plane opener: a tenant-mode hub's TENKAI_POSTGRES_URL does
    // not make its SQLite control plane unreadable here.
    let mut ctx = copied
        .then(|| Ctx::embedded_hub(&copy, false).ok())
        .flatten();
    let bundle = export(ctx.as_mut(), schema_version, log, seed_path, now_ms).await;
    drop(ctx);
    let _ = std::fs::remove_dir_all(&private);
    bundle
}

/// Store status and recovery diagnostics. One environment that cannot be
/// read must not cost the whole bundle: that is when support needs it most.
/// Errors carry no detail, which could name paths.
async fn collect_store(
    ctx: &mut Ctx,
    recovery: &mut Vec<crate::recovery_bundle::RecoveryBundle>,
    collection_errors: &mut Vec<String>,
    workloads: &mut Vec<SupportWorkload>,
) -> StoreStatus {
    // Environment objects, not the summary list: one environment with a bad
    // lease or hold must not hide the others.
    let environments = ctx
        .list_kind(crate::ontology::KIND_ENVIRONMENT)
        .await
        .map(|objects| {
            objects
                .into_iter()
                .map(|object| object.name)
                .collect::<Vec<_>>()
        });
    let releases = crate::catalog::list_releases(ctx).await;
    let store = StoreStatus {
        schema_version: None,
        supported_schema_version: crate::storage::SCHEMA_VERSION,
        health: match (&environments, &releases) {
            (Ok(_), Ok(_)) => "ok".into(),
            _ => "unreadable".into(),
        },
        environments: environments.as_ref().map_or(0, |list| list.len() as u64),
        releases: releases.as_ref().map_or(0, |list| list.len() as u64),
    };
    for name in environments.unwrap_or_default() {
        match crate::environment::inspect_environment(ctx, &name).await {
            Ok(report) => {
                if let Some(plan) = report.latest_plan.as_ref() {
                    match crate::recovery_bundle::export(ctx, &name, &plan.id).await {
                        Ok(diagnostic) => recovery.push(diagnostic),
                        Err(_) => collection_errors.push(format!(
                            "environment {name}: recovery diagnostic unavailable"
                        )),
                    }
                }
                if plan_has_in_cluster_release(ctx, report.latest_plan.as_ref()).await {
                    match crate::environment::cluster_config_path(ctx, &name).await {
                        Ok(Some(path)) if path.is_file() => {
                            let env = name.clone();
                            match tokio::task::spawn_blocking(move || {
                                collect_env_workloads(&env, &path)
                            })
                            .await
                            {
                                Ok(Ok(found)) => {
                                    workloads.extend(found.into_iter().map(|mut workload| {
                                        workload.spec_drift = spec_drift_for_workload(
                                            report
                                                .subscriptions
                                                .iter()
                                                .filter_map(|row| row.spec_drift.as_ref()),
                                            &workload,
                                        );
                                        workload
                                    }));
                                }
                                _ => collection_errors
                                    .push(format!("environment {name}: cluster unreadable")),
                            }
                        }
                        _ => collection_errors
                            .push(format!("environment {name}: cluster unreadable")),
                    }
                }
            }
            Err(_) => collection_errors.push(format!("environment {name}: unreadable")),
        }
    }
    store
}

fn spec_drift_for_workload<'a>(
    reports: impl IntoIterator<Item = &'a crate::spec_drift::SpecDriftView>,
    workload: &SupportWorkload,
) -> Option<crate::spec_drift::SpecDriftView> {
    for view in reports {
        if view.status == crate::spec_drift::SPEC_DRIFT_UNKNOWN {
            continue;
        }
        if let Some(object) = view.objects.iter().find(|object| {
            object.kind == workload.kind
                && object.name == workload.name
                && object.status != crate::spec_drift::SPEC_DRIFT_UNKNOWN
        }) {
            return Some(crate::spec_drift::SpecDriftView {
                status: object.status.clone(),
                objects: vec![object.clone()],
            });
        }
    }
    None
}

fn collect_env_workloads(environment: &str, cluster_config: &Path) -> Result<Vec<SupportWorkload>> {
    let executors = crate::software_executor::SoftwareExecutors::from_process();
    let Some(adapter) = executors.resolve(Some(
        crate::software_executor::SoftwareExecutorKind::KubernetesInProcess,
    ))?
    else {
        bail!("in-process kubernetes executor is not installed");
    };
    adapter.support_workloads(environment, cluster_config)
}

async fn plan_has_in_cluster_release(
    ctx: &mut Ctx,
    plan: Option<&crate::environment::EnvironmentPlanSummary>,
) -> bool {
    let Some(plan) = plan else {
        return false;
    };
    for step in &plan.steps {
        if step.release_id.is_empty() {
            continue;
        }
        let Ok(kind) = crate::plan::stored_release_executor(ctx, &step.release_id).await else {
            continue;
        };
        if matches!(
            kind,
            Some(crate::software_executor::SoftwareExecutorKind::KubernetesInProcess)
        ) {
            return true;
        }
    }
    false
}

/// Verify a bundle after transfer: schema, a signer trusted at the bundle's
/// `created_at_ms` (ADR 0042), and the embedded recovery diagnostics.
pub fn verify(bundle: &SupportBundle, roots: &TrustRoots) -> Result<()> {
    if bundle.schema != SUPPORT_BUNDLE_SCHEMA {
        bail!("unsupported support bundle schema {}", bundle.schema);
    }
    let signer = roots.resolve_signed_at(
        &bundle.key_id,
        bundle.statement.created_at_ms,
        crate::now_millis(),
    )?;
    crate::signature_verification::verify_strict(
        &signer.verifying_key,
        "support bundle signature",
        &bundle.signature,
        &canonical_bytes(&bundle.statement)?,
    )
    .context("the support bundle was changed after it was signed")?;
    for diagnostic in &bundle.statement.recovery {
        crate::recovery_bundle::verify(diagnostic)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn redaction_keeps_only_allowlisted_values_and_fields() {
        let config = redacted_config([
            ("TENKAI_MANAGEMENT_TOKEN".into(), "s3cret-token".into()),
            ("TENKAI_CA_BUNDLE".into(), "/etc/site/ca.pem".into()),
            (
                "TENKAI_TIME_SOURCE".into(),
                "ntp.customer.example:123".into(),
            ),
            ("TENKAI_BACKUP_RETAIN".into(), "7".into()),
            // An allowlisted name with a value that is not a plain word.
            ("TENKAI_CLOCK_WARN_MS".into(), "host.example".into()),
            ("TENKAI_CLOCK_REFUSE_MS".into(), "customer-db".into()),
            ("HOME".into(), "/home/operator".into()),
        ]);
        let rendered = serde_json::to_string(&config).unwrap();
        for secret in [
            "s3cret",
            "/etc/site",
            "customer.example",
            "host.example",
            "customer-db",
            "/home",
        ] {
            assert!(!rendered.contains(secret), "{secret} leaked: {rendered}");
        }
        assert_eq!(config.len(), 6);
        let retain = config
            .iter()
            .find(|c| c.name == "TENKAI_BACKUP_RETAIN")
            .unwrap();
        assert_eq!(retain.value.as_deref(), Some("7"));
        let token = config
            .iter()
            .find(|c| c.name == "TENKAI_MANAGEMENT_TOKEN")
            .unwrap();
        assert_eq!(
            (token.state.as_str(), token.value.as_deref()),
            ("set", None)
        );

        let log = "\
tenkai.backup outcome=ok file=tenkai-backup-1.db sha256=sha256:ab
tenkai.backup outcome=failed detail=cannot read directory state=customer-secret
tenkai.clock state=warn skew_ms=1500 warn_ms=1000 refuse_ms=30000
GET /v1/fleet/status from 10.0.0.7 user=alice
tenkai.audit_export outcome=ok sequence=3 entries=12";
        let events = redacted_log_events(log.as_bytes());
        assert!(!events.concat().contains("customer-secret"));
        assert_eq!(
            events,
            vec![
                "tenkai.backup outcome=ok",
                "tenkai.backup outcome=failed",
                "tenkai.clock state=warn skew_ms=1500 warn_ms=1000 refuse_ms=30000",
                "tenkai.audit_export outcome=ok sequence=3 entries=12",
            ]
        );
    }

    #[test]
    fn workload_reasons_drop_free_text_and_old_bundles_still_parse() {
        assert_eq!(
            allowlisted_reason("CrashLoopBackOff").as_deref(),
            Some("CrashLoopBackOff")
        );
        assert_eq!(allowlisted_reason("Error").as_deref(), Some("Error"));
        assert!(allowlisted_reason("host not found in upstream \"api\"").is_none());
        assert!(allowlisted_reason("back-off 40s restarting failed container=app").is_none());
        let sts_revision = "nginx-production-cache-statefulset-7d9f8c6b5a";
        assert!(sts_revision.len() > 40 && sts_revision.len() <= 63);
        assert_eq!(
            allowlisted_revision(sts_revision).as_deref(),
            Some(sts_revision)
        );
        assert_eq!(allowlisted_revision("1").as_deref(), Some("1"));
        assert!(allowlisted_revision("host not found").is_none());
        assert!(allowlisted_revision(&"a".repeat(64)).is_none());

        let workload = SupportWorkload {
            environment: "lab".into(),
            kind: "Deployment".into(),
            name: "web".into(),
            desired: Some(1),
            ready: Some(0),
            updated: Some(1),
            revision: Some("1".into()),
            pods: vec![SupportPod {
                phase: "Running".into(),
                ready: false,
                restarts: 4,
                waiting_reason: Some("CrashLoopBackOff".into()),
                last_reason: Some("Error".into()),
                last_exit_code: Some(1),
            }],
            events: vec![SupportEventCount {
                reason: "BackOff".into(),
                count: 6,
            }],
            spec_drift: None,
        };
        let rendered = serde_json::to_string(&workload).unwrap();
        assert!(!rendered.contains("host not found"), "{rendered}");

        let other = crate::spec_drift::SpecDriftView {
            status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
            objects: vec![crate::spec_drift::SpecDriftObject {
                kind: "Deployment".into(),
                name: "other".into(),
                status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
                fields: vec!["containers".into()],
            }],
        };
        let matching = crate::spec_drift::SpecDriftView {
            status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
            objects: vec![crate::spec_drift::SpecDriftObject {
                kind: "Deployment".into(),
                name: "web".into(),
                status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
                fields: vec!["images".into()],
            }],
        };
        let attached = spec_drift_for_workload([&other, &matching], &workload).unwrap();
        assert_eq!(attached.objects[0].name, "web");
        assert_eq!(attached.objects[0].fields, vec!["images"]);
        assert_eq!(
            spec_drift_for_workload([&crate::spec_drift::SpecDriftView::unknown()], &workload),
            None
        );
        let mixed = crate::spec_drift::SpecDriftView {
            status: crate::spec_drift::SPEC_DRIFT_MODIFIED.into(),
            objects: vec![crate::spec_drift::SpecDriftObject {
                kind: "Deployment".into(),
                name: "web".into(),
                status: crate::spec_drift::SPEC_DRIFT_UNKNOWN.into(),
                fields: Vec::new(),
            }],
        };
        assert_eq!(spec_drift_for_workload([&mixed], &workload), None);

        let old = serde_json::json!({
            "created_at_ms": 1,
            "tenkai_version": "0.8.0",
            "os": "linux",
            "arch": "x86_64",
            "config": [],
            "store": {
                "supported_schema_version": 1,
                "health": "ok",
                "environments": 0,
                "releases": 0
            },
            "executor_guard": "found",
            "recovery": [],
            "log_events": []
        });
        let statement: SupportStatement = serde_json::from_value(old).unwrap();
        assert!(statement.workloads.is_empty());
    }

    #[tokio::test]
    async fn the_bundle_verifies_after_transfer_and_refuses_edits() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "tenkai-support-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = dir.join("support.seed");
        std::fs::write(&seed, [9_u8; 32]).unwrap();
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        let public = SigningKey::from_bytes(&[9_u8; 32])
            .verifying_key()
            .to_bytes();
        let roots = TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: crate::signature_verification::key_id(&public),
                identity: "support".into(),
                public_key: STANDARD.encode(public),
                not_before: None,
                not_after: None,
                ..Default::default()
            }],
        };
        let mut ctx = Ctx::embedded(dir.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "site")
            .await
            .unwrap();
        let mut log: &[u8] = b"tenkai.backup outcome=ok";
        let bundle = export(Some(&mut ctx), None, Some(&mut log), &seed, 1_000)
            .await
            .unwrap();
        assert_eq!(bundle.statement.store.health, "ok");
        assert_eq!(bundle.statement.store.environments, 1);
        // Without a store the bundle is still written, saying so.
        let without = export(None, None, None, &seed, 1_000).await.unwrap();
        assert_eq!(without.statement.store.health, "unreadable");
        verify(&without, &roots).unwrap();

        // From a database path: the live file is not changed, and a missing
        // one is not created.
        drop(ctx);
        let database = dir.join("tenkai.db");
        let before = std::fs::read(&database).unwrap();
        let from_path = export_from_database(&database, None, &seed, 1_000)
            .await
            .unwrap();
        assert_eq!(from_path.statement.store.environments, 1);
        assert_eq!(
            from_path.statement.store.schema_version,
            Some(crate::storage::SCHEMA_VERSION)
        );
        assert_eq!(std::fs::read(&database).unwrap(), before);
        let missing = dir.join("missing.db");
        let none = export_from_database(&missing, None, &seed, 1_000)
            .await
            .unwrap();
        assert_eq!(none.statement.store.health, "unreadable");
        assert!(!missing.exists());

        // Through a file, as after offline transfer.
        let path = dir.join("support.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        verify(&SupportBundle::load(&path).unwrap(), &roots).unwrap();
        let mut edited = bundle;
        edited
            .statement
            .log_events
            .push("tenkai.forged outcome=ok".into());
        assert!(verify(&edited, &roots).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// In-process plans without a kubeconfig still sign, with a collection
    /// error and no path. Helm plans skip cluster collection entirely.
    #[tokio::test]
    async fn collect_store_records_cluster_errors_only_for_in_process_plans() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "tenkai-support-cluster-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = dir.join("support.seed");
        std::fs::write(&seed, [9_u8; 32]).unwrap();
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        let public = SigningKey::from_bytes(&[9_u8; 32])
            .verifying_key()
            .to_bytes();
        let roots = TrustRoots {
            version: crate::release_signing::TRUST_ROOT_VERSION,
            signers: vec![crate::release_signing::TrustedSigner {
                key_id: crate::signature_verification::key_id(&public),
                identity: "support".into(),
                public_key: STANDARD.encode(public),
                not_before: None,
                not_after: None,
                ..Default::default()
            }],
        };
        let mut ctx = Ctx::embedded(dir.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "cluster", "in-process")
            .await
            .unwrap();
        crate::plan::env_add(&mut ctx, "charts", "helm")
            .await
            .unwrap();
        store_release_and_plan(
            &mut ctx,
            "cluster",
            "cluster-app",
            "1.0.0",
            "kubernetes-inprocess",
            100,
        )
        .await;
        store_release_and_plan(&mut ctx, "charts", "chart-app", "1.0.0", "helm", 200).await;

        let mut log: &[u8] = b"tenkai.backup outcome=ok";
        let bundle = export(Some(&mut ctx), None, Some(&mut log), &seed, 1_000)
            .await
            .unwrap();
        verify(&bundle, &roots).unwrap();
        assert!(bundle.statement.workloads.is_empty(), "{bundle:?}");
        assert!(
            bundle
                .statement
                .collection_errors
                .iter()
                .any(|error| error == "environment cluster: cluster unreadable"),
            "{:?}",
            bundle.statement.collection_errors
        );
        assert!(
            bundle
                .statement
                .collection_errors
                .iter()
                .all(|error| error != "environment charts: cluster unreadable"),
            "{:?}",
            bundle.statement.collection_errors
        );
        let rendered = serde_json::to_string(&bundle.statement).unwrap();
        assert!(!rendered.contains(&dir.display().to_string()), "{rendered}");
        let _ = std::fs::remove_dir_all(dir);
    }

    async fn store_release_and_plan(
        ctx: &mut Ctx,
        environment: &str,
        product: &str,
        version: &str,
        executor: &str,
        created_at: i64,
    ) {
        let release_id = crate::ontology::release_id(product, version);
        ctx.create_once(crate::pb::sekai::Object {
            id: release_id.clone(),
            kind: crate::ontology::KIND_RELEASE.into(),
            name: format!("{product}@{version}"),
            namespace: crate::ontology::NS.into(),
            properties: std::collections::HashMap::from([
                ("product".into(), product.into()),
                ("version".into(), version.into()),
                (
                    "manifest".into(),
                    format!(
                        "[product]\nname = \"{product}\"\nversion = \"{version}\"\n\n[deploy]\nexecutor = \"{executor}\"\n"
                    ),
                ),
            ]),
            ..Default::default()
        })
        .await
        .unwrap();
        let mut plan = crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: String::new(),
            content_id: String::new(),
            environment: environment.into(),
            created_at,
            inputs: vec![crate::plan::DesiredStateInput {
                product: product.into(),
                instance: String::new(),
                channel: "stable".into(),
                channel_id: format!("tenkai:channel:{product}/stable"),
                desired_version: version.into(),
                release_id: release_id.clone(),
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                deployed_version: None,
                providers: Default::default(),
            }],
            steps: vec![crate::plan::Step {
                id: String::new(),
                order: 0,
                product: product.into(),
                instance: String::new(),
                action: crate::plan::Action::Install,
                from: None,
                to: version.into(),
                release_id,
                release_digest: "abc".into(),
                artifact_digest: "abc".into(),
                workdir: ".".into(),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
            }],
            state: crate::plan::PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        plan.bind_content_identity().unwrap();
        crate::plan::store(ctx, &plan).await.unwrap();
    }
}

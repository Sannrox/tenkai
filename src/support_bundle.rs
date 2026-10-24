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
//!   allowlisted fields.
//!
//! Nothing outside an allowlist leaves: no setting value that could hold a
//! secret, path or host, and no free-text log detail. The bundle is signed
//! with an Ed25519 seed and verifies offline. It is self-contained JSON, so a
//! larger whole-stack bundle can embed it unchanged as one entry.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::release_signing::TrustRoots;

pub const SUPPORT_BUNDLE_SCHEMA: &str = "tenkai.support-bundle.v1";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-SUPPORT-BUNDLE-V1\0";
/// At most this many log events are kept, the most recent ones.
const MAX_LOG_EVENTS: usize = 500;

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

/// Collect and sign a support bundle from the embedded store behind `ctx`;
/// `None` when the store could not be opened, which is reported as such.
/// `schema_version` is the database's own version, read before opening.
pub async fn export(
    ctx: Option<&mut Ctx>,
    schema_version: Option<u32>,
    log: Option<&mut dyn std::io::BufRead>,
    seed_path: &Path,
    now_ms: i64,
) -> Result<SupportBundle> {
    // Read before any await, so the reader is never held across one.
    let log_events = log.map(redacted_log_events).unwrap_or_default();
    let mut recovery = Vec::new();
    let mut collection_errors = Vec::new();
    let store = match ctx {
        Some(ctx) => StoreStatus {
            schema_version,
            ..collect_store(ctx, &mut recovery, &mut collection_errors).await
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
    };
    let key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let signature = key.sign(&canonical_bytes(&statement)?);
    Ok(SupportBundle {
        schema: SUPPORT_BUNDLE_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&key.verifying_key().to_bytes()),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

/// Collect from the embedded database at `database` without changing it:
/// the store is copied through SQLite's read-only backup path, which also
/// checks its integrity, into a private temporary directory, and only the
/// copy is opened (and migrated, if this version is newer). A missing,
/// corrupt or unopenable database is reported, never created or repaired.
pub async fn export_from_database(
    database: &Path,
    log: Option<&mut dyn std::io::BufRead>,
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
                if let Some(plan) = report.latest_plan {
                    match crate::recovery_bundle::export(ctx, &name, &plan.id).await {
                        Ok(diagnostic) => recovery.push(diagnostic),
                        Err(_) => collection_errors.push(format!(
                            "environment {name}: recovery diagnostic unavailable"
                        )),
                    }
                }
            }
            Err(_) => collection_errors.push(format!("environment {name}: unreadable")),
        }
    }
    store
}

/// Verify a bundle after transfer: schema, a trusted signer, and the
/// embedded recovery diagnostics.
pub fn verify(bundle: &SupportBundle, roots: &TrustRoots) -> Result<()> {
    if bundle.schema != SUPPORT_BUNDLE_SCHEMA {
        bail!("unsupported support bundle schema {}", bundle.schema);
    }
    let signer = roots.resolve(&bundle.key_id)?;
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
}

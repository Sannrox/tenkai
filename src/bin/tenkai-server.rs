//! Long-running network host for the Tenkai application core.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tenkai::assertion_verifier::{JwtAssertionVerifier, JwtEnterpriseAuthExtension};
use tenkai::auth_context::{
    AUTH_CONTEXT_CONTRACT_VERSION, AuthHostConfig, EnterpriseAuthExtension,
};
use tenkai::postgres_tenant::{
    resolve_reconcile_fence_for_replicas, resolve_server_tenant_store,
    tenant_postgres_store_capabilities,
};
use tenkai::reconciler::{Config as ReconcilerConfig, Reconciler};
use tenkai::runtime_capabilities::{
    RuntimeRequirements, community_auth_capabilities, community_sqlite_profile,
    enterprise_auth_capabilities, validate_runtime_capabilities,
};
use tenkai::server::{ServerConfig, router};
use tenkai::storage::{OperationalStore, SqliteStore};

const JWT_AUTH_EXTENSION_ID: &str = "auth.jwt.aldunis";
const JWT_VERIFIER_CONFIG_ENV: &str = "TENKAI_JWT_VERIFIER_CONFIG";

#[derive(Parser)]
#[command(
    name = "tenkai-server",
    version,
    about = "Tenkai network control plane"
)]
struct Cli {
    #[arg(long, env = "TENKAI_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(
        long,
        env = "TENKAI_DATABASE",
        default_value = ".tenkai-state/tenkai.db"
    )]
    database: PathBuf,
    #[arg(long, default_value_t = 10)]
    reconcile_interval: u64,
    #[arg(long, default_value_t = 8)]
    max_concurrency: usize,
    /// Use Tenkai's in-process state or an explicitly configured remote provider.
    #[arg(long, value_enum, default_value_t = ProviderMode::Embedded)]
    provider_mode: ProviderMode,
    /// Require tenant isolation capability before accepting traffic.
    #[arg(long, default_value_t = false)]
    tenant_mode: bool,
    /// Planned control-plane replica count. Values above 1 require shared replica-safe state.
    #[arg(long, default_value_t = 1)]
    replica_count: u32,
    /// Require high-availability capability before accepting traffic.
    #[arg(long, default_value_t = false)]
    require_high_availability: bool,
    /// Require enterprise authentication capability before accepting traffic.
    #[arg(long, default_value_t = false)]
    require_enterprise_auth: bool,
    /// Minimum operational store migration level required at startup.
    #[arg(long, default_value_t = 1)]
    min_migration_level: u32,
    /// Require an enterprise JWT verifier configured by TENKAI_JWT_VERIFIER_CONFIG.
    #[arg(long, default_value_t = false)]
    with_enterprise_auth: bool,
    /// Expose unauthenticated `GET /metrics` OpenMetrics on the loopback listener (#137).
    #[arg(long, env = "TENKAI_ENABLE_METRICS", default_value_t = false)]
    enable_metrics: bool,
    /// Enable the authenticated, non-executable local demo fixture surface.
    #[arg(long, default_value_t = false)]
    with_development_fixtures: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderMode {
    Embedded,
    Remote,
}

struct EnterpriseAuthComposition {
    auth_host: AuthHostConfig,
    extension: Option<Arc<dyn EnterpriseAuthExtension>>,
}

fn compose_enterprise_auth(
    trust_path: Option<&std::path::Path>,
    requested: bool,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
    let Some(trust_path) = trust_path else {
        anyhow::ensure!(
            !requested,
            "enterprise authentication requires {JWT_VERIFIER_CONFIG_ENV} to name a JWT trust file containing public verification keys"
        );
        return Ok(EnterpriseAuthComposition {
            auth_host: AuthHostConfig::community(),
            extension: None,
        });
    };

    let verifier = JwtAssertionVerifier::from_path(trust_path).with_context(|| {
        format!(
            "loading enterprise JWT trust configuration from {}",
            trust_path.display()
        )
    })?;
    let audience = verifier.config().audience.clone();
    let extension: Arc<dyn EnterpriseAuthExtension> =
        Arc::new(JwtEnterpriseAuthExtension::from_jwt_verifier(
            JWT_AUTH_EXTENSION_ID,
            verifier,
            require_tenant,
        ));
    Ok(EnterpriseAuthComposition {
        auth_host: AuthHostConfig {
            required_extension_id: Some(JWT_AUTH_EXTENSION_ID.into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some(audience),
        },
        extension: Some(extension),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    anyhow::ensure!(
        cli.listen.ip().is_loopback(),
        "tenkai-server currently accepts plaintext HTTP only and must bind to loopback; use an authenticated TLS reverse proxy for remote access"
    );
    let management_token =
        std::env::var("TENKAI_MANAGEMENT_TOKEN").context("TENKAI_MANAGEMENT_TOKEN is required")?;
    let runtime_assignments = std::env::var("TENKAI_RUNTIME_TOKENS")
        .ok()
        .map(|value| serde_json::from_str::<HashMap<String, String>>(&value))
        .transpose()
        .context("TENKAI_RUNTIME_TOKENS must be a JSON object mapping tokens to environments")?
        .unwrap_or_default();
    let development_fixture_principals = std::env::var("TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS")
        .ok()
        .map(|value| serde_json::from_str::<Vec<String>>(&value))
        .transpose()
        .context("TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS must be a JSON array of principal ids")?
        .unwrap_or_default()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        cli.with_development_fixtures || development_fixture_principals.is_empty(),
        "TENKAI_DEVELOPMENT_FIXTURE_PRINCIPALS requires --with-development-fixtures"
    );

    if let Some(parent) = cli.database.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("creating operational state directory {}", parent.display())
        })?;
    }
    let store = Arc::new(
        SqliteStore::open(&cli.database)
            .with_context(|| format!("opening {}", cli.database.display()))?,
    );
    let jwt_trust_path = std::env::var_os(JWT_VERIFIER_CONFIG_ENV).map(PathBuf::from);
    let enterprise_auth = compose_enterprise_auth(
        jwt_trust_path.as_deref(),
        cli.with_enterprise_auth || cli.require_enterprise_auth || cli.tenant_mode,
        cli.tenant_mode,
    )?;
    let auth_capabilities = if enterprise_auth.extension.is_some() {
        enterprise_auth_capabilities()
    } else {
        community_auth_capabilities()
    };
    let mut capabilities = community_sqlite_profile(auth_capabilities);
    // Prefer the live store advertisement so adapters own their claims.
    if let Some(store_component) = capabilities
        .components
        .iter_mut()
        .find(|component| component.component_id == "store.sqlite")
    {
        *store_component = store.runtime_capabilities();
    } else {
        capabilities.components.push(store.runtime_capabilities());
    }

    // Tenant mode requires durable Postgres hub store (#127): feature + URL.
    let tenant_store = resolve_server_tenant_store(cli.tenant_mode)
        .context("resolving tenant operational store for tenant mode")?;
    if let Some(ref tenant) = tenant_store {
        capabilities.components.push(tenant.runtime_capabilities());
        // Keep sqlite component for community ops tables; tenant adapter is additive.
        let _ = tenant_postgres_store_capabilities();
        if cli.tenant_mode {
            capabilities.profile = "enterprise-tenant-postgres".into();
        }
    }

    let requirements = RuntimeRequirements {
        tenant_mode: cli.tenant_mode,
        replica_count: cli.replica_count,
        require_high_availability: cli.require_high_availability,
        require_enterprise_authentication: cli.require_enterprise_auth,
        min_migration_level: cli.min_migration_level,
    };
    // Fail before accepting traffic when the composed runtime cannot satisfy
    // the requested capability set (tenant mode, multi-replica, HA, auth).
    validate_runtime_capabilities(&capabilities, &requirements)
        .with_context(|| "runtime capability negotiation failed at startup")?;

    let ctx = match cli.provider_mode {
        ProviderMode::Embedded => tenkai::client::Ctx::embedded(&cli.database)
            .context("opening embedded application state")?,
        ProviderMode::Remote => tenkai::client::connect()
            .await
            .context("connecting explicitly configured remote provider")?,
    };
    let runtime_environments = runtime_assignments
        .values()
        .cloned()
        .collect::<HashSet<_>>();
    let mut reconciler = Reconciler::new(
        ctx,
        ReconcilerConfig {
            max_concurrency: cli.max_concurrency,
            instance_id: format!(
                "tenkai-server-{}",
                std::env::var("TENKAI_INSTANCE_ID")
                    .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
            ),
            ..ReconcilerConfig::default()
        },
    )?
    .with_runtime_environments(runtime_environments);
    // Multi-host tick fencing (#129 / #135): durable Postgres fence when
    // TENKAI_POSTGRES_URL + features postgres; otherwise process-shared only.
    if let Some(fence) = resolve_reconcile_fence_for_replicas(cli.replica_count)
        .context("resolving multi-replica reconcile tick fence")?
    {
        reconciler = reconciler.with_shared_fence(fence);
    }
    let reconciler = Arc::new(reconciler);
    let app = router(
        ServerConfig {
            management_token,
            runtime_assignments,
            requirements,
            capabilities: capabilities.clone(),
            auth_host: enterprise_auth.auth_host,
            enterprise_auth: enterprise_auth.extension,
            federation: tenkai::federated_identity::FederationConfig::community(),
            identity_directory: std::sync::Arc::new(
                tenkai::federated_identity::IdentityDirectory::new(),
            ),
            tenant_store,
            metrics_enabled: cli.enable_metrics,
            development_fixtures: cli.with_development_fixtures.then_some(
                tenkai::server::DevelopmentFixtureConfig {
                    allowed_principals: development_fixture_principals,
                },
            ),
        },
        reconciler.clone(),
        store,
    )?;
    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    println!(
        "tenkai-server listening on {} profile={} capabilities={}",
        listener.local_addr()?,
        capabilities.profile,
        capabilities.diagnostic_names().join(",")
    );

    let interval = Duration::from_secs(cli.reconcile_interval);
    anyhow::ensure!(
        !interval.is_zero(),
        "reconcile interval must be greater than zero"
    );
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let reconcile_task = tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = timer.tick() => {
                    match reconciler.run_once().await {
                        Ok(report) => {
                            let diag = report.diagnostics();
                            // Structured diagnostics: stable field names, no secrets.
                            eprintln!(
                                "tenkai.reconcile outcome={} environments_total={} environments_failed={} environments_current={} environments_applied={} environments_busy={} environments_deferred={} environments_awaiting_runtime={} environments_awaiting_approval={}",
                                diag.outcome,
                                diag.environments_total,
                                diag.environments_failed,
                                diag.environments_current,
                                diag.environments_applied,
                                diag.environments_busy,
                                diag.environments_deferred,
                                diag.environments_awaiting_runtime,
                                diag.environments_awaiting_approval
                            );
                        }
                        Err(error) => {
                            eprintln!("tenkai.reconcile outcome=error detail=tick_failed");
                            eprintln!("reconciliation tick failed: {error:#}");
                        }
                    }
                }
            }
        }
    });

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("failed to install shutdown handler: {error}");
            }
            let _ = shutdown_tx.send(true);
        })
        .await;
    reconcile_task
        .await
        .context("joining reconciliation task during shutdown")?;
    result.context("serving Tenkai API")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    fn trust_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tenkai-jwt-trust-{}-{}.toml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let public_key = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[7_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        std::fs::write(
            &path,
            format!(
                "issuer = \"https://aldunis.example.test/\"\naudience = \"tenkai-control-plane\"\nclock_skew_secs = 60\n\n[[keys]]\nkey_id = \"active\"\npublic_key = \"{public_key}\"\n"
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn community_composition_stays_tenant_free_without_trust_config() {
        let composition = compose_enterprise_auth(None, false, false).unwrap();
        assert!(composition.extension.is_none());
        assert_eq!(composition.auth_host, AuthHostConfig::community());
    }

    #[test]
    fn requested_enterprise_auth_fails_without_trust_config() {
        let error = compose_enterprise_auth(None, true, true)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(JWT_VERIFIER_CONFIG_ENV), "{error}");
        assert!(!error.contains("token"));
        assert!(!error.contains("private"));
    }

    #[test]
    fn usable_trust_config_wires_required_extension_and_audience() {
        let path = trust_file();
        let composition = compose_enterprise_auth(Some(&path), true, true).unwrap();
        std::fs::remove_file(path).unwrap();

        let extension = composition.extension.unwrap();
        assert_eq!(extension.extension_id(), JWT_AUTH_EXTENSION_ID);
        assert_eq!(extension.expected_audience(), "tenkai-control-plane");
        assert_eq!(
            composition.auth_host.required_extension_id.as_deref(),
            Some(JWT_AUTH_EXTENSION_ID)
        );
        assert_eq!(
            composition.auth_host.expected_audience.as_deref(),
            Some("tenkai-control-plane")
        );
    }

    #[test]
    fn malformed_trust_config_fails_without_echoing_contents() {
        let path = std::env::temp_dir().join(format!(
            "tenkai-jwt-malformed-{}-{}.toml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let marker = "customer-secret-marker";
        std::fs::write(&path, format!("private_key = \"{marker}\"")).unwrap();
        let error = compose_enterprise_auth(Some(&path), true, true)
            .err()
            .unwrap();
        std::fs::remove_file(path).unwrap();
        let diagnostic = format!("{error:#}");

        assert!(
            diagnostic.contains("loading enterprise JWT trust configuration"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains(marker));
    }
}

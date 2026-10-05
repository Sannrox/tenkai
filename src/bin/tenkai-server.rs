//! Long-running network host for the Tenkai application core.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum};
use tenkai::assertion_verifier::{JwtAssertionVerifier, JwtEnterpriseAuthExtension};
use tenkai::auth_context::{
    AUTH_CONTEXT_CONTRACT_VERSION, AuthHostConfig, EnterpriseAuthExtension,
};
use tenkai::oidc_verifier::{
    JwksCache, OIDC_AUTH_EXTENSION_ID, OidcAuthExtension, OidcClientDiscovery, OidcConfig,
    key_source, spawn_refresher,
};
use tenkai::postgres_tenant::{
    compiled_host_feature_report, require_hub_tenant_mode, resolve_reconcile_fence_for_replicas,
    resolve_server_tenant_store, tenant_postgres_store_capabilities,
};
use tenkai::providers::{
    ChiseiOutcomeProvider, OUTCOME_PROVIDER_REGISTRATION_ENV, deliver_outcome_batch,
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
const OIDC_CONFIG_ENV: &str = "TENKAI_OIDC_CONFIG";

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
    /// Inbound delivery correlation identity for process-wide spans and metrics.
    #[arg(long, env = "TENKAI_OPERATION_ID")]
    operation_id: Option<String>,
    /// Enable the authenticated, non-executable local demo fixture surface.
    #[arg(long, default_value_t = false)]
    with_development_fixtures: bool,
    /// Optional terminal-outcome adapter. Disabled keeps standalone operation network-free.
    #[arg(
        long,
        env = "TENKAI_OUTCOME_PROVIDER",
        value_enum,
        default_value_t = OutcomeProviderMode::Disabled
    )]
    outcome_provider: OutcomeProviderMode,
    /// Namespace admitted by the configured Chisei telemetry-writer policy.
    #[arg(long, env = "TENKAI_OUTCOME_NAMESPACE")]
    outcome_namespace: Option<String>,
    /// Development only: serve a local console build at /ui/ instead of the
    /// bundle embedded by feature `ui`.
    #[arg(long)]
    ui_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderMode {
    Embedded,
    Remote,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutcomeProviderMode {
    Disabled,
    Chisei,
}

struct EnterpriseAuthComposition {
    auth_host: AuthHostConfig,
    extension: Option<Arc<dyn EnterpriseAuthExtension>>,
    oidc_client: Option<OidcClientDiscovery>,
}

/// Paths naming the enterprise verifier; at most one may be set.
#[derive(Clone, Copy, Default)]
struct EnterpriseAuthSources<'a> {
    jwt_trust: Option<&'a std::path::Path>,
    oidc: Option<&'a std::path::Path>,
}

async fn run_blocking_startup<T, F>(operation: &'static str, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .with_context(|| format!("joining blocking startup operation: {operation}"))?
}

fn compose_enterprise_auth(
    sources: EnterpriseAuthSources<'_>,
    requested: bool,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
    match (sources.jwt_trust, sources.oidc) {
        (Some(_), Some(_)) => {
            anyhow::bail!("set only one of {JWT_VERIFIER_CONFIG_ENV} and {OIDC_CONFIG_ENV}")
        }
        (None, None) => {
            anyhow::ensure!(
                !requested,
                "enterprise authentication requires {JWT_VERIFIER_CONFIG_ENV} (JWT trust file with public verification keys) or {OIDC_CONFIG_ENV} (OIDC trust configuration)"
            );
            Ok(EnterpriseAuthComposition {
                auth_host: AuthHostConfig::community(),
                extension: None,
                oidc_client: None,
            })
        }
        (Some(trust_path), None) => compose_jwt_auth(trust_path, require_tenant),
        (None, Some(oidc_path)) => compose_oidc_auth(oidc_path, require_tenant),
    }
}

fn compose_jwt_auth(
    trust_path: &std::path::Path,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
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
        oidc_client: None,
    })
}

/// Load the OIDC trust config and the provider's keys before serving. Startup
/// fails closed when no usable signing key can be loaded.
fn compose_oidc_auth(
    config_path: &std::path::Path,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
    let config = OidcConfig::load(config_path)
        .with_context(|| format!("loading OIDC configuration from {}", config_path.display()))?;
    // Discovery and JWKS use a blocking HTTP client, which must not run on
    // the async runtime's threads.
    let loader_config = config.clone();
    let keys = std::thread::spawn(move || key_source(&loader_config).and_then(JwksCache::load))
        .join()
        .map_err(|_| anyhow::anyhow!("OIDC key loading thread panicked"))?
        .context("loading OIDC signing keys")?;
    let keys = Arc::new(keys);
    let refresh = spawn_refresher(keys.clone(), Duration::from_secs(config.jwks_refresh_secs));
    let audience = config.audience.clone();
    let oidc_client = OidcClientDiscovery::from_config(&config);
    let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(
        OidcAuthExtension::new(config, keys, Some(refresh), require_tenant)
            .context("composing OIDC authentication")?,
    );
    Ok(EnterpriseAuthComposition {
        auth_host: AuthHostConfig {
            required_extension_id: Some(OIDC_AUTH_EXTENSION_ID.into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: Some(audience),
        },
        extension: Some(extension),
        oidc_client,
    })
}

fn parse_cli() -> Cli {
    let matches = Cli::command()
        .after_help(compiled_host_feature_report())
        .get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_cli();
    require_hub_tenant_mode(cli.tenant_mode)
        .context("hub host refuses to start as the community SQLite host")?;
    if let Some(operation_id) = cli
        .operation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        tenkai::telemetry::bind_process_operation_id(operation_id);
    }
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

    if !cli.tenant_mode {
        tenkai::storage::refuse_postgres_on_embedded().context(
            "spoke and community hosts refuse TENKAI_POSTGRES_URL; SQLite is the sole operational store",
        )?;
    }
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
    let outcome_provider = match cli.outcome_provider {
        OutcomeProviderMode::Disabled => {
            anyhow::ensure!(
                cli.outcome_namespace.is_none()
                    && std::env::var_os("TENKAI_OUTCOME_PROVIDER_URL").is_none()
                    && std::env::var_os("TENKAI_OUTCOME_PROVIDER_TOKEN").is_none()
                    && std::env::var_os(OUTCOME_PROVIDER_REGISTRATION_ENV).is_none(),
                "outcome provider configuration requires --outcome-provider chisei"
            );
            None
        }
        OutcomeProviderMode::Chisei => {
            anyhow::ensure!(
                matches!(cli.provider_mode, ProviderMode::Embedded),
                "outcome export requires embedded Tenkai application state so terminal state and outbox enqueue share one transaction"
            );
            let endpoint = std::env::var("TENKAI_OUTCOME_PROVIDER_URL")
                .context("TENKAI_OUTCOME_PROVIDER_URL is required for Chisei outcome export")?;
            let namespace = cli
                .outcome_namespace
                .as_deref()
                .context("TENKAI_OUTCOME_NAMESPACE is required for Chisei outcome export")?;
            let principal = std::env::var("TENKAI_OUTCOME_PROVIDER_PRINCIPAL")
                .unwrap_or_else(|_| "tenkai.outcome".into());
            let token = std::env::var("TENKAI_OUTCOME_PROVIDER_TOKEN").ok();
            let registration = std::env::var(OUTCOME_PROVIDER_REGISTRATION_ENV).with_context(|| {
                format!(
                    "{OUTCOME_PROVIDER_REGISTRATION_ENV} is required after the Sekai producer capability and terminal-outcome schema are registered"
                )
            })?;
            Some(
                ChiseiOutcomeProvider::new_for_export(
                    endpoint,
                    namespace,
                    principal,
                    token,
                    registration,
                )
                .context("validating Chisei outcome adapter configuration")?,
            )
        }
    };
    let jwt_trust_path = std::env::var_os(JWT_VERIFIER_CONFIG_ENV).map(PathBuf::from);
    let oidc_config_path = std::env::var_os(OIDC_CONFIG_ENV).map(PathBuf::from);
    let enterprise_auth = compose_enterprise_auth(
        EnterpriseAuthSources {
            jwt_trust: jwt_trust_path.as_deref(),
            oidc: oidc_config_path.as_deref(),
        },
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
    let tenant_store = run_blocking_startup("tenant operational store", move || {
        resolve_server_tenant_store(cli.tenant_mode).map_err(Into::into)
    })
    .await
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
        ProviderMode::Embedded if cli.tenant_mode => {
            tenkai::client::Ctx::embedded_hub(&cli.database, outcome_provider.is_some())
                .context("opening embedded application state")?
        }
        ProviderMode::Embedded => tenkai::client::Ctx::embedded_with_outcome_export(
            &cli.database,
            outcome_provider.is_some(),
        )
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
    if let Some(fence) = run_blocking_startup("multi-replica reconcile tick fence", move || {
        resolve_reconcile_fence_for_replicas(cli.replica_count).map_err(Into::into)
    })
    .await
    .context("resolving multi-replica reconcile tick fence")?
    {
        reconciler = reconciler.with_shared_fence(fence);
    }
    let reconciler = Arc::new(reconciler);
    let ui_connect_origins = enterprise_auth
        .oidc_client
        .as_ref()
        .map(|client| client.connect_origins.clone())
        .unwrap_or_default();
    let app = router(
        ServerConfig {
            management_token,
            runtime_assignments,
            environment_management_assignments: std::env::var("TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS")
                .ok()
                .map(|value| serde_json::from_str::<std::collections::HashMap<String, String>>(&value))
                .transpose()
                .context("TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS must be a JSON object mapping tokens to environments")?
                .unwrap_or_default(),
            requirements,
            capabilities: capabilities.clone(),
            auth_host: enterprise_auth.auth_host,
            enterprise_auth: enterprise_auth.extension,
            oidc_client: enterprise_auth.oidc_client,
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
            package_migration_trust_roots: std::env::var_os(
                "TENKAI_PACKAGE_MIGRATION_APPROVAL_TRUST_ROOTS",
            )
            .map(std::path::PathBuf::from),
        },
        reconciler.clone(),
        store.clone(),
    )?;
    let ui_source = match &cli.ui_dir {
        Some(dir) => {
            anyhow::ensure!(
                dir.join("index.html").is_file(),
                "--ui-dir {} has no index.html",
                dir.display()
            );
            Some(tenkai::server::ui::UiSource::Directory(dir.clone()))
        }
        None => tenkai::server::ui::UiSource::embedded(),
    };
    let ui_description = match (&ui_source, &cli.ui_dir) {
        (None, _) => None,
        (Some(_), Some(dir)) => Some(format!("dir:{}", dir.display())),
        (Some(_), None) => tenkai::server::ui::UiSource::embedded_tag().map(str::to_owned),
    };
    let app = match ui_source {
        Some(source) => tenkai::server::ui::mount(app, source, &ui_connect_origins)?,
        None => app,
    };
    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    println!(
        "tenkai-server listening on {} profile={} capabilities={}",
        listener.local_addr()?,
        capabilities.profile,
        capabilities.diagnostic_names().join(",")
    );
    if let Some(console) = ui_description {
        println!("tenkai-server console at /ui/ source={console}");
    }

    let interval = Duration::from_secs(cli.reconcile_interval);
    anyhow::ensure!(
        !interval.is_zero(),
        "reconcile interval must be greater than zero"
    );
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let outcome_task = outcome_provider.map(|provider| {
        let outcome_store = store.clone();
        let mut outcome_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(5));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = outcome_shutdown_rx.changed() => {
                        if changed.is_err() || *outcome_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = timer.tick() => {
                        match deliver_outcome_batch(
                            &*outcome_store,
                            &provider,
                            Duration::from_secs(5),
                            tenkai::now_millis(),
                            10,
                        ).await {
                            Ok((delivered, deferred)) if delivered > 0 || deferred > 0 => {
                                eprintln!(
                                    "tenkai.outcome_export delivered={} deferred={}",
                                    delivered, deferred
                                );
                            }
                            Ok(_) => {}
                            Err(error) => {
                                eprintln!(
                                    "tenkai.outcome_export outcome=degraded detail={}",
                                    error
                                );
                            }
                        }
                    }
                }
            }
        })
    });
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
    if let Some(outcome_task) = outcome_task {
        outcome_task
            .await
            .context("joining outcome delivery task during shutdown")?;
    }
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
        let composition =
            compose_enterprise_auth(EnterpriseAuthSources::default(), false, false).unwrap();
        assert!(composition.extension.is_none());
        assert_eq!(composition.auth_host, AuthHostConfig::community());
    }

    #[test]
    fn requested_enterprise_auth_fails_without_trust_config() {
        let error = compose_enterprise_auth(EnterpriseAuthSources::default(), true, true)
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
        let composition = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: Some(&path),
                oidc: None,
            },
            true,
            true,
        )
        .unwrap();
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
        let error = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: Some(&path),
                oidc: None,
            },
            true,
            true,
        )
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

    /// OIDC config backed by a static JWKS file holding the public RFC 7515 A.3 key.
    fn oidc_files() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-oidc-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let jwks = dir.join("jwks.json");
        std::fs::write(
            &jwks,
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"rfc7515-a3","use":"sig","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#,
        )
        .unwrap();
        let config = dir.join("oidc.toml");
        std::fs::write(
            &config,
            format!(
                "issuer = \"https://idp.example.test/realms/ops\"\naudience = \"tenkai\"\njwks_file = \"{}\"\n[client]\nclient_id = \"tenkai-console\"\n[grants]\nclaim = \"groups\"\n[[grants.rules]]\nvalue = \"admins\"\ncapabilities = [\"management\"]\n",
                jwks.display()
            ),
        )
        .unwrap();
        (dir, config)
    }

    #[test]
    fn oidc_config_wires_required_extension_and_client_discovery() {
        let (dir, config) = oidc_files();
        let composition = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: None,
                oidc: Some(&config),
            },
            true,
            false,
        )
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();

        let extension = composition.extension.unwrap();
        assert_eq!(extension.extension_id(), OIDC_AUTH_EXTENSION_ID);
        assert_eq!(extension.expected_audience(), "tenkai");
        assert_eq!(
            composition.auth_host.required_extension_id.as_deref(),
            Some(OIDC_AUTH_EXTENSION_ID)
        );
        let client = composition.oidc_client.unwrap();
        assert_eq!(client.client_id, "tenkai-console");
        assert_eq!(client.scopes, vec!["openid".to_string()]);
    }

    #[test]
    fn oidc_and_jwt_trust_are_mutually_exclusive_and_keys_are_required() {
        let (dir, config) = oidc_files();
        let jwt = trust_file();
        let both = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: Some(&jwt),
                oidc: Some(&config),
            },
            true,
            false,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(both.contains(OIDC_CONFIG_ENV), "{both}");
        std::fs::remove_file(jwt).unwrap();

        std::fs::remove_file(dir.join("jwks.json")).unwrap();
        let missing_keys = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: None,
                oidc: Some(&config),
            },
            true,
            false,
        )
        .err()
        .unwrap();
        assert!(
            format!("{missing_keys:#}").contains("loading OIDC signing keys"),
            "{missing_keys:#}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "current_thread")]
    async fn postgres_adapter_initialization_runs_outside_the_async_runtime() {
        let result = run_blocking_startup("postgres startup regression", || {
            let config = tenkai::postgres_tenant::PostgresTenantConfig::new(
                "postgres://127.0.0.1:1/tenkai",
            )?;
            Ok(config.open())
        })
        .await
        .expect("blocking startup task must join without a nested-runtime panic");

        assert!(
            result.is_err(),
            "the deterministic closed port must not connect"
        );
    }
}

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
use tenkai::deploy_webhook::{ProcessWebhookSecrets, deliver_webhook_batch};
use tenkai::issuer_auth::{ISSUER_AUTH_EXTENSION_ID, IssuerAuthExtension};
use tenkai::oidc_verifier::{
    JwksCache, OIDC_AUTH_EXTENSION_ID, OidcAuthExtension, OidcClientDiscovery, OidcConfig,
    key_source, spawn_refresher,
};
use tenkai::providers::{
    ChiseiOutcomeProvider, OUTCOME_PROVIDER_REGISTRATION_ENV, deliver_outcome_batch,
};
use tenkai::reconciler::{Config as ReconcilerConfig, Reconciler};
use tenkai::runtime_capabilities::{
    RuntimeRequirements, community_auth_capabilities, community_sqlite_profile,
    enterprise_auth_capabilities, shell_executor_capabilities, validate_runtime_capabilities,
};
use tenkai::storage::{OperationalStore, SqliteStore};
use tenkai_http::{ServerConfig, router};
use tenkai_postgres::{
    compiled_host_feature_report_with, require_hub_tenant_mode,
    resolve_reconcile_fence_for_replicas, resolve_server_tenant_store,
    tenant_postgres_store_capabilities,
};

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
    /// Refuse to start unless the shell executor guard resolves: a file named
    /// `tenkai-executor-guard` beside this binary, or the path in TENKAI_EXECUTOR_GUARD.
    #[arg(long, default_value_t = false)]
    require_executor: bool,
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
    /// Mutations whose token actor chain names an agent: `require_approval`
    /// lets agents only create plans, which still need approval under the
    /// environment's policy; `forbid` refuses every agent mutation.
    #[arg(
        long,
        env = "TENKAI_AGENT_ACTOR_POLICY",
        default_value = "require_approval"
    )]
    agent_actor_policy: tenkai::management_operations::AgentActorPolicy,
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

/// Paths naming enterprise verifiers. JWT and OIDC may both be set; tokens are
/// selected by `iss`.
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
        (Some(trust_path), Some(oidc_path)) => {
            compose_issuer_auth(trust_path, oidc_path, require_tenant)
        }
    }
}

fn load_jwt_extension(
    trust_path: &std::path::Path,
    require_tenant: bool,
) -> Result<(String, String, Arc<dyn EnterpriseAuthExtension>)> {
    let verifier = JwtAssertionVerifier::from_path(trust_path).with_context(|| {
        format!(
            "loading enterprise JWT trust configuration from {}",
            trust_path.display()
        )
    })?;
    let issuer = verifier.config().issuer.clone();
    let audience = verifier.config().audience.clone();
    let extension: Arc<dyn EnterpriseAuthExtension> =
        Arc::new(JwtEnterpriseAuthExtension::from_jwt_verifier(
            JWT_AUTH_EXTENSION_ID,
            verifier,
            require_tenant,
        ));
    Ok((issuer, audience, extension))
}

fn compose_jwt_auth(
    trust_path: &std::path::Path,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
    let (_issuer, audience, extension) = load_jwt_extension(trust_path, require_tenant)?;
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
fn load_oidc_extension(
    config_path: &std::path::Path,
    require_tenant: bool,
) -> Result<(
    String,
    Option<OidcClientDiscovery>,
    Arc<dyn EnterpriseAuthExtension>,
)> {
    let config = OidcConfig::load(config_path)
        .with_context(|| format!("loading OIDC configuration from {}", config_path.display()))?;
    match config.fleet_administrator_values().as_slice() {
        [] => eprintln!(
            "tenkai.auth first_administrator=missing detail=no OIDC grant rule gives fleet management; only TENKAI_MANAGEMENT_TOKEN can administer this server (see docs/configure-server-authentication.md#first-administrator)"
        ),
        values => eprintln!(
            "tenkai.auth first_administrator=configured claim={} values={}",
            config.grants.claim,
            values.join(",")
        ),
    }
    if require_tenant
        && config
            .grants
            .tenant_claim
            .as_deref()
            .is_none_or(|claim| claim.trim().is_empty())
    {
        anyhow::bail!(
            "tenant mode requires grants.tenant_claim in the OIDC config so tokens can resolve a tenant"
        );
    }
    // Discovery and JWKS use a blocking HTTP client, which must not run on
    // the async runtime's threads.
    let loader_config = config.clone();
    let keys = std::thread::spawn(move || key_source(&loader_config).and_then(JwksCache::load))
        .join()
        .map_err(|_| anyhow::anyhow!("OIDC key loading thread panicked"))?
        .context("loading OIDC signing keys")?;
    let keys = Arc::new(keys);
    let refresh = spawn_refresher(keys.clone(), Duration::from_secs(config.jwks_refresh_secs));
    let issuer = config.issuer.clone();
    let oidc_client = OidcClientDiscovery::from_config(&config);
    let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(
        OidcAuthExtension::new(config, keys, Some(refresh), require_tenant)
            .context("composing OIDC authentication")?,
    );
    Ok((issuer, oidc_client, extension))
}

fn compose_oidc_auth(
    config_path: &std::path::Path,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
    let (_issuer, oidc_client, extension) = load_oidc_extension(config_path, require_tenant)?;
    let audience = extension.expected_audience().to_string();
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

fn compose_issuer_auth(
    jwt_trust: &std::path::Path,
    oidc_path: &std::path::Path,
    require_tenant: bool,
) -> Result<EnterpriseAuthComposition> {
    let (jwt_issuer, _jwt_audience, jwt_extension) = load_jwt_extension(jwt_trust, require_tenant)?;
    let (oidc_issuer, oidc_client, oidc_extension) =
        load_oidc_extension(oidc_path, require_tenant)?;
    anyhow::ensure!(
        jwt_issuer != oidc_issuer,
        "JWT and OIDC verifiers must use distinct issuers; both are {jwt_issuer}"
    );
    let extension: Arc<dyn EnterpriseAuthExtension> = Arc::new(
        IssuerAuthExtension::new(vec![
            (jwt_issuer, jwt_extension),
            (oidc_issuer, oidc_extension),
        ])
        .context("composing multi-issuer authentication")?,
    );
    Ok(EnterpriseAuthComposition {
        auth_host: AuthHostConfig {
            required_extension_id: Some(ISSUER_AUTH_EXTENSION_ID.into()),
            expected_contract_version: AUTH_CONTEXT_CONTRACT_VERSION,
            expected_audience: None,
        },
        extension: Some(extension),
        oidc_client,
    })
}

fn parse_cli() -> Cli {
    let matches = Cli::command()
        .after_help(compiled_host_feature_report_with(
            cfg!(feature = "postgres"),
            cfg!(feature = "ui"),
        ))
        .get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[tokio::main]
async fn main() -> Result<()> {
    tenkai_executor::install();
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
    tenkai::key_revocation::load_configured()?;
    let management_token = tenkai::secret_source::require("TENKAI_MANAGEMENT_TOKEN")?;
    let runtime_assignments = tenkai::secret_source::read("TENKAI_RUNTIME_TOKENS")?
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

    // A host that must run shell-executor deploys refuses before it binds.
    if cli.require_executor {
        tenkai::fenced_mutation::executor_guard_executable()
            .context("--require-executor: the shell executor is unavailable")?;
    }

    // Bind and serve /healthz before SqliteStore::open so a large legacy import
    // cannot delay the listener (#516). /readyz stays 503 until the store is open.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    let bound = listener.local_addr()?;
    let opening_profile = if cli.tenant_mode {
        "enterprise-tenant-postgres"
    } else {
        "community-sqlite"
    };
    println!("tenkai-server listening on {bound} profile={opening_profile} capabilities=opening");
    let swap = tenkai_http::HotSwap::new(tenkai_http::opening_router(opening_profile, Vec::new()));
    let serving = swap.clone();
    let mut serve_shutdown = shutdown_tx.subscribe();
    let signal_shutdown = shutdown_tx.clone();
    let signal_received = tenkai::shutdown::listen().context("installing shutdown handler")?;
    tokio::spawn(async move {
        let signal = signal_received.await;
        eprintln!("tenkai-server shutting down signal={signal}");
        let _ = signal_shutdown.send(true);
    });
    let server_task = tokio::spawn(async move {
        axum::serve(listener, serving)
            .with_graceful_shutdown(async move {
                loop {
                    if *serve_shutdown.borrow() {
                        break;
                    }
                    if serve_shutdown.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
    });

    let database = cli.database.clone();
    let store = match run_blocking_startup("operational sqlite store", move || {
        SqliteStore::open(&database).with_context(|| format!("opening {}", database.display()))
    })
    .await
    {
        Ok(store) => Arc::new(store),
        Err(error) => {
            let _ = shutdown_tx.send(true);
            let _ = server_task.await;
            return Err(error);
        }
    };
    let outcome_provider = match cli.outcome_provider {
        OutcomeProviderMode::Disabled => {
            anyhow::ensure!(
                cli.outcome_namespace.is_none()
                    && std::env::var_os("TENKAI_OUTCOME_PROVIDER_URL").is_none()
                    && tenkai::secret_source::read("TENKAI_OUTCOME_PROVIDER_TOKEN")?.is_none()
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
            let token = tenkai::secret_source::read("TENKAI_OUTCOME_PROVIDER_TOKEN")?;
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

    // Resolve the deploy guard now so a missing install surfaces at startup and
    // in /readyz capabilities, not at the first shell-executor apply.
    match tenkai::fenced_mutation::executor_guard_executable() {
        Ok(_) => capabilities.components.push(shell_executor_capabilities()),
        Err(error) => eprintln!("tenkai-server warning: shell executor unavailable: {error:#}"),
    }

    let requirements = RuntimeRequirements {
        tenant_mode: cli.tenant_mode,
        replica_count: cli.replica_count,
        require_high_availability: cli.require_high_availability,
        require_enterprise_authentication: cli.require_enterprise_auth,
        min_migration_level: cli.min_migration_level,
        require_shell_executor: cli.require_executor,
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
    let ctx = ctx.with_release_trust_roots(
        std::env::var_os("TENKAI_RELEASE_TRUST_ROOTS").map(std::path::PathBuf::from),
    );
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
    let backups = backup_settings(cli.tenant_mode, &store)?;
    let imports = import_settings()?;
    let import_staging = imports.as_ref().map(|settings| settings.staging.clone());
    let clock_every = clock_settings()?;
    let audit_export = audit_export_settings(cli.tenant_mode)?;
    let app = router(
        ServerConfig {
            management_token,
            runtime_assignments,
            environment_management_assignments: tenkai::secret_source::read("TENKAI_ENVIRONMENT_MANAGEMENT_TOKENS")?
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
                tenkai_http::DevelopmentFixtureConfig {
                    allowed_principals: development_fixture_principals,
                },
            ),
            package_migration_trust_roots: std::env::var_os(
                "TENKAI_PACKAGE_MIGRATION_APPROVAL_TRUST_ROOTS",
            )
            .map(std::path::PathBuf::from),
            release_trust_roots: std::env::var_os("TENKAI_RELEASE_TRUST_ROOTS")
                .map(std::path::PathBuf::from),
            agent_actor_policy: cli.agent_actor_policy,
            backups: backups.as_ref().map(|(backups, _)| backups.clone()),
            imports: imports.clone(),
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
            Some(tenkai_http::ui::UiSource::Directory(dir.clone()))
        }
        None => tenkai_http::ui::UiSource::embedded(),
    };
    let ui_description = match (&ui_source, &cli.ui_dir) {
        (None, _) => None,
        (Some(_), Some(dir)) => Some(format!("dir:{}", dir.display())),
        (Some(_), None) => tenkai_http::ui::UiSource::embedded_tag().map(str::to_owned),
    };
    let app = match ui_source {
        Some(source) => tenkai_http::ui::mount(app, source, &ui_connect_origins)?,
        None => app,
    };
    swap.replace(app);
    println!(
        "tenkai-server ready profile={} capabilities={}",
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
    let host_backups = backups.as_ref().map(|(backups, _)| backups.clone());
    let backup_task = backups.and_then(|(backups, every)| {
        let every = every?;
        let mut backup_shutdown_rx = shutdown_tx.subscribe();
        Some(tokio::spawn(async move {
            let mut timer = tokio::time::interval(every);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = backup_shutdown_rx.changed() => {
                        if changed.is_err() || *backup_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = timer.tick() => {
                        let backups = backups.clone();
                        let taken = tokio::task::spawn_blocking(move || {
                            backups.take(tenkai::now_millis())
                        })
                        .await;
                        match taken {
                            Ok(Ok(manifest)) => eprintln!(
                                "tenkai.backup outcome=ok file={} sha256={}",
                                manifest.file, manifest.sha256
                            ),
                            Ok(Err(error)) => {
                                eprintln!("tenkai.backup outcome=failed detail={error:#}")
                            }
                            Err(error) => eprintln!("tenkai.backup outcome=failed detail={error}"),
                        }
                    }
                }
            }
        }))
    });
    let clock_task = clock_every.and_then(|every| {
        let guard = tenkai::clock_guard::installed()?;
        let mut clock_shutdown_rx = shutdown_tx.subscribe();
        Some(tokio::spawn(async move {
            let mut timer = tokio::time::interval(every);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = clock_shutdown_rx.changed() => {
                        if changed.is_err() || *clock_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = timer.tick() => {
                        let guard = guard.clone();
                        if let Ok(health) = tokio::task::spawn_blocking(move || guard.measure()).await
                            && health.state != "ok"
                        {
                            eprintln!(
                                "tenkai.clock state={} skew_ms={:?} warn_ms={} refuse_ms={}",
                                health.state, health.skew_ms, health.warn_ms, health.refuse_ms
                            );
                        }
                    }
                }
            }
        }))
    });
    let audit_task = audit_export.map(|(dir, seed, every)| {
        let audit_store = store.clone();
        let mut audit_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(every);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick is immediate; the first export waits one period.
            timer.tick().await;
            loop {
                tokio::select! {
                    changed = audit_shutdown_rx.changed() => {
                        if changed.is_err() || *audit_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = timer.tick() => {
                        let (store, dir, seed) = (audit_store.clone(), dir.clone(), seed.clone());
                        let exported = tokio::task::spawn_blocking(move || {
                            // Earlier exports may be signed by a rotated key.
                            let rotated = std::env::var_os("TENKAI_AUDIT_TRUST_ROOTS")
                                .map(|path| tenkai::release_signing::TrustRoots::load(std::path::Path::new(&path)))
                                .transpose()?;
                            tenkai::audit_export::export_next(
                                &*store,
                                &dir,
                                tenkai::now_millis(),
                                &seed,
                                rotated.as_ref(),
                            )
                        })
                        .await;
                        match exported {
                            Ok(Ok(export)) => eprintln!(
                                "tenkai.audit_export outcome=ok sequence={} entries={}",
                                export.statement.sequence,
                                export.statement.entries.len()
                            ),
                            Ok(Err(error)) => {
                                eprintln!("tenkai.audit_export outcome=failed detail={error:#}")
                            }
                            Err(error) => eprintln!("tenkai.audit_export outcome=failed detail={error}"),
                        }
                    }
                }
            }
        })
    });
    // Host events: backup age and clock drift, announced when they turn bad.
    let host_endpoints = tenkai::operational_events::host_endpoints_from_env()?;
    let host_staging = import_staging.clone();
    // Host alerts the outbox has not taken survive a restart beside the store.
    let host_alert_state = cli.database.with_extension("host-alerts.json");
    let host_reconciler = reconciler.clone();
    let host_task = (!host_endpoints.is_empty() || host_staging.is_some()).then(|| {
        let host_store = store.clone();
        let host_backups = host_backups.clone();
        let mut host_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(60));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut watch =
                tenkai::operational_events::HostWatch::with_state_file(host_alert_state);
            loop {
                tokio::select! {
                    changed = host_shutdown_rx.changed() => {
                        if changed.is_err() || *host_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = timer.tick() => {
                        let now = tenkai::now_millis();
                        let backup = host_backups.as_ref().map(|backups| backups.health(now));
                        let clock = tenkai::clock_guard::installed().map(|guard| guard.health());
                        watch.observe(
                            &*host_store,
                            &host_endpoints,
                            backup.as_ref(),
                            clock.as_ref(),
                            now,
                        );
                        // Failed imports the import request could not announce.
                        if let Some(staging) = &host_staging {
                            let mut ctx = host_reconciler.ctx_clone();
                            tenkai::operational_events::announce_failed_imports(
                                &mut ctx,
                                &*host_store,
                                staging,
                                now,
                            )
                            .await;
                        }
                    }
                }
            }
        })
    });
    let webhook_task = {
        let webhook_store = store.clone();
        let mut webhook_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(5));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = webhook_shutdown_rx.changed() => {
                        if changed.is_err() || *webhook_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = timer.tick() => {
                        match deliver_webhook_batch(
                            &*webhook_store,
                            &ProcessWebhookSecrets,
                            Duration::from_secs(5),
                            tenkai::now_millis(),
                            10,
                        ).await {
                            Ok((delivered, deferred)) if delivered > 0 || deferred > 0 => {
                                eprintln!(
                                    "tenkai.deploy_webhook delivered={} deferred={}",
                                    delivered, deferred
                                );
                            }
                            Ok(_) => {}
                            Err(error) => {
                                eprintln!(
                                    "tenkai.deploy_webhook outcome=degraded detail={}",
                                    error
                                );
                            }
                        }
                        match tenkai::operational_events::deliver_batch(
                            &*webhook_store,
                            &ProcessWebhookSecrets,
                            Duration::from_secs(5),
                            tenkai::now_millis(),
                            10,
                        ).await {
                            Ok((delivered, deferred)) if delivered > 0 || deferred > 0 => {
                                eprintln!(
                                    "tenkai.operational_event delivered={} deferred={}",
                                    delivered, deferred
                                );
                            }
                            Ok(_) => {}
                            Err(error) => {
                                eprintln!(
                                    "tenkai.operational_event outcome=degraded detail={}",
                                    error
                                );
                            }
                        }
                    }
                }
            }
        })
    };
    let tick_store = store.clone();
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
                            // Held and approval-waiting plans, once per transition.
                            let mut ctx = reconciler.ctx_clone();
                            tenkai::operational_events::announce_tick(
                                &mut ctx,
                                &*tick_store,
                                &report,
                                tenkai::now_millis(),
                            )
                            .await;
                            let diag = report.diagnostics();
                            // Structured diagnostics: stable field names, no secrets.
                            eprintln!(
                                "tenkai.reconcile outcome={} environments_total={} environments_failed={} environments_current={} environments_applied={} environments_busy={} environments_deferred={} environments_awaiting_runtime={} environments_awaiting_approval={} environments_held={}",
                                diag.outcome,
                                diag.environments_total,
                                diag.environments_failed,
                                diag.environments_current,
                                diag.environments_applied,
                                diag.environments_busy,
                                diag.environments_deferred,
                                diag.environments_awaiting_runtime,
                                diag.environments_awaiting_approval,
                                diag.environments_held
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

    let result = server_task
        .await
        .context("joining HTTP server task during shutdown")?;
    reconcile_task
        .await
        .context("joining reconciliation task during shutdown")?;
    if let Some(outcome_task) = outcome_task {
        outcome_task
            .await
            .context("joining outcome delivery task during shutdown")?;
    }
    webhook_task
        .await
        .context("joining webhook delivery task during shutdown")?;
    if let Some(host_task) = host_task {
        host_task
            .await
            .context("joining host event task during shutdown")?;
    }
    if let Some(audit_task) = audit_task {
        audit_task
            .await
            .context("joining audit export task during shutdown")?;
    }
    if let Some(clock_task) = clock_task {
        clock_task
            .await
            .context("joining clock check task during shutdown")?;
    }
    if let Some(backup_task) = backup_task {
        backup_task
            .await
            .context("joining backup task during shutdown")?;
    }
    result.context("serving Tenkai API")
}

/// Scheduled audit export from `TENKAI_AUDIT_EXPORT_DIR` and
/// `TENKAI_AUDIT_SIGNING_KEY` (an Ed25519 seed file), which must be set
/// together, every `TENKAI_AUDIT_EXPORT_INTERVAL_SECS` (default 86400).
/// Tenant-mode hubs keep tenant records in PostgreSQL and refuse it.
fn audit_export_settings(
    tenant_mode: bool,
) -> Result<Option<(std::path::PathBuf, std::path::PathBuf, Duration)>> {
    if tenant_mode && std::env::var_os("TENKAI_AUDIT_EXPORT_DIR").is_some() {
        anyhow::bail!(
            "TENKAI_AUDIT_EXPORT_DIR exports the SQLite operational store; tenant-mode hubs keep tenant records in PostgreSQL"
        );
    }
    match (
        std::env::var_os("TENKAI_AUDIT_EXPORT_DIR"),
        std::env::var_os("TENKAI_AUDIT_SIGNING_KEY"),
    ) {
        (None, None) => Ok(None),
        (Some(dir), Some(seed)) => {
            let every = std::env::var("TENKAI_AUDIT_EXPORT_INTERVAL_SECS")
                .ok()
                .map(|value| value.parse::<u64>())
                .transpose()
                .context("TENKAI_AUDIT_EXPORT_INTERVAL_SECS must be a whole number")?
                .unwrap_or(86_400);
            anyhow::ensure!(
                every > 0,
                "TENKAI_AUDIT_EXPORT_INTERVAL_SECS must be positive"
            );
            Ok(Some((dir.into(), seed.into(), Duration::from_secs(every))))
        }
        _ => anyhow::bail!(
            "TENKAI_AUDIT_EXPORT_DIR and TENKAI_AUDIT_SIGNING_KEY must be set together"
        ),
    }
}

/// Clock-drift guard from `TENKAI_TIME_SOURCE` (an SNTP `host:port`; unset:
/// off), `TENKAI_CLOCK_WARN_MS` (default 1000), `TENKAI_CLOCK_REFUSE_MS`
/// (default 30000, below the 60 s token skew) and `TENKAI_CLOCK_CHECK_SECS`
/// (default 60). Installs the guard and returns how often to measure.
fn clock_settings() -> Result<Option<Duration>> {
    let Some(server) = std::env::var("TENKAI_TIME_SOURCE")
        .ok()
        .filter(|server| !server.trim().is_empty())
    else {
        return Ok(None);
    };
    let number = |name: &str, default: i64| -> Result<i64> {
        std::env::var(name)
            .ok()
            .map(|value| value.parse::<i64>())
            .transpose()
            .with_context(|| format!("{name} must be a whole number"))
            .map(|value| value.unwrap_or(default))
    };
    let guard = tenkai::clock_guard::ClockGuard::new(tenkai::clock_guard::ClockPolicy {
        server,
        warn_ms: number("TENKAI_CLOCK_WARN_MS", 1_000)?,
        refuse_ms: number("TENKAI_CLOCK_REFUSE_MS", 30_000)?,
    })?;
    let every = number("TENKAI_CLOCK_CHECK_SECS", 60)?;
    anyhow::ensure!(every > 0, "TENKAI_CLOCK_CHECK_SECS must be positive");
    tenkai::clock_guard::install(std::sync::Arc::new(guard));
    Ok(Some(Duration::from_secs(every as u64)))
}

/// Server-side bundle import from `TENKAI_IMPORT_STAGING_DIR` and
/// `TENKAI_BUNDLE_TRUST_ROOTS`, which must be set together. Both are host
/// configuration; an import request names a staged file only.
fn import_settings() -> Result<Option<tenkai::offline_import::ImportSettings>> {
    match (
        std::env::var_os("TENKAI_IMPORT_STAGING_DIR"),
        std::env::var_os("TENKAI_BUNDLE_TRUST_ROOTS"),
    ) {
        (None, None) => Ok(None),
        (Some(staging), Some(trust_roots)) => {
            let staging = std::path::PathBuf::from(staging);
            anyhow::ensure!(
                staging.is_dir(),
                "TENKAI_IMPORT_STAGING_DIR {} is not a directory",
                staging.display()
            );
            Ok(Some(tenkai::offline_import::ImportSettings {
                staging,
                trust_roots: trust_roots.into(),
            }))
        }
        _ => anyhow::bail!(
            "TENKAI_IMPORT_STAGING_DIR and TENKAI_BUNDLE_TRUST_ROOTS must be set together"
        ),
    }
}

/// Server-mode backups from `TENKAI_BACKUP_DIR` (unset: off) and, when set,
/// `TENKAI_BACKUP_INTERVAL_SECS` (default 86400; 0 takes backups only on
/// demand), `TENKAI_BACKUP_RETAIN` (default 7) and
/// `TENKAI_BACKUP_MAX_AGE_SECS` (default twice the interval, else 172800).
/// Tenant-mode hubs keep their state in PostgreSQL and refuse the setting.
fn backup_settings(
    tenant_mode: bool,
    store: &Arc<SqliteStore>,
) -> Result<Option<(Arc<tenkai::backup::Backups>, Option<Duration>)>> {
    let Some(dir) = std::env::var_os("TENKAI_BACKUP_DIR") else {
        return Ok(None);
    };
    anyhow::ensure!(
        !tenant_mode,
        "TENKAI_BACKUP_DIR backs up the SQLite store; tenant-mode hubs back up PostgreSQL with its own tools"
    );
    let number = |name: &str, default: u64| -> Result<u64> {
        std::env::var(name)
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .with_context(|| format!("{name} must be a whole number"))
            .map(|value| value.unwrap_or(default))
    };
    let interval = number("TENKAI_BACKUP_INTERVAL_SECS", 86_400)?;
    let max_age = number(
        "TENKAI_BACKUP_MAX_AGE_SECS",
        if interval == 0 { 172_800 } else { interval * 2 },
    )?;
    let retain = number("TENKAI_BACKUP_RETAIN", 7)?;
    let backups = tenkai::backup::Backups::new(
        store.clone(),
        tenkai::backup::BackupPolicy {
            dir: dir.into(),
            retain: usize::try_from(retain)?,
            max_age_ms: i64::try_from(max_age.saturating_mul(1000))?,
        },
    )?;
    let every = (interval > 0).then(|| Duration::from_secs(interval));
    Ok(Some((Arc::new(backups), every)))
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
    fn oidc_and_jwt_trust_compose_one_issuer_router() {
        let (dir, config) = oidc_files();
        let jwt = trust_file();
        let composition = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: Some(&jwt),
                oidc: Some(&config),
            },
            true,
            false,
        )
        .unwrap();
        std::fs::remove_file(jwt).unwrap();
        std::fs::remove_dir_all(dir).unwrap();

        let extension = composition.extension.unwrap();
        assert_eq!(extension.extension_id(), ISSUER_AUTH_EXTENSION_ID);
        assert_eq!(
            composition.auth_host.required_extension_id.as_deref(),
            Some(ISSUER_AUTH_EXTENSION_ID)
        );
        assert!(composition.auth_host.expected_audience.is_none());
        assert_eq!(
            composition
                .oidc_client
                .as_ref()
                .map(|client| client.client_id.as_str()),
            Some("tenkai-console")
        );
    }

    #[test]
    fn oidc_and_jwt_trust_reject_duplicate_issuers_and_missing_keys() {
        let (dir, config) = oidc_files();
        let jwt = std::env::temp_dir().join(format!(
            "tenkai-jwt-dup-{}-{}.toml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let public_key = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[7_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        std::fs::write(
            &jwt,
            format!(
                "issuer = \"https://idp.example.test/realms/ops\"\naudience = \"tenkai-control-plane\"\nclock_skew_secs = 60\n\n[[keys]]\nkey_id = \"active\"\npublic_key = \"{public_key}\"\n"
            ),
        )
        .unwrap();
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
        assert!(both.contains("distinct issuers"), "{both}");
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

    #[test]
    fn tenant_mode_oidc_requires_tenant_claim_mapping() {
        let (dir, config) = oidc_files();
        let error = compose_enterprise_auth(
            EnterpriseAuthSources {
                jwt_trust: None,
                oidc: Some(&config),
            },
            true,
            true,
        )
        .err()
        .unwrap()
        .to_string();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(error.contains("tenant_claim"), "{error}");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "current_thread")]
    async fn postgres_adapter_initialization_runs_outside_the_async_runtime() {
        let result = run_blocking_startup("postgres startup regression", || {
            let config =
                tenkai_postgres::PostgresTenantConfig::new("postgres://127.0.0.1:1/tenkai")?;
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

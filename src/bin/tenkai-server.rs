//! Long-running network host for the Tenkai application core.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tenkai::reconciler::{Config as ReconcilerConfig, Reconciler};
use tenkai::runtime_capabilities::{
    RuntimeRequirements, community_auth_capabilities, community_sqlite_profile,
    enterprise_auth_capabilities, validate_runtime_capabilities,
};
use tenkai::server::{ServerConfig, router};
use tenkai::storage::{OperationalStore, SqliteStore};

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
    /// Advertise enterprise authentication capability (host-wired extension present).
    #[arg(long, default_value_t = false)]
    with_enterprise_auth: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderMode {
    Embedded,
    Remote,
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
    let auth_capabilities = if cli.with_enterprise_auth {
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
    let reconciler = Arc::new(
        Reconciler::new(
            ctx,
            ReconcilerConfig {
                max_concurrency: cli.max_concurrency,
                ..ReconcilerConfig::default()
            },
        )?
        .with_runtime_environments(runtime_environments),
    );
    let app = router(
        ServerConfig {
            management_token,
            runtime_assignments,
            requirements,
            capabilities: capabilities.clone(),
            auth_host: tenkai::auth_context::AuthHostConfig::community(),
            enterprise_auth: None,
            federation: tenkai::federated_identity::FederationConfig::community(),
            identity_directory: std::sync::Arc::new(
                tenkai::federated_identity::IdentityDirectory::new(),
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

use super::*;
use super::{Inner, migrate_tenant_schema, pg};
use postgres::Client;
use postgres::config::{Config, Host, SslMode};
use std::net::IpAddr;
use std::sync::Arc;
use tokio_postgres_rustls::MakeRustlsConnect;

impl Inner {
    pub fn connect(url: &str) -> Result<Self> {
        let config = hub_transport(url)?;
        let tls = verified_tls()?;
        Ok(Self {
            worker: Worker::start_recovering(
                move || connect_client(&config, tls.clone()),
                Client::is_closed,
            )?,
            fence: std::sync::OnceLock::new(),
        })
    }
}

/// Apply the hub transport policy (#445) to a `postgres://` URL.
///
/// Tenant data and store credentials leave the host only over TLS: when any
/// host is not loopback or a unix socket, `sslmode=prefer` is raised to
/// `require` and `sslmode=disable` is refused. Loopback-only URLs keep their
/// configured mode. Certificates are always verified (see [`verified_tls`]).
pub(super) fn hub_transport(url: &str) -> Result<Config> {
    let mut config: Config = url
        .parse()
        .map_err(|err| StoreError::AdapterUnavailable(format!("invalid postgres URL: {err}")))?;
    if is_loopback_only(&config) {
        return Ok(config);
    }
    if config.get_ssl_mode() == SslMode::Disable {
        return Err(StoreError::AdapterUnavailable(
            "postgres URL with a non-loopback host requires TLS; \
             sslmode=disable is allowed only for loopback hosts or unix sockets"
                .into(),
        ));
    }
    config.ssl_mode(SslMode::Require);
    Ok(config)
}

/// True when every configured endpoint stays on this machine. An empty host
/// list means libpq's local default (unix socket or localhost).
fn is_loopback_only(config: &Config) -> bool {
    let hosts_local = config.get_hosts().iter().all(|host| match host {
        Host::Tcp(name) => {
            name.eq_ignore_ascii_case("localhost")
                || name
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        #[cfg(unix)]
        Host::Unix(_) => true,
    });
    hosts_local && config.get_hostaddrs().iter().all(IpAddr::is_loopback)
}

/// Verifying rustls connector with an explicit ring provider and PostgreSQL
/// ALPN. It trusts `TENKAI_CA_BUNDLE` plus, unless
/// `TENKAI_TLS_SYSTEM_ROOTS=false`, the platform store (which honors
/// `SSL_CERT_FILE`/`SSL_CERT_DIR`) and the Mozilla roots.
fn verified_tls() -> Result<MakeRustlsConnect> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;
    let trust = tenkai::outbound_tls::OutboundTrust::from_env()
        .map_err(|err| StoreError::AdapterUnavailable(format!("postgres TLS setup: {err:#}")))?;
    let mut roots = rustls::RootCertStore::empty();
    if trust.system_roots {
        roots.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    }
    if let Some(pem) = &trust.bundle_pem {
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let certificate = certificate.map_err(|err| {
                StoreError::AdapterUnavailable(format!("postgres TLS setup: {err}"))
            })?;
            roots.add(certificate).map_err(|err| {
                StoreError::AdapterUnavailable(format!("postgres TLS setup: {err}"))
            })?;
        }
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| StoreError::AdapterUnavailable(format!("postgres TLS setup: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    // Required by PostgreSQL 17+ for `sslnegotiation=direct`; ignored otherwise.
    config.alpn_protocols = vec![b"postgresql".to_vec()];
    Ok(MakeRustlsConnect::new(config))
}

fn connect_client(config: &Config, tls: MakeRustlsConnect) -> Result<Client> {
    let mut client = config.connect(tls).map_err(pg)?;
    // PostgreSQL's IF NOT EXISTS DDL can still race in the system
    // catalogs when several replicas initialize a fresh database at
    // once. Serialize only the global adapter migration; the
    // session-scoped lock is released automatically if setup fails.
    client
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('tenkai_global_schema_migration', 0))",
            &[],
        )
        .map_err(pg)?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS tenkai_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                 );",
        )
        .map_err(pg)?;
    // Global adapter schema version (refuse newer).
    let found: Option<String> = client
        .query_opt(
            "SELECT value FROM tenkai_meta WHERE key = 'schema_version'",
            &[],
        )
        .map_err(pg)?
        .map(|row| row.get(0));
    match found {
        Some(value) => {
            let version: u32 = value.parse().map_err(|_| StoreError::InvalidData {
                kind: "schema",
                detail: format!("invalid schema_version {value}"),
            })?;
            if version > SCHEMA_VERSION {
                return Err(StoreError::UnsupportedSchema {
                    found: version,
                    supported: SCHEMA_VERSION,
                });
            }
            if version < SCHEMA_VERSION {
                client
                    .execute(
                        "UPDATE tenkai_meta SET value = $1 WHERE key = 'schema_version'",
                        &[&SCHEMA_VERSION.to_string()],
                    )
                    .map_err(pg)?;
            }
        }
        None => {
            client
                .execute(
                    "INSERT INTO tenkai_meta(key,value) VALUES('schema_version',$1)",
                    &[&SCHEMA_VERSION.to_string()],
                )
                .map_err(pg)?;
        }
    }
    // Hub-wide durable tick fence claims (#135). Not per-tenant: reconcile
    // environments are coordinated across the control plane.
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS tenkai_reconcile_tick_claims (
                    environment TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    generation BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL
                 );",
        )
        .map_err(pg)?;
    // The hub writer lease (#748): one row, a generation that only grows.
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS tenkai_hub_writer_lease (
                    id SMALLINT PRIMARY KEY CHECK (id = 1),
                    holder TEXT NOT NULL,
                    generation BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL
                 );",
        )
        .map_err(pg)?;
    // Stored OIDC grant rules (#836): hub-wide, one row per claim value, and
    // a generation every replica polls. Additive; older binaries ignore it.
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS tenkai_grant_rules (
                    value TEXT PRIMARY KEY,
                    rule_json TEXT NOT NULL
                 );
             CREATE TABLE IF NOT EXISTS tenkai_grant_rule_generation (
                    id SMALLINT PRIMARY KEY CHECK (id = 1),
                    generation BIGINT NOT NULL
                 );",
        )
        .map_err(pg)?;
    client
        .query_one(
            "SELECT pg_advisory_unlock(hashtextextended('tenkai_global_schema_migration', 0))",
            &[],
        )
        .map_err(pg)?;
    Ok(client)
}

impl Inner {
    pub fn ensure_tenant_schema(&self, schema: &str) -> Result<()> {
        let schema = schema.to_owned();
        self.worker.run(
            move |client| {
                let mut tx = client.transaction().map_err(pg)?;
                tx.query_one(
                    "SELECT pg_advisory_xact_lock(
                    hashtextextended('tenkai_tenant_schema:' || $1, 0)
                 )",
                    &[&schema],
                )
                .map_err(pg)?;
                tx.batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
                    .map_err(pg)?;
                tx.batch_execute(&format!("SET LOCAL search_path TO {schema}, public"))
                    .map_err(pg)?;
                migrate_tenant_schema(&mut tx)?;
                tx.commit().map_err(pg)?;
                Ok(())
            },
            StoreError::Postgres("postgres worker thread panicked".into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(url: &str) -> SslMode {
        hub_transport(url).expect("accepted").get_ssl_mode()
    }

    #[test]
    fn remote_hosts_require_tls() {
        assert_eq!(mode("postgres://u:p@db.internal/tenkai"), SslMode::Require);
        assert_eq!(
            mode("postgres://u:p@10.0.0.5/tenkai?sslmode=prefer"),
            SslMode::Require
        );
        assert_eq!(
            mode("postgres://u:p@localhost,db.internal/tenkai"),
            SslMode::Require,
            "one remote host in a multi-host list makes the URL remote"
        );
        assert_eq!(
            mode("postgres://u:p@localhost/tenkai?hostaddr=10.0.0.5"),
            SslMode::Require,
            "a remote hostaddr overrides a loopback host name"
        );
    }

    #[test]
    fn remote_plaintext_fails_closed() {
        let err = hub_transport("postgres://u:p@db.internal/tenkai?sslmode=disable")
            .expect_err("plaintext to a remote host must be refused")
            .to_string();
        assert!(err.contains("requires TLS"), "{err}");
    }

    #[test]
    fn loopback_keeps_configured_mode() {
        for url in [
            "postgres://u:p@127.0.0.1:5432/tenkai?sslmode=disable",
            "postgres://u:p@localhost/tenkai?sslmode=disable",
            "postgres://u:p@[::1]/tenkai?sslmode=disable",
            "postgres://u:p@%2Fvar%2Frun%2Fpostgresql/tenkai?sslmode=disable",
        ] {
            assert_eq!(mode(url), SslMode::Disable, "{url}");
        }
        assert_eq!(mode("postgres://u:p@127.0.0.1/tenkai"), SslMode::Prefer);
    }
}

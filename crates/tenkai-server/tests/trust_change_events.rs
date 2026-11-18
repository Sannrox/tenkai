//! Certificate threshold crossings on `/v1/events` (#784), behind
//! `TENKAI_TRUST_CHANGE_EVENTS`.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

mod support;

use support::{DEADLINE, Spawned};

use tenkai::storage::OperationalStore as _;

/// A CA certificate valid for `days` more days.
fn ca_bundle(path: &Path, days: i64) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(days);
    let key = rcgen::KeyPair::generate().unwrap();
    std::fs::write(path, params.self_signed(&key).unwrap().pem()).unwrap();
}

/// A running server; killed when stopped or dropped.
struct Server(Spawned);

impl Server {
    /// Starts the server and returns once it is ready.
    fn start(database: &Path, bundle: Option<&Path>, events: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tenkai-server"));
        command
            .args(["--listen", "127.0.0.1:0"])
            .arg("--database")
            .arg(database)
            .env(
                "TENKAI_MANAGEMENT_TOKEN",
                "trust-events-test-management-token-0123456789",
            )
            .env("TENKAI_TRUST_CHANGE_EVENTS", events.to_string())
            .env_remove("TENKAI_HOST_WEBHOOKS")
            .env_remove("TENKAI_SMTP_SINKS")
            .env_remove("TENKAI_IMPORT_STAGING_DIR")
            .env_remove("TENKAI_CA_BUNDLE");
        if let Some(bundle) = bundle {
            command.env("TENKAI_CA_BUNDLE", bundle);
        }
        let server = Spawned::spawn(&mut command);
        server.ready();
        Self(server)
    }

    /// The first `tenkai.trust_event` line the server logs, or `None` past
    /// the deadline.
    fn trust_log(&self) -> Option<String> {
        self.0
            .stderr_line(DEADLINE, |line| line.starts_with("tenkai.trust_event"))
    }

    /// Stops the server and returns the stderr it wrote and was not read.
    fn stop(self) -> String {
        self.0.stop()
    }
}

fn trust_events(database: &Path) -> Vec<String> {
    tenkai::storage::SqliteStore::open(database)
        .unwrap()
        .list_change_events_after(0, 100)
        .unwrap()
        .into_iter()
        .map(|event| event.resource)
        .filter(|resource| resource.starts_with("trust/"))
        .collect()
}

/// Off: nothing is written. On: a certificate inside the warning threshold
/// appends one event, and a restart with the status unchanged appends none.
/// Removing the certificate records one recovery, and no more after restart.
#[test]
fn a_crossing_appends_one_event_only_when_enabled_and_not_again_after_restart() {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-trust-events-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let database = dir.join("tenkai.db");
    let bundle = dir.join("ca.pem");
    ca_bundle(&bundle, 20);
    // The host watch's first tick runs right after ready; give it time.
    let settle = Duration::from_secs(3);

    let server = Server::start(&database, Some(&bundle), false);
    std::thread::sleep(settle);
    let logged = server.stop();
    assert!(!logged.contains("tenkai.trust_event"), "{logged}");
    assert_eq!(trust_events(&database), Vec::<String>::new());

    let server = Server::start(&database, Some(&bundle), true);
    let appended = server.trust_log();
    server.stop();
    let appended = appended.expect("the crossing is announced");
    assert!(
        appended.contains("outcome=appended resource=trust/warning"),
        "{appended}"
    );
    assert_eq!(trust_events(&database), ["trust/warning"]);

    let server = Server::start(&database, Some(&bundle), true);
    std::thread::sleep(settle);
    let logged = server.stop();
    assert!(!logged.contains("tenkai.trust_event"), "{logged}");
    assert_eq!(trust_events(&database), ["trust/warning"]);

    // The certificate is no longer configured: recovery is recorded once.
    let server = Server::start(&database, None, true);
    let recovered = server.trust_log();
    server.stop();
    let recovered = recovered.expect("the recovery is recorded");
    assert!(
        recovered.contains("outcome=appended resource=trust/ok"),
        "{recovered}"
    );
    let server = Server::start(&database, None, true);
    std::thread::sleep(settle);
    let logged = server.stop();
    assert!(!logged.contains("tenkai.trust_event"), "{logged}");
    assert_eq!(trust_events(&database), ["trust/warning", "trust/ok"]);
    let _ = std::fs::remove_dir_all(&dir);
}

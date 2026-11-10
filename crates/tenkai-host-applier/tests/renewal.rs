//! Host workload certificate renewal (ADR 0046 §3): the applier installs a
//! renewed certificate only for exactly the grant it recorded, only while
//! the product is installed and its record still holds the certificate the
//! renewal replaces.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tenkai::host_apply::HostRelease;
use tenkai::host_apply::identity::{HostIdentityRecord, HostIdentityRenewal, RENEWAL_FILE};
use tenkai::host_apply::sealed::{HostSealedValues, SEALED_FILE};
use tenkai::host_apply::state::{AppliedState, AppliedStateRecord, record_path};
use tenkai::identity_issuer::IssuerKey;
use tenkai::workload_identity::{
    CertificateRole, IdentityGrant, IdentitySection, IssuedIdentity, Reload,
};
use tenkai_host_applier::{Applied, ApplierPaths, renew, secrets, store};

const ENVIRONMENT: &str = "edge";

/// An applier host with a memory-backed spool, and an identity issuer.
struct Host {
    roots: Vec<PathBuf>,
    paths: ApplierPaths,
    spool: PathBuf,
    issuer: IssuerKey,
    sealing: PathBuf,
}

impl Host {
    fn new(shm: &Path) -> Self {
        let name = format!(
            "tenkai-host-renewal-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let root = std::env::temp_dir().join(&name);
        let spool_root = shm.join(&name);
        let paths = ApplierPaths {
            config_dir: root.join("etc"),
            state_dir: root.join("state"),
            run_dir: root.join("run"),
        };
        for dir in [&paths.config_dir, &paths.state_dir, &paths.run_dir] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let spool = spool_root.join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        std::fs::write(
            paths.config_dir.join("host-applier.toml"),
            format!(
                "version = 1\nspool_dir = {:?}\n",
                spool.display().to_string()
            ),
        )
        .unwrap();
        let sealing = root.join("sealing");
        std::fs::create_dir_all(&sealing).unwrap();
        let public = tenkai::sealing_key::SealingKey::open_or_generate(&sealing)
            .unwrap()
            .public()
            .clone();
        let issuer =
            tenkai::identity_issuer::generate(ENVIRONMENT, 1, &public, tenkai::now_millis() / 1000)
                .unwrap();
        Self {
            roots: vec![root, spool_root],
            paths,
            spool,
            issuer,
            sealing,
        }
    }

    fn grant(&self, reload: Reload, dns_names: &[&str]) -> IdentityGrant {
        let section = IdentitySection {
            certificate: CertificateRole::Server,
            reload,
            dns_names: dns_names.iter().map(|name| (*name).into()).collect(),
        };
        tenkai::workload_identity::grant(&section, ENVIRONMENT, "api", &self.issuer).unwrap()
    }

    fn issue(&self, grant: &IdentityGrant) -> IssuedIdentity {
        let opener = tenkai::sealed_secret::SealedOpener::load(&self.sealing).unwrap();
        let key = self.issuer.open(ENVIRONMENT, &opener).unwrap();
        tenkai::workload_identity::issue(grant, &self.issuer, key, tenkai::now_millis() / 1000)
            .unwrap()
    }

    /// What an approved install leaves: `api` applied, its certificate
    /// written and recorded.
    fn installed(&self, issued: &IssuedIdentity) -> HostIdentityRecord {
        let mut product = AppliedStateRecord::empty(ENVIRONMENT, "api");
        product.state = AppliedState::Applied {
            release: HostRelease {
                version: "1.0.0".into(),
                manifest_digest: "a".repeat(64),
            },
        };
        let path = record_path(&self.paths.state_dir, ENVIRONMENT, "api");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(&product).unwrap()).unwrap();
        secrets::write_identity(&self.paths, ENVIRONMENT, "api", issued).unwrap();
        let record = HostIdentityRecord::new(ENVIRONMENT, "api", "api", issued);
        store::write_identity_record(&self.paths, &record).unwrap();
        record
    }

    /// Spool what the runtime spools to replace `record` with `issued`.
    fn spool_renewal(&self, record: &HostIdentityRecord, issued: &IssuedIdentity) -> String {
        let renewal = HostIdentityRenewal::new(record);
        let instance = renewal.instance_key();
        let dir = self.spool.join(&instance);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(RENEWAL_FILE),
            serde_json::to_vec(&renewal).unwrap(),
        )
        .unwrap();
        let values = HostSealedValues::new(Vec::new(), Some(issued.into()));
        std::fs::write(dir.join(SEALED_FILE), serde_json::to_vec(&values).unwrap()).unwrap();
        instance
    }

    fn installed_certificate(&self) -> String {
        std::fs::read_to_string(
            self.paths
                .state_dir
                .join(secrets::IDENTITY)
                .join(ENVIRONMENT)
                .join("api")
                .join(secrets::CURRENT_LINK)
                .join("cert.pem"),
        )
        .unwrap()
    }

    fn refused(&self, instance: &str) -> String {
        match renew::renew(&self.paths, instance).unwrap() {
            Applied::Refused(reason) => reason,
            other => panic!("renewal must be refused: {other:?}"),
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        for root in &self.roots {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn memory_backed() -> Option<PathBuf> {
    let shm = PathBuf::from("/dev/shm");
    tenkai::host_apply::sealed::require_memory_backed(&shm)
        .is_ok()
        .then_some(shm)
}

#[test]
fn a_renewal_replaces_exactly_the_recorded_certificate() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let grant = host.grant(Reload::Runtime, &["api.edge.internal"]);
    let first = host.issue(&grant);
    let record = host.installed(&first);

    let renewed = host.issue(&grant);
    let instance = host.spool_renewal(&record, &renewed);
    assert!(renew::spooled(&host.paths, &instance));
    assert_eq!(
        renew::renew(&host.paths, &instance).unwrap(),
        Applied::Renewed
    );
    assert_eq!(host.installed_certificate(), renewed.certificate);
    let recorded = store::identity_record(&host.paths, ENVIRONMENT, "api")
        .unwrap()
        .unwrap();
    assert_eq!(recorded.certificate, renewed.certificate);
    assert_eq!(recorded.grant, grant);

    // The same renewal again: the certificate it replaces is gone.
    let reason = host.refused(&instance);
    assert!(reason.contains("changed since"), "{reason}");
    assert_eq!(host.installed_certificate(), renewed.certificate);
}

#[test]
fn a_renewal_never_widens_or_revives_a_certificate() {
    let Some(shm) = memory_backed() else {
        eprintln!("skipped: no memory-backed /dev/shm on this host");
        return;
    };
    let host = Host::new(&shm);
    let grant = host.grant(Reload::Runtime, &["api.edge.internal"]);
    let first = host.issue(&grant);
    let record = host.installed(&first);

    // A certificate for a name the approved step did not grant.
    let wider = host.issue(&host.grant(Reload::Runtime, &["api.edge.internal", "bank.example"]));
    let instance = host.spool_renewal(&record, &wider);
    host.refused(&instance);
    assert_eq!(host.installed_certificate(), first.certificate);

    // A restart-reload workload renews with a restart, not in place.
    let restart = host.grant(Reload::Restart, &["api.edge.internal"]);
    let record = host.installed(&host.issue(&restart));
    let instance = host.spool_renewal(&record, &host.issue(&restart));
    let reason = host.refused(&instance);
    assert!(reason.contains("restart"), "{reason}");

    // An uninstalled product's certificate stays gone.
    let record = host.installed(&host.issue(&grant));
    let product = AppliedStateRecord::empty(ENVIRONMENT, "api");
    std::fs::write(
        record_path(&host.paths.state_dir, ENVIRONMENT, "api"),
        serde_json::to_vec(&product).unwrap(),
    )
    .unwrap();
    let instance = host.spool_renewal(&record, &host.issue(&grant));
    let reason = host.refused(&instance);
    assert!(reason.contains("not installed"), "{reason}");
    // Each refusal is recorded for the runtime to report.
    assert!(store::refusal(&host.paths, &instance).unwrap().is_some());
}

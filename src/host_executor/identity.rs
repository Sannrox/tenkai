//! Renew host workload certificates through the applier (ADR 0046 §3); see
//! [`crate::host_apply::identity`] for what the applier checks.

use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use anyhow::{Context as _, Result, bail};

use super::{HostExecutor, read_bounded, read_record};
use crate::host_apply::identity::{
    HostIdentityRecord, HostIdentityRenewal, RENEWAL_FILE, identity_record_path,
};
use crate::host_apply::sealed::HostSealedValues;
use crate::host_apply::state::AppliedState;
use crate::workload_identity::{InstalledIdentity, IssuedIdentity};

/// A certificate the applier installed for a product that is still
/// installed, and the grant it proves.
#[derive(Debug, Clone)]
pub struct InstalledHostIdentity {
    pub record: HostIdentityRecord,
    pub installed: InstalledIdentity,
}

impl HostExecutor {
    /// The workload certificates the applier recorded in `environment`,
    /// each named by its instance with what it proves, or why it proves
    /// nothing. A product that is no longer installed is left out: its
    /// certificate is not renewed.
    pub fn installed_identities(
        &self,
        environment: &str,
    ) -> Result<Vec<(String, Result<InstalledHostIdentity>)>> {
        let dir = self.state_dir.join("identities");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).with_context(|| format!("reading {}", dir.display())),
        };
        let mut found = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let Some(bytes) = read_record(&path)? else {
                continue;
            };
            let record: HostIdentityRecord = match serde_json::from_slice(&bytes) {
                Ok(record) => record,
                Err(error) => {
                    found.push((
                        path.display().to_string(),
                        Err(anyhow::Error::from(error).context("parsing the identity record")),
                    ));
                    continue;
                }
            };
            // Only where its environment and instance put it: a record
            // copied under another name is not this environment's.
            if record.environment != environment
                || path != identity_record_path(&self.state_dir, environment, &record.instance)
            {
                continue;
            }
            if self.applied_state(environment, &record.product)?.state == AppliedState::Empty {
                continue;
            }
            let installed = InstalledIdentity::read(
                environment,
                &record.instance,
                &record.certificate,
                &record.ca,
                &serde_json::to_vec(&record.grant)?,
            );
            found.push((
                record.instance.clone(),
                installed.map(|installed| InstalledHostIdentity { record, installed }),
            ));
        }
        Ok(found)
    }

    /// Have the applier replace `installed`'s certificate with `issued`,
    /// spooled with the approved rotation plans that prove its bundle's
    /// further issuers or its move to the next issuer, and confirm from its record that it did. The applier refuses when
    /// the certificate changed since it was read, so a step that installed
    /// or removed one meanwhile wins.
    pub async fn renew_identity(
        &self,
        installed: &InstalledHostIdentity,
        issued: &IssuedIdentity,
        issuer_proofs: Vec<crate::identity_issuer::IssuerProof>,
    ) -> Result<()> {
        let renewal = HostIdentityRenewal::new(&installed.record);
        let instance = renewal.instance_key();
        let since_ms = crate::now_millis();
        let spooled = self.spool_renewal(&instance, &renewal).and_then(|()| {
            self.write_sealed(
                &instance,
                &HostSealedValues::new(Vec::new(), Some(issued.into()), issuer_proofs),
            )
        });
        if let Err(error) = spooled {
            self.discard_spool(&instance);
            return Err(error.context("spooling the renewal"));
        }
        let started = self.units.start(&instance).await;
        self.discard_spool(&instance);
        let path = identity_record_path(&self.state_dir, &renewal.environment, &renewal.instance);
        let installed_now = read_bounded(&path, super::MAX_RECORD_BYTES)?
            .map(|bytes| serde_json::from_slice::<HostIdentityRecord>(&bytes))
            .transpose()?;
        if installed_now.is_some_and(|record| record.certificate == issued.certificate) {
            return Ok(());
        }
        if let Some(reason) = self.refusal_since(&instance, since_ms)? {
            bail!("the host applier refused the renewal: {reason}");
        }
        match started {
            Err(error) => Err(error.context("the host applier did not install the renewal")),
            Ok(()) => bail!("the host applier did not install the renewal"),
        }
    }

    /// Spool `renewal` as `instance`, this attempt's own directory: the
    /// document goes in a staging directory renamed into place.
    fn spool_renewal(&self, instance: &str, renewal: &HostIdentityRenewal) -> Result<()> {
        let staging = self
            .spool_dir
            .join(format!(".staging-{}", uuid::Uuid::new_v4().simple()));
        let written = (|| {
            std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(staging.join(RENEWAL_FILE))?;
            serde_json::to_writer(&mut file, renewal)?;
            file.sync_all()?;
            anyhow::Ok(())
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
        std::fs::rename(&staging, self.spool_dir.join(instance))
            .with_context(|| format!("spooling renewal {instance}"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use super::*;
    use crate::host_apply::sealed::SEALED_FILE;
    use crate::host_apply::state::{
        AppliedStateRecord, HostApplyRefused, REFUSED_FILE, REFUSED_SCHEMA, instance_dir,
        record_path,
    };
    use crate::host_executor::{HostUnits, UnitFuture};
    use crate::workload_identity::{CertificateRole, IdentitySection, Reload};

    /// Stands in for the applier unit: installs a spooled renewal by
    /// writing its record, or refuses it.
    struct Applier {
        spool: PathBuf,
        state: PathBuf,
        refuse: bool,
    }

    impl HostUnits for Applier {
        fn start<'a>(&'a self, instance: &'a str) -> UnitFuture<'a> {
            let spooled = self.spool.join(instance);
            let renewal: HostIdentityRenewal =
                serde_json::from_slice(&std::fs::read(spooled.join(RENEWAL_FILE)).unwrap())
                    .unwrap();
            let sealed =
                HostSealedValues::parse(&std::fs::read(spooled.join(SEALED_FILE)).unwrap())
                    .unwrap();
            if self.refuse {
                write(
                    &instance_dir(&self.state, instance).join(REFUSED_FILE),
                    &HostApplyRefused {
                        schema: REFUSED_SCHEMA.into(),
                        instance: instance.into(),
                        reason: "the certificate changed".into(),
                        refused_at: crate::now_millis(),
                    },
                );
            } else {
                let path =
                    identity_record_path(&self.state, &renewal.environment, &renewal.instance);
                let mut record: HostIdentityRecord =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                record.certificate = sealed.identity.unwrap().certificate;
                write(&path, &record);
            }
            Box::pin(async { Ok(()) })
        }

        fn stop(&self, _instance: &str) -> Result<()> {
            Ok(())
        }

        fn running(&self) -> UnitFuture<'_, Vec<String>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn write(path: &Path, value: &impl serde::Serialize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }

    /// A runtime-side host executor over a memory-backed spool, an issuer,
    /// and `api` installed in `edge` with a certificate recorded.
    struct Case {
        root: PathBuf,
        state: PathBuf,
        spool: PathBuf,
        issuer: crate::identity_issuer::IssuerKey,
        grant: crate::workload_identity::IdentityGrant,
    }

    impl Case {
        fn new(shm: &Path) -> Self {
            let root = shm.join(format!(
                "tenkai-host-renew-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
            let (state, spool) = (root.join("state"), root.join("spool"));
            std::fs::create_dir_all(&spool).unwrap();
            let public = crate::sealing_key::SealingKey::open_or_generate(&root)
                .unwrap()
                .public()
                .clone();
            let issuer =
                crate::identity_issuer::generate("edge", 1, &public, crate::now_millis() / 1000)
                    .unwrap();
            let section = IdentitySection {
                certificate: CertificateRole::Server,
                reload: Reload::Runtime,
                dns_names: vec!["api.edge.internal".into()],
            };
            let grant = crate::workload_identity::grant(&section, "edge", "api", &issuer).unwrap();
            let case = Self {
                root,
                state,
                spool,
                issuer,
                grant,
            };
            let mut product = AppliedStateRecord::empty("edge", "api");
            product.state = AppliedState::Applied {
                release: crate::host_apply::HostRelease {
                    version: "1.0.0".into(),
                    manifest_digest: "a".repeat(64),
                },
            };
            write(&record_path(&case.state, "edge", "api"), &product);
            let issued = case.issue();
            write(
                &identity_record_path(&case.state, "edge", "api"),
                &HostIdentityRecord::new("edge", "api", "api", &issued),
            );
            case
        }

        fn issue(&self) -> IssuedIdentity {
            let opener = crate::sealed_secret::SealedOpener::load(&self.root).unwrap();
            let key = self.issuer.open("edge", &opener).unwrap();
            crate::workload_identity::issue(
                &self.grant,
                &self.issuer,
                key,
                crate::now_millis() / 1000,
            )
            .unwrap()
        }

        fn executor(&self, refuse: bool) -> HostExecutor {
            HostExecutor::new(
                self.spool.clone(),
                self.state.clone(),
                Arc::new(Applier {
                    spool: self.spool.clone(),
                    state: self.state.clone(),
                    refuse,
                }),
            )
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The runtime reads what the applier recorded, spools the renewal,
    /// confirms the applier installed exactly its certificate, and reports
    /// a refusal by its reason. Nothing stays in the spool.
    #[tokio::test]
    async fn a_host_certificate_renews_through_the_applier() {
        let shm = Path::new("/dev/shm");
        if crate::host_apply::sealed::require_memory_backed(shm).is_err() {
            eprintln!("skipped: no memory-backed /dev/shm on this host");
            return;
        }
        let case = Case::new(shm);
        let executor = case.executor(false);
        let mut found = executor.installed_identities("edge").unwrap();
        assert!(executor.installed_identities("prod").unwrap().is_empty());
        let (instance, installed) = found.pop().unwrap();
        assert_eq!(instance, "api");
        let installed = installed.unwrap();
        assert_eq!(installed.installed.grant, case.grant);

        let issued = case.issue();
        executor
            .renew_identity(&installed, &issued, Vec::new())
            .await
            .unwrap();
        let recorded = executor
            .installed_identities("edge")
            .unwrap()
            .pop()
            .unwrap()
            .1
            .unwrap();
        assert_eq!(recorded.record.certificate, issued.certificate);
        assert_eq!(std::fs::read_dir(&case.spool).unwrap().count(), 0);

        let refused = case
            .executor(true)
            .renew_identity(&recorded, &case.issue(), Vec::new())
            .await
            .unwrap_err();
        assert!(
            format!("{refused:#}").contains("the certificate changed"),
            "{refused:#}"
        );
        assert_eq!(std::fs::read_dir(&case.spool).unwrap().count(), 0);

        // An uninstalled product's certificate is not listed for renewal.
        write(
            &record_path(&case.state, "edge", "api"),
            &AppliedStateRecord::empty("edge", "api"),
        );
        assert!(executor.installed_identities("edge").unwrap().is_empty());
    }
}

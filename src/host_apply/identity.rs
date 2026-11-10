//! Renewal of a host release's workload certificate (ADR 0046 §3).
//!
//! The applier keeps an [`HostIdentityRecord`] beside its applied-state
//! records: the grant, certificate and issuer certificate it installed, all
//! public, so the unprivileged runtime can tell when one is due without
//! reading the root-only key. To renew, the runtime issues a fresh key and
//! certificate for the recorded grant and spools a [`HostIdentityRenewal`]
//! with it under [`HostIdentityRenewal::instance_key`]. The applier installs it only while
//! the product is still applied and its record still holds the certificate
//! the renewal replaces, and only for exactly the grant it recorded itself.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::workload_identity::IdentityGrant;

pub const IDENTITY_RECORD_SCHEMA: &str = "tenkai.host-identity.v1";
pub const RENEWAL_SCHEMA: &str = "tenkai.host-identity-renewal.v1";
/// `<spool>/<instance>/renewal.json`, in place of `request.json`.
pub const RENEWAL_FILE: &str = "renewal.json";
/// Renewal documents are a few hundred bytes.
pub const MAX_RENEWAL_BYTES: u64 = 16 * 1024;

/// The workload certificate the applier installed for one instance.
/// Readable by everyone: it holds no key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentityRecord {
    pub schema: String,
    pub environment: String,
    /// The product whose lock serializes writes of this certificate.
    pub product: String,
    pub instance: String,
    pub grant: IdentityGrant,
    pub certificate: String,
    pub ca: String,
}

impl HostIdentityRecord {
    pub fn new(
        environment: &str,
        product: &str,
        instance: &str,
        issued: &crate::workload_identity::IssuedIdentity,
    ) -> Self {
        Self {
            schema: IDENTITY_RECORD_SCHEMA.into(),
            environment: environment.into(),
            product: product.into(),
            instance: instance.into(),
            grant: issued.grant.clone(),
            certificate: issued.certificate.clone(),
            ca: issued.ca.clone(),
        }
    }
}

/// `identities/<key>.json` under `state_dir`, one per environment and
/// instance.
pub fn identity_record_path(state_dir: &Path, environment: &str, instance: &str) -> PathBuf {
    state_dir.join("identities").join(format!(
        "{}.json",
        super::product_key(environment, instance)
    ))
}

/// What the runtime asks the applier to renew.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentityRenewal {
    pub schema: String,
    pub environment: String,
    pub product: String,
    pub instance: String,
    /// [`certificate_digest`] of the certificate this one replaces.
    pub replaces: String,
    /// Fresh per attempt, so two attempts never share a spool or a unit.
    pub attempt: String,
}

impl HostIdentityRenewal {
    pub fn new(record: &HostIdentityRecord) -> Self {
        Self {
            schema: RENEWAL_SCHEMA.into(),
            environment: record.environment.clone(),
            product: record.product.clone(),
            instance: record.instance.clone(),
            replaces: certificate_digest(&record.certificate),
            attempt: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let renewal: Self = serde_json::from_slice(bytes)?;
        if renewal.schema != RENEWAL_SCHEMA {
            bail!("{RENEWAL_FILE} is not a {RENEWAL_SCHEMA} document");
        }
        crate::ontology::validate_identifier("environment", &renewal.environment)?;
        crate::ontology::validate_identifier("product", &renewal.product)?;
        crate::ontology::validate_identifier("instance", &renewal.instance)?;
        Ok(renewal)
    }

    /// The spool and unit instance this attempt runs as, bound to all of
    /// it. Attempts to replace the same certificate race only on the
    /// applier's product lock, where the first wins and the rest find the
    /// certificate changed.
    pub fn instance_key(&self) -> String {
        let bound = format!(
            "renewal\0{}\0{}\0{}\0{}",
            self.environment, self.instance, self.replaces, self.attempt
        );
        format!("{:x}", Sha256::digest(bound.as_bytes()))
    }
}

/// `sha256:<hex>` of a certificate's PEM text.
pub fn certificate_digest(certificate: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(certificate.as_bytes()))
}

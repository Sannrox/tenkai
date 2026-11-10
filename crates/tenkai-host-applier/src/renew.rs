//! One run of `tenkai-host-apply@<instance>.service` for a spooled workload
//! certificate renewal (ADR 0046 §3).
//!
//! A renewal needs no approval: it installs a fresh certificate and key for
//! exactly the grant an approved step installed, which this applier
//! recorded itself. Under the product lock it checks that the product is
//! still applied, that the record still holds the certificate the renewal
//! replaces, and that the new certificate proves the recorded grant, is
//! valid now and matches its key. Anything else is refused and recorded in
//! `refused.json`; nothing is written.

use anyhow::{Context as _, Result, bail};
use tenkai::host_apply::identity::{HostIdentityRecord, certificate_digest};
use tenkai::host_apply::state::AppliedState;
use tenkai::workload_identity::Reload;

use crate::{Applied, ApplierConfig, ApplierPaths, copy, secrets, store};

/// Whether `instance` is a spooled renewal. A spool or config that cannot be
/// read answers no, so the step path refuses it and records why.
pub fn spooled(paths: &ApplierPaths, instance: &str) -> bool {
    ApplierConfig::load(paths)
        .and_then(|config| copy::is_renewal(&config.spool_dir, instance))
        .unwrap_or(false)
}

/// Install the renewal spooled as `instance`, or record why not.
pub fn renew(paths: &ApplierPaths, instance: &str) -> Result<Applied> {
    match install(paths, instance) {
        Ok(()) => Ok(Applied::Renewed),
        Err(error) => {
            let reason = format!("{error:#}");
            store::record_refusal(paths, instance, &reason, tenkai::now_millis())?;
            Ok(Applied::Refused(reason))
        }
    }
}

fn install(paths: &ApplierPaths, instance: &str) -> Result<()> {
    let config = ApplierConfig::load(paths)?;
    let spooled = copy::read_renewal(&config.spool_dir, instance)?;
    let renewal = &spooled.renewal;
    let (environment, product) = (&renewal.environment, &renewal.product);
    if !spooled.sealed.values.is_empty() {
        bail!("a renewal writes no sealed values");
    }
    let _lock = store::lock_product(paths, environment, product)?;
    if store::read_record(paths, environment, product)?.state == AppliedState::Empty {
        bail!("{product} is not installed in {environment}; its certificate is not renewed");
    }
    let record =
        store::identity_record(paths, environment, &renewal.instance)?.with_context(|| {
            format!(
                "no workload certificate is recorded for {} in {environment}",
                renewal.instance
            )
        })?;
    if record.product != *product {
        bail!(
            "the certificate of {} belongs to {}, not {product}",
            renewal.instance,
            record.product
        );
    }
    if certificate_digest(&record.certificate) != renewal.replaces {
        bail!(
            "the certificate of {} changed since this renewal was asked for",
            renewal.instance
        );
    }
    if record.grant.reload != Reload::Runtime {
        bail!(
            "{} reads its certificate only at start; it renews with a restart",
            renewal.instance
        );
    }
    let issued = spooled
        .sealed
        .bind_identity(Some(&record.grant))?
        .context("the renewal carries no certificate")?;
    secrets::write_identity(paths, environment, &renewal.instance, &issued)
        .context("writing the renewed workload certificate")?;
    store::write_identity_record(
        paths,
        &HostIdentityRecord::new(environment, product, &renewal.instance, &issued),
    )
}

//! Workload certificate state an environment runtime reports (ADR 0046 §3).
//!
//! The runtime renews workload certificates on its own, with or without the
//! server. Once the server is reachable it reports, per instance, the
//! validity of the certificate its target holds and the last renewal
//! attempt it audited. `status` reads the stored reports to show an instance
//! whose certificate is in its last sixth as near expiry, with the expiry
//! time and the last failure.
//!
//! Like host records ([`crate::host_records`]), each report is its own
//! immutable object addressed by its environment, instance and content
//! digest, so writing one again writes the same bytes and needs no lock. A
//! report is stored only when it is further on than the stored one of its
//! instance ([`progress`]), so a late or repeated report never moves an
//! instance back; the one it supersedes is then removed.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::pb::sekai::Object;

pub const CERTIFICATE_REPORT_SCHEMA: &str = "tenkai.workload-certificate.v1";
/// Most reports one request may carry; a runtime sends more in batches.
pub const MAX_REPORTS: usize = 1024;
/// Failure reasons are short; a longer one is cut to this many bytes.
pub const MAX_REASON_BYTES: usize = 512;

/// One instance's workload certificate, as its runtime last saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateReport {
    pub schema: String,
    pub environment: String,
    pub instance: String,
    /// Validity of the certificate the target holds, in Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// The last renewal attempt the runtime audited for this instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_renewal: Option<RenewalEvent>,
}

/// One renewal attempt, as the runtime audits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewalEvent {
    /// When the attempt ended, in Unix seconds.
    pub at: i64,
    pub instance: String,
    pub outcome: RenewalOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RenewalOutcome {
    /// A fresh certificate valid until `not_after` was written.
    Renewed { not_after: i64 },
    /// Nothing was written, for `reason`.
    Failed { reason: String },
}

/// What `status` shows of an instance's workload certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CertificateStatus {
    /// When the certificate expires, in Unix seconds.
    pub expires_at: i64,
    /// In the last sixth of its lifetime, so renewal is late.
    pub near_expiry: bool,
    /// Why the last renewal attempt failed, while it is the latest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub renewal_failure: Option<String>,
}

impl CertificateReport {
    /// What `status` shows of this report at `now_secs`.
    pub fn status(&self, now_secs: i64) -> CertificateStatus {
        let lifetime = self.not_after.saturating_sub(self.not_before);
        CertificateStatus {
            expires_at: self.not_after,
            near_expiry: now_secs >= self.not_after.saturating_sub(lifetime / 6),
            // A failure from before this certificate was issued is not
            // this certificate's.
            renewal_failure: match &self.last_renewal {
                Some(RenewalEvent {
                    at,
                    outcome: RenewalOutcome::Failed { reason },
                    ..
                }) if *at >= self.not_before => Some(reason.clone()),
                _ => None,
            },
        }
    }
}

/// How far on a report is: a later certificate, then a later attempt.
fn progress(report: &CertificateReport) -> (i64, i64) {
    (
        report.not_after,
        report
            .last_renewal
            .as_ref()
            .map_or(i64::MIN, |event| event.at),
    )
}

fn report_id(environment: &str, instance: &str, json: &str) -> String {
    format!(
        "tenkai:workload-certificate:{environment}:{instance}:{:x}",
        Sha256::digest(json.as_bytes())
    )
}

/// Admit `reports` for `environment`. Every report must be one of this
/// environment's, for a valid instance, once. Stores each report that is
/// further on than the stored one of its instance and removes the one it
/// supersedes. Returns the instances whose report was stored.
pub async fn admit(
    ctx: &mut Ctx,
    environment: &str,
    reports: &[CertificateReport],
) -> Result<Vec<String>> {
    if reports.len() > MAX_REPORTS {
        bail!("a report carries at most {MAX_REPORTS} workload certificates");
    }
    let mut seen = std::collections::BTreeSet::new();
    for report in reports {
        if report.schema != CERTIFICATE_REPORT_SCHEMA {
            bail!(
                "certificate report of {} is not a {CERTIFICATE_REPORT_SCHEMA} report",
                report.instance
            );
        }
        if report.environment != environment {
            bail!(
                "certificate report of {} names environment {}, not {environment}",
                report.instance,
                report.environment
            );
        }
        crate::ontology::validate_identifier("instance", &report.instance)?;
        if report
            .last_renewal
            .as_ref()
            .is_some_and(|event| event.instance != report.instance)
        {
            bail!(
                "certificate report of {} carries another instance's renewal",
                report.instance
            );
        }
        if let Some(RenewalEvent {
            outcome: RenewalOutcome::Failed { reason },
            ..
        }) = &report.last_renewal
            && reason.len() > MAX_REASON_BYTES
        {
            bail!(
                "certificate report of {} carries a failure longer than {MAX_REASON_BYTES} bytes",
                report.instance
            );
        }
        if !seen.insert(report.instance.as_str()) {
            bail!("the report carries two certificates of {}", report.instance);
        }
    }
    // The environment must exist; nothing of it is written.
    crate::environment::environment(ctx, environment).await?;
    let (stored_now, _) = load(ctx, environment).await?;
    let now = crate::now_millis();
    let mut stored = Vec::new();
    for report in reports {
        if stored_now
            .get(&report.instance)
            .is_some_and(|current| progress(current) >= progress(report))
        {
            continue;
        }
        let json = serde_json::to_string(report)?;
        let id = report_id(environment, &report.instance, &json);
        if ctx.get(&id).await?.is_some() {
            continue;
        }
        ctx.put(Object {
            id,
            kind: crate::ontology::KIND_WORKLOAD_CERTIFICATE.into(),
            name: format!(
                "workload certificate of {} in {environment}",
                report.instance
            ),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("environment".into(), environment.into()),
                ("instance".into(), report.instance.clone()),
                ("report".into(), json),
            ]),
            created: now,
            updated: now,
        })
        .await?;
        stored.push(report.instance.clone());
    }
    if !stored.is_empty() {
        let (_, superseded) = load(ctx, environment).await?;
        for id in superseded {
            ctx.delete(&id).await?;
        }
    }
    Ok(stored)
}

/// The furthest stored report of each instance in `environment`, and the
/// ids of the reports they supersede. Equal progress is broken by id, so
/// every reader picks the same report.
async fn load(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<(BTreeMap<String, CertificateReport>, Vec<String>)> {
    let objects = ctx
        .find_by_property(
            crate::ontology::KIND_WORKLOAD_CERTIFICATE,
            "environment",
            environment,
        )
        .await?;
    let mut best: BTreeMap<String, (CertificateReport, String)> = BTreeMap::new();
    let mut superseded = Vec::new();
    for object in objects {
        let Some(json) = object.properties.get("report") else {
            continue;
        };
        let report: CertificateReport = serde_json::from_str(json)
            .with_context(|| format!("parsing the certificate report {}", object.id))?;
        if report.environment != environment
            || object.properties.get("instance") != Some(&report.instance)
        {
            bail!(
                "the certificate report {} names another instance",
                object.id
            );
        }
        let key = (progress(&report), object.id.clone());
        match best.get(&report.instance) {
            Some((current, id)) if (progress(current), id.clone()) >= key => {
                superseded.push(object.id);
            }
            _ => {
                if let Some((_, id)) = best.insert(report.instance.clone(), (report, object.id)) {
                    superseded.push(id);
                }
            }
        }
    }
    Ok((
        best.into_iter()
            .map(|(instance, (report, _))| (instance, report))
            .collect(),
        superseded,
    ))
}

/// The furthest reported certificate of each instance in `environment`.
pub async fn reported(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<BTreeMap<String, CertificateReport>> {
    Ok(load(ctx, environment).await?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(not_after: i64, last: Option<(i64, RenewalOutcome)>) -> CertificateReport {
        CertificateReport {
            schema: CERTIFICATE_REPORT_SCHEMA.into(),
            environment: "prod".into(),
            instance: "api".into(),
            not_before: not_after - 24 * 3600,
            not_after,
            last_renewal: last.map(|(at, outcome)| RenewalEvent {
                at,
                instance: "api".into(),
                outcome,
            }),
        }
    }

    /// The last sixth of the lifetime is near expiry, with the failure
    /// that kept renewal from clearing it; a renewed certificate is not.
    #[test]
    fn a_certificate_in_its_last_sixth_is_near_expiry() {
        let expires = 100_000;
        let failed = report(
            expires,
            Some((
                expires - 5 * 3600,
                RenewalOutcome::Failed {
                    reason: "the cluster is unreachable".into(),
                },
            )),
        );
        let status = failed.status(expires - 4 * 3600 - 1);
        assert!(!status.near_expiry);
        let status = failed.status(expires - 4 * 3600);
        assert!(status.near_expiry);
        assert_eq!(status.expires_at, expires);
        assert_eq!(
            status.renewal_failure.as_deref(),
            Some("the cluster is unreachable")
        );

        let renewed_until = expires + 8 * 3600;
        let renewed = report(
            renewed_until,
            Some((
                expires - 3600,
                RenewalOutcome::Renewed {
                    not_after: renewed_until,
                },
            )),
        );
        assert!(progress(&renewed) > progress(&failed));
        let status = renewed.status(expires - 3600);
        assert!(!status.near_expiry);
        assert!(status.renewal_failure.is_none());
    }

    /// A late or repeated report never moves an instance back, and one
    /// report per instance remains.
    #[tokio::test]
    async fn a_late_report_never_moves_a_certificate_back() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-certificate-reports-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "runtime")
            .await
            .unwrap();

        let first = report(100_000, None);
        let failed = report(
            100_000,
            Some((
                90_000,
                RenewalOutcome::Failed {
                    reason: "unreachable".into(),
                },
            )),
        );
        let renewed = report(
            170_000,
            Some((91_000, RenewalOutcome::Renewed { not_after: 170_000 })),
        );
        assert_eq!(
            admit(&mut ctx, "prod", std::slice::from_ref(&first))
                .await
                .unwrap(),
            ["api"]
        );
        assert_eq!(
            admit(&mut ctx, "prod", std::slice::from_ref(&renewed))
                .await
                .unwrap(),
            ["api"]
        );
        for late in [first, failed, renewed.clone()] {
            assert!(admit(&mut ctx, "prod", &[late]).await.unwrap().is_empty());
        }
        assert_eq!(reported(&mut ctx, "prod").await.unwrap()["api"], renewed);
        let objects = ctx
            .find_by_property(
                crate::ontology::KIND_WORKLOAD_CERTIFICATE,
                "instance",
                "api",
            )
            .await
            .unwrap();
        assert_eq!(objects.len(), 1, "{objects:?}");

        let foreign = CertificateReport {
            environment: "other".into(),
            ..report(200_000, None)
        };
        admit(&mut ctx, "prod", &[foreign]).await.unwrap_err();
        let _ = std::fs::remove_file(database);
    }
}

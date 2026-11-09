//! Host applied-state records an environment runtime reports (ADR 0048 §2).
//!
//! The root-side applier keeps one applied-state record per environment and
//! product on the host it runs on (ADR 0041 §2). When that host is a remote
//! runtime's, the server cannot read the record, so the runtime reports it.
//! The server keeps each reported record as an admitted, read-only fact, and
//! plans host steps from it as it does from a record on its own disk. A
//! reported record only names the generation and source release a step
//! expects; the applier checks both again before it runs anything, so a
//! stale record makes the step refused, never run.
//!
//! Each reported record is its own immutable object, addressed by its
//! environment, product, and content digest. A report never rewrites
//! anything: writing an object again writes the same bytes, so concurrent
//! and delayed reports need no lock or revision check. Planning takes the
//! most advanced record of each product ([`progress`]), so a report that
//! arrives late never moves a product back. A report removes only records
//! another stored record strictly supersedes.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::host_apply::state::{APPLIED_STATE_SCHEMA, AppliedStateRecord};
use crate::host_executor::HostExecutor;
use crate::pb::sekai::Object;

/// Most records one report may carry.
const MAX_RECORDS: usize = 1024;

/// Where an applier's run of one product stands. Generations advance when an
/// install or uninstall starts, not when it ends, and a health step never
/// advances one; so within a generation, a later start, and then its result,
/// are further on.
///
/// Starts within a generation are ordered by the applier host's clock: the
/// record carries no durable sequence. A clock stepped back between two starts
/// can rank the later one lower; planning then asks for a step that already
/// ran, which still needs approval and the applier's checks, so nothing runs
/// unapproved. A sequence in the applier's record would remove that.
fn progress(record: &AppliedStateRecord) -> (u64, i64, Option<i64>) {
    let started = record.last_started.as_ref();
    let finished = record
        .last_result
        .as_ref()
        .filter(|result| started.is_some_and(|started| started.instance == result.instance))
        .map(|result| result.finished_at);
    (
        record.generation,
        started.map_or(i64::MIN, |started| started.started_at),
        finished,
    )
}

fn record_id(environment: &str, product: &str, json: &str) -> String {
    format!(
        "tenkai:host-record:{environment}:{product}:{:x}",
        Sha256::digest(json.as_bytes())
    )
}

/// Set once a runtime reported for `environment`, with or without records:
/// from then on its host steps are planned from reported records only.
fn reported_id(environment: &str) -> String {
    format!("tenkai:host-records-reported:{environment}")
}

/// Admit `records` for `environment`. Every record must be one of this
/// environment's, for a valid product, once. Stores each record not already
/// stored, then removes this environment's records that a stored record of
/// the same product supersedes. Returns the products whose record was new.
pub async fn admit(
    ctx: &mut Ctx,
    environment: &str,
    records: &[AppliedStateRecord],
) -> Result<Vec<String>> {
    if records.len() > MAX_RECORDS {
        bail!("a report carries at most {MAX_RECORDS} host records");
    }
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        if record.schema != APPLIED_STATE_SCHEMA {
            bail!(
                "host record of {} is not a {APPLIED_STATE_SCHEMA} record",
                record.product
            );
        }
        if record.environment != environment {
            bail!(
                "host record of {} names environment {}, not {environment}",
                record.product,
                record.environment
            );
        }
        crate::ontology::validate_identifier("product", &record.product)?;
        if !seen.insert(record.product.as_str()) {
            bail!("the report carries two host records of {}", record.product);
        }
    }
    // The environment must exist; nothing of it is written.
    crate::environment::environment(ctx, environment).await?;
    let now = crate::now_millis();
    let mut stored = Vec::new();
    for record in records {
        let json = serde_json::to_string(record)?;
        let id = record_id(environment, &record.product, &json);
        if ctx.get(&id).await?.is_some() {
            continue;
        }
        ctx.put(Object {
            id,
            kind: crate::ontology::KIND_HOST_RECORD.into(),
            name: format!("host record of {} in {environment}", record.product),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("environment".into(), environment.into()),
                ("product".into(), record.product.clone()),
                ("record".into(), json),
            ]),
            created: now,
            updated: now,
        })
        .await?;
        stored.push(record.product.clone());
    }
    let marker = reported_id(environment);
    if ctx.get(&marker).await?.is_none() {
        ctx.put(Object {
            id: marker,
            kind: crate::ontology::KIND_HOST_RECORD.into(),
            name: format!("host records reported for {environment}"),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([(
                "environment".into(),
                environment.into(),
            )]),
            created: now,
            updated: now,
        })
        .await?;
    }
    if !stored.is_empty() {
        let (_, superseded) = load(ctx, environment).await?;
        for id in superseded {
            ctx.delete(&id).await?;
        }
    }
    Ok(stored)
}

/// The most advanced reported record of each product in `environment`, and
/// the ids of the records they supersede; `None` when its runtime never
/// reported. Equal progress is broken by record id, so every reader picks
/// the same record.
async fn load(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<(Option<BTreeMap<String, AppliedStateRecord>>, Vec<String>)> {
    let objects = ctx
        .find_by_property(
            crate::ontology::KIND_HOST_RECORD,
            "environment",
            environment,
        )
        .await?;
    let marker = reported_id(environment);
    let reported = objects.iter().any(|object| object.id == marker);
    let mut best: BTreeMap<String, (AppliedStateRecord, String)> = BTreeMap::new();
    let mut superseded = Vec::new();
    for object in objects {
        let Some(json) = object.properties.get("record") else {
            continue;
        };
        let record: AppliedStateRecord = serde_json::from_str(json)
            .with_context(|| format!("parsing the reported host record {}", object.id))?;
        if record.environment != environment
            || object.properties.get("product") != Some(&record.product)
        {
            bail!(
                "the reported host record {} names another product",
                object.id
            );
        }
        let key = (progress(&record), object.id.clone());
        match best.get(&record.product) {
            Some((current, id)) if (progress(current), id.clone()) >= key => {
                superseded.push(object.id);
            }
            _ => {
                if let Some((_, id)) = best.insert(record.product.clone(), (record, object.id)) {
                    superseded.push(id);
                }
            }
        }
    }
    let records = reported.then(|| {
        best.into_iter()
            .map(|(product, (record, _))| (product, record))
            .collect()
    });
    Ok((records, superseded))
}

/// Where planning reads an environment's host records from.
pub(crate) enum HostRecords<'a> {
    /// The applier on this server's host.
    Local(&'a HostExecutor),
    /// What the environment's runtime reported, by product.
    Reported(BTreeMap<String, AppliedStateRecord>),
}

impl<'a> HostRecords<'a> {
    /// The records of `environment`: reported ones once its runtime reported,
    /// else this process's applier. Without either, host steps cannot be
    /// planned and the error says why.
    pub(crate) async fn of(
        ctx: &mut Ctx,
        executors: &'a crate::software_executor::SoftwareExecutors,
        environment: &str,
    ) -> Result<Self> {
        if let (Some(records), _) = load(ctx, environment).await? {
            return Ok(Self::Reported(records));
        }
        match executors.host() {
            Ok(host) => Ok(Self::Local(host)),
            // The executor's own reason first: it names what is missing here.
            Err(error) => Err(anyhow::anyhow!(
                "{error:#}; no host applied-state records are reported for {environment}, and a runtime that runs host releases reports them"
            )),
        }
    }

    /// The record of `product`, or the empty record of a product the applier
    /// never touched.
    pub(crate) fn applied_state(
        &self,
        environment: &str,
        product: &str,
    ) -> Result<AppliedStateRecord> {
        match self {
            Self::Local(host) => host.applied_state(environment, product),
            Self::Reported(records) => Ok(records
                .get(product)
                .cloned()
                .unwrap_or_else(|| AppliedStateRecord::empty(environment, product))),
        }
    }

    /// Every record of `environment`, by product.
    pub(crate) fn applied_states(&self, environment: &str) -> Result<Vec<AppliedStateRecord>> {
        match self {
            Self::Local(host) => host.applied_states(environment),
            Self::Reported(records) => Ok(records.values().cloned().collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_apply::HostRelease;
    use crate::host_apply::state::AppliedState;

    fn record(product: &str, generation: u64, version: &str) -> AppliedStateRecord {
        AppliedStateRecord {
            generation,
            state: AppliedState::Applied {
                release: HostRelease {
                    version: version.into(),
                    manifest_digest: "a".repeat(64),
                },
            },
            ..AppliedStateRecord::empty("edge", product)
        }
    }

    /// `cluster` at generation 1 while its install of 1.1.0 runs, and once
    /// it succeeded: the same generation, further on.
    fn install_running_then_done() -> (AppliedStateRecord, AppliedStateRecord) {
        let release = |version: &str| HostRelease {
            version: version.into(),
            manifest_digest: "a".repeat(64),
        };
        let started = crate::host_apply::state::HostApplyStarted {
            schema: crate::host_apply::state::STARTED_SCHEMA.into(),
            instance: "b".repeat(64),
            plan_id: "plan".into(),
            plan_digest: format!("sha256:{}", "c".repeat(64)),
            step_id: "plan:step:0".into(),
            environment: "edge".into(),
            product: "cluster".into(),
            action: crate::host_apply::HostAction::Install,
            release: release("1.1.0"),
            generation: 1,
            started_at: 1_000,
            cgroup: None,
        };
        let running = AppliedStateRecord {
            generation: 1,
            state: AppliedState::Dirty {
                from: Some(release("1.0.0")),
                to: Some(release("1.1.0")),
            },
            last_started: Some(started.clone()),
            ..AppliedStateRecord::empty("edge", "cluster")
        };
        let result = started.result(
            crate::host_apply::state::HostApplyOutcome::Succeeded,
            Some(0),
            "done",
            2_000,
        );
        let done = running.complete(&started, &result);
        (running, done)
    }

    async fn ctx(label: &str) -> (std::path::PathBuf, Ctx) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-host-records-{label}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "edge", "runtime host")
            .await
            .unwrap();
        (database, ctx)
    }

    async fn reported(ctx: &mut Ctx) -> Result<Vec<AppliedStateRecord>> {
        let executors = crate::software_executor::SoftwareExecutors::default();
        HostRecords::of(ctx, &executors, "edge")
            .await?
            .applied_states("edge")
    }

    #[tokio::test]
    async fn without_a_report_or_a_local_applier_nothing_is_planned() {
        let (database, mut ctx) = ctx("none").await;
        let error = reported(&mut ctx).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("no host applied-state records are reported for edge"),
            "{error:#}"
        );
        // An empty report says the runtime's applier holds nothing yet.
        admit(&mut ctx, "edge", &[]).await.unwrap();
        assert!(reported(&mut ctx).await.unwrap().is_empty());
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn a_delayed_report_never_moves_a_product_back() {
        let (database, mut ctx) = ctx("order").await;
        admit(&mut ctx, "edge", &[record("cluster", 2, "1.1.0")])
            .await
            .unwrap();
        admit(&mut ctx, "edge", &[record("cluster", 1, "1.0.0")])
            .await
            .unwrap();
        assert_eq!(
            reported(&mut ctx).await.unwrap(),
            [record("cluster", 2, "1.1.0")]
        );
        // Within one generation, a completed step outranks the snapshot
        // taken while it ran, in either arrival order.
        let (running, done) = install_running_then_done();
        for order in [[&running, &done], [&done, &running]] {
            let (database, mut ctx) = super::tests::ctx("same-generation").await;
            for record in order {
                admit(&mut ctx, "edge", std::slice::from_ref(record))
                    .await
                    .unwrap();
            }
            assert_eq!(
                reported(&mut ctx).await.unwrap(),
                std::slice::from_ref(&done)
            );
            let _ = std::fs::remove_file(database);
        }
        // Superseded records are removed: one record per product remains.
        let objects = ctx
            .find_by_property(crate::ontology::KIND_HOST_RECORD, "product", "cluster")
            .await
            .unwrap();
        assert_eq!(objects.len(), 1, "{objects:?}");
        let _ = std::fs::remove_file(database);
    }

    #[tokio::test]
    async fn records_of_another_environment_or_twice_one_product_are_refused() {
        let (database, mut ctx) = ctx("refused").await;
        let foreign = AppliedStateRecord {
            environment: "other".into(),
            ..record("cluster", 1, "1.0.0")
        };
        assert!(admit(&mut ctx, "edge", &[foreign]).await.is_err());
        let twice = [record("cluster", 1, "1.0.0"), record("cluster", 2, "1.1.0")];
        assert!(admit(&mut ctx, "edge", &twice).await.is_err());
        // Nothing of a refused report is stored.
        assert!(reported(&mut ctx).await.is_err());
        let _ = std::fs::remove_file(database);
    }
}

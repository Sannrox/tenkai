//! Delivery performance for one environment over a period (#1083).
//!
//! Computed only from recorded deployment attempts, their release's publish
//! time, instance health reports, and deployed exposure records. Reads only;
//! the same records always give the same report. Definitions live in
//! `docs/delivery-report.md`.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::apply::StepOutcomeStatus;
use crate::client::Ctx;
use crate::ontology::{KIND_DEPLOYMENT, release_id};
use crate::schema_contract::omitted_when_none;

/// The period a report covers when the query names none.
pub const DEFAULT_PERIOD_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Query parameters for `GET /v1/environments/{environment}/delivery-report`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeliveryReportQuery {
    /// Inclusive start, Unix milliseconds. Default: 30 days before `until_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ms: Option<i64>,
    /// Exclusive end, Unix milliseconds. Default: now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<i64>,
}

/// Delivery performance of one environment over `[since_ms, until_ms)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeliveryReport {
    pub environment: String,
    pub since_ms: i64,
    pub until_ms: i64,
    /// No attempt was recorded and no instance health was reported in the
    /// period. The rows then say nothing about how the environment ran.
    pub missing_data: bool,
    /// One row per product and channel, ordered by product then channel.
    pub rows: Vec<DeliveryMetrics>,
}

/// Delivery metrics for one product and channel in one environment.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeliveryMetrics {
    pub product: String,
    /// The channel the instances subscribe to now; absent for instances no
    /// longer subscribed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub channel: Option<String>,
    /// Change attempts that succeeded.
    pub deployments: u32,
    /// Install, upgrade and removal attempts that finished. Rollbacks and
    /// blocked attempts are not changes.
    pub change_attempts: u32,
    /// Change attempts that failed or were rolled back.
    pub change_failures: u32,
    /// `change_failures / change_attempts`; absent without change attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub change_failure_rate: Option<f64>,
    /// Median time from the release's publication to its successful deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub lead_time_ms: Option<i64>,
    /// Failures in the period that a later attempt restored.
    pub restores: u32,
    /// Failures in the period still not restored at its end.
    pub unrestored: u32,
    /// Median time from a failure to its restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub time_to_restore_ms: Option<i64>,
    /// Advisory exposures open at the end of the period on the releases running then.
    pub open_exposures: u32,
    /// Age at the end of the period of the oldest of those exposures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub oldest_exposure_age_ms: Option<i64>,
}

/// One recorded attempt, reduced to what the metrics read.
struct Attempt {
    instance: String,
    product: String,
    rollback: bool,
    status: StepOutcomeStatus,
    created_at: i64,
    finished_at: i64,
    from_version: Option<String>,
    to_version: String,
}

impl Attempt {
    fn is_change(&self) -> bool {
        !self.rollback && self.status != StepOutcomeStatus::Blocked
    }

    fn is_failure(&self) -> bool {
        matches!(
            self.status,
            StepOutcomeStatus::Failed | StepOutcomeStatus::RolledBack
        )
    }

    /// Whether the instance serves a working release once this attempt ends.
    fn restores_service(&self) -> bool {
        matches!(
            self.status,
            StepOutcomeStatus::Succeeded | StepOutcomeStatus::RolledBack
        )
    }

    /// The version running after this attempt, if it ended on a working one.
    fn running_version(&self) -> Option<&str> {
        match self.status {
            StepOutcomeStatus::Succeeded => Some(&self.to_version),
            StepOutcomeStatus::RolledBack => self.from_version.as_deref(),
            _ => None,
        }
    }
}

/// Delivery performance of `environment_name`. Refuses an unknown environment
/// and an empty or inverted period.
pub async fn delivery_report(
    ctx: &mut Ctx,
    environment_name: &str,
    query: &DeliveryReportQuery,
) -> Result<DeliveryReport> {
    let env = crate::environment::environment(ctx, environment_name).await?;
    let until_ms = query.until_ms.unwrap_or_else(crate::now_millis);
    let since_ms = query
        .since_ms
        .unwrap_or_else(|| until_ms.saturating_sub(DEFAULT_PERIOD_MS));
    if since_ms >= until_ms {
        bail!("delivery report period is empty: since {since_ms} is not before until {until_ms}");
    }

    let mut attempts = Vec::new();
    for object in ctx
        .find_by_property(KIND_DEPLOYMENT, "environment", &env.name)
        .await?
    {
        if object.created >= until_ms {
            continue;
        }
        let property = |key: &str| object.properties.get(key).filter(|v| !v.is_empty());
        let Some(status) = property("status") else {
            continue;
        };
        let product = property("product").cloned().unwrap_or_default();
        attempts.push(Attempt {
            instance: property("instance")
                .cloned()
                .unwrap_or_else(|| product.clone()),
            product,
            rollback: property("action").map(String::as_str) == Some("rollback"),
            status: StepOutcomeStatus::parse(status)?,
            created_at: object.created,
            finished_at: object.updated.max(object.created),
            from_version: property("from_version").cloned(),
            to_version: property("to_version").cloned().unwrap_or_default(),
        });
    }
    attempts.sort_by(|left, right| {
        (left.created_at, &left.instance).cmp(&(right.created_at, &right.instance))
    });

    let mut channels = BTreeMap::new();
    for subscription in crate::environment::list_subscriptions(ctx, &env).await? {
        let instance = if subscription.instance.is_empty() {
            subscription.product.clone()
        } else {
            subscription.instance
        };
        let channel = subscription.channel.properties.get("channel").cloned();
        channels.insert(instance, (subscription.product, channel));
    }

    let mut published = BTreeMap::new();
    for attempt in attempts.iter().filter(|a| {
        a.is_change() && a.status == StepOutcomeStatus::Succeeded && a.created_at >= since_ms
    }) {
        let id = release_id(&attempt.product, &attempt.to_version);
        if let std::collections::btree_map::Entry::Vacant(slot) = published.entry(id) {
            let created = ctx.get(slot.key()).await?.map(|release| release.created);
            slot.insert(created);
        }
    }

    let exposures = crate::exposure::all_deployed_exposures(ctx).await?;
    let in_period = attempts.iter().any(|a| a.created_at >= since_ms);
    let reported = crate::instance_health::reported(ctx, &env.name)
        .await?
        .values()
        .any(|observation| observation.observed_at_ms >= since_ms);

    let mut instances: BTreeMap<&str, Vec<&Attempt>> = BTreeMap::new();
    for attempt in &attempts {
        instances
            .entry(&attempt.instance)
            .or_default()
            .push(attempt);
    }
    let mut rows: BTreeMap<(String, Option<String>), Row> = BTreeMap::new();
    for (instance, (product, channel)) in &channels {
        rows.entry((product.clone(), channel.clone())).or_default();
        instances.entry(instance).or_default();
    }
    for (instance, history) in instances {
        let (product, channel) = channels.get(instance).cloned().unwrap_or_else(|| {
            let product = history
                .first()
                .map(|a| a.product.clone())
                .unwrap_or_default();
            (product, None)
        });
        let row = rows.entry((product.clone(), channel)).or_default();
        row.add_instance(&history, since_ms, &published);
        let running = history
            .iter()
            .rev()
            .find_map(|attempt| attempt.running_version());
        if let Some(version) = running {
            let running_id = release_id(&product, version);
            for exposure in &exposures {
                let open = exposure.first_seen_at < until_ms
                    && exposure.closed_at.is_none_or(|closed| closed > until_ms);
                if open && exposure.release_id == running_id {
                    row.exposure_ages.push(until_ms - exposure.first_seen_at);
                }
            }
        }
    }

    Ok(DeliveryReport {
        environment: env.name,
        since_ms,
        until_ms,
        missing_data: !in_period && !reported,
        rows: rows
            .into_iter()
            .map(|((product, channel), row)| row.metrics(product, channel))
            .collect(),
    })
}

/// Raw observations for one row, folded into [`DeliveryMetrics`] at the end.
#[derive(Default)]
struct Row {
    deployments: u32,
    change_attempts: u32,
    change_failures: u32,
    lead_times: Vec<i64>,
    restore_times: Vec<i64>,
    unrestored: u32,
    exposure_ages: Vec<i64>,
}

impl Row {
    /// Fold one instance's attempts, oldest first. Consecutive failures form
    /// one incident, restored by the first attempt after them that leaves a
    /// working release; its time to restore runs from the first failure.
    fn add_instance(
        &mut self,
        history: &[&Attempt],
        since_ms: i64,
        published: &BTreeMap<String, Option<i64>>,
    ) {
        let mut incident: Option<i64> = None;
        for attempt in history {
            let counted = attempt.created_at >= since_ms;
            if counted && attempt.is_change() {
                self.change_attempts += 1;
                if attempt.is_failure() {
                    self.change_failures += 1;
                    incident.get_or_insert(attempt.created_at);
                } else {
                    self.deployments += 1;
                    let id = release_id(&attempt.product, &attempt.to_version);
                    if let Some(Some(published_at)) = published.get(&id)
                        && attempt.finished_at >= *published_at
                    {
                        self.lead_times.push(attempt.finished_at - published_at);
                    }
                }
            }
            if attempt.restores_service()
                && let Some(started) = incident.take()
            {
                self.restore_times.push(attempt.finished_at - started);
            }
        }
        if incident.is_some() {
            self.unrestored += 1;
        }
    }

    fn metrics(self, product: String, channel: Option<String>) -> DeliveryMetrics {
        DeliveryMetrics {
            product,
            channel,
            deployments: self.deployments,
            change_attempts: self.change_attempts,
            change_failures: self.change_failures,
            change_failure_rate: (self.change_attempts > 0)
                .then(|| f64::from(self.change_failures) / f64::from(self.change_attempts)),
            lead_time_ms: lower_median(self.lead_times),
            restores: u32::try_from(self.restore_times.len()).unwrap_or(u32::MAX),
            unrestored: self.unrestored,
            time_to_restore_ms: lower_median(self.restore_times),
            open_exposures: u32::try_from(self.exposure_ages.len()).unwrap_or(u32::MAX),
            oldest_exposure_age_ms: self.exposure_ages.into_iter().max(),
        }
    }
}

/// The lower of the two middle values, so the median is always a recorded one.
fn lower_median(mut values: Vec<i64>) -> Option<i64> {
    values.sort_unstable();
    values.get(values.len().saturating_sub(1) / 2).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ontology::{KIND_RELEASE, NS, deployment_id};
    use crate::pb::record::Object;
    use std::collections::HashMap;

    async fn store(label: &str) -> (Ctx, std::path::PathBuf) {
        let database = std::env::temp_dir().join(format!(
            "tenkai-delivery-report-{label}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        (ctx, database)
    }

    /// One `api` attempt from 1.0.0 to `to`, created at `at` and finished 10 ms later.
    async fn attempt(ctx: &mut Ctx, at: i64, action: &str, status: &str, to: &str) {
        ctx.put(Object {
            id: deployment_id("prod", "api", at),
            kind: KIND_DEPLOYMENT.into(),
            name: "api (prod)".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), "prod".into()),
                ("product".into(), "api".into()),
                ("instance".into(), "api".into()),
                ("from_version".into(), "1.0.0".into()),
                ("to_version".into(), to.into()),
                ("status".into(), status.into()),
                ("action".into(), action.into()),
            ]),
            created: at,
            updated: at + 10,
        })
        .await
        .unwrap();
    }

    async fn release(ctx: &mut Ctx, version: &str, published_at: i64) {
        ctx.put(Object {
            id: release_id("api", version),
            kind: KIND_RELEASE.into(),
            name: format!("api@{version}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("product".into(), "api".into()),
                ("version".into(), version.into()),
            ]),
            created: published_at,
            updated: published_at,
        })
        .await
        .unwrap();
    }

    fn period(since_ms: i64, until_ms: i64) -> DeliveryReportQuery {
        DeliveryReportQuery {
            since_ms: Some(since_ms),
            until_ms: Some(until_ms),
        }
    }

    #[tokio::test]
    async fn a_failure_then_a_rollback_is_one_failure_and_one_restore() {
        let (mut ctx, database) = store("restore").await;
        attempt(&mut ctx, 1_000, "upgrade", "failed", "1.1.0").await;
        attempt(&mut ctx, 1_500, "rollback", "succeeded", "1.0.0").await;
        // A failure the executor rolled back itself is restored on its own.
        attempt(&mut ctx, 2_000, "upgrade", "rolled_back", "1.2.0").await;

        let report = delivery_report(&mut ctx, "prod", &period(0, 10_000))
            .await
            .unwrap();
        let [row] = report.rows.as_slice() else {
            panic!("one row: {:?}", report.rows)
        };
        assert_eq!(
            (row.change_attempts, row.change_failures, row.deployments),
            (2, 2, 0)
        );
        assert_eq!((row.restores, row.unrestored), (2, 0));
        // Lower median of 510 (1_510 - 1_000) and 10 (2_010 - 2_000).
        assert_eq!(row.time_to_restore_ms, Some(10));
        assert_eq!(row.change_failure_rate, Some(1.0));
        std::fs::remove_file(database).ok();
    }

    #[tokio::test]
    async fn an_environment_that_recorded_nothing_in_the_period_is_missing_data() {
        let (mut ctx, database) = store("missing").await;
        attempt(&mut ctx, 1_000, "upgrade", "succeeded", "1.1.0").await;

        let quiet = delivery_report(&mut ctx, "prod", &period(5_000, 10_000))
            .await
            .unwrap();
        assert!(quiet.missing_data);
        let [row] = quiet.rows.as_slice() else {
            panic!("one row: {:?}", quiet.rows)
        };
        assert_eq!((row.change_attempts, row.deployments), (0, 0));

        let active = delivery_report(&mut ctx, "prod", &period(0, 10_000))
            .await
            .unwrap();
        assert!(!active.missing_data);
        std::fs::remove_file(database).ok();
    }

    #[tokio::test]
    async fn the_same_records_give_the_same_report() {
        let (mut ctx, database) = store("stable").await;
        release(&mut ctx, "1.1.0", 400).await;
        attempt(&mut ctx, 1_000, "upgrade", "succeeded", "1.1.0").await;
        attempt(&mut ctx, 2_000, "upgrade", "failed", "1.2.0").await;

        let first = delivery_report(&mut ctx, "prod", &period(0, 10_000))
            .await
            .unwrap();
        let second = delivery_report(&mut ctx, "prod", &period(0, 10_000))
            .await
            .unwrap();
        assert_eq!(first, second);
        let row = &first.rows[0];
        assert_eq!(row.lead_time_ms, Some(610));
        assert_eq!((row.deployments, row.unrestored), (1, 1));
        std::fs::remove_file(database).ok();
    }

    #[tokio::test]
    async fn an_empty_period_is_refused() {
        let (mut ctx, database) = store("empty").await;
        let error = delivery_report(&mut ctx, "prod", &period(10, 10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("period is empty"), "{error}");
        std::fs::remove_file(database).ok();
    }
}

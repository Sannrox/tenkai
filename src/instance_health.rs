//! Continuous instance health a runtime reports after apply (#1057).
//!
//! Apply still writes `deployment_health.<instance>` once. The runtime then
//! re-runs `deploy.health` on its work poll and POSTs an observation bound
//! to the placed artifact digest. Each observation is an immutable object;
//! the newest `observed_at_ms` of an instance wins, so a takeover never
//! moves health back. Status overlays a report onto apply-time health when
//! the digest still matches the deployed release, and a report older than
//! [`DEFAULT_MAX_AGE_MS`] as `unknown`. Serving health on the environment
//! object stays the apply-time value until soak reads observations.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::pb::sekai::Object;
use crate::software_executor::sanitize_diagnostic_text;

pub const HEALTH_OBSERVATION_SCHEMA: &str = "tenkai.instance-health.v1";
pub const DEFAULT_MAX_AGE_MS: i64 = 60_000;
pub const MAX_STDOUT_BYTES: usize = 64 * 1024;
pub const MAX_REPORTS: usize = 1024;
pub const MAX_CHECKS: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 512;
pub const MAX_AGE_PROPERTY: &str = "health_observation_max_age_ms";

/// One named check inside a probe's structured stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HealthCheck {
    pub name: String,
    pub state: HealthCheckState,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckState {
    Healthy,
    Repairing,
    Warning,
    Failing,
}

impl HealthCheckState {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "healthy" => Some(Self::Healthy),
            "repairing" => Some(Self::Repairing),
            "warning" => Some(Self::Warning),
            "failing" => Some(Self::Failing),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Repairing => "repairing",
            Self::Warning => "warning",
            Self::Failing => "failing",
        }
    }
}

/// One instance's latest health probe, as its runtime last saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthObservation {
    pub schema: String,
    pub environment: String,
    pub instance: String,
    pub artifact_digest: String,
    pub observed_at_ms: i64,
    pub state: HealthCheckState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<HealthCheck>,
}

impl HealthObservation {
    /// Serving label waves and soak already read: failing is `unhealthy`.
    pub fn serving_label(&self) -> &'static str {
        match self.state {
            HealthCheckState::Failing => "unhealthy",
            HealthCheckState::Healthy | HealthCheckState::Repairing | HealthCheckState::Warning => {
                "healthy"
            }
        }
    }

    pub fn status_at(&self, now_ms: i64, max_age_ms: i64) -> HealthStatus {
        if now_ms.saturating_sub(self.observed_at_ms) > max_age_ms {
            return HealthStatus {
                health: "unknown".into(),
                checks: Vec::new(),
            };
        }
        HealthStatus {
            health: self.serving_label().into(),
            checks: self
                .checks
                .iter()
                .filter(|check| check.state >= HealthCheckState::Warning)
                .cloned()
                .collect(),
        }
    }
}

/// What `status` shows of one instance's continuous observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HealthStatus {
    pub health: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<HealthCheck>,
}

/// Build an observation from a probe's exit and stdout.
pub fn from_probe(
    environment: &str,
    instance: &str,
    artifact_digest: &str,
    observed_at_ms: i64,
    exit_ok: bool,
    stdout: &[u8],
) -> HealthObservation {
    let truncated = stdout.len() > MAX_STDOUT_BYTES;
    let checks = if truncated {
        let mut checks = vec![HealthCheck {
            name: "truncated".into(),
            state: HealthCheckState::Warning,
            message: "probe stdout exceeded 64KiB; check messages were dropped".into(),
        }];
        if !exit_ok {
            checks.push(HealthCheck {
                name: "probe".into(),
                state: HealthCheckState::Failing,
                message: "probe exited non-zero".into(),
            });
        }
        checks
    } else {
        let mut checks = parse_structured_checks(stdout);
        if checks.is_empty() {
            checks.push(HealthCheck {
                name: "probe".into(),
                state: if exit_ok {
                    HealthCheckState::Healthy
                } else {
                    HealthCheckState::Failing
                },
                message: String::new(),
            });
        } else if !exit_ok
            && checks
                .iter()
                .all(|check| check.state < HealthCheckState::Failing)
        {
            if checks.len() >= MAX_CHECKS {
                checks.pop();
            }
            checks.push(HealthCheck {
                name: "probe".into(),
                state: HealthCheckState::Failing,
                message: "probe exited non-zero".into(),
            });
        }
        checks
    };
    let state = checks
        .iter()
        .map(|check| check.state)
        .max()
        .unwrap_or(HealthCheckState::Healthy);
    HealthObservation {
        schema: HEALTH_OBSERVATION_SCHEMA.into(),
        environment: environment.into(),
        instance: instance.into(),
        artifact_digest: artifact_digest.into(),
        observed_at_ms,
        state,
        checks,
    }
}

fn parse_structured_checks(stdout: &[u8]) -> Vec<HealthCheck> {
    let Ok(text) = std::str::from_utf8(stdout) else {
        return Vec::new();
    };
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    let mut checks = Vec::new();
    let mut overflow = false;
    for (name, body) in map {
        let Some(entry) = body.as_object() else {
            continue;
        };
        let Some(state) = entry
            .get("state")
            .and_then(|state| state.as_str())
            .and_then(HealthCheckState::parse)
        else {
            continue;
        };
        if crate::ontology::validate_identifier("check", name).is_err() {
            continue;
        }
        if checks.len() >= MAX_CHECKS {
            overflow = true;
            continue;
        }
        let message = entry
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or_default();
        let message = truncate_bytes(sanitize_diagnostic_text(message), MAX_MESSAGE_BYTES);
        checks.push(HealthCheck {
            name: name.clone(),
            state,
            message,
        });
    }
    if overflow {
        if checks.len() >= MAX_CHECKS {
            checks.pop();
        }
        checks.push(HealthCheck {
            name: "overflow".into(),
            state: HealthCheckState::Failing,
            message: "probe named more than 64 checks".into(),
        });
    }
    checks
}

fn truncate_bytes(text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn report_id(environment: &str, instance: &str, json: &str) -> String {
    format!(
        "tenkai:instance-health:{environment}:{instance}:{:x}",
        Sha256::digest(json.as_bytes())
    )
}

/// Admit `reports` for `environment`. Newest `observed_at_ms` of an instance
/// wins. Returns the instances whose report was stored.
pub async fn admit(
    ctx: &mut Ctx,
    environment: &str,
    reports: &[HealthObservation],
) -> Result<Vec<String>> {
    if reports.len() > MAX_REPORTS {
        bail!("a report carries at most {MAX_REPORTS} instance health observations");
    }
    let mut seen = std::collections::BTreeSet::new();
    for report in reports {
        if report.schema != HEALTH_OBSERVATION_SCHEMA {
            bail!(
                "health observation of {} is not a {HEALTH_OBSERVATION_SCHEMA} report",
                report.instance
            );
        }
        if report.environment != environment {
            bail!(
                "health observation of {} names environment {}, not {environment}",
                report.instance,
                report.environment
            );
        }
        crate::ontology::validate_identifier("instance", &report.instance)?;
        if report.observed_at_ms <= 0 {
            bail!(
                "health observation of {} is missing observed_at_ms",
                report.instance
            );
        }
        let now = crate::now_millis();
        if report.observed_at_ms
            > now.saturating_add(crate::signature_verification::SIGNED_AT_CLOCK_SKEW_MS)
        {
            bail!("health observation of {} is in the future", report.instance);
        }
        if report.artifact_digest.is_empty()
            || !report
                .artifact_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!(
                "health observation of {} is missing artifact_digest",
                report.instance
            );
        }
        if report.checks.len() > MAX_CHECKS {
            bail!(
                "health observation of {} carries more than {MAX_CHECKS} checks",
                report.instance
            );
        }
        for check in &report.checks {
            crate::ontology::validate_identifier("check", &check.name)?;
        }
        let derived = report
            .checks
            .iter()
            .map(|check| check.state)
            .max()
            .unwrap_or(HealthCheckState::Healthy);
        if report.state != derived {
            bail!(
                "health observation of {} state does not match its checks",
                report.instance
            );
        }
        if !seen.insert(report.instance.as_str()) {
            bail!(
                "the report carries two health observations of {}",
                report.instance
            );
        }
    }
    crate::environment::environment(ctx, environment).await?;
    let (stored_now, _) = load(ctx, environment).await?;
    let now = crate::now_millis();
    let mut stored = Vec::new();
    for report in reports {
        if stored_now
            .get(&report.instance)
            .is_some_and(|current| current.observed_at_ms >= report.observed_at_ms)
        {
            continue;
        }
        let mut report = report.clone();
        for check in &mut report.checks {
            check.message =
                truncate_bytes(sanitize_diagnostic_text(&check.message), MAX_MESSAGE_BYTES);
        }
        let json = serde_json::to_string(&report)?;
        let id = report_id(environment, &report.instance, &json);
        if ctx.get(&id).await?.is_some() {
            continue;
        }
        ctx.put(Object {
            id,
            kind: crate::ontology::KIND_INSTANCE_HEALTH.into(),
            name: format!("instance health of {} in {environment}", report.instance),
            namespace: crate::ontology::NS.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("environment".into(), environment.into()),
                ("instance".into(), report.instance.clone()),
                ("report".into(), json),
                ("observed_at_ms".into(), report.observed_at_ms.to_string()),
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

type StoredOrder = (i64, String);

async fn load(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<(BTreeMap<String, HealthObservation>, Vec<String>)> {
    let objects = ctx
        .find_by_property(
            crate::ontology::KIND_INSTANCE_HEALTH,
            "environment",
            environment,
        )
        .await?;
    let mut best: BTreeMap<String, (HealthObservation, StoredOrder)> = BTreeMap::new();
    let mut superseded = Vec::new();
    for object in objects {
        let Some(json) = object.properties.get("report") else {
            continue;
        };
        let report: HealthObservation = serde_json::from_str(json)
            .with_context(|| format!("parsing the health observation {}", object.id))?;
        if report.environment != environment
            || object.properties.get("instance") != Some(&report.instance)
        {
            bail!(
                "the health observation {} names another instance",
                object.id
            );
        }
        let key = (report.observed_at_ms, object.id.clone());
        match best.get(&report.instance) {
            Some((_, current)) if *current >= key => superseded.push(key.1),
            _ => {
                if let Some((_, (_, id))) = best.insert(report.instance.clone(), (report, key)) {
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

/// The newest observation of each instance in `environment`.
pub async fn reported(
    ctx: &mut Ctx,
    environment: &str,
) -> Result<BTreeMap<String, HealthObservation>> {
    Ok(load(ctx, environment).await?.0)
}

pub fn max_age_ms(env: &Object) -> i64 {
    env.properties
        .get(MAX_AGE_PROPERTY)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_AGE_MS)
}

/// Overlay apply-time health with a fresh observation, or `unknown` when stale.
pub fn overlay(
    apply_health: Option<String>,
    observation: Option<&HealthObservation>,
    deployed_digest: Option<&str>,
    now_ms: i64,
    max_age_ms: i64,
) -> (Option<String>, Vec<HealthCheck>) {
    let Some(observation) = observation else {
        return (apply_health, Vec::new());
    };
    if deployed_digest != Some(observation.artifact_digest.as_str()) {
        return (apply_health, Vec::new());
    }
    let status = observation.status_at(now_ms, max_age_ms);
    (Some(status.health), status.checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;

    const DIGEST: &str = "ab";

    fn observation(at: i64, state: HealthCheckState) -> HealthObservation {
        HealthObservation {
            schema: HEALTH_OBSERVATION_SCHEMA.into(),
            environment: "prod".into(),
            instance: "api".into(),
            artifact_digest: DIGEST.into(),
            observed_at_ms: at,
            state,
            checks: vec![HealthCheck {
                name: "probe".into(),
                state,
                message: String::new(),
            }],
        }
    }

    fn probe(at: i64, exit_ok: bool, stdout: &[u8]) -> HealthObservation {
        from_probe("prod", "api", DIGEST, at, exit_ok, stdout)
    }

    #[test]
    fn structured_stdout_picks_the_worst_check_and_redacts() {
        let stdout = br#"{"http":{"state":"healthy","message":"ok"},"disk":{"state":"failing","message":"token=secret-value"}}"#;
        let report = probe(10, true, stdout);
        assert_eq!(report.state, HealthCheckState::Failing);
        let disk = report
            .checks
            .iter()
            .find(|check| check.name == "disk")
            .unwrap();
        assert_eq!(disk.state, HealthCheckState::Failing);
        assert!(!disk.message.contains("secret-value"), "{}", disk.message);
    }

    #[test]
    fn a_long_multibyte_message_truncates_on_a_character_boundary() {
        let message = "€".repeat(200);
        let stdout = format!(r#"{{"disk":{{"state":"warning","message":"{message}"}}}}"#);
        let report = probe(10, true, stdout.as_bytes());
        let disk = report
            .checks
            .iter()
            .find(|check| check.name == "disk")
            .unwrap();
        assert!(disk.message.len() <= MAX_MESSAGE_BYTES);
        assert!(disk.message.is_char_boundary(disk.message.len()));
        assert!(disk.message.starts_with("€"));
    }

    #[test]
    fn oversized_stdout_adds_the_truncation_check() {
        let stdout = vec![b'x'; MAX_STDOUT_BYTES + 8];
        let report = probe(10, true, &stdout);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "truncated" && check.state == HealthCheckState::Warning)
        );
        assert_eq!(report.checks.len(), 1);
        let killed = probe(10, false, &stdout);
        assert_eq!(killed.state, HealthCheckState::Failing);
        assert_eq!(killed.serving_label(), "unhealthy");
    }

    #[test]
    fn extra_named_checks_are_a_failing_overflow() {
        let mut body = serde_json::Map::new();
        for i in 0..=MAX_CHECKS {
            body.insert(format!("c{i:02}"), serde_json::json!({"state": "healthy"}));
        }
        let stdout = serde_json::Value::Object(body).to_string();
        let report = probe(10, true, stdout.as_bytes());
        assert_eq!(report.state, HealthCheckState::Failing);
        assert!(report.checks.len() <= MAX_CHECKS);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "overflow" && check.state == HealthCheckState::Failing)
        );
    }

    #[test]
    fn a_full_check_list_still_records_a_failed_exit() {
        let mut body = serde_json::Map::new();
        for i in 0..MAX_CHECKS {
            body.insert(format!("c{i:02}"), serde_json::json!({"state": "healthy"}));
        }
        let stdout = serde_json::Value::Object(body).to_string();
        let report = probe(10, false, stdout.as_bytes());
        assert_eq!(report.state, HealthCheckState::Failing);
        assert!(report.checks.len() <= MAX_CHECKS);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "probe" && check.state == HealthCheckState::Failing)
        );
    }

    #[test]
    fn a_plain_exit_code_is_the_only_check() {
        let healthy = probe(10, true, b"");
        assert_eq!(healthy.state, HealthCheckState::Healthy);
        let failing = probe(10, false, b"boom");
        assert_eq!(failing.state, HealthCheckState::Failing);
        assert_eq!(failing.serving_label(), "unhealthy");
    }

    #[test]
    fn a_stale_report_reads_unknown() {
        let report = observation(1, HealthCheckState::Healthy);
        let status = report.status_at(DEFAULT_MAX_AGE_MS + 2, DEFAULT_MAX_AGE_MS);
        assert_eq!(status.health, "unknown");
        assert!(status.checks.is_empty());
    }

    #[test]
    fn overlay_uses_the_observation_or_keeps_apply_health() {
        let report = observation(10, HealthCheckState::Failing);
        let (health, checks) = overlay(
            Some("healthy".into()),
            Some(&report),
            Some(DIGEST),
            11,
            DEFAULT_MAX_AGE_MS,
        );
        assert_eq!(health.as_deref(), Some("unhealthy"));
        assert_eq!(checks.len(), 1);
        let (health, checks) = overlay(
            Some("healthy".into()),
            None,
            Some(DIGEST),
            11,
            DEFAULT_MAX_AGE_MS,
        );
        assert_eq!(health.as_deref(), Some("healthy"));
        assert!(checks.is_empty());
        let stale = observation(1, HealthCheckState::Healthy);
        let (health, checks) = overlay(
            Some("healthy".into()),
            Some(&stale),
            Some(DIGEST),
            DEFAULT_MAX_AGE_MS + 2,
            DEFAULT_MAX_AGE_MS,
        );
        assert_eq!(health.as_deref(), Some("unknown"));
        assert!(checks.is_empty());
        let (health, checks) = overlay(
            Some("healthy".into()),
            Some(&report),
            Some("other"),
            11,
            DEFAULT_MAX_AGE_MS,
        );
        assert_eq!(health.as_deref(), Some("healthy"));
        assert!(checks.is_empty());
    }

    #[tokio::test]
    async fn a_future_report_is_refused() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-instance-health-future-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "runtime")
            .await
            .unwrap();
        // admit() reads now again; +1ms lost the race on a loaded runner (#1270).
        let future = observation(
            crate::now_millis() + crate::signature_verification::SIGNED_AT_CLOCK_SKEW_MS + 60_000,
            HealthCheckState::Healthy,
        );
        let error = admit(&mut ctx, "prod", std::slice::from_ref(&future))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("future"), "{error}");
    }

    #[tokio::test]
    async fn a_late_report_never_moves_health_back() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-instance-health-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "runtime")
            .await
            .unwrap();

        let first = observation(20, HealthCheckState::Failing);
        let older = observation(10, HealthCheckState::Healthy);
        assert_eq!(
            admit(&mut ctx, "prod", std::slice::from_ref(&first))
                .await
                .unwrap(),
            ["api"]
        );
        assert!(
            admit(&mut ctx, "prod", std::slice::from_ref(&older))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reported(&mut ctx, "prod").await.unwrap()["api"].state,
            HealthCheckState::Failing
        );
    }

    #[tokio::test]
    async fn a_mismatched_or_invalid_check_is_refused() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-instance-health-admit-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "runtime")
            .await
            .unwrap();

        let mut mismatched = observation(30, HealthCheckState::Healthy);
        mismatched.checks[0].state = HealthCheckState::Failing;
        let error = admit(&mut ctx, "prod", std::slice::from_ref(&mismatched))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match its checks"), "{error}");

        let mut invalid = observation(31, HealthCheckState::Healthy);
        invalid.checks[0].name = "../escape".into();
        let error = admit(&mut ctx, "prod", std::slice::from_ref(&invalid))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("check"), "{error}");
    }

    #[tokio::test]
    async fn admit_redacts_check_messages() {
        let database = std::env::temp_dir().join(format!(
            "tenkai-instance-health-redact-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "runtime")
            .await
            .unwrap();
        let mut report = observation(40, HealthCheckState::Failing);
        report.checks[0].message = "token=secret-value".into();
        admit(&mut ctx, "prod", std::slice::from_ref(&report))
            .await
            .unwrap();
        let stored = &reported(&mut ctx, "prod").await.unwrap()["api"];
        assert!(
            !stored.checks[0].message.contains("secret-value"),
            "{}",
            stored.checks[0].message
        );
    }
}

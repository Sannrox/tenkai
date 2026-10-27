//! Post-apply health and SLO gates (#590).
//!
//! Releases and channels may declare Prometheus-compatible instant queries with
//! thresholds and a bake window. After each successful non-rollback Plan Step
//! the executor evaluates those gates. A failing gate halts the rollout, or
//! restores a previously signed release when `on_fail = "rollback"`. Releases
//! without SLO gates keep today's apply behavior. Evidence shares the same
//! binding shape as model-release canary records (ADR 0032 / #584).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::apply::{Outcome, StepOutcomeStatus};
use crate::client::Ctx;
use crate::manifest::{GateFailPolicy, GateSection, SloComparator, SloGate};
use crate::ontology::{KIND_HEALTH_GATE_EVIDENCE, NS, channel_id, env_id, health_gate_evidence_id};
use crate::pb::sekai::Object;
use crate::plan::{Action, Plan, Step};
use crate::providers::{
    EvidenceBinding, PROVIDER_CONTRACT_VERSION, ProviderEvent, enqueue_optional_event,
};

pub const HEALTH_GATE_EVIDENCE_SCHEMA: &str = "tenkai.health_gate_evidence.v1";
pub const HEALTH_GATE_PROVIDER_KIND: &str = "health_gate";
pub const CHANNEL_HEALTH_GATES_PROPERTY: &str = "health_gates";

/// Bound for one metrics sample batch. Blocking `query_instant` work that
/// exceeds this is treated as unavailable so the bake window cannot hold the
/// environment apply lease indefinitely.
pub const METRICS_SAMPLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Instant-vector source for Prometheus-compatible queries.
///
/// `query_instant` must return in bounded time. Hosts wrapping HTTP clients
/// should apply their own request timeout; Tenkai converts samples that exceed
/// [`METRICS_SAMPLE_TIMEOUT`] into unavailable evidence.
pub trait HealthMetricsSource: Send + Sync {
    fn query_instant(&self, query: &str) -> Result<f64>;
}

/// Deterministic in-memory source for tests and host injection.
#[derive(Debug, Default)]
pub struct FakeMetricsSource {
    values: BTreeMap<String, f64>,
    sequences: Mutex<BTreeMap<String, VecDeque<f64>>>,
}

impl FakeMetricsSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_value(mut self, query: impl Into<String>, value: f64) -> Self {
        self.values.insert(query.into(), value);
        self
    }

    pub fn with_samples(
        self,
        query: impl Into<String>,
        samples: impl IntoIterator<Item = f64>,
    ) -> Self {
        self.sequences
            .lock()
            .expect("fake metrics mutex")
            .insert(query.into(), samples.into_iter().collect());
        self
    }
}

impl HealthMetricsSource for FakeMetricsSource {
    fn query_instant(&self, query: &str) -> Result<f64> {
        if let Some(value) = self
            .sequences
            .lock()
            .expect("fake metrics mutex")
            .get_mut(query)
            .and_then(VecDeque::pop_front)
        {
            return Ok(value);
        }
        self.values.get(query).copied().with_context(|| {
            format!("fake metrics source has no instant sample for query {query:?}")
        })
    }
}

/// Effective SLO contract after merging release and channel declarations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HealthGateSpec {
    #[serde(default)]
    pub slo: Vec<SloGate>,
    #[serde(default)]
    pub bake_window_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_fail: Option<GateFailPolicy>,
}

impl HealthGateSpec {
    pub fn is_empty(&self) -> bool {
        self.slo.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        for gate in &self.slo {
            crate::ontology::validate_identifier("slo gate name", &gate.name)?;
            if !names.insert(gate.name.as_str()) {
                bail!("duplicate SLO gate name {}", gate.name);
            }
            if gate.query.trim().is_empty() {
                bail!("SLO gate {} has an empty Prometheus query", gate.name);
            }
            if !gate.threshold.is_finite() {
                bail!("SLO gate {} threshold must be finite", gate.name);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    Fail,
    Unavailable,
}

impl GateVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSample {
    pub name: String,
    pub query: String,
    pub op: SloComparator,
    pub threshold: f64,
    pub value: Option<f64>,
    pub verdict: GateVerdict,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthGateEvidence {
    pub schema: String,
    pub plan_id: String,
    pub step_id: String,
    pub release_id: String,
    pub release_digest: String,
    pub environment: String,
    pub bake_window_seconds: u32,
    pub on_fail: GateFailPolicy,
    pub overall: GateVerdict,
    pub gates: Vec<GateSample>,
    pub observed_at: i64,
}

impl HealthGateEvidence {
    pub fn passed(&self) -> bool {
        self.overall == GateVerdict::Pass
    }

    pub fn summary(&self) -> String {
        let gates = self
            .gates
            .iter()
            .map(|gate| match (gate.verdict, gate.value) {
                (GateVerdict::Pass, Some(value)) | (GateVerdict::Fail, Some(value)) => {
                    format!(
                        "{}={value} {} {} => {}",
                        gate.name,
                        gate.op.as_str(),
                        gate.threshold,
                        gate.verdict.as_str()
                    )
                }
                _ => format!(
                    "{} => {}{}",
                    gate.name,
                    gate.verdict.as_str(),
                    if gate.detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", gate.detail)
                    }
                ),
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "health/SLO gate {} for {} (bake {}s, on_fail={}): {gates}",
            self.overall.as_str(),
            self.release_id,
            self.bake_window_seconds,
            self.on_fail.as_str()
        )
    }
}

/// Merge release-manifest gates with an optional channel overlay.
///
/// Channel gates of the same name replace the release gate. A non-zero channel
/// bake window and an explicit channel fail policy override the release values.
pub fn merge_specs(release: &GateSection, channel: Option<&HealthGateSpec>) -> HealthGateSpec {
    let mut by_name: BTreeMap<String, SloGate> = BTreeMap::new();
    for gate in &release.slo {
        by_name.insert(gate.name.clone(), gate.clone());
    }
    let mut spec = HealthGateSpec {
        bake_window_seconds: release.bake_window_seconds,
        on_fail: Some(release.on_fail),
        slo: Vec::new(),
    };
    if let Some(channel) = channel {
        for gate in &channel.slo {
            by_name.insert(gate.name.clone(), gate.clone());
        }
        if channel.bake_window_seconds > 0 {
            spec.bake_window_seconds = channel.bake_window_seconds;
        }
        if let Some(policy) = channel.on_fail {
            spec.on_fail = Some(policy);
        }
    }
    spec.slo = by_name.into_values().collect();
    spec
}

pub fn evaluate(
    spec: &HealthGateSpec,
    source: Option<&dyn HealthMetricsSource>,
    plan: &Plan,
    step: &Step,
    observed_at: i64,
) -> HealthGateEvidence {
    let mut gates = Vec::with_capacity(spec.slo.len());
    for gate in &spec.slo {
        let sample = match source {
            None => GateSample {
                name: gate.name.clone(),
                query: gate.query.clone(),
                op: gate.op,
                threshold: gate.threshold,
                value: None,
                verdict: GateVerdict::Unavailable,
                detail: "no health metrics source is configured".into(),
            },
            Some(source) => match source.query_instant(&gate.query) {
                Ok(value) if value.is_finite() => GateSample {
                    name: gate.name.clone(),
                    query: gate.query.clone(),
                    op: gate.op,
                    threshold: gate.threshold,
                    value: Some(value),
                    verdict: if compare(gate.op, value, gate.threshold) {
                        GateVerdict::Pass
                    } else {
                        GateVerdict::Fail
                    },
                    detail: String::new(),
                },
                Ok(value) => GateSample {
                    name: gate.name.clone(),
                    query: gate.query.clone(),
                    op: gate.op,
                    threshold: gate.threshold,
                    value: None,
                    verdict: GateVerdict::Unavailable,
                    detail: format!("metric sample is not finite ({value})"),
                },
                Err(error) => GateSample {
                    name: gate.name.clone(),
                    query: gate.query.clone(),
                    op: gate.op,
                    threshold: gate.threshold,
                    value: None,
                    verdict: GateVerdict::Unavailable,
                    detail: error.to_string(),
                },
            },
        };
        gates.push(sample);
    }
    let overall = if gates.iter().any(|gate| gate.verdict == GateVerdict::Fail) {
        GateVerdict::Fail
    } else if gates
        .iter()
        .any(|gate| gate.verdict == GateVerdict::Unavailable)
    {
        GateVerdict::Unavailable
    } else {
        GateVerdict::Pass
    };
    HealthGateEvidence {
        schema: HEALTH_GATE_EVIDENCE_SCHEMA.into(),
        plan_id: plan.id.clone(),
        step_id: step.id.clone(),
        release_id: step.release_id.clone(),
        release_digest: step.release_digest.clone(),
        environment: plan.environment.clone(),
        bake_window_seconds: spec.bake_window_seconds,
        on_fail: spec.on_fail.unwrap_or_default(),
        overall,
        gates,
        observed_at,
    }
}

fn compare(op: SloComparator, value: f64, threshold: f64) -> bool {
    match op {
        SloComparator::Lt => value < threshold,
        SloComparator::Lte => value <= threshold,
        SloComparator::Gt => value > threshold,
        SloComparator::Gte => value >= threshold,
    }
}

pub async fn resolve_spec(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
    release: &GateSection,
) -> Result<HealthGateSpec> {
    let channel = load_channel_overlay(ctx, environment, product).await?;
    let spec = merge_specs(release, channel.as_ref());
    spec.validate()?;
    Ok(spec)
}

async fn load_channel_overlay(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
) -> Result<Option<HealthGateSpec>> {
    let Some(env) = ctx.get(&env_id(environment)).await? else {
        return Ok(None);
    };
    let channels = ctx
        .linked(&env.id, crate::ontology::REL_SUBSCRIBES, "out")
        .await?;
    let Some(channel) = channels
        .into_iter()
        .find(|channel| channel.properties.get("product").map(String::as_str) == Some(product))
    else {
        return Ok(None);
    };
    let Some(raw) = channel.properties.get(CHANNEL_HEALTH_GATES_PROPERTY) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let spec: HealthGateSpec = serde_json::from_str(raw).with_context(|| {
        format!(
            "parsing {} on {}",
            CHANNEL_HEALTH_GATES_PROPERTY, channel.id
        )
    })?;
    spec.validate()?;
    Ok(Some(spec))
}

/// Attach channel-level SLO gates without changing ChannelRecord schema.
pub async fn set_channel_health_gates(
    ctx: &mut Ctx,
    product: &str,
    channel: &str,
    spec: &HealthGateSpec,
) -> Result<()> {
    spec.validate()?;
    let owner = format!("health-gates:{product}/{channel}:{}", crate::now_millis());
    let lock = crate::canary::claim_promotion_lock(ctx, product, channel, &owner).await?;
    let result = async {
        crate::canary::confirm_promotion_lock(ctx, &lock).await?;
        let id = channel_id(product, channel);
        let mut object = ctx
            .get(&id)
            .await?
            .with_context(|| format!("channel {product}/{channel} does not exist"))?;
        object.properties.insert(
            CHANNEL_HEALTH_GATES_PROPERTY.into(),
            serde_json::to_string(spec)?,
        );
        ctx.put(object).await?;
        Ok(())
    }
    .await;
    let unlock = crate::canary::release_promotion_lock(ctx, &lock).await;
    match (result, unlock) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(unlock)) => {
            Err(error.context(format!("releasing promotion lock also failed: {unlock}")))
        }
        (Ok(()), Err(error)) => Err(error.context("releasing promotion lock failed")),
    }
}

pub async fn persist_evidence(
    ctx: &mut Ctx,
    plan: &Plan,
    evidence: &HealthGateEvidence,
) -> Result<Object> {
    let object = evidence_object(plan, evidence)?;
    let stored = ctx.put(object).await?;
    enqueue_health_gate_event(ctx, plan, evidence);
    Ok(stored)
}

fn evidence_object(plan: &Plan, evidence: &HealthGateEvidence) -> Result<Object> {
    let json = serde_json::to_string(evidence)?;
    Ok(Object {
        id: health_gate_evidence_id(&plan.id, &evidence.step_id),
        kind: KIND_HEALTH_GATE_EVIDENCE.into(),
        name: format!("health-gate-{}", evidence.step_id),
        namespace: NS.into(),
        properties: [
            ("schema".into(), evidence.schema.clone()),
            ("plan_id".into(), evidence.plan_id.clone()),
            ("step_id".into(), evidence.step_id.clone()),
            ("release_id".into(), evidence.release_id.clone()),
            ("release_digest".into(), evidence.release_digest.clone()),
            ("environment".into(), evidence.environment.clone()),
            ("verdict".into(), evidence.overall.as_str().into()),
            ("evidence".into(), json),
            ("observed_at".into(), evidence.observed_at.to_string()),
        ]
        .into_iter()
        .collect(),
        ..Object::default()
    })
}

fn enqueue_health_gate_event(ctx: &mut Ctx, plan: &Plan, evidence: &HealthGateEvidence) {
    let Some(store) = ctx.embedded_arc() else {
        return;
    };
    let Ok(payload) = serde_json::to_string(evidence) else {
        return;
    };
    let binding = EvidenceBinding {
        contract_version: PROVIDER_CONTRACT_VERSION,
        release_digest: evidence.release_digest.clone(),
        plan_digest: plan.content_id.clone(),
        configuration_digest: digest_bytes(payload.as_bytes()),
        environment_id: evidence.environment.clone(),
    };
    let event = ProviderEvent {
        id: health_gate_evidence_id(&plan.id, &evidence.step_id),
        binding,
        payload_json: payload,
        collected_at_ms: None,
        source_sequence: None,
    };
    let _ = enqueue_optional_event(
        store.as_ref(),
        HEALTH_GATE_PROVIDER_KIND,
        &event,
        evidence.observed_at,
    );
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn emit_telemetry(plan: &Plan, evidence: &HealthGateEvidence) {
    let mut attrs =
        crate::telemetry::DeliveryAttributes::from_plan(crate::telemetry::Operation::Health, plan);
    attrs.outcome = Some(evidence.overall.as_str().into());
    attrs.release_digest = Some(evidence.release_digest.clone());
    let mut span = crate::telemetry::start_span("tenkai.health_gate", &attrs);
    if evidence.passed() {
        span.succeed();
        crate::telemetry::record_metric(crate::telemetry::METRIC_HEALTH_GATE_OUTCOME, 1.0, &attrs);
    } else {
        span.fail();
        crate::telemetry::record_metric(crate::telemetry::METRIC_HEALTH_GATE_OUTCOME, 0.0, &attrs);
    }
}

pub(crate) async fn step_requires_slo_evaluation(
    ctx: &mut Ctx,
    environment: &str,
    step: &Step,
) -> Result<bool> {
    match step.action {
        Action::Rollback => Ok(false),
        Action::Restart => restart_retries_failed_health_gate(ctx, environment, step).await,
        _ => Ok(true),
    }
}

async fn restart_retries_failed_health_gate(
    ctx: &mut Ctx,
    environment: &str,
    step: &Step,
) -> Result<bool> {
    let env = crate::environment::environment(ctx, environment).await?;
    Ok(env
        .properties
        .get(&format!("failed_target.{}", step.product))
        == Some(&step.release_id))
}

pub async fn previous_release_is_auto_rollback_target(
    ctx: &mut Ctx,
    environment: &str,
    step: &Step,
) -> Result<bool> {
    let Some(pin) = step.restore.as_ref() else {
        return Ok(false);
    };
    Ok(
        crate::catalog::load_deployable_snapshot(ctx, &pin.release_id, environment)
            .await
            .is_ok(),
    )
}

pub async fn load_release_gate_section(
    ctx: &mut Ctx,
    release_id: &str,
    expected_digest: &str,
) -> Result<GateSection> {
    let object = ctx.get(release_id).await?.with_context(|| {
        format!("release {release_id} is missing during health-gate evaluation")
    })?;
    let raw = object
        .properties
        .get("manifest")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("release {release_id} has no stored manifest"))?;
    let stored_digest = object.properties.get("digest").cloned().unwrap_or_default();
    let actual_digest = crate::manifest::digest(raw);
    if stored_digest != expected_digest || actual_digest != expected_digest {
        bail!(
            "release {release_id} manifest digest {actual_digest} does not match plan pin {expected_digest}"
        );
    }
    Ok(crate::manifest::parse_raw(raw)?.gate)
}

fn unavailable_timeout(spec: &HealthGateSpec, plan: &Plan, step: &Step) -> HealthGateEvidence {
    let detail = format!(
        "metrics sample exceeded {}s bound",
        METRICS_SAMPLE_TIMEOUT.as_secs()
    );
    HealthGateEvidence {
        schema: HEALTH_GATE_EVIDENCE_SCHEMA.into(),
        plan_id: plan.id.clone(),
        step_id: step.id.clone(),
        release_id: step.release_id.clone(),
        release_digest: step.release_digest.clone(),
        environment: plan.environment.clone(),
        bake_window_seconds: spec.bake_window_seconds,
        on_fail: spec.on_fail.unwrap_or_default(),
        overall: GateVerdict::Unavailable,
        gates: spec
            .slo
            .iter()
            .map(|gate| GateSample {
                name: gate.name.clone(),
                query: gate.query.clone(),
                op: gate.op,
                threshold: gate.threshold,
                value: None,
                verdict: GateVerdict::Unavailable,
                detail: detail.clone(),
            })
            .collect(),
        observed_at: crate::now_millis(),
    }
}

async fn sample_with_lease(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    spec: HealthGateSpec,
    source: Option<Arc<dyn HealthMetricsSource>>,
    plan: Plan,
    step: Step,
) -> Result<HealthGateEvidence> {
    crate::apply::refresh_environment_lease(ctx, lease)
        .await
        .context("refreshing environment apply lease before SLO sampling")?;
    let timeout_spec = spec.clone();
    let timeout_plan = plan.clone();
    let timeout_step = step.clone();
    let mut work = tokio::task::spawn_blocking(move || {
        evaluate(&spec, source.as_deref(), &plan, &step, crate::now_millis())
    });
    let mut refresh = tokio::time::interval(Duration::from_secs(10));
    refresh.tick().await;
    let timeout = tokio::time::sleep(METRICS_SAMPLE_TIMEOUT);
    tokio::pin!(timeout);
    let evidence = loop {
        tokio::select! {
            joined = &mut work => {
                break joined.context("SLO metrics sampling task failed")?;
            }
            _ = &mut timeout => {
                // Tokio cannot cancel `spawn_blocking` work. The source
                // contract requires `query_instant` to return in bounded time;
                // this deadline fail-closes apply and detaches any remaining
                // blocking query rather than holding the environment lease.
                break unavailable_timeout(&timeout_spec, &timeout_plan, &timeout_step);
            }
            _ = refresh.tick() => crate::apply::refresh_environment_lease(ctx, lease)
                .await
                .context("refreshing environment apply lease during SLO sampling")?,
        }
    };
    crate::apply::refresh_environment_lease(ctx, lease)
        .await
        .context("refreshing environment apply lease after SLO sampling")?;
    Ok(evidence)
}

/// Evaluate SLO gates from the admitted, digest-bound release after activation.
///
/// Rollback steps never re-enter this path, so a gate-triggered restore cannot
/// loop (#549). Automatic rollback uses the plan's restore pin and the same
/// signed-release admission as #562.
pub(crate) async fn decide_after_success(
    ctx: &mut Ctx,
    lease: &crate::apply::EnvironmentLease,
    plan: &Plan,
    step: &Step,
    skip_gates: bool,
    release_gate: &GateSection,
) -> Result<Option<HealthGateDecision>> {
    if skip_gates || !step_requires_slo_evaluation(ctx, &plan.environment, step).await? {
        return Ok(None);
    }
    let spec = resolve_spec(ctx, &plan.environment, &step.product, release_gate).await?;
    if spec.is_empty() {
        return Ok(None);
    }
    let source = ctx.health_metrics();
    let deadline = crate::now_millis()
        .saturating_add(i64::from(spec.bake_window_seconds).saturating_mul(1000));
    let evidence = loop {
        let sample = sample_with_lease(
            ctx,
            lease,
            spec.clone(),
            source.clone(),
            plan.clone(),
            step.clone(),
        )
        .await?;
        if !sample.passed() || spec.bake_window_seconds == 0 {
            break sample;
        }
        let now = crate::now_millis();
        if now >= deadline {
            break sample;
        }
        let sleep_ms = u64::try_from(deadline - now).unwrap_or(0).min(1_000);
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms.max(1))).await;
    };
    persist_evidence(ctx, plan, &evidence).await?;
    emit_telemetry(plan, &evidence);
    if evidence.passed() {
        return Ok(None);
    }
    let mut action = spec.on_fail.unwrap_or_default();
    if action == GateFailPolicy::Rollback
        && !previous_release_is_auto_rollback_target(ctx, &plan.environment, step).await?
    {
        action = GateFailPolicy::Halt;
    }
    Ok(Some(HealthGateDecision { evidence, action }))
}

#[derive(Debug, Clone)]
pub struct HealthGateDecision {
    pub evidence: HealthGateEvidence,
    pub action: GateFailPolicy,
}

impl HealthGateDecision {
    pub fn halted_outcome(&self, step: &Step) -> Outcome {
        Outcome::new(
            step.clone(),
            StepOutcomeStatus::Failed,
            self.evidence.summary(),
        )
    }
}

pub fn source_arc(source: impl HealthMetricsSource + 'static) -> Arc<dyn HealthMetricsSource> {
    Arc::new(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{PlanState, ReleasePin};

    fn step(action: Action) -> Step {
        Step {
            id: "step-1".into(),
            order: 0,
            product: "api".into(),
            action,
            from: Some("1.0.0".into()),
            to: "1.1.0".into(),
            release_id: "tenkai:release:api@1.1.0".into(),
            release_digest: "sha256:aaaa".into(),
            artifact_digest: "sha256:bbbb".into(),
            workdir: "/tmp".into(),
            restore: Some(ReleasePin {
                release_id: "tenkai:release:api@1.0.0".into(),
                digest: "sha256:cccc".into(),
                artifact_digest: "sha256:dddd".into(),
                workdir: "/tmp".into(),
            }),
        }
    }

    fn plan() -> Plan {
        Plan {
            format_version: 1,
            id: "tenkai:plan:local:1:content".into(),
            content_id: "content".into(),
            environment: "local".into(),
            created_at: 1,
            inputs: Vec::new(),
            steps: vec![step(Action::Upgrade)],
            state: PlanState::Running,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        }
    }

    fn spec(on_fail: GateFailPolicy) -> HealthGateSpec {
        HealthGateSpec {
            slo: vec![SloGate {
                name: "error_rate".into(),
                query: "error_rate".into(),
                op: SloComparator::Lte,
                threshold: 0.01,
            }],
            bake_window_seconds: 30,
            on_fail: Some(on_fail),
        }
    }

    #[test]
    fn passing_gate_continues() {
        let source = FakeMetricsSource::new().with_value("error_rate", 0.001);
        let evidence = evaluate(
            &spec(GateFailPolicy::Halt),
            Some(&source),
            &plan(),
            &step(Action::Upgrade),
            10,
        );
        assert!(evidence.passed());
        assert_eq!(evidence.gates[0].value, Some(0.001));
        assert_eq!(evidence.gates[0].verdict, GateVerdict::Pass);
        assert!(evidence.summary().contains("error_rate=0.001"));
    }

    #[test]
    fn failing_gate_halts_within_bake_window() {
        let source = FakeMetricsSource::new().with_value("error_rate", 0.5);
        let spec = spec(GateFailPolicy::Halt);
        let evidence = evaluate(&spec, Some(&source), &plan(), &step(Action::Upgrade), 10);
        assert_eq!(evidence.overall, GateVerdict::Fail);
        assert_eq!(evidence.bake_window_seconds, 30);
        assert!(!evidence.passed());
    }

    #[test]
    fn non_finite_sample_fails_closed() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let source = FakeMetricsSource::new().with_value("error_rate", value);
            let evidence = evaluate(
                &spec(GateFailPolicy::Halt),
                Some(&source),
                &plan(),
                &step(Action::Upgrade),
                10,
            );
            assert_eq!(evidence.overall, GateVerdict::Unavailable, "{value}");
            assert!(
                evidence.gates[0].detail.contains("not finite"),
                "{}",
                evidence.gates[0].detail
            );
            assert_eq!(evidence.gates[0].value, None);
        }
    }

    #[test]
    fn missing_source_fails_closed() {
        let evidence = evaluate(
            &spec(GateFailPolicy::Halt),
            None,
            &plan(),
            &step(Action::Upgrade),
            10,
        );
        assert_eq!(evidence.overall, GateVerdict::Unavailable);
        assert!(
            evidence.gates[0]
                .detail
                .contains("no health metrics source")
        );
    }

    #[test]
    fn channel_gates_override_release_names() {
        let release = GateSection {
            eval_suite: None,
            slo: vec![SloGate {
                name: "error_rate".into(),
                query: "release_query".into(),
                op: SloComparator::Lte,
                threshold: 0.05,
            }],
            bake_window_seconds: 5,
            on_fail: GateFailPolicy::Halt,
        };
        let channel = HealthGateSpec {
            slo: vec![SloGate {
                name: "error_rate".into(),
                query: "channel_query".into(),
                op: SloComparator::Lte,
                threshold: 0.01,
            }],
            bake_window_seconds: 15,
            on_fail: Some(GateFailPolicy::Rollback),
        };
        let merged = merge_specs(&release, Some(&channel));
        assert_eq!(merged.slo[0].query, "channel_query");
        assert_eq!(merged.bake_window_seconds, 15);
        assert_eq!(merged.on_fail, Some(GateFailPolicy::Rollback));
    }

    #[test]
    fn omitted_channel_on_fail_keeps_release_policy() {
        let release = GateSection {
            eval_suite: None,
            slo: vec![SloGate {
                name: "error_rate".into(),
                query: "release_query".into(),
                op: SloComparator::Lte,
                threshold: 0.05,
            }],
            bake_window_seconds: 5,
            on_fail: GateFailPolicy::Rollback,
        };
        let channel = HealthGateSpec {
            slo: vec![SloGate {
                name: "latency".into(),
                query: "p99".into(),
                op: SloComparator::Lte,
                threshold: 200.0,
            }],
            bake_window_seconds: 0,
            on_fail: None,
        };
        let merged = merge_specs(&release, Some(&channel));
        assert_eq!(merged.on_fail, Some(GateFailPolicy::Rollback));
        assert_eq!(merged.slo.len(), 2);
    }

    #[test]
    fn empty_spec_is_additive() {
        assert!(HealthGateSpec::default().is_empty());
        assert!(merge_specs(&GateSection::default(), None).is_empty());
    }

    async fn publish_software(ctx: &mut Ctx, root: &std::path::Path, version: &str, gate: &str) {
        std::fs::write(
            root.join("tenkai.toml"),
            format!(
                "[product]\nname = \"slo-demo\"\nversion = \"{version}\"\n\n[deploy]\ninstall = \"true\"\n{gate}"
            ),
        )
        .unwrap();
        crate::catalog::publish(
            ctx,
            &root.join("tenkai.toml"),
            &crate::catalog::PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    fn apply_options() -> crate::apply::ExecutionOptions<'static> {
        crate::apply::ExecutionOptions {
            skip_gates: false,
            emergency_reason: None,
            authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                reason: "slo gate fixture",
            },
            software_executor: Some(std::sync::Arc::new(
                crate::software_executor::FakeSoftwareExecutor::new(),
            )),
            model_runtime_executor: None,
            worker_lifecycle: None,
            artifact_registry: None,
            delivery_adapter: None,
            delivery_fence: None,
        }
    }

    async fn apply_current(ctx: &mut Ctx) -> Vec<crate::apply::Outcome> {
        let plan = crate::plan::create(ctx, "local").await.unwrap();
        crate::apply::execute_with_options(ctx, &plan.id, apply_options())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn passing_slo_gate_continues_apply() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-pass-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx.set_health_metrics(source_arc(
            FakeMetricsSource::new().with_value("error_rate", 0.001),
        ));
        crate::plan::env_add(&mut ctx, "local", "slo")
            .await
            .unwrap();
        publish_software(
            &mut ctx,
            &root,
            "1.0.0",
            "[gate]\nbake_window_seconds = 0\non_fail = \"halt\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nop = \"lte\"\nthreshold = 0.01\n",
        )
        .await;
        let actor = crate::auth_context::test_management_context("slo-pass");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "slo-demo", "stable")
            .await
            .unwrap();
        let outcomes = apply_current(&mut ctx).await;
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.classified_status().unwrap() == StepOutcomeStatus::Succeeded),
            "{outcomes:?}"
        );
        let evidence = ctx.list_kind(KIND_HEALTH_GATE_EVIDENCE).await.unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].properties.get("verdict").unwrap(), "pass");
        let parsed: HealthGateEvidence =
            serde_json::from_str(evidence[0].properties.get("evidence").unwrap()).unwrap();
        assert_eq!(parsed.gates[0].value, Some(0.001));
        assert_eq!(parsed.gates[0].verdict, GateVerdict::Pass);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn failing_slo_gate_halts_within_bake_window() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-halt-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx.set_health_metrics(source_arc(
            FakeMetricsSource::new().with_value("error_rate", 0.9),
        ));
        crate::plan::env_add(&mut ctx, "local", "slo")
            .await
            .unwrap();
        publish_software(
            &mut ctx,
            &root,
            "1.0.0",
            "[gate]\nbake_window_seconds = 60\non_fail = \"halt\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nthreshold = 0.01\n",
        )
        .await;
        let actor = crate::auth_context::test_management_context("slo-halt");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "slo-demo", "stable")
            .await
            .unwrap();
        let outcomes = apply_current(&mut ctx).await;
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            StepOutcomeStatus::Failed
        );
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.classified_status().unwrap() != StepOutcomeStatus::Succeeded),
            "SLO halt must not record a prior Succeeded outcome: {outcomes:?}"
        );
        assert!(outcomes[0].detail.contains("bake 60s"), "{:?}", outcomes[0]);
        let evidence = ctx.list_kind(KIND_HEALTH_GATE_EVIDENCE).await.unwrap();
        assert_eq!(evidence[0].properties.get("verdict").unwrap(), "fail");
        let retry = apply_current(&mut ctx).await;
        assert_eq!(
            retry[0].classified_status().unwrap(),
            StepOutcomeStatus::Failed,
            "explicit restart of an SLO-held target must re-evaluate gates: {retry:?}"
        );
        assert!(
            retry
                .iter()
                .all(|outcome| outcome.classified_status().unwrap() != StepOutcomeStatus::Succeeded),
            "{retry:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    struct BlockingMetricsSource;

    impl HealthMetricsSource for BlockingMetricsSource {
        fn query_instant(&self, _query: &str) -> Result<f64> {
            std::thread::sleep(METRICS_SAMPLE_TIMEOUT + Duration::from_secs(2));
            Ok(0.0)
        }
    }

    #[tokio::test]
    async fn stalled_metrics_sample_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-timeout-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx.set_health_metrics(source_arc(BlockingMetricsSource));
        crate::plan::env_add(&mut ctx, "local", "slo")
            .await
            .unwrap();
        publish_software(
            &mut ctx,
            &root,
            "1.0.0",
            "[gate]\nbake_window_seconds = 0\non_fail = \"halt\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nthreshold = 0.01\n",
        )
        .await;
        let actor = crate::auth_context::test_management_context("slo-timeout");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "slo-demo", "stable")
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let outcomes = apply_current(&mut ctx).await;
        assert!(
            started.elapsed() < METRICS_SAMPLE_TIMEOUT + Duration::from_secs(5),
            "stalled metrics must not hold the apply lease for the full blocking query"
        );
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            StepOutcomeStatus::Failed,
            "{outcomes:?}"
        );
        let evidence: HealthGateEvidence = serde_json::from_str(
            ctx.list_kind(KIND_HEALTH_GATE_EVIDENCE).await.unwrap()[0]
                .properties
                .get("evidence")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(evidence.overall, GateVerdict::Unavailable);
        assert!(evidence.gates[0].detail.contains("exceeded"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn later_sample_in_bake_window_halts() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-bake-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        ctx.set_health_metrics(source_arc(
            FakeMetricsSource::new().with_samples("error_rate", [0.001, 0.9]),
        ));
        crate::plan::env_add(&mut ctx, "local", "slo")
            .await
            .unwrap();
        publish_software(
            &mut ctx,
            &root,
            "1.0.0",
            "[gate]\nbake_window_seconds = 1\non_fail = \"halt\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nthreshold = 0.01\n",
        )
        .await;
        let actor = crate::auth_context::test_management_context("slo-bake");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "slo-demo", "stable")
            .await
            .unwrap();
        let outcomes = apply_current(&mut ctx).await;
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            StepOutcomeStatus::Failed,
            "{outcomes:?}"
        );
        let evidence: HealthGateEvidence = serde_json::from_str(
            ctx.list_kind(KIND_HEALTH_GATE_EVIDENCE).await.unwrap()[0]
                .properties
                .get("evidence")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(evidence.gates[0].value, Some(0.9));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn rollback_policy_restores_prior_release_without_loop() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-rollback-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "slo")
            .await
            .unwrap();
        publish_software(&mut ctx, &root, "1.0.0", "").await;
        let actor = crate::auth_context::test_management_context("slo-rollback");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "slo-demo", "stable")
            .await
            .unwrap();
        apply_current(&mut ctx).await;

        publish_software(
            &mut ctx,
            &root,
            "1.1.0",
            "[gate]\nbake_window_seconds = 5\non_fail = \"rollback\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nthreshold = 0.01\n",
        )
        .await;
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.1.0", "stable")
            .await
            .unwrap();
        ctx.set_health_metrics(source_arc(
            FakeMetricsSource::new().with_value("error_rate", 1.0),
        ));
        let outcomes = apply_current(&mut ctx).await;
        assert_eq!(
            outcomes[0].classified_status().unwrap(),
            StepOutcomeStatus::RolledBack,
            "{outcomes:?}"
        );
        let status = crate::environment::status(&mut ctx, "local").await.unwrap();
        let deployed = status
            .iter()
            .find(|row| row.product == "slo-demo")
            .and_then(|row| row.deployed.as_deref());
        assert_eq!(deployed, Some("1.0.0"), "{status:?}");
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.classified_status().unwrap() != StepOutcomeStatus::Succeeded),
            "SLO restore must not record a prior Succeeded outcome: {outcomes:?}"
        );
        let environment = ctx
            .get(&crate::ontology::env_id("local"))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            environment
                .properties
                .get("deployed_prev.slo-demo")
                .map(String::as_str),
            Some("1.1.0"),
            "rejected release must not become the next rollback destination: {environment:?}"
        );
        let evidence = ctx.list_kind(KIND_HEALTH_GATE_EVIDENCE).await.unwrap();
        assert_eq!(evidence.len(), 1, "gate-triggered restore must not loop");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn promote_preserves_channel_health_gates() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-channel-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_software(&mut ctx, &root, "1.0.0", "").await;
        let actor = crate::auth_context::test_management_context("slo-channel");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        let overlay = HealthGateSpec {
            slo: vec![SloGate {
                name: "error_rate".into(),
                query: "error_rate".into(),
                op: SloComparator::Lte,
                threshold: 0.01,
            }],
            bake_window_seconds: 5,
            on_fail: Some(GateFailPolicy::Halt),
        };
        set_channel_health_gates(&mut ctx, "slo-demo", "stable", &overlay)
            .await
            .unwrap();
        publish_software(&mut ctx, &root, "1.1.0", "").await;
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.1.0", "stable")
            .await
            .unwrap();
        let channel = ctx
            .get(&crate::ontology::channel_id("slo-demo", "stable"))
            .await
            .unwrap()
            .unwrap();
        let stored: HealthGateSpec = serde_json::from_str(
            channel
                .properties
                .get(CHANNEL_HEALTH_GATES_PROPERTY)
                .expect("health_gates overlay"),
        )
        .unwrap();
        assert_eq!(stored.slo[0].name, "error_rate");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn ungated_release_behaves_as_today() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-slo-ungated-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "slo")
            .await
            .unwrap();
        publish_software(&mut ctx, &root, "1.0.0", "").await;
        let actor = crate::auth_context::test_management_context("slo-ungated");
        crate::catalog::promote(&mut ctx, &actor, "slo-demo@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "slo-demo", "stable")
            .await
            .unwrap();
        let outcomes = apply_current(&mut ctx).await;
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.classified_status().unwrap() == StepOutcomeStatus::Succeeded));
        assert!(
            ctx.list_kind(KIND_HEALTH_GATE_EVIDENCE)
                .await
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

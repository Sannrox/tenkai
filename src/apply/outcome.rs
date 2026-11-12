//! Closed Step outcome vocabulary and caller-facing lifecycle classification.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::plan::{PlanState, Step};
use crate::schema_contract::omitted_when_none;
use crate::software_executor::sanitize_diagnostic_text;

/// Durable status of one Plan Step execution.
///
/// Serialized spellings are part of the existing command and persistence
/// contracts, so new variants require an explicit compatibility decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcomeStatus {
    Succeeded,
    Blocked,
    Failed,
    RolledBack,
}

impl StepOutcomeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "succeeded" => Ok(Self::Succeeded),
            "blocked" => Ok(Self::Blocked),
            "failed" => Ok(Self::Failed),
            "rolled_back" => Ok(Self::RolledBack),
            other => anyhow::bail!("unknown persisted Step outcome status {other:?}"),
        }
    }

    pub(crate) fn plan_state(self) -> PlanState {
        match self {
            Self::Succeeded => PlanState::Succeeded,
            Self::Blocked => PlanState::Blocked,
            Self::Failed | Self::RolledBack => PlanState::Failed,
        }
    }

    pub fn is_success(self) -> bool {
        self == Self::Succeeded
    }
}

impl std::fmt::Display for StepOutcomeStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed deploy-failure phase recorded on an attempt (#1055).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentCausePhase {
    Admission,
    Pull,
    Activate,
    HealthProbe,
    SloGate,
    Cleanup,
    Restore,
}

impl DeploymentCausePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Pull => "pull",
            Self::Activate => "activate",
            Self::HealthProbe => "health_probe",
            Self::SloGate => "slo_gate",
            Self::Cleanup => "cleanup",
            Self::Restore => "restore",
        }
    }
}

/// Closed deploy-failure kind the executor already distinguishes (#1055).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentCauseKind {
    ProbeFailed,
    GateBreached,
    CommandExited,
    NotReady,
    TargetUnavailable,
    CompatibilityBlocked,
    PlacementRefused,
    CleanupFailed,
    RestoreFailed,
    Restored,
    ExecutorFailed,
    HostNotRestored,
    DrainWait,
}

impl DeploymentCauseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProbeFailed => "probe_failed",
            Self::GateBreached => "gate_breached",
            Self::CommandExited => "command_exited",
            Self::NotReady => "not_ready",
            Self::TargetUnavailable => "target_unavailable",
            Self::CompatibilityBlocked => "compatibility_blocked",
            Self::PlacementRefused => "placement_refused",
            Self::CleanupFailed => "cleanup_failed",
            Self::RestoreFailed => "restore_failed",
            Self::Restored => "restored",
            Self::ExecutorFailed => "executor_failed",
            Self::HostNotRestored => "host_not_restored",
            Self::DrainWait => "drain_wait",
        }
    }
}

/// Byte cap for one persisted cause record. Raw output is dropped first.
const MAX_CAUSE_BYTES: usize = 2_048;
const MAX_RAW_CHARS: usize = 512;
const MAX_SUMMARY_CHARS: usize = 240;
const MAX_RESOURCES: usize = 8;

/// Bounded, redacted structured cause of one failed or rolled-back attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentCause {
    pub phase: DeploymentCausePhase,
    pub kind: DeploymentCauseKind,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub raw: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub gate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub gate_value: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

impl DeploymentCause {
    pub fn new(
        phase: DeploymentCausePhase,
        kind: DeploymentCauseKind,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            kind,
            summary: summary.into(),
            raw: None,
            resources: Vec::new(),
            gate: None,
            gate_value: None,
            truncated: false,
        }
        .seal()
    }

    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = Some(raw.into());
        self.seal()
    }

    pub fn with_resources(mut self, resources: Vec<String>) -> Self {
        self.resources = resources;
        self.seal()
    }

    pub fn with_gate(mut self, gate: impl Into<String>, value: Option<String>) -> Self {
        self.gate = Some(gate.into());
        self.gate_value = value;
        self.seal()
    }

    pub fn at_phase(mut self, phase: DeploymentCausePhase) -> Self {
        self.phase = phase;
        self
    }

    pub fn with_kind(mut self, kind: DeploymentCauseKind) -> Self {
        self.kind = kind;
        self
    }

    /// Classify executor-facing diagnostic prose into a sealed cause.
    pub fn classify(detail: &str) -> Self {
        let sanitized = sanitize_diagnostic_text(detail);
        let lower = sanitized.to_ascii_lowercase();
        let (phase, kind) = classify_phase_kind(&lower);
        let summary = first_line(&sanitized);
        let raw = (sanitized != summary).then_some(sanitized);
        Self {
            phase,
            kind,
            summary,
            raw,
            resources: named_resources(detail),
            gate: None,
            gate_value: None,
            truncated: false,
        }
        .seal()
    }

    /// Redact, cap, and drop raw output first when the record is oversized.
    pub fn seal(mut self) -> Self {
        self.summary = first_line(&sanitize_diagnostic_text(&self.summary));
        if let Some(raw) = self.raw.take() {
            let original_chars = raw.chars().count();
            let cleaned = sanitize_diagnostic_text(&raw);
            if original_chars > cleaned.chars().count() {
                self.truncated = true;
            }
            if cleaned.is_empty() || cleaned == self.summary {
                self.raw = None;
            } else {
                let clipped: String = cleaned.chars().take(MAX_RAW_CHARS).collect();
                if clipped.chars().count() < cleaned.chars().count() {
                    self.truncated = true;
                }
                self.raw = Some(clipped);
            }
        }
        self.resources.truncate(MAX_RESOURCES);
        for resource in &mut self.resources {
            *resource = sanitize_diagnostic_text(resource);
        }
        self.resources.retain(|resource| !resource.is_empty());
        if let Some(gate) = self.gate.take() {
            let cleaned = first_line(&sanitize_diagnostic_text(&gate));
            self.gate = (!cleaned.is_empty()).then_some(cleaned);
        }
        if let Some(value) = self.gate_value.take() {
            let cleaned = first_line(&sanitize_diagnostic_text(&value));
            self.gate_value = (!cleaned.is_empty()).then_some(cleaned);
        }
        if encoded_len(&self) > MAX_CAUSE_BYTES {
            self.raw = None;
            self.truncated = true;
        }
        if encoded_len(&self) > MAX_CAUSE_BYTES {
            self.resources.clear();
            self.truncated = true;
        }
        while encoded_len(&self) > MAX_CAUSE_BYTES {
            self.truncated = true;
            if self.gate_value.take().is_some() {
                continue;
            }
            if self.gate.take().is_some() {
                continue;
            }
            let chars = self.summary.chars().count();
            if chars > 1 {
                self.summary = self.summary.chars().take(chars / 2).collect();
                continue;
            }
            break;
        }
        self
    }

    pub(crate) fn to_property(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }

    pub(crate) fn from_property(raw: &str) -> Option<Self> {
        serde_json::from_str(raw).ok()
    }
}

fn encoded_len(cause: &DeploymentCause) -> usize {
    serde_json::to_vec(cause)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or(text).trim();
    line.chars().take(MAX_SUMMARY_CHARS).collect()
}

fn classify_phase_kind(lower: &str) -> (DeploymentCausePhase, DeploymentCauseKind) {
    if lower.contains("health/slo gate") || lower.contains("slo gate") {
        return (
            DeploymentCausePhase::SloGate,
            DeploymentCauseKind::GateBreached,
        );
    }
    // Producer format from `format_software_phase_error`: honor `phase=` first
    // so later-phase text cannot steal admission/health kinds.
    if let Some(phase) = software_phase_token(lower) {
        return match phase {
            "health" => {
                let kind = if lower.contains("not ready") {
                    DeploymentCauseKind::NotReady
                } else {
                    DeploymentCauseKind::ProbeFailed
                };
                (DeploymentCausePhase::HealthProbe, kind)
            }
            "apply" | "restart" => (
                DeploymentCausePhase::Activate,
                DeploymentCauseKind::CommandExited,
            ),
            "restore" => (
                DeploymentCausePhase::Restore,
                DeploymentCauseKind::RestoreFailed,
            ),
            "remove" => (
                DeploymentCausePhase::Cleanup,
                DeploymentCauseKind::CleanupFailed,
            ),
            _ => (
                DeploymentCausePhase::Activate,
                DeploymentCauseKind::ExecutorFailed,
            ),
        };
    }
    if lower.contains("probe failed")
        || lower.contains("health wait")
        || lower.contains("health is")
    {
        let kind = if lower.contains("not ready") {
            DeploymentCauseKind::NotReady
        } else {
            DeploymentCauseKind::ProbeFailed
        };
        return (DeploymentCausePhase::HealthProbe, kind);
    }
    if lower.contains("restore or health") || lower.contains("restore executor") {
        return (
            DeploymentCausePhase::Restore,
            DeploymentCauseKind::RestoreFailed,
        );
    }
    if lower.contains("waiting for bounded drain") {
        return (
            DeploymentCausePhase::Cleanup,
            DeploymentCauseKind::DrainWait,
        );
    }
    if lower.contains("outgoing release cleanup") || lower.contains("cleanup failed") {
        return (
            DeploymentCausePhase::Cleanup,
            DeploymentCauseKind::CleanupFailed,
        );
    }
    if lower.contains("never restored") || lower.contains("never restore") {
        return (
            DeploymentCausePhase::Activate,
            DeploymentCauseKind::HostNotRestored,
        );
    }
    if lower.contains("placement") {
        return (
            DeploymentCausePhase::Admission,
            DeploymentCauseKind::PlacementRefused,
        );
    }
    if lower.contains("incompatible") || lower.contains("compatibility") {
        return (
            DeploymentCausePhase::Admission,
            DeploymentCauseKind::CompatibilityBlocked,
        );
    }
    if lower.contains("unavailable") {
        return (
            DeploymentCausePhase::Admission,
            DeploymentCauseKind::TargetUnavailable,
        );
    }
    if lower.contains("artifact") && (lower.contains("pull") || lower.contains("oci")) {
        return (
            DeploymentCausePhase::Pull,
            DeploymentCauseKind::CommandExited,
        );
    }
    if lower.contains("not ready") {
        return (
            DeploymentCausePhase::HealthProbe,
            DeploymentCauseKind::NotReady,
        );
    }
    if lower.contains("exit status") || lower.contains("exited") {
        return (
            DeploymentCausePhase::Activate,
            DeploymentCauseKind::CommandExited,
        );
    }
    (
        DeploymentCausePhase::Activate,
        DeploymentCauseKind::ExecutorFailed,
    )
}

fn software_phase_token(lower: &str) -> Option<&str> {
    let rest = lower.split_once("phase=")?.1;
    let token = rest
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | ';' | ':'))
        .next()
        .filter(|token| !token.is_empty())?;
    Some(token)
}

fn named_resources(detail: &str) -> Vec<String> {
    let mut resources = Vec::new();
    for token in detail.split_whitespace() {
        let trimmed = token
            .trim_matches(|c: char| matches!(c, ',' | ';' | ':' | ')' | '(' | '"' | '\'' | '.'));
        if let Some(name) = trimmed.strip_prefix("container/") {
            push_resource(&mut resources, name);
        } else if let Some((kind, name)) = trimmed.split_once('/')
            && kind
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase() || kind.contains('.'))
            && !name.is_empty()
            && name.len() < 80
        {
            push_resource(&mut resources, trimmed);
        }
    }
    if let Some(rest) = detail.split_once("container ").map(|(_, rest)| rest)
        && let Some(name) = rest.split_whitespace().next()
    {
        push_resource(
            &mut resources,
            name.trim_matches(|c: char| matches!(c, ',' | ';' | ':' | ')' | '(')),
        );
    }
    resources
}

fn push_resource(resources: &mut Vec<String>, name: &str) {
    if name.is_empty() || resources.iter().any(|existing| existing == name) {
        return;
    }
    if resources.len() < MAX_RESOURCES {
        resources.push(name.to_string());
    }
}

/// Outcome of one immutable Plan Step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    pub step: Step,
    pub status: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<DeploymentCause>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<DeploymentCause>,
    /// The deployment attempt this outcome recorded (#1054), if it recorded
    /// one in this execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
}

impl Outcome {
    pub fn new(step: Step, status: StepOutcomeStatus, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let cause = match status {
            StepOutcomeStatus::Succeeded => None,
            _ if detail.is_empty() => None,
            _ => Some(DeploymentCause::classify(&detail)),
        };
        Self::recorded(step, status, detail, cause, None)
    }

    /// Record `detail` without reclassifying it. Use when `detail` concatenates
    /// an original failure and a restore result.
    pub fn recorded(
        step: Step,
        status: StepOutcomeStatus,
        detail: impl Into<String>,
        cause: Option<DeploymentCause>,
        restore: Option<DeploymentCause>,
    ) -> Self {
        Self {
            step,
            status: status.as_str().into(),
            detail: detail.into(),
            cause,
            restore,
            attempt_id: None,
        }
    }

    pub fn with_cause(mut self, cause: DeploymentCause) -> Self {
        self.cause = Some(cause);
        self
    }

    pub fn with_restore(mut self, restore: DeploymentCause) -> Self {
        self.restore = Some(restore);
        self
    }

    pub fn classified_status(&self) -> anyhow::Result<StepOutcomeStatus> {
        StepOutcomeStatus::parse(&self.status)
    }

    pub(crate) fn plan_state(&self) -> anyhow::Result<PlanState> {
        Ok(self.classified_status()?.plan_state())
    }

    pub(crate) fn is_gate_blocked(&self) -> anyhow::Result<bool> {
        Ok(self.classified_status()? == StepOutcomeStatus::Blocked
            && self.detail.starts_with("gate "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step() -> Step {
        Step {
            id: "step-1".into(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: crate::plan::Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: "tenkai:release:api@1.0.0".into(),
            release_digest: "sha256:release".into(),
            artifact_digest: "sha256:artifact".into(),
            workdir: ".".into(),
            host: None,
            sealed: Vec::new(),
            restore: None,
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
            target_changes: Vec::new(),
        }
    }

    #[test]
    fn status_serialization_preserves_the_existing_contract() {
        assert_eq!(
            serde_json::to_string(&StepOutcomeStatus::RolledBack).unwrap(),
            "\"rolled_back\""
        );
        assert_eq!(
            serde_json::from_str::<StepOutcomeStatus>("\"blocked\"").unwrap(),
            StepOutcomeStatus::Blocked
        );
    }

    #[test]
    fn public_string_field_remains_compatible_but_classification_fails_closed() {
        let outcome = Outcome {
            step: step(),
            status: "future_status".into(),
            detail: String::new(),
            cause: None,
            restore: None,
            attempt_id: None,
        };

        assert!(outcome.classified_status().is_err());
    }

    #[test]
    fn older_outcome_json_reads_without_cause_fields() {
        let json = serde_json::json!({
            "step": step(),
            "status": "failed",
            "detail": "boom",
        });
        let outcome: Outcome = serde_json::from_value(json).unwrap();
        assert_eq!(outcome.detail, "boom");
        assert_eq!(outcome.cause, None);
        assert_eq!(outcome.restore, None);
    }

    #[test]
    fn classify_health_probe_slo_gate_and_command() {
        let probe = DeploymentCause::classify("probe failed: Deployment/api is not ready");
        assert_eq!(probe.phase, DeploymentCausePhase::HealthProbe);
        assert_eq!(probe.kind, DeploymentCauseKind::NotReady);
        assert!(
            probe
                .resources
                .iter()
                .any(|name| name.contains("Deployment/api"))
        );

        let gate = DeploymentCause::classify(
            "health/SLO gate fail for tenkai:release:api@1.1.0 (bake 0s, on_fail=rollback): error_rate=1 > 0.01 => fail",
        );
        assert_eq!(gate.phase, DeploymentCausePhase::SloGate);
        assert_eq!(gate.kind, DeploymentCauseKind::GateBreached);

        let command = DeploymentCause::classify(
            "software deploy phase=apply product=api@1.1.0 environment/namespace=prod: helm upgrade failed (status exit status: 1): rendered",
        );
        assert_eq!(command.phase, DeploymentCausePhase::Activate);
        assert_eq!(command.kind, DeploymentCauseKind::CommandExited);
        assert_eq!(
            command.summary,
            "software deploy phase=apply product=api@1.1.0 environment/namespace=prod: helm upgrade failed (status exit status: 1): rendered"
        );
    }

    #[test]
    fn seal_drops_raw_before_other_fields_when_oversized() {
        let raw = "x".repeat(8_000);
        let cause = DeploymentCause::new(
            DeploymentCausePhase::Activate,
            DeploymentCauseKind::CommandExited,
            "command exited",
        )
        .with_raw(raw);
        assert!(cause.truncated, "{cause:?}");
        assert!(
            cause
                .raw
                .as_ref()
                .is_none_or(|raw| raw.chars().count() <= MAX_RAW_CHARS),
            "{cause:?}"
        );
        assert_eq!(cause.summary, "command exited");
        assert!(encoded_len(&cause) <= MAX_CAUSE_BYTES);
    }

    #[test]
    fn seal_fits_wide_summary_and_gate_fields_under_the_byte_cap() {
        let fat = "\u{1F600}".repeat(MAX_SUMMARY_CHARS);
        let cause = DeploymentCause::new(
            DeploymentCausePhase::SloGate,
            DeploymentCauseKind::GateBreached,
            fat.clone(),
        )
        .with_gate(fat.clone(), Some(fat));
        assert!(cause.truncated, "{cause:?}");
        assert!(encoded_len(&cause) <= MAX_CAUSE_BYTES, "{cause:?}");
    }

    #[test]
    fn classify_honors_software_phase_token_before_later_prose() {
        let apply = DeploymentCause::classify(
            "software deploy phase=apply product=api@1.1.0 environment/namespace=prod: target unavailable and not ready",
        );
        assert_eq!(apply.phase, DeploymentCausePhase::Activate);
        assert_eq!(apply.kind, DeploymentCauseKind::CommandExited);

        let restore = DeploymentCause::classify(
            "software deploy phase=restore product=api@1.0.0 environment/namespace=prod: probe failed",
        );
        assert_eq!(restore.phase, DeploymentCausePhase::Restore);
        assert_eq!(restore.kind, DeploymentCauseKind::RestoreFailed);
    }

    #[test]
    fn outcome_new_classifies_failed_detail() {
        let outcome = Outcome::new(
            step(),
            StepOutcomeStatus::Failed,
            "software deploy phase=health product=api@1.0.0 environment/namespace=prod: probe failed",
        );
        let cause = outcome.cause.expect("classified");
        assert_eq!(cause.phase, DeploymentCausePhase::HealthProbe);
        assert_eq!(cause.kind, DeploymentCauseKind::ProbeFailed);
    }

    #[test]
    fn recorded_keeps_the_supplied_cause_on_combined_restore_detail() {
        let original = DeploymentCause::new(
            DeploymentCausePhase::Activate,
            DeploymentCauseKind::CommandExited,
            "command exited",
        );
        let restore = DeploymentCause::new(
            DeploymentCausePhase::Restore,
            DeploymentCauseKind::Restored,
            "restored 1.0.0",
        );
        let outcome = Outcome::recorded(
            step(),
            StepOutcomeStatus::RolledBack,
            "command exited; restored 1.0.0; restored api to 1.0.0; channel head is unchanged",
            Some(original.clone()),
            Some(restore.clone()),
        );
        assert_eq!(outcome.cause.as_ref(), Some(&original));
        assert_eq!(outcome.restore.as_ref(), Some(&restore));
    }
}

//! Versioned two-way model-release evidence schema (ADR 0032).
//!
//! Tenkai emits runtime health and canary evidence for a model identity.
//! Chisei emits evaluation results for that same identity. Promotion refuses
//! when either side is missing, stale, or invalid. Export and gate wiring are
//! follow-on; this module is the contract those paths must share.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::ontology::validate_identifier;
use crate::signature_verification::{decode_exact, validate_key_id, validate_prefixed_digest};

pub const RUNTIME_EVIDENCE_SCHEMA: &str = "tenkai.model_runtime_evidence.v1";
pub const EVALUATION_EVIDENCE_SCHEMA: &str = "chisei.model_evaluation_evidence.v1";
pub const CLOCK_SKEW_ALLOWANCE_MS: i64 = 60_000;
const MAX_ENDPOINT_BYTES: usize = 512;

/// Shared model identity for both evidence directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelReleaseIdentity {
    pub provider: String,
    pub model: String,
    pub profile_version: String,
    pub artifact_digest: String,
    pub endpoint: String,
}

/// Tenkai → Chisei runtime health and canary evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimeEvidence {
    pub schema: String,
    pub identity: ModelReleaseIdentity,
    pub release_id: String,
    pub release_digest: String,
    pub health: RuntimeHealth,
    pub canary: RuntimeCanary,
    pub observed_at: i64,
    pub expires_at: i64,
    pub signer: EvidenceSigner,
}

/// Chisei → Tenkai evaluation result for the same identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelEvaluationEvidence {
    pub schema: String,
    pub identity: ModelReleaseIdentity,
    pub eval_suite_id: String,
    pub eval_run_id: String,
    pub outcome: EvaluationOutcome,
    pub observed_at: i64,
    pub expires_at: i64,
    pub signer: EvidenceSigner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCanary {
    Passed,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSigner {
    pub key_id: String,
    pub signature: String,
}

/// Closed promotion-refusal vocabulary from ADR 0032.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelReleaseEvidenceFailure {
    #[error("missing")]
    Missing,
    #[error("stale")]
    Stale,
    #[error("invalid")]
    Invalid,
}

impl ModelRuntimeEvidence {
    pub fn parse_json(value: &str) -> std::result::Result<Self, ModelReleaseEvidenceFailure> {
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        parsed
            .validate()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_EVIDENCE_SCHEMA {
            bail!("unsupported model runtime evidence schema {}", self.schema);
        }
        self.identity.validate()?;
        if self.release_id.is_empty() {
            bail!("runtime evidence release_id must not be empty");
        }
        validate_prefixed_digest("release_digest", &self.release_digest)?;
        validate_timestamps(self.observed_at, self.expires_at)?;
        self.signer.validate()?;
        Ok(())
    }

    fn promotion_refusal(
        &self,
        expected: &ModelReleaseIdentity,
        now_ms: i64,
    ) -> Option<ModelReleaseEvidenceFailure> {
        if self.validate().is_err() || &self.identity != expected {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        if is_stale(self.observed_at, self.expires_at, now_ms) {
            return Some(ModelReleaseEvidenceFailure::Stale);
        }
        if self.health != RuntimeHealth::Healthy || self.canary != RuntimeCanary::Passed {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        None
    }
}

impl ModelEvaluationEvidence {
    pub fn parse_json(value: &str) -> std::result::Result<Self, ModelReleaseEvidenceFailure> {
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        parsed
            .validate()
            .map_err(|_| ModelReleaseEvidenceFailure::Invalid)?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != EVALUATION_EVIDENCE_SCHEMA {
            bail!(
                "unsupported model evaluation evidence schema {}",
                self.schema
            );
        }
        self.identity.validate()?;
        validate_identifier("eval_suite_id", &self.eval_suite_id)?;
        validate_identifier("eval_run_id", &self.eval_run_id)?;
        validate_timestamps(self.observed_at, self.expires_at)?;
        self.signer.validate()?;
        Ok(())
    }

    fn promotion_refusal(
        &self,
        expected: &ModelReleaseIdentity,
        now_ms: i64,
    ) -> Option<ModelReleaseEvidenceFailure> {
        if self.validate().is_err() || &self.identity != expected {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        if is_stale(self.observed_at, self.expires_at, now_ms) {
            return Some(ModelReleaseEvidenceFailure::Stale);
        }
        if self.outcome != EvaluationOutcome::Passed {
            return Some(ModelReleaseEvidenceFailure::Invalid);
        }
        None
    }
}

impl ModelReleaseIdentity {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("provider", &self.provider)?;
        validate_identifier("model", &self.model)?;
        validate_identifier("profile_version", &self.profile_version)?;
        validate_prefixed_digest("artifact_digest", &self.artifact_digest)?;
        validate_endpoint(&self.endpoint)?;
        Ok(())
    }
}

impl EvidenceSigner {
    pub fn validate(&self) -> Result<()> {
        validate_key_id("signer.key_id", &self.key_id)?;
        decode_exact::<64>("signer.signature", &self.signature)
            .context("signer.signature must be a 64-byte Ed25519 signature")?;
        Ok(())
    }
}

/// Refuse promotion unless both directions are present, fresh, and passing.
pub fn evaluate_model_release_promotion(
    runtime: Option<&ModelRuntimeEvidence>,
    evaluation: Option<&ModelEvaluationEvidence>,
    expected: &ModelReleaseIdentity,
    now_ms: i64,
) -> std::result::Result<(), ModelReleaseEvidenceFailure> {
    let Some(runtime) = runtime else {
        return Err(ModelReleaseEvidenceFailure::Missing);
    };
    let Some(evaluation) = evaluation else {
        return Err(ModelReleaseEvidenceFailure::Missing);
    };
    if let Some(failure) = runtime.promotion_refusal(expected, now_ms) {
        return Err(failure);
    }
    if let Some(failure) = evaluation.promotion_refusal(expected, now_ms) {
        return Err(failure);
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES || value.chars().any(char::is_control) {
        bail!("endpoint is empty, oversized, or contains control characters");
    }
    let parsed = url::Url::parse(value).context("endpoint must be an absolute URI")?;
    if parsed.cannot_be_a_base() {
        bail!("endpoint must be an absolute URI");
    }
    Ok(())
}

fn validate_timestamps(observed_at: i64, expires_at: i64) -> Result<()> {
    if observed_at <= 0 || expires_at <= observed_at {
        bail!("evidence timestamps must be positive and expire after observation");
    }
    Ok(())
}

fn is_stale(observed_at: i64, expires_at: i64, now_ms: i64) -> bool {
    observed_at > now_ms.saturating_add(CLOCK_SKEW_ALLOWANCE_MS) || expires_at <= now_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNTIME_EXAMPLE: &str =
        include_str!("../docs/examples/model-release-evidence/runtime-health.json");
    const EVALUATION_EXAMPLE: &str =
        include_str!("../docs/examples/model-release-evidence/evaluation-result.json");
    const NOW_MS: i64 = 1_700_000_100_000;

    fn expected_identity() -> ModelReleaseIdentity {
        ModelRuntimeEvidence::parse_json(RUNTIME_EXAMPLE)
            .expect("runtime example")
            .identity
    }

    #[test]
    fn example_records_validate_and_admit_promotion() {
        let runtime = ModelRuntimeEvidence::parse_json(RUNTIME_EXAMPLE).expect("runtime example");
        let evaluation =
            ModelEvaluationEvidence::parse_json(EVALUATION_EXAMPLE).expect("evaluation example");
        assert_eq!(runtime.schema, RUNTIME_EVIDENCE_SCHEMA);
        assert_eq!(evaluation.schema, EVALUATION_EVIDENCE_SCHEMA);
        assert_eq!(runtime.identity, evaluation.identity);
        evaluate_model_release_promotion(
            Some(&runtime),
            Some(&evaluation),
            &runtime.identity,
            NOW_MS,
        )
        .expect("fresh passing examples admit promotion");
        let runtime_again: ModelRuntimeEvidence =
            serde_json::from_str(&serde_json::to_string(&runtime).unwrap()).unwrap();
        let evaluation_again: ModelEvaluationEvidence =
            serde_json::from_str(&serde_json::to_string(&evaluation).unwrap()).unwrap();
        assert_eq!(runtime, runtime_again);
        assert_eq!(evaluation, evaluation_again);
    }

    #[test]
    fn unknown_fields_and_unknown_schema_are_invalid() {
        let mutated = RUNTIME_EXAMPLE.replacen(
            r#""schema": "tenkai.model_runtime_evidence.v1""#,
            r#""schema": "tenkai.model_runtime_evidence.v1", "extra": true"#,
            1,
        );
        assert_eq!(
            ModelRuntimeEvidence::parse_json(&mutated).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
        let unknown_schema =
            RUNTIME_EXAMPLE.replace(RUNTIME_EVIDENCE_SCHEMA, "tenkai.model_runtime_evidence.v0");
        assert_eq!(
            ModelRuntimeEvidence::parse_json(&unknown_schema).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
        let mutated_eval = EVALUATION_EXAMPLE.replacen(
            r#""outcome": "passed""#,
            r#""outcome": "passed", "score": 1"#,
            1,
        );
        assert_eq!(
            ModelEvaluationEvidence::parse_json(&mutated_eval).unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn promotion_refuses_missing_stale_and_invalid_evidence() {
        let runtime = ModelRuntimeEvidence::parse_json(RUNTIME_EXAMPLE).unwrap();
        let evaluation = ModelEvaluationEvidence::parse_json(EVALUATION_EXAMPLE).unwrap();
        let expected = expected_identity();

        assert_eq!(
            evaluate_model_release_promotion(None, Some(&evaluation), &expected, NOW_MS)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Missing
        );
        assert_eq!(
            evaluate_model_release_promotion(Some(&runtime), None, &expected, NOW_MS).unwrap_err(),
            ModelReleaseEvidenceFailure::Missing
        );

        let mut stale = runtime.clone();
        stale.expires_at = NOW_MS;
        assert_eq!(
            evaluate_model_release_promotion(Some(&stale), Some(&evaluation), &expected, NOW_MS)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Stale
        );

        let mut failed = runtime.clone();
        failed.canary = RuntimeCanary::Failed;
        assert_eq!(
            evaluate_model_release_promotion(Some(&failed), Some(&evaluation), &expected, NOW_MS)
                .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );

        let mut mismatched = expected.clone();
        mismatched.model = "other-model".into();
        assert_eq!(
            evaluate_model_release_promotion(
                Some(&runtime),
                Some(&evaluation),
                &mismatched,
                NOW_MS
            )
            .unwrap_err(),
            ModelReleaseEvidenceFailure::Invalid
        );
    }

    #[test]
    fn identity_rejects_unschemed_endpoints() {
        let mut identity = expected_identity();
        identity.endpoint = "gpu-node-3".into();
        assert!(identity.validate().is_err());
        identity.endpoint = "served://qwen-coder".into();
        identity.validate().unwrap();
    }
}

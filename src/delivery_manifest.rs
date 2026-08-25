//! Portable delivery-manifest profile v1 (#291).
//!
//! Independent planner and runtime admission call the shipped release,
//! approval, and runtime functions. Ontology-package names are opaque
//! content-bound identities with no payload.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::plan::Plan;
use crate::plan_approval;
use crate::release_signing::{self, SignatureEnvelope, TrustRoots, VerificationEvidence};
use crate::runtime_delivery::{
    RuntimeCompletion, complete_runtime_work, validate_runtime_completion,
};

pub const PROFILE: &str = "tenkai.delivery-manifest.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFixture {
    pub profile: String,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub supported_capabilities: Vec<String>,
    #[serde(default)]
    pub ontology_package_ref: Option<String>,
    #[serde(default)]
    pub ontology_package_payload: Option<String>,
}

pub fn admit_fixture(fixture: &ProfileFixture) -> Result<()> {
    if fixture.profile != PROFILE {
        bail!("unsupported delivery-manifest profile {}", fixture.profile);
    }
    if fixture.ontology_package_payload.is_some() {
        bail!("ontology package payloads are excluded from the delivery-manifest profile");
    }
    admit_ontology_package_ref(fixture.ontology_package_ref.as_deref())?;
    admit_required_capabilities(
        &fixture.required_capabilities,
        &fixture.supported_capabilities,
    )
}

pub fn admit_ontology_package_ref(value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let lower = value.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token=", "{", "payload"] {
        if lower.contains(needle) {
            bail!("ontology package ref must be an opaque identity, not a payload or credential");
        }
    }
    if value.trim() != value
        || value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("ontology package ref is empty, non-canonical, or too long");
    }
    if value.starts_with("sha256:") {
        crate::signature_verification::validate_prefixed_digest("ontology package ref", value)?;
        return Ok(());
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '.' | '_' | '/' | '-'))
    {
        bail!("ontology package ref is not a stable opaque identity");
    }
    Ok(())
}

pub fn admit_required_capabilities(required: &[String], supported: &[String]) -> Result<()> {
    let supported = supported.iter().cloned().collect::<BTreeSet<_>>();
    for capability in required {
        if capability.trim() != capability || capability.is_empty() {
            bail!("required capability is empty or non-canonical");
        }
        if !supported.contains(capability) {
            bail!("unknown required capability {capability} is not success");
        }
    }
    Ok(())
}

pub fn admit_signed_release(
    envelope: &SignatureEnvelope,
    roots: &TrustRoots,
    manifest_digest: &str,
    artifact_digest: &str,
) -> Result<VerificationEvidence> {
    release_signing::verify_release(envelope, roots, manifest_digest, artifact_digest)
}

pub fn admit_signed_plan(
    plan: &Plan,
    approval: &Path,
    trust_roots: &Path,
    now: i64,
) -> Result<plan_approval::VerificationEvidence> {
    plan_approval::verify(plan, approval, trust_roots, now, false)
}

pub async fn admit_runtime_completion(
    ctx: &mut Ctx,
    environment: &str,
    completion: &RuntimeCompletion,
) -> Result<()> {
    validate_runtime_completion(ctx, environment, completion).await?;
    complete_runtime_work(ctx, environment, completion).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;
    use crate::plan::Plan;
    use crate::runtime_delivery::RuntimeStepReceipt;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    fn fixture() -> ProfileFixture {
        ProfileFixture {
            profile: PROFILE.into(),
            required_capabilities: vec!["plan.execute".into()],
            supported_capabilities: vec!["plan.execute".into(), "runtime.complete".into()],
            ontology_package_ref: Some(format!("sha256:{}", "ab".repeat(32))),
            ontology_package_payload: None,
        }
    }

    #[test]
    fn fixture_admits_opaque_ontology_ref_and_rejects_payloads() {
        admit_fixture(&fixture()).unwrap();
        let mut payload = fixture();
        payload.ontology_package_payload = Some(r#"{"reducer":"expand"}"#.into());
        let err = admit_fixture(&payload).unwrap_err().to_string();
        assert!(err.contains("payloads are excluded"), "{err}");
        let mut unknown = fixture();
        unknown.required_capabilities = vec!["capability.unknown".into()];
        let err = admit_fixture(&unknown).unwrap_err().to_string();
        assert!(err.contains("unknown required capability"), "{err}");
        let err = admit_ontology_package_ref(Some("bearer token=secret"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("opaque identity"), "{err}");
    }

    #[tokio::test]
    async fn planner_and_runtime_admit_valid_signed_fixtures_and_reject_altered_bytes() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-manifest-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "prod", "profile fixture")
            .await
            .unwrap();

        let product = root.join("1.0.0");
        std::fs::create_dir_all(&product).unwrap();
        std::fs::write(
            product.join("tenkai.toml"),
            r#"
[product]
name = "profile-app"
version = "1.0.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = product.join("release.sig.json");
        let trust = product.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &product.join("tenkai.toml"), &signature, &trust)
            .unwrap();
        let envelope = SignatureEnvelope::load(&signature).unwrap();
        let roots = TrustRoots::load(&trust).unwrap();
        admit_signed_release(
            &envelope,
            &roots,
            &envelope.statement.manifest_digest,
            &envelope.statement.artifact_digest,
        )
        .unwrap();
        let err = admit_signed_release(
            &envelope,
            &roots,
            &"0".repeat(64),
            &envelope.statement.artifact_digest,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("manifest digest"), "{err}");

        crate::catalog::publish(
            &mut ctx,
            &product.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                allow_unsigned_development: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("profile");
        crate::catalog::promote(&mut ctx, &actor, "profile-app@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "prod", "profile-app", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create_for_reconcile(&mut ctx, "prod")
            .await
            .unwrap();
        assert!(!plan.steps.is_empty(), "{plan:?}");

        let approval = root.join("approval.json");
        let approval_trust = root.join("approval-trust.toml");
        write_plan_approval(&plan, &approval, &approval_trust);
        admit_signed_plan(&plan, &approval, &approval_trust, crate::now_millis()).unwrap();
        let raw = std::fs::read_to_string(&approval).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
        envelope["statement"]["environment"] = serde_json::Value::String("other".into());
        std::fs::write(&approval, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let err = admit_signed_plan(&plan, &approval, &approval_trust, crate::now_millis())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("different executable content") || err.contains("signature"),
            "{err}"
        );

        write_plan_approval(&plan, &approval, &approval_trust);
        let success = RuntimeCompletion {
            plan_id: plan.id.clone(),
            generation: 1,
            succeeded: true,
            detail: "profile runtime completion".into(),
            receipts: vec![RuntimeStepReceipt {
                step_id: plan.steps[0].id.clone(),
                succeeded: true,
                detail: "profile runtime completion".into(),
            }],
        };
        admit_runtime_completion(&mut ctx, "prod", &success)
            .await
            .unwrap();
        admit_runtime_completion(&mut ctx, "prod", &success)
            .await
            .unwrap();
        let mut conflict = success.clone();
        conflict.succeeded = false;
        conflict.detail = "conflicting result".into();
        conflict.receipts[0].succeeded = false;
        let err = admit_runtime_completion(&mut ctx, "prod", &conflict)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("conflict"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_plan_approval(plan: &Plan, approval: &Path, trust: &Path) {
        use crate::plan_approval::{
            APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, canonical_bytes,
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let public = key.verifying_key().to_bytes();
        let kid = crate::release_signing::key_id(&public);
        let now = crate::now_millis();
        let statement = ApprovalStatement {
            plan_digest: format!("sha256:{}", plan.executable_digest().unwrap()),
            environment: plan.environment.clone(),
            purpose: "execute_plan".into(),
            skip_gates: false,
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(60_000),
            policy_provider: "builtin".into(),
            policy_evidence_id: "profile-decision".into(),
            policy_digest: format!("sha256:{}", "cd".repeat(32)),
        };
        let signature = key.sign(&canonical_bytes(&statement).unwrap());
        let envelope = ApprovalEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: kid.clone(),
            statement,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };
        std::fs::write(approval, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        std::fs::write(
            trust,
            format!(
                "version = 1\n\n[[signers]]\nkey_id = \"{kid}\"\nidentity = \"approver@localhost\"\npublic_key = \"{}\"\n",
                base64::engine::general_purpose::STANDARD.encode(public)
            ),
        )
        .unwrap();
    }
}

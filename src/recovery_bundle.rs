//! Bounded, read-only recovery diagnostic (ADR 0027).
//!
//! Derived at observed read time. Not a store and not an apply grant.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::plan::{self, PlanState};

pub const BUNDLE_SCHEMA: &str = "tenkai.recovery_bundle.v1";
pub const NO_AUTHORITY: &str = "none";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReleaseRef {
    pub product: String,
    pub version: String,
    pub release_id: String,
    pub release_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBundle {
    pub schema: String,
    pub observed_at: i64,
    pub environment: String,
    pub plan_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_content_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence_generation: Option<u64>,
    pub recovery_required: bool,
    pub releases: Vec<RecoveryReleaseRef>,
    pub findings: Vec<String>,
    pub authority: String,
}

pub fn verify(bundle: &RecoveryBundle) -> Result<()> {
    if bundle.schema != BUNDLE_SCHEMA {
        bail!("unsupported recovery bundle schema {}", bundle.schema);
    }
    if bundle.authority != NO_AUTHORITY {
        bail!("recovery bundle must not convey execution authority");
    }
    if bundle.observed_at <= 0 {
        bail!("recovery bundle observed_at is missing");
    }
    if bundle.plan_id.trim().is_empty() {
        bail!("recovery bundle plan identity is missing");
    }
    if bundle.environment.trim().is_empty() {
        bail!("recovery bundle environment is missing");
    }
    Ok(())
}

pub async fn export(ctx: &mut Ctx, environment: &str, plan_id: &str) -> Result<RecoveryBundle> {
    crate::ontology::validate_identifier("environment", environment)?;
    if plan_id.trim().is_empty() {
        bail!("recovery bundle plan identity is missing");
    }
    let mut findings = Vec::new();
    let mut plan_content_id = None;
    let mut plan_state = None;
    let mut recovery_required = false;
    let mut releases = Vec::new();
    match plan::load(ctx, plan_id).await {
        Ok(plan) => {
            if plan.environment != environment {
                findings.push(format!(
                    "plan {plan_id} is bound to environment {}, not {environment}",
                    plan.environment
                ));
            }
            plan_content_id = Some(plan.content_id.clone());
            plan_state = Some(plan.state.to_string());
            recovery_required = plan.state == PlanState::Failed
                || plan.status_detail.to_ascii_lowercase().contains("recovery");
            for step in &plan.steps {
                releases.push(RecoveryReleaseRef {
                    product: step.product.clone(),
                    version: step.to.clone(),
                    release_id: step.release_id.clone(),
                    release_digest: step.release_digest.clone(),
                });
            }
        }
        Err(error) => findings.push(format!("plan missing or unreadable: {error:#}")),
    }
    let fence_generation = match crate::apply::inspect_environment_lease(ctx, environment).await {
        Ok(lease) => lease.generation,
        Err(error) => {
            findings.push(format!("fence unreadable: {error:#}"));
            None
        }
    };
    let bundle = RecoveryBundle {
        schema: BUNDLE_SCHEMA.into(),
        observed_at: crate::now_millis(),
        environment: environment.into(),
        plan_id: plan_id.into(),
        plan_content_id,
        plan_state,
        fence_generation,
        recovery_required,
        releases,
        findings,
        authority: NO_AUTHORITY.into(),
    };
    verify(&bundle)?;
    Ok(bundle)
}

pub fn write_verified(path: &Path, bundle: &RecoveryBundle) -> Result<()> {
    verify(bundle)?;
    let bytes = serde_json::to_vec_pretty(bundle).context("encoding recovery bundle")?;
    let parsed: RecoveryBundle =
        serde_json::from_slice(&bytes).context("re-parsing recovery bundle")?;
    verify(&parsed)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::ontology::register;

    #[tokio::test]
    async fn missing_plan_stays_explicit_and_has_no_authority() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-recovery-bundle-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "site-a", "fixture")
            .await
            .unwrap();
        let bundle = export(&mut ctx, "site-a", "tenkai:plan:site-a:1:missing")
            .await
            .unwrap();
        verify(&bundle).unwrap();
        assert_eq!(bundle.authority, NO_AUTHORITY);
        assert!(
            bundle
                .findings
                .iter()
                .any(|finding| finding.contains("plan missing")),
            "{:?}",
            bundle.findings
        );
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(!encoded.contains("Bearer"));
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("workdir"));
        let path = root.join("bundle.json");
        write_verified(&path, &bundle).unwrap();
        let round: RecoveryBundle = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        verify(&round).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn granted_authority_fails_closed() {
        let mut bundle = RecoveryBundle {
            schema: BUNDLE_SCHEMA.into(),
            observed_at: 1,
            environment: "site-a".into(),
            plan_id: "tenkai:plan:site-a:1:abc".into(),
            plan_content_id: None,
            plan_state: None,
            fence_generation: None,
            recovery_required: false,
            releases: Vec::new(),
            findings: Vec::new(),
            authority: "apply".into(),
        };
        let err = verify(&bundle).unwrap_err().to_string();
        assert!(err.contains("must not convey execution authority"), "{err}");
        bundle.authority = NO_AUTHORITY.into();
        bundle.schema = "tenkai.recovery_bundle.v2".into();
        let err = verify(&bundle).unwrap_err().to_string();
        assert!(err.contains("unsupported recovery bundle schema"), "{err}");
    }
}

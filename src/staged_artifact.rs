//! Staged JSON product kinds: policy_bundle, eval_suite, agent_definition.
//!
//! These kinds deliver versioned descriptor documents through Catalog channels
//! and plan/apply like routing_config. Apply stages content-addressed JSON only;
//! Tenkai does not become an IdP, policy engine UI, eval runner, or agent
//! orchestrator.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::manifest::{Manifest, ProductKind};

pub const POLICY_BUNDLE_VERSION: u32 = 1;
pub const EVAL_SUITE_PRODUCT_VERSION: u32 = 1;
pub const AGENT_DEFINITION_VERSION: u32 = 1;

/// Policy document delivered as a `policy_bundle` product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleDocument {
    pub version: u32,
    pub policies: Vec<PolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntry {
    pub id: String,
    pub effect: String,
    pub action: String,
}

impl PolicyBundleDocument {
    pub fn validate(&self) -> Result<()> {
        if self.version != POLICY_BUNDLE_VERSION {
            bail!(
                "unsupported policy_bundle version {}; expected {POLICY_BUNDLE_VERSION}",
                self.version
            );
        }
        if self.policies.is_empty() {
            bail!("policy_bundle must contain at least one policy");
        }
        let mut ids = std::collections::HashSet::new();
        for policy in &self.policies {
            crate::ontology::validate_identifier("policy.id", &policy.id)?;
            crate::ontology::validate_identifier("policy.action", &policy.action)?;
            if !matches!(policy.effect.as_str(), "allow" | "deny") {
                bail!("policy {} effect must be allow or deny", policy.id);
            }
            if !ids.insert(policy.id.as_str()) {
                bail!("duplicate policy id {}", policy.id);
            }
        }
        Ok(())
    }
}

/// Versioned evaluation contract delivered as an `eval_suite` product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalSuiteDocument {
    pub version: u32,
    pub suite_id: String,
    pub cases: Vec<String>,
}

impl EvalSuiteDocument {
    pub fn validate(&self) -> Result<()> {
        if self.version != EVAL_SUITE_PRODUCT_VERSION {
            bail!(
                "unsupported eval_suite product version {}; expected {EVAL_SUITE_PRODUCT_VERSION}",
                self.version
            );
        }
        crate::ontology::validate_identifier("eval_suite.suite_id", &self.suite_id)?;
        if self.cases.is_empty() {
            bail!("eval_suite must declare at least one case");
        }
        let mut seen = std::collections::HashSet::new();
        for case in &self.cases {
            crate::ontology::validate_identifier("eval_suite.case", case)?;
            if !seen.insert(case.as_str()) {
                bail!("duplicate eval_suite case {case}");
            }
        }
        Ok(())
    }
}

/// Agent runtime descriptor delivered as an `agent_definition` product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionDocument {
    pub version: u32,
    pub agent_id: String,
    pub runtime: String,
    pub entrypoint: String,
}

impl AgentDefinitionDocument {
    pub fn validate(&self) -> Result<()> {
        if self.version != AGENT_DEFINITION_VERSION {
            bail!(
                "unsupported agent_definition version {}; expected {AGENT_DEFINITION_VERSION}",
                self.version
            );
        }
        crate::ontology::validate_identifier("agent_definition.agent_id", &self.agent_id)?;
        crate::ontology::validate_identifier("agent_definition.runtime", &self.runtime)?;
        if self.entrypoint.trim().is_empty() || self.entrypoint.contains('\0') {
            bail!("agent_definition.entrypoint must be a non-empty path without NUL");
        }
        if self.entrypoint.contains("..") {
            bail!("agent_definition.entrypoint must not contain path traversal");
        }
        Ok(())
    }
}

pub fn load_policy_bundle(path: &Path) -> Result<PolicyBundleDocument> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading policy_bundle {}", path.display()))?;
    let doc: PolicyBundleDocument = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing policy_bundle {}", path.display()))?;
    doc.validate()?;
    Ok(doc)
}

pub fn load_eval_suite_document(path: &Path) -> Result<EvalSuiteDocument> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading eval_suite {}", path.display()))?;
    let doc: EvalSuiteDocument = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing eval_suite {}", path.display()))?;
    doc.validate()?;
    Ok(doc)
}

pub fn load_agent_definition(path: &Path) -> Result<AgentDefinitionDocument> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading agent_definition {}", path.display()))?;
    let doc: AgentDefinitionDocument = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing agent_definition {}", path.display()))?;
    doc.validate()?;
    Ok(doc)
}

pub fn document_digest<T: Serialize>(doc: &T) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(doc)?)))
}

/// Stages a validated JSON document atomically under a state path.
pub struct LocalStagedArtifactExecutor {
    state_path: PathBuf,
}

impl LocalStagedArtifactExecutor {
    pub fn new(state_path: PathBuf) -> Self {
        Self { state_path }
    }

    pub fn apply_json_bytes(&self, bytes: &[u8], expected_digest: &str) -> Result<String> {
        crate::atomic_state::write_bytes_verified(&self.state_path, bytes, |observed| {
            let observed_digest = format!("{:x}", Sha256::digest(observed));
            if observed_digest != expected_digest {
                bail!("staged artifact post-mutation verification failed");
            }
            Ok(())
        })?;
        Ok(expected_digest.into())
    }

    pub fn apply_serializable<T: Serialize>(&self, doc: &T) -> Result<String> {
        let bytes = serde_json::to_vec_pretty(doc)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        self.apply_json_bytes(&bytes, &digest)
    }

    pub fn remove(&self) -> Result<()> {
        crate::atomic_state::remove_if_exists(&self.state_path)
    }

    pub fn observe_digest(&self) -> Result<Option<String>> {
        match crate::atomic_state::read_optional(&self.state_path)? {
            Some(bytes) => Ok(Some(format!("{:x}", Sha256::digest(bytes)))),
            None => Ok(None),
        }
    }
}

/// Relative document path from a staged-product manifest.
pub fn staged_document_path(manifest: &Manifest) -> Result<&str> {
    match manifest.product.kind {
        ProductKind::PolicyBundle => manifest
            .policy
            .as_ref()
            .map(|s| s.document.as_str())
            .context("policy_bundle needs [policy].document"),
        ProductKind::EvalSuite => manifest
            .eval_suite_product
            .as_ref()
            .map(|s| s.document.as_str())
            .context("eval_suite needs [eval_suite_product].document"),
        ProductKind::AgentDefinition => manifest
            .agent
            .as_ref()
            .map(|s| s.document.as_str())
            .context("agent_definition needs [agent].document"),
        _ => bail!("product kind is not a staged JSON artifact"),
    }
}

pub fn validate_staged_manifest(manifest: &Manifest, workdir: &Path) -> Result<()> {
    let relative = staged_document_path(manifest)?;
    crate::manifest::validate_input_path("staged.document", relative)?;
    let path = workdir.join(relative);
    match manifest.product.kind {
        ProductKind::PolicyBundle => {
            load_policy_bundle(&path)?;
        }
        ProductKind::EvalSuite => {
            load_eval_suite_document(&path)?;
        }
        ProductKind::AgentDefinition => {
            load_agent_definition(&path)?;
        }
        _ => bail!("not a staged product kind"),
    }
    Ok(())
}

pub fn state_path_for(kind: ProductKind, base: &Path, product: &str) -> PathBuf {
    let leaf = match kind {
        ProductKind::PolicyBundle => "policy_bundle",
        ProductKind::EvalSuite => "eval_suite",
        ProductKind::AgentDefinition => "agent_definition",
        _ => "staged",
    };
    base.join(leaf).join(format!("{product}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_bundle_apply_observe_remove() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-policy-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let executor = LocalStagedArtifactExecutor::new(root.join("active.json"));
        let doc = PolicyBundleDocument {
            version: 1,
            policies: vec![PolicyEntry {
                id: "deploy-allow".into(),
                effect: "allow".into(),
                action: "deploy".into(),
            }],
        };
        doc.validate().unwrap();
        let digest = executor.apply_serializable(&doc).unwrap();
        assert_eq!(
            executor.observe_digest().unwrap().as_deref(),
            Some(digest.as_str())
        );
        executor.remove().unwrap();
        assert!(executor.observe_digest().unwrap().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn eval_suite_and_agent_validate() {
        let suite = EvalSuiteDocument {
            version: 1,
            suite_id: "gate-smoke".into(),
            cases: vec!["health".into(), "latency".into()],
        };
        suite.validate().unwrap();
        let agent = AgentDefinitionDocument {
            version: 1,
            agent_id: "ops-agent".into(),
            runtime: "local".into(),
            entrypoint: "agents/ops.toml".into(),
        };
        agent.validate().unwrap();
        let bad = AgentDefinitionDocument {
            version: 1,
            agent_id: "x".into(),
            runtime: "local".into(),
            entrypoint: "../secret".into(),
        };
        assert!(bad.validate().is_err());
    }

    #[tokio::test]
    async fn publish_plan_apply_policy_eval_and_agent_products() {
        use crate::client::Ctx;
        use crate::manifest::ProductKind;

        let root = std::env::temp_dir().join(format!(
            "tenkai-staged-e2e-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        std::fs::create_dir_all(root.join("policy")).unwrap();
        std::fs::create_dir_all(root.join("eval")).unwrap();
        std::fs::create_dir_all(root.join("agent")).unwrap();

        std::fs::write(
            root.join("policy/policy.json"),
            r#"{"version":1,"policies":[{"id":"allow-deploy","effect":"allow","action":"deploy"}]}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("policy/tenkai.toml"),
            r#"
[product]
name = "deploy-policy"
version = "1.0.0"
kind = "policy_bundle"

[policy]
document = "policy.json"
"#,
        )
        .unwrap();

        std::fs::write(
            root.join("eval/suite.json"),
            r#"{"version":1,"suite_id":"gate-smoke","cases":["health"]}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("eval/tenkai.toml"),
            r#"
[product]
name = "gate-smoke-suite"
version = "1.0.0"
kind = "eval_suite"

[eval_suite_product]
document = "suite.json"
"#,
        )
        .unwrap();

        std::fs::write(
            root.join("agent/agent.json"),
            r#"{"version":1,"agent_id":"ops-agent","runtime":"local","entrypoint":"agents/ops.toml"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("agent/tenkai.toml"),
            r#"
[product]
name = "ops-agent-def"
version = "1.0.0"
kind = "agent_definition"

[agent]
document = "agent.json"
"#,
        )
        .unwrap();

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let options = crate::catalog::PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
        };
        for name in ["policy", "eval", "agent"] {
            crate::catalog::publish(&mut ctx, &root.join(name).join("tenkai.toml"), &options)
                .await
                .unwrap();
        }
        crate::catalog::promote(&mut ctx, "deploy-policy@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, "gate-smoke-suite@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, "ops-agent-def@1.0.0", "stable")
            .await
            .unwrap();

        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "deploy-policy", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "gate-smoke-suite", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "ops-agent-def", "stable")
            .await
            .unwrap();

        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps.len(), 3);
        let kinds: Vec<_> = plan
            .steps
            .iter()
            .map(|step| {
                // product names map to kinds via published manifests
                step.product.clone()
            })
            .collect();
        assert!(kinds.contains(&"deploy-policy".to_string()));
        assert!(kinds.contains(&"gate-smoke-suite".to_string()));
        assert!(kinds.contains(&"ops-agent-def".to_string()));

        crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                approval: None,
                approval_trust_roots: None,
                unapproved_development_reason: Some("staged product e2e"),
            },
        )
        .await
        .unwrap();

        // Invalid policy fails closed at publish.
        std::fs::write(
            root.join("policy/policy.json"),
            r#"{"version":1,"policies":[]}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("policy/tenkai.toml"),
            r#"
[product]
name = "bad-policy"
version = "1.0.0"
kind = "policy_bundle"

[policy]
document = "policy.json"
"#,
        )
        .unwrap();
        let err = crate::catalog::publish(&mut ctx, &root.join("policy/tenkai.toml"), &options)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("policy_bundle") || err.contains("at least one"),
            "{err}"
        );

        let _ = ProductKind::PolicyBundle;
        let _ = std::fs::remove_dir_all(root);
    }
}

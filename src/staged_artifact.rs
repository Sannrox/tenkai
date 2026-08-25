//! Staged JSON product kinds: policy_bundle, eval_suite, agent_definition,
//! prompt_package.
//!
//! These kinds deliver versioned descriptor documents through Catalog channels
//! and plan/apply like routing_config. Apply stages content-addressed JSON only;
//! Tenkai does not become an IdP, policy engine UI, eval runner, or agent
//! orchestrator.
//!
//! Callers use a small interface ([`is_staged_kind`], [`activate`],
//! [`deactivate`], [`validate_staged_manifest`]). Kind-specific document
//! paths, state namespaces, and schema validators stay local to this module
//! so dispatch does not reappear at every call site (see research #188).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::manifest::{Manifest, ProductKind};
use crate::product_kind::StagedKind;

impl StagedKind {
    fn state_namespace(self) -> &'static str {
        match self {
            Self::PolicyBundle => "policy_bundle",
            Self::EvalSuite => "eval_suite",
            Self::AgentDefinition => "agent_definition",
            Self::PromptPackage => "prompt_package",
        }
    }

    fn document_path(self, manifest: &Manifest) -> Result<&str> {
        match self {
            Self::PolicyBundle => manifest
                .policy
                .as_ref()
                .map(|section| section.document.as_str())
                .context("policy_bundle needs [policy].document"),
            Self::EvalSuite => manifest
                .eval_suite_product
                .as_ref()
                .map(|section| section.document.as_str())
                .context("eval_suite needs [eval_suite_product].document"),
            Self::AgentDefinition => manifest
                .agent
                .as_ref()
                .map(|section| section.document.as_str())
                .context("agent_definition needs [agent].document"),
            Self::PromptPackage => manifest
                .prompt
                .as_ref()
                .map(|section| section.document.as_str())
                .context("prompt_package needs [prompt].document"),
        }
    }

    fn load_canonical_bytes(self, path: &Path) -> Result<Vec<u8>> {
        match self {
            Self::PolicyBundle => {
                let doc = load_policy_bundle(path)?;
                Ok(serde_json::to_vec_pretty(&doc)?)
            }
            Self::EvalSuite => {
                let doc = load_eval_suite_document(path)?;
                Ok(serde_json::to_vec_pretty(&doc)?)
            }
            Self::AgentDefinition => {
                let doc = load_agent_definition(path)?;
                Ok(serde_json::to_vec_pretty(&doc)?)
            }
            Self::PromptPackage => {
                let doc = load_prompt_package(path)?;
                Ok(serde_json::to_vec_pretty(&doc)?)
            }
        }
    }

    fn validate_bytes(self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::PolicyBundle => {
                let doc: PolicyBundleDocument =
                    serde_json::from_slice(bytes).context("parsing policy_bundle document")?;
                doc.validate()
            }
            Self::EvalSuite => {
                let doc: EvalSuiteDocument =
                    serde_json::from_slice(bytes).context("parsing eval_suite document")?;
                doc.validate()
            }
            Self::AgentDefinition => {
                let doc: AgentDefinitionDocument =
                    serde_json::from_slice(bytes).context("parsing agent_definition document")?;
                doc.validate()
            }
            Self::PromptPackage => {
                let doc: PromptPackageDocument =
                    serde_json::from_slice(bytes).context("parsing prompt_package document")?;
                doc.validate()
            }
        }
    }

    fn state_path(self, base: &Path, product: &str) -> PathBuf {
        base.join(self.state_namespace())
            .join(format!("{product}.json"))
    }
}

/// True when `kind` stages a versioned JSON descriptor through this module.
pub fn is_staged_kind(kind: ProductKind) -> bool {
    kind.policy().staged_kind().is_some()
}

/// Validate kind-specific document bytes without reading the filesystem.
pub fn validate_document_bytes(kind: ProductKind, bytes: &[u8]) -> Result<()> {
    let staged = kind
        .policy()
        .staged_kind()
        .context("product kind is not a staged JSON artifact")?;
    staged.validate_bytes(bytes)
}

/// Load, validate, and atomically stage the document for a staged product.
///
/// Resolves the kind-specific document path, re-canonicalizes through the
/// typed schema, and writes under the kind's state namespace.
pub fn activate(
    manifest: &Manifest,
    workdir: &Path,
    state_root: &Path,
    product: &str,
) -> Result<()> {
    let staged = manifest
        .product
        .kind
        .policy()
        .staged_kind()
        .context("product kind is not a staged JSON artifact")?;
    let relative = staged.document_path(manifest)?;
    crate::manifest::validate_input_path("staged.document", relative)?;
    let bytes = staged.load_canonical_bytes(&workdir.join(relative))?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    LocalStagedArtifactExecutor::new(staged.state_path(state_root, product))
        .apply_json_bytes(&bytes, &digest)
        .map(|_| ())
}

/// Remove the staged document for `product` under the kind's state namespace.
pub fn deactivate(kind: ProductKind, state_root: &Path, product: &str) -> Result<()> {
    let staged = kind
        .policy()
        .staged_kind()
        .context("product kind is not a staged JSON artifact")?;
    LocalStagedArtifactExecutor::new(staged.state_path(state_root, product)).remove()
}

pub const POLICY_BUNDLE_VERSION: u32 = 1;
pub const EVAL_SUITE_PRODUCT_VERSION: u32 = 1;
pub const AGENT_DEFINITION_VERSION: u32 = 1;
pub const PROMPT_PACKAGE_VERSION: u32 = 1;

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

/// Versioned prompt package staged as an immutable Catalog product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptPackageDocument {
    pub version: u32,
    pub package_id: String,
    pub runtime: String,
    pub eval_suite: String,
    pub prompts: Vec<PromptEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptEntry {
    pub id: String,
    pub body: String,
}

impl PromptPackageDocument {
    pub fn validate(&self) -> Result<()> {
        if self.version != PROMPT_PACKAGE_VERSION {
            bail!(
                "unsupported prompt_package version {}; expected {PROMPT_PACKAGE_VERSION}",
                self.version
            );
        }
        crate::ontology::validate_identifier("prompt_package.package_id", &self.package_id)?;
        crate::ontology::validate_identifier("prompt_package.runtime", &self.runtime)?;
        crate::ontology::validate_identifier("prompt_package.eval_suite", &self.eval_suite)?;
        if self.prompts.is_empty() {
            bail!("prompt_package must declare at least one prompt");
        }
        let mut seen = std::collections::HashSet::new();
        for prompt in &self.prompts {
            crate::ontology::validate_identifier("prompt_package.prompt.id", &prompt.id)?;
            if !seen.insert(prompt.id.as_str()) {
                bail!("duplicate prompt id {}", prompt.id);
            }
            if prompt.body.trim().is_empty() {
                bail!("prompt {} body must not be empty", prompt.id);
            }
            if prompt.body.contains('\0') {
                bail!("prompt {} body must not contain NUL", prompt.id);
            }
            let lower = prompt.body.to_ascii_lowercase();
            if lower.contains("begin private key")
                || lower.contains("api_key")
                || lower.contains("secret_key")
            {
                bail!(
                    "prompt {} body must not contain credentials or private keys",
                    prompt.id
                );
            }
        }
        Ok(())
    }

    pub fn content_digest(&self) -> Result<String> {
        self.validate()?;
        let canonical = serde_json::to_vec(self)?;
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
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

pub fn load_prompt_package(path: &Path) -> Result<PromptPackageDocument> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading prompt_package {}", path.display()))?;
    let doc: PromptPackageDocument = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing prompt_package {}", path.display()))?;
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
    let staged = manifest
        .product
        .kind
        .policy()
        .staged_kind()
        .context("product kind is not a staged JSON artifact")?;
    staged.document_path(manifest)
}

pub fn validate_staged_manifest(manifest: &Manifest, workdir: &Path) -> Result<()> {
    let staged = manifest
        .product
        .kind
        .policy()
        .staged_kind()
        .context("not a staged product kind")?;
    let relative = staged.document_path(manifest)?;
    crate::manifest::validate_input_path("staged.document", relative)?;
    let bytes = staged.load_canonical_bytes(&workdir.join(relative))?;
    if staged == crate::product_kind::StagedKind::PromptPackage {
        let doc: PromptPackageDocument = serde_json::from_slice(&bytes)?;
        let gate = manifest
            .gate
            .eval_suite
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("prompt_package requires [gate].eval_suite"))?;
        if gate != doc.eval_suite {
            bail!(
                "prompt_package eval_suite {gate} does not match package evaluation pin {}",
                doc.eval_suite
            );
        }
    }
    Ok(())
}

pub fn state_path_for(kind: ProductKind, base: &Path, product: &str) -> PathBuf {
    match kind.policy().staged_kind() {
        Some(staged) => staged.state_path(base, product),
        None => base.join("staged").join(format!("{product}.json")),
    }
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
        let package = PromptPackageDocument {
            version: 1,
            package_id: "ops-prompts".into(),
            runtime: "local".into(),
            eval_suite: "prompt-quality".into(),
            prompts: vec![PromptEntry {
                id: "system".into(),
                body: "You are a bounded operator assistant.".into(),
            }],
        };
        package.validate().unwrap();
        assert!(package.content_digest().unwrap().starts_with("sha256:"));
        let secret = PromptPackageDocument {
            version: 1,
            package_id: "ops-prompts".into(),
            runtime: "local".into(),
            eval_suite: "prompt-quality".into(),
            prompts: vec![PromptEntry {
                id: "system".into(),
                body: "api_key=super-secret".into(),
            }],
        };
        assert!(secret.validate().is_err());
    }

    #[test]
    fn prompt_package_requires_matching_eval_gate() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-prompt-gate-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("prompt.json"),
            r#"{"version":1,"package_id":"ops-prompts","runtime":"local","eval_suite":"prompt-quality","prompts":[{"id":"system","body":"You are a bounded operator assistant."}]}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "ops-prompts"
version = "1.0.0"
kind = "prompt_package"
[prompt]
document = "prompt.json"
"#,
        )
        .unwrap();
        let err = match crate::manifest::load(&root.join("tenkai.toml")) {
            Ok(_) => panic!("expected missing eval gate to fail"),
            Err(error) => error.to_string(),
        };
        assert!(err.contains("[gate].eval_suite"), "{err}");
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "ops-prompts"
version = "1.0.0"
kind = "prompt_package"
[prompt]
document = "prompt.json"
[gate]
eval_suite = "other-suite"
"#,
        )
        .unwrap();
        let err = match crate::manifest::load(&root.join("tenkai.toml")) {
            Ok(_) => panic!("expected mismatched eval gate to fail"),
            Err(error) => error.to_string(),
        };
        assert!(err.contains("does not match"), "{err}");
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "ops-prompts"
version = "1.0.0"
kind = "prompt_package"
[prompt]
document = "prompt.json"
[gate]
eval_suite = "prompt-quality"
"#,
        )
        .unwrap();
        crate::manifest::load(&root.join("tenkai.toml")).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn activate_and_deactivate_use_kind_namespace() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-staged-activate-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let workdir = root.join("src");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::write(
            workdir.join("policy.json"),
            r#"{"version":1,"policies":[{"id":"allow-deploy","effect":"allow","action":"deploy"}]}"#,
        )
        .unwrap();
        let raw = r#"
[product]
name = "deploy-policy"
version = "1.0.0"
kind = "policy_bundle"

[policy]
document = "policy.json"
"#;
        let manifest = crate::manifest::parse_raw(raw).unwrap();
        assert!(is_staged_kind(manifest.product.kind));
        activate(&manifest, &workdir, &root.join("state"), "deploy-policy").unwrap();
        let state = state_path_for(
            ProductKind::PolicyBundle,
            &root.join("state"),
            "deploy-policy",
        );
        assert!(state.exists());
        assert!(state.to_string_lossy().contains("policy_bundle"));
        deactivate(
            ProductKind::PolicyBundle,
            &root.join("state"),
            "deploy-policy",
        )
        .unwrap();
        assert!(!state.exists());
        let _ = std::fs::remove_dir_all(root);
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
            change_set_evidence: None,
        };
        for name in ["policy", "eval", "agent"] {
            crate::catalog::publish(&mut ctx, &root.join(name).join("tenkai.toml"), &options)
                .await
                .unwrap();
        }
        let actor = crate::auth_context::test_management_context("staged-promote");
        crate::catalog::promote(&mut ctx, &actor, "deploy-policy@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "gate-smoke-suite@1.0.0", "stable")
            .await
            .unwrap();
        crate::catalog::promote(&mut ctx, &actor, "ops-agent-def@1.0.0", "stable")
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
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "staged product e2e",
                },
                software_executor: None,
                delivery_adapter: None,
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

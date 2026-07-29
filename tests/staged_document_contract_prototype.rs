//! Research-only prototype for issue #188.
//!
//! This proves that the three staged document schemas can share an internal
//! registry/validation call shape without changing their public identities.

use anyhow::Result;
use serde_json::Value;
use tenkai::manifest::{Manifest, ProductKind};
use tenkai::staged_artifact::{AgentDefinitionDocument, EvalSuiteDocument, PolicyBundleDocument};

struct StagedSchema {
    kind: ProductKind,
    document_path: for<'a> fn(&'a Manifest) -> Result<&'a str>,
    state_namespace: &'static str,
    validate_json: fn(&[u8]) -> Result<Value>,
}

fn policy_path(manifest: &Manifest) -> Result<&str> {
    Ok(manifest
        .policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("policy section is required"))?
        .document
        .as_str())
}

fn eval_path(manifest: &Manifest) -> Result<&str> {
    Ok(manifest
        .eval_suite_product
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("eval_suite_product section is required"))?
        .document
        .as_str())
}

fn agent_path(manifest: &Manifest) -> Result<&str> {
    Ok(manifest
        .agent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("agent section is required"))?
        .document
        .as_str())
}

fn validate_policy(bytes: &[u8]) -> Result<Value> {
    let document: PolicyBundleDocument = serde_json::from_slice(bytes)?;
    document.validate()?;
    Ok(serde_json::to_value(document)?)
}

fn validate_eval(bytes: &[u8]) -> Result<Value> {
    let document: EvalSuiteDocument = serde_json::from_slice(bytes)?;
    document.validate()?;
    Ok(serde_json::to_value(document)?)
}

fn validate_agent(bytes: &[u8]) -> Result<Value> {
    let document: AgentDefinitionDocument = serde_json::from_slice(bytes)?;
    document.validate()?;
    Ok(serde_json::to_value(document)?)
}

const SCHEMAS: [StagedSchema; 3] = [
    StagedSchema {
        kind: ProductKind::PolicyBundle,
        document_path: policy_path,
        state_namespace: "policy_bundle",
        validate_json: validate_policy,
    },
    StagedSchema {
        kind: ProductKind::EvalSuite,
        document_path: eval_path,
        state_namespace: "eval_suite",
        validate_json: validate_eval,
    },
    StagedSchema {
        kind: ProductKind::AgentDefinition,
        document_path: agent_path,
        state_namespace: "agent_definition",
        validate_json: validate_agent,
    },
];

fn schema(kind: ProductKind) -> &'static StagedSchema {
    SCHEMAS
        .iter()
        .find(|candidate| candidate.kind == kind)
        .expect("prototype registry covers every staged kind")
}

#[test]
fn shared_registry_preserves_typed_validation() {
    let fixtures = [
        (
            ProductKind::PolicyBundle,
            r#"
[product]
name = "deploy-policy"
version = "1.0.0"
kind = "policy_bundle"
[policy]
document = "policy.json"
"#,
            "policy.json",
            br#"{"version":1,"policies":[{"id":"allow-deploy","effect":"allow","action":"deploy"}]}"#
                .as_slice(),
        ),
        (
            ProductKind::EvalSuite,
            r#"
[product]
name = "gate-smoke-suite"
version = "1.0.0"
kind = "eval_suite"
[eval_suite_product]
document = "suite.json"
"#,
            "suite.json",
            br#"{"version":1,"suite_id":"gate-smoke","cases":["health"]}"#.as_slice(),
        ),
        (
            ProductKind::AgentDefinition,
            r#"
[product]
name = "ops-agent-def"
version = "1.0.0"
kind = "agent_definition"
[agent]
document = "agent.json"
"#,
            "agent.json",
            br#"{"version":1,"agent_id":"ops-agent","runtime":"local","entrypoint":"agents/ops.toml"}"#
                .as_slice(),
        ),
    ];

    for (kind, raw_manifest, expected_path, bytes) in fixtures {
        let descriptor = schema(kind);
        let manifest = tenkai::manifest::parse_raw(raw_manifest).unwrap();
        assert_eq!(
            (descriptor.document_path)(&manifest).unwrap(),
            expected_path
        );
        assert!(!descriptor.state_namespace.is_empty());
        (descriptor.validate_json)(bytes).unwrap();
    }

    assert!(
        (schema(ProductKind::PolicyBundle).validate_json)(br#"{"version":1,"policies":[]}"#)
            .is_err()
    );
    assert!(
        (schema(ProductKind::EvalSuite).validate_json)(
            br#"{"version":1,"suite_id":"gate-smoke","cases":["health","health"]}"#
        )
        .is_err()
    );
    assert!(
        (schema(ProductKind::AgentDefinition).validate_json)(
            br#"{"version":1,"agent_id":"ops-agent","runtime":"local","entrypoint":"../secret"}"#
        )
        .is_err()
    );
}

//! Regression for issue #188: staged kinds share one production mapping.
//!
//! Public product identities stay separate; document path, state namespace, and
//! typed validation are resolved through the `staged_artifact` interface.

use std::path::Path;

use tenkai::manifest::ProductKind;
use tenkai::staged_artifact::{
    is_staged_kind, staged_document_path, state_path_for, validate_document_bytes,
};

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
            "policy_bundle",
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
            "eval_suite",
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
            "agent_definition",
            br#"{"version":1,"agent_id":"ops-agent","runtime":"local","entrypoint":"agents/ops.toml"}"#
                .as_slice(),
        ),
    ];

    for (kind, raw_manifest, expected_path, namespace, bytes) in fixtures {
        assert!(is_staged_kind(kind));
        let manifest = tenkai::manifest::parse_raw(raw_manifest).unwrap();
        assert_eq!(staged_document_path(&manifest).unwrap(), expected_path);
        assert_eq!(
            state_path_for(kind, Path::new("/state"), "product"),
            Path::new("/state").join(namespace).join("product.json")
        );
        validate_document_bytes(kind, bytes).unwrap();
    }

    assert!(
        validate_document_bytes(ProductKind::PolicyBundle, br#"{"version":1,"policies":[]}"#)
            .is_err()
    );
    assert!(
        validate_document_bytes(
            ProductKind::EvalSuite,
            br#"{"version":1,"suite_id":"gate-smoke","cases":["health","health"]}"#
        )
        .is_err()
    );
    assert!(
        validate_document_bytes(
            ProductKind::AgentDefinition,
            br#"{"version":1,"agent_id":"ops-agent","runtime":"local","entrypoint":"../secret"}"#
        )
        .is_err()
    );
    assert!(!is_staged_kind(ProductKind::Software));
    assert!(
        validate_document_bytes(ProductKind::Software, b"{}")
            .unwrap_err()
            .to_string()
            .contains("not a staged JSON artifact")
    );
}

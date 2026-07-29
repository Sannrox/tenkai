//! Research-only read-model prototype for issue #189.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutPolicyViewV1 {
    schema: String,
    selection: SelectionRefs,
    authorization: AuthorizationRefs,
    scheduling: SchedulingRefs,
    observation: ObservationRefs,
    recovery: RecoveryRefs,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionRefs {
    channel: String,
    subscription: String,
    constraints: Vec<String>,
    facts: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRefs {
    release_evidence: String,
    plan_approval: String,
    canary_policy: Option<String>,
    emergency_decision: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulingRefs {
    maintenance_revision: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationRefs {
    plan: String,
    health: String,
    wave_environments: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRefs {
    rollback: Option<String>,
    reconciliation: String,
}

#[test]
fn one_view_still_requires_every_independent_authority() {
    let raw = r#"{
      "schema": "tenkai.rollout-policy-view.v1",
      "selection": {
        "channel": "tenkai:channel:api/stable",
        "subscription": "tenkai:environment:prod->api/stable",
        "constraints": ["constraint.version_range.api"],
        "facts": ["architecture", "memory_gib"]
      },
      "authorization": {
        "release_evidence": "tenkai:release:api@2.0.0",
        "plan_approval": "tenkai:approval:prod-plan",
        "canary_policy": "tenkai:canary-policy:api/stable",
        "emergency_decision": "tenkai:action:emergency-start"
      },
      "scheduling": {
        "maintenance_revision": "tenkai:maintenance:prod@revision"
      },
      "observation": {
        "plan": "tenkai:plan:prod",
        "health": "tenkai:deployment:prod/api",
        "wave_environments": ["canary", "stage", "prod"]
      },
      "recovery": {
        "rollback": "tenkai:rollback:prod/api",
        "reconciliation": "tenkai:environment:prod"
      }
    }"#;

    let view: RolloutPolicyViewV1 = serde_json::from_str(raw).unwrap();
    assert_eq!(view.schema, "tenkai.rollout-policy-view.v1");
    assert!(!view.selection.channel.is_empty());
    assert!(!view.selection.subscription.is_empty());
    assert!(!view.selection.constraints.is_empty());
    assert!(!view.selection.facts.is_empty());
    assert!(view.authorization.canary_policy.is_some());
    assert!(view.authorization.emergency_decision.is_some());
    assert!(!view.scheduling.maintenance_revision.is_empty());
    assert_eq!(
        view.observation.wave_environments,
        ["canary", "stage", "prod"]
    );
    assert!(view.recovery.rollback.is_some());

    let unknown = raw.replace(
        r#""schema": "tenkai.rollout-policy-view.v1","#,
        r#""schema": "tenkai.rollout-policy-view.v1", "execute": true,"#,
    );
    assert!(serde_json::from_str::<RolloutPolicyViewV1>(&unknown).is_err());
}

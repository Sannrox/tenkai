//! Bounded approval brief computed at planning and covered by the plan digest (#1089).
//!
//! Risky-change codes are a fixed list, not heuristics: `deleted_volume` when a
//! `volumes` field drops a live volume, `changed_ports` when `ports` differ,
//! `widened_grant` when Role/ClusterRole `rules` differ.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Plan, Step};
use crate::actor_chain::{Actor, ActorKind};
use crate::client::Ctx;
use crate::pb::sekai::Object;
use crate::spec_drift::TargetChange;

/// Who proposed the plan. Copied onto the approval brief, which the digest covers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanProposer {
    pub principal: String,
    pub actor_chain: Vec<Actor>,
}

/// Bounded facts an approver reads before the full step list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBrief {
    pub proposer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ApprovalBriefActor>,
    pub blast_radius: ApprovalBriefBlast,
    pub changes: ApprovalBriefChanges,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    pub policy: ApprovalBriefPolicy,
}

/// One actor that called on behalf of the proposer, outermost first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBriefActor {
    pub id: String,
    /// `human` or `agent`.
    pub kind: String,
}

/// Environments, instances, criticality, and whether a restore pin exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBriefBlast {
    pub environment: String,
    pub instances: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub criticality: Option<String>,
    pub rollback_available: bool,
}

/// Counts of rendered target-change kinds plus flagged risky changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBriefChanges {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risky: Vec<String>,
}

/// What the live approval policy would do without a human, and the agent budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBriefPolicy {
    /// `auto` or `require_human`.
    pub without_human: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub reason: Option<String>,
    /// `inside`, `over`, or `not_configured`.
    pub budget: String,
}

const DELETED_VOLUME: &str = "deleted_volume";
const CHANGED_PORTS: &str = "changed_ports";
const WIDENED_GRANT: &str = "widened_grant";

fn actor_briefs(actors: &[Actor]) -> Vec<ApprovalBriefActor> {
    actors
        .iter()
        .map(|actor| ApprovalBriefActor {
            id: actor.id.clone(),
            kind: match actor.kind {
                ActorKind::Human => "human".into(),
                ActorKind::Agent => "agent".into(),
            },
        })
        .collect()
}

fn agent_budget(has_agent: bool, without_human: &str) -> &'static str {
    if !has_agent {
        "not_configured"
    } else if without_human == "auto" {
        "inside"
    } else {
        "over"
    }
}

/// Compute the brief for `steps` in `environment` from live policy and proposer.
/// `default_principal` is used when the ctx has no authenticated proposer
/// (`embedded` for operator plans, `reconciler` for reconcile).
pub(crate) async fn compute(
    ctx: &mut Ctx,
    environment: &str,
    env_obj: &Object,
    steps: &[Step],
    default_principal: &str,
) -> ApprovalBrief {
    let proposer = ctx.plan_proposer();
    let has_agent = proposer
        .actor_chain
        .iter()
        .any(|actor| actor.kind == ActorKind::Agent);
    let products: Vec<String> = steps
        .iter()
        .map(|step| step.product.clone())
        .filter(|name| !name.is_empty())
        .collect();
    // Blast/policy lookups are advisory: errors omit fields or force
    // require_human rather than failing plan create (skip-gates still works).
    let (criticality, criticality_ok) =
        match crate::criticality_store::effective_for_targets(ctx, environment, &products).await {
            Ok(level) => (level.map(|level| level.as_str().to_owned()), true),
            Err(_) => (None, false),
        };
    let skeleton = brief_skeleton(environment, steps);
    let (signals, signals_ok) =
        match crate::approval_policy::delivery_signals_for_plan(ctx, &skeleton).await {
            Ok(signals) => (signals, true),
            Err(_) => (crate::approval_policy::DeliverySignals::default(), false),
        };
    let (without_human, reason) =
        match crate::approval_policy::load_live_policy(&env_obj.properties) {
            Ok(None) => (
                "require_human".to_string(),
                Some("no plan approval policy".into()),
            ),
            Err(_) => (
                "require_human".to_string(),
                Some("malformed plan approval policy".into()),
            ),
            Ok(Some(_)) if !criticality_ok || !signals_ok => (
                "require_human".to_string(),
                Some("approval signals unavailable".into()),
            ),
            Ok(Some(policy)) => {
                let criticality_level = criticality
                    .as_deref()
                    .and_then(|value| crate::criticality::CriticalityLevel::parse(value).ok());
                match crate::approval_policy::evaluate(
                    &policy,
                    &skeleton,
                    false,
                    signals,
                    criticality_level,
                ) {
                    crate::approval_policy::Decision::Auto { .. } => ("auto".to_string(), None),
                    crate::approval_policy::Decision::RequireHuman { reason } => {
                        ("require_human".to_string(), Some(reason))
                    }
                }
            }
        };
    let budget = agent_budget(has_agent, &without_human);
    let mut evidence = Vec::new();
    if crate::preview::is_preview(env_obj) {
        evidence.push("preview".into());
    }
    for step in steps {
        if step_has_slo_gates(ctx, environment, step).await {
            evidence.push("gates".into());
            break;
        }
    }
    ApprovalBrief {
        proposer: if proposer.principal.is_empty() {
            default_principal.into()
        } else {
            proposer.principal
        },
        actor_chain: actor_briefs(&proposer.actor_chain),
        blast_radius: blast_radius(environment, steps, criticality),
        changes: summarize_changes(steps),
        evidence,
        policy: ApprovalBriefPolicy {
            without_human,
            reason,
            budget: budget.into(),
        },
    }
}

fn brief_skeleton(environment: &str, steps: &[Step]) -> Plan {
    Plan {
        format_version: super::PLAN_FORMAT_VERSION,
        id: String::new(),
        content_id: String::new(),
        environment: environment.into(),
        created_at: 0,
        inputs: Vec::new(),
        steps: steps.to_vec(),
        state: super::PlanState::Computed,
        gates_skipped: None,
        status_detail: String::new(),
        maintenance_blocked: false,
        prior_warnings: Vec::new(),
        recalled_recovery_reason: None,
        credential_runway: None,
        approval_brief: None,
    }
}

fn blast_radius(
    environment: &str,
    steps: &[Step],
    criticality: Option<String>,
) -> ApprovalBriefBlast {
    let mut instances = BTreeSet::new();
    let mut rollback_available = false;
    for step in steps {
        instances.insert(step.instance_name().to_string());
        if step.restore.is_some() {
            rollback_available = true;
        }
    }
    ApprovalBriefBlast {
        environment: environment.into(),
        instances: instances.into_iter().collect(),
        criticality,
        rollback_available,
    }
}

fn summarize_changes(steps: &[Step]) -> ApprovalBriefChanges {
    let mut counts = BTreeMap::new();
    let mut risky = BTreeSet::new();
    for step in steps {
        for change in &step.target_changes {
            if change.fields.is_empty() {
                continue;
            }
            *counts.entry(change.kind.clone()).or_insert(0) += 1;
            flag_risky(change, &mut risky);
        }
        if grant_widened(step) {
            risky.insert(format!("{WIDENED_GRANT}:{}", step.instance_name()));
        }
    }
    ApprovalBriefChanges {
        counts,
        risky: risky.into_iter().collect(),
    }
}

fn flag_risky(change: &TargetChange, risky: &mut BTreeSet<String>) {
    for field in &change.fields {
        let code = match field.field.as_str() {
            "volumes" if volume_deleted(field.from.as_deref(), field.to.as_deref()) => {
                DELETED_VOLUME
            }
            "ports" => CHANGED_PORTS,
            "rules" if matches!(change.kind.as_str(), "Role" | "ClusterRole") => WIDENED_GRANT,
            _ => continue,
        };
        risky.insert(format!("{code}:{} {}", change.kind, change.name));
    }
}

fn volume_deleted(from: Option<&str>, to: Option<&str>) -> bool {
    let Some(from_names) = volume_names(from) else {
        return false;
    };
    // A hashed or otherwise unreadable `to` is unknown, not an empty set.
    let Some(to_names) = (match to {
        None => Some(BTreeSet::new()),
        Some(_) => volume_names(to),
    }) else {
        return false;
    };
    from_names.iter().any(|name| !to_names.contains(name))
}

fn volume_names(rendered: Option<&str>) -> Option<BTreeSet<String>> {
    let rendered = rendered?.trim();
    if rendered.is_empty() {
        return Some(BTreeSet::new());
    }
    let value: Value = serde_json::from_str(rendered).ok()?;
    let array = value.as_array()?;
    let mut names = BTreeSet::new();
    for item in array {
        let name = match item {
            Value::String(name) => name.as_str(),
            Value::Object(_) => item.get("name")?.as_str()?,
            _ => return None,
        };
        if !name.is_empty() {
            names.insert(name.to_string());
        }
    }
    Some(names)
}

/// True when a non-empty SLO spec applies. Overlay, digest, and parse errors
/// omit `gates` evidence so they cannot abort planning.
async fn step_has_slo_gates(ctx: &mut Ctx, environment: &str, step: &Step) -> bool {
    if !step.deploys_release() {
        return false;
    }
    match crate::health_gate::step_requires_slo_evaluation(ctx, environment, step).await {
        Ok(true) => {}
        _ => return false,
    }
    let Ok(gate) =
        crate::health_gate::load_release_gate_section(ctx, &step.release_id, &step.release_digest)
            .await
    else {
        return false;
    };
    crate::health_gate::resolve_spec(ctx, environment, &step.product, &gate)
        .await
        .is_ok_and(|spec| !spec.is_empty())
}

fn grant_widened(step: &Step) -> bool {
    let Some(identity) = &step.identity else {
        return false;
    };
    let Some(restore) = &step.restore_identity else {
        return !identity.peers.is_empty();
    };
    identity.peers.servers.len() > restore.peers.servers.len()
        || identity
            .peers
            .clients
            .values()
            .map(BTreeSet::len)
            .sum::<usize>()
            > restore
                .peers
                .clients
                .values()
                .map(BTreeSet::len)
                .sum::<usize>()
}

/// Human lines for the brief, printed before step detail.
pub fn render(brief: &ApprovalBrief) -> Vec<String> {
    let mut lines = vec![format!("proposer: {}", brief.proposer)];
    if !brief.actor_chain.is_empty() {
        let actors: Vec<String> = brief
            .actor_chain
            .iter()
            .map(|actor| format!("{} ({})", actor.id, actor.kind))
            .collect();
        lines.push(format!("actor chain: {}", actors.join(", ")));
    }
    lines.push(format!(
        "policy: {}{}",
        brief.policy.without_human,
        brief
            .policy
            .reason
            .as_deref()
            .map(|reason| format!(" ({reason})"))
            .unwrap_or_default()
    ));
    lines.push(format!("budget: {}", brief.policy.budget));
    let instances = if brief.blast_radius.instances.is_empty() {
        "-".into()
    } else {
        brief.blast_radius.instances.join(",")
    };
    lines.push(format!(
        "blast: env={} instances={} criticality={} rollback={}",
        brief.blast_radius.environment,
        instances,
        brief.blast_radius.criticality.as_deref().unwrap_or("-"),
        if brief.blast_radius.rollback_available {
            "yes"
        } else {
            "no"
        }
    ));
    if !brief.changes.counts.is_empty() {
        let counts: Vec<String> = brief
            .changes
            .counts
            .iter()
            .map(|(kind, count)| format!("{kind}:{count}"))
            .collect();
        lines.push(format!("changes: {}", counts.join(" ")));
    }
    if !brief.changes.risky.is_empty() {
        lines.push(format!("risky: {}", brief.changes.risky.join(", ")));
    }
    if !brief.evidence.is_empty() {
        lines.push(format!("evidence: {}", brief.evidence.join(", ")));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Action;
    use crate::spec_drift::TargetFieldChange;

    fn step_with_changes(target_changes: Vec<TargetChange>) -> Step {
        Step {
            id: "s".into(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: Action::Upgrade,
            from: Some("1.0.0".into()),
            to: "2.0.0".into(),
            release_id: "tenkai:release:api@2.0.0".into(),
            release_digest: "d".into(),
            artifact_digest: "a".into(),
            workdir: "/srv".into(),
            restore: None,
            host: None,
            sealed: Vec::new(),
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
            target_changes,
        }
    }

    #[test]
    fn a_plan_that_deletes_a_volume_flags_it() {
        let desired = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [{"name": "config", "configMap": {"name": "app"}}]
            }}}
        });
        let live = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [
                    {"name": "config", "configMap": {"name": "app"}},
                    {"name": "cache", "emptyDir": {}}
                ]
            }}}
        });
        let dropped =
            crate::spec_drift::compare_desired_live("Deployment", "web", &desired, Some(&live));
        let added =
            crate::spec_drift::compare_desired_live("Deployment", "web", &live, Some(&desired));
        let source_changed_desired = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [{"name": "config", "configMap": {"name": "app2"}}]
            }}}
        });
        let source_changed = crate::spec_drift::compare_desired_live(
            "Deployment",
            "web",
            &source_changed_desired,
            Some(&desired),
        );
        let source_from = source_changed.fields[0].from.as_deref().unwrap();
        let source_to = source_changed.fields[0].to.as_deref().unwrap();
        assert_ne!(source_from, source_to, "{source_changed:?}");
        assert!(!source_from.contains("app2"), "{source_from}");
        assert!(source_to.contains("app2"), "{source_to}");
        assert_eq!(
            summarize_changes(&[step_with_changes(vec![dropped])]).risky,
            vec!["deleted_volume:Deployment web".to_string()]
        );
        assert!(
            summarize_changes(&[step_with_changes(vec![added])])
                .risky
                .is_empty()
        );
        assert!(
            summarize_changes(&[step_with_changes(vec![source_changed])])
                .risky
                .is_empty()
        );
        let many_live = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [
                    {"name": "cache", "emptyDir": {}},
                    {"name": "config", "configMap": {"name": "app"}},
                    {"name": "data", "emptyDir": {}},
                    {"name": "logs", "emptyDir": {}}
                ]
            }}}
        });
        let many_desired = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [
                    {"name": "cache", "emptyDir": {}},
                    {"name": "config", "configMap": {"name": "app"}},
                    {"name": "data", "emptyDir": {}}
                ]
            }}}
        });
        let dropped_many = crate::spec_drift::compare_desired_live(
            "Deployment",
            "web",
            &many_desired,
            Some(&many_live),
        );
        assert!(
            dropped_many.fields[0]
                .from
                .as_deref()
                .is_some_and(|from| !from.starts_with("sha256:")),
            "{dropped_many:?}"
        );
        assert_eq!(
            summarize_changes(&[step_with_changes(vec![dropped_many])]).risky,
            vec!["deleted_volume:Deployment web".to_string()]
        );
        let added_many = crate::spec_drift::compare_desired_live(
            "Deployment",
            "web",
            &many_live,
            Some(&many_desired),
        );
        assert!(
            summarize_changes(&[step_with_changes(vec![added_many])])
                .risky
                .is_empty()
        );
        let source_changed_many_desired = serde_json::json!({
            "spec": {"template": {"spec": {
                "containers": [{"name": "app", "image": "app:1"}],
                "volumes": [
                    {"name": "cache", "emptyDir": {}},
                    {"name": "config", "secret": {"secretName": "app"}},
                    {"name": "data", "emptyDir": {}},
                    {"name": "logs", "emptyDir": {}}
                ]
            }}}
        });
        let source_changed_many = crate::spec_drift::compare_desired_live(
            "Deployment",
            "web",
            &source_changed_many_desired,
            Some(&many_live),
        );
        let many_from = source_changed_many.fields[0].from.as_deref().unwrap();
        let many_to = source_changed_many.fields[0].to.as_deref().unwrap();
        assert_ne!(many_from, many_to, "{source_changed_many:?}");
        assert!(
            many_from.starts_with("sha256:") && many_to.starts_with("sha256:"),
            "{source_changed_many:?}"
        );
        assert!(
            summarize_changes(&[step_with_changes(vec![source_changed_many])])
                .risky
                .is_empty()
        );
        let hashed = TargetChange {
            kind: "Deployment".into(),
            name: "web".into(),
            fields: vec![TargetFieldChange {
                field: "volumes".into(),
                from: Some(r#"["cache","config"]"#.into()),
                to: Some("sha256:deadbeef".into()),
            }],
            field_count: None,
            live_digest: "sha256:live".into(),
        };
        assert!(
            summarize_changes(&[step_with_changes(vec![hashed])])
                .risky
                .is_empty()
        );
    }

    #[test]
    fn role_rule_changes_flag_widened_grant() {
        let role = TargetChange {
            kind: "Role".into(),
            name: "reader".into(),
            fields: vec![TargetFieldChange {
                field: "rules".into(),
                from: Some("[*]".into()),
                to: Some("[get]".into()),
            }],
            field_count: None,
            live_digest: "sha256:live".into(),
        };
        let ingress = TargetChange {
            kind: "Ingress".into(),
            name: "web".into(),
            fields: vec![TargetFieldChange {
                field: "rules".into(),
                from: Some("old".into()),
                to: Some("new".into()),
            }],
            field_count: None,
            live_digest: "sha256:live".into(),
        };
        assert_eq!(
            summarize_changes(&[step_with_changes(vec![role])]).risky,
            vec!["widened_grant:Role reader".to_string()]
        );
        assert!(
            summarize_changes(&[step_with_changes(vec![ingress])])
                .risky
                .is_empty()
        );
    }

    #[test]
    fn an_agent_proposed_plan_records_the_chain_and_budget() {
        let proposer = PlanProposer {
            principal: "user-1".into(),
            actor_chain: vec![Actor {
                id: "assistant-7".into(),
                kind: ActorKind::Agent,
            }],
        };
        let actor_chain = actor_briefs(&proposer.actor_chain);
        assert_eq!(actor_chain[0].id, "assistant-7");
        assert_eq!(actor_chain[0].kind, "agent");
        assert_eq!(agent_budget(true, "require_human"), "over");
        assert_eq!(agent_budget(true, "auto"), "inside");
        assert_eq!(agent_budget(false, "require_human"), "not_configured");
        let brief = ApprovalBrief {
            proposer: proposer.principal.clone(),
            actor_chain,
            blast_radius: ApprovalBriefBlast {
                environment: "prod".into(),
                instances: vec!["api".into()],
                criticality: Some("high".into()),
                rollback_available: true,
            },
            changes: ApprovalBriefChanges {
                counts: BTreeMap::new(),
                risky: Vec::new(),
            },
            evidence: Vec::new(),
            policy: ApprovalBriefPolicy {
                without_human: "require_human".into(),
                reason: Some("policy mode is manual".into()),
                budget: "over".into(),
            },
        };
        let rendered = render(&brief);
        assert_eq!(rendered[0], "proposer: user-1");
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("assistant-7 (agent)"))
        );
        assert!(rendered.iter().any(|line| line.contains("budget: over")));
    }

    async fn compute_brief(policy_path: Option<&std::path::Path>, step: Step) -> ApprovalBrief {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-brief-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ctx = crate::client::Ctx::embedded(dir.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "local", "brief")
            .await
            .unwrap();
        let mut env_obj = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        if let Some(path) = policy_path {
            env_obj.properties.insert(
                crate::approval_policy::PLAN_APPROVAL_POLICY_PROPERTY.into(),
                path.to_string_lossy().into(),
            );
        }
        compute(&mut ctx, "local", &env_obj, &[step], "embedded").await
    }

    #[tokio::test]
    async fn gate_lookup_errors_do_not_block_the_brief() {
        let brief = compute_brief(None, step_with_changes(Vec::new())).await;
        assert!(!brief.evidence.iter().any(|item| item == "gates"));
        assert_eq!(
            brief.policy.reason.as_deref(),
            Some("no plan approval policy")
        );
    }

    #[tokio::test]
    async fn a_malformed_policy_is_named_in_the_brief() {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-brief-policy-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "this is not a plan approval policy").unwrap();
        let brief = compute_brief(Some(&policy), step_with_changes(Vec::new())).await;
        assert_eq!(
            brief.policy.reason.as_deref(),
            Some("malformed plan approval policy")
        );
    }
}

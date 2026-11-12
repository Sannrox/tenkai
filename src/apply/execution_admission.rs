//! Plan freshness admission shared by reconciliation and final execution.

use std::fmt;

use anyhow::Result;

use crate::client::Ctx;
use crate::ontology::env_id;
use crate::plan::{Action, Plan};

/// Reconciliation only needs to know whether an approved computed Plan still
/// describes current operational state. Final execution preserves the exact
/// rejection through [`admit`] immediately before mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateAdmission {
    Admissible,
    Superseded,
}

#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    EnvironmentMissing,
    DeploymentUnknown {
        product: String,
    },
    DeploymentChanged {
        product: String,
        expected: Option<String>,
        actual: Option<String>,
    },
    ChannelMissing {
        channel_id: String,
    },
    ChannelMoved {
        product: String,
        channel: String,
    },
    PreviewClosed {
        detail: String,
    },
    Resubscribed {
        product: String,
    },
    Unsubscribed {
        product: String,
    },
    BindingsChanged {
        product: String,
    },
    SealedChanged {
        product: String,
    },
}

impl fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvironmentMissing => write!(formatter, "environment not found"),
            Self::DeploymentUnknown { product } => write!(
                formatter,
                "cannot apply {product} while its deployment state is unknown; reconcile or roll back first"
            ),
            Self::DeploymentChanged {
                product,
                expected,
                actual,
            } => write!(
                formatter,
                "is stale for {product}: expected deployed version {expected:?}, found {actual:?}"
            ),
            Self::ChannelMissing { channel_id } => {
                write!(formatter, "channel {channel_id} not found")
            }
            Self::ChannelMoved { product, channel } => write!(
                formatter,
                "is stale for {product}: channel {channel} no longer selects the approved release"
            ),
            Self::PreviewClosed { detail } => write!(formatter, "{detail}"),
            Self::Resubscribed { product } => write!(
                formatter,
                "is stale for {product}: the environment subscribes to it again"
            ),
            Self::Unsubscribed { product } => write!(
                formatter,
                "is stale for {product}: the environment no longer subscribes to it"
            ),
            Self::BindingsChanged { product } => write!(
                formatter,
                "is stale for {product}: dependency bindings changed"
            ),
            Self::SealedChanged { product } => {
                write!(formatter, "is stale for {product}: sealed secrets changed")
            }
        }
    }
}

pub(crate) async fn classify_candidate(ctx: &mut Ctx, plan: &Plan) -> Result<CandidateAdmission> {
    Ok(match inspect(ctx, plan).await? {
        Ok(()) => CandidateAdmission::Admissible,
        Err(_) => CandidateAdmission::Superseded,
    })
}

pub(super) async fn admit(ctx: &mut Ctx, plan: &Plan) -> Result<()> {
    // Only a runtime holds a sealing key, so only a runtime re-wraps.
    if let Some(step) = plan.steps.iter().find(|step| step.rewrap.is_some()) {
        anyhow::bail!(
            "plan {} step {} re-wraps sealed values; only an environment runtime in built-in mode runs it",
            plan.id,
            step.id
        );
    }
    // The issuing key exists unsealed only inside runtimes, so the server
    // never issues a certificate, even for an environment without a separate
    // runtime (ADR 0046 §8).
    if let Some((step, what)) = plan.steps.iter().find_map(|step| {
        if step.issuer.is_some() {
            Some((step, "activates an identity issuer"))
        } else if step.identity_grants().next().is_some() {
            Some((step, "issues a workload certificate"))
        } else {
            None
        }
    }) {
        anyhow::bail!(
            "plan {} step {} {what}, and the server never holds the issuing key; enroll an environment runtime in built-in mode that names workload_identity to run it",
            plan.id,
            step.id
        );
    }
    inspect(ctx, plan)
        .await?
        .map_err(|rejection| anyhow::anyhow!("plan {} {rejection}", plan.id))
}

async fn inspect(ctx: &mut Ctx, plan: &Plan) -> Result<Result<(), Rejection>> {
    let Some(environment) = ctx.get(&env_id(&plan.environment)).await? else {
        return Ok(Err(Rejection::EnvironmentMissing));
    };
    if let Err(error) = crate::preview::admit_plan(&environment, crate::now_millis()) {
        return Ok(Err(Rejection::PreviewClosed {
            detail: error.to_string(),
        }));
    }
    // A removal is planned because the environment stopped subscribing to
    // the instance, and everything else because it subscribes: either is
    // stale once that changed.
    let subscriptions = crate::environment::list_subscriptions(ctx, &environment).await?;
    if let Some(input) = plan.inputs.iter().find(|input| {
        !subscriptions
            .iter()
            .any(|sub| sub.channel.id == input.channel_id && sub.instance == input.instance_name())
    }) {
        return Ok(Err(Rejection::Unsubscribed {
            product: input.product.clone(),
        }));
    }
    if plan.steps.iter().any(|step| step.action == Action::Remove) {
        let subscribed: Vec<&str> = subscriptions
            .iter()
            .map(|sub| sub.instance.as_str())
            .collect();
        if let Some(step) = plan.steps.iter().find(|step| {
            step.action == Action::Remove && subscribed.contains(&step.instance_name())
        }) {
            return Ok(Err(Rejection::Resubscribed {
                product: step.product.clone(),
            }));
        }
    }
    for step in &plan.steps {
        let instance = step.instance_name();
        // The plan digest and its approval cover the sealed digests a step
        // names; a rotation since then needs its own plan.
        if step.action != Action::Remove
            && crate::sealed_secret::step_bindings(&environment, instance)
                .ok()
                .as_ref()
                != Some(&step.sealed)
        {
            return Ok(Err(Rejection::SealedChanged {
                product: step.product.clone(),
            }));
        }
        // The root-side applier admits a host step only at the generation
        // and from the release its own record names, so the server's view,
        // unknown after a failed host step, does not hold it back.
        if step.host.is_some() {
            continue;
        }
        // A removal that failed left the deployment unknown; its retry
        // removes exactly the recorded failed target (ADR 0049).
        let retried_removal = step.action == Action::Remove
            && step.from.is_none()
            && environment
                .properties
                .get(&format!("failed_target.{instance}"))
                == Some(&step.release_id);
        if step.action != Action::Rollback
            && !retried_removal
            && environment
                .properties
                .get(&format!("deployment_health.{instance}"))
                .is_some_and(|health| health == "unknown")
        {
            return Ok(Err(Rejection::DeploymentUnknown {
                product: step.product.clone(),
            }));
        }
        let actual = environment.properties.get(&format!("deployed.{instance}"));
        if actual != step.from.as_ref() {
            return Ok(Err(Rejection::DeploymentChanged {
                product: step.product.clone(),
                expected: step.from.clone(),
                actual: actual.cloned(),
            }));
        }
    }
    for input in &plan.inputs {
        let Some(channel) = ctx.get(&input.channel_id).await? else {
            return Ok(Err(Rejection::ChannelMissing {
                channel_id: input.channel_id.clone(),
            }));
        };
        let channel_version = channel
            .properties
            .get("current_version")
            .map(String::as_str)
            .unwrap_or_default();
        let channel_release = channel
            .properties
            .get("current_release")
            .map(String::as_str)
            .unwrap_or_default();
        if channel_version.is_empty() || channel_release.is_empty() {
            return Ok(Err(Rejection::ChannelMoved {
                product: input.product.clone(),
                channel: input.channel.clone(),
            }));
        }
        // DesiredStateInput stores the constrained selection, which may differ
        // from the raw channel head (version pins / model-runtime variants).
        let selected = crate::plan::resolve_subscription_selection(
            ctx,
            &environment,
            &plan.environment,
            &input.product,
            channel_version,
            channel_release,
        )
        .await?;
        if selected.0 != input.desired_version || selected.1 != input.release_id {
            return Ok(Err(Rejection::ChannelMoved {
                product: input.product.clone(),
                channel: input.channel.clone(),
            }));
        }
        let live = crate::environment_bindings::EnvironmentBindings::from_properties(
            &environment.properties,
        )
        .for_dependent(input.instance_name());
        if live != input.providers {
            return Ok(Err(Rejection::BindingsChanged {
                product: input.product.clone(),
            }));
        }
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, NS, REL_SUBSCRIBES, channel_id};
    use crate::pb::sekai::Object;
    use crate::plan::{DesiredStateInput, PLAN_FORMAT_VERSION, PlanState, Step};

    fn object(id: String, kind: &str, name: &str, properties: HashMap<String, String>) -> Object {
        Object {
            id,
            kind: kind.into(),
            name: name.into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties,
            created: 1,
            updated: 1,
        }
    }

    fn plan() -> Plan {
        let channel_id = channel_id("api", "stable");
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: "tenkai:plan:prod:test".into(),
            content_id: "content".into(),
            environment: "prod".into(),
            created_at: 1,
            inputs: vec![DesiredStateInput {
                product: "api".into(),

                instance: String::new(),
                channel: "stable".into(),
                channel_id,
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "release-digest".into(),
                artifact_digest: "artifact-digest".into(),
                deployed_version: Some("1.0.0".into()),
                providers: Default::default(),
            }],
            steps: vec![Step {
                id: "tenkai:plan:prod:test:step:0".into(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: Action::Upgrade,
                from: Some("1.0.0".into()),
                to: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "release-digest".into(),
                artifact_digest: "artifact-digest".into(),
                workdir: "/srv/api".into(),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        }
    }

    fn context(name: &str) -> Ctx {
        let database = std::env::temp_dir().join(format!(
            "tenkai-execution-admission-{name}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ));
        let _ = std::fs::remove_file(&database);
        Ctx::embedded(database).unwrap()
    }

    async fn put_current_state(ctx: &mut Ctx) {
        ctx.put(object(
            env_id("prod"),
            KIND_ENVIRONMENT,
            "prod",
            HashMap::from([("deployed.api".into(), "1.0.0".into())]),
        ))
        .await
        .unwrap();
        ctx.put(object(
            channel_id("api", "stable"),
            KIND_CHANNEL,
            "api/stable",
            HashMap::from([
                ("current_version".into(), "2.0.0".into()),
                ("current_release".into(), "tenkai:release:api@2.0.0".into()),
            ]),
        ))
        .await
        .unwrap();
        ctx.link(
            &env_id("prod"),
            &channel_id("api", "stable"),
            REL_SUBSCRIBES,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn current_plan_is_admissible_to_selection_and_execution() {
        let mut ctx = context("current");
        put_current_state(&mut ctx).await;
        let plan = plan();
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Admissible
        );
        admit(&mut ctx, &plan).await.unwrap();
    }

    #[tokio::test]
    async fn an_identity_plan_in_an_environment_without_a_separate_runtime_is_refused() {
        use crate::workload_identity::{CertificateRole, IdentityGrant, Reload};

        let mut ctx = context("identity");
        put_current_state(&mut ctx).await;
        let mut plan = plan();
        plan.steps[0].identity = Some(IdentityGrant {
            uri: "tenkai://prod/api".into(),
            dns_names: vec!["api.prod.svc".into()],
            certificate: CertificateRole::Server,
            reload: Reload::Restart,
            issuer_generation: 1,
            issuer_fingerprint: "sha256:issuer".into(),
            peers: Default::default(),
        });
        let error = admit(&mut ctx, &plan).await.unwrap_err().to_string();
        assert!(
            error.contains("issues a workload certificate")
                && error.contains("enroll an environment runtime"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn changed_bindings_are_superseded_but_actionable_at_execution() {
        let mut ctx = context("changed-bindings");
        put_current_state(&mut ctx).await;
        let mut plan = plan();
        plan.inputs[0]
            .providers
            .insert("database".into(), "db-a".into());
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Superseded
        );
        assert!(
            admit(&mut ctx, &plan)
                .await
                .unwrap_err()
                .to_string()
                .contains("dependency bindings changed")
        );
        let mut environment = ctx.get(&env_id("prod")).await.unwrap().unwrap();
        environment.properties.insert(
            crate::environment_bindings::binding_key("api", "database"),
            "db-a".into(),
        );
        ctx.put(environment).await.unwrap();
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Admissible
        );
    }

    #[tokio::test]
    async fn missing_environment_is_superseded_but_actionable_at_execution() {
        let mut ctx = context("missing-environment");
        let plan = plan();
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Superseded
        );
        assert_eq!(
            admit(&mut ctx, &plan).await.unwrap_err().to_string(),
            "plan tenkai:plan:prod:test environment not found"
        );
    }

    #[tokio::test]
    async fn unknown_deployment_is_superseded_but_actionable_at_execution() {
        let mut ctx = context("unknown-deployment");
        put_current_state(&mut ctx).await;
        let mut environment = ctx.get(&env_id("prod")).await.unwrap().unwrap();
        environment
            .properties
            .insert("deployment_health.api".into(), "unknown".into());
        ctx.put(environment).await.unwrap();
        let plan = plan();
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Superseded
        );
        assert!(
            admit(&mut ctx, &plan)
                .await
                .unwrap_err()
                .to_string()
                .contains("deployment state is unknown")
        );
    }

    #[tokio::test]
    async fn changed_deployment_is_superseded_but_actionable_at_execution() {
        let mut ctx = context("changed-deployment");
        put_current_state(&mut ctx).await;
        let mut environment = ctx.get(&env_id("prod")).await.unwrap().unwrap();
        environment
            .properties
            .insert("deployed.api".into(), "1.1.0".into());
        ctx.put(environment).await.unwrap();
        let plan = plan();
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Superseded
        );
        assert!(
            admit(&mut ctx, &plan)
                .await
                .unwrap_err()
                .to_string()
                .contains("expected deployed version Some(\"1.0.0\"), found Some(\"1.1.0\")")
        );
    }

    #[tokio::test]
    async fn moved_channel_is_superseded_but_actionable_at_execution() {
        let mut ctx = context("moved-channel");
        put_current_state(&mut ctx).await;
        let mut channel = ctx
            .get(&channel_id("api", "stable"))
            .await
            .unwrap()
            .unwrap();
        channel
            .properties
            .insert("current_version".into(), "3.0.0".into());
        ctx.put(channel).await.unwrap();
        let plan = plan();
        assert_eq!(
            classify_candidate(&mut ctx, &plan).await.unwrap(),
            CandidateAdmission::Superseded
        );
        assert!(
            admit(&mut ctx, &plan)
                .await
                .unwrap_err()
                .to_string()
                .contains("channel stable no longer selects")
        );
    }

    #[tokio::test]
    async fn torn_down_preview_is_refused_at_apply_admission() {
        let mut ctx = context("preview-torn-down");
        crate::ontology::register(&mut ctx).await.unwrap();
        let pin = crate::preview::BranchPin {
            contract: crate::preview::PIN_CONTRACT.into(),
            namespace: "acme".into(),
            branch_id: "types".into(),
            head_revision: "rev-1".into(),
            pin_digest: format!("sha256:{}", "a".repeat(64)),
        };
        crate::preview::provision(
            &mut ctx,
            "review",
            pin,
            crate::now_millis() + 86_400_000,
            "",
            1_000,
        )
        .await
        .unwrap();
        crate::preview::close_branch(&mut ctx, "review", 2_000)
            .await
            .unwrap();

        let leftover = Plan {
            format_version: PLAN_FORMAT_VERSION,
            id: "tenkai:plan:review:leftover".into(),
            content_id: "content".into(),
            environment: "review".into(),
            created_at: 1,
            inputs: Vec::new(),
            steps: vec![Step {
                id: "tenkai:plan:review:leftover:step:0".into(),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: Action::Rollback,
                from: Some("2.0.0".into()),
                to: "1.0.0".into(),
                release_id: "tenkai:release:api@1.0.0".into(),
                release_digest: "digest".into(),
                artifact_digest: "artifact".into(),
                workdir: "/srv/api".into(),
                host: None,
                sealed: Vec::new(),
                restore: None,
                rewrap: None,
                issuer: None,
                identity: None,
                restore_identity: None,
                target_changes: Vec::new(),
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        };
        assert_eq!(
            classify_candidate(&mut ctx, &leftover).await.unwrap(),
            CandidateAdmission::Superseded
        );
        let error = admit(&mut ctx, &leftover).await.unwrap_err().to_string();
        assert!(error.contains("torn down"), "{error}");
    }

    #[tokio::test]
    async fn version_pin_below_channel_head_remains_admissible() {
        let mut ctx = context("version-pin");
        put_current_state(&mut ctx).await;
        ctx.put(object(
            "tenkai:release:api@1.0.0".into(),
            "tenkai.release",
            "api@1.0.0",
            HashMap::from([("version".into(), "1.0.0".into())]),
        ))
        .await
        .unwrap();
        let mut environment = ctx.get(&env_id("prod")).await.unwrap().unwrap();
        environment
            .properties
            .insert("constraint.version_pin.api".into(), "1.0.0".into());
        environment
            .properties
            .insert("deployed.api".into(), "0.9.0".into());
        ctx.put(environment).await.unwrap();

        let mut pinned = plan();
        pinned.inputs[0].desired_version = "1.0.0".into();
        pinned.inputs[0].release_id = "tenkai:release:api@1.0.0".into();
        pinned.inputs[0].deployed_version = Some("0.9.0".into());
        pinned.steps[0].from = Some("0.9.0".into());
        pinned.steps[0].to = "1.0.0".into();
        pinned.steps[0].release_id = "tenkai:release:api@1.0.0".into();

        assert_eq!(
            classify_candidate(&mut ctx, &pinned).await.unwrap(),
            CandidateAdmission::Admissible
        );
        admit(&mut ctx, &pinned).await.unwrap();
    }
}

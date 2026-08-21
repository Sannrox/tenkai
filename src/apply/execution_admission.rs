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
    inspect(ctx, plan)
        .await?
        .map_err(|rejection| anyhow::anyhow!("plan {} {rejection}", plan.id))
}

async fn inspect(ctx: &mut Ctx, plan: &Plan) -> Result<Result<(), Rejection>> {
    let Some(environment) = ctx.get(&env_id(&plan.environment)).await? else {
        return Ok(Err(Rejection::EnvironmentMissing));
    };
    for step in &plan.steps {
        if step.action != Action::Rollback
            && environment
                .properties
                .get(&format!("deployment_health.{}", step.product))
                .is_some_and(|health| health == "unknown")
        {
            return Ok(Err(Rejection::DeploymentUnknown {
                product: step.product.clone(),
            }));
        }
        let actual = environment
            .properties
            .get(&format!("deployed.{}", step.product));
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
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::ontology::{KIND_CHANNEL, KIND_ENVIRONMENT, NS, channel_id};
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
                channel: "stable".into(),
                channel_id,
                desired_version: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "release-digest".into(),
                artifact_digest: "artifact-digest".into(),
                deployed_version: Some("1.0.0".into()),
            }],
            steps: vec![Step {
                id: "tenkai:plan:prod:test:step:0".into(),
                order: 0,
                product: "api".into(),
                action: Action::Upgrade,
                from: Some("1.0.0".into()),
                to: "2.0.0".into(),
                release_id: "tenkai:release:api@2.0.0".into(),
                release_digest: "release-digest".into(),
                artifact_digest: "artifact-digest".into(),
                workdir: "/srv/api".into(),
                restore: None,
            }],
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
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

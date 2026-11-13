//! Read-only listing of recorded `tenkai.deployment` attempts (#1054).

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::environment::environment;
use crate::ontology::{KIND_DEPLOYMENT, REL_PART_OF_PLAN, validate_identifier};
use crate::page::{Page, PageQuery};
use crate::pb::sekai::Object;
use crate::schema_contract::omitted_when_none;

/// One recorded deployment attempt, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentAttemptView {
    pub id: String,
    pub created_at: i64,
    pub instance: String,
    pub product: String,
    pub from_version: Option<String>,
    pub to_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub action: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub lease_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub cause: Option<crate::apply::DeploymentCause>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub restore: Option<crate::apply::DeploymentCause>,
}

/// One page of [`DeploymentAttemptView`] values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentHistoryPage {
    pub items: Vec<DeploymentAttemptView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub next_cursor: Option<String>,
    /// Environment owner contact and notification URLs (#1066).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = omitted_when_none)]
    pub owner: Option<crate::owner::OwnerView>,
}

impl From<Page<DeploymentAttemptView>> for DeploymentHistoryPage {
    fn from(page: Page<DeploymentAttemptView>) -> Self {
        Self {
            items: page.items,
            next_cursor: page.next_cursor,
            owner: None,
        }
    }
}

/// Query parameters for `GET /v1/environments/{environment}/history`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentHistoryQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Instance name. Unnamed instances equal the product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}

impl DeploymentHistoryQuery {
    fn page(&self) -> PageQuery {
        PageQuery {
            limit: self.limit,
            cursor: self.cursor.clone(),
        }
    }
}

/// Deployment attempts for `environment`, newest first.
///
/// Refuses an unregistered environment. Does not take a lease or write.
pub async fn list_deployment_history(
    ctx: &mut Ctx,
    environment_name: &str,
    query: &DeploymentHistoryQuery,
) -> Result<DeploymentHistoryPage> {
    let env = environment(ctx, environment_name).await?;
    let limit = query.page().limit().map_err(anyhow::Error::msg)?;
    let instance = query
        .product
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(instance) = instance {
        validate_identifier("instance", instance)?;
    }
    let objects = ctx
        .find_by_property(KIND_DEPLOYMENT, "environment", &env.name)
        .await?;
    let mut items: Vec<DeploymentAttemptView> = objects.iter().map(view_from_object).collect();
    if let Some(instance) = instance {
        items.retain(|item| item.instance == instance);
    }
    items.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    if let Some(cursor) = query.cursor.as_deref() {
        let parsed = parse_cursor(cursor)?;
        items.retain(|item| is_before_cursor(item, &parsed));
    }
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    for item in &mut items {
        if item.plan_id.is_none() {
            item.plan_id = plan_id_from_links(ctx, &item.id).await?;
        }
    }
    let next_cursor = has_more.then(|| items.last().map(encode_cursor)).flatten();
    let mut page = DeploymentHistoryPage::from(Page { items, next_cursor });
    let reachable = crate::owner::environment_notification_endpoints(ctx, environment_name)
        .await
        .unwrap_or_default();
    page.owner = crate::owner::view_from_object(&env).map(|view| view.with_reachable(&reachable));
    Ok(page)
}

/// Latest failed or rolled back attempt per instance, newest instance first.
pub async fn latest_failures(
    ctx: &mut Ctx,
    environment_name: &str,
) -> Result<Vec<DeploymentAttemptView>> {
    let env = environment(ctx, environment_name).await?;
    let objects = ctx
        .find_by_property(KIND_DEPLOYMENT, "environment", &env.name)
        .await?;
    let mut items: Vec<DeploymentAttemptView> = objects.iter().map(view_from_object).collect();
    items.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if !matches!(item.status.as_str(), "failed" | "rolled_back") {
            continue;
        }
        if seen.insert(item.instance.clone()) {
            out.push(item);
        }
    }
    for item in &mut out {
        if item.plan_id.is_none() {
            item.plan_id = plan_id_from_links(ctx, &item.id).await?;
        }
    }
    Ok(out)
}

fn view_from_object(object: &Object) -> DeploymentAttemptView {
    let product = object
        .properties
        .get("product")
        .cloned()
        .unwrap_or_default();
    let instance = object
        .properties
        .get("instance")
        .cloned()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| product.clone());
    let from = object
        .properties
        .get("from_version")
        .cloned()
        .filter(|value| !value.is_empty());
    DeploymentAttemptView {
        id: object.id.clone(),
        created_at: object.created,
        instance,
        product,
        from_version: from,
        to_version: object
            .properties
            .get("to_version")
            .cloned()
            .unwrap_or_default(),
        action: object
            .properties
            .get("action")
            .cloned()
            .filter(|value| !value.is_empty()),
        status: object.properties.get("status").cloned().unwrap_or_default(),
        plan_id: object
            .properties
            .get("plan_id")
            .cloned()
            .filter(|value| !value.is_empty()),
        detail: object.properties.get("detail").cloned().unwrap_or_default(),
        lease_generation: object.properties.get("lease_generation").cloned(),
        cause: object
            .properties
            .get("cause")
            .and_then(|raw| crate::apply::DeploymentCause::from_property(raw)),
        restore: object
            .properties
            .get("restore")
            .and_then(|raw| crate::apply::DeploymentCause::from_property(raw)),
    }
}

async fn plan_id_from_links(ctx: &mut Ctx, attempt_id: &str) -> Result<Option<String>> {
    let links = ctx.links(attempt_id, REL_PART_OF_PLAN).await?;
    Ok(links.into_iter().next().map(|link| link.to_id))
}

struct HistoryCursor {
    created_at: i64,
    id: String,
}

fn encode_cursor(item: &DeploymentAttemptView) -> String {
    format!("{}:{}", item.created_at, item.id)
}

fn parse_cursor(cursor: &str) -> Result<HistoryCursor> {
    let (created, id) = cursor
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("history cursor is invalid"))?;
    let created_at = created
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("history cursor is invalid"))?;
    if id.is_empty() {
        anyhow::bail!("history cursor is invalid");
    }
    Ok(HistoryCursor {
        created_at,
        id: id.to_string(),
    })
}

fn is_before_cursor(item: &DeploymentAttemptView, cursor: &HistoryCursor) -> bool {
    item.created_at < cursor.created_at
        || (item.created_at == cursor.created_at && item.id < cursor.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::ontology::{KIND_DEPLOYMENT, NS, REL_PART_OF_PLAN, deployment_id};
    use crate::page::DEFAULT_PAGE_LIMIT;
    use crate::pb::sekai::Object;
    use std::collections::HashMap;

    fn db_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-history-{label}-{}-{}.db",
            std::process::id(),
            crate::now_millis()
        ))
    }

    fn attempt(
        env: &str,
        instance: &str,
        product: &str,
        created: i64,
        status: &str,
        detail: &str,
        plan_id: &str,
    ) -> Object {
        Object {
            id: deployment_id(env, instance, created),
            kind: KIND_DEPLOYMENT.into(),
            name: format!("{instance} ({env})"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("environment".into(), env.into()),
                ("product".into(), product.into()),
                ("instance".into(), instance.into()),
                ("from_version".into(), "1.0.0".into()),
                ("to_version".into(), "1.1.0".into()),
                ("status".into(), status.into()),
                ("detail".into(), detail.into()),
                ("action".into(), "upgrade".into()),
                ("plan_id".into(), plan_id.into()),
                ("lease_generation".into(), "1".into()),
            ]),
            created,
            updated: created,
        }
    }

    #[tokio::test]
    async fn history_is_newest_first_and_pages_stably() {
        let database = db_path("page");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        for (created, status, detail) in [
            (1_000, "failed", "probe failed: not ready"),
            (2_000, "rolled_back", "restored 1.0.0"),
            (3_000, "succeeded", ""),
        ] {
            ctx.put(attempt(
                "prod",
                "api",
                "api",
                created,
                status,
                detail,
                "tenkai:plan:prod:1",
            ))
            .await
            .unwrap();
        }
        let first = list_deployment_history(
            &mut ctx,
            "prod",
            &DeploymentHistoryQuery {
                limit: Some(2),
                cursor: None,
                product: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            first
                .items
                .iter()
                .map(|item| (item.created_at, item.status.as_str()))
                .collect::<Vec<_>>(),
            [(3_000, "succeeded"), (2_000, "rolled_back")]
        );
        let cursor = first.next_cursor.clone().expect("next page");
        ctx.put(attempt(
            "prod",
            "api",
            "api",
            4_000,
            "succeeded",
            "later",
            "tenkai:plan:prod:2",
        ))
        .await
        .unwrap();
        let second = list_deployment_history(
            &mut ctx,
            "prod",
            &DeploymentHistoryQuery {
                limit: Some(2),
                cursor: Some(cursor),
                product: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].created_at, 1_000);
        assert_eq!(second.items[0].detail, "probe failed: not ready");
        assert!(second.next_cursor.is_none());
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn product_filter_and_latest_failures() {
        let database = db_path("filter");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        ctx.put(attempt(
            "prod",
            "api",
            "api",
            1_000,
            "failed",
            "api probe",
            "tenkai:plan:1",
        ))
        .await
        .unwrap();
        ctx.put(attempt(
            "prod",
            "web",
            "web",
            2_000,
            "failed",
            "web probe",
            "tenkai:plan:2",
        ))
        .await
        .unwrap();
        ctx.put(attempt(
            "prod",
            "api",
            "api",
            3_000,
            "succeeded",
            "",
            "tenkai:plan:3",
        ))
        .await
        .unwrap();
        let api = list_deployment_history(
            &mut ctx,
            "prod",
            &DeploymentHistoryQuery {
                limit: Some(DEFAULT_PAGE_LIMIT),
                cursor: None,
                product: Some("api".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(api.items.len(), 2);
        assert!(api.items.iter().all(|item| item.instance == "api"));
        let failures = latest_failures(&mut ctx, "prod").await.unwrap();
        assert_eq!(
            failures
                .iter()
                .map(|item| item.instance.as_str())
                .collect::<Vec<_>>(),
            ["web", "api"]
        );
        assert_eq!(failures[0].detail, "web probe");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn product_filter_keeps_older_rows_without_instance_property() {
        let database = db_path("mixed");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        let mut legacy = attempt(
            "prod",
            "api",
            "api",
            1_000,
            "failed",
            "legacy",
            "tenkai:plan:1",
        );
        legacy.properties.remove("instance");
        ctx.put(legacy).await.unwrap();
        ctx.put(attempt(
            "prod",
            "api",
            "api",
            2_000,
            "succeeded",
            "",
            "tenkai:plan:2",
        ))
        .await
        .unwrap();
        let page = list_deployment_history(
            &mut ctx,
            "prod",
            &DeploymentHistoryQuery {
                limit: Some(DEFAULT_PAGE_LIMIT),
                cursor: None,
                product: Some("api".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].created_at, 2_000);
        assert_eq!(page.items[1].detail, "legacy");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn missing_plan_id_property_reads_the_link() {
        let database = db_path("link");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        let mut object = attempt("prod", "api", "api", 1_000, "failed", "boom", "");
        object.properties.remove("plan_id");
        ctx.put(object.clone()).await.unwrap();
        ctx.link(&object.id, "tenkai:plan:prod:linked", REL_PART_OF_PLAN)
            .await
            .unwrap();
        let page = list_deployment_history(&mut ctx, "prod", &DeploymentHistoryQuery::default())
            .await
            .unwrap();
        assert_eq!(
            page.items[0].plan_id.as_deref(),
            Some("tenkai:plan:prod:linked")
        );
        let failures = latest_failures(&mut ctx, "prod").await.unwrap();
        assert_eq!(
            failures[0].plan_id.as_deref(),
            Some("tenkai:plan:prod:linked")
        );
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn inspect_lists_latest_failures_and_missing_env_fails() {
        let database = db_path("inspect");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        ctx.put(attempt(
            "prod",
            "api",
            "api",
            1_000,
            "failed",
            "probe failed: not ready",
            "tenkai:plan:prod:1",
        ))
        .await
        .unwrap();
        let report = crate::environment::inspect_environment(&mut ctx, "prod")
            .await
            .unwrap();
        assert_eq!(report.latest_failures.len(), 1);
        assert_eq!(report.latest_failures[0].detail, "probe failed: not ready");
        assert_eq!(report.latest_failures[0].cause, None);
        let missing =
            list_deployment_history(&mut ctx, "absent", &DeploymentHistoryQuery::default())
                .await
                .unwrap_err();
        assert!(missing.to_string().contains("not registered"), "{missing}");
        let _ = std::fs::remove_file(&database);
    }

    #[tokio::test]
    async fn history_reads_cause_and_restore_when_present() {
        let database = db_path("cause");
        let _ = std::fs::remove_file(&database);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::environment::env_add(&mut ctx, "prod", "prod")
            .await
            .unwrap();
        let mut object = attempt(
            "prod",
            "api",
            "api",
            1_000,
            "failed",
            "probe failed: not ready; restore or health check of 1.0.0 also failed",
            "tenkai:plan:prod:1",
        );
        let cause = crate::apply::DeploymentCause::classify("probe failed: not ready");
        let restore = crate::apply::DeploymentCause::classify(
            "software deploy phase=restore product=api@1.0.0 environment/namespace=prod: boom",
        )
        .at_phase(crate::apply::DeploymentCausePhase::Restore)
        .with_kind(crate::apply::DeploymentCauseKind::RestoreFailed);
        object
            .properties
            .insert("cause".into(), cause.to_property().unwrap());
        object
            .properties
            .insert("restore".into(), restore.to_property().unwrap());
        ctx.put(object).await.unwrap();
        let page = list_deployment_history(&mut ctx, "prod", &DeploymentHistoryQuery::default())
            .await
            .unwrap();
        let item = &page.items[0];
        assert!(item.detail.contains("restore or health"));
        let stored = item.cause.as_ref().expect("cause");
        assert_eq!(
            stored.phase,
            crate::apply::DeploymentCausePhase::HealthProbe
        );
        assert_eq!(stored.kind, crate::apply::DeploymentCauseKind::NotReady);
        let stored_restore = item.restore.as_ref().expect("restore");
        assert_eq!(
            stored_restore.phase,
            crate::apply::DeploymentCausePhase::Restore
        );
        assert_eq!(
            stored_restore.kind,
            crate::apply::DeploymentCauseKind::RestoreFailed
        );
        let json = serde_json::to_value(item).unwrap();
        assert!(json.get("cause").is_some());
        assert!(json.get("restore").is_some());
        let _ = std::fs::remove_file(&database);
    }
}

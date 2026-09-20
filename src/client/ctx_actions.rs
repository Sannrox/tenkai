//! Action execution, object-change, and emergency-override methods on `Ctx`.

use anyhow::{Context as _, Result};

use sekai_client::CallOptions;

use super::{Ctx, action_actor_from_changes, block_embedded};
use crate::pb::graph_action::ActionResult;
use crate::pb::sekai::{
    Decision, ListObjectChangesRequest, ListObjectChangesResponse, ObjectChange,
};

impl Ctx {
    pub async fn execute_action_result(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<ActionResult> {
        self.backend
            .action_lifecycle()
            .execute(action, params, false)
            .await
    }

    pub async fn preview_action_result(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<ActionResult> {
        self.backend
            .action_lifecycle()
            .execute(action, params, true)
            .await
    }

    pub async fn execute_action(
        &mut self,
        action: &str,
        params: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let result = self.execute_action_result(action, params).await?;
        if result.decision != "allow" {
            anyhow::bail!("action {action} was not allowed: {}", result.decision);
        }
        Ok(())
    }

    pub async fn deny_action(&mut self, approval_id: &str, reason: &str) -> Result<()> {
        self.backend
            .action_lifecycle()
            .deny(approval_id, reason)
            .await
    }

    pub async fn action_decisions(
        &mut self,
        actor: &str,
        action: &str,
        after: i64,
    ) -> Result<Vec<Decision>> {
        self.backend
            .action_lifecycle()
            .decisions(actor, action, after)
            .await
    }

    pub async fn object_changes(&mut self, object_id: &str) -> Result<Vec<ObjectChange>> {
        if let Some(store) = self.embedded_arc() {
            let object_id = object_id.to_string();
            return block_embedded(store, move |store| store.changes(&object_id)).await;
        }
        let mut offset = 0;
        let mut all = Vec::new();
        loop {
            let response: ListObjectChangesResponse = self
                .remote_unary(
                    "/sekai.SekaiService/ListObjectChanges",
                    ListObjectChangesRequest {
                        object_id: object_id.into(),
                        limit: 100,
                        offset,
                    },
                    CallOptions::default(),
                )
                .await?;
            let changes = response.changes;
            let received = changes.len();
            all.extend(changes);
            if received < 100 {
                return Ok(all);
            }
            offset += received as i32;
        }
    }

    pub async fn authorize_emergency_override(
        &mut self,
        plan_id: &str,
        reason: &str,
    ) -> Result<String> {
        let correlation = uuid::Uuid::new_v4().to_string();
        let result = self
            .execute_action_result(
                crate::ontology::ACTION_EMERGENCY_OVERRIDE,
                std::collections::HashMap::from([
                    ("id".into(), plan_id.into()),
                    ("reason".into(), reason.into()),
                    ("correlation".into(), correlation.clone()),
                ]),
            )
            .await?;
        match result.decision.as_str() {
            "allow" => self
                .emergency_override_actor(plan_id, &correlation)
                .await?
                .context("governed emergency override has no authenticated actor evidence"),
            "require_approval" => {
                anyhow::bail!(
                    "emergency maintenance override requires approval {}; governed ActionInstance admission denies require_approval and Tenkai does not resume deferred overrides",
                    result.approval_id,
                )
            }
            decision => {
                anyhow::bail!("emergency maintenance override was not allowed: {decision}")
            }
        }
    }

    async fn emergency_override_actor(
        &mut self,
        plan_id: &str,
        correlation: &str,
    ) -> Result<Option<String>> {
        let Some(plan) = self.get(plan_id).await? else {
            return Ok(None);
        };
        if plan
            .properties
            .get("last_emergency_override_correlation")
            .is_none_or(|stored| stored != correlation)
        {
            return Ok(None);
        }
        self.action_actor(
            plan_id,
            "properties.last_emergency_override_correlation",
            correlation,
        )
        .await
    }

    async fn action_actor(
        &mut self,
        object_id: &str,
        field: &str,
        correlation: &str,
    ) -> Result<Option<String>> {
        Ok(action_actor_from_changes(
            &self.object_changes(object_id).await?,
            field,
            correlation,
        ))
    }
}

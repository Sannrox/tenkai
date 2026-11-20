//! Admit an upgrade onto an advisory-recalled release that strictly lowers
//! blocking exposure (#1068).
//!
//! The comparator is the same match, waiver, grace, and
//! `exposure.block_severity` threshold as [`super::plan_gate`]. A missing,
//! stale, or unevaluable feed refuses. A recall is advisory-caused only when
//! an imported notice lists the release or a `tenkai.deployed_exposure` for
//! that release has `auto_recalled_at`. Promotion-policy, range-only, and
//! untyped claims are never admitted.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::client::Ctx;
use crate::ontology::{KIND_RELEASE_RECALL, release_recall_id};
use crate::plan::{Action, RecalledUpgradeAdmission, Step};

use super::blocking_advisory_ids;

/// Named gate: recall is not bound to an advisory by a catalog record.
pub const UNBOUND_GATE: &str = "recalled_upgrade_unbound";
/// Named gate: target blocking set is not a proper subset of the current pin.
pub const NOT_LOWER_GATE: &str = "recalled_upgrade_not_lower";
/// Named gate: no current pin, or the change is not an upgrade.
pub const NOT_UPGRADE_GATE: &str = "recalled_upgrade_not_upgrade";

/// Validate the operator reason the same way recalled recovery does.
pub fn require_reason(reason: &str) -> Result<&str> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        bail!("recalled upgrade requires a non-empty --recalled-upgrade-reason");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        bail!("recalled upgrade reason must not contain control characters");
    }
    Ok(trimmed)
}

/// Admit `target_release` as a strictly lower-exposure upgrade from
/// `current_release` for `product` in `environment`.
pub async fn admit(
    ctx: &mut Ctx,
    environment: &str,
    product: &str,
    current_release: &str,
    target_release: &str,
    reason: &str,
) -> Result<RecalledUpgradeAdmission> {
    let reason = require_reason(reason)?.to_string();
    if let Some(gate) = unbound_reason(ctx, target_release).await? {
        bail!("{gate}");
    }
    let current = match blocking_advisory_ids(ctx, environment, current_release).await? {
        Ok(ids) => ids,
        Err(gate) => bail!("{gate}"),
    };
    let target = match blocking_advisory_ids(ctx, environment, target_release).await? {
        Ok(ids) => ids,
        Err(gate) => bail!("{gate}"),
    };
    if !target.is_subset(&current) || target.len() >= current.len() {
        bail!(
            "{NOT_LOWER_GATE}: {target_release} blocking advisories [{}] are not a proper subset of {current_release} [{}]",
            join_ids(&target),
            join_ids(&current)
        );
    }
    Ok(RecalledUpgradeAdmission {
        reason,
        product: product.to_string(),
        current_release: current_release.to_string(),
        target_release: target_release.to_string(),
        current_advisories: current.into_iter().collect(),
        target_advisories: target.into_iter().collect(),
    })
}

/// Re-evaluate a signed admission against live feed and catalog records.
///
/// Returns `Ok(None)` when the admission still holds, or `Ok(Some(gate))`
/// when apply must refuse.
pub async fn recheck(
    ctx: &mut Ctx,
    environment: &str,
    admission: &RecalledUpgradeAdmission,
    step: &Step,
) -> Result<Option<String>> {
    if step.action != Action::Upgrade || step.release_id != admission.target_release {
        return Ok(None);
    }
    match admit(
        ctx,
        environment,
        &admission.product,
        &admission.current_release,
        &admission.target_release,
        &admission.reason,
    )
    .await
    {
        Ok(_) => Ok(None),
        Err(error) => Ok(Some(error.to_string())),
    }
}

async fn unbound_reason(ctx: &mut Ctx, release_id: &str) -> Result<Option<String>> {
    let claim = ctx.get(&release_recall_id(release_id)).await?;
    if let Some(claim) = &claim {
        if claim.kind != KIND_RELEASE_RECALL {
            return Ok(Some(format!(
                "{UNBOUND_GATE}: {release_id} has conflicting recall evidence"
            )));
        }
        if claim
            .properties
            .get("policy_id")
            .is_some_and(|value| !value.is_empty())
        {
            return Ok(Some(format!(
                "{UNBOUND_GATE}: {release_id} was recalled by a promotion policy"
            )));
        }
    }
    if notice_lists_release(ctx, release_id).await? {
        return Ok(None);
    }
    if auto_recalled(ctx, release_id).await? {
        return Ok(None);
    }
    Ok(Some(format!(
        "{UNBOUND_GATE}: {release_id} is not bound to an advisory by a recall notice or auto-recall stamp"
    )))
}

async fn auto_recalled(ctx: &mut Ctx, release_id: &str) -> Result<bool> {
    for object in ctx.list_kind(super::KIND_DEPLOYED_EXPOSURE).await? {
        if object.kind != super::KIND_DEPLOYED_EXPOSURE {
            continue;
        }
        if object.properties.get("release_id").map(String::as_str) != Some(release_id) {
            continue;
        }
        if object
            .properties
            .get("auto_recalled_at")
            .is_some_and(|value| !value.is_empty())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn notice_lists_release(ctx: &mut Ctx, rid: &str) -> Result<bool> {
    let Some(spec) = release_spec(rid) else {
        return Ok(false);
    };
    for object in ctx
        .list_kind(crate::recall_notice::KIND_RECALL_NOTICE)
        .await?
    {
        if object.kind != crate::recall_notice::KIND_RECALL_NOTICE {
            continue;
        }
        let Some(document) = object.properties.get("document") else {
            continue;
        };
        if document_lists_spec(document, &spec) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn release_spec(rid: &str) -> Option<String> {
    let rest = rid.strip_prefix("tenkai:release:")?;
    let (product, version) = rest.split_once('@')?;
    Some(format!("{product}@{version}"))
}

fn document_lists_spec(document: &str, spec: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(document) else {
        return false;
    };
    if array_has_release(value.pointer("/statement/recalled"), spec) {
        return true;
    }
    let Some(encoded) = value.get("statement").and_then(|value| value.as_str()) else {
        return false;
    };
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(statement) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    array_has_release(statement.get("recalled"), spec)
}

fn array_has_release(recalled: Option<&serde_json::Value>, spec: &str) -> bool {
    let Some(serde_json::Value::Array(entries)) = recalled else {
        return false;
    };
    entries
        .iter()
        .any(|entry| entry.get("release").and_then(|value| value.as_str()) == Some(spec))
}

fn join_ids(ids: &BTreeSet<String>) -> String {
    ids.iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

//! Built-in provision executor: a saved plan bound by the plan digest (ADR 0052).
//!
//! Prepare runs the named CLI's plan command, seals the saved plan to the
//! approved runtime recipients, and returns a value-free resource summary.
//! Apply opens that saved plan, checks its digest, re-renders the summary,
//! and applies exactly that plan. Destroy and replace are risky-change codes.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::ontology::validate_identifier;
use crate::pb::record::Object;
use crate::sealed_secret::{SealedTarget, SealedValue};

/// Environment property holding a sealed saved plan for one instance.
pub const SAVED_PROPERTY_PREFIX: &str = "provision_saved.";
/// Secret name used as associated data for a sealed saved plan.
pub const SAVED_PLAN_SECRET: &str = "provision";
/// Secret key used as associated data for a sealed saved plan.
pub const SAVED_PLAN_KEY: &str = "saved-plan";

/// Compatible CLIs a provision release may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProvisionCli {
    Terraform,
    Tofu,
}

impl ProvisionCli {
    pub const ALL: [Self; 2] = [Self::Terraform, Self::Tofu];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Tofu => "tofu",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|cli| name.eq_ignore_ascii_case(cli.as_str()))
    }
}

impl std::fmt::Display for ProvisionCli {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ProvisionCli {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> Result<Self> {
        Self::from_name(name)
            .with_context(|| format!("unknown provision CLI {name:?}; expected terraform or tofu"))
    }
}

/// Signed `[provision]` section: which CLI and version this release needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionSection {
    pub cli: ProvisionCli,
    pub cli_version: String,
}

impl ProvisionSection {
    pub fn validate(&self) -> Result<()> {
        if self.cli_version.is_empty()
            || self.cli_version.len() > 64
            || !self
                .cli_version
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'/')
        {
            bail!("provision.cli_version must be a non-empty printable version without '/'");
        }
        Ok(())
    }
}

/// One resource action in a value-free summary.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ResourceAction {
    Create,
    Update,
    Replace,
    Delete,
    Read,
}

impl ResourceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Replace => "replace",
            Self::Delete => "delete",
            Self::Read => "read",
        }
    }
}

impl std::fmt::Display for ResourceAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One resource address and its action, with every attribute value removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceSummary {
    pub address: String,
    pub action: ResourceAction,
}

/// Deterministic, value-free summary of a saved plan.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvisionSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceSummary>,
}

impl ProvisionSummary {
    /// Canonical JSON used for the summary digest.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("encoding the provision summary")
    }

    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_json()?))
    }

    pub fn counts(&self) -> BTreeMap<String, u32> {
        let mut counts = BTreeMap::new();
        for resource in &self.resources {
            *counts
                .entry(resource.action.as_str().to_owned())
                .or_insert(0) += 1;
        }
        counts
    }

    /// Risky-change codes covered by the plan digest: destroy and replace.
    pub fn risky_codes(&self) -> Vec<String> {
        let mut codes = Vec::new();
        for resource in &self.resources {
            let code = match resource.action {
                ResourceAction::Delete => DESTROYED_RESOURCE,
                ResourceAction::Replace => REPLACED_RESOURCE,
                ResourceAction::Create | ResourceAction::Update | ResourceAction::Read => continue,
            };
            codes.push(format!("{code}:{}", resource.address));
        }
        codes
    }

    pub fn has_destroy_or_replace(&self) -> bool {
        self.resources.iter().any(|resource| {
            matches!(
                resource.action,
                ResourceAction::Delete | ResourceAction::Replace
            )
        })
    }
}

/// Risky-change code for a saved plan that deletes a resource.
pub const DESTROYED_RESOURCE: &str = "destroyed_resource";
/// Risky-change code for a saved plan that deletes and recreates a resource.
pub const REPLACED_RESOURCE: &str = "replaced_resource";

/// Bound into a prepare or apply step: CLI pair, recipients, digest, summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvisionStep {
    pub cli: String,
    pub cli_version: String,
    /// Wire-form recipient public keys the runtime may seal to (ADR 0052).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub saved_plan_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub summary: Option<ProvisionSummary>,
    /// Prepare/apply a destroy saved plan (unsubscribe).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub destroy: bool,
    /// Sealed saved plan copied onto an apply step. Omitted on prepare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub sealed: Option<SealedValue>,
}

impl ProvisionStep {
    pub fn cli_pair(&self) -> Result<(ProvisionCli, &str)> {
        let cli = self
            .cli
            .parse()
            .with_context(|| format!("provision step names unknown CLI {}", self.cli))?;
        if self.cli_version.is_empty() {
            bail!("provision step names no CLI version");
        }
        Ok((cli, self.cli_version.as_str()))
    }

    pub fn summary_digest(&self) -> Result<Option<String>> {
        self.summary
            .as_ref()
            .map(ProvisionSummary::digest)
            .transpose()
    }
}

/// Prepare result the runtime reports and the server stores for the next apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvisionReceipt {
    pub saved_plan_digest: String,
    pub summary_digest: String,
    pub summary: ProvisionSummary,
    /// Sealed saved plan. Present on prepare; omitted on apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(transform = crate::schema_contract::omitted_when_none)]
    pub sealed: Option<SealedValue>,
}

/// Durable record of a completed prepare, keyed by instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedPlanRecord {
    pub release_digest: String,
    pub cli: String,
    pub cli_version: String,
    pub saved_plan_digest: String,
    pub summary_digest: String,
    pub summary: ProvisionSummary,
    pub sealed: SealedValue,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub destroy: bool,
}

/// Bytes of a prepared saved plan plus the value-free summary.
#[derive(Debug)]
pub struct PreparedPlan {
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
    pub summary: ProvisionSummary,
}

impl PreparedPlan {
    pub fn saved_plan_digest(&self) -> String {
        sha256_hex(&self.plaintext)
    }

    pub fn summary_digest(&self) -> Result<String> {
        self.summary.digest()
    }
}

/// Associated-data target for a sealed saved plan of `instance` in `environment`.
pub fn saved_plan_target(environment: &str, instance: &str) -> Result<SealedTarget> {
    SealedTarget::new(
        environment,
        instance,
        crate::sealed_secret::SecretRef::new(SAVED_PLAN_SECRET, SAVED_PLAN_KEY)?,
    )
}

/// Digest of plaintext saved-plan bytes.
pub fn saved_plan_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Render a value-free summary from `terraform show -json` (or tofu) output.
///
/// Only `address` and `change.actions` are read. Attribute values, before/after
/// maps, and sensitive marks are dropped so the brief cannot leak them.
pub fn summary_from_plan_json(raw: &[u8]) -> Result<ProvisionSummary> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).context("saved plan JSON is not an object")?;
    let Some(changes) = value.get("resource_changes").and_then(|v| v.as_array()) else {
        bail!("saved plan JSON has no resource_changes array");
    };
    let mut resources = Vec::new();
    for change in changes {
        let address = change
            .get("address")
            .and_then(|v| v.as_str())
            .context("resource change has no address")?;
        if address.is_empty() {
            bail!("resource change has an empty address");
        }
        let actions = change
            .get("change")
            .and_then(|v| v.get("actions"))
            .and_then(|v| v.as_array())
            .context("resource change has no actions")?;
        let names: Vec<&str> = actions
            .iter()
            .map(|v| v.as_str().context("resource action is not a string"))
            .collect::<Result<_>>()?;
        let Some(action) = resource_action(&names)? else {
            continue;
        };
        resources.push(ResourceSummary {
            address: address.to_owned(),
            action,
        });
    }
    resources.sort_by(|left, right| left.address.cmp(&right.address));
    Ok(ProvisionSummary { resources })
}

fn resource_action(actions: &[&str]) -> Result<Option<ResourceAction>> {
    Ok(match actions {
        ["no-op"] => None,
        ["create"] => Some(ResourceAction::Create),
        ["update"] => Some(ResourceAction::Update),
        ["delete"] => Some(ResourceAction::Delete),
        ["read"] => Some(ResourceAction::Read),
        ["delete", "create"] | ["create", "delete"] => Some(ResourceAction::Replace),
        other => bail!(
            "saved plan has unknown resource actions {other:?}; refusing an undetermined summary"
        ),
    })
}

/// Remote backends that take a state lock. Local files and anything else are refused.
const LOCKING_BACKENDS: &[&str] = &[
    "s3",
    "gcs",
    "azurerm",
    "remote",
    "consul",
    "kubernetes",
    "pg",
    "oss",
    "cos",
    "http",
    "cloud",
];

/// Refuse a workdir whose Terraform/OpenTofu config uses a local file or a
/// backend without locking. Publication and prepare both call this.
pub fn admit_locking_backend(workdir: &Path) -> Result<String> {
    let (backend, body) = scan_backend(workdir)?;
    if backend == "local" {
        bail!("provision releases refuse a local state file; use a remote backend with locking");
    }
    if !LOCKING_BACKENDS.contains(&backend.as_str()) {
        bail!(
            "provision releases refuse backend {backend:?}; use a remote backend with locking ({})",
            LOCKING_BACKENDS.join(", ")
        );
    }
    match backend.as_str() {
        "s3" if !(body.contains("dynamodb_table") || body.contains("use_lockfile")) => {
            bail!(
                "provision releases refuse an s3 backend without dynamodb_table or use_lockfile locking"
            );
        }
        "http" if !body.contains("lock_address") => {
            bail!("provision releases refuse an http backend without lock_address");
        }
        _ => {}
    }
    Ok(backend)
}

fn scan_backend(workdir: &Path) -> Result<(String, String)> {
    let mut combined = String::new();
    let entries =
        std::fs::read_dir(workdir).with_context(|| format!("listing {}", workdir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", workdir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !(name.ends_with(".tf") || name.ends_with(".tofu")) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        combined.push_str(&text);
        combined.push('\n');
    }
    if combined.trim().is_empty() {
        bail!(
            "provision workdir {} has no .tf or .tofu files declaring a state backend",
            workdir.display()
        );
    }
    let mut found = Vec::new();
    for (prefix, label) in [('"', "backend"), ('\'', "backend")] {
        let needle = format!("backend {prefix}");
        let mut rest = combined.as_str();
        while let Some(at) = rest.find(&needle) {
            let after = &rest[at + needle.len()..];
            let Some(end) = after.find(prefix) else {
                bail!("provision backend block is unterminated");
            };
            let name = &after[..end];
            let body = backend_body(&after[end + 1..]);
            found.push((name.to_owned(), body));
            rest = &after[end + 1..];
        }
        let _ = label;
    }
    if let Some(at) = combined.find("cloud") {
        let after = combined[at + 5..].trim_start();
        if after.starts_with('{') {
            found.push(("cloud".into(), backend_body(after)));
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found.dedup_by(|left, right| left.0 == right.0);
    match found.as_slice() {
        [] => bail!(
            "provision workdir {} declares no remote state backend; a local state file is refused",
            workdir.display()
        ),
        [(name, body)] => Ok((name.clone(), body.clone())),
        many => bail!(
            "provision workdir {} declares more than one backend ({})",
            workdir.display(),
            many.iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn backend_body(after_name: &str) -> String {
    let trimmed = after_name.trim_start();
    let Some(rest) = trimmed.strip_prefix('{') else {
        return String::new();
    };
    let mut depth = 1_i32;
    for (index, ch) in rest.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[..index].to_owned();
                }
            }
            _ => {}
        }
    }
    rest.to_owned()
}

/// Whether CLI stderr is a leftover state lock, which is reported and never broken.
pub fn is_leftover_lock(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("error acquiring the state lock")
        || lower.contains("state lock is held")
        || (lower.contains("lock id") && lower.contains("lock"))
}

pub fn leftover_lock_detail(stderr: &str) -> String {
    format!(
        "the provisioning tool left a state lock; it is reported and never broken: {}",
        crate::software_executor::sanitize_diagnostic_text(stderr)
    )
}

/// Stored prepare for `instance`, when one exists.
pub fn stored_saved_plan(env_obj: &Object, instance: &str) -> Result<Option<SavedPlanRecord>> {
    let Some(raw) = env_obj
        .properties
        .get(&format!("{SAVED_PROPERTY_PREFIX}{instance}"))
    else {
        return Ok(None);
    };
    serde_json::from_str(raw)
        .with_context(|| format!("provision saved plan for {instance} is malformed"))
        .map(Some)
}

/// Store `record` as the instance's current saved plan.
pub fn stamp_saved_plan(
    env_obj: &mut Object,
    instance: &str,
    record: &SavedPlanRecord,
) -> Result<()> {
    validate_identifier("instance", instance)?;
    env_obj.properties.insert(
        format!("{SAVED_PROPERTY_PREFIX}{instance}"),
        serde_json::to_string(record).context("encoding the provision saved plan")?,
    );
    Ok(())
}

/// Drop a used or stale saved plan so the next change prepares again.
pub fn clear_saved_plan(env_obj: &mut Object, instance: &str) {
    env_obj
        .properties
        .remove(&format!("{SAVED_PROPERTY_PREFIX}{instance}"));
}

/// Wire-form unrevoked runtime recipient keys, plus the recovery key.
pub async fn plan_recipients(ctx: &mut Ctx, environment: &str) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    if let Some(store) = ctx.operational_store() {
        for record in store
            .runtime_sealing_keys(environment)
            .context("listing runtime recipient keys")?
        {
            crate::sealing_key::SealingPublicKey::from_wire(&record.public_key)
                .context("a stored runtime sealing key is not a public key")?;
            keys.push(record.public_key);
        }
    }
    if let Some(recovery) = crate::sealed_secret::stored_recovery_key(ctx, environment).await? {
        keys.push(recovery.to_wire());
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// Parse approved recipient wires into public keys.
pub fn recipient_keys(wires: &[String]) -> Result<Vec<crate::sealing_key::SealingPublicKey>> {
    wires
        .iter()
        .map(|wire| crate::sealing_key::SealingPublicKey::from_wire(wire))
        .collect()
}

/// Bind a provision release's plan step: prepare when no matching saved plan
/// exists, otherwise apply that saved plan. `destroy` is true for unsubscribe.
pub fn bind_step(
    step: &mut crate::plan::Step,
    input: Option<&mut crate::plan::DesiredStateInput>,
    section: &ProvisionSection,
    env_obj: &Object,
    recipients: Vec<String>,
) -> Result<()> {
    use crate::plan::Action;
    let destroy =
        step.action == Action::Remove || step.provision.as_ref().is_some_and(|p| p.destroy);
    let instance = step.instance_name().to_string();
    let matching = stored_saved_plan(env_obj, &instance)?.filter(|record| {
        record.release_digest == step.release_digest
            && record.cli == section.cli.as_str()
            && record.cli_version == section.cli_version
            && record.destroy == destroy
    });
    if let Some(record) = matching {
        if let Some(input) = input {
            input.saved_plan_digest = record.saved_plan_digest.clone();
        }
        step.provision = Some(ProvisionStep {
            cli: record.cli.clone(),
            cli_version: record.cli_version.clone(),
            recipients,
            saved_plan_digest: record.saved_plan_digest,
            summary: Some(record.summary),
            destroy,
            sealed: Some(record.sealed),
        });
        return Ok(());
    }
    step.action = Action::ProvisionPrepare;
    step.restore = None;
    if let Some(input) = input {
        input.saved_plan_digest.clear();
    }
    step.provision = Some(ProvisionStep {
        cli: section.cli.to_string(),
        cli_version: section.cli_version.clone(),
        recipients,
        saved_plan_digest: String::new(),
        summary: None,
        destroy,
        sealed: None,
    });
    Ok(())
}

/// Persist or clear the saved plan a runtime receipt reported.
pub fn apply_receipt(
    env_obj: &mut Object,
    step: &crate::plan::Step,
    receipt: &crate::runtime_delivery::RuntimeStepReceipt,
) -> Result<()> {
    let instance = step.instance_name();
    if step.action == crate::plan::Action::ProvisionPrepare {
        if receipt.succeeded {
            let Some(provision) = receipt.provision.as_ref() else {
                bail!("prepare step {instance} succeeded without a saved-plan receipt");
            };
            let Some(sealed) = provision.sealed.clone() else {
                bail!("prepare step {instance} succeeded without a sealed saved plan");
            };
            let section = step
                .provision
                .as_ref()
                .context("prepare step names no provision binding")?;
            stamp_saved_plan(
                env_obj,
                instance,
                &SavedPlanRecord {
                    release_digest: step.release_digest.clone(),
                    cli: section.cli.clone(),
                    cli_version: section.cli_version.clone(),
                    saved_plan_digest: provision.saved_plan_digest.clone(),
                    summary_digest: provision.summary_digest.clone(),
                    summary: provision.summary.clone(),
                    sealed,
                    destroy: section.destroy,
                },
            )?;
        }
        return Ok(());
    }
    if step.provision.is_some() {
        // Any apply attempt leaves the saved plan stale.
        clear_saved_plan(env_obj, instance);
    }
    Ok(())
}

/// Reason a destroy or replace must reach a human, matching downgrade/rollback.
pub fn risky_human_reason() -> &'static str {
    "destroyed_resource or replaced_resource requires a human-signed envelope"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("tenkai-provision-{}-{}", std::process::id(), nanos));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_tf(dir: &Path, body: &str) {
        fs::write(dir.join("main.tf"), body).unwrap();
    }

    fn plan_json(changes: &str) -> Vec<u8> {
        format!(r#"{{"format_version":"1.2","resource_changes":[{changes}]}}"#).into_bytes()
    }

    fn change(address: &str, actions: &str) -> String {
        format!(
            r#"{{"address":"{address}","change":{{"actions":{actions},"before":{{"secret":"s3cret"}},"after":{{"secret":"other"}}}}}}"#
        )
    }

    #[test]
    fn summary_keeps_addresses_and_actions_and_drops_values() {
        let raw = plan_json(&format!(
            "{},{},{}",
            change("aws_instance.web", r#"["create"]"#),
            change("aws_db_instance.main", r#"["delete","create"]"#),
            change("aws_s3_bucket.old", r#"["delete"]"#),
        ));
        let summary = summary_from_plan_json(&raw).unwrap();
        let encoded = String::from_utf8(summary.canonical_json().unwrap()).unwrap();
        assert!(!encoded.contains("s3cret"), "{encoded}");
        assert!(!encoded.contains("other"), "{encoded}");
        assert_eq!(
            summary.resources,
            vec![
                ResourceSummary {
                    address: "aws_db_instance.main".into(),
                    action: ResourceAction::Replace,
                },
                ResourceSummary {
                    address: "aws_instance.web".into(),
                    action: ResourceAction::Create,
                },
                ResourceSummary {
                    address: "aws_s3_bucket.old".into(),
                    action: ResourceAction::Delete,
                },
            ]
        );
        assert_eq!(
            summary.risky_codes(),
            vec![
                "replaced_resource:aws_db_instance.main".to_string(),
                "destroyed_resource:aws_s3_bucket.old".to_string(),
            ]
        );
    }

    #[test]
    fn summary_is_deterministic_across_input_order() {
        let first = summary_from_plan_json(&plan_json(&format!(
            "{},{}",
            change("b.x", r#"["update"]"#),
            change("a.x", r#"["create"]"#),
        )))
        .unwrap();
        let second = summary_from_plan_json(&plan_json(&format!(
            "{},{}",
            change("a.x", r#"["create"]"#),
            change("b.x", r#"["update"]"#),
        )))
        .unwrap();
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
        assert_eq!(first, second);
    }

    #[test]
    fn create_before_destroy_is_replace() {
        let summary = summary_from_plan_json(&plan_json(&change(
            "aws_instance.web",
            r#"["create","delete"]"#,
        )))
        .unwrap();
        assert_eq!(summary.resources[0].action, ResourceAction::Replace);
        assert_eq!(
            summary.risky_codes(),
            vec!["replaced_resource:aws_instance.web".to_string()]
        );
    }

    #[test]
    fn no_op_and_read_are_not_risky() {
        let summary = summary_from_plan_json(&plan_json(&format!(
            "{},{}",
            change("aws_ami.data", r#"["read"]"#),
            change("aws_instance.web", r#"["no-op"]"#),
        )))
        .unwrap();
        assert_eq!(
            summary.resources,
            vec![ResourceSummary {
                address: "aws_ami.data".into(),
                action: ResourceAction::Read,
            }]
        );
        assert!(summary.risky_codes().is_empty());
        assert!(!summary.has_destroy_or_replace());
    }

    #[test]
    fn unknown_actions_fail_closed() {
        let error = summary_from_plan_json(&plan_json(&change("x.y", r#"["create","update"]"#)))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown resource actions"), "{error}");
    }

    #[test]
    fn a_mismatched_summary_digest_is_visible() {
        let summary = summary_from_plan_json(&plan_json(&change("a.b", r#"["create"]"#))).unwrap();
        let mut other = summary.clone();
        other.resources[0].action = ResourceAction::Delete;
        assert_ne!(summary.digest().unwrap(), other.digest().unwrap());
    }

    #[test]
    fn local_and_unlocked_backends_are_refused() {
        let dir = tmp();
        write_tf(&dir, r#"terraform { backend "local" {} }"#);
        let error = admit_locking_backend(&dir).unwrap_err().to_string();
        assert!(error.contains("local state file"), "{error}");

        write_tf(&dir, r#"terraform { backend "s3" { bucket = "b" } }"#);
        let error = admit_locking_backend(&dir).unwrap_err().to_string();
        assert!(error.contains("use_lockfile"), "{error}");

        write_tf(&dir, "resource \"null_resource\" \"x\" {}");
        let error = admit_locking_backend(&dir).unwrap_err().to_string();
        assert!(error.contains("no remote state backend"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn locking_s3_and_cloud_backends_are_admitted() {
        let dir = tmp();
        write_tf(
            &dir,
            r#"terraform { backend "s3" { bucket = "b" dynamodb_table = "locks" } }"#,
        );
        assert_eq!(admit_locking_backend(&dir).unwrap(), "s3");

        write_tf(
            &dir,
            r#"terraform { backend "s3" { bucket = "b" use_lockfile = true } }"#,
        );
        assert_eq!(admit_locking_backend(&dir).unwrap(), "s3");

        write_tf(
            &dir,
            "terraform {\n  cloud {\n    organization = \"acme\"\n  }\n}\n",
        );
        assert_eq!(admit_locking_backend(&dir).unwrap(), "cloud");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_lock_text_is_named_and_not_treated_as_success() {
        assert!(is_leftover_lock(
            "Error: Error acquiring the state lock\nLock Info:\n  ID: abc"
        ));
        let detail = leftover_lock_detail("Error acquiring the state lock");
        assert!(detail.contains("never broken"), "{detail}");
        assert!(!is_leftover_lock("Apply complete! Resources: 1 added."));
    }

    #[test]
    fn saved_plan_digest_covers_the_plaintext_bytes() {
        let first = saved_plan_digest(b"plan-a");
        let second = saved_plan_digest(b"plan-b");
        assert_ne!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first, saved_plan_digest(b"plan-a"));
    }

    fn empty_env() -> Object {
        Object {
            id: "tenkai:env:prod".into(),
            kind: "Environment".into(),
            name: "prod".into(),
            namespace: "tenkai".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        }
    }

    fn sample_step(action: crate::plan::Action) -> crate::plan::Step {
        crate::plan::Step {
            id: "step-0".into(),
            order: 0,
            product: "infra".into(),
            instance: String::new(),
            action,
            from: None,
            to: "1.0.0".into(),
            release_id: "tenkai:release:infra@1.0.0".into(),
            release_digest: "sha256:aaaa".into(),
            artifact_digest: "bbbb".into(),
            workdir: "/tmp".into(),
            restore: None,
            host: None,
            sealed: Vec::new(),
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
            target_changes: Vec::new(),
            reason: String::new(),
            cluster_namespace: None,
            provision: None,
        }
    }

    #[test]
    fn bind_step_prepares_when_no_saved_plan_matches() {
        let mut step = sample_step(crate::plan::Action::Install);
        let mut input = crate::plan::DesiredStateInput {
            product: "infra".into(),
            instance: String::new(),
            channel: "stable".into(),
            channel_id: "tenkai:channel:infra/stable".into(),
            desired_version: "1.0.0".into(),
            release_id: step.release_id.clone(),
            release_digest: step.release_digest.clone(),
            artifact_digest: step.artifact_digest.clone(),
            deployed_version: None,
            providers: Default::default(),
            saved_plan_digest: String::new(),
        };
        let section = ProvisionSection {
            cli: ProvisionCli::Tofu,
            cli_version: "1.8.0".into(),
        };
        bind_step(
            &mut step,
            Some(&mut input),
            &section,
            &empty_env(),
            vec!["recipient".into()],
        )
        .unwrap();
        assert_eq!(step.action, crate::plan::Action::ProvisionPrepare);
        let provision = step.provision.unwrap();
        assert_eq!(provision.cli, "tofu");
        assert_eq!(provision.cli_version, "1.8.0");
        assert!(!provision.destroy);
        assert!(provision.saved_plan_digest.is_empty());
        assert!(input.saved_plan_digest.is_empty());
    }

    #[test]
    fn unsubscribe_prepare_sets_destroy() {
        let mut step = sample_step(crate::plan::Action::Remove);
        let section = ProvisionSection {
            cli: ProvisionCli::Terraform,
            cli_version: "1.9.0".into(),
        };
        bind_step(&mut step, None, &section, &empty_env(), Vec::new()).unwrap();
        assert_eq!(step.action, crate::plan::Action::ProvisionPrepare);
        assert!(step.provision.unwrap().destroy);
    }

    fn dummy_sealed() -> SealedValue {
        SealedValue {
            format_version: 1,
            ciphertext: "AA==".into(),
            wraps: Vec::new(),
        }
    }

    fn matching_record() -> SavedPlanRecord {
        SavedPlanRecord {
            release_digest: "sha256:aaaa".into(),
            cli: "tofu".into(),
            cli_version: "1.8.0".into(),
            saved_plan_digest: "sha256:plan".into(),
            summary_digest: "sha256:sum".into(),
            summary: ProvisionSummary {
                resources: vec![ResourceSummary {
                    address: "null_resource.demo".into(),
                    action: ResourceAction::Create,
                }],
            },
            sealed: dummy_sealed(),
            destroy: false,
        }
    }

    #[test]
    fn bind_step_applies_a_matching_saved_plan() {
        let mut env = empty_env();
        stamp_saved_plan(&mut env, "infra", &matching_record()).unwrap();
        let mut step = sample_step(crate::plan::Action::Install);
        let mut input = crate::plan::DesiredStateInput {
            product: "infra".into(),
            instance: String::new(),
            channel: "stable".into(),
            channel_id: "tenkai:channel:infra/stable".into(),
            desired_version: "1.0.0".into(),
            release_id: step.release_id.clone(),
            release_digest: step.release_digest.clone(),
            artifact_digest: step.artifact_digest.clone(),
            deployed_version: None,
            providers: Default::default(),
            saved_plan_digest: String::new(),
        };
        let section = ProvisionSection {
            cli: ProvisionCli::Tofu,
            cli_version: "1.8.0".into(),
        };
        bind_step(
            &mut step,
            Some(&mut input),
            &section,
            &env,
            vec!["recipient".into()],
        )
        .unwrap();
        assert_eq!(step.action, crate::plan::Action::Install);
        let provision = step.provision.unwrap();
        assert_eq!(provision.saved_plan_digest, "sha256:plan");
        assert_eq!(input.saved_plan_digest, "sha256:plan");
        assert!(provision.sealed.is_some());
    }

    #[test]
    fn apply_receipt_clears_the_saved_plan_after_a_failed_apply() {
        let mut env = empty_env();
        stamp_saved_plan(&mut env, "infra", &matching_record()).unwrap();
        let mut step = sample_step(crate::plan::Action::Install);
        step.provision = Some(ProvisionStep {
            cli: "tofu".into(),
            cli_version: "1.8.0".into(),
            recipients: Vec::new(),
            saved_plan_digest: "sha256:plan".into(),
            summary: None,
            destroy: false,
            sealed: Some(dummy_sealed()),
        });
        let receipt = crate::runtime_delivery::RuntimeStepReceipt {
            step_id: step.id.clone(),
            succeeded: false,
            detail: "leftover lock".into(),
            wraps: Vec::new(),
            provision: None,
        };
        apply_receipt(&mut env, &step, &receipt).unwrap();
        assert!(stored_saved_plan(&env, "infra").unwrap().is_none());
    }

    fn fake_plan_bytes() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "format_version": "1.2",
            "resource_changes": [{
                "address": "null_resource.demo",
                "change": { "actions": ["create"] }
            }]
        }))
        .unwrap()
    }

    fn sealed_saved_plan(dir: &Path, plaintext: &[u8]) -> SealedValue {
        let key = crate::sealing_key::SealingKey::open_or_generate(dir).unwrap();
        let recipient = crate::sealing_key::SealingPublicKey::from_wire(&key.to_wire()).unwrap();
        let target = saved_plan_target("prod", "infra").unwrap();
        crate::sealed_secret::seal_saved_plan(&target, plaintext, &[recipient]).unwrap()
    }

    fn apply_step(
        sealed: SealedValue,
        digest: String,
        summary: ProvisionSummary,
    ) -> crate::plan::Step {
        let mut step = sample_step(crate::plan::Action::Install);
        step.provision = Some(ProvisionStep {
            cli: "tofu".into(),
            cli_version: "1.8.0".into(),
            recipients: Vec::new(),
            saved_plan_digest: digest,
            summary: Some(summary),
            destroy: false,
            sealed: Some(sealed),
        });
        step
    }

    #[test]
    fn apply_refuses_a_saved_plan_whose_digest_is_not_the_approved_one() {
        let dir = tmp();
        let plaintext = fake_plan_bytes();
        let sealed = sealed_saved_plan(&dir, &plaintext);
        let summary = summary_from_plan_json(&plaintext).unwrap();
        let step = apply_step(sealed, "sha256:not-the-plan".into(), summary);
        let provision = step.provision.as_ref().unwrap();
        let request = crate::software_executor::request_from_parts(
            "infra",
            "1.0.0",
            "prod",
            &dir,
            "tenkai:release:infra@1.0.0",
        );
        let err = crate::runtime_builtin::run_provision(
            &crate::software_executor::FakeSoftwareExecutor::new(),
            &request,
            provision,
            crate::plan::Action::Install,
            crate::runtime_builtin::ProvisionScope {
                environment: "prod",
                instance: "infra",
                sealing_dir: Some(&dir),
            },
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is not the approved"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_refuses_a_re_rendered_summary_that_does_not_match() {
        let dir = tmp();
        let plaintext = fake_plan_bytes();
        let sealed = sealed_saved_plan(&dir, &plaintext);
        let digest = saved_plan_digest(&plaintext);
        let step = apply_step(sealed, digest, ProvisionSummary::default());
        let provision = step.provision.as_ref().unwrap();
        let request = crate::software_executor::request_from_parts(
            "infra",
            "1.0.0",
            "prod",
            &dir,
            "tenkai:release:infra@1.0.0",
        );
        let err = crate::runtime_builtin::run_provision(
            &crate::software_executor::FakeSoftwareExecutor::new(),
            &request,
            provision,
            crate::plan::Action::Install,
            crate::runtime_builtin::ProvisionScope {
                environment: "prod",
                instance: "infra",
                sealing_dir: Some(&dir),
            },
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("re-rendered provision summary"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}

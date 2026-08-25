//! Accepted change-set closure pin admission for Catalog publication.
//!
//! The pin is a Tenkai Catalog fact. The external change-set authority remains
//! the owner of proposal, merge, and member publication. Tenkai stores only
//! identities, digests, and credential-free acceptance evidence.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
use crate::manifest::ChangeSetMemberSection;
use crate::manifest::ChangeSetPinSection;
use crate::pb::sekai::Object;
use crate::signature_verification;

pub const PIN_CONTRACT: &str = "tenkai.change_set_pin.v1";
pub const EVIDENCE_SCHEMA: &str = "tenkai.change_set_publication_evidence.v1";
pub const MAX_MEMBERS: usize = 32;
pub const MAX_TEXT_BYTES: usize = 256;
const MAX_EVIDENCE_BYTES: u64 = 16 * 1024;

const MEMBER_KINDS: &[&str] = &[
    "object_type",
    "interface_type",
    "ontology_class",
    "ontology_relation",
    "link_type",
    "action_type",
    "control",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetMember {
    pub kind: String,
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetPin {
    pub contract: String,
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub base_digest: String,
    pub closure_digest: String,
    pub receipt_digest: String,
    pub members: Vec<ChangeSetMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetPublicationEvidence {
    pub schema: String,
    pub status: String,
    pub authorized: bool,
    pub contract: String,
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub base_digest: String,
    pub closure_digest: String,
    pub receipt_digest: String,
    pub members: Vec<ChangeSetMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSetPinProjection {
    pub contract: String,
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub closure_digest: String,
    pub receipt_digest: String,
    pub pin_digest: String,
    pub status: String,
    pub members: Vec<ChangeSetMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeSetEvidenceInput {
    File(PathBuf),
    Document(Box<ChangeSetPublicationEvidence>),
    Unavailable { reason: String },
    Unauthorized { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedChangeSetPin {
    pub pin: ChangeSetPin,
    pub evidence: ChangeSetPublicationEvidence,
    pub pin_digest: String,
}

pub fn admit_publication(
    pin: Option<&ChangeSetPinSection>,
    evidence: Option<&ChangeSetEvidenceInput>,
) -> Result<Option<AdmittedChangeSetPin>> {
    match (pin, evidence) {
        (None, None) => Ok(None),
        (None, Some(_)) => {
            bail!(
                "change-set publication evidence was supplied without a [change_set_pin] manifest section"
            )
        }
        (Some(_), None) => {
            bail!(
                "release pin requires change-set publication evidence; missing evidence fails closed before Catalog mutation"
            )
        }
        (Some(section), Some(input)) => Ok(Some(admit_pin(section, input)?)),
    }
}

pub fn stored_properties(admitted: &AdmittedChangeSetPin) -> Result<HashMap<String, String>> {
    Ok(HashMap::from([
        (
            "change_set_pin".into(),
            serde_json::to_string(&admitted.pin)?,
        ),
        (
            "change_set_evidence".into(),
            serde_json::to_string(&admitted.evidence)?,
        ),
        ("change_set_pin_digest".into(), admitted.pin_digest.clone()),
    ]))
}

pub fn validate_stored(release: &Object, expected: Option<&AdmittedChangeSetPin>) -> Result<()> {
    let expected_properties = match expected {
        Some(admitted) => stored_properties(admitted)?,
        None => HashMap::new(),
    };
    for key in [
        "change_set_pin",
        "change_set_evidence",
        "change_set_pin_digest",
    ] {
        let stored = release
            .properties
            .get(key)
            .map(String::as_str)
            .unwrap_or("");
        let wanted = expected_properties
            .get(key)
            .map(String::as_str)
            .unwrap_or("");
        if stored != wanted {
            bail!(
                "release {} already exists with different immutable change-set pin evidence",
                release.id
            );
        }
    }
    Ok(())
}

pub fn stored_projection(release: &Object) -> Result<Option<ChangeSetPinProjection>> {
    let Some(raw_pin) = release.properties.get("change_set_pin") else {
        if release.properties.contains_key("change_set_evidence")
            || release.properties.contains_key("change_set_pin_digest")
        {
            bail!("stored change-set pin properties are incomplete");
        }
        return Ok(None);
    };
    let pin: ChangeSetPin = serde_json::from_str(raw_pin)?;
    let evidence: ChangeSetPublicationEvidence = serde_json::from_str(
        release
            .properties
            .get("change_set_evidence")
            .ok_or_else(|| anyhow::anyhow!("stored change-set pin has no publication evidence"))?,
    )?;
    let stored_digest = release
        .properties
        .get("change_set_pin_digest")
        .ok_or_else(|| anyhow::anyhow!("stored change-set pin has no digest"))?;
    pin.validate()?;
    evidence.validate_structure()?;
    require_accepted_match(&pin, &evidence)?;
    let pin_digest = pin.digest()?;
    if stored_digest != &pin_digest {
        bail!("stored change-set pin digest does not match its canonical pin");
    }
    Ok(Some(ChangeSetPinProjection {
        contract: pin.contract,
        namespace: pin.namespace,
        branch_id: pin.branch_id,
        proposal_id: pin.proposal_id,
        closure_digest: pin.closure_digest,
        receipt_digest: pin.receipt_digest,
        pin_digest,
        status: evidence.status,
        members: pin.members,
    }))
}

pub fn require_stored_accepted(release: &Object) -> Result<Option<ChangeSetPinProjection>> {
    stored_projection(release)
}

impl ChangeSetPin {
    pub fn from_section(section: &ChangeSetPinSection) -> Result<Self> {
        let mut pin = Self {
            contract: section.contract.clone(),
            namespace: section.namespace.clone(),
            branch_id: section.branch_id.clone(),
            proposal_id: section.proposal_id.clone(),
            base_digest: section.base_digest.clone(),
            closure_digest: section.closure_digest.clone(),
            receipt_digest: section.receipt_digest.clone(),
            members: section
                .members
                .iter()
                .map(|member| ChangeSetMember {
                    kind: member.kind.clone(),
                    id: member.id.clone(),
                    digest: member.digest.clone(),
                })
                .collect(),
        };
        pin.canonicalize()?;
        pin.validate()?;
        Ok(pin)
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut output = b"TENKAI-CHANGE-SET-PIN-V1\0".to_vec();
        for value in [
            &self.contract,
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.base_digest,
            &self.closure_digest,
            &self.receipt_digest,
        ] {
            signature_verification::push_len_prefixed(&mut output, value.as_bytes());
        }
        output.extend_from_slice(&(self.members.len() as u64).to_be_bytes());
        for member in &self.members {
            signature_verification::push_len_prefixed(&mut output, member.kind.as_bytes());
            signature_verification::push_len_prefixed(&mut output, member.id.as_bytes());
            signature_verification::push_len_prefixed(&mut output, member.digest.as_bytes());
        }
        Ok(format!("sha256:{:x}", Sha256::digest(output)))
    }

    fn canonicalize(&mut self) -> Result<()> {
        self.members.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.contract != PIN_CONTRACT {
            bail!(
                "unknown change-set pin contract {:?}; expected {PIN_CONTRACT}",
                self.contract
            );
        }
        validate_text("change-set pin namespace", &self.namespace)?;
        validate_text("change-set pin branch_id", &self.branch_id)?;
        validate_text("change-set pin proposal_id", &self.proposal_id)?;
        signature_verification::validate_prefixed_digest(
            "change-set pin base_digest",
            &self.base_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "change-set pin closure_digest",
            &self.closure_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "change-set pin receipt_digest",
            &self.receipt_digest,
        )?;
        validate_members(&self.members)?;
        Ok(())
    }
}

impl ChangeSetPublicationEvidence {
    pub fn load_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            bail!("change-set publication evidence must be a regular file");
        }
        let mut raw = Vec::new();
        file.take(MAX_EVIDENCE_BYTES + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_EVIDENCE_BYTES {
            bail!("change-set publication evidence exceeds {MAX_EVIDENCE_BYTES} bytes");
        }
        let evidence: Self = serde_json::from_slice(&raw)?;
        let mut evidence = evidence;
        evidence.canonicalize();
        evidence.validate_structure()?;
        Ok(evidence)
    }

    fn canonicalize(&mut self) {
        self.members.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.id.cmp(&right.id))
        });
    }

    fn validate_structure(&self) -> Result<()> {
        if self.schema != EVIDENCE_SCHEMA {
            bail!(
                "unknown change-set publication evidence schema {:?}; expected {EVIDENCE_SCHEMA}",
                self.schema
            );
        }
        match self.status.as_str() {
            "accepted" | "unaccepted" | "incomplete" | "recalled" => {}
            other => bail!("unknown change-set publication status {other:?}"),
        }
        if self.contract != PIN_CONTRACT {
            bail!(
                "unknown change-set evidence contract {:?}; expected {PIN_CONTRACT}",
                self.contract
            );
        }
        validate_text("change-set evidence namespace", &self.namespace)?;
        validate_text("change-set evidence branch_id", &self.branch_id)?;
        validate_text("change-set evidence proposal_id", &self.proposal_id)?;
        signature_verification::validate_prefixed_digest(
            "change-set evidence base_digest",
            &self.base_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "change-set evidence closure_digest",
            &self.closure_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "change-set evidence receipt_digest",
            &self.receipt_digest,
        )?;
        if self.status != "incomplete" {
            validate_members(&self.members)?;
        } else if self.members.len() > MAX_MEMBERS {
            bail!("change-set publication evidence has too many members");
        }
        Ok(())
    }
}

fn admit_pin(
    section: &ChangeSetPinSection,
    input: &ChangeSetEvidenceInput,
) -> Result<AdmittedChangeSetPin> {
    let pin = ChangeSetPin::from_section(section)?;
    let evidence = load_evidence(input)?;
    require_accepted_match(&pin, &evidence)?;
    let pin_digest = pin.digest()?;
    Ok(AdmittedChangeSetPin {
        pin,
        evidence,
        pin_digest,
    })
}

fn load_evidence(input: &ChangeSetEvidenceInput) -> Result<ChangeSetPublicationEvidence> {
    match input {
        ChangeSetEvidenceInput::File(path) => ChangeSetPublicationEvidence::load_file(path),
        ChangeSetEvidenceInput::Document(evidence) => {
            let mut evidence = evidence.as_ref().clone();
            evidence.canonicalize();
            evidence.validate_structure()?;
            Ok(evidence)
        }
        ChangeSetEvidenceInput::Unavailable { reason } => {
            bail!("change-set publication evidence is unavailable: {reason}")
        }
        ChangeSetEvidenceInput::Unauthorized { reason } => {
            bail!("change-set publication evidence is unauthorized: {reason}")
        }
    }
}

fn require_accepted_match(
    pin: &ChangeSetPin,
    evidence: &ChangeSetPublicationEvidence,
) -> Result<()> {
    if !evidence.authorized {
        bail!("change-set publication evidence is unauthorized");
    }
    match evidence.status.as_str() {
        "accepted" => {}
        "unaccepted" => bail!("change-set closure is not accepted"),
        "incomplete" => bail!("change-set closure is incomplete"),
        "recalled" => bail!("change-set closure has been recalled"),
        other => bail!("unknown change-set publication status {other:?}"),
    }
    if evidence.contract != pin.contract
        || evidence.namespace != pin.namespace
        || evidence.branch_id != pin.branch_id
        || evidence.proposal_id != pin.proposal_id
        || evidence.base_digest != pin.base_digest
        || evidence.closure_digest != pin.closure_digest
        || evidence.receipt_digest != pin.receipt_digest
    {
        bail!("change-set publication evidence does not match the release pin identity");
    }
    if evidence.members != pin.members {
        bail!("change-set publication evidence members do not match the release pin");
    }
    Ok(())
}

fn validate_members(members: &[ChangeSetMember]) -> Result<()> {
    if members.is_empty() {
        bail!("change-set pin must declare at least one member digest");
    }
    if members.len() > MAX_MEMBERS {
        bail!("change-set pin has too many members");
    }
    let mut previous: Option<(&str, &str)> = None;
    for member in members {
        if !MEMBER_KINDS.contains(&member.kind.as_str()) {
            bail!("unknown change-set member kind {:?}", member.kind);
        }
        validate_text("change-set member id", &member.id)?;
        signature_verification::validate_prefixed_digest(
            "change-set member digest",
            &member.digest,
        )?;
        let current = (member.kind.as_str(), member.id.as_str());
        if previous.is_some_and(|value| value >= current) {
            bail!("change-set members must be unique and canonically sorted");
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.contains('/')
        || value.contains('\\')
    {
        bail!("{label} is empty, oversized, or not an opaque identifier");
    }
    Ok(())
}

#[cfg(test)]
fn sample_pin() -> ChangeSetPinSection {
    ChangeSetPinSection {
        contract: PIN_CONTRACT.into(),
        namespace: "acme".into(),
        branch_id: "types".into(),
        proposal_id: "prop-1".into(),
        base_digest: format!("sha256:{}", "a".repeat(64)),
        closure_digest: format!("sha256:{}", "b".repeat(64)),
        receipt_digest: format!("sha256:{}", "c".repeat(64)),
        members: vec![ChangeSetMemberSection {
            kind: "object_type".into(),
            id: "widget".into(),
            digest: format!("sha256:{}", "d".repeat(64)),
        }],
    }
}

#[cfg(test)]
fn sample_evidence_for(pin: &ChangeSetPinSection) -> ChangeSetPublicationEvidence {
    ChangeSetPublicationEvidence {
        schema: EVIDENCE_SCHEMA.into(),
        status: "accepted".into(),
        authorized: true,
        contract: pin.contract.clone(),
        namespace: pin.namespace.clone(),
        branch_id: pin.branch_id.clone(),
        proposal_id: pin.proposal_id.clone(),
        base_digest: pin.base_digest.clone(),
        closure_digest: pin.closure_digest.clone(),
        receipt_digest: pin.receipt_digest.clone(),
        members: pin
            .members
            .iter()
            .map(|member| ChangeSetMember {
                kind: member.kind.clone(),
                id: member.id.clone(),
                digest: member.digest.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{self, CatalogReader, PublishOptions};
    use crate::client::Ctx;

    fn pin_toml(section: &ChangeSetPinSection) -> String {
        let mut body = format!(
            r#"
[change_set_pin]
contract = "{}"
namespace = "{}"
branch_id = "{}"
proposal_id = "{}"
base_digest = "{}"
closure_digest = "{}"
receipt_digest = "{}"
"#,
            section.contract,
            section.namespace,
            section.branch_id,
            section.proposal_id,
            section.base_digest,
            section.closure_digest,
            section.receipt_digest,
        );
        for member in &section.members {
            body.push_str(&format!(
                r#"
[[change_set_pin.members]]
kind = "{}"
id = "{}"
digest = "{}"
"#,
                member.kind, member.id, member.digest
            ));
        }
        body
    }

    fn write_pinned_manifest(dir: &Path, version: &str, section: &ChangeSetPinSection) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "api"
version = "{version}"

[deploy]
install = "true"
{}"#,
                pin_toml(section)
            ),
        )
        .unwrap();
    }

    #[test]
    fn unknown_contract_and_member_kind_fail_closed() {
        let mut section = sample_pin();
        section.contract = "tenkai.change_set_pin.v2".into();
        let err = ChangeSetPin::from_section(&section)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown change-set pin contract"), "{err}");

        let mut section = sample_pin();
        section.members[0].kind = "secret".into();
        let err = ChangeSetPin::from_section(&section)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown change-set member kind"), "{err}");
    }

    #[test]
    fn unaccepted_incomplete_and_unauthorized_evidence_fail_before_success() {
        let section = sample_pin();
        let mut evidence = sample_evidence_for(&section);
        evidence.status = "unaccepted".into();
        let err = admit_publication(
            Some(&section),
            Some(&ChangeSetEvidenceInput::Document(Box::new(evidence))),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not accepted"), "{err}");

        let mut evidence = sample_evidence_for(&section);
        evidence.status = "incomplete".into();
        evidence.members.clear();
        let err = admit_publication(
            Some(&section),
            Some(&ChangeSetEvidenceInput::Document(Box::new(evidence))),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("incomplete"), "{err}");

        let mut evidence = sample_evidence_for(&section);
        evidence.authorized = false;
        let err = admit_publication(
            Some(&section),
            Some(&ChangeSetEvidenceInput::Document(Box::new(evidence))),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unauthorized"), "{err}");
    }

    #[test]
    fn changed_or_omitted_members_fail_closed() {
        let section = sample_pin();
        let mut evidence = sample_evidence_for(&section);
        evidence.members[0].digest = format!("sha256:{}", "e".repeat(64));
        let err = admit_publication(
            Some(&section),
            Some(&ChangeSetEvidenceInput::Document(Box::new(evidence))),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("members do not match"), "{err}");

        let mut evidence = sample_evidence_for(&section);
        evidence.members.push(ChangeSetMember {
            kind: "control".into(),
            id: "extra".into(),
            digest: format!("sha256:{}", "f".repeat(64)),
        });
        let err = admit_publication(
            Some(&section),
            Some(&ChangeSetEvidenceInput::Document(Box::new(evidence))),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("members do not match"), "{err}");
    }

    #[test]
    fn outage_fails_closed_without_an_admitted_pin() {
        let section = sample_pin();
        let err = admit_publication(
            Some(&section),
            Some(&ChangeSetEvidenceInput::Unavailable {
                reason: "timeout".into(),
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unavailable"), "{err}");
        assert!(err.contains("timeout"), "{err}");
    }

    #[tokio::test]
    async fn publication_inspect_replay_conflict_plan_apply_rollback_and_recall() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-change-set-pin-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();

        let prior = root.join("1.0.0");
        std::fs::create_dir_all(&prior).unwrap();
        std::fs::write(
            prior.join("tenkai.toml"),
            r#"
[product]
name = "api"
version = "1.0.0"

[deploy]
install = "true"
"#,
        )
        .unwrap();
        catalog::publish(
            &mut ctx,
            &prior.join("tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let section = sample_pin();
        let evidence = sample_evidence_for(&section);
        write_pinned_manifest(&root.join("1.1.0"), "1.1.0", &section);
        let options = PublishOptions {
            allow_unsigned_development: true,
            change_set_evidence: Some(ChangeSetEvidenceInput::Document(Box::new(evidence.clone()))),
            ..Default::default()
        };
        catalog::publish(&mut ctx, &root.join("1.1.0/tenkai.toml"), &options)
            .await
            .unwrap();
        let replay = catalog::publish(&mut ctx, &root.join("1.1.0/tenkai.toml"), &options)
            .await
            .unwrap();
        assert!(replay.contains("already published"), "{replay}");

        let inspected = catalog::inspect_release(&mut ctx, "api@1.1.0")
            .await
            .unwrap();
        let pin = inspected.change_set_pin.expect("retained pin");
        assert_eq!(pin.namespace, "acme");
        assert_eq!(pin.proposal_id, "prop-1");
        assert_eq!(pin.status, "accepted");
        assert_eq!(pin.members.len(), 1);
        assert_eq!(pin.members[0].id, "widget");
        let stored = ctx
            .get(&crate::ontology::release_id("api", "1.1.0"))
            .await
            .unwrap()
            .unwrap();
        let projected = stored_projection(&stored).unwrap().unwrap();
        assert_eq!(projected.pin_digest, pin.pin_digest);

        let mut changed = evidence.clone();
        changed.members[0].digest = format!("sha256:{}", "e".repeat(64));
        let conflict = catalog::publish(
            &mut ctx,
            &root.join("1.1.0/tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                change_set_evidence: Some(ChangeSetEvidenceInput::Document(Box::new(changed))),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            conflict.contains("members do not match")
                || conflict.contains("different immutable change-set pin"),
            "{conflict}"
        );

        write_pinned_manifest(&root.join("1.2.0"), "1.2.0", &section);
        let outage = catalog::publish(
            &mut ctx,
            &root.join("1.2.0/tenkai.toml"),
            &PublishOptions {
                allow_unsigned_development: true,
                change_set_evidence: Some(ChangeSetEvidenceInput::Unavailable {
                    reason: "provider timeout".into(),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(outage.contains("unavailable"), "{outage}");
        assert!(
            ctx.get(&crate::ontology::release_id("api", "1.2.0"))
                .await
                .unwrap()
                .is_none()
        );

        let actor = crate::auth_context::test_management_context("change-set-pin");
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        catalog::promote(&mut ctx, &actor, "api@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "api", "stable")
            .await
            .unwrap();
        let baseline = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &baseline.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "change-set pin baseline",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        catalog::promote(&mut ctx, &actor, "api@1.1.0", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        assert_eq!(plan.steps[0].to, "1.1.0");
        crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "change-set pin apply",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        let rollback = crate::plan::rollback_step(&mut ctx, "local", "api")
            .await
            .unwrap();
        assert_eq!(rollback.to, "1.0.0");

        catalog::recall(&mut ctx, &actor, "api@1.1.0")
            .await
            .unwrap();
        let recalled = crate::catalog::EmbeddedCatalog::new(&mut ctx)
            .lookup_release("tenkai:release:api@1.1.0", "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(recalled.contains("recalled"), "{recalled}");

        let _ = std::fs::remove_dir_all(root);
    }
}

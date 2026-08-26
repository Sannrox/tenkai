//! Signed Workshop module delivery without renderer or type-authority ownership.
//!
//! Tenkai admits a versioned module profile, activates one module digest, and
//! retains the observed `(module, type, runtime)` tuple. Workshop owns
//! presentation. Type revisions and package grants stay with their external
//! authorities and appear only as content-bound digests.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::change_set_pin::{AdmittedChangeSetPin, ChangeSetPin};
use crate::client::Ctx;
use crate::manifest::Manifest;
use crate::pb::sekai::Object;
use crate::signature_verification;

pub const MODULE_PROFILE: &str = "tenkai.workshop_module.v1";
pub const ACTIVATION_SCHEMA: &str = "tenkai.workshop_module_activation.v1";
pub const MODULE_DOCUMENT_VERSION: u32 = 1;
pub const COMPATIBILITY_VERSION: u32 = 1;
pub const MEMBER_KIND_MODULE: &str = "workshop_module";
pub const MEMBER_KIND_TYPE: &str = "type_revision";
pub const MEMBER_KIND_RUNTIME: &str = "runtime";

const OBSERVED_TYPE: &str = "observed.type_digest";
const OBSERVED_RUNTIME: &str = "observed.runtime_digest";
const ACTIVATION_PREFIX: &str = "module_activation.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilitySet {
    pub version: u32,
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkshopModuleDocument {
    pub version: u32,
    pub profile: String,
    pub module_id: String,
    pub module_digest: String,
    pub type_compatibility: CompatibilitySet,
    pub runtime_compatibility: CompatibilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCompatibility {
    pub type_digest: String,
    pub runtime_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleActivationReceipt {
    pub schema: String,
    pub environment: String,
    pub product: String,
    pub release: String,
    pub module_id: String,
    pub module_digest: String,
    pub type_digest: String,
    pub runtime_digest: String,
    pub closure_digest: String,
    pub pin_digest: String,
    pub receipt_digest: String,
}

impl CompatibilitySet {
    fn validate(&self, label: &str) -> Result<()> {
        if self.version != COMPATIBILITY_VERSION {
            bail!(
                "unsupported {label} compatibility version {}; expected {COMPATIBILITY_VERSION}",
                self.version
            );
        }
        if self.digests.is_empty() {
            bail!("{label} compatibility must declare at least one digest");
        }
        let mut seen = BTreeSet::new();
        for digest in &self.digests {
            signature_verification::validate_prefixed_digest(
                &format!("{label} compatibility digest"),
                digest,
            )?;
            if !seen.insert(digest.as_str()) {
                bail!("{label} compatibility digest {digest} is duplicated");
            }
        }
        Ok(())
    }

    fn contains(&self, digest: &str) -> bool {
        self.digests.iter().any(|candidate| candidate == digest)
    }
}

impl WorkshopModuleDocument {
    pub fn validate(&self) -> Result<()> {
        if self.version != MODULE_DOCUMENT_VERSION {
            bail!(
                "unsupported workshop_module version {}; expected {MODULE_DOCUMENT_VERSION}",
                self.version
            );
        }
        if self.profile != MODULE_PROFILE {
            bail!(
                "unknown workshop module profile {:?}; expected {MODULE_PROFILE}",
                self.profile
            );
        }
        crate::ontology::validate_identifier("workshop_module.module_id", &self.module_id)?;
        signature_verification::validate_prefixed_digest(
            "workshop_module.module_digest",
            &self.module_digest,
        )?;
        self.type_compatibility.validate("type")?;
        self.runtime_compatibility.validate("runtime")?;
        Ok(())
    }
}

pub fn load_document(path: &Path) -> Result<WorkshopModuleDocument> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading workshop_module {}", path.display()))?;
    parse_document_bytes(&bytes)
        .with_context(|| format!("parsing workshop_module {}", path.display()))
}

pub fn parse_document_bytes(bytes: &[u8]) -> Result<WorkshopModuleDocument> {
    let doc: WorkshopModuleDocument =
        serde_json::from_slice(bytes).context("parsing workshop_module document")?;
    doc.validate()?;
    Ok(doc)
}

pub fn document_from_manifest(
    manifest: &Manifest,
    workdir: &Path,
) -> Result<WorkshopModuleDocument> {
    let relative = manifest
        .module
        .as_ref()
        .map(|section| section.document.as_str())
        .context("workshop_module needs [module].document")?;
    crate::manifest::validate_input_path("module.document", relative)?;
    load_document(&workdir.join(relative))
}

pub fn admit_publication(
    manifest: &Manifest,
    workdir: &Path,
    admitted: Option<&AdmittedChangeSetPin>,
) -> Result<WorkshopModuleDocument> {
    let doc = document_from_manifest(manifest, workdir)?;
    let Some(admitted) = admitted else {
        bail!(
            "workshop_module release requires an accepted change-set closure pin and publication evidence"
        );
    };
    require_pin_binds_profile(&admitted.pin, &doc)?;
    Ok(doc)
}

pub fn require_pin_binds_profile(pin: &ChangeSetPin, doc: &WorkshopModuleDocument) -> Result<()> {
    require_member(pin, MEMBER_KIND_MODULE, &doc.module_id, &doc.module_digest)?;
    for digest in &doc.type_compatibility.digests {
        require_kind_digest(pin, MEMBER_KIND_TYPE, digest)?;
    }
    for digest in &doc.runtime_compatibility.digests {
        require_kind_digest(pin, MEMBER_KIND_RUNTIME, digest)?;
    }
    Ok(())
}

fn require_member(pin: &ChangeSetPin, kind: &str, id: &str, digest: &str) -> Result<()> {
    let Some(member) = pin
        .members
        .iter()
        .find(|member| member.kind == kind && member.id == id)
    else {
        bail!("change-set pin is missing {kind} member {id}");
    };
    if member.digest != digest {
        bail!(
            "change-set pin {kind} member {id} digest {} does not match required {digest}",
            member.digest
        );
    }
    Ok(())
}

fn require_kind_digest(pin: &ChangeSetPin, kind: &str, digest: &str) -> Result<()> {
    if pin
        .members
        .iter()
        .any(|member| member.kind == kind && member.digest == digest)
    {
        return Ok(());
    }
    bail!("change-set pin is missing {kind} digest {digest}");
}

pub fn observed_from_object(env_obj: &Object) -> Result<Option<ObservedCompatibility>> {
    let type_digest = env_obj.properties.get(OBSERVED_TYPE).cloned();
    let runtime_digest = env_obj.properties.get(OBSERVED_RUNTIME).cloned();
    match (type_digest, runtime_digest) {
        (None, None) => Ok(None),
        (Some(type_digest), Some(runtime_digest)) => {
            let observed = ObservedCompatibility {
                type_digest,
                runtime_digest,
            };
            validate_observed(&observed)?;
            Ok(Some(observed))
        }
        _ => bail!(
            "environment observed type and runtime digests must be set together; incomplete observation fails closed"
        ),
    }
}

fn validate_observed(observed: &ObservedCompatibility) -> Result<()> {
    signature_verification::validate_prefixed_digest(
        "observed type digest",
        &observed.type_digest,
    )?;
    signature_verification::validate_prefixed_digest(
        "observed runtime digest",
        &observed.runtime_digest,
    )?;
    Ok(())
}

pub async fn set_observed_compatibility(
    ctx: &mut Ctx,
    env: &str,
    type_digest: &str,
    runtime_digest: &str,
) -> Result<String> {
    crate::ontology::validate_identifier("environment", env)?;
    let observed = ObservedCompatibility {
        type_digest: type_digest.to_string(),
        runtime_digest: runtime_digest.to_string(),
    };
    validate_observed(&observed)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    env_obj
        .properties
        .insert(OBSERVED_TYPE.into(), observed.type_digest.clone());
    env_obj
        .properties
        .insert(OBSERVED_RUNTIME.into(), observed.runtime_digest.clone());
    env_obj.updated = crate::now_millis();
    ctx.put(env_obj).await?;
    Ok(format!(
        "set {env} observed type={} runtime={}",
        observed.type_digest, observed.runtime_digest
    ))
}

pub fn activations_from_object(env_obj: &Object) -> Result<Vec<ModuleActivationReceipt>> {
    let mut receipts = Vec::new();
    for (key, value) in &env_obj.properties {
        if key.starts_with(ACTIVATION_PREFIX) {
            receipts.push(parse_receipt(value)?);
        }
    }
    receipts.sort_by(|left, right| left.product.cmp(&right.product));
    Ok(receipts)
}

fn parse_receipt(raw: &str) -> Result<ModuleActivationReceipt> {
    let receipt: ModuleActivationReceipt = serde_json::from_str(raw)?;
    receipt.validate()?;
    Ok(receipt)
}

impl ModuleActivationReceipt {
    fn validate(&self) -> Result<()> {
        if self.schema != ACTIVATION_SCHEMA {
            bail!(
                "unknown workshop module activation schema {:?}; expected {ACTIVATION_SCHEMA}",
                self.schema
            );
        }
        crate::ontology::validate_identifier("module_activation.environment", &self.environment)?;
        crate::ontology::validate_identifier("module_activation.product", &self.product)?;
        crate::ontology::validate_identifier("module_activation.module_id", &self.module_id)?;
        signature_verification::validate_prefixed_digest(
            "module_activation.module_digest",
            &self.module_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "module_activation.type_digest",
            &self.type_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "module_activation.runtime_digest",
            &self.runtime_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "module_activation.closure_digest",
            &self.closure_digest,
        )?;
        signature_verification::validate_prefixed_digest(
            "module_activation.pin_digest",
            &self.pin_digest,
        )?;
        let expected = self.identity_digest()?;
        if self.receipt_digest != expected {
            bail!("module activation receipt digest does not match its canonical identity");
        }
        Ok(())
    }

    fn identity_digest(&self) -> Result<String> {
        let mut output = b"TENKAI-WORKSHOP-MODULE-ACTIVATION-V1\0".to_vec();
        for value in [
            &self.schema,
            &self.environment,
            &self.product,
            &self.release,
            &self.module_id,
            &self.module_digest,
            &self.type_digest,
            &self.runtime_digest,
            &self.closure_digest,
            &self.pin_digest,
        ] {
            signature_verification::push_len_prefixed(&mut output, value.as_bytes());
        }
        Ok(format!("sha256:{:x}", Sha256::digest(output)))
    }

    fn matches_identity(&self, other: &Self) -> bool {
        self.environment == other.environment
            && self.product == other.product
            && self.release == other.release
            && self.module_digest == other.module_digest
            && self.type_digest == other.type_digest
            && self.runtime_digest == other.runtime_digest
            && self.closure_digest == other.closure_digest
            && self.pin_digest == other.pin_digest
            && self.receipt_digest == other.receipt_digest
    }
}

pub fn admit_compatibility(
    doc: &WorkshopModuleDocument,
    observed: &ObservedCompatibility,
) -> Result<()> {
    if !doc.type_compatibility.contains(&observed.type_digest) {
        bail!(
            "observed type digest {} is incompatible with workshop module {}",
            observed.type_digest,
            doc.module_id
        );
    }
    if !doc.runtime_compatibility.contains(&observed.runtime_digest) {
        bail!(
            "observed runtime digest {} is incompatible with workshop module {}",
            observed.runtime_digest,
            doc.module_id
        );
    }
    Ok(())
}

pub async fn admit_plan(
    ctx: &mut Ctx,
    env: &str,
    env_obj: &Object,
    release_id: &str,
) -> Result<()> {
    let release = ctx
        .get(release_id)
        .await?
        .with_context(|| format!("release {release_id} not found for workshop module admission"))?;
    let raw = release
        .properties
        .get("manifest")
        .with_context(|| format!("release {release_id} has no stored manifest"))?;
    let manifest = crate::manifest::parse_raw(raw)?;
    let workdir = release
        .properties
        .get("workdir")
        .with_context(|| format!("release {release_id} has no stored workdir"))?;
    let doc = document_from_manifest(&manifest, Path::new(workdir))?;
    let Some(pin) = crate::change_set_pin::stored_projection(&release)? else {
        bail!("workshop_module release {release_id} is missing accepted closure pin evidence");
    };
    let Some(observed) = observed_from_object(env_obj)? else {
        bail!(
            "environment {env} has no observed type and runtime digests; set them before planning a workshop_module"
        );
    };
    admit_compatibility(&doc, &observed)?;
    let _ = pin;
    Ok(())
}

pub async fn activate(
    ctx: &mut Ctx,
    env: &str,
    product: &str,
    manifest: &Manifest,
    workdir: &Path,
    state_root: &Path,
) -> Result<()> {
    let doc = document_from_manifest(manifest, workdir)?;
    let mut env_obj = crate::environment::environment(ctx, env).await?;
    let observed = observed_from_object(&env_obj)?.with_context(|| {
        format!(
            "environment {env} has no observed type and runtime digests; refusing workshop_module mutation"
        )
    })?;
    admit_compatibility(&doc, &observed)?;
    let release = format!("{}@{}", manifest.product.name, manifest.product.version);
    let release_object = ctx
        .get(&crate::ontology::release_id(
            &manifest.product.name,
            &manifest.product.version,
        ))
        .await?
        .with_context(|| format!("release {release} is not published"))?;
    let pin = crate::change_set_pin::stored_projection(&release_object)?
        .with_context(|| format!("release {release} is missing accepted closure pin evidence"))?;
    let mut receipt = ModuleActivationReceipt {
        schema: ACTIVATION_SCHEMA.into(),
        environment: env.into(),
        product: product.into(),
        release,
        module_id: doc.module_id.clone(),
        module_digest: doc.module_digest.clone(),
        type_digest: observed.type_digest.clone(),
        runtime_digest: observed.runtime_digest.clone(),
        closure_digest: pin.closure_digest,
        pin_digest: pin.pin_digest,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt.identity_digest()?;
    receipt.validate()?;

    if let Some(existing) = activation_from_object(&env_obj, product)? {
        if existing.matches_identity(&receipt) {
            if staged_profile_matches(state_root, product, &doc)? {
                return Ok(());
            }
        } else if existing.release == receipt.release
            && (existing.module_digest != receipt.module_digest
                || existing.type_digest != receipt.type_digest
                || existing.runtime_digest != receipt.runtime_digest)
        {
            bail!(
                "workshop module {} already has a conflicting activation receipt under the same release identity",
                product
            );
        }
    }

    crate::staged_artifact::activate(manifest, workdir, state_root, product)?;
    env_obj = crate::environment::environment(ctx, env).await?;
    let after = observed_from_object(&env_obj)?.with_context(|| {
        format!("environment {env} lost observed type and runtime digests during module activation")
    })?;
    if after != observed {
        let _ = crate::staged_artifact::deactivate(
            crate::manifest::ProductKind::WorkshopModule,
            state_root,
            product,
        );
        bail!(
            "workshop_module activation changed observed type or runtime digests; module-only delivery must preserve them"
        );
    }
    env_obj.properties.insert(
        format!("{ACTIVATION_PREFIX}{product}"),
        serde_json::to_string(&receipt)?,
    );
    env_obj.updated = crate::now_millis();
    if let Err(error) = ctx.put(env_obj).await {
        let _ = crate::staged_artifact::deactivate(
            crate::manifest::ProductKind::WorkshopModule,
            state_root,
            product,
        );
        return Err(error);
    }
    Ok(())
}

fn staged_profile_matches(
    state_root: &Path,
    product: &str,
    expected: &WorkshopModuleDocument,
) -> Result<bool> {
    let path = crate::staged_artifact::state_path_for(
        crate::manifest::ProductKind::WorkshopModule,
        state_root,
        product,
    );
    match crate::atomic_state::read_optional(&path)? {
        Some(bytes) => Ok(parse_document_bytes(&bytes)? == *expected),
        None => Ok(false),
    }
}

pub async fn deactivate(ctx: &mut Ctx, env: &str, product: &str, state_root: &Path) -> Result<()> {
    let path = crate::staged_artifact::state_path_for(
        crate::manifest::ProductKind::WorkshopModule,
        state_root,
        product,
    );
    let prior = crate::atomic_state::read_optional(&path)?;
    crate::staged_artifact::deactivate(
        crate::manifest::ProductKind::WorkshopModule,
        state_root,
        product,
    )?;
    let persist = async {
        let mut env_obj = crate::environment::environment(ctx, env).await?;
        env_obj
            .properties
            .remove(&format!("{ACTIVATION_PREFIX}{product}"));
        env_obj.updated = crate::now_millis();
        ctx.put(env_obj).await?;
        Ok::<(), anyhow::Error>(())
    };
    if let Err(error) = persist.await {
        if let Some(bytes) = prior
            && let Err(restore) =
                crate::atomic_state::write_bytes_verified(&path, &bytes, |_| Ok(()))
        {
            return Err(error.context(format!(
                "restoring staged workshop module after receipt update failed: {restore}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

fn activation_from_object(
    env_obj: &Object,
    product: &str,
) -> Result<Option<ModuleActivationReceipt>> {
    match env_obj
        .properties
        .get(&format!("{ACTIVATION_PREFIX}{product}"))
    {
        Some(raw) => Ok(Some(parse_receipt(raw)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
pub(crate) fn sample_digests() -> (String, String, String) {
    (
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        format!("sha256:{}", "3".repeat(64)),
    )
}

#[cfg(test)]
pub(crate) fn sample_document() -> WorkshopModuleDocument {
    let (module_digest, type_digest, runtime_digest) = sample_digests();
    WorkshopModuleDocument {
        version: MODULE_DOCUMENT_VERSION,
        profile: MODULE_PROFILE.into(),
        module_id: "hello-workshop".into(),
        module_digest,
        type_compatibility: CompatibilitySet {
            version: COMPATIBILITY_VERSION,
            digests: vec![type_digest],
        },
        runtime_compatibility: CompatibilitySet {
            version: COMPATIBILITY_VERSION,
            digests: vec![runtime_digest],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{self, PublishOptions};
    use crate::change_set_pin::{
        ChangeSetEvidenceInput, ChangeSetMember, ChangeSetPublicationEvidence, EVIDENCE_SCHEMA,
        PIN_CONTRACT,
    };
    use crate::client::Ctx;
    use crate::manifest::{ChangeSetMemberSection, ChangeSetPinSection};

    fn pin_section(doc: &WorkshopModuleDocument) -> ChangeSetPinSection {
        ChangeSetPinSection {
            contract: PIN_CONTRACT.into(),
            namespace: "workshop".into(),
            branch_id: "modules".into(),
            proposal_id: "prop-1".into(),
            base_digest: format!("sha256:{}", "a".repeat(64)),
            closure_digest: format!("sha256:{}", "b".repeat(64)),
            receipt_digest: format!("sha256:{}", "c".repeat(64)),
            members: vec![
                ChangeSetMemberSection {
                    kind: MEMBER_KIND_RUNTIME.into(),
                    id: "runtime-local".into(),
                    digest: doc.runtime_compatibility.digests[0].clone(),
                },
                ChangeSetMemberSection {
                    kind: MEMBER_KIND_TYPE.into(),
                    id: "type-v1".into(),
                    digest: doc.type_compatibility.digests[0].clone(),
                },
                ChangeSetMemberSection {
                    kind: MEMBER_KIND_MODULE.into(),
                    id: doc.module_id.clone(),
                    digest: doc.module_digest.clone(),
                },
            ],
        }
    }

    fn evidence_for(section: &ChangeSetPinSection) -> ChangeSetPublicationEvidence {
        ChangeSetPublicationEvidence {
            schema: EVIDENCE_SCHEMA.into(),
            status: "accepted".into(),
            authorized: true,
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
        }
    }

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

    fn write_module_release(dir: &Path, name: &str, version: &str, doc: &WorkshopModuleDocument) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("module.json"),
            serde_json::to_vec_pretty(doc).unwrap(),
        )
        .unwrap();
        let section = pin_section(doc);
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "{name}"
version = "{version}"
kind = "workshop_module"
[module]
document = "module.json"
{}
"#,
                pin_toml(&section)
            ),
        )
        .unwrap();
    }

    fn publish_options(doc: &WorkshopModuleDocument) -> PublishOptions {
        let section = pin_section(doc);
        PublishOptions {
            signature: None,
            trust_roots: None,
            allow_unsigned_development: true,
            provenance: Vec::new(),
            provenance_trust_roots: None,
            change_set_evidence: Some(ChangeSetEvidenceInput::Document(Box::new(evidence_for(
                &section,
            )))),
        }
    }

    #[test]
    fn document_rejects_unknown_profile_and_empty_compatibility() {
        let mut doc = sample_document();
        doc.profile = "tenkai.workshop_module.v2".into();
        assert!(doc.validate().is_err());
        let mut doc = sample_document();
        doc.type_compatibility.digests.clear();
        assert!(doc.validate().is_err());
        let mut doc = sample_document();
        doc.runtime_compatibility.version = 2;
        assert!(doc.validate().is_err());
    }

    #[test]
    fn compatibility_fails_closed_on_digest_mismatch() {
        let doc = sample_document();
        let err = admit_compatibility(
            &doc,
            &ObservedCompatibility {
                type_digest: format!("sha256:{}", "9".repeat(64)),
                runtime_digest: doc.runtime_compatibility.digests[0].clone(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("incompatible"), "{err}");
    }

    #[tokio::test]
    async fn publish_plan_apply_preserves_type_runtime_and_receipt() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-workshop-e2e-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let v1 = root.join("v1");
        let v2 = root.join("v2");
        let doc_v1 = sample_document();
        let mut doc_v2 = sample_document();
        doc_v2.module_digest = format!("sha256:{}", "4".repeat(64));
        write_module_release(&v1, "hello-workshop", "1.0.0", &doc_v1);
        write_module_release(&v2, "hello-workshop", "1.0.1", &doc_v2);

        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        catalog::publish(&mut ctx, &v1.join("tenkai.toml"), &publish_options(&doc_v1))
            .await
            .unwrap();
        catalog::publish(&mut ctx, &v2.join("tenkai.toml"), &publish_options(&doc_v2))
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("workshop-promote");
        catalog::promote(&mut ctx, &actor, "hello-workshop@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        set_observed_compatibility(
            &mut ctx,
            "local",
            &doc_v1.type_compatibility.digests[0],
            &doc_v1.runtime_compatibility.digests[0],
        )
        .await
        .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "hello-workshop", "stable")
            .await
            .unwrap();

        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "workshop module e2e",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();

        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let observed = observed_from_object(&env).unwrap().unwrap();
        assert_eq!(observed.type_digest, doc_v1.type_compatibility.digests[0]);
        assert_eq!(
            observed.runtime_digest,
            doc_v1.runtime_compatibility.digests[0]
        );
        let first = activations_from_object(&env).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].module_digest, doc_v1.module_digest);
        let first_receipt = first[0].clone();
        let state_root = root.join(".tenkai-state/runtime/local/routing");
        let staged = crate::staged_artifact::state_path_for(
            crate::manifest::ProductKind::WorkshopModule,
            &state_root,
            "hello-workshop",
        );
        assert!(staged.exists());
        std::fs::remove_file(&staged).unwrap();

        let restart_step = crate::plan::restart_step(&mut ctx, "local", "hello-workshop")
            .await
            .unwrap();
        let restart = crate::plan::create_from_steps(&mut ctx, "local", vec![restart_step])
            .await
            .unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &restart.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "workshop module restart",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let again = activations_from_object(&env).unwrap();
        assert_eq!(again, vec![first_receipt.clone()]);
        assert!(
            staged.exists(),
            "restart must restage a missing module profile"
        );

        catalog::promote(&mut ctx, &actor, "hello-workshop@1.0.1", "stable")
            .await
            .unwrap();
        let upgrade = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &upgrade.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "workshop module upgrade",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let observed = observed_from_object(&env).unwrap().unwrap();
        assert_eq!(observed.type_digest, doc_v1.type_compatibility.digests[0]);
        let upgraded = activations_from_object(&env).unwrap();
        assert_eq!(upgraded[0].module_digest, doc_v2.module_digest);
        assert_eq!(upgraded[0].type_digest, observed.type_digest);

        let rollback_step = crate::plan::rollback_step(&mut ctx, "local", "hello-workshop")
            .await
            .unwrap();
        let rollback = crate::plan::create_from_steps(&mut ctx, "local", vec![rollback_step])
            .await
            .unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &rollback.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "workshop module rollback",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let rolled = activations_from_object(&env).unwrap();
        assert_eq!(rolled[0].module_digest, doc_v1.module_digest);

        set_observed_compatibility(
            &mut ctx,
            "local",
            &format!("sha256:{}", "9".repeat(64)),
            &doc_v1.runtime_compatibility.digests[0],
        )
        .await
        .unwrap();
        let err = crate::plan::create(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("incompatible"), "{err}");

        catalog::recall(&mut ctx, &actor, "hello-workshop@1.0.0")
            .await
            .unwrap();
        catalog::promote(&mut ctx, &actor, "hello-workshop@1.0.1", "stable")
            .await
            .unwrap();
        set_observed_compatibility(
            &mut ctx,
            "local",
            &doc_v1.type_compatibility.digests[0],
            &doc_v1.runtime_compatibility.digests[0],
        )
        .await
        .unwrap();
        catalog::recall(&mut ctx, &actor, "hello-workshop@1.0.1")
            .await
            .unwrap();
        let err = crate::plan::create(&mut ctx, "local")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("recalled"), "{err}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn missing_pin_and_unauthorized_evidence_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-workshop-deny-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        std::fs::create_dir_all(&root).unwrap();
        let doc = sample_document();
        std::fs::write(
            root.join("module.json"),
            serde_json::to_vec_pretty(&doc).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("tenkai.toml"),
            r#"
[product]
name = "hello-workshop"
version = "1.0.0"
kind = "workshop_module"
[module]
document = "module.json"
"#,
        )
        .unwrap();
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let err = catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("closure pin") || err.contains("change-set"),
            "{err}"
        );

        write_module_release(&root, "hello-workshop", "1.0.1", &doc);
        let mut unauthorized = evidence_for(&pin_section(&doc));
        unauthorized.authorized = false;
        let err = catalog::publish(
            &mut ctx,
            &root.join("tenkai.toml"),
            &PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: Some(ChangeSetEvidenceInput::Document(Box::new(unauthorized))),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("unauthorized"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failed_restore_records_recovery_required() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-workshop-restore-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        let database = root.join("tenkai.db");
        let v1 = root.join("v1");
        let v2 = root.join("v2");
        let doc_v1 = sample_document();
        let mut doc_v2 = sample_document();
        doc_v2.module_digest = format!("sha256:{}", "4".repeat(64));
        write_module_release(&v1, "hello-workshop", "1.0.0", &doc_v1);
        write_module_release(&v2, "hello-workshop", "1.0.1", &doc_v2);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        catalog::publish(&mut ctx, &v1.join("tenkai.toml"), &publish_options(&doc_v1))
            .await
            .unwrap();
        catalog::publish(&mut ctx, &v2.join("tenkai.toml"), &publish_options(&doc_v2))
            .await
            .unwrap();
        let actor = crate::auth_context::test_management_context("workshop-restore");
        catalog::promote(&mut ctx, &actor, "hello-workshop@1.0.0", "stable")
            .await
            .unwrap();
        crate::plan::env_add(&mut ctx, "local", "fixture")
            .await
            .unwrap();
        set_observed_compatibility(
            &mut ctx,
            "local",
            &doc_v1.type_compatibility.digests[0],
            &doc_v1.runtime_compatibility.digests[0],
        )
        .await
        .unwrap();
        crate::plan::subscribe(&mut ctx, "local", "hello-workshop", "stable")
            .await
            .unwrap();
        let plan = crate::plan::create(&mut ctx, "local").await.unwrap();
        crate::apply::execute_with_options(
            &mut ctx,
            &plan.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "workshop restore setup",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
        .unwrap();
        catalog::promote(&mut ctx, &actor, "hello-workshop@1.0.1", "stable")
            .await
            .unwrap();
        let upgrade = crate::plan::create(&mut ctx, "local").await.unwrap();
        set_observed_compatibility(
            &mut ctx,
            "local",
            &format!("sha256:{}", "9".repeat(64)),
            &doc_v1.runtime_compatibility.digests[0],
        )
        .await
        .unwrap();
        let _ = crate::apply::execute_with_options(
            &mut ctx,
            &upgrade.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: crate::apply::ExecutionAuthorization::LocalDevelopment {
                    reason: "workshop restore fail",
                },
                software_executor: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await;
        let env = crate::environment::environment(&mut ctx, "local")
            .await
            .unwrap();
        let health = env
            .properties
            .get("deployment_health.hello-workshop")
            .cloned()
            .unwrap_or_default();
        assert!(
            health == "unknown" || health == "unhealthy" || health == "failed",
            "expected recovery-required health, got {health}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

//! Local plan-approval verification for the environment runtime (ADR 0045 §4).
//!
//! The runtime holds an approval policy and trust roots on its own host,
//! outside the server's reach, and shares evaluation with the host applier
//! ([`crate::host_apply::HostApprovalPolicy`]). A step that writes a sealed
//! secret is refused unless those envelopes meet the local policy. Other
//! steps are unchanged.

use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

use crate::host_apply::HostApprovalPolicy;
use crate::plan::{Plan, Step};
use crate::plan_approval::ApprovalEnvelope;

const RUNTIME_REFUSAL: &str = "runtime approval policy";

/// Whether a sealed step may run, should wait for more envelopes, or must
/// fail the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepDecision {
    Allowed,
    /// Approvals have not met the local quorum yet. Keep the claim; do not
    /// complete it, so later envelopes can still authorize the same plan.
    Wait(String),
    /// Unrecoverable: no policy, or envelopes bound to different content.
    Refuse(String),
}

/// Load a runtime-local approval policy. The file and its parent directory
/// must be owned by this process's user and not writable by group or others,
/// so a compromised server cannot replace the file between stat and read.
pub fn load(path: &Path) -> Result<HostApprovalPolicy> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        require_owner_only(parent)?;
    }
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    require_owner_only_meta(
        &file
            .metadata()
            .with_context(|| format!("statting {}", path.display()))?,
        path,
    )?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("reading {}", path.display()))?;
    HostApprovalPolicy::parse(&raw)
        .with_context(|| format!("loading runtime approval policy {}", path.display()))
}

/// Before `step` runs: if it writes a sealed secret, recompute the plan
/// digest, find the step, and evaluate `envelopes` against `policy`. A
/// runtime with no policy refuses that step with a named reason. Empty or
/// incomplete envelopes wait rather than failing the plan.
pub fn decide_step(
    policy: Option<&HostApprovalPolicy>,
    plan: &Plan,
    step: &Step,
    envelopes: &[ApprovalEnvelope],
    now_ms: i64,
) -> Result<StepDecision> {
    let planned = plan
        .steps
        .iter()
        .find(|candidate| candidate.id == step.id)
        .with_context(|| format!("plan {} has no step {}", plan.id, step.id))?;
    if !planned.requires_local_approval_policy() {
        return Ok(StepDecision::Allowed);
    }
    let Some(policy) = policy else {
        return Ok(StepDecision::Refuse(format!(
            "runtime has no local approval policy; refusing sealed step {}",
            step.id
        )));
    };
    match policy.verify_plan_as(RUNTIME_REFUSAL, plan, envelopes, now_ms) {
        Ok(_) => Ok(StepDecision::Allowed),
        Err(error) => {
            let message = format!("{error:#}");
            if message.contains("different executable content") {
                return Ok(StepDecision::Refuse(message));
            }
            Ok(StepDecision::Wait(message))
        }
    }
}

/// Strict form of [`decide_step`]: wait and refuse both surface as errors.
pub fn require_step(
    policy: Option<&HostApprovalPolicy>,
    plan: &Plan,
    step: &Step,
    envelopes: &[ApprovalEnvelope],
    now_ms: i64,
) -> Result<()> {
    match decide_step(policy, plan, step, envelopes, now_ms)? {
        StepDecision::Allowed => Ok(()),
        StepDecision::Wait(reason) | StepDecision::Refuse(reason) => bail!("{reason}"),
    }
}

fn require_owner_only(path: &Path) -> Result<()> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    require_owner_only_meta(&metadata, path)
}

fn require_owner_only_meta(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
    // SAFETY: geteuid is always defined on Unix and has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        bail!(
            "runtime approval policy {} is owned by uid {}, not by this process",
            path.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "runtime approval policy {} is writable by group or others",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_policy::{QuorumPurpose, QuorumRule};
    use crate::host_apply::fixture::{self, HostFixture};
    use crate::plan::{Action, SealedStep};
    use crate::plan_approval::ApprovalEnvelope;

    fn rule(n: u32) -> QuorumRule {
        QuorumRule {
            purpose: QuorumPurpose::ExecutePlan,
            n,
            groups: vec!["ops".into()],
            exclude_requester: false,
            min_criticality: None,
        }
    }

    fn sealed_plan(now: i64) -> crate::plan::Plan {
        let id = format!("tenkai:plan:edge:{now}");
        crate::plan::Plan {
            format_version: crate::plan::PLAN_FORMAT_VERSION,
            id: id.clone(),
            content_id: format!("content-{now}"),
            environment: "edge".into(),
            created_at: now,
            inputs: Vec::new(),
            steps: vec![crate::plan::Step {
                id: format!("{id}:step:0"),
                order: 0,
                product: "api".into(),
                instance: String::new(),
                action: Action::Install,
                from: None,
                to: "1.0.0".into(),
                release_id: crate::ontology::release_id("api", "1.0.0"),
                release_digest: "sha256:manifest".into(),
                artifact_digest: "sha256:artifact".into(),
                workdir: "/var/lib/tenkai/releases/unused".into(),
                restore: None,
                host: None,
                sealed: Some(SealedStep {
                    secret: "db".into(),
                    key: "password".into(),
                    digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .into(),
                }),
            }],
            state: crate::plan::PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
        }
    }

    fn envelopes(
        fixture: &HostFixture,
        plan: &crate::plan::Plan,
        now: i64,
        who: &[usize],
    ) -> Vec<ApprovalEnvelope> {
        who.iter()
            .map(|index| fixture.approve(plan, *index, now))
            .collect()
    }

    #[test]
    fn ordinary_steps_do_not_need_a_local_policy() {
        let now = crate::now_millis();
        let mut plan = sealed_plan(now);
        plan.steps[0].sealed = None;
        require_step(None, &plan, &plan.steps[0], &[], now).unwrap();
    }

    #[test]
    fn sealed_step_without_a_local_policy_is_refused() {
        let now = crate::now_millis();
        let plan = sealed_plan(now);
        let error = require_step(None, &plan, &plan.steps[0], &[], now).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no local approval policy"), "{message}");
        assert!(message.contains(&plan.steps[0].id), "{message}");
    }

    #[test]
    fn envelopes_below_local_quorum_are_refused() {
        let fixture = HostFixture::new(&[("alice", &["ops"]), ("bob", &["ops"])], vec![rule(2)]);
        let now = crate::now_millis();
        let plan = sealed_plan(now);
        let one = envelopes(&fixture, &plan, now, &[0]);
        let error = require_step(
            Some(&fixture.trust.policy),
            &plan,
            &plan.steps[0],
            &one,
            now,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("runtime approval policy"), "{message}");
        assert!(
            message.contains("need 2 execute_plan approvals"),
            "{message}"
        );
        require_step(
            Some(&fixture.trust.policy),
            &plan,
            &plan.steps[0],
            &envelopes(&fixture, &plan, now, &[0, 1]),
            now,
        )
        .unwrap();
    }

    #[test]
    fn plan_altered_after_approval_fails_the_digest_check() {
        let fixture = HostFixture::new(&[("alice", &["ops"])], vec![rule(1)]);
        let now = crate::now_millis();
        let mut plan = sealed_plan(now);
        let signed = envelopes(&fixture, &plan, now, &[0]);
        plan.steps[0].to = "9.9.9".into();
        let error = require_step(
            Some(&fixture.trust.policy),
            &plan,
            &plan.steps[0],
            &signed,
            now,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("different executable content"),
            "{message}"
        );
    }

    #[test]
    fn revoked_approver_key_does_not_count() {
        // Seeds no other test uses: revocation is process-wide.
        let mut fixture = HostFixture::new(&[("alice", &["ops"])], vec![rule(1)]);
        let revoked = fixture::key(251);
        fixture.approvers[0].key = revoked.clone();
        fixture.trust.policy.signers[0] = fixture::signer("alice", &revoked, &["ops"]);
        let now = crate::now_millis();
        let plan = sealed_plan(now);
        let signed = envelopes(&fixture, &plan, now, &[0]);
        require_step(
            Some(&fixture.trust.policy),
            &plan,
            &plan.steps[0],
            &signed,
            now,
        )
        .unwrap();

        let authority = fixture::key(252);
        let authorities = crate::release_signing::TrustRoots {
            version: 1,
            signers: vec![crate::release_signing::TrustedSigner::new(
                fixture::key_id(&authority),
                "revocations@example.com",
                fixture::public_key(&authority),
            )],
        };
        let dir = std::env::temp_dir().join(format!(
            "tenkai-runtime-revocations-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = dir.join("authority.seed");
        std::fs::write(&seed, [252_u8; 32]).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        let list = crate::key_revocation::sign(
            crate::key_revocation::RevocationStatement {
                sequence: 1,
                issued_at: now,
                revoked: vec![crate::key_revocation::RevokedKey {
                    key_id: fixture::key_id(&revoked),
                    reason: "compromised".into(),
                }],
            },
            &seed,
        )
        .unwrap();
        let installed = dir.join("key-revocations.json");
        std::fs::write(&installed, serde_json::to_vec(&list).unwrap()).unwrap();
        crate::key_revocation::load_installed(&installed, &authorities).unwrap();
        let error = require_step(
            Some(&fixture.trust.policy),
            &plan,
            &plan.steps[0],
            &signed,
            now,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("revoked"), "{message}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_step_without_a_sealed_binding_encodes_as_before() {
        let plan = sealed_plan(crate::now_millis());
        let bound = serde_json::to_value(&plan.steps[0]).unwrap();
        assert_eq!(bound["sealed"]["secret"], "db");
        let mut unbound_plan = plan;
        unbound_plan.steps[0].sealed = None;
        let unbound = serde_json::to_value(&unbound_plan.steps[0]).unwrap();
        assert!(unbound.get("sealed").is_none(), "{unbound}");
        let decoded: crate::plan::Step = serde_json::from_value(unbound).unwrap();
        assert_eq!(decoded.sealed, None);
    }

    #[test]
    fn empty_envelopes_wait_instead_of_refusing() {
        let fixture = HostFixture::new(&[("alice", &["ops"])], vec![rule(1)]);
        let now = crate::now_millis();
        let plan = sealed_plan(now);
        match decide_step(Some(&fixture.trust.policy), &plan, &plan.steps[0], &[], now).unwrap() {
            StepDecision::Wait(reason) => {
                assert!(reason.contains("runtime approval policy"), "{reason}");
            }
            other => panic!("expected wait, got {other:?}"),
        }
    }

    #[test]
    fn missing_policy_refuses_rather_than_waiting() {
        let now = crate::now_millis();
        let plan = sealed_plan(now);
        match decide_step(None, &plan, &plan.steps[0], &[], now).unwrap() {
            StepDecision::Refuse(reason) => {
                assert!(reason.contains("no local approval policy"), "{reason}");
            }
            other => panic!("expected refuse, got {other:?}"),
        }
    }

    #[test]
    fn load_refuses_a_group_writable_parent() {
        let fixture = HostFixture::new(&[("alice", &["ops"])], vec![rule(1)]);
        let dir = std::env::temp_dir().join(format!(
            "tenkai-runtime-policy-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, toml::to_string(&fixture.trust.policy).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        load(&path).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        let message = format!("{:#}", load(&path).unwrap_err());
        assert!(message.contains("writable by group or others"), "{message}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

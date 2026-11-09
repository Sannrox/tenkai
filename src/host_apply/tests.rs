use std::path::PathBuf;

use super::fixture::{self, HostFixture, SignedRelease, StepSpec};
use super::*;
use crate::approval_policy::{QuorumPurpose, QuorumRule};
use crate::plan::Action;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-host-apply-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn rule(purpose: QuorumPurpose, n: u32, groups: &[&str]) -> QuorumRule {
    QuorumRule {
        purpose,
        n,
        groups: groups.iter().map(|group| group.to_string()).collect(),
        exclude_requester: false,
        min_criticality: None,
    }
}

struct Case {
    fixture: HostFixture,
    workdir: PathBuf,
    release: SignedRelease,
}

impl Case {
    fn new(quorum: Vec<QuorumRule>) -> Self {
        let fixture = HostFixture::new(
            &[("alice", &["ops"]), ("bob", &["ops"]), ("carol", &["qa"])],
            quorum,
        );
        let workdir = temp_dir("release");
        let release = fixture.release(
            &workdir,
            "k3s",
            "1.2.0",
            ["./install.sh", "./uninstall.sh", "./health.sh"],
            &[
                ("install.sh", b"#!/bin/sh\nexit 0\n"),
                ("bin/k3s", b"binary"),
            ],
        );
        Self {
            fixture,
            workdir,
            release,
        }
    }

    fn spec(&self, action: HostAction, step_action: Action, from: Option<&str>) -> StepSpec {
        StepSpec {
            release: self.release.clone(),
            action,
            step_action,
            from: from.map(str::to_string),
            expected_generation: 0,
        }
    }

    fn install_request(&self, approvers: &[usize]) -> HostApplyRequest {
        let now = crate::now_millis();
        let plan = self.fixture.plan(
            "edge",
            now,
            &[self.spec(HostAction::Install, Action::Install, None)],
        );
        let approvals = approvers
            .iter()
            .map(|index| self.fixture.approve(&plan, *index, now))
            .collect();
        self.fixture.request(&plan, 0, &self.release, approvals)
    }

    fn verify(&self, request: &HostApplyRequest) -> anyhow::Result<VerifiedHostStep> {
        verify_copied_request(
            request,
            &request.instance()?,
            &self.workdir,
            &self.fixture.trust,
            crate::now_millis(),
        )
    }
}

fn refusal(result: anyhow::Result<VerifiedHostStep>) -> String {
    format!("{:#}", result.expect_err("verification must refuse"))
}

#[test]
fn verified_step_comes_from_signed_and_approved_content() {
    let case = Case::new(Vec::new());
    let request = case.install_request(&[0]);
    let verified = case.verify(&request).unwrap();
    assert_eq!(verified.product, "k3s");
    assert_eq!(verified.environment, "edge");
    assert_eq!(verified.action, HostAction::Install);
    assert_eq!(verified.command, "./install.sh");
    assert_eq!(verified.release.version, "1.2.0");
    assert_eq!(verified.expected_generation, 0);
    assert_eq!(verified.instance, request.instance().unwrap());
}

#[test]
fn tampered_artifact_is_refused() {
    let case = Case::new(Vec::new());
    let request = case.install_request(&[0]);
    std::fs::write(case.workdir.join("bin/k3s"), b"other binary").unwrap();
    assert!(refusal(case.verify(&request)).contains("do not match their signed digest"));
}

#[test]
fn unsigned_or_untrusted_release_signer_is_refused() {
    let case = Case::new(Vec::new());
    let mut request = case.install_request(&[0]);
    request.signature = fixture::sign_release_with(
        &fixture::key(9),
        &request.signature.statement.manifest_digest,
        &request.signature.statement.artifact_digest,
        crate::now_millis(),
    );
    assert!(refusal(case.verify(&request)).contains("is not trusted"));

    let mut unsigned = case.install_request(&[0]);
    unsigned.signature.signature =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 64]);
    assert!(refusal(case.verify(&unsigned)).contains("release signature"));
}

#[test]
fn revoked_release_signer_is_refused() {
    // Seeds no other test uses: revocation is process-wide.
    let mut case = Case::new(Vec::new());
    let revoked = fixture::key(241);
    case.fixture.release_key = revoked.clone();
    case.fixture.trust.release_roots.signers = vec![crate::release_signing::TrustedSigner::new(
        fixture::key_id(&revoked),
        "revoked@example.com",
        fixture::public_key(&revoked),
    )];
    case.release = case.fixture.release(
        &case.workdir,
        "k3s",
        "1.2.0",
        ["./install.sh", "./uninstall.sh", "./health.sh"],
        &[],
    );
    let request = case.install_request(&[0]);
    case.verify(&request).unwrap();

    let authority = fixture::key(242);
    let authorities = crate::release_signing::TrustRoots {
        version: 1,
        signers: vec![crate::release_signing::TrustedSigner::new(
            fixture::key_id(&authority),
            "revocations@example.com",
            fixture::public_key(&authority),
        )],
    };
    let dir = temp_dir("revocations");
    let seed = dir.join("authority.seed");
    std::fs::write(&seed, [242_u8; 32]).unwrap();
    std::fs::set_permissions(&seed, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let list = crate::key_revocation::sign(
        crate::key_revocation::RevocationStatement {
            sequence: 1,
            issued_at: crate::now_millis(),
            revoked: vec![crate::key_revocation::RevokedKey {
                key_id: fixture::key_id(&revoked),
                reason: "compromised".into(),
            }],
        },
        &crate::signer::open_key(&seed).unwrap(),
    )
    .unwrap();
    let installed = dir.join("key-revocations.json");
    std::fs::write(&installed, serde_json::to_vec(&list).unwrap()).unwrap();
    crate::key_revocation::load_installed(&installed, &authorities).unwrap();
    assert!(refusal(case.verify(&request)).contains("revoked"));
}

#[test]
fn release_signer_outside_its_window_is_refused() {
    let mut case = Case::new(Vec::new());
    let now = crate::now_millis();
    case.fixture.trust.release_roots.signers[0].not_after = Some(now - 60_000);
    let request = case.install_request(&[0]);
    assert!(refusal(case.verify(&request)).contains("not_after"));

    // Signed inside the window: still verifies after the window closed.
    let mut earlier = case.install_request(&[0]);
    earlier.signature = case.fixture.sign_release(
        &earlier.signature.statement.manifest_digest,
        &earlier.signature.statement.artifact_digest,
        now - 120_000,
    );
    case.verify(&earlier).unwrap();

    case.fixture.trust.release_roots.signers[0].not_after = None;
    let mut future = case.install_request(&[0]);
    future.signature = case.fixture.sign_release(
        &future.signature.statement.manifest_digest,
        &future.signature.statement.artifact_digest,
        now + 3_600_000,
    );
    assert!(refusal(case.verify(&future)).contains("future"));
}

#[test]
fn manifest_must_declare_the_host_executor() {
    let case = Case::new(Vec::new());
    let mut request = case.install_request(&[0]);
    request.manifest = request
        .manifest
        .replace("executor = \"host\"", "executor = \"shell\"");
    assert!(refusal(case.verify(&request)).contains("executor = \"host\""));
}

#[test]
fn plan_changed_after_approval_is_refused() {
    let case = Case::new(Vec::new());
    let mut request = case.install_request(&[0]);
    request.plan.steps[0]
        .host
        .as_mut()
        .unwrap()
        .expected_generation = 5;
    // The server names the instance after the changed plan, so only the
    // approvals no longer match its digest.
    let message = refusal(case.verify(&request));
    assert!(
        message.contains("different executable content"),
        "{message}"
    );
}

#[test]
fn instance_name_must_match_the_verified_request() {
    let case = Case::new(Vec::new());
    let request = case.install_request(&[0]);
    let other = instance_key(
        &request.plan_digest().unwrap(),
        "other",
        HostAction::Install,
    );
    let result = verify_copied_request(
        &request,
        &other,
        &case.workdir,
        &case.fixture.trust,
        crate::now_millis(),
    );
    assert!(refusal(result).contains("does not match"));
}

#[test]
fn request_action_must_be_the_steps_action() {
    let case = Case::new(Vec::new());
    let mut request = case.install_request(&[0]);
    request.action = HostAction::Uninstall;
    assert!(refusal(case.verify(&request)).contains("authorizes install, not uninstall"));
}

#[test]
fn approvals_below_quorum_are_refused() {
    let case = Case::new(vec![rule(QuorumPurpose::ExecutePlan, 2, &["ops"])]);
    let one = case.install_request(&[0]);
    assert!(refusal(case.verify(&one)).contains("need 2 execute_plan approvals"));
    // The same signer twice counts once.
    let mut twice = case.install_request(&[0]);
    twice.approvals.push(twice.approvals[0].clone());
    assert!(refusal(case.verify(&twice)).contains("need 2"));
    // Carol is outside the rule's group.
    let other_group = case.install_request(&[0, 2]);
    assert!(refusal(case.verify(&other_group)).contains("need 2"));
    case.verify(&case.install_request(&[0, 1])).unwrap();
}

#[test]
fn skip_gates_rule_always_applies() {
    let case = Case::new(vec![rule(QuorumPurpose::SkipGates, 2, &[])]);
    assert!(refusal(case.verify(&case.install_request(&[0]))).contains("skip_gates"));
    case.verify(&case.install_request(&[0, 2])).unwrap();
}

#[test]
fn approvals_for_the_wrong_purpose_are_refused() {
    let case = Case::new(vec![rule(QuorumPurpose::Downgrade, 1, &["qa"])]);
    let now = crate::now_millis();
    let plan = case.fixture.plan(
        "edge",
        now,
        &[case.spec(HostAction::Install, Action::Downgrade, Some("1.3.0"))],
    );
    let ops_only = case.fixture.request(
        &plan,
        0,
        &case.release,
        vec![case.fixture.approve(&plan, 0, now)],
    );
    assert!(refusal(case.verify(&ops_only)).contains("downgrade"));
    let qa = case.fixture.request(
        &plan,
        0,
        &case.release,
        vec![case.fixture.approve(&plan, 2, now)],
    );
    case.verify(&qa).unwrap();
}

#[test]
fn expired_approval_does_not_count() {
    let case = Case::new(Vec::new());
    let now = crate::now_millis();
    let plan = case.fixture.plan(
        "edge",
        now,
        &[case.spec(HostAction::Install, Action::Install, None)],
    );
    let expired = fixture::approve_with(
        &case.fixture.approvers[0].key,
        &plan,
        "external-review",
        now - 7_200_000,
        now - 3_600_000,
    );
    let request = case.fixture.request(&plan, 0, &case.release, vec![expired]);
    assert!(refusal(case.verify(&request)).contains("expired"));
}

#[test]
fn server_auto_approval_never_authorizes_a_host_step() {
    let case = Case::new(Vec::new());
    let now = crate::now_millis();
    let plan = case.fixture.plan(
        "edge",
        now,
        &[case.spec(HostAction::Install, Action::Install, None)],
    );
    let auto = fixture::approve_with(
        &case.fixture.approvers[0].key,
        &plan,
        crate::approval_policy::POLICY_PROVIDER,
        now - 1_000,
        now + 60_000,
    );
    let request = case.fixture.request(&plan, 0, &case.release, vec![auto]);
    assert!(refusal(case.verify(&request)).contains("automatic approvals never authorize"));

    let mut auto_signer = fixture::signer("robot", &fixture::key(150), &[]);
    auto_signer.environments = vec!["edge".into()];
    auto_signer.providers = vec![crate::approval_policy::POLICY_PROVIDER.into()];
    let mut policy = case.fixture.trust.policy.clone();
    policy.signers.push(auto_signer);
    let error = HostApprovalPolicy::parse(&toml::to_string(&policy).unwrap()).unwrap_err();
    assert!(format!("{error:#}").contains("automatic or preflight signer"));
}

#[test]
fn approval_lifetime_is_bounded_by_the_host_policy() {
    let mut case = Case::new(Vec::new());
    case.fixture.trust.policy.max_approval_ttl_ms = Some(60_000);
    // The fixture's approvals live an hour.
    assert!(refusal(case.verify(&case.install_request(&[0]))).contains("max_approval_ttl_ms"));
}

#[test]
fn host_policy_refuses_requester_exclusion() {
    let raw = "version = 1\nsigners = []\n[[quorum]]\npurpose = \"execute_plan\"\nn = 2\nexclude_requester = true\n";
    let error = HostApprovalPolicy::parse(raw).unwrap_err();
    assert!(format!("{error:#}").contains("excludes the requester"));
}

#[test]
fn uninstall_and_health_act_on_the_installed_release() {
    let case = Case::new(Vec::new());
    let now = crate::now_millis();
    for action in [HostAction::Uninstall, HostAction::Health] {
        let wrong = case
            .fixture
            .plan("edge", now, &[case.spec(action, Action::Upgrade, None)]);
        let request = case.fixture.request(
            &wrong,
            0,
            &case.release,
            vec![case.fixture.approve(&wrong, 0, now)],
        );
        assert!(refusal(case.verify(&request)).contains("installed release"));
        let right = case.fixture.plan(
            "edge",
            now,
            &[case.spec(action, Action::Upgrade, Some("1.2.0"))],
        );
        let request = case.fixture.request(
            &right,
            0,
            &case.release,
            vec![case.fixture.approve(&right, 0, now)],
        );
        let verified = case.verify(&request).unwrap();
        assert_eq!(verified.command, format!("./{action}.sh"));
    }
}

/// Steps without a host binding encode exactly as before the field existed,
/// so existing plan digests and approvals are unchanged.
#[test]
fn a_step_without_a_host_binding_encodes_as_before() {
    let case = Case::new(Vec::new());
    let mut plan = case.fixture.plan(
        "edge",
        1,
        &[case.spec(HostAction::Install, Action::Install, None)],
    );
    let bound = serde_json::to_value(&plan.steps[0]).unwrap();
    assert_eq!(
        bound["host"],
        serde_json::json!({"action": "install", "expected_generation": 0})
    );
    plan.steps[0].host = None;
    let unbound = serde_json::to_value(&plan.steps[0]).unwrap();
    assert!(unbound.get("host").is_none(), "{unbound}");
    let decoded: crate::plan::Step = serde_json::from_value(unbound).unwrap();
    assert_eq!(decoded.host, None);
}

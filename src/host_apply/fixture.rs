//! Signed host-apply requests for tests: a release key, approver keys, a host
//! approval policy, releases written to a workdir, plans with host steps, and
//! approval envelopes.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};

use super::{HostApplyRequest, HostApprovalPolicy, HostTrust, REQUEST_SCHEMA};
use crate::approval_policy::QuorumRule;
use crate::plan::{Action, HostAction, HostStep, PLAN_FORMAT_VERSION, Plan, PlanState, Step};
use crate::plan_approval::{APPROVAL_SCHEMA, ApprovalEnvelope, ApprovalStatement, TrustedSigner};
use crate::release_signing::{
    ENVELOPE_SCHEMA, Provenance, ReleaseStatement, SignatureEnvelope, TrustRoots,
};

/// One approver: its trust-root identity and signing key.
pub struct Approver {
    pub identity: String,
    pub key: SigningKey,
}

/// Keys and root-owned trust for one test.
pub struct HostFixture {
    pub release_key: SigningKey,
    pub approvers: Vec<Approver>,
    pub trust: HostTrust,
}

/// A release written to a workdir and signed.
#[derive(Debug, Clone)]
pub struct SignedRelease {
    pub product: String,
    pub version: String,
    pub manifest: String,
    pub signature: SignatureEnvelope,
}

/// What one host step of a fixture plan does.
#[derive(Debug, Clone)]
pub struct StepSpec {
    pub release: SignedRelease,
    pub action: HostAction,
    pub step_action: Action,
    pub from: Option<String>,
    pub expected_generation: u64,
}

/// A distinct, valid Ed25519 key from a small seed.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn key_id(key: &SigningKey) -> String {
    crate::signature_verification::key_id(&key.verifying_key().to_bytes())
}

pub fn public_key(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

/// A trust-root signer entry for `key`.
pub fn signer(identity: &str, key: &SigningKey, groups: &[&str]) -> TrustedSigner {
    TrustedSigner {
        key_id: key_id(key),
        identity: identity.into(),
        public_key: public_key(key),
        environments: Vec::new(),
        providers: Vec::new(),
        groups: groups.iter().map(|group| group.to_string()).collect(),
        not_before: None,
        not_after: None,
    }
}

impl HostFixture {
    /// `approvers` are `(identity, groups)`; keys use seeds 100, 101, ...
    pub fn new(approvers: &[(&str, &[&str])], quorum: Vec<QuorumRule>) -> Self {
        let release_key = key(7);
        let approvers: Vec<(Approver, TrustedSigner)> = approvers
            .iter()
            .enumerate()
            .map(|(index, (identity, groups))| {
                let key = key(100 + index as u8);
                let entry = signer(identity, &key, groups);
                (
                    Approver {
                        identity: identity.to_string(),
                        key,
                    },
                    entry,
                )
            })
            .collect();
        let policy = HostApprovalPolicy {
            version: 1,
            max_approval_ttl_ms: None,
            signers: approvers.iter().map(|(_, entry)| entry.clone()).collect(),
            quorum,
        };
        let release_roots = TrustRoots {
            version: 1,
            signers: vec![crate::release_signing::TrustedSigner::new(
                key_id(&release_key),
                "release@example.com",
                public_key(&release_key),
            )],
        };
        Self {
            release_key,
            approvers: approvers
                .into_iter()
                .map(|(approver, _)| approver)
                .collect(),
            trust: HostTrust {
                release_roots,
                policy,
            },
        }
    }

    /// Write `files` under `workdir` as the release's deploy inputs (each
    /// file's top-level entry) and sign a manifest declaring
    /// `executor = "host"` with `install`, `uninstall`, and `health` commands.
    pub fn release(
        &self,
        workdir: &Path,
        product: &str,
        version: &str,
        commands: [&str; 3],
        files: &[(&str, &[u8])],
    ) -> SignedRelease {
        let inputs: std::collections::BTreeSet<&str> = files
            .iter()
            .map(|(name, _)| name.split('/').next().unwrap())
            .collect();
        let inputs: Vec<&str> = inputs.into_iter().collect();
        self.release_with_inputs(workdir, product, version, commands, files, &inputs)
    }

    /// [`Self::release`] with explicit `deploy.inputs`.
    pub fn release_with_inputs(
        &self,
        workdir: &Path,
        product: &str,
        version: &str,
        commands: [&str; 3],
        files: &[(&str, &[u8])],
        inputs: &[&str],
    ) -> SignedRelease {
        std::fs::create_dir_all(workdir).unwrap();
        for (name, bytes) in files {
            let path = workdir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
        }
        let inputs: Vec<String> = inputs.iter().map(|input| format!("{input:?}")).collect();
        let manifest = format!(
            "[product]\nname = {product:?}\nversion = {version:?}\n\n[deploy]\nexecutor = \"host\"\ninstall = {:?}\nuninstall = {:?}\nhealth = {:?}\ninputs = [{}]\n",
            commands[0],
            commands[1],
            commands[2],
            inputs.join(", ")
        );
        let parsed = crate::manifest::parse_raw(&manifest).unwrap();
        let artifact_digest =
            crate::manifest::artifact_digest(workdir, &parsed.immutable_inputs()).unwrap();
        let signature = self.sign_release(
            &crate::manifest::digest(&manifest),
            &artifact_digest,
            crate::now_millis(),
        );
        SignedRelease {
            product: product.into(),
            version: version.into(),
            manifest,
            signature,
        }
    }

    /// A release signature by the fixture's release key, signed at `signed_at`.
    pub fn sign_release(
        &self,
        manifest_digest: &str,
        artifact_digest: &str,
        signed_at: i64,
    ) -> SignatureEnvelope {
        sign_release_with(
            &self.release_key,
            manifest_digest,
            artifact_digest,
            signed_at,
        )
    }

    /// A plan for `environment` with one step per spec, in order.
    pub fn plan(&self, environment: &str, created_at: i64, steps: &[StepSpec]) -> Plan {
        let id = format!("tenkai:plan:{environment}:{created_at}");
        let steps = steps
            .iter()
            .enumerate()
            .map(|(order, spec)| {
                let manifest_digest = crate::manifest::digest(&spec.release.manifest);
                Step {
                    id: format!("{id}:step:{order}"),
                    order: order as u32,
                    product: spec.release.product.clone(),
                    instance: String::new(),
                    action: spec.step_action,
                    from: spec.from.clone(),
                    to: spec.release.version.clone(),
                    release_id: crate::ontology::release_id(
                        &spec.release.product,
                        &spec.release.version,
                    ),
                    release_digest: manifest_digest,
                    artifact_digest: spec.release.signature.statement.artifact_digest.clone(),
                    workdir: "/var/lib/tenkai/releases/unused".into(),
                    restore: None,
                    host: Some(HostStep {
                        action: spec.action,
                        expected_generation: spec.expected_generation,
                    }),
                    sealed: Vec::new(),
                    rewrap: None,
                    issuer: None,
                    identity: None,
                    restore_identity: None,
                    target_changes: Vec::new(),
                }
            })
            .collect();
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            id,
            content_id: format!("content-{created_at}"),
            environment: environment.into(),
            created_at,
            inputs: Vec::new(),
            steps,
            state: PlanState::Computed,
            gates_skipped: None,
            status_detail: String::new(),
            maintenance_blocked: false,
            prior_warnings: Vec::new(),
            recalled_recovery_reason: None,
            credential_runway: None,
            approval_brief: None,
        }
    }

    /// An approval of `plan` by approver `index`, valid from `now - 1s` to
    /// `now + 1h`.
    pub fn approve(&self, plan: &Plan, index: usize, now: i64) -> ApprovalEnvelope {
        approve_with(
            &self.approvers[index].key,
            plan,
            "external-review",
            now - 1_000,
            now + 3_600_000,
        )
    }

    /// The request for step `step_index` of `plan`, carrying `approvals`.
    pub fn request(
        &self,
        plan: &Plan,
        step_index: usize,
        release: &SignedRelease,
        approvals: Vec<ApprovalEnvelope>,
    ) -> HostApplyRequest {
        let step = &plan.steps[step_index];
        HostApplyRequest {
            schema: REQUEST_SCHEMA.into(),
            plan: plan.clone(),
            step_id: step.id.clone(),
            action: step.host.expect("fixture steps are host steps").action,
            manifest: release.manifest.clone(),
            signature: release.signature.clone(),
            approvals,
        }
    }
}

/// A release signature by `key`.
pub fn sign_release_with(
    key: &SigningKey,
    manifest_digest: &str,
    artifact_digest: &str,
    signed_at: i64,
) -> SignatureEnvelope {
    let mut envelope = SignatureEnvelope {
        schema: ENVELOPE_SCHEMA.into(),
        key_id: key_id(key),
        statement: ReleaseStatement {
            manifest_digest: manifest_digest.into(),
            artifact_digest: artifact_digest.into(),
            provenance: Provenance {
                source_uri: "https://example.com/host-release".into(),
                revision: "r1".into(),
                builder: "fixture".into(),
                built_at_unix_ms: signed_at,
                materials: Default::default(),
            },
        },
        signature: String::new(),
    };
    envelope.signature = STANDARD.encode(key.sign(&envelope.signed_bytes().unwrap()).to_bytes());
    envelope
}

/// An approval of `plan` by `key` under `provider`.
pub fn approve_with(
    key: &SigningKey,
    plan: &Plan,
    provider: &str,
    issued_at: i64,
    expires_at: i64,
) -> ApprovalEnvelope {
    let statement = ApprovalStatement {
        plan_digest: format!("sha256:{}", plan.executable_digest().unwrap()),
        environment: plan.environment.clone(),
        purpose: "execute_plan".into(),
        skip_gates: false,
        issued_at,
        expires_at,
        policy_provider: provider.into(),
        policy_evidence_id: "fixture".into(),
        policy_digest: format!("sha256:{}", "0".repeat(64)),
    };
    let signature = key.sign(&crate::plan_approval::canonical_bytes(&statement).unwrap());
    ApprovalEnvelope {
        schema: APPROVAL_SCHEMA.into(),
        key_id: key_id(key),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    }
}

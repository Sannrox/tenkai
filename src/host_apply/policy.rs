//! The root-owned host approval policy (ADR 0041 §2, ADR 0037).
//!
//! The root side cannot see gates, the gate-skip flag, the apply requester,
//! or product criticality; they are server state. So every quorum rule
//! applies regardless of `min_criticality`, the `skip_gates` and
//! `execute_plan` rules always apply, and a policy that excludes the
//! requester is refused when it loads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::approval_policy::{QuorumPurpose, QuorumRule, default_quorum};
use crate::plan::{Action, Plan};
use crate::plan_approval::{
    ApprovalEnvelope, CountedApproval, TrustRoots, TrustedSigner, count_quorum, quorum_refusal,
    verify_envelope,
};

const POLICY_VERSION: u32 = 1;

/// Trusted approvers and quorum rules for host steps, read only from a
/// root-owned file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostApprovalPolicy {
    pub version: u32,
    /// Longest approval lifetime (`expires_at - issued_at`) that counts, in
    /// milliseconds. Bounds how long a recalled release stays runnable under
    /// an approved plan, since recall is not visible to the root side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_approval_ttl_ms: Option<i64>,
    /// Approvers, in the plan-approval trust-root signer format. The server's
    /// automatic (`builtin-auto`) and preflight signers are refused.
    pub signers: Vec<TrustedSigner>,
    #[serde(default)]
    pub quorum: Vec<QuorumRule>,
}

impl HostApprovalPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading host approval policy {}", path.display()))?;
        Self::parse(&raw)
            .with_context(|| format!("loading host approval policy {}", path.display()))
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let policy: Self = toml::from_str(raw).context("parsing host approval policy")?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        if self.version != POLICY_VERSION {
            bail!("host approval policy version must be {POLICY_VERSION}");
        }
        if self.max_approval_ttl_ms.is_some_and(|ttl| ttl <= 0) {
            bail!("host approval policy max_approval_ttl_ms must be positive");
        }
        let mut seen = BTreeSet::new();
        for rule in &self.quorum {
            if rule.n == 0 {
                bail!("host approval policy quorum n must be at least 1");
            }
            if rule.exclude_requester {
                bail!(
                    "host approval policy quorum {} excludes the requester, which the host side cannot verify",
                    rule.purpose.as_str()
                );
            }
            if let Some(min) = &rule.min_criticality {
                crate::criticality::CriticalityLevel::parse(min)
                    .map_err(|error| anyhow::anyhow!("quorum min_criticality {error}"))?;
            }
            if !seen.insert((rule.purpose.as_str(), rule.min_criticality.as_deref())) {
                bail!(
                    "host approval policy quorum purpose {} is duplicated",
                    rule.purpose.as_str()
                );
            }
            for group in &rule.groups {
                crate::ontology::validate_identifier("quorum group", group)?;
            }
        }
        for signer in &self.signers {
            if signer.providers.iter().any(|provider| {
                provider == crate::approval_policy::POLICY_PROVIDER
                    || provider == crate::host_preflight::PREFLIGHT_PROVIDER
            }) {
                bail!(
                    "host approval policy signer {} is an automatic or preflight signer; host steps need human or external approvers",
                    signer.identity
                );
            }
        }
        self.trust_roots().validate()?;
        Ok(())
    }

    fn trust_roots(&self) -> TrustRoots {
        TrustRoots {
            version: 1,
            signers: self.signers.clone(),
        }
    }

    /// Every rule for `purpose`, whatever its `min_criticality`, or the
    /// default of one trusted approval when the policy names none.
    fn rules(&self, purpose: QuorumPurpose) -> Vec<QuorumRule> {
        let rules: Vec<QuorumRule> = self
            .quorum
            .iter()
            .filter(|rule| rule.purpose == purpose)
            .cloned()
            .collect();
        if rules.is_empty() {
            vec![default_quorum(purpose)]
        } else {
            rules
        }
    }

    /// Verify `envelopes` for `plan` at `now_ms`. An envelope that fails
    /// verification, is automatic, or outlives `max_approval_ttl_ms` does not
    /// count; each one that does counts until it expires or its signer's
    /// window closes.
    pub fn evaluate(
        &self,
        plan: &Plan,
        envelopes: &[ApprovalEnvelope],
        now_ms: i64,
    ) -> HostApprovals {
        let roots = self.trust_roots();
        let mut candidates = Vec::new();
        let mut rejected = Vec::new();
        for envelope in envelopes {
            let statement = &envelope.statement;
            if statement.policy_provider == crate::approval_policy::POLICY_PROVIDER {
                rejected.push(format!(
                    "{}: automatic approvals never authorize a local-policy step",
                    envelope.key_id
                ));
                continue;
            }
            if let Some(ttl) = self.max_approval_ttl_ms
                && statement.expires_at.saturating_sub(statement.issued_at) > ttl
            {
                rejected.push(format!(
                    "{}: approval lifetime exceeds the host policy's max_approval_ttl_ms",
                    envelope.key_id
                ));
                continue;
            }
            // The gate-skip flag is server state; an approval binds it either way.
            match verify_envelope(plan, envelope, &roots, now_ms, statement.skip_gates) {
                Ok(evidence) => {
                    let signer = roots.signer(&envelope.key_id).ok();
                    candidates.push(Candidate {
                        approval: CountedApproval {
                            key_id: evidence.key_id,
                            identity: evidence.signer_identity,
                            groups: signer
                                .map(|signer| signer.groups.clone())
                                .unwrap_or_default(),
                            auto: false,
                        },
                        valid_until: statement.expires_at.min(
                            signer
                                .and_then(|signer| signer.not_after)
                                .map_or(i64::MAX, |not_after| not_after.saturating_add(1)),
                        ),
                    })
                }
                Err(error) => rejected.push(format!("{}: {error:#}", envelope.key_id)),
            }
        }
        let rules = [
            QuorumPurpose::ExecutePlan,
            QuorumPurpose::SkipGates,
            QuorumPurpose::Rollback,
            QuorumPurpose::Downgrade,
        ]
        .into_iter()
        .map(|purpose| (purpose, self.rules(purpose)))
        .collect();
        HostApprovals {
            refusal_prefix: "host approval policy",
            rules,
            candidates,
            rejected,
        }
    }

    /// Same as [`Self::evaluate`], with a refusal prefix the runtime uses so
    /// operators can tell a local-policy refusal from a host-applier one.
    pub fn evaluate_as(
        &self,
        refusal_prefix: &'static str,
        plan: &Plan,
        envelopes: &[ApprovalEnvelope],
        now_ms: i64,
    ) -> HostApprovals {
        let mut approvals = self.evaluate(plan, envelopes, now_ms);
        approvals.refusal_prefix = refusal_prefix;
        approvals
    }

    /// Recompute the plan digest (via envelope verification), evaluate the
    /// envelopes, and require every purpose the plan needs from its steps.
    pub fn verify_plan(
        &self,
        plan: &Plan,
        envelopes: &[ApprovalEnvelope],
        now_ms: i64,
    ) -> Result<HostApprovals> {
        self.verify_plan_as("host approval policy", plan, envelopes, now_ms)
    }

    pub fn verify_plan_as(
        &self,
        refusal_prefix: &'static str,
        plan: &Plan,
        envelopes: &[ApprovalEnvelope],
        now_ms: i64,
    ) -> Result<HostApprovals> {
        let approvals = self.evaluate_as(refusal_prefix, plan, envelopes, now_ms);
        approvals.require_all(&plan_purposes(plan))?;
        Ok(approvals)
    }
}

/// The purposes a plan needs before any of its host steps runs, from the
/// plan alone: `execute_plan`, `skip_gates` (as if gates were skipped), and
/// `rollback` or `downgrade` when any step is one.
pub fn plan_purposes(plan: &Plan) -> Vec<QuorumPurpose> {
    let mut purposes = vec![QuorumPurpose::ExecutePlan, QuorumPurpose::SkipGates];
    if plan
        .steps
        .iter()
        .any(|step| step.action == Action::Rollback)
    {
        purposes.push(QuorumPurpose::Rollback);
    }
    if plan
        .steps
        .iter()
        .any(|step| step.action == Action::Downgrade)
    {
        purposes.push(QuorumPurpose::Downgrade);
    }
    purposes
}

/// One verified approval and when it stops counting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    approval: CountedApproval,
    /// Exclusive: the approval counts while `now < valid_until`.
    valid_until: i64,
}

/// Verified approvals for one plan, and the host policy's rules to count
/// them against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostApprovals {
    refusal_prefix: &'static str,
    rules: BTreeMap<QuorumPurpose, Vec<QuorumRule>>,
    candidates: Vec<Candidate>,
    rejected: Vec<String>,
}

impl HostApprovals {
    /// The approvals still valid at `now_ms`. The applier recounts with this
    /// after waiting for the product lock, so an approval that expired in
    /// the meantime no longer counts while the others still do.
    pub fn at(&self, now_ms: i64) -> Self {
        let (valid, expired): (Vec<Candidate>, Vec<Candidate>) = self
            .candidates
            .iter()
            .cloned()
            .partition(|candidate| now_ms < candidate.valid_until);
        let mut rejected = self.rejected.clone();
        rejected.extend(expired.into_iter().map(|candidate| {
            format!(
                "{}: stopped being valid before the step could start",
                candidate.approval.key_id
            )
        }));
        Self {
            refusal_prefix: self.refusal_prefix,
            rules: self.rules.clone(),
            candidates: valid,
            rejected,
        }
    }

    /// Refuse unless every purpose in `purposes` is met.
    pub fn require_all(&self, purposes: &[QuorumPurpose]) -> Result<()> {
        purposes
            .iter()
            .try_for_each(|purpose| self.require(*purpose))
    }

    /// Refuse unless every rule for `purpose` is met.
    pub fn require(&self, purpose: QuorumPurpose) -> Result<()> {
        let approvals: Vec<CountedApproval> = self
            .candidates
            .iter()
            .map(|candidate| candidate.approval.clone())
            .collect();
        let missing: Vec<String> = self
            .rules
            .get(&purpose)
            .into_iter()
            .flatten()
            .filter_map(|rule| {
                let tally = count_quorum(rule, &approvals, None);
                (tally.missing > 0).then(|| quorum_refusal(rule, &tally))
            })
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let refusal = missing.join("; ");
        if self.rejected.is_empty() {
            bail!("{}: {refusal}", self.refusal_prefix);
        }
        bail!(
            "{}: {refusal}; not counted: {}",
            self.refusal_prefix,
            self.rejected.join("; ")
        )
    }
}

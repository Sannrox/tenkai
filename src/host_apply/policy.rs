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

    /// Verify `envelopes` for `plan` at `now_ms` and tally them against
    /// every purpose. An envelope that fails verification, is automatic, or
    /// outlives `max_approval_ttl_ms` does not count.
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
                    "{}: automatic approvals never authorize host steps",
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
                Ok(evidence) => candidates.push(CountedApproval {
                    key_id: evidence.key_id,
                    identity: evidence.signer_identity,
                    groups: roots
                        .signer(&envelope.key_id)
                        .map(|signer| signer.groups.clone())
                        .unwrap_or_default(),
                    auto: false,
                }),
                Err(error) => rejected.push(format!("{}: {error:#}", envelope.key_id)),
            }
        }
        let mut refusals = BTreeMap::new();
        for purpose in [
            QuorumPurpose::ExecutePlan,
            QuorumPurpose::SkipGates,
            QuorumPurpose::Rollback,
            QuorumPurpose::Downgrade,
        ] {
            let missing: Vec<String> = self
                .rules(purpose)
                .iter()
                .filter_map(|rule| {
                    let tally = count_quorum(rule, &candidates, None);
                    (tally.missing > 0).then(|| quorum_refusal(rule, &tally))
                })
                .collect();
            if !missing.is_empty() {
                refusals.insert(purpose, missing.join("; "));
            }
        }
        HostApprovals { refusals, rejected }
    }
}

/// Which purposes' quorums a set of approvals satisfies for one plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostApprovals {
    refusals: BTreeMap<QuorumPurpose, String>,
    rejected: Vec<String>,
}

impl HostApprovals {
    /// Refuse unless every rule for `purpose` is met.
    pub fn require(&self, purpose: QuorumPurpose) -> Result<()> {
        let Some(refusal) = self.refusals.get(&purpose) else {
            return Ok(());
        };
        if self.rejected.is_empty() {
            bail!("host approval policy: {refusal}");
        }
        bail!(
            "host approval policy: {refusal}; not counted: {}",
            self.rejected.join("; ")
        )
    }

    /// The purposes a plan needs before any of its host steps runs, from the
    /// plan alone: `execute_plan`, `skip_gates` (as if gates were skipped),
    /// and `rollback` or `downgrade` when any step is one.
    pub fn require_for_plan(&self, plan: &Plan) -> Result<()> {
        self.require(QuorumPurpose::ExecutePlan)?;
        self.require(QuorumPurpose::SkipGates)?;
        if plan
            .steps
            .iter()
            .any(|step| step.action == Action::Rollback)
        {
            self.require(QuorumPurpose::Rollback)?;
        }
        if plan
            .steps
            .iter()
            .any(|step| step.action == Action::Downgrade)
        {
            self.require(QuorumPurpose::Downgrade)?;
        }
        Ok(())
    }
}

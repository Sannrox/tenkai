//! Host steps through apply (ADR 0041 §2), against an applier that verifies
//! and records exactly as the root side does, without systemd or root.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};

use crate::client::Ctx;
use crate::host_apply::state::{
    AppliedState, AppliedStateRecord, HostApplyOutcome, HostApplyRefused, REFUSED_FILE,
    REFUSED_SCHEMA, RESULT_FILE, instance_dir, record_path,
};
use crate::host_apply::{
    ARTIFACTS_DIR, HostAction, HostApplyRequest, HostApprovalPolicy, HostTrust, REQUEST_FILE,
};
use crate::host_executor::{HostExecutor, HostUnits, UnitFuture};
use crate::plan::{Action, HostStep, Plan};
use crate::software_executor::SoftwareExecutors;

use super::{ExecutionAuthorization, ExecutionOptions, Outcome, StepOutcomeStatus};

type Hook = Box<dyn FnOnce() -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Plays the root side: verifies the spooled request with the applier's
/// checks, admits it against the applied-state record, "runs" the command,
/// and records the result. A recorded instance never runs again.
struct Applier {
    root: PathBuf,
    spool: PathBuf,
    state: PathBuf,
    /// Host actions whose command fails.
    fail: Mutex<BTreeSet<HostAction>>,
    /// Runs once a command starts; the command then waits for a stop.
    hang: Mutex<Option<Hook>>,
    stopped: tokio::sync::Notify,
    /// Every start, and every command that ran, as `action product@version`.
    starts: Mutex<Vec<String>>,
    runs: Mutex<Vec<String>>,
}

impl Applier {
    /// Root-owned trust in the real applier: the dev release key, and the
    /// dev approver as the host approval policy's only signer.
    fn trust(&self) -> Result<HostTrust> {
        let approvers = crate::plan_approval::TrustRoots::load(&self.root.join("approvers.toml"))?;
        Ok(HostTrust {
            release_roots: crate::release_signing::TrustRoots::load(
                &self.root.join("release-trust.toml"),
            )?,
            policy: HostApprovalPolicy {
                version: 1,
                max_approval_ttl_ms: None,
                signers: approvers.signers,
                quorum: Vec::new(),
            },
        })
    }

    fn write(path: &Path, value: &impl serde::Serialize) -> Result<()> {
        std::fs::create_dir_all(path.parent().context("record has a parent")?)?;
        std::fs::write(path, serde_json::to_vec(value)?)?;
        Ok(())
    }

    async fn run(&self, instance: &str) -> Result<()> {
        let result_path = instance_dir(&self.state, instance).join(RESULT_FILE);
        if result_path.exists() {
            return Ok(());
        }
        let now = crate::now_millis();
        let spooled = self.spool.join(instance);
        let request = HostApplyRequest::parse(&std::fs::read(spooled.join(REQUEST_FILE))?)?;
        let admitted = (|| {
            let verified =
                crate::host_apply::verify_request(&request, instance, &self.trust()?, now)?;
            verified.verify_artifacts(&spooled.join(ARTIFACTS_DIR))?;
            let path = record_path(&self.state, &verified.environment, &verified.product);
            let record: AppliedStateRecord = match std::fs::read(&path) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(_) => AppliedStateRecord::empty(&verified.environment, &verified.product),
            };
            let (started, next) = record.admit(&verified, None, now)?;
            Self::write(&path, &next)?;
            anyhow::Ok((verified, path, started, next))
        })();
        let (verified, path, started, next) = match admitted {
            Ok(admitted) => admitted,
            Err(error) => {
                Self::write(
                    &instance_dir(&self.state, instance).join(REFUSED_FILE),
                    &HostApplyRefused {
                        schema: REFUSED_SCHEMA.into(),
                        instance: instance.into(),
                        reason: format!("{error:#}"),
                        refused_at: now,
                    },
                )?;
                anyhow::bail!("refused: {error:#}");
            }
        };
        self.runs.lock().unwrap().push(format!(
            "{} {}@{}",
            verified.action, verified.product, verified.release.version
        ));
        let hang = self.hang.lock().unwrap().take();
        let outcome = if let Some(hook) = hang {
            hook().await;
            self.stopped.notified().await;
            HostApplyOutcome::Stopped
        } else if self.fail.lock().unwrap().contains(&verified.action) {
            HostApplyOutcome::Failed
        } else {
            HostApplyOutcome::Succeeded
        };
        let result = started.result(outcome, None, "emulated", crate::now_millis());
        Self::write(&path, &next.complete(&started, &result))?;
        Self::write(&result_path, &result)?;
        Ok(())
    }
}

/// [`HostUnits`] over the emulated applier, as `systemctl` would drive it.
struct Units(Arc<Applier>);

impl HostUnits for Units {
    fn start<'a>(&'a self, instance: &'a str) -> UnitFuture<'a> {
        Box::pin(async move {
            let request = HostApplyRequest::parse(&std::fs::read(
                self.0.spool.join(instance).join(REQUEST_FILE),
            )?)?;
            let step = request
                .plan
                .steps
                .iter()
                .find(|step| step.id == request.step_id)
                .context("spooled step")?;
            self.0
                .starts
                .lock()
                .unwrap()
                .push(format!("{} {}@{}", request.action, step.product, step.to));
            self.0.run(instance).await
        })
    }

    fn stop(&self, _instance: &str) -> Result<()> {
        self.0.stopped.notify_one();
        Ok(())
    }
}

struct Host {
    root: PathBuf,
    ctx: Ctx,
    applier: Arc<Applier>,
    executors: SoftwareExecutors,
}

impl Host {
    async fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "tenkai-host-step-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let spool = root.join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        crate::plan::env_add(&mut ctx, "edge", "host releases")
            .await
            .unwrap();
        let applier = Arc::new(Applier {
            root: root.clone(),
            spool: spool.clone(),
            state: root.join("state"),
            fail: Mutex::default(),
            hang: Mutex::default(),
            stopped: tokio::sync::Notify::new(),
            starts: Mutex::default(),
            runs: Mutex::default(),
        });
        let executor = HostExecutor::new(
            spool,
            applier.state.clone(),
            Arc::new(Units(applier.clone())),
        );
        let executors = SoftwareExecutors::default().with_host(Arc::new(executor));
        Self {
            root,
            ctx,
            applier,
            executors,
        }
    }

    /// Sign, publish, and promote `cluster@version`, subscribed by `edge`.
    async fn release(&mut self, version: &str, health: bool) {
        self.release_with(version, health, "").await;
    }

    /// [`Self::release`] with `extra` manifest sections appended.
    async fn release_with(&mut self, version: &str, health: bool, extra: &str) {
        let dir = self.root.join(format!("cluster-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("install.sh"), "echo install\n").unwrap();
        let health = if health { "health = \"true\"\n" } else { "" };
        let manifest = dir.join("tenkai.toml");
        std::fs::write(
            &manifest,
            format!(
                "[product]\nname = \"cluster\"\nversion = \"{version}\"\n\n[deploy]\nexecutor = \"host\"\ninstall = \"sh install.sh\"\nuninstall = \"true\"\n{health}inputs = [\"install.sh\"]\n{extra}"
            ),
        )
        .unwrap();
        let signature = dir.join("signature.json");
        let roots = self.root.join("release-trust.toml");
        crate::dev_sign::sign_release(&self.root.join("keys"), &manifest, &signature, &roots)
            .unwrap();
        crate::catalog::publish(
            &mut self.ctx,
            &manifest,
            &crate::catalog::PublishOptions {
                signature: Some(signature),
                trust_roots: Some(roots),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let actor = crate::auth_context::test_management_context("host-step");
        crate::catalog::promote(
            &mut self.ctx,
            &actor,
            &format!("cluster@{version}"),
            "stable",
        )
        .await
        .unwrap();
        crate::plan::subscribe(&mut self.ctx, "edge", "cluster", "stable")
            .await
            .unwrap();
    }

    async fn plan(&mut self) -> Plan {
        crate::plan::create_with(&mut self.ctx, "edge", &self.executors)
            .await
            .unwrap()
    }

    /// Approve `plan` with the dev approver and apply it.
    async fn apply(&mut self, plan: &Plan) -> Result<Vec<Outcome>> {
        let approval = self.root.join(format!("approval-{}.json", plan.created_at));
        let approvers = self.root.join("approvers.toml");
        crate::dev_sign::sign_plan_approval_for_digest(
            &self.root.join("keys"),
            &format!("sha256:{}", plan.executable_digest().unwrap()),
            "edge",
            &approval,
            &approvers,
            3600,
        )
        .unwrap();
        super::execute_with_options(
            &mut self.ctx,
            &plan.id,
            ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: ExecutionAuthorization::Signed {
                    approval: &approval,
                    trust_roots: &approvers,
                    requester: None,
                },
                software_executors: self.executors.clone(),
                model_runtime_executor: None,
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await
    }

    async fn deployed(&mut self) -> Option<String> {
        crate::environment::environment(&mut self.ctx, "edge")
            .await
            .unwrap()
            .properties
            .get("deployed.cluster")
            .cloned()
    }

    fn record(&self) -> AppliedStateRecord {
        serde_json::from_slice(
            &std::fs::read(record_path(&self.applier.state, "edge", "cluster")).unwrap(),
        )
        .unwrap()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn statuses(outcomes: &[Outcome]) -> Vec<StepOutcomeStatus> {
    outcomes
        .iter()
        .map(|outcome| outcome.classified_status().unwrap())
        .collect()
}

#[tokio::test]
async fn install_and_health_run_through_the_applier_at_the_planned_generations() {
    let mut host = Host::new("install").await;
    host.release("1.0.0", true).await;

    let plan = host.plan().await;

    let bindings: Vec<_> = plan
        .steps
        .iter()
        .map(|step| {
            (
                step.action,
                step.from.clone(),
                step.host,
                step.restore.is_some(),
            )
        })
        .collect();
    assert_eq!(
        bindings,
        [
            (
                Action::Install,
                None,
                Some(HostStep {
                    action: HostAction::Install,
                    expected_generation: 0
                }),
                false
            ),
            (
                Action::Restart,
                Some("1.0.0".into()),
                Some(HostStep {
                    action: HostAction::Health,
                    expected_generation: 1
                }),
                false
            ),
        ]
    );

    let outcomes = host.apply(&plan).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Succeeded, StepOutcomeStatus::Succeeded],
        "{outcomes:?}"
    );
    assert_eq!(
        *host.applier.runs.lock().unwrap(),
        ["install cluster@1.0.0", "health cluster@1.0.0"]
    );
    assert_eq!(host.deployed().await.as_deref(), Some("1.0.0"));
    assert_eq!(host.record().generation, 1);
    // The spool holds nothing once the steps ended.
    assert_eq!(std::fs::read_dir(&host.applier.spool).unwrap().count(), 0);
    assert!(host.plan().await.steps.is_empty(), "converged");

    // The next plan starts from what the applier recorded.
    host.release("1.1.0", false).await;
    let upgrade = host.plan().await;
    assert_eq!(upgrade.steps.len(), 1);
    assert_eq!(upgrade.steps[0].action, Action::Upgrade);
    assert_eq!(upgrade.steps[0].from.as_deref(), Some("1.0.0"));
    assert_eq!(
        upgrade.steps[0].host,
        Some(HostStep {
            action: HostAction::Install,
            expected_generation: 1
        })
    );
}

#[tokio::test]
async fn a_failed_host_install_stays_failed_and_nothing_is_restored() {
    let mut host = Host::new("failed").await;
    host.release("1.0.0", false).await;
    let plan = host.plan().await;
    host.apply(&plan).await.unwrap();
    host.release("2.0.0", false).await;
    host.applier
        .fail
        .lock()
        .unwrap()
        .insert(HostAction::Install);

    let plan = host.plan().await;
    let outcomes = host.apply(&plan).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Failed],
        "{outcomes:?}"
    );
    assert!(
        outcomes[0].detail.contains("run an approved rollback plan"),
        "{outcomes:?}"
    );
    // No cleanup of 2.0.0 and no restore of 1.0.0: only the one install ran.
    assert_eq!(
        *host.applier.runs.lock().unwrap(),
        ["install cluster@1.0.0", "install cluster@2.0.0"]
    );
    assert!(matches!(host.record().state, AppliedState::Dirty { .. }));
    // The server no longer knows which release is live ...
    assert_eq!(host.deployed().await, None);

    // ... but the applier's record does, so an approved plan can move on
    // from the dirty record at its current generation.
    host.applier.fail.lock().unwrap().clear();
    let retry = host.plan().await;
    assert_eq!(retry.steps.len(), 1);
    assert_eq!(retry.steps[0].from.as_deref(), Some("1.0.0"));
    assert_eq!(
        retry.steps[0].host,
        Some(HostStep {
            action: HostAction::Install,
            expected_generation: 2
        })
    );
    let outcomes = host.apply(&retry).await.unwrap();
    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Succeeded],
        "{outcomes:?}"
    );
    assert_eq!(host.deployed().await.as_deref(), Some("2.0.0"));
    assert!(host.plan().await.steps.is_empty(), "converged");
}

#[tokio::test]
async fn an_slo_gate_on_a_host_release_is_refused_before_anything_runs() {
    let mut host = Host::new("slo").await;
    host.release_with(
        "1.0.0",
        false,
        "\n[gate]\nbake_window_seconds = 0\non_fail = \"halt\"\n\n[[gate.slo]]\nname = \"error_rate\"\nquery = \"error_rate\"\nthreshold = 0.01\n",
    )
    .await;
    let plan = host.plan().await;

    let error = host.apply(&plan).await.unwrap_err();

    assert!(error.to_string().contains("SLO health gates"), "{error:#}");
    assert!(host.applier.starts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_refusal_fails_the_step_with_the_appliers_reason() {
    let mut host = Host::new("refused").await;
    host.release("1.0.0", false).await;
    let plan = host.plan().await;
    // Another host step moved the record on since the plan was made.
    let mut record = AppliedStateRecord::empty("edge", "cluster");
    record.generation = 4;
    Applier::write(
        &record_path(&host.applier.state, "edge", "cluster"),
        &record,
    )
    .unwrap();

    let outcomes = host.apply(&plan).await.unwrap();

    assert_eq!(
        statuses(&outcomes),
        [StepOutcomeStatus::Failed],
        "{outcomes:?}"
    );
    assert!(
        outcomes[0].detail.contains("did not run")
            && outcomes[0].detail.contains("refused")
            && outcomes[0].detail.contains(
                "expects generation 0 of cluster in edge, but the record is at generation 4"
            ),
        "{outcomes:?}"
    );
    assert!(host.applier.runs.lock().unwrap().is_empty());
    // Nothing ran, so nothing became unknown: the next plan can be made.
    host.plan().await;
}

#[tokio::test(start_paused = true)]
async fn losing_the_lease_stops_the_unit_and_a_retry_never_runs_it_again() {
    let mut host = Host::new("lease").await;
    host.release("1.0.0", false).await;
    let plan = host.plan().await;
    let database = host.root.join("tenkai.db");
    let lease = super::claim_environment(&mut host.ctx, "edge", &plan.id)
        .await
        .unwrap();
    let token = lease.fencing_token.clone();
    // While the command runs, another controller's cleanup ends this lease.
    *host.applier.hang.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            let mut other = Ctx::embedded(database).unwrap();
            other
                .release_lease(super::ENVIRONMENT_LEASE_NAMESPACE, "edge", &token)
                .await
                .unwrap();
        })
    }));
    let release = super::release_content::admit(
        &mut host.ctx,
        &crate::plan::ReleasePin {
            release_id: plan.steps[0].release_id.clone(),
            digest: plan.steps[0].release_digest.clone(),
            artifact_digest: plan.steps[0].artifact_digest.clone(),
            workdir: plan.steps[0].workdir.clone(),
        },
        "edge",
        "cluster",
        false,
    )
    .await
    .unwrap();
    let approvals = {
        let path = host.root.join("approval.json");
        crate::dev_sign::sign_plan_approval_for_digest(
            &host.root.join("keys"),
            &format!("sha256:{}", plan.executable_digest().unwrap()),
            "edge",
            &path,
            &host.root.join("approvers.toml"),
            3600,
        )
        .unwrap();
        crate::plan_approval::load_envelopes(&path).unwrap()
    };
    let signature = crate::catalog::signature_envelope(&mut host.ctx, &plan.steps[0].release_id)
        .await
        .unwrap();
    let request = super::step_lifecycle::host_request(
        &plan,
        &plan.steps[0],
        plan.steps[0].host.unwrap(),
        &release,
        signature,
        &approvals,
    )
    .unwrap();
    let executor = host.executors.host().unwrap().clone();

    let error = super::host_step::run(&mut host.ctx, &lease, &executor, &request, &release)
        .await
        .unwrap_err();

    assert!(
        format!("{error:#}").contains("is not the active fenced holder"),
        "{error:#}"
    );
    let instance = request.instance().unwrap();
    let result: crate::host_apply::state::HostApplyResult = serde_json::from_slice(
        &std::fs::read(instance_dir(&host.applier.state, &instance).join(RESULT_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(result.outcome, HostApplyOutcome::Stopped);

    // A retry of the same step addresses the same instance and gets its
    // recorded result: nothing is spooled, started, or run again.
    super::unlock_environment(&mut host.ctx, "edge")
        .await
        .unwrap();
    let lease = super::claim_environment(&mut host.ctx, "edge", &plan.id)
        .await
        .unwrap();
    let retried = super::host_step::run(&mut host.ctx, &lease, &executor, &request, &release)
        .await
        .unwrap();
    assert_eq!(retried, super::host_step::HostStepEnd::Recorded(result));
    assert_eq!(
        *host.applier.starts.lock().unwrap(),
        ["install cluster@1.0.0"]
    );
    assert_eq!(
        *host.applier.runs.lock().unwrap(),
        ["install cluster@1.0.0"]
    );
}

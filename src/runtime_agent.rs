//! Pull-only environment runtime for one configured Tenkai environment.

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use reqwest::StatusCode;
use tokio::process::Command;

use crate::inventory::{self, RUNTIME_INVENTORY_SOURCE};
use crate::plan::{Plan, Step};
use crate::runtime_delivery::{RuntimeCompletion, RuntimeStepReceipt};
use crate::runtime_delivery::{RuntimeHeartbeat, RuntimeInventoryReport, RuntimeWork};

/// `base_url` without a trailing `/`, when credentials may be sent to it:
/// HTTPS, or HTTP on loopback.
fn protected_base_url(base_url: String) -> Result<String> {
    let base_url = base_url.trim_end_matches('/').to_owned();
    let parsed = url::Url::parse(&base_url)?;
    let protected = parsed.scheme() == "https"
        || (parsed.scheme() == "http"
            && parsed.host().is_some_and(|host| match host {
                url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(address) => address.is_loopback(),
                url::Host::Ipv6(address) => address.is_loopback(),
            }));
    anyhow::ensure!(
        protected,
        "runtime credentials require HTTPS or an HTTP loopback URL"
    );
    Ok(base_url)
}

/// Where an enrolled runtime keeps its sealing key: the certificate
/// directory, else beside its credential file.
pub fn sealing_dir(certificate_dir: Option<&Path>, credential_file: &Path) -> PathBuf {
    certificate_dir
        .map(PathBuf::from)
        .or_else(|| credential_file.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The agent's own credential (#630): the one kept in `credential_file`, or,
/// on first start, the one the server issues for the enrollment token, written
/// there (owner-only) before it is used. `enrollment_token` is read only when
/// there is no credential yet, so a removed bootstrap secret does not block a
/// restart. The token is spent on the server when redeemed, so a crash
/// before the write needs a new token.
///
/// With `certificate_dir` (#674), enrollment also gets a runner certificate:
/// the agent generates its key there (owner-only, or in a hardware store
/// when `TENKAI_RUNTIME_KEY_STORE=hardware`, #785), sends only a CSR, and
/// writes the issued `cert.pem` and the runner `ca.pem` beside it.
///
/// A server that requires runner attestation (#675) answers
/// `attestation_missing` (HTTP 428) without spending the token; the agent
/// then signs host evidence (the checks of `preflight`, when given, and its
/// probed facts) with its runner key and enrolls again.
pub async fn enrolled_credential(
    base_url: &str,
    environment: &str,
    enrollment_token: impl FnOnce() -> Result<Option<String>>,
    credential_file: &std::path::Path,
    certificate_dir: Option<&std::path::Path>,
    preflight: Option<&std::path::Path>,
) -> Result<String> {
    match std::fs::read_to_string(credential_file) {
        Ok(stored) => {
            let stored = stored.trim().to_owned();
            anyhow::ensure!(
                stored.starts_with(crate::runtime_credentials::CREDENTIAL_PREFIX),
                "{} does not hold a runtime credential",
                credential_file.display()
            );
            return Ok(stored);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", credential_file.display()));
        }
    }
    let token = enrollment_token()?.with_context(|| {
        format!(
            "{} does not exist; an enrollment token is required to create it",
            credential_file.display()
        )
    })?;
    let base_url = protected_base_url(base_url.to_owned())?;
    // Certificate files without a credential are left by an enrollment that
    // stopped before saving its credential: they belong to no runner now.
    if let Some(dir) = certificate_dir {
        for name in [RUNNER_CERT, RUNNER_CA] {
            crate::atomic_state::remove_if_exists(&dir.join(name))?;
        }
    }
    let csr = certificate_dir
        .map(|dir| crate::runner_key::RunnerKey::open_or_generate(dir)?.csr())
        .transpose()?;
    let sealing_dir = sealing_dir(certificate_dir, credential_file);
    let sealing = crate::sealing_key::SealingKey::open_or_generate(&sealing_dir)?;
    // No redirects: the token goes only to the protected URL checked above.
    let client = crate::outbound_tls::client()?
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let url = format!("{base_url}/v1/runtime/environments/{environment}/enroll");
    let mut request = crate::runtime_delivery::RuntimeEnrollRequest {
        token,
        csr,
        attestation: None,
        sealing_public_key: Some(sealing.to_wire()),
    };
    let mut attempts = 0;
    let enrolled: crate::runtime_delivery::RuntimeEnrolled = loop {
        attempts += 1;
        anyhow::ensure!(attempts <= 4, "runtime enrollment retry loop exhausted");
        let response = client.post(&url).json(&request).send().await?;
        let status = response.status();
        if status == reqwest::StatusCode::PRECONDITION_REQUIRED {
            if request.attestation.is_some() {
                let detail = response.text().await.unwrap_or_default();
                bail!("runtime enrollment refused: {status} {detail}");
            }
            let (Some(dir), Some(csr)) = (certificate_dir, &request.csr) else {
                bail!("the server requires runner attestation, which needs --certificate-dir");
            };
            let schema = crate::runner_attestation::AttestationSchema::for_challenge(
                &response.text().await.unwrap_or_default(),
            )?;
            request.attestation = Some(host_attestation(dir, environment, csr, preflight, schema)?);
            continue;
        }
        if status.is_success() {
            break response.json().await?;
        }
        let detail = response.text().await.unwrap_or_default();
        if request.sealing_public_key.is_some()
            && unknown_field_rejected(status, &detail, "sealing_public_key")
        {
            // An older replica (`deny_unknown_fields`) during a rolling
            // deploy: omit the additive field and retry. The token is unspent.
            request.sealing_public_key = None;
            continue;
        }
        bail!("runtime enrollment refused: {status} {detail}");
    };
    if let Some(dir) = certificate_dir {
        let (Some(certificate), Some(ca)) = (&enrolled.certificate, &enrolled.ca) else {
            bail!("the server returned no runner certificate for the CSR");
        };
        write_owner_only(&dir.join(RUNNER_CERT), certificate)?;
        write_owner_only(&dir.join(RUNNER_CA), ca)?;
    }
    write_owner_only(credential_file, &enrolled.credential)?;
    eprintln!(
        "enrolled runtime credential {} for {}",
        enrolled.credential_id, enrolled.environment
    );
    eprintln!(
        "sealing key fingerprint {} (sealed_secrets)",
        sealing.fingerprint()
    );
    Ok(enrolled.credential)
}

/// File names in a runner certificate directory (#674).
const RUNNER_CERT: &str = "cert.pem";
const RUNNER_CA: &str = "ca.pem";

/// A CSR over the agent's own key in `dir`, generating the key (kept
/// owner-only, never sent) when there is none yet.
#[cfg(test)]
fn runner_csr(dir: &std::path::Path) -> Result<String> {
    crate::runner_key::RunnerKey::open_or_generate(dir)?.csr()
}

/// Host evidence for `environment`, signed as `schema` with the runner key
/// in `dir` for the key of `csr` (#675).
fn host_attestation(
    dir: &std::path::Path,
    environment: &str,
    csr: &str,
    preflight: Option<&std::path::Path>,
    schema: crate::runner_attestation::AttestationSchema,
) -> Result<crate::runner_attestation::RunnerAttestation> {
    let key = crate::runner_key::RunnerKey::open(dir)?
        .with_context(|| format!("reading the runner key in {}", dir.display()))?;
    key.sign_attestation(schema, host_evidence(environment, preflight)?, csr)
}

/// This host's evidence for `environment` now: the checks of the preflight
/// config at `preflight` (none without one) and the probed inventory facts.
fn host_evidence(
    environment: &str,
    preflight: Option<&std::path::Path>,
) -> Result<crate::runner_attestation::HostEvidence> {
    let checked_at = crate::now_millis();
    let checks = match preflight {
        Some(path) => crate::host_preflight::run_checks(
            &crate::host_preflight::PreflightConfig::load(path)?,
            checked_at,
        ),
        None => Vec::new(),
    };
    Ok(crate::runner_attestation::HostEvidence {
        environment: environment.into(),
        checks,
        facts: inventory::facts_map(&inventory::probe_local_inventory()?),
        checked_at,
    })
}

/// The agent's runner certificate from `dir` as a client identity with the
/// certificate's expiry (unix seconds), when enrollment issued one (#674).
pub fn runner_identity(
    dir: &std::path::Path,
) -> Result<Option<(crate::runner_key::ClientAuth, i64)>> {
    let Some(key) = crate::runner_key::RunnerKey::open(dir)? else {
        return Ok(None);
    };
    key.tls_identity(dir)
}

/// Replace `path` with `contents`, owner-only, in one rename: a reader sees
/// the old file or the new one, never a partial one.
fn replace_file(path: &std::path::Path, contents: &str) -> Result<()> {
    crate::atomic_state::write_file(path, contents.as_bytes(), Some(0o600))
        .with_context(|| format!("writing {}", path.display()))
}

/// Write `secret` to `path` readable by the owner only, replacing nothing:
/// a temporary file beside it is synced and linked into place, and the
/// directory is synced so the new name survives a host crash.
fn write_owner_only(path: &std::path::Path, secret: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // Unique per attempt: a leftover from a crash never blocks a retry.
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let written = file
        .write_all(secret.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&temporary, path));
    let _ = std::fs::remove_file(&temporary);
    written.with_context(|| format!("writing {}", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing {}", directory.display()))
}

/// How a runtime applies a claimed step.
#[derive(Clone)]
pub enum StepExecutor {
    /// An operator program, run through `tenkai-runtime-guard`.
    Program(PathBuf),
    /// Tenkai's own executors (ADR 0048).
    Builtin(std::sync::Arc<crate::runtime_builtin::BuiltinConfig>),
}

impl From<PathBuf> for StepExecutor {
    fn from(program: PathBuf) -> Self {
        Self::Program(program)
    }
}

/// How often a runtime looks for workload certificates to renew. A
/// certificate is due with a third of its lifetime left, so a minute is
/// far inside that.
const RENEWAL_PASS_INTERVAL_MS: i64 = 60_000;

#[derive(Clone)]
pub struct RuntimeClient {
    base_url: String,
    environment: String,
    instance_id: String,
    token: String,
    executor: StepExecutor,
    http: reqwest::Client,
    /// Where the runner certificate lives, when the agent has one (#674).
    certificate_dir: Option<PathBuf>,
    /// The runner key kept with the certificate directory (#674, #785).
    runner_key: Option<crate::runner_key::RunnerKey>,
    /// A client presenting the runner certificate, and the certificate's
    /// expiry (unix seconds). Replaced on renewal.
    certified: std::sync::Arc<std::sync::RwLock<Option<(reqwest::Client, i64)>>>,
    /// When true, probe local inventory and POST to the hub each poll (#136).
    inventory_report: bool,
    /// Where the agent keeps its own versions, to run its own release (#685).
    home: Option<std::sync::Arc<crate::runtime_self_upgrade::Home>>,
    /// Set once the agent switched to a new version of itself: it stops so
    /// the supervisor starts that version.
    restart: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// When the last workload certificate renewal pass ran (Unix millis),
    /// so a fast poll does not list the target every time. In memory only:
    /// what is due is read from the target, and a restart just runs a pass.
    renewal_pass_at: std::sync::Arc<std::sync::atomic::AtomicI64>,
    /// The host preflight config whose checks runner attestation carries.
    preflight: Option<PathBuf>,
    /// Local approval policy and trust roots, installed on this host
    /// (ADR 0045 §4). Absent: sealed steps are refused with a named reason.
    local_policy: Option<crate::host_apply::HostApprovalPolicy>,
}

impl RuntimeClient {
    pub fn new(
        base_url: impl Into<String>,
        environment: impl Into<String>,
        token: impl Into<String>,
        executor: impl Into<StepExecutor>,
    ) -> Result<Self> {
        Self::new_with_options(base_url, environment, token, executor, true)
    }

    pub fn new_with_options(
        base_url: impl Into<String>,
        environment: impl Into<String>,
        token: impl Into<String>,
        executor: impl Into<StepExecutor>,
        inventory_report: bool,
    ) -> Result<Self> {
        let executor = executor.into();
        let base_url = protected_base_url(base_url.into())?;
        let environment = environment.into();
        let token = token.into();
        anyhow::ensure!(!environment.is_empty(), "runtime environment is required");
        anyhow::ensure!(!token.is_empty(), "runtime token is required");
        if let StepExecutor::Program(program) = &executor {
            anyhow::ensure!(
                program.is_absolute(),
                "runtime executor path must be absolute"
            );
        }
        Ok(Self {
            base_url,
            environment,
            instance_id: uuid::Uuid::new_v4().to_string(),
            token,
            executor,
            http: crate::outbound_tls::client()?
                .timeout(Duration::from_secs(10))
                .build()?,
            inventory_report,
            certificate_dir: None,
            runner_key: None,
            certified: Default::default(),
            home: None,
            restart: Default::default(),
            renewal_pass_at: Default::default(),
            preflight: None,
            local_policy: None,
        })
    }

    /// Run the checks of the preflight config at `path` for runner
    /// attestation (#675).
    pub fn with_preflight(mut self, path: PathBuf) -> Self {
        self.preflight = Some(path);
        self
    }

    /// Verify sealed steps against this host-owned approval policy
    /// (ADR 0045 §4). Without it, those steps are refused.
    pub fn with_local_policy(mut self, policy: crate::host_apply::HostApprovalPolicy) -> Self {
        self.local_policy = Some(policy);
        self
    }

    /// Run the agent's own releases with versions kept under `home` (#685).
    /// A switch not yet reported keeps the instance identity that claimed it.
    pub fn with_home(mut self, home: crate::runtime_self_upgrade::Home) -> Result<Self> {
        if let Some(pending) = home.pending()? {
            self.instance_id = pending.instance_id;
        }
        self.home = Some(std::sync::Arc::new(home));
        Ok(self)
    }

    /// Present the runner certificate kept in `dir` on every request (#674).
    /// The certificate is renewed ahead of expiry; with a certificate
    /// directory the agent never falls back to its bearer for work, so its
    /// lease identity stays the runner's.
    pub fn with_certificate_dir(mut self, dir: PathBuf) -> Result<Self> {
        let key = crate::runner_key::RunnerKey::open_or_generate(&dir)?;
        let loaded = key.tls_identity(&dir)?;
        self.certificate_dir = Some(dir);
        self.runner_key = Some(key);
        if let Some((identity, not_after)) = loaded {
            self.install_identity(identity, not_after)?;
        }
        Ok(self)
    }

    fn install_identity(
        &self,
        identity: crate::runner_key::ClientAuth,
        not_after: i64,
    ) -> Result<()> {
        let client = match identity {
            crate::runner_key::ClientAuth::Pem(identity) => crate::outbound_tls::client()?
                .timeout(Duration::from_secs(10))
                .identity(identity)
                .build()?,
            crate::runner_key::ClientAuth::Rustls(resolver) => {
                let mut config = crate::outbound_tls::OutboundTrust::from_env()?
                    .rustls_client_config_with_auth(Some(resolver))?;
                // reqwest is built without the http2 feature, so advertise HTTP/1.1 only.
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                reqwest::Client::builder()
                    .use_preconfigured_tls(config)
                    .timeout(Duration::from_secs(10))
                    .build()?
            }
        };
        *self
            .certified
            .write()
            .map_err(|_| anyhow::anyhow!("runner certificate lock poisoned"))? =
            Some((client, not_after));
        Ok(())
    }

    /// The certified client while its certificate is valid for another
    /// minute, if any.
    fn certified_client(&self) -> Option<reqwest::Client> {
        let now = crate::now_millis() / 1_000;
        self.certified
            .read()
            .ok()?
            .as_ref()
            .filter(|(_, not_after)| now + 60 < *not_after)
            .map(|(client, _)| client.clone())
    }

    /// The client for work: the certified one when the agent has a
    /// certificate directory (refusing while it holds no valid certificate),
    /// else the bearer one.
    fn client(&self) -> Result<reqwest::Client> {
        if self.certificate_dir.is_none() {
            return Ok(self.http.clone());
        }
        self.certified_client()
            .context("the runner certificate is missing or expired; renewing it first")
    }

    /// Renew the runner certificate once a third of its lifetime is left, or
    /// it has expired: with the current certificate while it is valid, else
    /// with the enrolled bearer. The key stays the same and never leaves the
    /// host.
    async fn renew_certificate_if_due(&self) -> Result<()> {
        let Some(dir) = &self.certificate_dir else {
            return Ok(());
        };
        let now = crate::now_millis() / 1_000;
        let due = self
            .certified
            .read()
            .map_err(|_| anyhow::anyhow!("runner certificate lock poisoned"))?
            .as_ref()
            .is_none_or(|(_, not_after)| {
                *not_after - now < crate::runner_ca::RUNNER_CERTIFICATE_TTL_SECS / 3
            });
        if !due {
            return Ok(());
        }
        let client = self.certified_client().unwrap_or_else(|| self.http.clone());
        let key = self
            .runner_key
            .as_ref()
            .context("the runner key is missing from the certificate directory")?;
        let csr = key.csr()?;
        let mut sealing_public_key =
            Some(crate::sealing_key::SealingKey::open_or_generate(dir)?.to_wire());
        let send = |attestation: Option<crate::runner_attestation::RunnerAttestation>,
                    sealing_public_key: Option<String>| {
            client
                .post(format!(
                    "{}/v1/runtime/environments/{}/certificate",
                    self.base_url, self.environment
                ))
                .bearer_auth(&self.token)
                .header("x-tenkai-runtime-instance", &self.instance_id)
                .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
                .json(&crate::runtime_delivery::RuntimeCertificateRequest {
                    csr: csr.clone(),
                    attestation,
                    sealing_public_key,
                })
                .send()
        };
        // Evidence only when this server asks for it on this request (#675),
        // in a schema it names (#849): a server of an earlier release, during
        // a rolling deploy or after a rollback, refuses the unknown field and
        // names no schemas, so it gets v1. The same retry drops
        // `sealing_public_key` when that replica predates it.
        let mut attestation = None;
        let mut attempts = 0;
        let renewed: crate::runtime_delivery::RuntimeCertificate = loop {
            attempts += 1;
            anyhow::ensure!(
                attempts <= 4,
                "runner certificate renewal retry loop exhausted"
            );
            let response = send(attestation.clone(), sealing_public_key.clone()).await?;
            let status = response.status();
            if status == reqwest::StatusCode::PRECONDITION_REQUIRED {
                if attestation.is_some() {
                    let detail = response.text().await.unwrap_or_default();
                    bail!("renewing the runner certificate returned {status}: {detail}");
                }
                let schema = crate::runner_attestation::AttestationSchema::for_challenge(
                    &response.text().await.unwrap_or_default(),
                )?;
                let evidence = host_evidence(&self.environment, self.preflight.as_deref())?;
                attestation = Some(key.sign_attestation(schema, evidence, &csr)?);
                continue;
            }
            if status.is_success() {
                break decode_response(response, "renewing the runner certificate").await?;
            }
            let detail = response.text().await.unwrap_or_default();
            if sealing_public_key.is_some()
                && unknown_field_rejected(status, &detail, "sealing_public_key")
            {
                sealing_public_key = None;
                continue;
            }
            bail!("renewing the runner certificate returned {status}: {detail}");
        };
        replace_file(&dir.join(RUNNER_CA), &renewed.ca)?;
        replace_file(&dir.join(RUNNER_CERT), &renewed.certificate)?;
        let (identity, not_after) = key
            .tls_identity(dir)?
            .context("the renewed runner certificate did not load")?;
        self.install_identity(identity, not_after)
    }

    /// Whether the agent switched to a new version of itself and must stop.
    pub fn restart_requested(&self) -> bool {
        self.restart.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub async fn run_once(&self) -> Result<bool> {
        if let Err(error) = self.renew_certificate_if_due().await {
            eprintln!("runner certificate renewal failed (retrying next poll): {error:#}");
        }
        // Before anything that needs the server, so certificates renew while
        // it is unreachable (ADR 0046 §3).
        self.renew_workload_identities().await;
        // Refresh admitted inventory facts before work pull (#136). Failures are
        // visible but non-fatal so temporary probe issues do not stop delivery.
        if let Err(error) = self.report_inventory().await {
            eprintln!("runtime inventory report failed (continuing): {error:#}");
        }
        self.report_host_records_or_warn().await;
        if self.report_switch().await? {
            return Ok(true);
        }
        let work = self.pull().await?;
        if let Some(request) = &work.issuer_candidate
            && let Err(error) = self.offer_issuer_candidate(request).await
        {
            eprintln!("identity issuer candidate failed (retrying next poll): {error:#}");
        }
        let approvals = work.approvals;
        let (Some(plan), Some(claim)) = (work.plan, work.claim) else {
            return Ok(false);
        };
        if let Some(completion_json) = claim.completion_json {
            let completion: RuntimeCompletion = serde_json::from_str(&completion_json)
                .context("decoding durable runtime completion for replay")?;
            anyhow::ensure!(
                completion.plan_id == plan.id && completion.generation == claim.generation,
                "durable runtime completion does not match its claim"
            );
            self.complete(completion).await?;
            return Ok(true);
        }
        validate_plan(&plan, &self.environment)?;

        if !self.heartbeat(&plan.id, claim.generation).await? {
            bail!("runtime claim was fenced before local approval");
        }
        for step in &plan.steps {
            match crate::runtime_local_approval::decide_step(
                self.local_policy.as_ref(),
                &plan,
                step,
                &approvals,
                crate::now_millis(),
            )? {
                crate::runtime_local_approval::StepDecision::Allowed => {}
                crate::runtime_local_approval::StepDecision::Wait(reason) => {
                    eprintln!(
                        "runtime local approval pending for step {} (continuing): {reason}",
                        step.id
                    );
                    return Ok(true);
                }
                crate::runtime_local_approval::StepDecision::Refuse(reason) => {
                    let receipts = plan
                        .steps
                        .iter()
                        .map(|later| RuntimeStepReceipt {
                            step_id: later.id.clone(),
                            succeeded: false,
                            detail: if later.id == step.id {
                                reason.clone()
                            } else {
                                "not executed after an earlier step failed".into()
                            },
                            wraps: Vec::new(),
                        })
                        .collect();
                    self.complete(RuntimeCompletion {
                        plan_id: plan.id,
                        generation: claim.generation,
                        succeeded: false,
                        detail: "environment runtime reported a failed step".into(),
                        receipts,
                    })
                    .await?;
                    return Ok(true);
                }
            }
        }

        // A unit an earlier holder left running stops before anything of
        // this plan runs.
        if let StepExecutor::Builtin(config) = &self.executor {
            crate::runtime_builtin::fence_host_units(self, config, &plan.id, claim.generation)
                .await?;
        }
        let mut receipts = Vec::with_capacity(plan.steps.len());
        let mut succeeded = true;
        for (index, step) in plan.steps.iter().enumerate() {
            if !self.heartbeat(&plan.id, claim.generation).await? {
                bail!("runtime claim was fenced before step {}", step.id);
            }
            let receipt = if step.product == crate::runtime_self_upgrade::SELF_PRODUCT {
                let last = index + 1 == plan.steps.len();
                match self
                    .switch_self(&plan.id, claim.generation, step, last, &receipts)
                    .await?
                {
                    Some(receipt) => receipt,
                    // Switched: the new version reports this plan.
                    None => return Ok(true),
                }
            } else {
                self.execute_step(&plan, claim.generation, step, &approvals)
                    .await?
            };
            if !receipt.succeeded {
                eprintln!(
                    "runtime step {} failed: {}",
                    receipt.step_id, receipt.detail
                );
            }
            succeeded &= receipt.succeeded;
            receipts.push(receipt);
            if !succeeded {
                break;
            }
        }
        for step in plan.steps.iter().skip(receipts.len()) {
            receipts.push(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "not executed after an earlier step failed".into(),
                wraps: Vec::new(),
            });
        }
        self.complete(RuntimeCompletion {
            plan_id: plan.id,
            generation: claim.generation,
            succeeded,
            detail: if succeeded {
                "environment runtime completed every step".into()
            } else {
                "environment runtime reported a failed step".into()
            },
            receipts,
        })
        .await?;
        // The next plan is made from what this one left on the host.
        self.report_host_records_or_warn().await;
        Ok(true)
    }

    /// Run the agent's own step (#685): stage the release's binaries and
    /// switch to them. `None` once switched; the plan is then reported by the
    /// new version. A receipt when there is nothing to switch or it fails.
    async fn switch_self(
        &self,
        plan_id: &str,
        generation: u64,
        step: &Step,
        last: bool,
        receipts: &[RuntimeStepReceipt],
    ) -> Result<Option<RuntimeStepReceipt>> {
        let receipt = |succeeded: bool, detail: String| {
            Some(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded,
                detail,
                wraps: Vec::new(),
            })
        };
        if !last {
            return Ok(receipt(
                false,
                "the runtime agent's own release must be the plan's last step".into(),
            ));
        }
        let Some(home) = &self.home else {
            return Ok(receipt(
                false,
                "TENKAI_RUNTIME_HOME is not set; the runtime agent cannot switch its own version"
                    .into(),
            ));
        };
        // Pulled from the server, into a directory only this agent writes:
        // an agent on another host has no access to the server's files.
        let download = match self
            .while_claimed(
                plan_id,
                generation,
                self.download_self_release(home, plan_id, generation, step),
            )
            .await
        {
            Ok(download) => download,
            Err(error) => {
                return Ok(receipt(
                    false,
                    format!("fetching the runtime agent release: {error:#}"),
                ));
            }
        };
        // Its bytes and modes must be the signed release's before anything is
        // staged, run or switched; staging checks its own copy again.
        let expected = step.artifact_digest.clone();
        let staging = {
            let home = home.clone();
            tokio::task::spawn_blocking(move || {
                let source = download.path();
                crate::runtime_self_upgrade::verify_release(source, &expected)
                    .and_then(|()| home.stage(source, &expected))
            })
            .await
            .context("staging the runtime agent")?
        };
        let staged = match staging {
            Ok(staged) => staged,
            Err(error) => {
                return Ok(receipt(
                    false,
                    format!("staging the runtime agent: {error:#}"),
                ));
            }
        };
        let Some(current) = home.current()? else {
            return Ok(receipt(
                false,
                "the runtime agent has no current version; run `tenkai-runtime install` first"
                    .into(),
            ));
        };
        // A restart of the running version still restarts: the switch below
        // repoints `current` at itself and the restarted agent reports it.
        if current == staged && step.action != crate::plan::Action::Restart {
            return Ok(receipt(
                true,
                format!("runtime agent already runs version {staged}"),
            ));
        }
        // Staging can take a while: switch only while the claim still holds,
        // so a runtime that has taken over is never raced.
        if !self.heartbeat(plan_id, generation).await? {
            bail!("runtime claim was fenced before switching to version {staged}");
        }
        home.write_pending(&crate::runtime_self_upgrade::Pending {
            plan_id: plan_id.into(),
            generation,
            step_id: step.id.clone(),
            instance_id: self.instance_id.clone(),
            receipts: receipts.to_vec(),
            from: current,
            to: staged.clone(),
            reverted: false,
        })?;
        if let Err(error) = home.switch(&staged) {
            home.clear_pending()?;
            return Ok(receipt(
                false,
                format!("switching the runtime agent: {error:#}"),
            ));
        }
        self.restart
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(None)
    }

    /// Report a switch of the agent's own version, once the version it left
    /// for is running, or the previous one after a revert (#685). True when
    /// there was one to report.
    async fn report_switch(&self) -> Result<bool> {
        let Some(home) = &self.home else {
            return Ok(false);
        };
        let Some(pending) = home.pending()? else {
            return Ok(false);
        };
        // A revert interrupted by a crash is finished before anything is
        // reported.
        home.finish_revert(&pending)?;
        let current = home.current()?;
        // Prepared but never switched (a crash between the two): resume the
        // switch under the claim, or drop it once the claim is gone. The
        // new version was never started, so this is no failure to report.
        if !pending.reverted
            && pending.from != pending.to
            && current.as_deref() == Some(pending.from.as_str())
        {
            if self.renewable(&pending.plan_id, pending.generation).await? {
                home.switch(&pending.to)?;
                self.restart
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            } else {
                home.clear_pending()?;
            }
            return Ok(true);
        }
        let (succeeded, detail) = if !pending.reverted && current.as_deref() == Some(&pending.to) {
            (
                true,
                format!("runtime agent now runs version {}", pending.to),
            )
        } else {
            (
                false,
                format!(
                    "runtime agent version {} did not start; running version {} again",
                    pending.to, pending.from
                ),
            )
        };
        // Lost or refused meanwhile, the claim is taken again and the plan
        // runs again; its own step then finds the version already current. A
        // refusal must not keep this report, or the agent would never pull
        // the work that recovers it; a transport failure retries.
        if self.renewable(&pending.plan_id, pending.generation).await? {
            let mut receipts = pending.receipts.clone();
            receipts.push(RuntimeStepReceipt {
                step_id: pending.step_id.clone(),
                succeeded,
                detail,
                wraps: Vec::new(),
            });
            let all = receipts.iter().all(|receipt| receipt.succeeded);
            self.complete(RuntimeCompletion {
                plan_id: pending.plan_id.clone(),
                generation: pending.generation,
                succeeded: all,
                detail: if all {
                    "environment runtime completed every step".into()
                } else {
                    "environment runtime reported a failed step".into()
                },
                receipts,
            })
            .await?;
        }
        home.clear_pending()?;
        Ok(true)
    }

    pub async fn run(&self, interval: Duration) -> Result<()> {
        anyhow::ensure!(
            !interval.is_zero(),
            "poll interval must be greater than zero"
        );
        // Renewal also ticks on its own, so a long plan does not hold
        // workload certificates past their expiry.
        let renew = async {
            let mut tick = tokio::time::interval(Duration::from_millis(
                RENEWAL_PASS_INTERVAL_MS.unsigned_abs(),
            ));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                self.renew_workload_identities().await;
            }
        };
        tokio::select! {
            polled = self.poll(interval) => polled,
            never = renew => never,
        }
    }

    /// Poll for work every `interval`, backing off on failure, until a
    /// restart is requested.
    async fn poll(&self, interval: Duration) -> Result<()> {
        let mut consecutive_failures = 0_u32;
        loop {
            let delay = match self.run_once().await {
                Ok(_) if self.restart_requested() => return Ok(()),
                Ok(_) => {
                    consecutive_failures = 0;
                    interval
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    eprintln!("runtime poll failed; retrying: {error:#}");
                    let exponent = consecutive_failures.saturating_sub(1).min(6);
                    Duration::from_secs(1_u64 << exponent).min(Duration::from_secs(60))
                }
            };
            tokio::time::sleep(delay).await;
        }
    }

    async fn pull(&self) -> Result<RuntimeWork> {
        let mut request = self
            .client()?
            .get(format!(
                "{}/v1/runtime/environments/{}/work",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"));
        // A server that predates the header ignores it and offers no issuer
        // work; one that knows it offers issuer work only with it.
        if self.workload_identity() {
            request = request.header(
                "x-tenkai-runtime-capabilities",
                format!(
                    "{},{}",
                    crate::runtime_delivery::WORKLOAD_IDENTITY_CAPABILITY,
                    crate::runtime_delivery::PEER_GRANTS_CAPABILITY
                ),
            );
        }
        decode_response(request.send().await?, "pulling runtime work").await
    }

    /// Renew the workload certificates of this environment that are due, at
    /// most once per [`RENEWAL_PASS_INTERVAL_MS`]. Never fails the poll: an
    /// instance that could not be renewed is logged and retried next pass.
    async fn renew_workload_identities(&self) {
        let StepExecutor::Builtin(config) = &self.executor else {
            return;
        };
        // Claim the pass, so the poll and the ticker in [`Self::run`] never
        // run two at once.
        let now = crate::now_millis();
        let last = self
            .renewal_pass_at
            .load(std::sync::atomic::Ordering::SeqCst);
        if (last != 0 && now.saturating_sub(last) < RENEWAL_PASS_INTERVAL_MS)
            || self
                .renewal_pass_at
                .compare_exchange(
                    last,
                    now,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_err()
        {
            return;
        }
        let config = std::sync::Arc::clone(config);
        let environment = self.environment.clone();
        let pass = tokio::task::spawn_blocking(move || {
            crate::runtime_builtin::renew_identities(&config, &environment, now / 1000)
        })
        .await;
        match pass {
            Ok(Ok(renewals)) => {
                for renewal in renewals {
                    match renewal.outcome {
                        Ok(expires) => eprintln!(
                            "renewed the workload certificate of {}; it expires at {expires}",
                            renewal.instance
                        ),
                        Err(error) => eprintln!(
                            "renewing the workload certificate of {} failed (retrying): {error}",
                            renewal.instance
                        ),
                    }
                }
            }
            Ok(Err(error)) => {
                eprintln!("workload certificate renewal failed (retrying): {error:#}")
            }
            Err(error) => eprintln!("workload certificate renewal panicked (retrying): {error}"),
        }
    }

    /// Whether this runtime runs identity issuer steps (ADR 0046 §2): only
    /// the built-in executor with a sealing key opens the issuer key.
    fn workload_identity(&self) -> bool {
        matches!(&self.executor, StepExecutor::Builtin(config) if config.sealing_dir.is_some())
    }

    /// Generate an identity issuer candidate sealed to this runtime's own
    /// key only, and upload it (ADR 0046 §2). It never seals to a key the
    /// server names, so a server cannot read the issuer; other runtimes get
    /// it through approved re-wraps. The key exists unsealed only in this
    /// call. If another runtime's candidate was kept first, the server
    /// returns it and this key is dropped; a crash before the upload loses
    /// only this key, and the next poll generates another.
    async fn offer_issuer_candidate(
        &self,
        request: &crate::identity_issuer::CandidateRequest,
    ) -> Result<()> {
        let StepExecutor::Builtin(config) = &self.executor else {
            bail!("only a built-in runtime generates an issuer candidate");
        };
        let dir = config
            .sealing_dir
            .as_deref()
            .context("this runtime has no sealing key")?;
        let own = crate::sealing_key::SealingKey::open_or_generate(dir)?;
        let candidate = crate::identity_issuer::generate(
            &self.environment,
            request.generation,
            own.public(),
            crate::now_millis() / 1000,
        )?;
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/identity-issuer/candidate",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&candidate)
            .send()
            .await?;
        let kept: crate::identity_issuer::IssuerKey =
            decode_response(response, "uploading the identity issuer candidate").await?;
        if kept.fingerprint != candidate.fingerprint {
            eprintln!(
                "identity issuer generation {} already has candidate {}; dropped this one",
                kept.generation, kept.fingerprint
            );
        }
        Ok(())
    }

    /// Probe local admitted inventory and POST to the hub (#136).
    ///
    /// No-op when `inventory_report` is disabled. Never invents unknown keys.
    pub async fn report_inventory(&self) -> Result<()> {
        if !self.inventory_report {
            return Ok(());
        }
        let facts = inventory::probe_local_inventory()?;
        if facts.is_empty() {
            return Ok(());
        }
        let report = RuntimeInventoryReport {
            facts: inventory::facts_map(&facts),
            source: RUNTIME_INVENTORY_SOURCE.into(),
        };
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/inventory",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&report)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response.text().await.unwrap_or_default();
            bail!("reporting runtime inventory returned {status}: {detail}");
        }
        Ok(())
    }

    /// [`Self::report_host_records`], whose failure leaves the server
    /// planning from the records it last stored: visible, and retried next
    /// poll.
    async fn report_host_records_or_warn(&self) {
        if let Err(error) = self.report_host_records().await {
            eprintln!("host applied-state report failed (continuing): {error:#}");
        }
    }

    /// Report every applied-state record this host's applier keeps for the
    /// environment, so the server plans host steps from them (ADR 0048 §2).
    /// Only a built-in runtime with a host applier reports.
    pub async fn report_host_records(&self) -> Result<()> {
        let StepExecutor::Builtin(config) = &self.executor else {
            return Ok(());
        };
        let Ok(host) = config.executors.host() else {
            return Ok(());
        };
        let report = crate::runtime_delivery::RuntimeHostRecordsReport {
            records: host.applied_states(&self.environment)?,
        };
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/host-records",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&report)
            .send()
            .await?;
        let status = response.status();
        if matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ) {
            bail!("the server does not accept host applied-state records; upgrade the server");
        }
        let _: crate::runtime_delivery::RuntimeHostRecordsResponse =
            decode_response(response, "reporting host applied-state records").await?;
        Ok(())
    }

    /// Run `work` while renewing the plan's claim every 30 seconds; stop it
    /// once the claim is fenced (#685).
    async fn while_claimed<T>(
        &self,
        plan_id: &str,
        generation: u64,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        tokio::pin!(work);
        let mut renew = tokio::time::interval(Duration::from_secs(30));
        renew.tick().await;
        loop {
            tokio::select! {
                done = &mut work => return done,
                _ = renew.tick() => {
                    if !self.heartbeat(plan_id, generation).await? {
                        bail!("runtime claim was fenced while fetching the runtime agent");
                    }
                }
            }
        }
    }

    /// Download the agent's own release for `step` into a fresh private
    /// directory under the home, each binary with the mode the server
    /// reports (#685).
    async fn download_self_release(
        &self,
        home: &crate::runtime_self_upgrade::Home,
        plan_id: &str,
        generation: u64,
        step: &Step,
    ) -> Result<crate::runtime_self_upgrade::Download> {
        let download = home.download_dir()?;
        let dir = download.path();
        for name in crate::runtime_self_upgrade::BINARIES {
            let response = self
                .client()?
                .post(format!(
                    "{}/v1/runtime/environments/{}/self-release",
                    self.base_url, self.environment
                ))
                .timeout(Duration::from_secs(300))
                .bearer_auth(&self.token)
                .header("x-tenkai-runtime-instance", &self.instance_id)
                .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
                .json(&crate::runtime_delivery::RuntimeSelfReleaseFile {
                    plan_id: plan_id.into(),
                    generation,
                    step_id: step.id.clone(),
                    name: name.into(),
                })
                .send()
                .await?;
            let status = response.status();
            if !status.is_success() {
                bail!("the server refused {name}: {status}");
            }
            let mode = response
                .headers()
                .get("x-tenkai-file-mode")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| u32::from_str_radix(value, 8).ok())
                .filter(|mode| *mode <= 0o7777);
            let Some(mode) = mode else {
                bail!("the server sent {name} without a file mode");
            };
            let bytes = response.bytes().await?;
            let written = (|| -> std::io::Result<()> {
                use std::io::Write as _;
                use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
                let path = dir.join(name);
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            })();
            written.with_context(|| format!("writing {name}"))?;
        }
        Ok(download)
    }

    /// Whether the claim still holds: `false` when the server refuses the
    /// renewal for any client-side reason (fenced, withdrawn admission or
    /// placement), an error only when it could not answer.
    async fn renewable(&self, plan_id: &str, generation: u64) -> Result<bool> {
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/heartbeat",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&RuntimeHeartbeat {
                plan_id: plan_id.into(),
                generation,
            })
            .send()
            .await?;
        let status = response.status();
        if status.is_client_error() {
            eprintln!(
                "runtime agent switch report for plan {plan_id} refused ({status}); continuing"
            );
            return Ok(false);
        }
        let _: crate::storage::RuntimeClaim =
            decode_response(response, "renewing runtime claim").await?;
        Ok(true)
    }

    pub(crate) fn environment(&self) -> &str {
        &self.environment
    }

    /// The release package for `step`, or with `restore` its restore pin,
    /// for built-in mode (ADR 0048 §3). The inner `Err` is the server's
    /// refusal, worded for the step's receipt.
    pub(crate) async fn fetch_release(
        &self,
        plan_id: &str,
        generation: u64,
        step: &Step,
        restore: bool,
    ) -> Result<Result<crate::runtime_delivery::RuntimeRelease, String>> {
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/release",
                self.base_url, self.environment
            ))
            .timeout(Duration::from_secs(300))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&crate::runtime_delivery::RuntimeReleaseRequest {
                plan_id: plan_id.into(),
                generation,
                step_id: step.id.clone(),
                restore,
                removal: !restore
                    && step.action == crate::plan::Action::Remove
                    && step.host.is_none(),
            })
            .send()
            .await?;
        let status = response.status();
        if matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ) {
            return Ok(Err(
                "the server does not hand releases to a runtime in built-in mode; upgrade the server"
                    .into(),
            ));
        }
        if status == StatusCode::CONFLICT {
            bail!("runtime claim was fenced before step {}", step.id);
        }
        // Only a refusal of this step fails it. Credential, attestation and
        // availability errors leave the claim to be retried.
        if status == StatusCode::PRECONDITION_FAILED {
            let detail = response.text().await.unwrap_or_default();
            return Ok(Err(crate::software_executor::sanitize_diagnostic_text(
                &format!("the server refused the release: {detail}"),
            )));
        }
        decode_response(response, "fetching the release")
            .await
            .map(Ok)
    }

    pub(crate) async fn heartbeat(&self, plan_id: &str, generation: u64) -> Result<bool> {
        // A long plan outlives a certificate's renewal window: renew here too.
        if let Err(error) = self.renew_certificate_if_due().await {
            eprintln!("runner certificate renewal failed (retrying): {error:#}");
        }
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/heartbeat",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&RuntimeHeartbeat {
                plan_id: plan_id.into(),
                generation,
            })
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(false);
        }
        let _: crate::storage::RuntimeClaim =
            decode_response(response, "renewing runtime claim").await?;
        Ok(true)
    }

    async fn execute_step(
        &self,
        plan: &Plan,
        generation: u64,
        step: &Step,
        approvals: &[crate::plan_approval::ApprovalEnvelope],
    ) -> Result<RuntimeStepReceipt> {
        match &self.executor {
            StepExecutor::Program(program) => {
                self.execute_program_step(program, &plan.id, generation, step)
                    .await
            }
            StepExecutor::Builtin(config) => {
                crate::runtime_builtin::execute_step(
                    self, config, plan, generation, step, approvals,
                )
                .await
            }
        }
    }

    async fn execute_program_step(
        &self,
        program: &std::path::Path,
        plan_id: &str,
        generation: u64,
        step: &Step,
    ) -> Result<RuntimeStepReceipt> {
        // A sealed value is never handed to a command or program (ADR 0048
        // §4), nor is the identity issuer key (ADR 0046 §2).
        if !step.sealed.is_empty() || step.issuer.is_some() {
            return Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: format!(
                    "step {} writes sealed secrets; operator executor programs never receive them (run the runtime in built-in mode)",
                    step.id
                ),
                wraps: Vec::new(),
            });
        }
        let guard = std::env::current_exe().ok().and_then(|path| {
            path.parent()
                .map(|parent| parent.join("tenkai-runtime-guard"))
        });
        let Some(guard) = guard else {
            return Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "runtime guard could not be located".into(),
                wraps: Vec::new(),
            });
        };
        let mut command = Command::new(guard);
        command
            .arg("--executor")
            .arg(program)
            .arg("--action")
            .arg(step.action.to_string())
            .arg("--product")
            .arg(&step.product)
            .arg("--target-version")
            .arg(&step.to)
            .arg("--release-digest")
            .arg(&step.release_digest)
            .arg("--artifact-digest")
            .arg(&step.artifact_digest)
            .arg("--workdir")
            .arg(&step.workdir)
            .arg("--idempotency-key")
            .arg(format!("{}:{}", plan_id, step.id))
            .kill_on_drop(true)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.as_std_mut().process_group(0);
        let child = command.spawn();
        let status = match child {
            Ok(mut child) => {
                // Keeping this pipe open is the guard's parent-liveness fence.
                // The kernel closes it even when this runtime is killed.
                let _control_pipe = child.stdin.take();
                let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        status = child.wait() => break status,
                        _ = heartbeat.tick() => {
                            match self.heartbeat(plan_id, generation).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    terminate_process_group(&mut child).await;
                                    break Err(std::io::Error::other("runtime claim was fenced"));
                                }
                                Err(error) => {
                                    terminate_process_group(&mut child).await;
                                    return Err(error).context("runtime heartbeat outcome is ambiguous");
                                }
                            }
                        }
                    }
                }
            }
            Err(error) => Err(error),
        };
        match status {
            Ok(status) if status.success() => Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: true,
                detail: "executor completed successfully".into(),
                wraps: Vec::new(),
            }),
            Ok(_) => Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "executor returned a non-success status".into(),
                wraps: Vec::new(),
            }),
            Err(_) => Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "executor could not be started".into(),
                wraps: Vec::new(),
            }),
        }
    }

    async fn complete(&self, completion: RuntimeCompletion) -> Result<()> {
        let response = self
            .client()?
            .post(format!(
                "{}/v1/runtime/environments/{}/complete",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .json(&completion)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response.text().await.unwrap_or_default();
            bail!("reporting runtime completion returned {status}: {detail}");
        }
        Ok(())
    }
}

async fn terminate_process_group(child: &mut tokio::process::Child) {
    if let Some(process_id) = child.id() {
        // The executor is the process-group leader. A negative PID fences its
        // complete command tree before another runtime may claim the plan.
        unsafe {
            libc::kill(-(process_id as i32), libc::SIGKILL);
        }
    }
    let _ = child.wait().await;
}

/// An older replica refused an additive JSON field (`deny_unknown_fields`).
fn unknown_field_rejected(status: StatusCode, body: &str, field: &str) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
    ) && body.contains("unknown field")
        && body.contains(field)
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    operation: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        bail!("{operation} returned {status}: {detail}");
    }
    response
        .json()
        .await
        .with_context(|| format!("decoding response while {operation}"))
}

fn validate_plan(plan: &Plan, environment: &str) -> Result<()> {
    anyhow::ensure!(
        plan.environment == environment,
        "server returned work for a different environment"
    );
    anyhow::ensure!(
        plan.format_version == crate::plan::PLAN_FORMAT_VERSION,
        "server returned an unsupported plan format"
    );
    let digest = plan.executable_digest()?;
    let object = plan.to_object()?;
    anyhow::ensure!(
        object.properties.get("content_digest") == Some(&digest),
        "runtime plan failed immutable-content validation"
    );
    let mut step_ids = std::collections::HashSet::new();
    anyhow::ensure!(
        plan.steps.iter().all(|step| {
            // An identity issuer step names no release (ADR 0046 §2).
            !step.id.is_empty()
                && (step.issuer.is_some()
                    || (!step.release_digest.is_empty() && !step.artifact_digest.is_empty()))
                && step_ids.insert(step.id.as_str())
        }),
        "runtime plan contains malformed or duplicate steps"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_sealing_field_is_a_retryable_old_replica() {
        assert!(unknown_field_rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Failed to deserialize the JSON body into the target type: unknown field `sealing_public_key`, expected one of `token`, `csr`, `attestation`",
            "sealing_public_key",
        ));
        assert!(!unknown_field_rejected(
            StatusCode::BAD_REQUEST,
            "the sealing public key is not an uncompressed P-256 point",
            "sealing_public_key",
        ));
    }

    #[tokio::test]
    async fn the_credential_file_is_kept_owner_only_and_never_replaced() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "tenkai-runtime-credential-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("credential");
        let missing =
            enrolled_credential("http://127.0.0.1:9", "prod", || Ok(None), &file, None, None)
                .await
                .unwrap_err()
                .to_string();
        assert!(
            missing.contains("enrollment token is required"),
            "{missing}"
        );

        write_owner_only(&file, "tkr_first").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_owner_only(&file, "tkr_second").is_err());
        // A kept credential is used without contacting the server.
        let kept = enrolled_credential(
            "http://127.0.0.1:9",
            "prod",
            || anyhow::bail!("not read when a credential is kept"),
            &file,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(kept, "tkr_first");
        std::fs::write(&file, "not a credential").unwrap();
        assert!(
            enrolled_credential("http://127.0.0.1:9", "prod", || Ok(None), &file, None, None)
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn credentials_require_a_protected_transport() {
        let executor = PathBuf::from("/usr/bin/true");
        assert!(
            RuntimeClient::new("http://example.test", "prod", "secret", executor.clone()).is_err()
        );
        assert!(RuntimeClient::new("http://127.0.0.1:8080", "prod", "secret", executor).is_ok());
    }

    /// The runner key is generated once, owner-only, and only a CSR leaves
    /// the host; the stored certificate and key load as a client identity
    /// (#674).
    #[test]
    fn the_runner_key_stays_on_the_host_and_the_certificate_loads() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("tenkai-runner-cert-{}", uuid::Uuid::new_v4()));
        assert!(runner_identity(&dir).unwrap().is_none());
        let csr = runner_csr(&dir).unwrap();
        assert!(csr.contains("CERTIFICATE REQUEST") && !csr.contains("PRIVATE KEY"));
        let key = dir.join(crate::runner_key::RUNNER_KEY);
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let first = std::fs::read(&key).unwrap();
        runner_csr(&dir).unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), first, "the key was replaced");

        let (cert, ca_key) = crate::runner_ca::RunnerCa::generate("runner CA").unwrap();
        let ca = crate::runner_ca::RunnerCa::from_pem(&cert, &ca_key).unwrap();
        let issued = ca
            .issue(
                &csr,
                &crate::runner_ca::RunnerIdentity {
                    environment: "prod".into(),
                    runner_id: format!("sha256:{}", "cd".repeat(32)),
                },
                crate::now_millis() / 1_000,
            )
            .unwrap();
        write_owner_only(&dir.join(RUNNER_CERT), &issued).unwrap();
        let (_, not_after) = runner_identity(&dir).unwrap().unwrap();
        assert!(not_after > crate::now_millis() / 1_000);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Renewal sends evidence only after a 428 on that request (#675), in
    /// the schema the 428 names, or v1 when it names none (#849): an agent
    /// that attested to one server still renews against a server of an
    /// earlier release, with or without attestation.
    #[tokio::test]
    async fn an_agent_that_attested_renews_against_a_server_without_attestation() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (cert, ca_key) = crate::runner_ca::RunnerCa::generate("runner CA").unwrap();
        let ca = Arc::new(crate::runner_ca::RunnerCa::from_pem(&cert, &ca_key).unwrap());
        // True: the server requires attestation; false: an earlier release.
        let requires = Arc::new(AtomicBool::new(true));
        // The 428 body: this release's challenge, or an earlier one's.
        let challenge = Arc::new(std::sync::Mutex::new(
            serde_json::to_string(&crate::runner_attestation::AttestationChallenge::new(
                &crate::runner_attestation::AttestationRefusal::Missing,
            ))
            .unwrap(),
        ));
        let attested = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let app = {
            let (ca, requires, challenge, attested) = (
                ca.clone(),
                requires.clone(),
                challenge.clone(),
                attested.clone(),
            );
            axum::Router::new().route(
                "/v1/runtime/environments/prod/certificate",
                axum::routing::post(move |body: axum::body::Bytes| {
                    let (ca, requires, challenge, attested) =
                        (ca.clone(), requires.clone(), challenge.clone(), attested.clone());
                    async move {
                        use axum::http::StatusCode;
                        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        if !requires.load(Ordering::SeqCst)
                            && raw.get("sealing_public_key").is_some()
                        {
                            return (
                                StatusCode::UNPROCESSABLE_ENTITY,
                                "unknown field `sealing_public_key`".into(),
                            );
                        }
                        let schema = raw
                            .get("attestation")
                            .map(|attestation| attestation["schema"].as_str().unwrap().to_owned());
                        match (requires.load(Ordering::SeqCst), schema) {
                            (true, None) => {
                                let body = challenge.lock().unwrap().clone();
                                return (StatusCode::PRECONDITION_REQUIRED, body);
                            }
                            (false, Some(_)) => {
                                return (StatusCode::BAD_REQUEST, "unknown field `attestation`".into());
                            }
                            (true, Some(schema)) => attested.lock().unwrap().push(schema),
                            (false, None) => {}
                        }
                        let csr = raw["csr"].as_str().unwrap();
                        let certificate = ca
                            .issue(
                                csr,
                                &crate::runner_ca::RunnerIdentity {
                                    environment: "prod".into(),
                                    runner_id: format!("sha256:{}", "cd".repeat(32)),
                                },
                                crate::now_millis() / 1_000,
                            )
                            .unwrap();
                        let body = serde_json::json!({"certificate": certificate, "ca": ca.trust_bundle()});
                        (StatusCode::OK, body.to_string())
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let dir =
            std::env::temp_dir().join(format!("tenkai-attest-renew-{}", uuid::Uuid::new_v4()));
        let client = RuntimeClient::new(
            format!("http://{address}"),
            "prod",
            "tkc_bearer",
            PathBuf::from("/bin/true"),
        )
        .unwrap()
        .with_certificate_dir(dir.clone())
        .unwrap();
        client.renew_certificate_if_due().await.unwrap();
        // Rolled back to a server that requires attestation but names no
        // schemas, then to one without attestation: renew each time.
        *challenge.lock().unwrap() =
            r#"{"error":"runner attestation required: attestation_missing"}"#.into();
        *client.certified.write().unwrap() = None;
        client.renew_certificate_if_due().await.unwrap();
        requires.store(false, Ordering::SeqCst);
        *client.certified.write().unwrap() = None;
        client.renew_certificate_if_due().await.unwrap();
        assert_eq!(
            *attested.lock().unwrap(),
            [
                crate::runner_attestation::ATTESTATION_SCHEMA,
                crate::runner_attestation::LEGACY_ATTESTATION_SCHEMA
            ],
            "attested after each 428, in the schema it named"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

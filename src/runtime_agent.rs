//! Pull-only environment runtime for one configured Tenkai environment.

use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
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

/// The agent's own credential (#630): the one kept in `credential_file`, or,
/// on first start, the one the server issues for the enrollment token, written
/// there (owner-only) before it is used. `enrollment_token` is read only when
/// there is no credential yet, so a removed bootstrap secret does not block a
/// restart. The token is spent on the server when redeemed, so a crash
/// before the write needs a new token.
///
/// With `certificate_dir` (#674), enrollment also gets a runner certificate:
/// the agent generates its key there (owner-only), sends only a CSR, and
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
    let csr = certificate_dir.map(runner_csr).transpose()?;
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
    };
    let mut response = client.post(&url).json(&request).send().await?;
    if response.status() == reqwest::StatusCode::PRECONDITION_REQUIRED {
        let (Some(dir), Some(csr)) = (certificate_dir, &request.csr) else {
            bail!("the server requires runner attestation, which needs --certificate-dir");
        };
        request.attestation = Some(host_attestation(dir, environment, csr, preflight)?);
        response = client.post(&url).json(&request).send().await?;
    }
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        bail!("runtime enrollment refused: {status} {detail}");
    }
    let enrolled: crate::runtime_delivery::RuntimeEnrolled = response.json().await?;
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
    Ok(enrolled.credential)
}

/// File names in a runner certificate directory (#674).
const RUNNER_KEY: &str = "key.pem";
const RUNNER_CERT: &str = "cert.pem";
const RUNNER_CA: &str = "ca.pem";

/// A CSR over the agent's own key in `dir`, generating the key (kept
/// owner-only, never sent) when there is none yet.
fn runner_csr(dir: &std::path::Path) -> Result<String> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let key_path = dir.join(RUNNER_KEY);
    let key = match std::fs::read_to_string(&key_path) {
        Ok(pem) => rcgen::KeyPair::from_pem(&pem).context("reading the runner key")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = rcgen::KeyPair::generate()?;
            write_owner_only(&key_path, &key.serialize_pem())?;
            key
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", key_path.display())),
    };
    Ok(rcgen::CertificateParams::new(Vec::<String>::new())?
        .serialize_request(&key)?
        .pem()?)
}

/// Host evidence for `environment`, signed with the runner key in `dir`
/// for the key of `csr` (#675): the checks of the preflight config at
/// `preflight` (none without one) and the probed inventory facts.
fn host_attestation(
    dir: &std::path::Path,
    environment: &str,
    csr: &str,
    preflight: Option<&std::path::Path>,
) -> Result<crate::runner_attestation::RunnerAttestation> {
    let now = crate::now_millis();
    let checks = match preflight {
        Some(path) => crate::host_preflight::run_checks(
            &crate::host_preflight::PreflightConfig::load(path)?,
            now,
        ),
        None => Vec::new(),
    };
    let facts = inventory::facts_map(&inventory::probe_local_inventory()?);
    let key = std::fs::read_to_string(dir.join(RUNNER_KEY)).context("reading the runner key")?;
    crate::runner_attestation::sign(environment, checks, facts, &key, csr, now)
}

/// The agent's runner certificate, its issuing CA and key from `dir` as a
/// client identity with the certificate's expiry (unix seconds), when
/// enrollment issued one (#674).
pub fn runner_identity(dir: &std::path::Path) -> Result<Option<(reqwest::Identity, i64)>> {
    let read = |name: &str| std::fs::read(dir.join(name));
    match (read(RUNNER_CERT), read(RUNNER_KEY)) {
        (Ok(mut certificate), Ok(key)) => {
            let (_, pem) = x509_parser::pem::parse_x509_pem(&certificate)
                .map_err(|error| anyhow::anyhow!("reading the runner certificate: {error}"))?;
            let not_after = pem
                .parse_x509()
                .map_err(|error| anyhow::anyhow!("reading the runner certificate: {error}"))?
                .validity()
                .not_after
                .timestamp();
            // The issuing runner CA follows the leaf, so a server that
            // trusts only a root above an intermediate runner CA can build
            // the chain.
            if let Ok(ca) = read(RUNNER_CA) {
                certificate.extend_from_slice(b"\n");
                certificate.extend_from_slice(&ca);
            }
            certificate.extend_from_slice(b"\n");
            certificate.extend_from_slice(&key);
            let identity = reqwest::Identity::from_pem(&certificate)
                .context("loading the runner certificate")?;
            Ok(Some((identity, not_after)))
        }
        (Err(error), _) | (_, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        (Err(error), _) | (_, Err(error)) => {
            Err(error).with_context(|| format!("reading {}", dir.display()))
        }
    }
}

/// Replace `path` with `contents`, owner-only, in one rename: a reader sees
/// the old file or the new one, never a partial one.
fn replace_file(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.with_context(|| format!("writing {}", path.display()))?;
    crate::runtime_self_upgrade::sync_dir(path.parent().unwrap_or(std::path::Path::new(".")))
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

#[derive(Clone)]
pub struct RuntimeClient {
    base_url: String,
    environment: String,
    instance_id: String,
    token: String,
    executor: PathBuf,
    http: reqwest::Client,
    /// Where the runner certificate lives, when the agent has one (#674).
    certificate_dir: Option<PathBuf>,
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
    /// The host preflight config whose checks runner attestation carries.
    preflight: Option<PathBuf>,
}

impl RuntimeClient {
    pub fn new(
        base_url: impl Into<String>,
        environment: impl Into<String>,
        token: impl Into<String>,
        executor: PathBuf,
    ) -> Result<Self> {
        Self::new_with_options(base_url, environment, token, executor, true)
    }

    pub fn new_with_options(
        base_url: impl Into<String>,
        environment: impl Into<String>,
        token: impl Into<String>,
        executor: PathBuf,
        inventory_report: bool,
    ) -> Result<Self> {
        let base_url = protected_base_url(base_url.into())?;
        let environment = environment.into();
        let token = token.into();
        anyhow::ensure!(!environment.is_empty(), "runtime environment is required");
        anyhow::ensure!(!token.is_empty(), "runtime token is required");
        anyhow::ensure!(
            executor.is_absolute(),
            "runtime executor path must be absolute"
        );
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
            certified: Default::default(),
            home: None,
            restart: Default::default(),
            preflight: None,
        })
    }

    /// Run the checks of the preflight config at `path` for runner
    /// attestation (#675).
    pub fn with_preflight(mut self, path: PathBuf) -> Self {
        self.preflight = Some(path);
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
        let loaded = runner_identity(&dir)?;
        self.certificate_dir = Some(dir);
        if let Some((identity, not_after)) = loaded {
            self.install_identity(identity, not_after)?;
        }
        Ok(self)
    }

    fn install_identity(&self, identity: reqwest::Identity, not_after: i64) -> Result<()> {
        let client = crate::outbound_tls::client()?
            .timeout(Duration::from_secs(10))
            .identity(identity)
            .build()?;
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
        let csr = runner_csr(dir)?;
        let attest =
            |csr: &str| host_attestation(dir, &self.environment, csr, self.preflight.as_deref());
        let send = |attestation| {
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
                })
                .send()
        };
        // Evidence only when this server asks for it on this request (#675):
        // a server of an earlier release, during a rolling deploy or after a
        // rollback, refuses the unknown field.
        let mut response = send(None).await?;
        if response.status() == reqwest::StatusCode::PRECONDITION_REQUIRED {
            response = send(Some(attest(&csr)?)).await?;
        }
        let renewed: crate::runtime_delivery::RuntimeCertificate =
            decode_response(response, "renewing the runner certificate").await?;
        replace_file(&dir.join(RUNNER_CA), &renewed.ca)?;
        replace_file(&dir.join(RUNNER_CERT), &renewed.certificate)?;
        let (identity, not_after) =
            runner_identity(dir)?.context("the renewed runner certificate did not load")?;
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
        // Refresh admitted inventory facts before work pull (#136). Failures are
        // visible but non-fatal so temporary probe issues do not stop delivery.
        if let Err(error) = self.report_inventory().await {
            eprintln!("runtime inventory report failed (continuing): {error:#}");
        }
        if self.report_switch().await? {
            return Ok(true);
        }
        let work = self.pull().await?;
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
                self.execute_step(&plan.id, claim.generation, step).await?
            };
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
        let response = self
            .client()?
            .get(format!(
                "{}/v1/runtime/environments/{}/work",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
            .header("x-tenkai-runtime-version", env!("CARGO_PKG_VERSION"))
            .send()
            .await?;
        decode_response(response, "pulling runtime work").await
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

    async fn heartbeat(&self, plan_id: &str, generation: u64) -> Result<bool> {
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
        plan_id: &str,
        generation: u64,
        step: &Step,
    ) -> Result<RuntimeStepReceipt> {
        let guard = std::env::current_exe().ok().and_then(|path| {
            path.parent()
                .map(|parent| parent.join("tenkai-runtime-guard"))
        });
        let Some(guard) = guard else {
            return Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "runtime guard could not be located".into(),
            });
        };
        let mut command = Command::new(guard);
        command
            .arg("--executor")
            .arg(&self.executor)
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
            }),
            Ok(_) => Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "executor returned a non-success status".into(),
            }),
            Err(_) => Ok(RuntimeStepReceipt {
                step_id: step.id.clone(),
                succeeded: false,
                detail: "executor could not be started".into(),
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
            !step.id.is_empty()
                && !step.release_digest.is_empty()
                && !step.artifact_digest.is_empty()
                && step_ids.insert(step.id.as_str())
        }),
        "runtime plan contains malformed or duplicate steps"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let key = dir.join(RUNNER_KEY);
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

    /// Renewal sends evidence only after a 428 on that request (#675): an
    /// agent that attested to one server still renews against a server of
    /// an earlier release, which refuses the unknown `attestation` field.
    #[tokio::test]
    async fn an_agent_that_attested_renews_against_a_server_without_attestation() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let (cert, ca_key) = crate::runner_ca::RunnerCa::generate("runner CA").unwrap();
        let ca = Arc::new(crate::runner_ca::RunnerCa::from_pem(&cert, &ca_key).unwrap());
        // True: the server requires attestation; false: an earlier release.
        let requires = Arc::new(AtomicBool::new(true));
        let attested = Arc::new(AtomicUsize::new(0));
        let app = {
            let (ca, requires, attested) = (ca.clone(), requires.clone(), attested.clone());
            axum::Router::new().route(
                "/v1/runtime/environments/prod/certificate",
                axum::routing::post(move |body: axum::body::Bytes| {
                    let (ca, requires, attested) = (ca.clone(), requires.clone(), attested.clone());
                    async move {
                        use axum::http::StatusCode;
                        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let has = raw.get("attestation").is_some();
                        match (requires.load(Ordering::SeqCst), has) {
                            (true, false) => return (StatusCode::PRECONDITION_REQUIRED, String::new()),
                            (false, true) => {
                                return (StatusCode::BAD_REQUEST, "unknown field `attestation`".into());
                            }
                            (true, true) => {
                                attested.fetch_add(1, Ordering::SeqCst);
                            }
                            (false, false) => {}
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
        assert_eq!(attested.load(Ordering::SeqCst), 1, "attested after the 428");
        // Rolled back to a server without attestation: renew again.
        requires.store(false, Ordering::SeqCst);
        *client.certified.write().unwrap() = None;
        client.renew_certificate_if_due().await.unwrap();
        assert_eq!(attested.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}

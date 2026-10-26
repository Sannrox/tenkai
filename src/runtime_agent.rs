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
pub async fn enrolled_credential(
    base_url: &str,
    environment: &str,
    enrollment_token: impl FnOnce() -> Result<Option<String>>,
    credential_file: &std::path::Path,
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
    // No redirects: the token goes only to the protected URL checked above.
    let response = crate::outbound_tls::client()?
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!(
            "{base_url}/v1/runtime/environments/{environment}/enroll"
        ))
        .json(&crate::runtime_delivery::RuntimeEnrollRequest { token })
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!("runtime enrollment refused: {status}");
    }
    let enrolled: crate::runtime_delivery::RuntimeEnrolled = response.json().await?;
    write_owner_only(credential_file, &enrolled.credential)?;
    eprintln!(
        "enrolled runtime credential {} for {}",
        enrolled.credential_id, enrolled.environment
    );
    Ok(enrolled.credential)
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
    /// When true, probe local inventory and POST to the hub each poll (#136).
    inventory_report: bool,
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
        })
    }

    pub async fn run_once(&self) -> Result<bool> {
        // Refresh admitted inventory facts before work pull (#136). Failures are
        // visible but non-fatal so temporary probe issues do not stop delivery.
        if let Err(error) = self.report_inventory().await {
            eprintln!("runtime inventory report failed (continuing): {error:#}");
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
        for step in &plan.steps {
            if !self.heartbeat(&plan.id, claim.generation).await? {
                bail!("runtime claim was fenced before step {}", step.id);
            }
            let receipt = self.execute_step(&plan.id, claim.generation, step).await?;
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

    pub async fn run(&self, interval: Duration) -> Result<()> {
        anyhow::ensure!(
            !interval.is_zero(),
            "poll interval must be greater than zero"
        );
        let mut consecutive_failures = 0_u32;
        loop {
            let delay = match self.run_once().await {
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
            .http
            .get(format!(
                "{}/v1/runtime/environments/{}/work",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
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
            .http
            .post(format!(
                "{}/v1/runtime/environments/{}/inventory",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
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

    async fn heartbeat(&self, plan_id: &str, generation: u64) -> Result<bool> {
        let response = self
            .http
            .post(format!(
                "{}/v1/runtime/environments/{}/heartbeat",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
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
            .http
            .post(format!(
                "{}/v1/runtime/environments/{}/complete",
                self.base_url, self.environment
            ))
            .bearer_auth(&self.token)
            .header("x-tenkai-runtime-instance", &self.instance_id)
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
        let missing = enrolled_credential("http://127.0.0.1:9", "prod", || Ok(None), &file)
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
        )
        .await
        .unwrap();
        assert_eq!(kept, "tkr_first");
        std::fs::write(&file, "not a credential").unwrap();
        assert!(
            enrolled_credential("http://127.0.0.1:9", "prod", || Ok(None), &file)
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
}

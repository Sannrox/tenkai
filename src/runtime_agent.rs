//! Pull-only environment runtime for one configured Tenkai environment.

use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use reqwest::StatusCode;
use tokio::process::Command;

use crate::plan::{Plan, Step};
use crate::reconciler::{RuntimeCompletion, RuntimeStepReceipt};
use crate::server::{RuntimeHeartbeat, RuntimeWork};

#[derive(Clone)]
pub struct RuntimeClient {
    base_url: String,
    environment: String,
    instance_id: String,
    token: String,
    executor: PathBuf,
    http: reqwest::Client,
}

impl RuntimeClient {
    pub fn new(
        base_url: impl Into<String>,
        environment: impl Into<String>,
        token: impl Into<String>,
        executor: PathBuf,
    ) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
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
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
        })
    }

    pub async fn run_once(&self) -> Result<bool> {
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

    #[test]
    fn credentials_require_a_protected_transport() {
        let executor = PathBuf::from("/usr/bin/true");
        assert!(
            RuntimeClient::new("http://example.test", "prod", "secret", executor.clone()).is_err()
        );
        assert!(RuntimeClient::new("http://127.0.0.1:8080", "prod", "secret", executor).is_ok());
    }
}

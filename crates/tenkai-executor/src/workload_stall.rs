//! Why a workload is not Available, and whether waiting longer can help (#982).
//!
//! The in-process wait reads the workload's conditions and the pods of its
//! current revision, turns them into a bounded, credential-free cause, and
//! fails the step early only on signals that do not heal by themselves.
//! A normal rolling update produces none of them.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use serde_json::Value;

/// A crash-looping container fails the step once it has restarted this often.
pub(crate) const CRASH_LOOP_RESTARTS: i32 = 3;
/// An image pull that keeps failing this long fails the step. The kubelet
/// retries after 10 s, then 20 s, so this covers at least three pull attempts.
pub(crate) const IMAGE_PULL_GRACE: Duration = Duration::from_secs(45);
/// At most this many causes are reported per workload.
const MAX_CAUSES: usize = 3;
/// Each message taken from the cluster is cut to this many characters.
const MAX_MESSAGE_CHARS: usize = 240;

/// Live state the wait reads to explain a workload that is not Available.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkloadEvidence {
    /// The workload object as the API server returned it.
    pub workload: Value,
    /// Pods of the workload's current revision. Pods of an older revision are
    /// left out, so a crash loop that the rollout replaces does not fail it.
    pub pods: Vec<Pod>,
}

/// What the cluster says is holding a workload back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stall {
    /// Bounded, operator-facing explanation. Never contains env values.
    pub cause: String,
    /// Waiting longer cannot help: fail the step now.
    pub terminal: bool,
}

/// Classifies evidence across polls. It remembers when each image pull
/// failure was first seen, so a pull that keeps failing turns terminal.
#[derive(Debug, Default)]
pub(crate) struct StallClassifier {
    pull_failing_since: HashMap<String, Instant>,
}

struct Signal {
    text: String,
    terminal: bool,
}

impl StallClassifier {
    /// Returns `None` when the evidence names no cause, for example while
    /// new pods are still starting.
    pub(crate) fn classify(
        &mut self,
        kind: &str,
        name: &str,
        evidence: &WorkloadEvidence,
        now: Instant,
    ) -> Option<Stall> {
        let mut signals = workload_signals(kind, name, &evidence.workload);
        let mut pulling = Vec::new();
        for pod in &evidence.pods {
            signals.extend(self.pod_signals(pod, now, &mut pulling));
        }
        self.pull_failing_since
            .retain(|key, _| pulling.contains(key));
        if signals.is_empty() {
            return None;
        }
        // Terminal signals first so the cause names what failed the step.
        signals.sort_by_key(|signal| !signal.terminal);
        let terminal = signals[0].terminal;
        let cause = signals
            .into_iter()
            .take(MAX_CAUSES)
            .map(|signal| signal.text)
            .collect::<Vec<_>>()
            .join("; ");
        Some(Stall { cause, terminal })
    }

    fn pod_signals(&mut self, pod: &Pod, now: Instant, pulling: &mut Vec<String>) -> Vec<Signal> {
        let pod_name = pod.metadata.name.as_deref().unwrap_or("<unnamed>");
        let Some(status) = &pod.status else {
            return Vec::new();
        };
        let mut signals = Vec::new();
        for condition in status.conditions.iter().flatten() {
            if condition.type_ == "PodScheduled" && condition.status == "False" {
                signals.push(Signal {
                    text: format!(
                        "pod {pod_name} is pending: {}{}",
                        condition.reason.as_deref().unwrap_or("NotScheduled"),
                        message_suffix(condition.message.as_deref())
                    ),
                    terminal: false,
                });
            }
        }
        let containers = status
            .init_container_statuses
            .iter()
            .flatten()
            .chain(status.container_statuses.iter().flatten());
        for container in containers {
            if let Some(signal) = self.container_signal(pod_name, container, now, pulling) {
                signals.push(signal);
            }
        }
        signals
    }

    fn container_signal(
        &mut self,
        pod_name: &str,
        container: &ContainerStatus,
        now: Instant,
        pulling: &mut Vec<String>,
    ) -> Option<Signal> {
        let waiting = container.state.as_ref()?.waiting.as_ref()?;
        let reason = waiting.reason.as_deref()?;
        let subject = format!("pod {pod_name} container {}", container.name);
        match reason {
            "CrashLoopBackOff" => Some(Signal {
                text: format!(
                    "{subject} {reason} after {} restarts{}",
                    container.restart_count,
                    last_termination(container)
                ),
                terminal: container.restart_count >= CRASH_LOOP_RESTARTS,
            }),
            "ImagePullBackOff" | "ErrImagePull" | "InvalidImageName" => {
                let key = format!("{pod_name}/{}", container.name);
                let since = *self.pull_failing_since.entry(key.clone()).or_insert(now);
                pulling.push(key);
                let failing_for = now.saturating_duration_since(since);
                Some(Signal {
                    text: format!(
                        "{subject} {reason} for {}s{}",
                        failing_for.as_secs(),
                        message_suffix(waiting.message.as_deref())
                    ),
                    terminal: failing_for >= IMAGE_PULL_GRACE,
                })
            }
            "CreateContainerConfigError" | "CreateContainerError" | "RunContainerError" => {
                Some(Signal {
                    text: format!(
                        "{subject} {reason}{}",
                        message_suffix(waiting.message.as_deref())
                    ),
                    terminal: false,
                })
            }
            // ContainerCreating and PodInitializing are a normal start.
            _ => None,
        }
    }
}

/// Deployment conditions. A refusal by admission and an exceeded progress
/// deadline are terminal; Kubernetes itself will not retry them into success.
/// Conditions the controller has not yet reconciled against the applied
/// generation are stale and ignored.
fn workload_signals(kind: &str, name: &str, workload: &Value) -> Vec<Signal> {
    let generation = workload
        .pointer("/metadata/generation")
        .and_then(Value::as_i64);
    let observed = workload
        .pointer("/status/observedGeneration")
        .and_then(Value::as_i64);
    if generation.is_some_and(|generation| observed.is_none_or(|observed| observed < generation)) {
        return Vec::new();
    }
    let conditions = workload
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let mut signals = Vec::new();
    for condition in conditions {
        let text = |field: &str| condition.get(field).and_then(Value::as_str);
        let (Some(type_name), Some(status)) = (text("type"), text("status")) else {
            continue;
        };
        let reason = text("reason").unwrap_or_default();
        let message = text("message");
        let terminal = match (type_name, status, reason) {
            ("ReplicaFailure", "True", "FailedCreate") => is_admission_refusal(message),
            ("ReplicaFailure", "True", _) => false,
            ("Progressing", "False", "ProgressDeadlineExceeded") => true,
            _ => continue,
        };
        signals.push(Signal {
            text: format!(
                "{kind} {name} {type_name}={status} {reason}{}",
                message_suffix(message)
            ),
            terminal,
        });
    }
    signals
}

/// Admission refused the pod: a Pod Security level, a validating webhook,
/// or a LimitRange. An exceeded quota or a service account that is not there
/// yet can clear without a new release, so they keep waiting.
fn is_admission_refusal(message: Option<&str>) -> bool {
    let Some(message) = message else {
        return false;
    };
    let refused = message.contains("is forbidden") || message.contains("denied the request");
    refused
        && !message.contains("exceeded quota")
        && !message.contains("error looking up service account")
}

fn last_termination(container: &ContainerStatus) -> String {
    let Some(terminated) = container
        .last_state
        .as_ref()
        .and_then(|state| state.terminated.as_ref())
    else {
        return String::new();
    };
    format!(
        ", last exit code {}{}{}",
        terminated.exit_code,
        terminated
            .reason
            .as_deref()
            .map(|reason| format!(" ({reason})"))
            .unwrap_or_default(),
        message_suffix(terminated.message.as_deref())
    )
}

/// `": <message>"`, single line and cut to [`MAX_MESSAGE_CHARS`], or empty.
fn message_suffix(message: Option<&str>) -> String {
    let Some(message) = message.map(str::trim).filter(|message| !message.is_empty()) else {
        return String::new();
    };
    let mut line: String = message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .collect();
    if message.chars().count() > MAX_MESSAGE_CHARS {
        line.push('…');
    }
    format!(": {line}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn deployment(conditions: Value) -> Value {
        json!({
            "kind": "Deployment",
            "metadata": {"name": "web", "generation": 2},
            "status": {"observedGeneration": 2, "conditions": conditions},
        })
    }

    fn pod(name: &str, status: Value) -> Pod {
        serde_json::from_value(json!({"metadata": {"name": name}, "status": status})).unwrap()
    }

    fn waiting(reason: &str, message: &str, restarts: i32) -> Value {
        json!({
            "containerStatuses": [{
                "name": "app",
                "restartCount": restarts,
                "state": {"waiting": {"reason": reason, "message": message}},
                "lastState": {"terminated": {"exitCode": 1, "reason": "Error",
                    "message": "host not found in upstream \"api\""}},
            }]
        })
    }

    fn evidence(conditions: Value, pods: Vec<Pod>) -> WorkloadEvidence {
        WorkloadEvidence {
            workload: deployment(conditions),
            pods,
        }
    }

    fn progressing() -> Value {
        json!([
            {"type": "Progressing", "status": "True", "reason": "ReplicaSetUpdated"},
            {"type": "Available", "status": "False", "reason": "MinimumReplicasUnavailable"},
        ])
    }

    #[test]
    fn crash_loop_fails_at_the_restart_threshold_and_names_the_exit() {
        let mut classifier = StallClassifier::default();
        let now = Instant::now();
        let early = evidence(
            progressing(),
            vec![pod("web-1", waiting("CrashLoopBackOff", "back-off 10s", 1))],
        );
        let stall = classifier
            .classify("Deployment", "web", &early, now)
            .unwrap();
        assert!(!stall.terminal, "{stall:?}");

        let looping = evidence(
            progressing(),
            vec![pod(
                "web-1",
                waiting("CrashLoopBackOff", "back-off 40s", CRASH_LOOP_RESTARTS),
            )],
        );
        let stall = classifier
            .classify("Deployment", "web", &looping, now)
            .unwrap();
        assert!(stall.terminal, "{stall:?}");
        assert!(
            stall
                .cause
                .contains("pod web-1 container app CrashLoopBackOff after 3 restarts"),
            "{}",
            stall.cause
        );
        assert!(
            stall
                .cause
                .contains("last exit code 1 (Error): host not found in upstream"),
            "{}",
            stall.cause
        );
    }

    #[test]
    fn admission_refusal_fails_at_once_with_the_refusal_message() {
        let refused = json!([
            {"type": "Available", "status": "False", "reason": "MinimumReplicasUnavailable"},
            {"type": "ReplicaFailure", "status": "True", "reason": "FailedCreate",
             "message": "pods \"web-5d8f\" is forbidden: violates PodSecurity \"restricted:latest\": allowPrivilegeEscalation != false"},
        ]);
        let stall = StallClassifier::default()
            .classify(
                "Deployment",
                "web",
                &evidence(refused, Vec::new()),
                Instant::now(),
            )
            .unwrap();
        assert!(stall.terminal);
        assert!(
            stall.cause.starts_with(
                "Deployment web ReplicaFailure=True FailedCreate: pods \"web-5d8f\" is forbidden: violates PodSecurity"
            ),
            "{}",
            stall.cause
        );
    }

    #[test]
    fn quota_refusal_and_stale_conditions_keep_waiting() {
        let quota = json!([
            {"type": "ReplicaFailure", "status": "True", "reason": "FailedCreate",
             "message": "pods \"web-5d8f\" is forbidden: exceeded quota: compute"},
        ]);
        let stall = StallClassifier::default()
            .classify(
                "Deployment",
                "web",
                &evidence(quota, Vec::new()),
                Instant::now(),
            )
            .unwrap();
        assert!(!stall.terminal, "{stall:?}");

        let mut stale = deployment(json!([
            {"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"},
        ]));
        stale["status"]["observedGeneration"] = json!(1);
        let stall = StallClassifier::default().classify(
            "Deployment",
            "web",
            &WorkloadEvidence {
                workload: stale,
                pods: Vec::new(),
            },
            Instant::now(),
        );
        assert_eq!(stall, None);
    }

    #[test]
    fn image_pull_failure_turns_terminal_after_the_grace() {
        let mut classifier = StallClassifier::default();
        let started = Instant::now();
        let failing = evidence(
            progressing(),
            vec![pod(
                "web-1",
                waiting(
                    "ImagePullBackOff",
                    "Back-off pulling image \"registry.invalid/app:1\"",
                    0,
                ),
            )],
        );
        let first = classifier
            .classify("Deployment", "web", &failing, started)
            .unwrap();
        assert!(!first.terminal, "{first:?}");
        let later = classifier
            .classify("Deployment", "web", &failing, started + IMAGE_PULL_GRACE)
            .unwrap();
        assert!(later.terminal, "{later:?}");
        assert!(
            later.cause.contains(
                "pod web-1 container app ImagePullBackOff for 45s: Back-off pulling image"
            ),
            "{}",
            later.cause
        );
    }

    #[test]
    fn a_healthy_slow_rollout_names_no_cause() {
        let starting = evidence(
            progressing(),
            vec![
                pod("web-1", waiting("ContainerCreating", "", 0)),
                pod(
                    "web-2",
                    json!({"containerStatuses": [{"name": "app", "restartCount": 0,
                        "state": {"running": {}}}]}),
                ),
            ],
        );
        assert_eq!(
            StallClassifier::default().classify("Deployment", "web", &starting, Instant::now()),
            None
        );
    }

    #[test]
    fn pending_pods_and_config_errors_are_named_without_failing() {
        let pending = evidence(
            progressing(),
            vec![
                pod(
                    "web-1",
                    json!({"conditions": [{"type": "PodScheduled", "status": "False",
                        "reason": "Unschedulable",
                        "message": "0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims."}]}),
                ),
                pod(
                    "web-2",
                    waiting(
                        "CreateContainerConfigError",
                        "secret \"api-token\" not found",
                        0,
                    ),
                ),
            ],
        );
        let stall = StallClassifier::default()
            .classify("Deployment", "web", &pending, Instant::now())
            .unwrap();
        assert!(!stall.terminal);
        assert!(
            stall.cause.contains("pod web-1 is pending: Unschedulable: 0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims."),
            "{}",
            stall.cause
        );
        assert!(
            stall.cause.contains(
                "pod web-2 container app CreateContainerConfigError: secret \"api-token\" not found"
            ),
            "{}",
            stall.cause
        );
    }

    #[test]
    fn cause_is_bounded() {
        let long = "x".repeat(10_000);
        let pods = (0..20)
            .map(|index| {
                pod(
                    &format!("web-{index}"),
                    waiting("CreateContainerError", &long, 0),
                )
            })
            .collect();
        let stall = StallClassifier::default()
            .classify(
                "Deployment",
                "web",
                &evidence(progressing(), pods),
                Instant::now(),
            )
            .unwrap();
        assert!(stall.cause.chars().count() < 1_000, "{}", stall.cause.len());
    }
}

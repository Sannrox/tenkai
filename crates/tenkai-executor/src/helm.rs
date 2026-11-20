//! Helm CLI software-executor adapter (`helm upgrade --install` / `helm uninstall`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use tenkai::now_millis;

use crate::helm_secrets::{self, LiveSecrets};
use crate::temp_doc::TempDoc;
use tenkai::software_executor::{
    LiveWorkload, SoftwareApplyRequest, SoftwareDeployPhase, SoftwareExecutor,
    SoftwareObserveStatus, run_captured_command, validate_request,
};

/// Helm reference launcher (`helm upgrade --install` / `helm uninstall`).
///
/// Binary from `TENKAI_HELM_BIN` or `helm` on PATH. Namespace = environment
/// name (validated identifier). Chart path = product workdir.
#[derive(Debug, Clone)]
pub struct HelmSoftwareExecutor {
    pub helm_binary: PathBuf,
}

impl Default for HelmSoftwareExecutor {
    fn default() -> Self {
        let helm_binary = std::env::var_os("TENKAI_HELM_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("helm"));
        Self { helm_binary }
    }
}

impl HelmSoftwareExecutor {
    /// A `helm` command for `request`, pointed at its cluster configuration
    /// when the request names one. Every call uses this, so a request never
    /// reaches a different cluster than its other calls.
    fn helm(&self, request: &SoftwareApplyRequest) -> Command {
        let mut command = Command::new(&self.helm_binary);
        if let Some(path) = &request.cluster_config_path {
            command.arg("--kubeconfig").arg(path);
        }
        command
    }

    fn helm_upgrade(
        &self,
        request: &SoftwareApplyRequest,
        phase: SoftwareDeployPhase,
        label: &str,
        extra_sets: &[String],
    ) -> Result<()> {
        validate_request(request)?;
        if !request.workdir.is_dir() {
            bail!(
                "helm chart workdir does not exist: {}",
                request.workdir.display()
            );
        }
        // Sealed values and the workload certificate land first, so the
        // release can read them as it starts.
        let secrets = if request.opened_secrets.is_empty() && request.identity.is_none() {
            None
        } else {
            let cluster_config = request
                .cluster_config_path
                .as_deref()
                .context("writing sealed secrets needs a cluster configuration")?;
            let api = LiveSecrets::connect(cluster_config, request.target_namespace())?;
            let sets = helm_secrets::write(&api, request)?;
            helm_secrets::write_identity(&api, request)?;
            Some((api, sets))
        };
        let identity_sets = helm_secrets::identity_sets(request)?;
        let mut command = self.helm(request);
        command
            .arg("upgrade")
            .arg("--install")
            .arg(request.instance_name())
            .arg(&request.workdir)
            .arg("--namespace")
            .arg(request.target_namespace())
            .arg("--create-namespace")
            .arg("--wait")
            .arg("--timeout")
            .arg("5m");
        let _values_file = helm_values_file(request, &mut command)?;
        let _dependency_file = helm_dependency_file(request, &mut command)?;
        let secret_sets = secrets.iter().flat_map(|(_, sets)| sets);
        for set in extra_sets.iter().chain(secret_sets).chain(&identity_sets) {
            command.arg("--set").arg(set);
        }
        run_captured_command(
            &mut command,
            phase,
            label,
            &request.product,
            &request.environment,
            "helm",
            "set TENKAI_HELM_BIN or install helm",
        )?;
        // Older Secrets are an optional cleanup: the apply stands, and the
        // next one retries.
        if let Some((api, _)) = &secrets
            && let Err(error) = helm_secrets::prune(api, request)
        {
            eprintln!(
                "{}: leaving older sealed Secrets in place: {error:#}",
                request.instance_name()
            );
        }
        Ok(())
    }
}

impl SoftwareExecutor for HelmSoftwareExecutor {
    fn installed_identities(
        &self,
        target: &tenkai::software_executor::IdentityTarget<'_>,
    ) -> Result<Vec<(String, Result<tenkai::workload_identity::InstalledIdentity>)>> {
        // Without a cluster configuration this runtime applies no Helm
        // release, so it holds no certificate to renew.
        let Some(cluster_config) = target.cluster_config_path else {
            return Ok(Vec::new());
        };
        let api = LiveSecrets::connect_existing(cluster_config)?;
        helm_secrets::installed_identities(&api, &api, target.environment)
    }

    fn renew_identity(
        &self,
        target: &tenkai::software_executor::IdentityTarget<'_>,
        installed: &tenkai::workload_identity::InstalledIdentity,
        issued: &tenkai::workload_identity::IssuedIdentity,
    ) -> Result<()> {
        let cluster_config = target
            .cluster_config_path
            .context("renewing a workload certificate needs a cluster configuration")?;
        let api = LiveSecrets::connect_existing(cluster_config)?;
        helm_secrets::renew_identity_secret(&api, target.environment, installed, issued)?;
        helm_secrets::finish_restart(&api, &api, target.environment, &installed.instance)
    }

    fn resume_identity_restarts(
        &self,
        target: &tenkai::software_executor::IdentityTarget<'_>,
    ) -> Result<Vec<(String, Result<()>)>> {
        let Some(cluster_config) = target.cluster_config_path else {
            return Ok(Vec::new());
        };
        let api = LiveSecrets::connect_existing(cluster_config)?;
        helm_secrets::finish_restarts(&api, &api, target.environment)
    }

    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.helm_upgrade(
            request,
            SoftwareDeployPhase::Apply,
            "upgrade --install",
            &[],
        )
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let mut command = self.helm(request);
        command
            .arg("uninstall")
            .arg(request.instance_name())
            .arg("--namespace")
            .arg(request.target_namespace())
            .arg("--wait")
            // A removal retried after a crash finds the release gone.
            .arg("--ignore-not-found");
        run_captured_command(
            &mut command,
            SoftwareDeployPhase::Remove,
            "uninstall",
            &request.product,
            &request.environment,
            "helm",
            "set TENKAI_HELM_BIN or install helm",
        )?;
        // Helm does not own the sealed Secrets. When a runtime, their only
        // writer, removes a release (failed-apply cleanup, a rollback's
        // outgoing release), every Tenkai-owned Secret of the instance goes
        // with it, found by its labels without the opened values. Removals
        // anywhere else never touch the cluster's Secrets API.
        if request.remove_owned_secrets
            && let Some(cluster_config) = &request.cluster_config_path
        {
            let api = LiveSecrets::connect_existing(cluster_config)?;
            helm_secrets::remove_all(&api, request)?;
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let output = self
            .helm(request)
            .arg("status")
            .arg(request.instance_name())
            .arg("--namespace")
            .arg(request.target_namespace())
            .output()
            .with_context(|| format!("starting helm status via {}", self.helm_binary.display()))?;
        if !output.status.success() {
            // Only a definite "release: not found" is Absent. An unreachable
            // API server, expired credentials, or an RBAC denial says nothing
            // about the release, so convergence must not reinstall on it.
            return Ok(
                if String::from_utf8_lossy(&output.stderr).contains("release: not found") {
                    SoftwareObserveStatus::Absent
                } else {
                    SoftwareObserveStatus::Unknown
                },
            );
        }
        let values = self
            .helm(request)
            .arg("get")
            .arg("values")
            .arg(request.instance_name())
            .arg("--namespace")
            .arg(request.target_namespace())
            .arg("--all")
            .arg("-o")
            .arg("json")
            .output();
        let Ok(values) = values else {
            return Ok(SoftwareObserveStatus::Mismatched);
        };
        if !values.status.success() {
            return Ok(SoftwareObserveStatus::Mismatched);
        }
        if helm_values_mismatch(&String::from_utf8_lossy(&values.stdout), request) {
            Ok(SoftwareObserveStatus::Mismatched)
        } else {
            Ok(SoftwareObserveStatus::Present)
        }
    }

    fn stop(&self, request: &SoftwareApplyRequest) -> Result<()> {
        self.helm_upgrade(
            request,
            SoftwareDeployPhase::Stop,
            "upgrade --install --stop",
            &["replicaCount=0".into(), "replicas=0".into()],
        )
    }

    fn restart(&self, request: &SoftwareApplyRequest) -> Result<()> {
        let nonce = now_millis();
        self.helm_upgrade(
            request,
            SoftwareDeployPhase::Restart,
            "upgrade --install --restart",
            &[format!("tenkai.restartNonce={nonce}")],
        )
    }

    fn list_live_workloads(
        &self,
        environment: &str,
        cluster_config: Option<&std::path::Path>,
    ) -> Result<Vec<LiveWorkload>> {
        let Some(cluster_config) = cluster_config else {
            return Ok(Vec::new());
        };
        let mut command = Command::new(&self.helm_binary);
        command.arg("--kubeconfig").arg(cluster_config);
        let output = command
            .arg("list")
            .arg("-n")
            .arg(environment)
            .arg("-o")
            .arg("json")
            .output()
            .with_context(|| {
                format!(
                    "starting helm list via {} (set TENKAI_HELM_BIN or install helm)",
                    self.helm_binary.display()
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("helm list -n {environment} failed: {}", stderr.trim());
        }
        parse_helm_list_json(&String::from_utf8_lossy(&output.stdout))
    }

    fn manages_cluster_namespaces(&self) -> bool {
        true
    }

    fn apply_cluster_namespace(
        &self,
        request: &tenkai::cluster_namespace::ClusterNamespaceApplyRequest,
    ) -> Result<()> {
        crate::in_process_kubernetes::apply_cluster_namespace_objects(
            &crate::in_process_kubernetes::LiveKubeApi,
            request,
        )
    }
}

fn parse_helm_list_json(stdout: &str) -> Result<Vec<LiveWorkload>> {
    let raw = if stdout.trim().is_empty() {
        "[]"
    } else {
        stdout
    };
    let releases: Vec<HelmListRelease> =
        serde_json::from_str(raw).context("parsing helm list JSON")?;
    Ok(releases
        .into_iter()
        .filter(|release| !release.name.is_empty())
        .map(|release| LiveWorkload {
            kind: "helm".into(),
            name: release.name,
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct HelmListRelease {
    #[serde(default)]
    name: String,
}

/// Writes the Tenkai-managed values to a generated values file and passes it
/// with `-f`. Helm reads a values file as data, so no value can add structure
/// the way `--set` syntax (`,`, `=`, `[`, `\`) would. Tenkai metadata stays a
/// string; overlay values keep the scalar typing `--set` gave them.
fn helm_values_file(request: &SoftwareApplyRequest, command: &mut Command) -> Result<TempDoc> {
    let values = serde_json::json!({ "tenkai": tenkai_values(request)? });
    let doc = TempDoc::write("values.json", values.to_string().as_bytes())?;
    command.arg("-f").arg(doc.path());
    Ok(doc)
}

/// The `tenkai` values tree for `request`. A dotted overlay key nests, as it
/// did under `--set`; a key that collides with another key's path is refused.
fn tenkai_values(request: &SoftwareApplyRequest) -> Result<serde_json::Value> {
    use serde_json::{Map, Value};
    let mut config = Map::new();
    for (key, value) in &request.overlays {
        let (parents, leaf) = match key.rsplit_once('.') {
            Some((parents, leaf)) => (parents.split('.').collect(), leaf),
            None => (Vec::new(), key.as_str()),
        };
        let mut node = &mut config;
        for part in parents {
            let child = node
                .entry(part)
                .or_insert_with(|| Value::Object(Map::new()));
            node = child
                .as_object_mut()
                .with_context(|| format!("overlay {key} collides with another overlay key"))?;
        }
        if node
            .insert(leaf.to_owned(), overlay_scalar(value))
            .is_some()
        {
            bail!("overlay {key} collides with another overlay key");
        }
    }
    Ok(serde_json::json!({
        "version": request.version,
        "releaseId": request.release_id,
        "instance": request.instance_name(),
        "configDigest": request.config_digest,
        "config": config,
    }))
}

/// One overlay value typed as Helm `--set` types a scalar: `true` / `false`
/// and integers without a leading zero; everything else, `null` included,
/// stays a string.
fn overlay_scalar(value: &str) -> serde_json::Value {
    if value.eq_ignore_ascii_case("true") {
        return true.into();
    }
    if value.eq_ignore_ascii_case("false") {
        return false.into();
    }
    if (value == "0" || !value.starts_with('0'))
        && let Ok(number) = value.parse::<i64>()
    {
        return number.into();
    }
    value.into()
}

fn helm_dependency_file(
    request: &SoftwareApplyRequest,
    command: &mut Command,
) -> Result<Option<TempDoc>> {
    if request.dependency_document.is_empty() {
        return Ok(None);
    }
    let doc = TempDoc::write("dependencies.json", request.dependency_document.as_bytes())?;
    command.arg("--set-file").arg(format!(
        "{}={}",
        tenkai::dependency_document::HELM_VALUES_KEY,
        doc.path().display()
    ));
    Ok(Some(doc))
}

fn helm_values_mismatch(values_json: &str, request: &SoftwareApplyRequest) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(values_json) else {
        return true;
    };
    let tenkai = value.get("tenkai");
    let version = tenkai
        .and_then(|node| node.get("version"))
        .and_then(|v| v.as_str());
    if version != Some(request.version.as_str()) {
        return true;
    }
    let release_id = tenkai
        .and_then(|node| node.get("releaseId"))
        .and_then(|v| v.as_str());
    if release_id != Some(request.release_id.as_str()) {
        return true;
    }
    let digest = tenkai
        .and_then(|node| node.get("configDigest"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if digest != request.config_digest {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;
    use tenkai::software_executor::{SoftwareApplyRequest, request_from_parts};

    fn sample_request(root: &Path) -> SoftwareApplyRequest {
        std::fs::create_dir_all(root).unwrap();
        let mut request =
            request_from_parts("api", "1.0.0", "prod", root, "tenkai:release:api@1.0.0");
        request.overlays = BTreeMap::new();
        request
    }

    fn fake_helm_path(root: &Path) -> PathBuf {
        root.join(format!(
            "fake-helm-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    /// Install a fake `helm` at `path`. Staging is closed here; `install(1)`
    /// writes the executable in a child so this process never holds a write
    /// handle a concurrent fork could inherit (`execve` then fails with
    /// "Text file busy", #767).
    fn write_fake_helm(path: &Path, contents: &str) {
        use std::io::Write as _;
        let staging = path.with_extension("staging");
        {
            let mut file = std::fs::File::create(&staging).unwrap();
            file.write_all(contents.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let status = Command::new("install")
            .args(["-m", "755"])
            .arg(&staging)
            .arg(path)
            .status()
            .expect("running install for the fake helm fixture");
        assert!(
            status.success(),
            "installing fake helm at {} failed: {status}",
            path.display()
        );
        let _ = std::fs::remove_file(&staging);
    }

    #[test]
    fn helm_apply_captures_and_sanitizes_stderr() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-diag-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let script = fake_helm_path(&root);
        write_fake_helm(
            &script,
            "#!/bin/sh\necho 'helm failed; Authorization: Bearer super-secret-token' >&2\nexit 1\n",
        );
        let request = sample_request(&root);
        let executor = HelmSoftwareExecutor {
            helm_binary: script,
        };
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("phase=apply"), "{err}");
        assert!(err.contains("helm"), "{err}");
        assert!(!err.contains("super-secret-token"), "{err}");
        assert!(err.contains("[redacted]"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Regression for #1308: only a definite not-found is Absent.
    #[test]
    fn helm_observe_failure_is_absent_only_when_release_not_found() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-obs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let request = sample_request(&root.join("chart"));
        for (stderr, expected) in [
            (
                "Error: Kubernetes cluster unreachable: connection refused",
                SoftwareObserveStatus::Unknown,
            ),
            (
                "Error: secrets is forbidden: User cannot list resource",
                SoftwareObserveStatus::Unknown,
            ),
            ("Error: release: not found", SoftwareObserveStatus::Absent),
        ] {
            let script = fake_helm_path(&root);
            write_fake_helm(
                &script,
                &format!("#!/bin/sh\necho '{stderr}' >&2\nexit 1\n"),
            );
            let executor = HelmSoftwareExecutor {
                helm_binary: script,
            };
            assert_eq!(executor.observe(&request).unwrap(), expected, "{stderr}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn every_helm_call_targets_the_requested_cluster_config() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-kube-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let log = root.join("argv");
        let script = fake_helm_path(&root);
        write_fake_helm(
            &script,
            &format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
        );
        let mut request = sample_request(&root.join("chart"));
        request.cluster_config_path = Some(root.join("cluster.yaml"));
        let executor = HelmSoftwareExecutor {
            helm_binary: script,
        };
        executor.apply(&request).unwrap();
        executor.remove(&request).unwrap();
        let _ = executor.observe(&request).unwrap();
        let calls = std::fs::read_to_string(&log).unwrap();
        let expected = format!("--kubeconfig {}", root.join("cluster.yaml").display());
        assert_eq!(calls.lines().count(), 4, "{calls}");
        assert!(
            calls.lines().all(|call| call.starts_with(&expected)),
            "{calls}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn overlay_values_reach_only_their_own_config_key() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-vals-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let (argv, values) = (root.join("argv"), root.join("values.json"));
        let script = fake_helm_path(&root);
        write_fake_helm(
            &script,
            &format!(
                "#!/bin/sh\necho \"$@\" > {argv}\nwhile [ $# -gt 0 ]; do [ \"$1\" = -f ] && cp \"$2\" {values}; shift; done\n",
                argv = argv.display(),
                values = values.display()
            ),
        );
        let mut request = sample_request(&root.join("chart"));
        request.config_digest = "123".into();
        request.overlays = BTreeMap::from([
            ("motd".into(), r"x,image.repository=evil,a[0]=b\,c.d".into()),
            ("db.port".into(), "5432".into()),
            ("zone".into(), "007".into()),
            ("debug".into(), "false".into()),
        ]);
        let executor = HelmSoftwareExecutor {
            helm_binary: script,
        };
        executor.apply(&request).unwrap();
        let delivered: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&values).unwrap()).unwrap();
        assert_eq!(
            delivered,
            serde_json::json!({"tenkai": {
                "version": "1.0.0",
                "releaseId": "tenkai:release:api@1.0.0",
                "instance": "api",
                "configDigest": "123",
                "config": {
                    "motd": r"x,image.repository=evil,a[0]=b\,c.d",
                    "db": {"port": 5432},
                    "zone": "007",
                    "debug": false,
                },
            }})
        );
        let argv = std::fs::read_to_string(&argv).unwrap();
        assert!(!argv.contains("--set"), "{argv}");
        assert!(!helm_values_mismatch(&delivered.to_string(), &request));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn colliding_overlay_keys_are_refused() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-clash-{}", uuid::Uuid::new_v4()));
        let mut request = sample_request(&root);
        request.overlays =
            BTreeMap::from([("db".into(), "x".into()), ("db.port".into(), "1".into())]);
        let err = tenkai_values(&request).unwrap_err().to_string();
        assert!(err.contains("collides"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn helm_values_detect_version_and_digest_mismatch() {
        let root = std::env::temp_dir().join(format!("tenkai-helm-obs-{}", uuid::Uuid::new_v4()));
        let mut request = sample_request(&root);
        request.config_digest = "abc".into();
        assert!(!helm_values_mismatch(
            r#"{"tenkai":{"version":"1.0.0","releaseId":"tenkai:release:api@1.0.0","configDigest":"abc"}}"#,
            &request
        ));
        assert!(helm_values_mismatch(
            r#"{"tenkai":{"version":"9.9.9","releaseId":"tenkai:release:api@1.0.0"}}"#,
            &request
        ));
        assert!(helm_values_mismatch(
            r#"{"tenkai":{"version":"1.0.0","releaseId":"tenkai:release:api@1.0.0","configDigest":"other"}}"#,
            &request
        ));
        assert!(helm_values_mismatch(r#"{"tenkai":{}}"#, &request));
        assert!(helm_values_mismatch("not-json", &request));
        let mut empty_digest = request.clone();
        empty_digest.config_digest.clear();
        assert!(helm_values_mismatch(
            r#"{"tenkai":{"version":"1.0.0","releaseId":"tenkai:release:api@1.0.0","configDigest":"stale"}}"#,
            &empty_digest
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn helm_list_json_names_releases_and_treats_empty_as_none() {
        let listed =
            parse_helm_list_json(r#"[{"name":"api"},{"name":""},{"name":"web"}]"#).unwrap();
        assert_eq!(
            listed,
            [
                LiveWorkload {
                    kind: "helm".into(),
                    name: "api".into(),
                },
                LiveWorkload {
                    kind: "helm".into(),
                    name: "web".into(),
                },
            ]
        );
        assert!(parse_helm_list_json("").unwrap().is_empty());
        assert!(parse_helm_list_json("[]").unwrap().is_empty());
    }

    #[test]
    fn helm_list_without_cluster_config_does_not_spawn() {
        let executor = HelmSoftwareExecutor {
            helm_binary: PathBuf::from("/no/such/tenkai-helm-list"),
        };
        assert!(
            executor
                .list_live_workloads("local", None)
                .unwrap()
                .is_empty()
        );
    }
}

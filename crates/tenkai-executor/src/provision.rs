//! Terraform / OpenTofu CLI adapter for the provision executor (ADR 0052).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use tenkai::provision::{
    PreparedPlan, ProvisionCli, ProvisionSummary, is_leftover_lock, leftover_lock_detail,
    summary_from_plan_json,
};
use tenkai::software_executor::{
    SoftwareApplyRequest, SoftwareDeployPhase, SoftwareExecutor, SoftwareObserveStatus,
    format_software_phase_error, sanitize_diagnostic_text, validate_request,
};
use tenkai::spec_drift::{SPEC_DRIFT_CURRENT, SPEC_DRIFT_MODIFIED, SpecDriftObject, SpecDriftView};

/// CLI adapter selected with `TENKAI_SOFTWARE_EXECUTOR=provision`.
#[derive(Debug, Clone)]
pub struct ProvisionExecutor {
    pub cli: ProvisionCli,
    pub binary: PathBuf,
}

impl Default for ProvisionExecutor {
    fn default() -> Self {
        Self::detect()
    }
}

impl ProvisionExecutor {
    fn detect() -> Self {
        if let Some(path) = std::env::var_os("TENKAI_TOFU_BIN") {
            return Self {
                cli: ProvisionCli::Tofu,
                binary: PathBuf::from(path),
            };
        }
        if let Some(path) = std::env::var_os("TENKAI_TERRAFORM_BIN") {
            return Self {
                cli: ProvisionCli::Terraform,
                binary: PathBuf::from(path),
            };
        }
        if which("tofu") {
            return Self {
                cli: ProvisionCli::Tofu,
                binary: PathBuf::from("tofu"),
            };
        }
        Self {
            cli: ProvisionCli::Terraform,
            binary: PathBuf::from("terraform"),
        }
    }

    fn noun(&self) -> &'static str {
        self.cli.as_str()
    }

    fn install_hint(&self) -> &'static str {
        match self.cli {
            ProvisionCli::Terraform => "set TENKAI_TERRAFORM_BIN or install terraform",
            ProvisionCli::Tofu => "set TENKAI_TOFU_BIN or install tofu",
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.env_remove("TF_LOG");
        command
    }

    fn run(
        &self,
        request: &SoftwareApplyRequest,
        phase: SoftwareDeployPhase,
        hint: &str,
        args: &[&str],
        stdout: bool,
    ) -> Result<Output> {
        let mut command = self.command();
        command.current_dir(&request.workdir);
        command.args(args);
        command.stdin(Stdio::null());
        command.stdout(if stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stderr(Stdio::piped());
        let output = command.output().with_context(|| {
            format!(
                "starting {} ({hint}) via {} ({})",
                self.noun(),
                self.binary.display(),
                self.install_hint()
            )
        })?;
        if output.status.success() {
            return Ok(output);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_leftover_lock(&stderr) {
            bail!(leftover_lock_detail(&stderr));
        }
        let detail = sanitize_diagnostic_text(stderr.trim());
        bail!(format_software_phase_error(
            phase,
            &request.product,
            &request.version,
            &request.environment,
            &format!(
                "{} {hint} failed (status {}): {detail}",
                self.noun(),
                output.status
            ),
        ))
    }

    fn require_running(stop: &AtomicBool) -> Result<()> {
        if stop.load(Ordering::Relaxed) {
            bail!("provision CLI stopped because the apply lease was lost");
        }
        Ok(())
    }

    fn plan_file(request: &SoftwareApplyRequest) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "tenkai-provision-{}-{}-{nanos}.tfplan",
            std::process::id(),
            request.instance_name()
        ))
    }

    fn init(&self, request: &SoftwareApplyRequest, stop: &AtomicBool) -> Result<()> {
        Self::require_running(stop)?;
        tenkai::provision::admit_locking_backend(&request.workdir)?;
        self.run(
            request,
            SoftwareDeployPhase::Plan,
            "init",
            &["init", "-input=false", "-no-color"],
            false,
        )?;
        Ok(())
    }

    fn plan_to_file(
        &self,
        request: &SoftwareApplyRequest,
        destroy: bool,
        refresh_only: bool,
        stop: &AtomicBool,
    ) -> Result<(PathBuf, ProvisionSummary)> {
        self.init(request, stop)?;
        Self::require_running(stop)?;
        let out = Self::plan_file(request);
        let out_s = out.to_string_lossy().into_owned();
        let mut args = vec!["plan", "-input=false", "-no-color", "-out", out_s.as_str()];
        if destroy {
            args.push("-destroy");
        }
        if refresh_only {
            args.push("-refresh-only");
        }
        let result = self.run(request, SoftwareDeployPhase::Plan, "plan", &args, false);
        if let Err(error) = result {
            let _ = std::fs::remove_file(&out);
            return Err(error);
        }
        match self.show_summary(request, &out) {
            Ok(summary) => Ok((out, summary)),
            Err(error) => {
                let _ = std::fs::remove_file(&out);
                Err(error)
            }
        }
    }

    fn show_summary(
        &self,
        request: &SoftwareApplyRequest,
        plan: &Path,
    ) -> Result<ProvisionSummary> {
        let output = self.run(
            request,
            SoftwareDeployPhase::Plan,
            "show",
            &["show", "-json", &plan.to_string_lossy()],
            true,
        )?;
        summary_from_plan_json(&output.stdout)
    }

    fn version_string(&self) -> Result<String> {
        let mut command = self.command();
        command.args(["version", "-json"]);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let output = command.output().with_context(|| {
            format!(
                "starting {} (version) via {} ({})",
                self.noun(),
                self.binary.display(),
                self.install_hint()
            )
        })?;
        if !output.status.success() {
            let stderr = sanitize_diagnostic_text(&String::from_utf8_lossy(&output.stderr));
            bail!("{} version failed: {stderr}", self.noun());
        }
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("provision CLI version -json is not an object")?;
        value
            .get("terraform_version")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .context("provision CLI version -json has no terraform_version")
    }
}

fn which(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    path.split(':')
        .any(|dir| Path::new(dir).join(name).is_file())
}

impl SoftwareExecutor for ProvisionExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        bail!(
            "provision apply uses a saved plan; {}@{} in {} has no bound plan",
            request.product,
            request.version,
            request.environment
        )
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        bail!(
            "provision removal is a destroy saved plan; {}@{} in {} has no bound plan",
            request.product,
            request.version,
            request.environment
        )
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        Ok(SoftwareObserveStatus::Unknown)
    }

    fn observe_spec_drift(&self, request: &SoftwareApplyRequest) -> Result<SpecDriftView> {
        match self.observe_provision_drift(request) {
            Ok(summary) => Ok(drift_view(request, &summary)),
            Err(_) => Ok(SpecDriftView::unknown()),
        }
    }

    fn prepare_provision(
        &self,
        request: &SoftwareApplyRequest,
        destroy: bool,
        stop: &AtomicBool,
    ) -> Result<PreparedPlan> {
        validate_request(request)?;
        let (path, summary) = self.plan_to_file(request, destroy, false, stop)?;
        let plaintext = std::fs::read(&path).with_context(|| format!("reading {}", path.display()));
        let _ = std::fs::remove_file(&path);
        Ok(PreparedPlan {
            plaintext: zeroize::Zeroizing::new(plaintext?),
            summary,
        })
    }

    fn apply_provision(
        &self,
        request: &SoftwareApplyRequest,
        saved_plan: &[u8],
        stop: &AtomicBool,
    ) -> Result<()> {
        validate_request(request)?;
        Self::require_running(stop)?;
        tenkai::provision::admit_locking_backend(&request.workdir)?;
        self.init(request, stop)?;
        let path = Self::plan_file(request);
        std::fs::write(&path, saved_plan).with_context(|| format!("writing {}", path.display()))?;
        let result = self.run(
            request,
            SoftwareDeployPhase::Apply,
            "apply",
            &[
                "apply",
                "-input=false",
                "-no-color",
                &path.to_string_lossy(),
            ],
            false,
        );
        let _ = std::fs::remove_file(&path);
        result.map(|_| ())
    }

    fn observe_provision_drift(&self, request: &SoftwareApplyRequest) -> Result<ProvisionSummary> {
        validate_request(request)?;
        let stop = AtomicBool::new(false);
        let (path, summary) = self.plan_to_file(request, false, true, &stop)?;
        let _ = std::fs::remove_file(&path);
        Ok(summary)
    }

    fn provision_cli_version(&self) -> Result<(ProvisionCli, String)> {
        Ok((self.cli, self.version_string()?))
    }

    fn summarize_saved_plan(
        &self,
        request: &SoftwareApplyRequest,
        saved_plan: &[u8],
    ) -> Result<ProvisionSummary> {
        validate_request(request)?;
        let path = Self::plan_file(request);
        std::fs::write(&path, saved_plan).with_context(|| format!("writing {}", path.display()))?;
        let summary = self.show_summary(request, &path);
        let _ = std::fs::remove_file(&path);
        summary
    }
}

fn drift_view(request: &SoftwareApplyRequest, summary: &ProvisionSummary) -> SpecDriftView {
    let drifted = summary.resources.iter().any(|resource| {
        matches!(
            resource.action,
            tenkai::provision::ResourceAction::Create
                | tenkai::provision::ResourceAction::Update
                | tenkai::provision::ResourceAction::Replace
                | tenkai::provision::ResourceAction::Delete
        )
    });
    if drifted {
        SpecDriftView::from_objects(
            summary
                .resources
                .iter()
                .map(|resource| SpecDriftObject {
                    kind: "provision".into(),
                    name: resource.address.clone(),
                    status: SPEC_DRIFT_MODIFIED.into(),
                    fields: vec![resource.action.as_str().into()],
                })
                .collect(),
        )
    } else {
        SpecDriftView::from_objects(vec![SpecDriftObject {
            kind: "provision".into(),
            name: request.instance_name().into(),
            status: SPEC_DRIFT_CURRENT.into(),
            fields: Vec::new(),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tenkai::software_executor::request_from_parts;
    use uuid::Uuid;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-provision-cli-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_exe(path: &Path, body: &str) {
        let staging = path.with_extension("staging");
        {
            let mut file = std::fs::File::create(&staging).unwrap();
            file.write_all(body.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let status = Command::new("install")
            .args(["-m", "755"])
            .arg(&staging)
            .arg(path)
            .status()
            .expect("install fake provision CLI");
        assert!(status.success(), "install {status}");
        let _ = std::fs::remove_file(&staging);
    }

    fn request(root: &Path) -> SoftwareApplyRequest {
        std::fs::write(
            root.join("main.tf"),
            r#"
terraform {
  backend "s3" {
    bucket = "state"
    key    = "prod"
    region = "us-east-1"
    dynamodb_table = "locks"
  }
}
"#,
        )
        .unwrap();
        request_from_parts("infra", "1.0.0", "prod", root, "tenkai:release:infra@1.0.0")
    }

    fn fake_cli(root: &Path, script: &str) -> ProvisionExecutor {
        let path = root.join("fake-tofu");
        write_exe(&path, script);
        ProvisionExecutor {
            cli: ProvisionCli::Tofu,
            binary: path,
        }
    }

    const SHOW_JSON: &str = r#"{"format_version":"1.2","resource_changes":[{"address":"null_resource.demo","change":{"actions":["create"],"before":null,"after":{"id":"s3cret"}}}]}"#;

    fn happy_script() -> String {
        format!(
            r#"#!/bin/sh
cmd=$1
case "$cmd" in
  version) echo '{{"terraform_version":"1.8.0"}}' ;;
  init) ;;
  plan)
    out=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "-out" ]; then out=$2; shift; fi
      shift
    done
    echo planned > "$out"
    ;;
  show) echo '{SHOW_JSON}' ;;
  apply) ;;
  *) echo "unknown $cmd" >&2; exit 1 ;;
esac
"#
        )
    }

    #[test]
    fn prepare_renders_value_free_summary_and_apply_uses_saved_plan() {
        let root = tmp();
        let executor = fake_cli(&root, &happy_script());
        let request = request(&root);
        let stop = AtomicBool::new(false);
        let prepared = executor.prepare_provision(&request, false, &stop).unwrap();
        assert_eq!(prepared.summary.resources.len(), 1);
        let encoded = String::from_utf8(prepared.summary.canonical_json().unwrap()).unwrap();
        assert!(!encoded.contains("s3cret"), "{encoded}");
        executor
            .apply_provision(&request, &prepared.plaintext, &stop)
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn leftover_lock_is_reported_and_not_broken() {
        let root = tmp();
        let executor = fake_cli(
            &root,
            r#"#!/bin/sh
echo 'Error acquiring the state lock: Lock ID 123' >&2
exit 1
"#,
        );
        let request = request(&root);
        let err = executor
            .prepare_provision(&request, false, &AtomicBool::new(false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("never broken"), "{err}");
        assert!(!err.to_ascii_lowercase().contains("force-unlock"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn local_backend_is_refused_before_the_cli_runs() {
        let root = tmp();
        std::fs::write(
            root.join("main.tf"),
            "resource \"null_resource\" \"x\" {}\n",
        )
        .unwrap();
        let executor = fake_cli(&root, &happy_script());
        let request = request_from_parts(
            "infra",
            "1.0.0",
            "prod",
            &root,
            "tenkai:release:infra@1.0.0",
        );
        let err = executor
            .prepare_provision(&request, false, &AtomicBool::new(false))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("local state") || err.contains("remote state"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn version_is_read_from_json() {
        let root = tmp();
        let executor = fake_cli(&root, &happy_script());
        let (cli, version) = executor.provision_cli_version().unwrap();
        assert_eq!(cli, ProvisionCli::Tofu);
        assert_eq!(version, "1.8.0");
        let _ = std::fs::remove_dir_all(root);
    }
}

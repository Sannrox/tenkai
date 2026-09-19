use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub struct CliDrill {
    pub root: PathBuf,
    pub db: PathBuf,
    pub keys: PathBuf,
    pub state_dir: PathBuf,
    pub release_trust: PathBuf,
    pub approval_trust: PathBuf,
    pub approvals: PathBuf,
    token: &'static str,
    extra_env_remove: &'static [&'static str],
}

impl CliDrill {
    pub fn new(
        prefix: &str,
        token: &'static str,
        extra_env_remove: &'static [&'static str],
    ) -> Self {
        let root = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            tenkai::now_millis()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let keys = root.join("keys");
        let state_dir = root.join("state");
        let approvals = root.join("approvals");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&approvals).unwrap();
        Self {
            db: root.join("tenkai.db"),
            release_trust: root.join("release-trust.toml"),
            approval_trust: root.join("approval-trust.toml"),
            keys,
            state_dir,
            approvals,
            root,
            token,
            extra_env_remove,
        }
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(tenkaictl_bin());
        command
            .arg("--database")
            .arg(&self.db)
            .args(args)
            .env("TENKAI_MANAGEMENT_TOKEN", self.token)
            .env("TENKAI_STATE_DIR", &self.state_dir)
            .env("TENKAI_EXECUTOR_GUARD", executor_guard_bin())
            .env("TMPDIR", &self.root)
            .env_remove("TENKAI_PLAN_APPROVAL_DIR")
            .env_remove("TENKAI_PLAN_APPROVAL_TRUST_ROOTS")
            .env_remove("TENKAI_SOFTWARE_EXECUTOR")
            .env_remove("TENKAI_HELM_BIN")
            .env_remove("TENKAI_KUBECTL_BIN")
            .env_remove("TENKAI_RUNTIME_EXECUTOR")
            .env_remove("TENKAI_DELIVERY_ADAPTER");
        for key in self.extra_env_remove {
            command.env_remove(key);
        }
        command
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command(args)
            .output()
            .unwrap_or_else(|error| panic!("failed to launch tenkaictl {args:?}: {error}"))
    }

    pub fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "tenkaictl {args:?} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        stdout
    }

    pub fn fail(&self, args: &[&str]) -> String {
        let output = self.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let combined = format!("{stdout}{stderr}");
        assert!(
            !output.status.success(),
            "tenkaictl {args:?} unexpectedly succeeded\n{combined}"
        );
        combined
    }

    pub fn sign_release(&self, manifest: &Path, signature: &Path) {
        self.ok(&[
            "dev",
            "sign-release",
            manifest.to_str().unwrap(),
            "--keys",
            self.keys.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--trust-roots",
            self.release_trust.to_str().unwrap(),
        ]);
    }

    pub fn sign_plan(&self, plan_id: &str, approval: &Path) {
        self.ok(&[
            "dev",
            "sign-approval",
            plan_id,
            "--keys",
            self.keys.to_str().unwrap(),
            "--approval",
            approval.to_str().unwrap(),
            "--trust-roots",
            self.approval_trust.to_str().unwrap(),
        ]);
    }

    pub fn apply_signed(&self, plan_id: &str, approval: &Path) -> String {
        self.ok(&[
            "apply",
            plan_id,
            "--approval",
            approval.to_str().unwrap(),
            "--approval-trust-roots",
            self.approval_trust.to_str().unwrap(),
        ])
    }
}

impl Drop for CliDrill {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn plan_id_from(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("plan id: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("missing plan id in:\n{stdout}"))
        .to_string()
}

fn tenkaictl_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenkaictl"))
}

fn executor_guard_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenkai-executor-guard"))
}

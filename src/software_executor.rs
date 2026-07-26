//! Software product apply ports (Kubernetes via Helm or native manifests).
//!
//! **Helm (#95):** chart-oriented `helm upgrade --install` when
//! `TENKAI_SOFTWARE_EXECUTOR=helm`.
//!
//! **Native Kubernetes (#105):** plain multi-doc YAML under `manifests/` via
//! `kubectl` argv (not Helm). Chosen over an in-process kube client for this
//! issue to keep zero new crate dependencies and match the external-binary
//! pattern used for Helm; an in-process client remains a valid follow-on.
//!
//! Community defaults keep the existing shell `deploy.install` path when no
//! software executor env is set.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

// Path is used by run_kubectl.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// Request to apply or remove a software product generation on one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareApplyRequest {
    pub product: String,
    pub version: String,
    pub environment: String,
    pub workdir: PathBuf,
    /// Optional release digest for audit (never a secret).
    pub release_id: String,
}

/// Pluggable software apply path. Tenkai never hard-depends on a cluster.
pub trait SoftwareExecutor: Send + Sync {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()>;
    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()>;
    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareObserveStatus {
    Absent,
    Present,
    Unknown,
}

/// Deterministic fake for CI (no cluster, no helm binary).
#[derive(Debug, Default)]
pub struct FakeSoftwareExecutor {
    applied: Mutex<Vec<String>>,
    fail_apply: bool,
}

impl FakeSoftwareExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_fail_apply(mut self, fail: bool) -> Self {
        self.fail_apply = fail;
        self
    }

    pub fn applied_keys(&self) -> Vec<String> {
        self.applied.lock().expect("fake software mutex").clone()
    }
}

impl SoftwareExecutor for FakeSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        if self.fail_apply {
            bail!(
                "fake software executor refused apply for {}@{} in {}",
                request.product,
                request.version,
                request.environment
            );
        }
        let key = request_key(request);
        self.applied.lock().expect("fake software mutex").push(key);
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let key = request_key(request);
        let mut guard = self.applied.lock().expect("fake software mutex");
        guard.retain(|entry| entry != &key);
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let key = request_key(request);
        let guard = self.applied.lock().expect("fake software mutex");
        if guard.iter().any(|entry| entry == &key) {
            Ok(SoftwareObserveStatus::Present)
        } else {
            Ok(SoftwareObserveStatus::Absent)
        }
    }
}

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

impl SoftwareExecutor for HelmSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        if !request.workdir.is_dir() {
            bail!(
                "helm chart workdir does not exist: {}",
                request.workdir.display()
            );
        }
        let status = Command::new(&self.helm_binary)
            .arg("upgrade")
            .arg("--install")
            .arg(&request.product)
            .arg(&request.workdir)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--create-namespace")
            .arg("--wait")
            .arg("--timeout")
            .arg("5m")
            .arg("--set")
            .arg(format!("tenkai.version={}", request.version))
            .arg("--set")
            .arg(format!("tenkai.releaseId={}", request.release_id))
            .status()
            .with_context(|| {
                format!(
                    "starting helm via {} (set TENKAI_HELM_BIN or install helm)",
                    self.helm_binary.display()
                )
            })?;
        if !status.success() {
            bail!(
                "helm upgrade --install failed for {} in namespace {} (status {status})",
                request.product,
                request.environment
            );
        }
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let status = Command::new(&self.helm_binary)
            .arg("uninstall")
            .arg(&request.product)
            .arg("--namespace")
            .arg(&request.environment)
            .arg("--wait")
            .status()
            .with_context(|| {
                format!("starting helm uninstall via {}", self.helm_binary.display())
            })?;
        if !status.success() {
            // Not found may still be non-zero depending on helm version; surface error.
            bail!(
                "helm uninstall failed for {} in namespace {} (status {status})",
                request.product,
                request.environment
            );
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let output = Command::new(&self.helm_binary)
            .arg("status")
            .arg(&request.product)
            .arg("--namespace")
            .arg(&request.environment)
            .output()
            .with_context(|| format!("starting helm status via {}", self.helm_binary.display()))?;
        if output.status.success() {
            Ok(SoftwareObserveStatus::Present)
        } else {
            Ok(SoftwareObserveStatus::Absent)
        }
    }
}

/// Directory under the release workdir that holds native Kubernetes manifests.
pub const KUBERNETES_MANIFESTS_DIR: &str = "manifests";

/// Native Kubernetes apply via `kubectl` (plain manifests, not Helm charts).
///
/// Binary from `TENKAI_KUBECTL_BIN` or `kubectl` on PATH. Namespace = environment
/// name. Manifests live in `{workdir}/manifests/**/*.{yaml,yml}` (sorted).
#[derive(Debug, Clone)]
pub struct KubernetesSoftwareExecutor {
    pub kubectl_binary: PathBuf,
}

impl Default for KubernetesSoftwareExecutor {
    fn default() -> Self {
        let kubectl_binary = std::env::var_os("TENKAI_KUBECTL_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("kubectl"));
        Self { kubectl_binary }
    }
}

impl SoftwareExecutor for KubernetesSoftwareExecutor {
    fn apply(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            bail!(
                "native kubernetes apply requires at least one .yaml/.yml under {}",
                manifests.display()
            );
        }
        ensure_namespace(self, &request.environment)?;
        for path in &files {
            let path_s = path.to_string_lossy();
            run_kubectl(
                &self.kubectl_binary,
                &[
                    "apply",
                    "-f",
                    path_s.as_ref(),
                    "--namespace",
                    &request.environment,
                ],
                SoftwareDeployPhase::Apply,
                &format!("apply -f {}", path.display()),
                &request.product,
                &request.environment,
            )?;
        }
        // Ownership labels for Tenkai correlation (values sanitized for k8s).
        let label_args = ownership_label_args(request);
        let manifests_s = manifests.to_string_lossy();
        let mut args: Vec<&str> = vec![
            "label",
            "--overwrite",
            "-f",
            manifests_s.as_ref(),
            "--recursive",
            "--namespace",
            &request.environment,
        ];
        let owned: Vec<String> = label_args;
        for label in &owned {
            args.push(label.as_str());
        }
        run_kubectl(
            &self.kubectl_binary,
            &args,
            SoftwareDeployPhase::Apply,
            "label --overwrite",
            &request.product,
            &request.environment,
        )?;
        Ok(())
    }

    fn remove(&self, request: &SoftwareApplyRequest) -> Result<()> {
        validate_request(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            bail!(
                "native kubernetes remove requires manifests under {}",
                manifests.display()
            );
        }
        // Delete in reverse order for safer teardown of dependent resources.
        for path in files.iter().rev() {
            let path_s = path.to_string_lossy();
            run_kubectl(
                &self.kubectl_binary,
                &[
                    "delete",
                    "-f",
                    path_s.as_ref(),
                    "--namespace",
                    &request.environment,
                    "--ignore-not-found=true",
                    "--wait=true",
                ],
                SoftwareDeployPhase::Remove,
                &format!("delete -f {}", path.display()),
                &request.product,
                &request.environment,
            )?;
        }
        Ok(())
    }

    fn observe(&self, request: &SoftwareApplyRequest) -> Result<SoftwareObserveStatus> {
        validate_request(request)?;
        let manifests = kubernetes_manifests_dir(&request.workdir)?;
        let files = list_manifest_files(&manifests)?;
        if files.is_empty() {
            return Ok(SoftwareObserveStatus::Unknown);
        }
        // Present only if every manifest file still resolves in the namespace.
        for path in &files {
            let output = Command::new(&self.kubectl_binary)
                .arg("get")
                .arg("-f")
                .arg(path)
                .arg("--namespace")
                .arg(&request.environment)
                .output()
                .with_context(|| {
                    format!("starting kubectl get via {}", self.kubectl_binary.display())
                })?;
            if !output.status.success() {
                return Ok(SoftwareObserveStatus::Absent);
            }
        }
        Ok(SoftwareObserveStatus::Present)
    }
}

fn kubernetes_manifests_dir(workdir: &Path) -> Result<PathBuf> {
    let dir = workdir.join(KUBERNETES_MANIFESTS_DIR);
    if !dir.is_dir() {
        bail!(
            "native kubernetes workdir must contain a {KUBERNETES_MANIFESTS_DIR}/ directory at {}",
            dir.display()
        );
    }
    // Refuse path escape: manifests dir must stay under workdir.
    let workdir_canon = workdir
        .canonicalize()
        .with_context(|| format!("canonicalizing workdir {}", workdir.display()))?;
    let dir_canon = dir
        .canonicalize()
        .with_context(|| format!("canonicalizing manifests {}", dir.display()))?;
    if !dir_canon.starts_with(&workdir_canon) {
        bail!("manifests directory escapes workdir");
    }
    Ok(dir)
}

/// Sorted list of manifest files for deterministic apply order.
pub fn list_manifest_files(manifests_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_manifest_files(manifests_dir, manifests_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_manifest_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("listing kubernetes manifests {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", path.display()))?;
        if file_type.is_dir() {
            collect_manifest_files(root, &path, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            // Ensure file remains under root.
            let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            let path_canon = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !path_canon.starts_with(&root_canon) {
                bail!(
                    "manifest path escapes manifests directory: {}",
                    path.display()
                );
            }
            out.push(path);
        }
    }
    Ok(())
}

fn ensure_namespace(executor: &KubernetesSoftwareExecutor, namespace: &str) -> Result<()> {
    use std::process::Stdio;
    let get = Command::new(&executor.kubectl_binary)
        .arg("get")
        .arg("namespace")
        .arg(namespace)
        // Missing namespaces are expected on first apply; do not spam NotFound.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| {
            format!(
                "checking namespace via {}",
                executor.kubectl_binary.display()
            )
        })?;
    if get.success() {
        return Ok(());
    }
    run_kubectl(
        &executor.kubectl_binary,
        &["create", "namespace", namespace],
        SoftwareDeployPhase::Apply,
        "create namespace",
        "namespace",
        namespace,
    )
}

fn ownership_label_args(request: &SoftwareApplyRequest) -> Vec<String> {
    vec![
        format!("tenkai.product={}", k8s_label_value(&request.product)),
        format!("tenkai.version={}", k8s_label_value(&request.version)),
        format!("tenkai.release-id={}", k8s_label_value(&request.release_id)),
    ]
}

/// Kubernetes label values: alphanumeric, '-', '_', '.'; other chars → '-'.
pub fn k8s_label_value(raw: &str) -> String {
    let mapped: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".into()
    } else {
        // Label values max 63 chars.
        trimmed.chars().take(63).collect()
    }
}

/// Operator-facing software deploy phase for diagnostics (#150).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareDeployPhase {
    Apply,
    Health,
    Restore,
    /// Uninstall / kubectl delete path (not the same as restore).
    Remove,
}

impl SoftwareDeployPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Health => "health",
            Self::Restore => "restore",
            Self::Remove => "remove",
        }
    }
}

/// Format a credential-free, phase-aware software deploy error (#150).
pub fn format_software_phase_error(
    phase: SoftwareDeployPhase,
    product: &str,
    version: &str,
    environment: &str,
    detail: &str,
) -> String {
    let sanitized = sanitize_diagnostic_text(detail);
    format!(
        "software deploy phase={} product={}@{} environment/namespace={}: {sanitized}",
        phase.as_str(),
        product,
        version,
        environment
    )
}

/// Auto-rollback note: channel head is not rewritten by restore (#150).
pub fn rollback_channel_note(product: &str, restored_version: &str) -> String {
    format!(
        "restored {product} to {restored_version}; channel head is unchanged (status may show behind until re-promote)"
    )
}

fn char_slice_eq_ignore_ascii(hay: &[char], start: usize, needle: &str) -> bool {
    let n: Vec<char> = needle.chars().collect();
    if start + n.len() > hay.len() {
        return false;
    }
    hay[start..start + n.len()]
        .iter()
        .zip(n.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// True when a field/env name looks like a credential carrier (substring heuristics).
fn looks_like_credential_key(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    // Collapse camelCase / snake_case / kebab-case for fragment matching.
    let compact: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    const FRAGMENTS: &[&str] = &[
        "authorization",
        "clientsecret",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "idtoken",
        "privatekey",
        "privatekeydata",
        "secretaccesskey",
        "accesskeyid",
        "accesskey",
        "apikey",
        "authkey",
        "password",
        "passwd",
        "credential",
        "credentials",
        "kubeconfig",
        "dockerconfigjson",
        "serviceaccount",
        "bearer",
        "secret",
        "token",
    ];
    FRAGMENTS.iter().any(|frag| compact.contains(frag))
}

/// Read a bare or JSON-quoted identifier starting at `i`.
/// Returns `(key_without_quotes, index_after_key)`.
fn read_identifier_key(chars: &[char], i: usize) -> Option<(String, usize)> {
    if i >= chars.len() {
        return None;
    }
    if chars[i] == '"' {
        let mut j = i + 1;
        let mut key = String::new();
        while j < chars.len() && chars[j] != '"' && chars[j] != '\n' {
            key.push(chars[j]);
            j += 1;
        }
        if j < chars.len() && chars[j] == '"' && !key.is_empty() {
            return Some((key, j + 1));
        }
        return None;
    }
    if !chars[i].is_ascii_alphabetic() && chars[i] != '_' {
        return None;
    }
    // Bare key: left boundary must not continue an identifier.
    if i > 0 {
        let prev = chars[i - 1];
        if prev.is_ascii_alphanumeric() || prev == '_' || prev == '-' {
            return None;
        }
    }
    let mut j = i;
    let mut key = String::new();
    while j < chars.len() {
        let c = chars[j];
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            key.push(c);
            j += 1;
        } else {
            break;
        }
    }
    if key.is_empty() { None } else { Some((key, j)) }
}

#[derive(Clone, Copy)]
enum CredentialValueStyle {
    /// JSON / query: quoted string, or unquoted until delimiter.
    Structured,
    /// YAML / HTTP header bare `key: value` — consume the rest of the line.
    RestOfLine,
}

/// After a key match, skip optional whitespace + `:`/`=` and redact the value.
fn skip_credential_value(
    chars: &[char],
    after_key: usize,
    style: CredentialValueStyle,
) -> Option<usize> {
    let mut j = after_key;
    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }
    if j >= chars.len() {
        return None;
    }
    let sep = chars[j];
    if sep != ':' && sep != '=' {
        return None;
    }
    j += 1;
    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }
    if j >= chars.len() {
        return Some(j);
    }
    if chars[j] == '"' || chars[j] == '\'' {
        let quote = chars[j];
        j += 1;
        let mut closed = false;
        while j < chars.len() && chars[j] != '\n' {
            // Honor common escapes so `\"` does not end the value early.
            if chars[j] == '\\' && j + 1 < chars.len() && chars[j + 1] != '\n' {
                j += 2;
                continue;
            }
            if chars[j] == quote {
                j += 1;
                closed = true;
                break;
            }
            j += 1;
        }
        // Unclosed quoted value: conservatively redact through end of line.
        if !closed {
            while j < chars.len() && chars[j] != '\n' {
                j += 1;
            }
        }
        return Some(j);
    }
    if matches!(style, CredentialValueStyle::RestOfLine) && sep == ':' {
        while j < chars.len() && chars[j] != '\n' {
            j += 1;
        }
        return Some(j);
    }
    // Unquoted query / form values: stop at whitespace or structural delimiters.
    while j < chars.len() {
        let c = chars[j];
        if c.is_whitespace() || matches!(c, ',' | '}' | ']' | '&' | ';' | '\n') {
            break;
        }
        j += 1;
    }
    Some(j)
}

/// Strip credential-like substrings from diagnostic text.
pub fn sanitize_diagnostic_text(raw: &str) -> String {
    // Bound work before scanning (kubectl can emit large payloads).
    const MAX_IN: usize = 2_000;
    let bounded: String = raw.chars().take(MAX_IN).collect();
    let cleaned: String = bounded
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    let lower = cleaned.to_ascii_lowercase();
    // Collapse whitespace so formatted JSON/YAML still matches.
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    for structure in [
        "kind:secret",
        "\"kind\":\"secret\"",
        "begincertificate",
        "beginrsaprivate",
        "beginopensshprivate",
        "beginprivatekey",
        "\"stringdata\"",
        "stringdata:",
        // Structured Secret data maps (not bare "data:" which matches "metadata:")
        "\"data\":{",
        "\ndata:",
        ".dockerconfigjson",
    ] {
        if compact.contains(&structure.replace('\n', "")) || lower.contains(structure) {
            return "kubectl output omitted (looked like secret or certificate material); inspect the cluster with kubectl describe and avoid pasting secrets into Tenkai"
                .into();
        }
    }
    // YAML map start for secret data field at line begin.
    if lower.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("data:") || t.starts_with("stringdata:")
    }) {
        return "kubectl output omitted (looked like secret or certificate material); inspect the cluster with kubectl describe and avoid pasting secrets into Tenkai"
            .into();
    }
    let mut out = String::with_capacity(cleaned.len().min(512));
    let chars: Vec<char> = cleaned.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Bearer <token> (Authorization header form).
        if char_slice_eq_ignore_ascii(&chars, i, "bearer ") {
            out.push_str("[redacted]");
            i += "bearer ".len();
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        if let Some((key, after_key)) = read_identifier_key(&chars, i)
            && looks_like_credential_key(&key)
        {
            // Quoted JSON keys use structured value parsing; bare keys use rest-of-line for `:`.
            let style = if chars[i] == '"' {
                CredentialValueStyle::Structured
            } else {
                CredentialValueStyle::RestOfLine
            };
            if let Some(end) = skip_credential_value(&chars, after_key, style) {
                out.push_str("[redacted]");
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    const MAX_CHARS: usize = 400;
    let mut capped: String = out.chars().take(MAX_CHARS).collect();
    if out.chars().count() > MAX_CHARS {
        capped.push('…');
    }
    capped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn run_kubectl(
    binary: &Path,
    args: &[&str],
    phase: SoftwareDeployPhase,
    phase_hint: &str,
    product: &str,
    environment: &str,
) -> Result<()> {
    use std::process::Stdio;
    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "starting kubectl ({phase_hint}) via {} (set TENKAI_KUBECTL_BIN or install kubectl)",
                binary.display()
            )
        })?;
    let mut stderr_buf = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        const MAX_STDERR: u64 = 4_096;
        let mut limited = pipe.by_ref().take(MAX_STDERR);
        use std::io::Read as _;
        let _ = limited.read_to_end(&mut stderr_buf);
        // Drain any remaining bytes so the child can exit.
        let mut sink = [0_u8; 1024];
        while pipe.read(&mut sink).unwrap_or(0) > 0 {}
    }
    let status = child.wait().with_context(|| {
        format!(
            "waiting for kubectl ({phase_hint}) via {}",
            binary.display()
        )
    })?;
    if status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&stderr_buf);
    let detail = sanitize_diagnostic_text(stderr.trim());
    bail!(
        "software deploy phase={} product={product} environment/namespace={environment}: kubectl {phase_hint} failed (status {status}): {detail}",
        phase.as_str()
    );
}

/// Select software executor from `TENKAI_SOFTWARE_EXECUTOR`, else None
/// (caller keeps shell install).
pub fn selected_software_executor() -> Option<Box<dyn SoftwareExecutor>> {
    match std::env::var("TENKAI_SOFTWARE_EXECUTOR") {
        Ok(value) if value.eq_ignore_ascii_case("helm") => {
            Some(Box::new(HelmSoftwareExecutor::default()))
        }
        Ok(value)
            if value.eq_ignore_ascii_case("kubernetes")
                || value.eq_ignore_ascii_case("k8s")
                || value.eq_ignore_ascii_case("native") =>
        {
            Some(Box::new(KubernetesSoftwareExecutor::default()))
        }
        Ok(value) if value.eq_ignore_ascii_case("fake") => {
            Some(Box::new(FakeSoftwareExecutor::new()))
        }
        _ => None,
    }
}

fn request_key(request: &SoftwareApplyRequest) -> String {
    format!(
        "{}|{}|{}",
        request.environment, request.product, request.version
    )
}

fn validate_request(request: &SoftwareApplyRequest) -> Result<()> {
    for (label, value) in [
        ("product", request.product.as_str()),
        ("version", request.version.as_str()),
        ("environment", request.environment.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("software apply {label} must not be empty");
        }
        if value.contains('/') || value.contains('\\') || value.contains('\0') {
            bail!("software apply {label} must not contain path separators or NULs");
        }
    }
    Ok(())
}

/// Build a request from release content fields (library helper).
pub fn request_from_parts(
    product: impl Into<String>,
    version: impl Into<String>,
    environment: impl Into<String>,
    workdir: impl AsRef<Path>,
    release_id: impl Into<String>,
) -> SoftwareApplyRequest {
    SoftwareApplyRequest {
        product: product.into(),
        version: version.into(),
        environment: environment.into(),
        workdir: workdir.as_ref().to_path_buf(),
        release_id: release_id.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(root: &Path) -> SoftwareApplyRequest {
        std::fs::create_dir_all(root).unwrap();
        SoftwareApplyRequest {
            product: "api".into(),
            version: "1.0.0".into(),
            environment: "prod".into(),
            workdir: root.to_path_buf(),
            release_id: "tenkai:release:api@1.0.0".into(),
        }
    }

    #[test]
    fn fake_apply_remove_and_observe() {
        let root = std::env::temp_dir().join(format!("tenkai-soft-{}", uuid::Uuid::new_v4()));
        let request = sample_request(&root);
        let executor = FakeSoftwareExecutor::new();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Absent
        );
        executor.apply(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.remove(&request).unwrap();
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Absent
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fake_fail_apply_is_actionable() {
        let root = std::env::temp_dir().join(format!("tenkai-soft-fail-{}", uuid::Uuid::new_v4()));
        let request = sample_request(&root);
        let executor = FakeSoftwareExecutor::new().with_fail_apply(true);
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("refused apply"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_path_injection_in_product() {
        let root = std::env::temp_dir().join(format!("tenkai-soft-bad-{}", uuid::Uuid::new_v4()));
        let mut request = sample_request(&root);
        request.product = "../evil".into();
        assert!(FakeSoftwareExecutor::new().apply(&request).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn selected_executor_defaults_to_none() {
        // When operator env is unset, shell path remains default.
        if std::env::var_os("TENKAI_SOFTWARE_EXECUTOR").is_none() {
            assert!(selected_software_executor().is_none());
        }
    }

    #[test]
    fn lists_manifests_sorted_and_rejects_missing_dir() {
        let root = std::env::temp_dir().join(format!("tenkai-mf-{}", uuid::Uuid::new_v4()));
        let manifests = root.join(KUBERNETES_MANIFESTS_DIR);
        std::fs::create_dir_all(manifests.join("nested")).unwrap();
        std::fs::write(manifests.join("b-deploy.yaml"), "apiVersion: v1\n").unwrap();
        std::fs::write(manifests.join("a-ns.yaml"), "apiVersion: v1\n").unwrap();
        std::fs::write(manifests.join("nested").join("c.yaml"), "apiVersion: v1\n").unwrap();
        std::fs::write(manifests.join("readme.txt"), "skip").unwrap();
        let files = list_manifest_files(&manifests).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a-ns.yaml", "b-deploy.yaml", "c.yaml"]);
        assert!(kubernetes_manifests_dir(&root.join("nope")).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn k8s_label_value_sanitizes_release_ids() {
        assert_eq!(
            k8s_label_value("tenkai:release:api@1.0.0"),
            "tenkai-release-api-1.0.0"
        );
        assert_eq!(k8s_label_value("---"), "unknown");
    }

    #[test]
    fn kubernetes_apply_requires_manifests_directory() {
        let root = std::env::temp_dir().join(format!("tenkai-k8s-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let request = sample_request(&root);
        let executor = KubernetesSoftwareExecutor {
            kubectl_binary: PathBuf::from("kubectl-not-used-before-manifest-check"),
        };
        let err = executor.apply(&request).unwrap_err().to_string();
        assert!(err.contains("manifests"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn phase_error_names_health_and_product_without_secrets() {
        let err = format_software_phase_error(
            SoftwareDeployPhase::Health,
            "hello-minikube",
            "0.2.0",
            "local",
            "error: rollout timed out; Bearer super-secret-token-value",
        );
        assert!(err.contains("phase=health"), "{err}");
        assert!(err.contains("hello-minikube@0.2.0"), "{err}");
        assert!(err.contains("environment/namespace=local"), "{err}");
        assert!(!err.contains("super-secret-token-value"), "{err}");
        assert!(err.contains("[redacted]"), "{err}");
        let long = format_software_phase_error(
            SoftwareDeployPhase::Apply,
            "api",
            "1.0.0",
            "stage",
            "token=abcdefghijklmnopqrstuvwxyz0123456789extra",
        );
        assert!(!long.contains("abcdefghij"), "{long}");
        assert!(long.contains("[redacted]"), "{long}");
        let json_secret = sanitize_diagnostic_text(
            r#"Error from server: {"kind": "Secret", "data": {"api-key": "supersecret"}}"#,
        );
        assert!(
            json_secret.contains("omitted") || json_secret.contains("secret"),
            "{json_secret}"
        );
        assert!(!json_secret.contains("supersecret"), "{json_secret}");
        let auth = sanitize_diagnostic_text("Authorization: Bearer super-secret-token\nnext");
        assert!(!auth.contains("super-secret-token"), "{auth}");
        assert!(auth.contains("[redacted]"), "{auth}");
        // JSON, query-string, env-style, and camelCase credential carriers (#150 / autoreview).
        for sample in [
            r#"error: {"token":"json-secret-value"}"#,
            r#"error: {"token": "json-secret-value"}"#,
            "client_secret=query-secret-value",
            "access_token=query-secret-value",
            "api_key=query-secret-value",
            "api-key: query-secret-value",
            r#"{"access_token":"json-secret-value","ok":true}"#,
            "AWS_SECRET_ACCESS_KEY=query-secret-value",
            "clientSecret=query-secret-value",
            "private-key-data=query-secret-value",
            "credentials=query-secret-value",
            r#"{"clientSecret":"json-secret-value"}"#,
        ] {
            let cleaned = sanitize_diagnostic_text(sample);
            assert!(
                !cleaned.contains("json-secret-value") && !cleaned.contains("query-secret-value"),
                "leaked secret in {sample:?} -> {cleaned}"
            );
            assert!(cleaned.contains("[redacted]"), "{sample:?} -> {cleaned}");
        }
        // Non-credential assignment must survive (operator-useful kubectl text).
        let safe = sanitize_diagnostic_text(
            "error: deployment.apps \"hello\" not found in namespace=local",
        );
        assert!(safe.contains("not found"), "{safe}");
        assert!(
            safe.contains("namespace=local") || safe.contains("namespace"),
            "{safe}"
        );
        // Escaped quotes inside a credential value must not leak the tail.
        let escaped = sanitize_diagnostic_text(r#"{"token":"prefix\"remaining-secret"}"#);
        assert!(!escaped.contains("remaining-secret"), "{escaped}");
        assert!(escaped.contains("[redacted]"), "{escaped}");
    }

    #[test]
    fn rollback_note_mentions_channel_unchanged() {
        let note = rollback_channel_note("api", "1.0.0");
        assert!(note.contains("restored api to 1.0.0"), "{note}");
        assert!(note.contains("channel head is unchanged"), "{note}");
    }

    /// Optional live-cluster path. Not run in default CI.
    #[test]
    #[ignore = "requires kubectl + cluster; set TENKAI_KUBECTL_BIN and run with --ignored"]
    fn kubernetes_operator_kind_path_smoke() {
        let binary = std::env::var("TENKAI_KUBECTL_BIN").unwrap_or_else(|_| "kubectl".into());
        let root = std::env::temp_dir().join(format!("tenkai-k8s-live-{}", uuid::Uuid::new_v4()));
        let manifests = root.join(KUBERNETES_MANIFESTS_DIR);
        std::fs::create_dir_all(&manifests).unwrap();
        // Minimal ConfigMap — safe for a disposable namespace.
        std::fs::write(
            manifests.join("configmap.yaml"),
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: tenkai-smoke
data:
  ok: "1"
"#,
        )
        .unwrap();
        let request = SoftwareApplyRequest {
            product: "smoke".into(),
            version: "0.0.1".into(),
            environment: format!("tenkai-smoke-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            workdir: root.clone(),
            release_id: "tenkai:release:smoke@0.0.1".into(),
        };
        let executor = KubernetesSoftwareExecutor {
            kubectl_binary: PathBuf::from(binary),
        };
        executor.apply(&request).expect("apply");
        assert_eq!(
            executor.observe(&request).unwrap(),
            SoftwareObserveStatus::Present
        );
        executor.remove(&request).expect("remove");
        let _ = std::fs::remove_dir_all(root);
    }
}

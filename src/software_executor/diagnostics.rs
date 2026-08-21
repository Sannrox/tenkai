//! Credential-free software-deploy diagnostics shared by Helm and kubectl.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

/// Operator-facing software deploy phase for diagnostics (#150).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareDeployPhase {
    Apply,
    Health,
    Restore,
    /// Uninstall / kubectl delete path (not the same as restore).
    Remove,
    Restart,
}

impl SoftwareDeployPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Health => "health",
            Self::Restore => "restore",
            Self::Remove => "remove",
            Self::Restart => "restart",
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

/// Run an external software-deploy binary, capturing and sanitizing stderr.
pub(super) fn run_captured_command(
    command: &mut Command,
    phase: SoftwareDeployPhase,
    phase_hint: &str,
    product: &str,
    environment: &str,
    tool: &str,
    install_hint: &str,
) -> Result<()> {
    let program = Path::new(command.get_program()).display().to_string();
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!("starting {tool} ({phase_hint}) via {program} ({install_hint})")
        })?;
    let mut stderr_buf = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        const MAX_STDERR: u64 = 4_096;
        let mut limited = pipe.by_ref().take(MAX_STDERR);
        let _ = limited.read_to_end(&mut stderr_buf);
        // Drain any remaining bytes so the child can exit.
        let mut sink = [0_u8; 1024];
        while pipe.read(&mut sink).unwrap_or(0) > 0 {}
    }
    let status = child
        .wait()
        .with_context(|| format!("waiting for {tool} ({phase_hint}) via {program}"))?;
    if status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&stderr_buf);
    let detail = sanitize_diagnostic_text(stderr.trim());
    bail!(
        "software deploy phase={} product={product} environment/namespace={environment}: {tool} {phase_hint} failed (status {status}): {detail}",
        phase.as_str()
    );
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
        "clientcertificatedata",
        "clientkeydata",
        "certificateauthoritydata",
        "clientkey",
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
        "databaseurl",
        "postgresurl",
        "mysqlurl",
        "redisurl",
    ];
    if FRAGMENTS.iter().any(|frag| compact.contains(frag)) {
        return true;
    }
    // TENKAI_*URL (postgresurl / databaseurl fragments cover *POSTGRES_URL / *DATABASE_URL).
    compact.starts_with("tenkai") && compact.ends_with("url")
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

const OMITTED_SENSITIVE_OUTPUT: &str = "kubectl output omitted (looked like secret or certificate material); inspect the cluster with kubectl describe and avoid pasting secrets into Tenkai";

/// YAML/JSON kubeconfig `users:` / `user:` blocks are fail-closed: omit entirely.
fn looks_like_kubeconfig_user_block(lower: &str, compact: &str) -> bool {
    if compact.contains("\"users\":") || compact.contains("\"user\":{") {
        return true;
    }
    lower.lines().any(|line| {
        let t = line.trim_start();
        yaml_mapping_key(t, "users") || yaml_mapping_key(t, "user")
    })
}

fn yaml_mapping_key(trimmed_line: &str, key: &str) -> bool {
    let Some(rest) = trimmed_line.strip_prefix(key) else {
        return false;
    };
    rest.is_empty() || rest.starts_with(':')
}

/// True when `chars[..key_start]` ends with `namespace=` (phase-error wrapper).
fn preceded_by_namespace_equals(chars: &[char], key_start: usize) -> bool {
    const NEEDLE: &[char] = &['n', 'a', 'm', 'e', 's', 'p', 'a', 'c', 'e', '='];
    if key_start < NEEDLE.len() {
        return false;
    }
    let start = key_start - NEEDLE.len();
    chars[start..key_start]
        .iter()
        .zip(NEEDLE.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// If `chars[i..]` is `scheme://userinfo@host`, return the index of `@`.
fn uri_userinfo_at(chars: &[char], i: usize) -> Option<usize> {
    if i > 0 {
        let prev = chars[i - 1];
        if prev.is_ascii_alphanumeric() || prev == '_' || prev == '-' || prev == '.' {
            return None;
        }
    }
    if i >= chars.len() || !chars[i].is_ascii_alphabetic() {
        return None;
    }
    let mut j = i + 1;
    while j < chars.len()
        && (chars[j].is_ascii_alphanumeric() || matches!(chars[j], '+' | '-' | '.'))
    {
        j += 1;
    }
    if j + 2 >= chars.len() || chars[j] != ':' || chars[j + 1] != '/' || chars[j + 2] != '/' {
        return None;
    }
    let authority = j + 3;
    let mut k = authority;
    let mut at = None;
    while k < chars.len() {
        let c = chars[k];
        if c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ')') {
            break;
        }
        if c == '@' {
            at = Some(k);
            break;
        }
        k += 1;
    }
    let at = at?;
    if at == authority {
        return None;
    }
    Some(at)
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
    if looks_like_kubeconfig_user_block(&lower, &compact) {
        return OMITTED_SENSITIVE_OUTPUT.into();
    }
    for structure in [
        "kind:secret",
        "\"kind\":\"secret\"",
        "begincertificate",
        "beginrsaprivate",
        "beginopensshprivate",
        "beginprivatekey",
        "beginecprivatekey",
        "beginencryptedprivatekey",
        "begindsaprivatekey",
        "\"stringdata\"",
        "stringdata:",
        // Structured Secret data maps (not bare "data:" / "*-data:" keys).
        "\"data\":{",
        ".dockerconfigjson",
    ] {
        if compact.contains(&structure.replace('\n', "")) || lower.contains(structure) {
            return OMITTED_SENSITIVE_OUTPUT.into();
        }
    }
    // YAML map start for secret data field at line begin.
    if lower.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("data:") || t.starts_with("stringdata:")
    }) {
        return OMITTED_SENSITIVE_OUTPUT.into();
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
            // `system:serviceaccount:...` is a Kubernetes username, not a YAML assignment.
            // Rest-of-line redaction here drops the required Forbidden reason.
            if matches!(style, CredentialValueStyle::RestOfLine) && i > 0 && chars[i - 1] == ':' {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            // Re-sanitizing `run_captured_command` output sees
            // `environment/namespace=<id>:` and would eat the failure text.
            if matches!(style, CredentialValueStyle::RestOfLine)
                && preceded_by_namespace_equals(&chars, i)
            {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            if let Some(end) = skip_credential_value(&chars, after_key, style) {
                out.push_str("[redacted]");
                i = end;
                continue;
            }
        }

        if let Some(at) = uri_userinfo_at(&chars, i) {
            while i + 2 < chars.len() && !(chars[i] == '/' && chars[i + 1] == '/') {
                out.push(chars[i]);
                i += 1;
            }
            out.push_str("//[redacted]");
            i = at;
            continue;
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

#[cfg(test)]
mod tests {
    use super::{SoftwareDeployPhase, format_software_phase_error, sanitize_diagnostic_text};

    fn assert_no_leak(sample: &str, leaked: &[&str]) -> String {
        let cleaned = sanitize_diagnostic_text(sample);
        for secret in leaked {
            assert!(
                !cleaned.contains(secret),
                "leaked {secret:?} in {sample:?} -> {cleaned}"
            );
        }
        cleaned
    }

    #[test]
    fn redacts_uri_userinfo_and_database_url_keys() {
        let url = assert_no_leak(
            "helm failed: postgres://app:s3cret@db.internal/tenkai",
            &["s3cret", "app:s3cret"],
        );
        assert!(url.contains("[redacted]"), "{url}");
        assert!(url.contains("postgres://"), "{url}");
        assert!(url.contains("db.internal"), "{url}");

        let env = assert_no_leak(
            "TENKAI_POSTGRES_URL=postgres://app:s3cret@db.internal/tenkai",
            &["s3cret", "app:s3cret", "postgres://app"],
        );
        assert!(env.contains("[redacted]"), "{env}");

        for sample in [
            "mysql://root:s3cret@127.0.0.1:3306/app",
            "redis://default:s3cret@cache:6379/0",
            "https://deploy:s3cret@registry.example/v2/",
            "APP_DATABASE_URL=postgres://app:s3cret@db.internal/tenkai",
            "FOO_POSTGRES_PASSWORD=s3cret",
        ] {
            let cleaned = assert_no_leak(sample, &["s3cret"]);
            assert!(
                cleaned.contains("[redacted]") || cleaned.contains("omitted"),
                "{sample:?} -> {cleaned}"
            );
        }
    }

    #[test]
    fn redacts_kubeconfig_data_fields_without_pem() {
        for sample in [
            "client-certificate-data: dGVzdA==",
            "client-key-data: dGVzdA==",
            "certificate-authority-data: dGVzdA==",
            r#"{"client-certificate-data":"dGVzdA=="}"#,
            "client-key: dGVzdA==",
        ] {
            let cleaned = assert_no_leak(sample, &["dGVzdA=="]);
            assert!(cleaned.contains("[redacted]"), "{sample:?} -> {cleaned}");
        }
    }

    #[test]
    fn omits_additional_pem_private_key_markers() {
        for marker in [
            "BEGIN EC PRIVATE KEY",
            "BEGIN ENCRYPTED PRIVATE KEY",
            "BEGIN DSA PRIVATE KEY",
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
        ] {
            let sample =
                format!("error: -----{marker}-----\nMIIFakePemFixture\n-----END PRIVATE KEY-----");
            let cleaned = assert_no_leak(&sample, &["MIIFakePemFixture"]);
            assert!(cleaned.contains("omitted"), "{marker} -> {cleaned}");
        }
    }

    #[test]
    fn omits_kubeconfig_users_user_block() {
        let yaml = "\
apiVersion: v1
kind: Config
users:
- name: minikube
  user:
    client-certificate-data: dGVzdA==
    client-key-data: dGVzdA==
";
        let cleaned = assert_no_leak(yaml, &["dGVzdA==", "minikube"]);
        assert!(cleaned.contains("omitted"), "{cleaned}");

        let json = r#"{"users":[{"name":"minikube","user":{"token":"s3cret"}}]}"#;
        let cleaned = assert_no_leak(json, &["s3cret", "minikube"]);
        assert!(cleaned.contains("omitted"), "{cleaned}");

        let inline_user = "user:\n  token: s3cret";
        let cleaned = assert_no_leak(inline_user, &["s3cret"]);
        assert!(cleaned.contains("omitted"), "{cleaned}");
    }

    #[test]
    fn keeps_existing_covered_shapes() {
        let bearer = assert_no_leak(
            "Authorization: Bearer s3cret-token\nnext",
            &["s3cret-token"],
        );
        assert!(bearer.contains("[redacted]"), "{bearer}");

        let path = assert_no_leak("users[].user.token: s3cret", &["s3cret"]);
        assert!(path.contains("[redacted]"), "{path}");

        let secret = assert_no_leak(
            r#"Error from server: {"kind": "Secret", "data": {"api-key": "s3cret"}}"#,
            &["s3cret"],
        );
        assert!(
            secret.contains("omitted") || secret.contains("secret"),
            "{secret}"
        );

        let safe = sanitize_diagnostic_text(
            "error: deployment.apps \"hello\" not found in namespace=local",
        );
        assert!(safe.contains("not found"), "{safe}");
        assert!(
            safe.contains("namespace=local") || safe.contains("namespace"),
            "{safe}"
        );
    }

    #[test]
    fn phase_error_sanitizes_before_persist_shape() {
        let err = format_software_phase_error(
            SoftwareDeployPhase::Apply,
            "api",
            "1.0.0",
            "stage",
            "helm failed: postgres://app:s3cret@db.internal/tenkai",
        );
        assert!(!err.contains("s3cret"), "{err}");
        assert!(err.contains("phase=apply"), "{err}");
        assert!(
            err.contains("[redacted]") || err.contains("omitted"),
            "{err}"
        );
    }

    #[test]
    fn resanitize_of_phase_error_keeps_required_text() {
        // apply maps run_captured_command errors through format_software_phase_error,
        // which sanitizes the already-wrapped string a second time.
        for environment in ["postgres-prod", "token-prod", "secret-store", "stage"] {
            let inner = format!(
                "software deploy phase=apply product=api environment/namespace={environment}: helm upgrade --install failed (status exit status 1): Error: UPGRADE FAILED: timed out waiting for the condition"
            );
            let cleaned = sanitize_diagnostic_text(&inner);
            assert!(
                cleaned.contains("timed out waiting for the condition"),
                "{environment}: dropped required text -> {cleaned}"
            );
            assert!(
                !cleaned.contains("s3cret"),
                "{environment}: unexpected leak -> {cleaned}"
            );
            let wrapped = format_software_phase_error(
                SoftwareDeployPhase::Apply,
                "api",
                "1.0.0",
                environment,
                &inner,
            );
            assert!(
                wrapped.contains("timed out waiting for the condition"),
                "{environment}: phase wrap dropped required text -> {wrapped}"
            );
        }
    }

    #[test]
    fn rbac_serviceaccount_keeps_forbidden_reason() {
        let sample = "Error from server (Forbidden): error when creating \"deploy.yaml\": deployments.apps is forbidden: User \"system:serviceaccount:default:foo\" cannot create resource \"deployments\" in API group \"apps\" in the namespace \"prod\"";
        let cleaned = sanitize_diagnostic_text(sample);
        assert!(
            cleaned.contains("cannot create resource"),
            "dropped RBAC reason -> {cleaned}"
        );
        assert!(
            cleaned.contains("system:serviceaccount:default:foo"),
            "dropped subject -> {cleaned}"
        );
        assert!(cleaned.contains("Forbidden"), "{cleaned}");
    }

    #[test]
    fn postgres_named_resource_keeps_rollout_reason() {
        let cleaned = sanitize_diagnostic_text(
            "Error: cannot patch postgres-prod: timeout waiting for rollout",
        );
        assert!(
            cleaned.contains("timeout waiting for rollout"),
            "dropped rollout reason -> {cleaned}"
        );
    }
}

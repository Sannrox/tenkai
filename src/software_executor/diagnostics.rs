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

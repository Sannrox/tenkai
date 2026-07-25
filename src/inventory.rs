//! Local hardware inventory probes for environment capability facts.
//!
//! Produces values for the admitted [`crate::plan::ENVIRONMENT_FACT_KEYS`] only.
//! Never collects secrets or contacts the network. Default CLI path is dry-run;
//! apply writes through existing `env facts` APIs.

use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::plan::ENVIRONMENT_FACT_KEYS;

/// Provenance token recorded in dry-run output (not a fact key).
pub const INVENTORY_SOURCE: &str = "local-probe";

/// One probed fact candidate for an environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryFact {
    pub key: String,
    pub value: String,
    pub source: &'static str,
}

/// Probe local machine inventory for admitted fact keys.
///
/// Keys with no reliable local signal are omitted (not invented).
pub fn probe_local_inventory() -> Result<Vec<InventoryFact>> {
    probe_with(SystemInventoryProbe)
}

/// Injectable probe surface for deterministic tests.
pub trait InventoryProbe {
    fn architecture(&self) -> Result<Option<String>>;
    fn memory_gib(&self) -> Result<Option<u64>>;
    fn accelerator(&self) -> Result<Option<String>>;
    fn free_disk_gib(&self) -> Result<Option<u64>>;
}

struct SystemInventoryProbe;

impl InventoryProbe for SystemInventoryProbe {
    fn architecture(&self) -> Result<Option<String>> {
        let arch = std::env::consts::ARCH;
        let normalized = match arch {
            "x86_64" | "x86" => arch.to_string(),
            "aarch64" => "arm64".into(),
            other => other.to_string(),
        };
        Ok(Some(normalized))
    }

    fn memory_gib(&self) -> Result<Option<u64>> {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("sysctl")
                .args(["-n", "hw.memsize"])
                .output()
                .context("probing memory via sysctl hw.memsize")?;
            if !output.status.success() {
                return Ok(None);
            }
            let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let bytes: u64 = raw
                .parse()
                .with_context(|| format!("parsing hw.memsize {raw:?}"))?;
            Ok(Some((bytes / (1024 * 1024 * 1024)).max(1)))
        }
        #[cfg(target_os = "linux")]
        {
            let content =
                std::fs::read_to_string("/proc/meminfo").context("reading /proc/meminfo")?;
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .unwrap_or("0")
                        .parse()
                        .context("parsing MemTotal")?;
                    return Ok(Some((kb / (1024 * 1024)).max(1)));
                }
            }
            Ok(None)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Ok(None)
        }
    }

    fn accelerator(&self) -> Result<Option<String>> {
        #[cfg(target_os = "macos")]
        {
            // Apple Silicon commonly exposes Metal; report a stable fact token.
            if std::env::consts::ARCH == "aarch64" {
                Ok(Some("apple-metal".into()))
            } else {
                Ok(None)
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Do not invent GPU presence without a reliable probe.
            Ok(None)
        }
    }

    fn free_disk_gib(&self) -> Result<Option<u64>> {
        // Optional; skip when not cheaply available without extra crates.
        Ok(None)
    }
}

pub fn probe_with(probe: impl InventoryProbe) -> Result<Vec<InventoryFact>> {
    let mut facts = Vec::new();
    if let Some(value) = probe.architecture()? {
        push_fact(&mut facts, "architecture", value)?;
    }
    if let Some(gib) = probe.memory_gib()? {
        push_fact(&mut facts, "memory_gib", gib.to_string())?;
    }
    if let Some(value) = probe.accelerator()? {
        push_fact(&mut facts, "accelerator", value)?;
    }
    if let Some(gib) = probe.free_disk_gib()? {
        push_fact(&mut facts, "free_disk_gib", gib.to_string())?;
    }
    Ok(facts)
}

fn push_fact(facts: &mut Vec<InventoryFact>, key: &str, value: String) -> Result<()> {
    if !ENVIRONMENT_FACT_KEYS.contains(&key) {
        bail!(
            "inventory probe produced unknown fact key {key:?}; admitted: {}",
            ENVIRONMENT_FACT_KEYS.join(", ")
        );
    }
    if value.trim().is_empty() {
        bail!("inventory fact {key} must not be empty");
    }
    facts.push(InventoryFact {
        key: key.into(),
        value,
        source: INVENTORY_SOURCE,
    });
    Ok(())
}

/// Format dry-run lines for operators (no secrets).
pub fn format_dry_run(env: &str, facts: &[InventoryFact]) -> String {
    let mut lines = vec![format!(
        "inventory probe for {env} (source={INVENTORY_SOURCE}; dry-run, not written)"
    )];
    if facts.is_empty() {
        lines.push("  (no facts detected)".into());
    } else {
        for fact in facts {
            lines.push(format!("  {}={}", fact.key, fact.value));
        }
        lines.push("re-run with --apply to write via env facts".into());
    }
    lines.join("\n")
}

/// Map facts to a BTreeMap for tests / JSON.
pub fn facts_map(facts: &[InventoryFact]) -> BTreeMap<String, String> {
    facts
        .iter()
        .map(|fact| (fact.key.clone(), fact.value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProbe {
        arch: Option<String>,
        mem: Option<u64>,
        accel: Option<String>,
        disk: Option<u64>,
    }

    impl InventoryProbe for FixedProbe {
        fn architecture(&self) -> Result<Option<String>> {
            Ok(self.arch.clone())
        }
        fn memory_gib(&self) -> Result<Option<u64>> {
            Ok(self.mem)
        }
        fn accelerator(&self) -> Result<Option<String>> {
            Ok(self.accel.clone())
        }
        fn free_disk_gib(&self) -> Result<Option<u64>> {
            Ok(self.disk)
        }
    }

    #[test]
    fn probe_emits_only_admitted_keys() {
        let facts = probe_with(FixedProbe {
            arch: Some("arm64".into()),
            mem: Some(32),
            accel: Some("apple-metal".into()),
            disk: None,
        })
        .unwrap();
        let map = facts_map(&facts);
        assert_eq!(map.get("architecture").map(String::as_str), Some("arm64"));
        assert_eq!(map.get("memory_gib").map(String::as_str), Some("32"));
        assert_eq!(
            map.get("accelerator").map(String::as_str),
            Some("apple-metal")
        );
        assert!(!map.contains_key("free_disk_gib"));
        for fact in &facts {
            assert_eq!(fact.source, INVENTORY_SOURCE);
            assert!(ENVIRONMENT_FACT_KEYS.contains(&fact.key.as_str()));
        }
    }

    #[test]
    fn dry_run_format_has_no_secret_patterns() {
        let facts = probe_with(FixedProbe {
            arch: Some("x86_64".into()),
            mem: Some(16),
            accel: None,
            disk: None,
        })
        .unwrap();
        let text = format_dry_run("prod", &facts);
        assert!(text.contains("dry-run"));
        assert!(text.contains("architecture=x86_64"));
        assert!(!text.to_lowercase().contains("token"));
        assert!(!text.contains("Bearer"));
    }

    #[test]
    fn system_probe_returns_architecture() {
        let facts = probe_local_inventory().unwrap();
        let arch = facts.iter().find(|f| f.key == "architecture");
        assert!(arch.is_some(), "expected architecture fact: {facts:?}");
    }
}

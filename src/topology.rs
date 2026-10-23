//! Replica topologies and anti-affinity placement (#689, part of #650).
//!
//! A release manifest may declare a `[topology]`: a named group of
//! environments, each one replica, and the placement fact that must differ
//! between them (`host` or `zone`). The facts come from each environment's
//! runtime inventory. The planner refuses a plan for a member environment
//! while two replicas share the fact, or while a replica has not reported it,
//! naming the conflicting facts. Releases without a topology plan as before.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;

/// `[topology]` in a release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologySection {
    pub name: String,
    /// The replica environments, at least two.
    pub environments: Vec<String>,
    /// The placement fact replicas must not share.
    pub anti_affinity: AntiAffinity,
}

/// The placement level replicas are spread across.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiAffinity {
    Host,
    Zone,
}

impl AntiAffinity {
    /// The environment fact this level reads.
    pub fn fact(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Zone => "zone",
        }
    }
}

impl TopologySection {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("topology needs a name");
        }
        if self.environments.len() < 2 {
            bail!(
                "topology {} needs at least two replica environments",
                self.name
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for environment in &self.environments {
            if environment.trim().is_empty() || !seen.insert(environment) {
                bail!(
                    "topology {} lists replica environment {environment:?} empty or twice",
                    self.name
                );
            }
        }
        Ok(())
    }

    /// Refuses placement of `environment` unless it is a replica and every
    /// replica's placement fact is known and distinct. `facts` maps each
    /// replica environment to its facts. A refusal is a [`PlacementRefused`].
    pub fn check_placement(
        &self,
        environment: &str,
        facts: &BTreeMap<String, BTreeMap<String, String>>,
    ) -> Result<()> {
        let key = self.anti_affinity.fact();
        if !self.environments.iter().any(|member| member == environment) {
            return Err(refused(format!(
                "environment {environment} is not a replica of topology {}; its replicas are {}",
                self.name,
                self.environments.join(", ")
            )));
        }
        let mut placed: BTreeMap<&str, &str> = BTreeMap::new();
        for member in &self.environments {
            let Some(value) = facts.get(member).and_then(|facts| facts.get(key)) else {
                return Err(refused(format!(
                    "topology {} cannot check {key} anti-affinity: replica {member} has no {key} fact; \
                     its runtime inventory must report it",
                    self.name
                )));
            };
            if let Some(other) = placed.insert(value.as_str(), member.as_str()) {
                return Err(refused(format!(
                    "topology {} violates {key} anti-affinity: replicas {other} and {member} \
                     both have {key}={value}",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

/// A placement the declared topology does not allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRefused(pub String);

impl std::fmt::Display for PlacementRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlacementRefused {}

fn refused(message: String) -> anyhow::Error {
    PlacementRefused(message).into()
}

/// Refuses a plan placing `release` on `environment` when the release
/// declares a topology that the replicas' placement facts violate.
pub async fn require_placement(ctx: &mut Ctx, environment: &str, release: &str) -> Result<()> {
    let Some(object) = ctx.get(release).await? else {
        bail!("release {release} is not published");
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(());
    };
    let manifest = crate::manifest::parse_raw(raw)?;
    require_manifest_placement(ctx, environment, &manifest).await
}

/// [`require_placement`] for a manifest already loaded, as apply admission
/// re-checks it before mutation: facts may change after a plan was made.
pub async fn require_manifest_placement(
    ctx: &mut Ctx,
    environment: &str,
    manifest: &crate::manifest::Manifest,
) -> Result<()> {
    let Some(topology) = &manifest.topology else {
        return Ok(());
    };
    let mut facts = BTreeMap::new();
    for member in &topology.environments {
        let member_facts = crate::environment::list_environment_facts(ctx, member)
            .await
            .with_context(|| format!("topology {} replica {member}", topology.name))?;
        facts.insert(member.clone(), member_facts);
    }
    topology.check_placement(environment, &facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology(anti_affinity: AntiAffinity) -> TopologySection {
        TopologySection {
            name: "ledger".into(),
            environments: vec!["ledger-a".into(), "ledger-b".into(), "ledger-c".into()],
            anti_affinity,
        }
    }

    fn facts(rows: &[(&str, &str, &str)]) -> BTreeMap<String, BTreeMap<String, String>> {
        let mut facts: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for (environment, key, value) in rows {
            facts
                .entry(environment.to_string())
                .or_default()
                .insert(key.to_string(), value.to_string());
        }
        facts
    }

    #[test]
    fn two_replicas_on_one_host_are_refused_naming_the_facts() {
        let placed = facts(&[
            ("ledger-a", "host", "h1"),
            ("ledger-b", "host", "h2"),
            ("ledger-c", "host", "h1"),
        ]);
        let err = topology(AntiAffinity::Host)
            .check_placement("ledger-b", &placed)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("ledger-a and ledger-c both have host=h1"),
            "{err}"
        );
    }

    #[test]
    fn distinct_placement_passes_and_zone_is_checked_separately() {
        let placed = facts(&[
            ("ledger-a", "host", "h1"),
            ("ledger-a", "zone", "z1"),
            ("ledger-b", "host", "h2"),
            ("ledger-b", "zone", "z1"),
            ("ledger-c", "host", "h3"),
            ("ledger-c", "zone", "z2"),
        ]);
        topology(AntiAffinity::Host)
            .check_placement("ledger-a", &placed)
            .unwrap();
        let err = topology(AntiAffinity::Zone)
            .check_placement("ledger-a", &placed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("both have zone=z1"), "{err}");
    }

    #[test]
    fn a_missing_fact_or_a_non_member_is_refused() {
        let placed = facts(&[("ledger-a", "host", "h1"), ("ledger-b", "host", "h2")]);
        let err = topology(AntiAffinity::Host)
            .check_placement("ledger-a", &placed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("replica ledger-c has no host fact"), "{err}");
        let err = topology(AntiAffinity::Host)
            .check_placement("elsewhere", &placed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a replica of topology ledger"), "{err}");
    }

    #[test]
    fn a_topology_needs_two_distinct_replicas() {
        let mut one = topology(AntiAffinity::Host);
        one.environments.truncate(1);
        assert!(one.validate().is_err());
        let mut twice = topology(AntiAffinity::Host);
        twice.environments[2] = "ledger-a".into();
        assert!(twice.validate().is_err());
        topology(AntiAffinity::Zone).validate().unwrap();
    }
}

//! Replica topologies and anti-affinity placement (#689, part of #650).
//!
//! A release manifest may declare a `[topology]`: a named group of
//! environments, each one replica, and the placement fact that must differ
//! between them (`host` or `zone`). The facts come from each environment's
//! runtime inventory. The planner refuses a plan for a member environment
//! while two replicas share the fact, or while a replica has not reported it,
//! naming the conflicting facts. Releases without a topology plan as before.
//!
//! A topology may also declare `min_available` (#690): a rolling wave starts
//! upgrading a serving replica only while at least that many of the other
//! replicas are healthy for the product, so an upgrade never takes more
//! replicas down than the topology can spare. An explicit failover drill
//! (#691) takes one serving replica out of service under the same lease,
//! proves the minimum still holds, restores it, and signs the evidence.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;

/// Shared with rolling waves so a drill cannot take a replica down while a
/// wave is already changing one, and the other way around.
pub const TOPOLOGY_LEASE_NAMESPACE: &str = "tenkai/topology-availability";
/// Same two-hour bound as a wave lease.
pub const TOPOLOGY_LEASE_MS: i64 = 2 * 60 * 60 * 1000;

/// `[topology]` in a release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologySection {
    pub name: String,
    /// The replica environments, at least two.
    pub environments: Vec<String>,
    /// The placement fact replicas must not share.
    pub anti_affinity: AntiAffinity,
    /// Replicas that must stay healthy while another one upgrades. At least
    /// one and fewer than the replicas, so an upgrade can always proceed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<usize>,
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
        if let Some(minimum) = self.min_available
            && (minimum == 0 || minimum >= self.environments.len())
        {
            bail!(
                "topology {} min_available must be at least 1 and below its {} replicas",
                self.name,
                self.environments.len()
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

impl TopologySection {
    /// Refuses starting `environment`'s upgrade while it is serving (in
    /// `serving`) and fewer than `min_available` of the other replicas are in
    /// `available`. Upgrading a replica that is not serving takes nothing
    /// down, so a first install and the repair of a failed replica proceed.
    /// An environment outside the topology, or a topology without a minimum,
    /// is not limited.
    pub fn check_availability(
        &self,
        environment: &str,
        serving: &BTreeSet<String>,
        available: &BTreeSet<String>,
    ) -> Result<()> {
        let Some(minimum) = self.min_available else {
            return Ok(());
        };
        if !self.environments.iter().any(|member| member == environment)
            || !serving.contains(environment)
        {
            return Ok(());
        }
        let others: Vec<&String> = self
            .environments
            .iter()
            .filter(|member| member.as_str() != environment)
            .collect();
        let up = others
            .iter()
            .filter(|member| available.contains(**member))
            .count();
        if up < minimum {
            let unready: Vec<&str> = others
                .iter()
                .filter(|member| !available.contains(**member))
                .map(|member| member.as_str())
                .collect();
            return Err(AvailabilityRefused(format!(
                "upgrading {environment} would leave {up} of topology {}'s replicas available, below its minimum {minimum}; not healthy: {}",
                self.name,
                unready.join(", ")
            ))
            .into());
        }
        Ok(())
    }
}

/// An upgrade start that would leave a topology below its minimum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityRefused(pub String);

impl std::fmt::Display for AvailabilityRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AvailabilityRefused {}

/// Refuses starting `environment`'s upgrade to `release` when the release's
/// topology would fall below its minimum. A replica is available while its
/// `deployment_health.<product>` reads `healthy` and no plan of it is left
/// running, since a run interrupted mid-way records no outcome.
pub async fn require_availability(ctx: &mut Ctx, environment: &str, release: &str) -> Result<()> {
    let Some((topology, product)) = availability_manifest(ctx, release).await? else {
        return Ok(());
    };
    let (serving, available) = replica_availability(ctx, &topology, &product).await?;
    topology.check_availability(environment, &serving, &available)
}

pub(crate) fn deployment_health_key(product: &str) -> String {
    format!("deployment_health.{product}")
}

/// Serving is healthy for the product; available is serving with no plan
/// left running. Doubt about a replica never waives the guard on it.
pub(crate) async fn replica_availability(
    ctx: &mut Ctx,
    topology: &TopologySection,
    product: &str,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let key = deployment_health_key(product);
    let mut serving = BTreeSet::new();
    let mut available = BTreeSet::new();
    for member in &topology.environments {
        let object = crate::environment::environment(ctx, member)
            .await
            .with_context(|| format!("topology {} replica {member}", topology.name))?;
        if object
            .properties
            .get(&key)
            .is_none_or(|health| health != "healthy")
        {
            continue;
        }
        serving.insert(member.clone());
        let running = crate::plan::list_for_environment(
            ctx,
            member,
            Some(&[crate::plan::PlanState::Running]),
        )
        .await?;
        if running.is_empty() {
            available.insert(member.clone());
        }
    }
    Ok((serving, available))
}

/// The topology `release` declares when it sets `min_available`.
pub async fn availability_topology(
    ctx: &mut Ctx,
    release: &str,
) -> Result<Option<TopologySection>> {
    Ok(availability_manifest(ctx, release)
        .await?
        .map(|(topology, _)| topology))
}

pub(crate) async fn availability_manifest(
    ctx: &mut Ctx,
    release: &str,
) -> Result<Option<(TopologySection, String)>> {
    let Some(object) = ctx.get(release).await? else {
        bail!("release {release} is not published");
    };
    let Some(raw) = object.properties.get("manifest") else {
        return Ok(None);
    };
    let manifest = crate::manifest::parse_raw(raw)?;
    Ok(manifest
        .topology
        .filter(|topology| topology.min_available.is_some())
        .map(|topology| (topology, manifest.product.name)))
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
            min_available: None,
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

    fn healthy(members: &[&str]) -> BTreeSet<String> {
        members.iter().map(|member| member.to_string()).collect()
    }

    #[test]
    fn min_available_leaves_a_replica_to_upgrade() {
        let mut ledger = topology(AntiAffinity::Host);
        for minimum in [0, 3] {
            ledger.min_available = Some(minimum);
            let err = ledger.validate().unwrap_err().to_string();
            assert!(err.contains("min_available"), "{err}");
        }
        ledger.min_available = Some(2);
        ledger.validate().unwrap();
    }

    /// Three replicas, minimum two: a serving replica upgrades only while
    /// both others serve, so a rolling upgrade never has fewer than two.
    #[test]
    fn a_serving_replica_upgrades_only_while_the_minimum_stays_up() {
        let mut ledger = topology(AntiAffinity::Host);
        ledger.min_available = Some(2);
        let all = healthy(&["ledger-a", "ledger-b", "ledger-c"]);
        for replica in ["ledger-a", "ledger-b", "ledger-c"] {
            ledger.check_availability(replica, &all, &all).unwrap();
        }
        let err = ledger
            .check_availability(
                "ledger-a",
                &healthy(&["ledger-a", "ledger-c"]),
                &healthy(&["ledger-a", "ledger-c"]),
            )
            .unwrap_err();
        let refused = err.downcast_ref::<AvailabilityRefused>().unwrap();
        assert!(
            refused.0.contains("1 of topology ledger")
                && refused.0.contains("minimum 2")
                && refused.0.contains("not healthy: ledger-b"),
            "{refused}"
        );
        // Every step of a rolling upgrade: the replica under upgrade is down,
        // and the next one starts only once it is back.
        let mut up = all.clone();
        for replica in ["ledger-a", "ledger-b", "ledger-c"] {
            ledger.check_availability(replica, &up, &up).unwrap();
            up.remove(replica);
            assert!(up.len() >= 2);
            for next in ["ledger-a", "ledger-b", "ledger-c"] {
                if next != replica && up.contains(next) {
                    assert!(ledger.check_availability(next, &up, &up).is_err());
                }
            }
            up.insert(replica.to_string());
        }
    }

    /// Upgrading a replica that is not serving takes nothing down: a first
    /// install and a failed replica's repair proceed. Outside the topology,
    /// or without a minimum, nothing is limited.
    #[test]
    fn upgrading_a_replica_that_is_down_is_allowed() {
        let mut ledger = topology(AntiAffinity::Host);
        ledger.min_available = Some(2);
        ledger
            .check_availability("ledger-a", &healthy(&[]), &healthy(&[]))
            .unwrap();
        ledger
            .check_availability("ledger-b", &healthy(&["ledger-a"]), &healthy(&["ledger-a"]))
            .unwrap();
        ledger
            .check_availability(
                "elsewhere",
                &healthy(&["elsewhere"]),
                &healthy(&["elsewhere"]),
            )
            .unwrap();
        ledger.min_available = None;
        ledger
            .check_availability("ledger-a", &healthy(&["ledger-a"]), &healthy(&["ledger-a"]))
            .unwrap();
    }

    /// A serving replica with a stale running plan is still serving: doubt
    /// about it never waives the guard on its own upgrade.
    #[test]
    fn a_serving_replica_with_a_left_running_plan_is_still_guarded() {
        let mut ledger = topology(AntiAffinity::Host);
        ledger.min_available = Some(2);
        let serving = healthy(&["ledger-a", "ledger-b", "ledger-c"]);
        let available = healthy(&["ledger-c"]);
        let err = ledger
            .check_availability("ledger-a", &serving, &available)
            .unwrap_err();
        assert!(err.to_string().contains("not healthy: ledger-b"), "{err}");
    }
}

//! Deterministic thousand-environment synthetic fleet (#299).
//!
//! Generation is evidence infrastructure, not a support claim. It persists only
//! Tenkai-owned environment records and does not skip signing, approval, or
//! gates on any product it plants.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use sha2::{Digest as _, Sha256};

use crate::client::Ctx;
use crate::connectivity::{self, ConnectivityClass};
use crate::environment;
use crate::ontology::{channel_id, validate_identifier};

pub const WORKLOAD_SIZE: u32 = 1_000;
pub const POSTURE_CURRENT: &str = "current";
pub const POSTURE_BEHIND: &str = "behind";
pub const POSTURE_UNHEALTHY: &str = "unhealthy";
pub const POSTURE_BLOCKED: &str = "blocked";
pub const POSTURE_DISCONNECTED: &str = "disconnected";
const PROPERTY_POSTURE: &str = "synthetic_workload.posture";
const PROPERTY_SEED: &str = "synthetic_workload.seed_digest";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkloadPosture {
    Current,
    Behind,
    Unhealthy,
    Blocked,
    Disconnected,
}

impl WorkloadPosture {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            POSTURE_CURRENT => Ok(Self::Current),
            POSTURE_BEHIND => Ok(Self::Behind),
            POSTURE_UNHEALTHY => Ok(Self::Unhealthy),
            POSTURE_BLOCKED => Ok(Self::Blocked),
            POSTURE_DISCONNECTED => Ok(Self::Disconnected),
            other => bail!("unknown workload posture {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => POSTURE_CURRENT,
            Self::Behind => POSTURE_BEHIND,
            Self::Unhealthy => POSTURE_UNHEALTHY,
            Self::Blocked => POSTURE_BLOCKED,
            Self::Disconnected => POSTURE_DISCONNECTED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadSpec {
    pub seed: String,
    pub product: String,
    pub channel: String,
    pub current_version: String,
    pub behind_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadMember {
    pub name: String,
    pub posture: WorkloadPosture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadPlan {
    pub seed_digest: String,
    pub product: String,
    pub channel: String,
    pub current_version: String,
    pub behind_version: String,
    pub members: Vec<WorkloadMember>,
}

impl WorkloadSpec {
    pub fn validate(&self) -> Result<()> {
        validate_seed(&self.seed)?;
        validate_identifier("product", &self.product)?;
        validate_identifier("channel", &self.channel)?;
        validate_identifier("current version", &self.current_version)?;
        validate_identifier("behind version", &self.behind_version)?;
        if self.current_version == self.behind_version {
            bail!("current and behind versions must differ");
        }
        Ok(())
    }
}

fn validate_seed(seed: &str) -> Result<()> {
    if seed.is_empty() || seed != seed.trim() || seed.len() > 128 {
        bail!("workload seed is empty, non-canonical, or too long");
    }
    if seed.chars().any(|ch| ch.is_control()) {
        bail!("workload seed must not contain control characters");
    }
    let lower = seed.to_ascii_lowercase();
    for needle in ["bearer ", "password=", "secret=", "token="] {
        if lower.contains(needle) {
            bail!("workload seed must not contain credential material");
        }
    }
    Ok(())
}

pub fn seed_digest(seed: &str) -> Result<String> {
    validate_seed(seed)?;
    Ok(format!("sha256:{:x}", Sha256::digest(seed.as_bytes())))
}

pub fn plan_workload(spec: &WorkloadSpec) -> Result<WorkloadPlan> {
    spec.validate()?;
    let digest = seed_digest(&spec.seed)?;
    let prefix = digest
        .strip_prefix("sha256:")
        .unwrap_or(&digest)
        .chars()
        .take(8)
        .collect::<String>();
    let postures = default_mix();
    let mut members = Vec::with_capacity(WORKLOAD_SIZE as usize);
    for (index, posture) in postures.into_iter().enumerate() {
        let name = format!("syn{prefix}{index:04}");
        validate_identifier("environment", &name)?;
        members.push(WorkloadMember { name, posture });
    }
    validate_members(&members)?;
    Ok(WorkloadPlan {
        seed_digest: digest,
        product: spec.product.clone(),
        channel: spec.channel.clone(),
        current_version: spec.current_version.clone(),
        behind_version: spec.behind_version.clone(),
        members,
    })
}

fn validate_members(members: &[WorkloadMember]) -> Result<()> {
    let mut names = BTreeSet::new();
    for member in members {
        if !names.insert(member.name.as_str()) {
            bail!("duplicate environment identity {}", member.name);
        }
    }
    if members.len() as u32 != WORKLOAD_SIZE {
        bail!(
            "workload must contain {WORKLOAD_SIZE} environments, got {}",
            members.len()
        );
    }
    let unique = members
        .iter()
        .map(|member| member.posture)
        .collect::<BTreeSet<_>>();
    if unique.len() < 2 {
        bail!("mixed postures were requested; refusing an all-healthy fleet");
    }
    Ok(())
}

fn default_mix() -> Vec<WorkloadPosture> {
    let cycle = [
        WorkloadPosture::Current,
        WorkloadPosture::Behind,
        WorkloadPosture::Unhealthy,
        WorkloadPosture::Blocked,
        WorkloadPosture::Disconnected,
    ];
    (0..WORKLOAD_SIZE)
        .map(|index| cycle[(index as usize) % cycle.len()])
        .collect()
}

pub fn posture_counts(plan: &WorkloadPlan) -> BTreeMap<&'static str, u32> {
    let mut counts = BTreeMap::new();
    for member in &plan.members {
        *counts.entry(member.posture.as_str()).or_insert(0) += 1;
    }
    counts
}

pub fn format_workload(plan: &WorkloadPlan) -> String {
    let counts = posture_counts(plan);
    format!(
        "synthetic workload seed_digest={} environments={}\n  current={} behind={} unhealthy={} blocked={} disconnected={}",
        plan.seed_digest,
        plan.members.len(),
        counts.get(POSTURE_CURRENT).copied().unwrap_or(0),
        counts.get(POSTURE_BEHIND).copied().unwrap_or(0),
        counts.get(POSTURE_UNHEALTHY).copied().unwrap_or(0),
        counts.get(POSTURE_BLOCKED).copied().unwrap_or(0),
        counts.get(POSTURE_DISCONNECTED).copied().unwrap_or(0),
    )
}

pub async fn materialize(ctx: &mut Ctx, spec: &WorkloadSpec) -> Result<WorkloadPlan> {
    let plan = plan_workload(spec)?;
    let channel = ctx.get(&channel_id(&plan.product, &plan.channel)).await?;
    if channel.is_none() {
        bail!(
            "channel {}/{} does not exist — publish and promote a signed release first",
            plan.product,
            plan.channel
        );
    }
    let mut planted = 0u32;
    for member in &plan.members {
        match plant_member(ctx, &plan, member).await {
            Ok(()) => planted += 1,
            Err(error) => {
                bail!("partial materialization is incomplete ({planted}/{WORKLOAD_SIZE}): {error}");
            }
        }
    }
    if planted != WORKLOAD_SIZE {
        bail!("partial materialization is incomplete ({planted}/{WORKLOAD_SIZE})");
    }
    Ok(plan)
}

async fn plant_member(ctx: &mut Ctx, plan: &WorkloadPlan, member: &WorkloadMember) -> Result<()> {
    let description = format!("synthetic {} {}", plan.seed_digest, member.posture.as_str());
    crate::plan::env_add(ctx, &member.name, &description).await?;
    let mut object = environment::environment(ctx, &member.name).await?;
    object
        .properties
        .insert(PROPERTY_SEED.into(), plan.seed_digest.clone());
    object
        .properties
        .insert(PROPERTY_POSTURE.into(), member.posture.as_str().into());
    object.updated = crate::now_millis();
    ctx.put(object).await?;

    match member.posture {
        WorkloadPosture::Disconnected => {
            connectivity::set_connectivity_class(ctx, &member.name, ConnectivityClass::Isolated)
                .await?;
        }
        WorkloadPosture::Current => {
            environment::subscribe(ctx, &member.name, &plan.product, &plan.channel).await?;
            environment::reconcile_deployment(
                ctx,
                &member.name,
                &plan.product,
                Some(&plan.current_version),
            )
            .await?;
        }
        WorkloadPosture::Behind => {
            environment::subscribe(ctx, &member.name, &plan.product, &plan.channel).await?;
            environment::reconcile_deployment(
                ctx,
                &member.name,
                &plan.product,
                Some(&plan.behind_version),
            )
            .await?;
        }
        WorkloadPosture::Unhealthy => {
            environment::subscribe(ctx, &member.name, &plan.product, &plan.channel).await?;
            environment::reconcile_deployment(
                ctx,
                &member.name,
                &plan.product,
                Some(&plan.current_version),
            )
            .await?;
            let mut object = environment::environment(ctx, &member.name).await?;
            object.properties.insert(
                format!("deployment_health.{}", plan.product),
                "unhealthy".into(),
            );
            object.properties.insert(
                format!("deployment_error.{}", plan.product),
                "synthetic unhealthy target".into(),
            );
            object.updated = crate::now_millis();
            ctx.put(object).await?;
        }
        WorkloadPosture::Blocked => {
            environment::subscribe(ctx, &member.name, &plan.product, &plan.channel).await?;
            environment::set_environment_constraint(
                ctx,
                &member.name,
                "require_fact",
                "architecture",
                "*",
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn stored_posture_counts(
    ctx: &mut Ctx,
    seed_digest: &str,
) -> Result<BTreeMap<String, u32>> {
    let listed = environment::list_environments(ctx).await?;
    let mut counts = BTreeMap::new();
    for entry in listed {
        let object = environment::environment(ctx, &entry.name).await?;
        let Some(digest) = object.properties.get(PROPERTY_SEED) else {
            continue;
        };
        if digest != seed_digest {
            continue;
        }
        let posture = object.properties.get(PROPERTY_POSTURE).ok_or_else(|| {
            anyhow::anyhow!("environment {} is missing workload posture", entry.name)
        })?;
        WorkloadPosture::parse(posture)?;
        *counts.entry(posture.clone()).or_insert(0) += 1;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::PublishOptions;
    use crate::client::Ctx;

    fn spec(seed: &str) -> WorkloadSpec {
        WorkloadSpec {
            seed: seed.into(),
            product: "scale-app".into(),
            channel: "stable".into(),
            current_version: "1.1.0".into(),
            behind_version: "1.0.0".into(),
        }
    }

    #[test]
    fn same_seed_reproduces_identities_and_mixed_counts() {
        let first = plan_workload(&spec("demo-seed")).unwrap();
        let second = plan_workload(&spec("demo-seed")).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.members.len(), WORKLOAD_SIZE as usize);
        let counts = posture_counts(&first);
        assert_eq!(counts.get(POSTURE_CURRENT).copied(), Some(200));
        assert_eq!(counts.get(POSTURE_BEHIND).copied(), Some(200));
        assert_eq!(counts.get(POSTURE_UNHEALTHY).copied(), Some(200));
        assert_eq!(counts.get(POSTURE_BLOCKED).copied(), Some(200));
        assert_eq!(counts.get(POSTURE_DISCONNECTED).copied(), Some(200));
        assert_ne!(plan_workload(&spec("other-seed")).unwrap(), first);
    }

    #[test]
    fn unknown_posture_duplicate_identity_and_all_healthy_fail_closed() {
        let err = WorkloadPosture::parse("modem").unwrap_err().to_string();
        assert!(err.contains("unknown workload posture"), "{err}");
        let err = seed_digest("bearer secret-token").unwrap_err().to_string();
        assert!(err.contains("credential material"), "{err}");
        let err = spec(" demo ").validate().unwrap_err().to_string();
        assert!(err.contains("non-canonical"), "{err}");
        let mut identical = spec("demo-seed");
        identical.behind_version = identical.current_version.clone();
        let err = plan_workload(&identical).unwrap_err().to_string();
        assert!(err.contains("must differ"), "{err}");
        let all_current = (0..WORKLOAD_SIZE)
            .map(|index| WorkloadMember {
                name: format!("synx{index:04}"),
                posture: WorkloadPosture::Current,
            })
            .collect::<Vec<_>>();
        let err = validate_members(&all_current).unwrap_err().to_string();
        assert!(err.contains("all-healthy"), "{err}");
        let mut duplicated = plan_workload(&spec("demo-seed")).unwrap().members;
        duplicated[1].name = duplicated[0].name.clone();
        let err = validate_members(&duplicated).unwrap_err().to_string();
        assert!(err.contains("duplicate environment identity"), "{err}");
    }

    #[test]
    fn format_names_the_mix_without_secrets() {
        let plan = plan_workload(&spec("demo-seed")).unwrap();
        let text = format_workload(&plan);
        assert!(text.contains("environments=1000"), "{text}");
        assert!(text.contains("current=200"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("bearer"), "{text}");
        assert!(!text.contains("token="), "{text}");
    }

    async fn publish_signed(ctx: &mut Ctx, root: &std::path::Path, version: &str) {
        let dir = root.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"
[product]
name = "scale-app"
version = "{version}"

[deploy]
install = "true"
"#
            ),
        )
        .unwrap();
        let keys = root.join("keys");
        let signature = dir.join("release.sig.json");
        let trust = dir.join("release-trust.toml");
        crate::dev_sign::sign_release(&keys, &dir.join("tenkai.toml"), &signature, &trust).unwrap();
        crate::catalog::publish(
            ctx,
            &dir.join("tenkai.toml"),
            &PublishOptions {
                signature: Some(signature),
                trust_roots: Some(trust),
                allow_unsigned_development: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn materialize_is_idempotent_and_refuses_missing_signed_channel() {
        let root = std::env::temp_dir().join(format!(
            "tenkai-workload-{}-{}",
            std::process::id(),
            crate::now_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut ctx = Ctx::embedded(root.join("tenkai.db")).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        let missing = materialize(&mut ctx, &spec("demo-seed"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("publish and promote a signed release"),
            "{missing}"
        );

        publish_signed(&mut ctx, &root, "1.0.0").await;
        publish_signed(&mut ctx, &root, "1.1.0").await;
        let actor = crate::auth_context::test_management_context("workload");
        crate::catalog::promote(&mut ctx, &actor, "scale-app@1.1.0", "stable")
            .await
            .unwrap();

        let first = materialize(&mut ctx, &spec("demo-seed")).await.unwrap();
        assert_eq!(first.members.len(), WORKLOAD_SIZE as usize);
        let stored = stored_posture_counts(&mut ctx, &first.seed_digest)
            .await
            .unwrap();
        assert_eq!(stored.get(POSTURE_CURRENT).copied(), Some(200));
        assert_eq!(stored.get(POSTURE_BEHIND).copied(), Some(200));
        assert_eq!(stored.get(POSTURE_UNHEALTHY).copied(), Some(200));
        assert_eq!(stored.get(POSTURE_BLOCKED).copied(), Some(200));
        assert_eq!(stored.get(POSTURE_DISCONNECTED).copied(), Some(200));
        let listed = environment::list_environments(&mut ctx).await.unwrap();
        let names: BTreeSet<_> = listed.iter().map(|entry| entry.name.clone()).collect();
        assert_eq!(names.len(), WORKLOAD_SIZE as usize);
        for entry in &listed {
            assert!(
                !entry.description.to_ascii_lowercase().contains("bearer"),
                "{}",
                entry.description
            );
        }

        let replay = materialize(&mut ctx, &spec("demo-seed")).await.unwrap();
        assert_eq!(replay.seed_digest, first.seed_digest);
        let replay_names: BTreeSet<_> = environment::list_environments(&mut ctx)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(replay_names, names);

        let current = first
            .members
            .iter()
            .find(|member| member.posture == WorkloadPosture::Current)
            .unwrap();
        let report = environment::inspect_environment(&mut ctx, &current.name)
            .await
            .unwrap();
        assert_eq!(report.subscriptions[0].state, "current");
        let _ = std::fs::remove_dir_all(root);
    }
}

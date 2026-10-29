//! Failover drill for a declared topology (#691, part of #650).
//!
//! On explicit request, take one serving replica out of service, prove the
//! remaining replicas still meet `min_available` and stay healthy, restore
//! it, and record signed evidence of the loss, the measured recovery, and
//! the restore. Out of service is Tenkai's serving signal, the same
//! `deployment_health` a rolling wave reads. A drill that would drop the
//! topology below its minimum is refused before anything is taken down. The
//! topology lease serializes the drill with rolling waves. The replica's
//! apply lease serializes the health writes with ordinary applies. The
//! previous health is stored with the outage so a crash can restore it,
//! and a restore only writes that health back while the replica is still
//! out of service.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::topology::{self, AvailabilityRefused, TopologySection};

pub const DRILL_SCHEMA: &str = "tenkai.topology-drill.v1";
/// Environment property holding the latest signed drill evidence as JSON.
pub const EVIDENCE_PROPERTY: &str = "topology_drill_evidence";
/// Durable restoration state written with the outage so a crash can resume.
/// Keyed by topology and product so two products sharing an environment
/// cannot overwrite each other's restore records.
pub const OUTAGE_PROPERTY_PREFIX: &str = "topology_drill.outage";
const SIGNING_DOMAIN: &[u8] = b"TENKAI-TOPOLOGY-DRILL-V1\0";
const OUT_OF_SERVICE: &str = "out_of_service";

fn outage_property(topology: &str, product: &str) -> String {
    format!("{OUTAGE_PROPERTY_PREFIX}.{topology}.{product}")
}

/// Signed drill result as stored on the drilled replica and written to `--out`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrillEvidence {
    pub schema: String,
    pub key_id: String,
    pub statement: DrillStatement,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrillStatement {
    pub release: String,
    pub topology: String,
    pub product: String,
    pub min_available: usize,
    pub replicas: Vec<String>,
    pub passed: bool,
    pub loss: LossRecord,
    pub recovery: RecoveryRecord,
    pub restore: RestoreRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LossRecord {
    pub replica: String,
    pub at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub remaining_available: Vec<String>,
    pub confirmed_at_ms: i64,
    pub duration_ms: i64,
    pub traffic_continued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRecord {
    pub replica: String,
    pub at_ms: i64,
    pub available: Vec<String>,
}

fn canonical_bytes(statement: &DrillStatement) -> Result<Vec<u8>> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, statement)?;
    Ok(bytes)
}

fn release_object_id(spec: &str) -> Result<String> {
    let rest = spec.strip_prefix("tenkai:release:").unwrap_or(spec);
    let Some((product, version)) = rest.split_once('@') else {
        bail!("expected <product>@<version>, got {spec:?}");
    };
    crate::ontology::validate_identifier("product", product)?;
    crate::ontology::validate_identifier("version", version)?;
    Ok(crate::ontology::release_id(product, version))
}

/// Take `replica` of `release`'s topology out of service, prove the minimum
/// still holds and remaining replicas stay healthy, restore it, and sign
/// the evidence with the Ed25519 seed at `seed_path` (32 bytes, mode 0600).
pub async fn run(
    ctx: &mut Ctx,
    release: &str,
    replica: &str,
    seed_path: &Path,
) -> Result<DrillEvidence> {
    crate::ontology::validate_identifier("environment", replica)?;
    let release_id = release_object_id(release)?;
    let Some((topology, product)) = topology::availability_manifest(ctx, &release_id).await? else {
        bail!("release {release} declares no topology with min_available");
    };
    if !topology.environments.iter().any(|member| member == replica) {
        bail!(
            "environment {replica} is not a replica of topology {}; its replicas are {}",
            topology.name,
            topology.environments.join(", ")
        );
    }

    let owner = format!("drill:{replica}");
    let lease = match ctx
        .acquire_lease(
            topology::TOPOLOGY_LEASE_NAMESPACE,
            &topology.name,
            &owner,
            topology::TOPOLOGY_LEASE_MS,
        )
        .await
    {
        Ok(lease) => lease,
        Err(_) => {
            return Err(AvailabilityRefused(format!(
                "topology {} is upgrading another replica; retry once it finishes",
                topology.name
            ))
            .into());
        }
    };

    let result = run_held(
        ctx,
        HeldDrill {
            release,
            replica,
            seed_path,
            topology: &topology,
            product: &product,
            fencing_token: &lease.fencing_token,
        },
    )
    .await;
    let _ = ctx
        .release_lease(
            topology::TOPOLOGY_LEASE_NAMESPACE,
            &topology.name,
            &lease.fencing_token,
        )
        .await;
    result
}

fn refuse_unless_ready(
    topology: &TopologySection,
    replica: &str,
    serving: &std::collections::BTreeSet<String>,
    available: &std::collections::BTreeSet<String>,
) -> Result<()> {
    if !serving.contains(replica) {
        bail!("replica {replica} is not serving; a drill takes a serving replica out of service");
    }
    topology.check_availability(replica, serving, available)
}

struct HeldDrill<'a> {
    release: &'a str,
    replica: &'a str,
    seed_path: &'a Path,
    topology: &'a TopologySection,
    product: &'a str,
    fencing_token: &'a str,
}

async fn run_held(ctx: &mut Ctx, drill: HeldDrill<'_>) -> Result<DrillEvidence> {
    let HeldDrill {
        release,
        replica,
        seed_path,
        topology,
        product,
        fencing_token,
    } = drill;
    restore_incomplete(ctx, topology, product).await?;
    let (serving, available) = topology::replica_availability(ctx, topology, product).await?;
    refuse_unless_ready(topology, replica, &serving, &available)?;
    let Some(minimum) = topology.min_available else {
        bail!("release {release} declares no topology with min_available");
    };

    let env_lease = claim_drill_environment(ctx, replica).await?;
    let result = finish_held(
        ctx,
        HeldDrill {
            release,
            replica,
            seed_path,
            topology,
            product,
            fencing_token,
        },
        minimum,
        &env_lease.fencing_token,
    )
    .await;
    let _ = crate::apply::release_environment(ctx, &env_lease).await;
    result
}

async fn finish_held(
    ctx: &mut Ctx,
    drill: HeldDrill<'_>,
    minimum: usize,
    env_fencing_token: &str,
) -> Result<DrillEvidence> {
    let HeldDrill {
        release,
        replica,
        seed_path,
        topology,
        product,
        fencing_token,
    } = drill;
    refresh_topology_lease(ctx, topology, fencing_token).await?;
    let (serving, available) = topology::replica_availability(ctx, topology, product).await?;
    refuse_unless_ready(topology, replica, &serving, &available)?;
    let outage = take_out(ctx, replica, product, &topology.name, env_fencing_token).await?;
    let lost_at_ms = crate::now_millis();
    let observed = observe_remaining(ctx, topology, product, replica, minimum, lost_at_ms).await;
    // Restore even if this refresh fails; the replica is already out of service.
    let refreshed = refresh_topology_lease(ctx, topology, fencing_token).await;
    restore(ctx, &outage, env_fencing_token)
        .await
        .context("restoring the drilled replica")?;
    refreshed?;
    let recovery = observed?;
    let restored_at = crate::now_millis();
    let (serving, available) = topology::replica_availability(ctx, topology, product).await?;
    if !serving.contains(replica) || !available.contains(replica) {
        bail!("replica {replica} did not become available after restore");
    }

    let statement = DrillStatement {
        release: release.into(),
        topology: topology.name.clone(),
        product: product.into(),
        min_available: minimum,
        replicas: topology.environments.clone(),
        passed: true,
        loss: LossRecord {
            replica: replica.into(),
            at_ms: lost_at_ms,
        },
        recovery,
        restore: RestoreRecord {
            replica: replica.into(),
            at_ms: restored_at,
            available: available.into_iter().collect(),
        },
    };
    let evidence = sign(statement, seed_path)?;
    record(ctx, replica, env_fencing_token, &evidence).await?;
    Ok(evidence)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutageRecord {
    topology: String,
    product: String,
    previous: Option<String>,
    /// Apply-lease token written with the outage so a crash can release it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    env_fencing_token: Option<String>,
}

struct Outage {
    environment: String,
    record: OutageRecord,
}

/// Lab outage uses Tenkai's serving signal (`deployment_health`), the same
/// one `min_available` reads. The previous health is stored on the replica
/// in the same write so a crash can restore it.
async fn take_out(
    ctx: &mut Ctx,
    replica: &str,
    product: &str,
    topology: &str,
    env_fencing_token: &str,
) -> Result<Outage> {
    let key = topology::deployment_health_key(product);
    let mut object = crate::environment::environment(ctx, replica).await?;
    let previous = object.properties.get(&key).cloned();
    let record = OutageRecord {
        topology: topology.into(),
        product: product.into(),
        previous,
        env_fencing_token: Some(env_fencing_token.into()),
    };
    object.properties.insert(
        outage_property(topology, product),
        serde_json::to_string(&record)?,
    );
    object.properties.insert(key, OUT_OF_SERVICE.into());
    put_env_fenced(ctx, object, replica, env_fencing_token).await?;
    Ok(Outage {
        environment: replica.into(),
        record,
    })
}

async fn restore(ctx: &mut Ctx, outage: &Outage, env_fencing_token: &str) -> Result<()> {
    apply_restore(ctx, &outage.environment, &outage.record, env_fencing_token).await
}

async fn apply_restore(
    ctx: &mut Ctx,
    replica: &str,
    record: &OutageRecord,
    env_fencing_token: &str,
) -> Result<()> {
    let key = topology::deployment_health_key(&record.product);
    let mut object = crate::environment::environment(ctx, replica).await?;
    let still_out = object
        .properties
        .get(&key)
        .is_some_and(|health| health == OUT_OF_SERVICE);
    if still_out {
        match &record.previous {
            Some(health) => {
                object.properties.insert(key, health.clone());
            }
            None => {
                object.properties.remove(&key);
            }
        }
    }
    object
        .properties
        .remove(&outage_property(&record.topology, &record.product));
    put_env_fenced(ctx, object, replica, env_fencing_token).await
}

async fn restore_incomplete(
    ctx: &mut Ctx,
    topology: &TopologySection,
    product: &str,
) -> Result<()> {
    let property = outage_property(&topology.name, product);
    for member in &topology.environments {
        let object = crate::environment::environment(ctx, member).await?;
        let Some(raw) = object.properties.get(&property) else {
            continue;
        };
        let record: OutageRecord = serde_json::from_str(raw)
            .with_context(|| format!("parsing incomplete topology drill outage on {member}"))?;
        if record.product != product || record.topology != topology.name {
            continue;
        }
        restore_member_outage(ctx, member, &record)
            .await
            .with_context(|| format!("restoring incomplete drill outage on {member}"))?;
    }
    Ok(())
}

async fn restore_member_outage(ctx: &mut Ctx, replica: &str, record: &OutageRecord) -> Result<()> {
    if let Some(token) = &record.env_fencing_token {
        let _ = crate::apply::release_environment_fence(ctx, replica, token).await;
    }
    let env_lease = claim_drill_environment(ctx, replica).await?;
    let restored = apply_restore(ctx, replica, record, &env_lease.fencing_token).await;
    let _ = crate::apply::release_environment(ctx, &env_lease).await;
    restored
}

async fn refresh_topology_lease(
    ctx: &mut Ctx,
    topology: &TopologySection,
    fencing_token: &str,
) -> Result<()> {
    ctx.refresh_lease(
        topology::TOPOLOGY_LEASE_NAMESPACE,
        &topology.name,
        fencing_token,
        topology::TOPOLOGY_LEASE_MS,
    )
    .await
    .map(|_| ())
    .map_err(|_| {
        AvailabilityRefused(format!(
            "topology {} is upgrading another replica; retry once it finishes",
            topology.name
        ))
        .into()
    })
}

async fn claim_drill_environment(
    ctx: &mut Ctx,
    replica: &str,
) -> Result<crate::apply::EnvironmentLease> {
    match crate::apply::claim_environment_for_drill(ctx, replica, &format!("drill:{replica}")).await
    {
        Ok(lease) => Ok(lease),
        Err(_) => Err(AvailabilityRefused(format!(
            "environment {replica} has an apply in progress; retry once it finishes"
        ))
        .into()),
    }
}

async fn put_env_fenced(
    ctx: &mut Ctx,
    object: crate::pb::sekai::Object,
    replica: &str,
    env_fencing_token: &str,
) -> Result<()> {
    ctx.guarded_update(
        object,
        crate::apply::ENVIRONMENT_LEASE_NAMESPACE,
        replica,
        env_fencing_token,
    )
    .await
    .map(|_| ())
}

async fn observe_remaining(
    ctx: &mut Ctx,
    topology: &TopologySection,
    product: &str,
    replica: &str,
    minimum: usize,
    lost_at_ms: i64,
) -> Result<RecoveryRecord> {
    let (_, available) = topology::replica_availability(ctx, topology, product).await?;
    if available.contains(replica) {
        bail!("replica {replica} is still available after being taken out of service");
    }
    let remaining: Vec<String> = topology
        .environments
        .iter()
        .filter(|member| member.as_str() != replica && available.contains(*member))
        .cloned()
        .collect();
    let traffic_continued = remaining.len() >= minimum;
    if !traffic_continued {
        let unready: Vec<&str> = topology
            .environments
            .iter()
            .filter(|member| member.as_str() != replica && !available.contains(*member))
            .map(|member| member.as_str())
            .collect();
        return Err(AvailabilityRefused(format!(
            "drilling {replica} left {} of topology {}'s replicas available, below its minimum {minimum}; not healthy: {}",
            remaining.len(),
            topology.name,
            unready.join(", ")
        ))
        .into());
    }
    let confirmed_at_ms = crate::now_millis();
    Ok(RecoveryRecord {
        remaining_available: remaining,
        confirmed_at_ms,
        duration_ms: confirmed_at_ms.saturating_sub(lost_at_ms),
        traffic_continued,
    })
}

fn sign(statement: DrillStatement, seed_path: &Path) -> Result<DrillEvidence> {
    let signing_key = SigningKey::from_bytes(&crate::approval_policy::load_signer_seed(seed_path)?);
    let signature = signing_key.sign(&canonical_bytes(&statement)?);
    Ok(DrillEvidence {
        schema: DRILL_SCHEMA.into(),
        key_id: crate::signature_verification::key_id(&signing_key.verifying_key().to_bytes()),
        statement,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

async fn record(
    ctx: &mut Ctx,
    replica: &str,
    env_fencing_token: &str,
    evidence: &DrillEvidence,
) -> Result<()> {
    let mut environment = crate::environment::environment(ctx, replica).await?;
    environment
        .properties
        .insert(EVIDENCE_PROPERTY.into(), serde_json::to_string(evidence)?);
    put_env_fenced(ctx, environment, replica, env_fencing_token).await
}

impl DrillEvidence {
    /// Check the signature against the signer's public key.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<()> {
        if self.schema != DRILL_SCHEMA {
            bail!("topology drill schema is not {DRILL_SCHEMA}");
        }
        if self.key_id != crate::signature_verification::key_id(public_key) {
            bail!("topology drill key_id does not match the signer");
        }
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| anyhow::anyhow!("topology drill public key is invalid"))?;
        crate::signature_verification::verify_strict(
            &key,
            "topology drill signature",
            &self.signature,
            &canonical_bytes(&self.statement)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Ctx;
    use crate::plan;
    use std::os::unix::fs::PermissionsExt as _;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tenkai-topology-drill-{name}-{}-{}-{}",
            std::process::id(),
            crate::now_millis(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_seed(path: &std::path::Path) {
        std::fs::write(path, [7u8; 32]).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_software_manifest(dir: &std::path::Path, extra: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("tenkai.toml"),
            format!(
                r#"[product]
name = "ledger"
version = "1.0.0"

[deploy]
workdir = "."
install = "true"
{extra}
"#
            ),
        )
        .unwrap();
    }

    async fn publish_unsigned(ctx: &mut Ctx, manifest: &std::path::Path) {
        crate::catalog::publish(
            ctx,
            manifest,
            &crate::catalog::PublishOptions {
                signature: None,
                trust_roots: None,
                allow_unsigned_development: true,
                provenance: Vec::new(),
                provenance_trust_roots: None,
                change_set_evidence: None,
                artifact_registry: None,
                state_dir: None,
            },
        )
        .await
        .unwrap();
    }

    async fn mark(ctx: &mut Ctx, env: &str, health: &str) {
        let mut object = crate::environment::environment(ctx, env).await.unwrap();
        object
            .properties
            .insert("deployment_health.ledger".into(), health.into());
        ctx.put(object).await.unwrap();
    }

    async fn health(ctx: &mut Ctx, env: &str) -> Option<String> {
        crate::environment::environment(ctx, env)
            .await
            .unwrap()
            .properties
            .get("deployment_health.ledger")
            .cloned()
    }

    async fn lab(min_available: Option<usize>) -> (std::path::PathBuf, Ctx, std::path::PathBuf) {
        let root = temp_root("lab");
        let database = root.join("tenkai.db");
        let product = root.join("product");
        let extra = match min_available {
            Some(minimum) => format!(
                "\n[topology]\nname = \"ledger-ha\"\nenvironments = [\"ledger-a\", \"ledger-b\", \"ledger-c\"]\nanti_affinity = \"host\"\nmin_available = {minimum}\n"
            ),
            None => {
                "\n[topology]\nname = \"ledger-ha\"\nenvironments = [\"ledger-a\", \"ledger-b\", \"ledger-c\"]\nanti_affinity = \"host\"\n"
                    .into()
            }
        };
        write_software_manifest(&product, &extra);
        let mut ctx = Ctx::embedded(&database).unwrap();
        crate::ontology::register(&mut ctx).await.unwrap();
        publish_unsigned(&mut ctx, &product.join("tenkai.toml")).await;
        let actor = crate::auth_context::test_management_context("topology-drill");
        crate::catalog::promote(&mut ctx, &actor, "ledger@1.0.0", "stable")
            .await
            .unwrap();
        for (env, host) in [("ledger-a", "h1"), ("ledger-b", "h2"), ("ledger-c", "h3")] {
            plan::env_add(&mut ctx, env, "replica").await.unwrap();
            plan::subscribe(&mut ctx, env, "ledger", "stable")
                .await
                .unwrap();
            crate::environment::set_environment_fact(&mut ctx, env, "host", host)
                .await
                .unwrap();
            mark(&mut ctx, env, "healthy").await;
        }
        let seed = root.join("drill.seed");
        write_seed(&seed);
        (root, ctx, seed)
    }

    #[tokio::test]
    async fn a_lab_drill_signs_loss_recovery_and_restore() {
        let (_root, mut ctx, seed) = lab(Some(2)).await;
        let evidence = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap();
        let public_key = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        evidence.verify(&public_key).unwrap();
        let statement = &evidence.statement;
        assert_eq!(statement.topology, "ledger-ha");
        assert_eq!(statement.min_available, 2);
        assert_eq!(statement.loss.replica, "ledger-a");
        assert_eq!(
            statement.recovery.remaining_available,
            vec!["ledger-b", "ledger-c"]
        );
        assert!(statement.recovery.traffic_continued);
        assert!(statement.recovery.confirmed_at_ms >= statement.loss.at_ms);
        assert_eq!(statement.restore.replica, "ledger-a");
        assert!(
            statement
                .restore
                .available
                .iter()
                .any(|name| name == "ledger-a")
        );
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("healthy")
        );
        let stored = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap()
            .properties
            .get(EVIDENCE_PROPERTY)
            .cloned()
            .unwrap();
        let recorded: DrillEvidence = serde_json::from_str(&stored).unwrap();
        assert_eq!(recorded, evidence);
        let _ = std::fs::remove_dir_all(_root);
    }

    #[tokio::test]
    async fn a_drill_that_would_drop_below_the_minimum_is_refused() {
        let (root, mut ctx, seed) = lab(Some(2)).await;
        mark(&mut ctx, "ledger-b", "unhealthy").await;
        let err = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap_err();
        let refused = err.downcast_ref::<AvailabilityRefused>().unwrap();
        assert!(
            refused.0.contains("minimum 2") && refused.0.contains("not healthy: ledger-b"),
            "{refused}"
        );
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("healthy")
        );
        let stored = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap();
        assert!(!stored.properties.contains_key(EVIDENCE_PROPERTY));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_held_topology_lease_refuses_the_drill() {
        let (root, mut ctx, seed) = lab(Some(2)).await;
        ctx.acquire_lease(
            topology::TOPOLOGY_LEASE_NAMESPACE,
            "ledger-ha",
            "wave",
            60_000,
        )
        .await
        .unwrap();
        let err = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap_err();
        let refused = err.downcast_ref::<AvailabilityRefused>().unwrap();
        assert!(refused.0.contains("upgrading another replica"), "{refused}");
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("healthy")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_topology_without_a_minimum_is_refused() {
        let (root, mut ctx, seed) = lab(None).await;
        let err = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no topology with min_available"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_crashed_drill_restores_the_replica_then_runs() {
        let (root, mut ctx, seed) = lab(Some(2)).await;
        let mut object = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap();
        object.properties.insert(
            outage_property("ledger-ha", "ledger"),
            serde_json::to_string(&OutageRecord {
                topology: "ledger-ha".into(),
                product: "ledger".into(),
                previous: Some("healthy".into()),
                env_fencing_token: None,
            })
            .unwrap(),
        );
        object
            .properties
            .insert("deployment_health.ledger".into(), OUT_OF_SERVICE.into());
        ctx.put(object).await.unwrap();

        let evidence = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap();
        assert!(evidence.statement.passed);
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("healthy")
        );
        let stored = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap();
        assert!(
            !stored
                .properties
                .contains_key(&outage_property("ledger-ha", "ledger"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_later_apply_keeps_its_health_across_crash_restore() {
        let (root, mut ctx, seed) = lab(Some(2)).await;
        let mut object = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap();
        object.properties.insert(
            outage_property("ledger-ha", "ledger"),
            serde_json::to_string(&OutageRecord {
                topology: "ledger-ha".into(),
                product: "ledger".into(),
                previous: Some("healthy".into()),
                env_fencing_token: None,
            })
            .unwrap(),
        );
        object
            .properties
            .insert("deployment_health.ledger".into(), "unknown".into());
        ctx.put(object).await.unwrap();

        let err = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not serving"), "{err}");
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("unknown")
        );
        let stored = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap();
        assert!(
            !stored
                .properties
                .contains_key(&outage_property("ledger-ha", "ledger"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_crashed_drill_releases_its_leftover_apply_lease() {
        let (root, mut ctx, seed) = lab(Some(2)).await;
        let leftover =
            crate::apply::claim_environment_for_drill(&mut ctx, "ledger-a", "drill:ledger-a")
                .await
                .unwrap();
        let mut object = crate::environment::environment(&mut ctx, "ledger-a")
            .await
            .unwrap();
        object.properties.insert(
            outage_property("ledger-ha", "ledger"),
            serde_json::to_string(&OutageRecord {
                topology: "ledger-ha".into(),
                product: "ledger".into(),
                previous: Some("healthy".into()),
                env_fencing_token: Some(leftover.fencing_token.clone()),
            })
            .unwrap(),
        );
        object
            .properties
            .insert("deployment_health.ledger".into(), OUT_OF_SERVICE.into());
        ctx.put(object).await.unwrap();

        let evidence = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap();
        assert!(evidence.statement.passed);
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("healthy")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_held_apply_lease_refuses_the_drill() {
        let (root, mut ctx, seed) = lab(Some(2)).await;
        crate::apply::claim_environment(&mut ctx, "ledger-a", "apply")
            .await
            .unwrap();
        let err = run(&mut ctx, "ledger@1.0.0", "ledger-a", &seed)
            .await
            .unwrap_err();
        let refused = err.downcast_ref::<AvailabilityRefused>().unwrap();
        assert!(refused.0.contains("apply in progress"), "{refused}");
        assert_eq!(
            health(&mut ctx, "ledger-a").await.as_deref(),
            Some("healthy")
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
